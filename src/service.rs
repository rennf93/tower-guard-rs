//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardClientIp;
use crate::GuardLayer;
use crate::body::{BoxError, GuardBody};
use crate::response;
use bytes::{Bytes, BytesMut};
use guard_core_engine::body_scan::extract_body_scan_values;
use guard_core_engine::ip_gate::IpGateVerdict;
use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;

/// Header names that are never scanned, mirroring the TypeScript adapters'
/// `EXCLUDED_HEADERS` (plus every `sec-*` header).
///
/// Negotiation and routing headers carry attacker-influenced-but-expected
/// values (`Accept`, `User-Agent`, ...) whose scanning costs false positives
/// without buying coverage: a payload smuggled into them must still survive
/// the path, query, and body views.
const EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
];

/// A [`tower::Service`] that screens requests through the Guard engine before
/// forwarding them to the wrapped service.
///
/// Built by [`GuardLayer::layer`](tower::Layer::layer). It requires the
/// wrapped service to be `Clone` (the inner service is cloned into the
/// request future so the guard can buffer the body before dispatching), which
/// every framework service used with `tower` middleware already satisfies.
pub struct GuardService<S> {
    inner: S,
    layer: GuardLayer,
}

impl<S> GuardService<S> {
    pub(crate) fn new(inner: S, layer: GuardLayer) -> Self {
        Self { inner, layer }
    }
}

impl<S: Clone> Clone for GuardService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for GuardService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardService")
            .field("inner", &self.inner)
            .field("layer", &self.layer)
            .finish()
    }
}

/// Why a request body could not be fully buffered.
enum BufferFailure {
    /// The body exceeded the buffering cap; reading stopped early.
    TooLarge,
    /// The body stream errored mid-read. The underlying error is dropped on
    /// purpose: it is body-transport noise (client abort, socket reset), not
    /// a security signal, and it must not leak into the `500` response.
    Read,
}

/// The outcome of scanning one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// No view tripped the engine.
    Clean,
    /// At least one view was flagged as a threat.
    Threat,
    /// The engine panicked; fail secure.
    Failed,
}

impl<S, B, B2> Service<Request<B>> for GuardService<S>
where
    S: Service<Request<B>, Response = Response<B2>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Body<Data = Bytes> + Unpin + Send + 'static + From<Bytes>,
    B::Error: Into<BoxError>,
    B2: Body<Data = Bytes> + Unpin + Send + 'static,
    B2::Error: Into<BoxError>,
{
    type Response = Response<GuardBody<B2>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let layer = self.layer.clone();
        Box::pin(async move {
            let (mut parts, mut body) = request.into_parts();

            // The IP gate runs before anything else: a denied IP must not
            // cost a body buffer, and detection still scans whatever passes.
            if let Some(denial) = enforce_ip_gate(&mut parts, &layer) {
                return Ok(denial.map(GuardBody::Generated));
            }

            let buffered = match buffer_body(&mut body, layer.body_cap()).await {
                Ok(buffered) => buffered,
                Err(BufferFailure::TooLarge) => {
                    return Ok(response::oversize().map(GuardBody::Generated));
                }
                Err(BufferFailure::Read) => {
                    return Ok(response::failure().map(GuardBody::Generated));
                }
            };
            match scan_request(&parts, buffered.as_ref(), &layer) {
                ScanOutcome::Clean => {
                    let rebuilt = B::from(buffered.unwrap_or_default());
                    let response = inner.call(Request::from_parts(parts, rebuilt)).await?;
                    Ok(response.map(GuardBody::Passthrough))
                }
                ScanOutcome::Threat => Ok(response::blocked().map(GuardBody::Generated)),
                ScanOutcome::Failed => Ok(response::failure().map(GuardBody::Generated)),
            }
        })
    }
}

/// Apply the configured IP gate to the request parts.
///
/// Returns the `403 Forbidden` response when the gate denies the request IP.
/// A passed request gets the gate's [`IpGateDecision`] inserted into the
/// request extensions (the family-local skip state, the equivalent of the
/// reference engine's `state.is_whitelisted` / `state.is_exempt`) so
/// downstream handlers can read it. Without a gate or without a
/// [`GuardClientIp`] extension the request is not attributed: the gate does
/// not run, and nothing is inserted.
fn enforce_ip_gate(parts: &mut Parts, layer: &GuardLayer) -> Option<Response<Full<Bytes>>> {
    let gate = layer.ip_gate()?;
    let GuardClientIp(ip) = parts.extensions.get::<GuardClientIp>()?;
    match gate.evaluate(*ip) {
        IpGateVerdict::Allowed(decision) => {
            parts.extensions.insert(decision);
            None
        }
        IpGateVerdict::Denied(_) => Some(response::forbidden()),
    }
}

/// Buffer a request body up to `cap` bytes.
///
/// `Ok(None)` means the body was empty. Trailers are discarded: the engine
/// scans content, and request trailers are not part of any scanned view.
async fn buffer_body<B>(body: &mut B, cap: usize) -> Result<Option<Bytes>, BufferFailure>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let mut buffered = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_error| BufferFailure::Read)?;
        if let Ok(data) = frame.into_data() {
            if buffered.len() + data.len() > cap {
                return Err(BufferFailure::TooLarge);
            }
            buffered.extend_from_slice(&data);
        }
    }
    Ok(if buffered.is_empty() {
        None
    } else {
        Some(buffered.freeze())
    })
}

/// Run the engine over every request view, recovering from engine panics.
///
/// The engine's `detect` is total by signature, so the only failure mode is a
/// panic. Catching it here keeps the connection alive and lets the guard
/// answer `500` instead of unwinding out of the request task.
fn scan_request(parts: &Parts, body: Option<&Bytes>, layer: &GuardLayer) -> ScanOutcome {
    match catch_unwind(AssertUnwindSafe(|| scan_views(parts, body, layer))) {
        Ok(true) => ScanOutcome::Threat,
        Ok(false) => ScanOutcome::Clean,
        Err(_) => ScanOutcome::Failed,
    }
}

/// One engine call per view, in the documented order: path, query, headers,
/// body. The first view the engine flags wins.
fn scan_views(parts: &Parts, body: Option<&Bytes>, layer: &GuardLayer) -> bool {
    let path = parts.uri.path();
    if path != "/" && flagged(layer, path, "url_path") {
        return true;
    }

    if let Some(query) = parts.uri.query()
        && !query.is_empty()
        && flagged(layer, query, "query_param")
    {
        return true;
    }

    for (name, value) in &parts.headers {
        if is_excluded_header(name.as_str()) {
            continue;
        }
        // Opaque (non-ASCII) header values cannot be represented as `&str`.
        // They are skipped rather than guessed at, mirroring the string-typed
        // header maps the TypeScript adapters hand to the engine.
        let Ok(value) = value.to_str() else {
            continue;
        };
        if flagged(layer, value, "header") {
            return true;
        }
    }

    if let Some(bytes) = body {
        // Content-type routing (urlencoded fields, multipart parts, JSON
        // walks, blob fallback) happens in the engine; every extracted value
        // is scanned with its reference context instead of the lossy
        // whole-body blob.
        let content_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if body_flagged(layer, content_type, bytes) {
            return true;
        }
    }

    false
}

/// Scan the buffered request body through the engine's body-value extraction
/// (`request_body` view).
///
/// Every extracted value goes through the normal detect path with the context
/// label the reference engine scans it under (`request_body:form_field`,
/// `request_body:multipart_field`, `:embedded_json` leaves, ...); the first
/// threat wins. A value with a forced category (a JSON mongo operator key the
/// reference reports straight from the JSON walk) is a threat outright. An
/// empty (or whitespace-only) body is not scanned, mirroring the previous
/// behavior.
fn body_flagged(layer: &GuardLayer, content_type: Option<&str>, bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return false;
    }
    for value in extract_body_scan_values(&text, content_type.unwrap_or(""), layer.config()) {
        if value.forced_category.is_some() || flagged(layer, &value.content, &value.context) {
            return true;
        }
    }
    false
}

/// One engine call: `true` when the engine flags the content.
fn flagged(layer: &GuardLayer, content: &str, view: &str) -> bool {
    (layer.detect_fn())(content, view, layer.config()).is_threat
}

fn is_excluded_header(name: &str) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE, GuardClientIp, IpGateConfig,
        default_config,
    };
    use guard_core_engine::detect::{DetectConfig, DetectVerdict};
    use guard_core_engine::ip_gate::IpGateDecision;
    use http::StatusCode;
    use http_body_util::Full;
    use std::convert::Infallible;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tower::{Layer, ServiceExt};
    fn panicking_detect(_content: &str, _context: &str, _config: &DetectConfig) -> DetectVerdict {
        panic!("engine exploded");
    }

    fn gate_ip(text: &str) -> GuardClientIp {
        GuardClientIp(IpAddr::from_str(text).expect("test address"))
    }

    /// The empty list, typed so the `new` calls stay inferable.
    const NIL: [&str; 0] = [];

    /// The checklist gate: a blacklisted exact IP and a blacklisted /24
    /// (192.0.2.x), an exempt exact IP and an exempt /28 (198.51.100.x), all
    /// disjoint.
    fn checklist_gate() -> IpGateConfig {
        IpGateConfig::new(
            [] as [&str; 0],
            ["203.0.113.9", "192.0.2.0/24"],
            ["198.51.100.7", "198.51.100.16/28"],
        )
        .expect("valid lists")
    }

    /// A guarded service whose `200` body reports the skip state the
    /// downstream handler sees in its request extensions.
    fn guarded(
        layer: &GuardLayer,
    ) -> impl Service<
        Request<Full<Bytes>>,
        Response = http::Response<crate::GuardBody<Full<Bytes>>>,
        Error = Infallible,
    > {
        layer.layer(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                let verdict = match request.extensions().get::<IpGateDecision>().copied() {
                    Some(decision) => {
                        format!(
                            "gate=on wh={} ex={}",
                            decision.is_whitelisted, decision.is_exempt
                        )
                    }
                    None => "gate=off".to_owned(),
                };
                Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from(verdict))))
            },
        ))
    }

    async fn status_and_body(
        layer: &GuardLayer,
        request: Request<Full<Bytes>>,
    ) -> (StatusCode, String) {
        let response = guarded(layer).oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn benign_request(ip: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .uri("/hello")
            .extension(gate_ip(ip))
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    async fn body_text(response: Response<GuardBody<Full<Bytes>>>) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let layer = GuardLayer::new(default_config()).with_detect_fn(panicking_detect);
        let service = layer.layer(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                Ok::<_, Infallible>(Response::new(request.into_body()))
            },
        ));
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::from_static(b"ping")))
            .expect("request");

        let response = service.oneshot(request).await.expect("response");
        assert_eq!(response.status(), 500);
        assert_eq!(body_text(response).await, FAILURE_MESSAGE);
    }

    #[tokio::test]
    async fn scan_views_reports_threat_through_catch_unwind() {
        let layer = GuardLayer::new(default_config());
        let parts = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(())
            .expect("request")
            .into_parts()
            .0;
        assert_eq!(
            scan_request(&parts, None, &layer),
            ScanOutcome::Threat,
            "traversal path should be flagged"
        );
    }

    #[tokio::test]
    async fn empty_body_is_not_scanned_and_still_forwarded() {
        let layer = GuardLayer::new(default_config());
        let service = layer.layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }));
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.oneshot(request).await.expect("response");
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn blocked_response_body_reports_the_documented_message() {
        let layer = GuardLayer::new(default_config());
        let service = layer.layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }));
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.oneshot(request).await.expect("response");
        assert_eq!(response.status(), 403);
        assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
    }

    #[test]
    fn excluded_headers_cover_the_negotiation_set_and_sec_prefix() {
        for name in [
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "connection",
        ] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["sec-fetch-site", "sec-ch-ua", "sec-websocket-key"] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["cookie", "authorization", "content-type", "x-api-key"] {
            assert!(!is_excluded_header(name), "{name} should be scanned");
        }
    }

    // --- the global IP gate (exempt_ips contract checklist) ---

    #[tokio::test]
    async fn blacklisted_ip_is_denied_with_the_forbidden_body() {
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(checklist_gate()),
            benign_request("203.0.113.9"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);

        // The blacklisted /24 denies its whole range.
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(checklist_gate()),
            benign_request("192.0.2.77"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);
    }

    #[tokio::test]
    async fn exempt_exact_and_cidr_ips_pass_with_the_skip_state_set() {
        // Checklist: exemption is observable behavior for the exact entry and
        // the CIDR member alike; the Rust family has no rate limiter yet, so
        // "skips rate limiting" is pinned at the flag level the contract
        // defines (the same state a whitelist match sets).
        let layer = GuardLayer::new(default_config()).with_ip_gate(checklist_gate());
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=false ex=true");

        let (status, body) = status_and_body(&layer, benign_request("198.51.100.20")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=false ex=true");
    }

    #[tokio::test]
    async fn exempt_ip_on_the_blacklist_is_still_denied() {
        let gate = IpGateConfig::new(NIL, ["198.51.100.7"], ["198.51.100.7"]).expect("valid lists");
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(gate),
            benign_request("198.51.100.7"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);
    }

    #[tokio::test]
    async fn exemption_never_opens_a_restrictive_whitelist() {
        let gate = IpGateConfig::new(["192.0.2.1"], NIL, ["198.51.100.7"]).expect("valid lists");
        let layer = GuardLayer::new(default_config()).with_ip_gate(gate);
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);

        // An exempt-only config adds no deny path of its own: with the
        // whitelist empty, every IP passes, exempt or not.
        let exempt_only = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(exempt_only),
            benign_request("192.0.2.8"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=false ex=false");
    }

    #[tokio::test]
    async fn whitelist_match_sets_both_flags_and_exemption_follows_the_list() {
        let gate = IpGateConfig::new(["198.51.100.7", "198.51.100.30"], NIL, ["198.51.100.7"])
            .expect("valid lists");
        let layer = GuardLayer::new(default_config()).with_ip_gate(gate);
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=true ex=true");

        // A whitelist member outside exempt_ips: plain whitelist skip state.
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.30")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=true ex=false");
    }

    #[tokio::test]
    async fn an_attack_from_an_exempt_ip_is_still_blocked_by_detection() {
        // Checklist: penetration detection still applies to exempt IPs.
        let layer = GuardLayer::new(default_config()).with_ip_gate(checklist_gate());
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("198.51.100.7"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, BLOCKED_MESSAGE,
            "detection must still scan exempt IPs"
        );
    }

    #[tokio::test]
    async fn without_a_client_ip_extension_the_gate_is_inert_and_detection_still_applies() {
        let layer = GuardLayer::new(default_config()).with_ip_gate(checklist_gate());
        // Not attributed: the gate cannot run, and the request flows on.
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=off");

        // Not attributed does not mean unscreened: detection still scans.
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BLOCKED_MESSAGE);
    }

    #[tokio::test]
    async fn invalid_exempt_entry_fails_closed_at_config_time() {
        let error = IpGateConfig::new(NIL, NIL, ["not-an-ip"]).unwrap_err();
        assert_eq!(error.list, "exempt_ips");
        assert_eq!(error.entry, "not-an-ip");
    }

    #[test]
    fn ipv4_mapped_request_matches_v4_entries_at_the_gate() {
        // Checklist: IPv4-mapped parity. std parses the mapped form as an
        // IPv6 address; the gate must still match it against v4 entries
        // exactly as the whitelist matcher does.
        let mapped = IpAddr::from_str("::ffff:198.51.100.7").expect("mapped address");
        let gate = IpGateConfig::new(["198.51.100.0/24"], NIL, ["198.51.100.7"]).expect("lists");
        assert!(
            matches!(gate.evaluate(mapped), IpGateVerdict::Allowed(decision) if decision.is_exempt)
        );
        assert!(matches!(
            gate.evaluate(mapped),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
    }

    // --- body-value extraction through the full service ---

    fn body_bytes(const_bytes: &[u8]) -> Full<Bytes> {
        Full::new(Bytes::copy_from_slice(const_bytes))
    }

    async fn status_for(request: Request<Full<Bytes>>) -> http::StatusCode {
        let service = GuardLayer::new(default_config()).layer(tower::service_fn(
            |_request: Request<Full<Bytes>>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            },
        ));
        service.oneshot(request).await.expect("response").status()
    }

    #[tokio::test]
    async fn sqli_in_a_form_field_is_blocked() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_bytes(b"q=1+OR+1%3D1"))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn backslash_probe_in_a_form_field_is_blocked_through_the_raw_view() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_bytes(b"q=\\default"))
            .expect("request");
        assert_eq!(
            status_for(request).await,
            http::StatusCode::FORBIDDEN,
            "\\default in a form field must stay a recon probe"
        );
    }

    #[tokio::test]
    async fn multipart_binary_island_smuggling_is_not_blocked() {
        // A binary-dense file part whose only printable fragment is shorter
        // than the minimum island run: no detection, request forwarded.
        let noise = noise_bytes(11, 4096);
        let mut body = Vec::new();
        body.extend_from_slice(b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"installer.zip\"\r\n\r\n");
        body.extend_from_slice(&noise);
        body.extend_from_slice(b"\x001 OR 1=1\x00");
        body.extend_from_slice(b"\r\n--B0--\r\n");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(&body))
            .expect("request");
        assert_eq!(
            status_for(request).await,
            http::StatusCode::OK,
            "the compressed fragment must not pattern-match"
        );
    }

    #[tokio::test]
    async fn plain_multipart_text_part_with_script_is_blocked() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n";
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(body.as_bytes()))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn multipart_binary_upload_with_embedded_script_is_blocked() {
        let noise = noise_bytes(12, 4096);
        let mut body = Vec::new();
        body.extend_from_slice(b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"page.html.bin\"\r\n\r\n");
        body.extend_from_slice(&noise);
        body.extend_from_slice(b"\x00<script>alert(1)</script>\x00");
        body.extend_from_slice(&noise_bytes(13, 4096));
        body.extend_from_slice(b"\r\n--B0--\r\n");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(&body))
            .expect("request");
        assert_eq!(
            status_for(request).await,
            http::StatusCode::FORBIDDEN,
            "the intact script island must detect"
        );
    }

    #[tokio::test]
    async fn embedded_json_leaf_attack_is_blocked() {
        let body = r#"data={"a":"<script>alert(1)</script>"}"#;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_bytes(body.as_bytes()))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mongo_operator_key_body_is_blocked() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/query")
            .header("content-type", "application/json")
            .body(body_bytes(br#"{"$where": "1 OR 1=1"}"#))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn benign_multipart_upload_is_forwarded() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"notes.txt\"\r\n\r\nhello world\r\n--B0--\r\n";
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(body.as_bytes()))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::OK);
    }

    /// Deterministic pseudo-random bytes: the binary-dense fixture.
    fn noise_bytes(seed: u64, size: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(u8::try_from(state % 256).expect("value below 256"));
        }
        out
    }
}
