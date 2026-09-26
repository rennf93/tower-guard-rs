//! # tower-guard-rs
//!
//! Application-layer security middleware for
//! [tower](https://github.com/tower-rs/tower)-based services, powered by the
//! [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine.
//! Part of the [Guard ecosystem](https://github.com/rennf93). It works with
//! any framework built on [`tower::Service`], including
//! [axum](https://github.com/tokio-rs/axum) (the [`axum-guard-rs`] wrapper
//! composes this crate), [hyper](https://github.com/hyperium/hyper), and
//! [warp](https://github.com/seanmonstar/warp).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`GuardLayer`] is a working [`tower::Layer`] and [`GuardService`] a working
//! [`tower::Service`] over `http::Request<B>`. The engine is wired in through
//! `guard-core-engine` (a path dependency until the engine is tagged and
//! published). Per the ecosystem boundary rules, this adapter holds framework
//! glue only: every detection decision comes from the engine.
//!
//! ## What it inspects
//!
//! One engine call per request view, mirroring the mapping used by the
//! sibling TypeScript adapters (`guard-core-ts`):
//!
//! | Request part | Engine context | Notes |
//! |---|---|---|
//! | Path | `url_path` | Skipped for `/` |
//! | Query string | `query_param` | Skipped when empty |
//! | Header values | `header` | Skips `sec-*` and hop-by-hop/negotiation headers (see `EXCLUDED_HEADERS`) |
//! | Body | `request_body` | Buffered first, capped (see below); routed by content type, so urlencoded fields, multipart parts, and JSON bodies are extracted into the values the reference engine scans individually instead of one whole-body blob |
//!
//! The HTTP method is not fed to the engine: the engine's `detect` signature
//! takes content plus a context, and the reference adapters do not scan the
//! method either.
//!
//! ## Body cap
//!
//! Request bodies are buffered so the engine can inspect them, and the buffer
//! is bounded by [`GuardLayer::with_body_cap`]. It defaults to the engine's
//! full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the
//! ecosystem default). A request whose body exceeds the cap is rejected with
//! `413 Payload Too Large` rather than forwarded unscanned: the engine would
//! only ever see a truncated prefix, which would be a bypass vector.
//!
//! ## Responses
//!
//! | Situation | Status | Body |
//! |---|---|---|
//! | The IP gate denies the client IP (blacklisted, or a non-empty whitelist matches neither the IP nor an exemption) | `403 Forbidden` | `Forbidden` |
//! | Engine flags a view | `403 Forbidden` | `Suspicious activity detected` |
//! | Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
//! | Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |
//!
//! The IP gate is optional (`GuardLayer::with_ip_gate`); when it is
//! configured, `exempt_ips` (like a whitelist match) only sets the skip state
//! on the request, never a deny path of its own - the exempt-vs-whitelist
//! contract in the engine's `ip_gate` module. The Rust family ships no rate
//! limiter, user-agent filter, cloud-provider blocker, or violation counter
//! yet, so there is nothing for the flag to skip; detection always scans
//! every request, exempt or not, per the contract.
//!
//! These bodies follow the ecosystem's plain-text convention (the bare
//! message, `text/plain; charset=utf-8`, same as the Python family) but
//! the adapter is deliberately **fail-secure**, unlike the TypeScript adapters
//! whose check pipeline logs and skips on error: any failure to complete the
//! security check results in `500`, never in an uninspected passthrough.
//!
//! A panic is caught with [`std::panic::catch_unwind`], so the default panic
//! hook still prints. `panic = "abort"` in the release profile disables that
//! recovery, because the process dies before the guard can respond.
//!
//! ## Example
//!
//! ```
//! use bytes::Bytes;
//! use http::{Request, Response, StatusCode};
//! use http_body_util::{BodyExt, Full};
//! use std::convert::Infallible;
//! use tower::{Layer, Service, ServiceExt};
//!
//! # let runtime = tokio::runtime::Builder::new_current_thread()
//! #     .enable_all()
//! #     .build()
//! #     .unwrap();
//! # runtime.block_on(async {
//! // Any `Service<Request<B>>` works, for example a router.
//! let upstream = tower::service_fn(|request: Request<Full<Bytes>>| async move {
//!     let body = request.into_body().collect().await.unwrap().to_bytes();
//!     Ok::<_, Infallible>(Response::new(Full::new(body)))
//! });
//!
//! let mut service =
//!     tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config()).layer(upstream);
//!
//! // Benign traffic passes through untouched.
//! let request = Request::builder()
//!     .uri("/search?q=hello")
//!     .body(Full::new(Bytes::new()))
//!     .unwrap();
//! let response = service.ready().await.unwrap().call(request).await.unwrap();
//! assert_eq!(response.status(), StatusCode::OK);
//!
//! // Attack traffic is blocked by the engine.
//! let request = Request::builder()
//!     .uri("/files/../../etc/passwd")
//!     .body(Full::new(Bytes::new()))
//!     .unwrap();
//! let response = service.ready().await.unwrap().call(request).await.unwrap();
//! assert_eq!(response.status(), StatusCode::FORBIDDEN);
//! # });
//! ```
//!
//! [`axum-guard-rs`]: https://github.com/rennf93/axum-guard-rs

mod body;
mod response;
mod service;

pub use guard_core_engine::detect::{DetectConfig, DetectVerdict, Threat};
pub use guard_core_engine::ip_gate::{
    IpGateConfig, IpGateDecision, IpGateDenial, IpGateError, IpGateVerdict,
};
use std::net::IpAddr;
use tower::Layer;

pub use crate::body::{BoxError, GuardBody};
pub use crate::response::{BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE, OVERSIZE_MESSAGE};
pub use crate::service::GuardService;

/// The client IP the IP gate evaluates, carried in request extensions.
///
/// The tower [`tower::Service`] surface is framework-neutral, so there is no
/// single place a peer address lives: insert this extension upstream and the
/// configured gate ([`GuardLayer::with_ip_gate`]) evaluates it. Without the
/// extension the gate cannot attribute the request and does not run; the
/// request still goes through detection.
///
/// axum applications map `ConnectInfo<SocketAddr>` into it (axum-guard-rs
/// ships [`axum_guard_rs::client_ip_layer`] for exactly that); a proxy
/// frontend can insert its resolved client IP instead.
///
/// [`axum_guard_rs::client_ip_layer`]: https://docs.rs/axum-guard-rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardClientIp(pub IpAddr);

/// Reference default detection configuration.
///
/// The engine's [`DetectConfig`] carries no `Default` impl, so the adapter
/// pins the ecosystem defaults here. They are the values the conformance
/// corpus records for the reference implementation:
///
/// | Knob | Value |
/// |---|---|
/// | `max_content_length` | `10_000` |
/// | `max_full_scan_bytes` | `262_144` |
/// | `preserve_attack_patterns` | `true` |
/// | `semantic_threshold` | `0.7` |
/// | `threat_score_threshold` | `1.0` |
/// | `binary_min_run_length` | `16` |
///
/// # Example
///
/// ```
/// let config = tower_guard_rs::default_config();
/// let layer = tower_guard_rs::GuardLayer::new(config);
/// # let _ = layer;
/// ```
#[must_use]
pub const fn default_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

/// Engine entry point stored in the layer.
///
/// Indirection exists so unit tests can substitute a panicking detector and
/// exercise the fail-secure path; production builds always store
/// [`guard_core_engine::detect::detect`].
pub(crate) type DetectFn = fn(&str, &str, &DetectConfig) -> DetectVerdict;

/// Screens requests with the Guard engine before they reach the wrapped
/// service.
///
/// Wraps any service whose response body type satisfies the bounds documented
/// on the [`tower::Service`] implementation (see [`GuardService`]), which
/// includes `axum`'s `Router` (and therefore [`axum-guard-rs`]).
///
/// [`axum-guard-rs`]: https://github.com/rennf93/axum-guard-rs
///
/// # Example
///
/// ```
/// use tower::Layer;
/// use tower_guard_rs::GuardLayer;
///
/// let layer = GuardLayer::new(tower_guard_rs::default_config())
///     // Reject bodies larger than 1 MiB with 413 instead of buffering more.
///     .with_body_cap(1_048_576);
/// # let _ = layer;
/// ```
#[derive(Debug, Clone)]
pub struct GuardLayer {
    config: DetectConfig,
    body_cap: usize,
    ip_gate: Option<IpGateConfig>,
    detect_fn: DetectFn,
}

impl GuardLayer {
    /// Build a layer from an engine [`DetectConfig`].
    ///
    /// The body buffering cap starts at `config.max_full_scan_bytes`, and no
    /// IP gate is configured (one can be added with
    /// [`GuardLayer::with_ip_gate`]).
    #[must_use]
    pub fn new(config: DetectConfig) -> Self {
        Self {
            config,
            body_cap: config.max_full_scan_bytes,
            ip_gate: None,
            detect_fn: guard_core_engine::detect::detect,
        }
    }

    /// Build a layer with [`default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(default_config())
    }

    /// Replace the body buffering cap, in bytes.
    ///
    /// A body larger than the cap is rejected with `413 Payload Too Large`.
    /// A cap of `0` rejects every request that carries a non-empty body.
    #[must_use]
    pub fn with_body_cap(mut self, body_cap: usize) -> Self {
        self.body_cap = body_cap;
        self
    }

    /// Install the global IP gate: a `whitelist`/`blacklist`/`exempt_ips`
    /// config built with [`IpGateConfig::new`] (which fails closed on an
    /// invalid entry).
    ///
    /// The gate runs before body buffering and before detection: an IP on the
    /// `blacklist` is denied with `403 Forbidden`, and so is any IP when a
    /// non-empty `whitelist` matches neither it nor an `exempt_ips` entry. A
    /// passed request gets the gate's [`IpGateDecision`] inserted into the
    /// request extensions, so downstream handlers can read the skip state
    /// (`is_whitelisted` / `is_exempt`). The client IP comes from the
    /// [`GuardClientIp`] extension; a request without it is not attributed and
    /// goes through detection unconditionally - detection still screens every
    /// request, exempt or not.
    ///
    /// # Example
    ///
    /// ```
    /// use tower::Layer;
    /// use tower_guard_rs::{GuardLayer, IpGateConfig};
    ///
    /// let gate = IpGateConfig::new(
    ///     [] as [&str; 0],
    ///     ["203.0.113.9"],
    ///     ["198.51.100.0/28"],
    /// )
    /// .expect("valid lists");
    /// let layer = GuardLayer::new(tower_guard_rs::default_config()).with_ip_gate(gate);
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    pub(crate) const fn config(&self) -> &DetectConfig {
        &self.config
    }

    pub(crate) const fn body_cap(&self) -> usize {
        self.body_cap
    }

    pub(crate) const fn ip_gate(&self) -> Option<&IpGateConfig> {
        self.ip_gate.as_ref()
    }

    pub(crate) const fn detect_fn(&self) -> DetectFn {
        self.detect_fn
    }

    /// Substitute the detector. Test-only: exercises the fail-secure path.
    #[cfg(test)]
    pub(crate) fn with_detect_fn(mut self, detect_fn: DetectFn) -> Self {
        self.detect_fn = detect_fn;
        self
    }
}

impl<S> Layer<S> for GuardLayer {
    type Service = GuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GuardService::new(inner, self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_corpus_knobs() {
        let config = default_config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.binary_min_run_length, 16);
    }

    #[test]
    fn body_cap_defaults_to_full_scan_cap_and_is_overridable() {
        let layer = GuardLayer::new(default_config());
        assert_eq!(layer.body_cap(), 262_144);
        let layer = layer.with_body_cap(1024);
        assert_eq!(layer.body_cap(), 1024);
    }
}
