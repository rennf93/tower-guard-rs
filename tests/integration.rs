//! End-to-end behavior of the public API: `GuardLayer` wrapping real
//! services, exercised with `tower::ServiceExt::oneshot`.

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode, header::HeaderName};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::util::BoxCloneService;
use tower::{Layer, Service, ServiceExt};
use tower_guard_rs::{
    BLOCKED_MESSAGE, FAILURE_MESSAGE, GuardLayer, OVERSIZE_MESSAGE, default_config,
};

type Echo = BoxCloneService<Request<Full<Bytes>>, Response<Full<Bytes>>, Infallible>;

/// An inner service that echoes `method path header-value body`, so tests can
/// assert that the guard forwards the request untouched.
fn echo() -> Echo {
    BoxCloneService::new(tower::service_fn(
        |request: Request<Full<Bytes>>| async move {
            let (parts, body) = request.into_parts();
            let body = body.collect().await.expect("body").to_bytes();
            let custom = parts
                .headers
                .get("x-custom")
                .map(|value| value.to_str().expect("ascii").to_owned())
                .unwrap_or_default();
            let echo = format!(
                "{} {} {custom} {}",
                parts.method,
                parts.uri.path(),
                String::from_utf8_lossy(&body)
            );
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(echo))))
        },
    ))
}

async fn body_text<B>(response: Response<B>) -> String
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + std::fmt::Debug,
{
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn get(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Full::new(Bytes::new()))
        .expect("request")
}

fn post(path: &str, body: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("request")
}

#[tokio::test]
async fn benign_request_passes_through_untouched() {
    let mut service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/items?limit=5")
        .header("x-custom", "hello")
        .body(Full::new(Bytes::from_static(b"{\"name\":\"renn\"}")))
        .expect("request");

    let response = service.ready().await.expect("ready").call(request).await;
    let response = response.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        "POST /api/items hello {\"name\":\"renn\"}"
    );
}

#[tokio::test]
async fn xss_payload_in_body_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let response = service
        .oneshot(post("/api/comment", "<script>alert(1)</script>"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "text/plain; charset=utf-8"
    );
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn traversal_payload_in_path_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let response = service
        .oneshot(get("/files/../../etc/passwd"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn command_injection_in_query_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let response = service
        .oneshot(get("/search?cmd=$(whoami)"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn xss_payload_in_scanned_header_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("x-comment", "<script>alert(1)</script>")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn excluded_headers_are_never_scanned() {
    // `User-Agent` is on the exclusion list, so even a value that looks like a
    // payload is not fed to the engine. This pins the documented policy.
    let service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("user-agent", "<script>alert(1)</script>")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn body_over_the_cap_is_rejected_with_413() {
    let layer = GuardLayer::new(default_config()).with_body_cap(16);
    let service = layer.layer(echo());
    let response = service
        .oneshot(post(
            "/api/items",
            "this body is much longer than sixteen bytes",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_text(response).await, OVERSIZE_MESSAGE);
}

#[tokio::test]
async fn body_under_the_cap_is_forwarded_intact() {
    let layer = GuardLayer::new(default_config()).with_body_cap(16);
    let service = layer.layer(echo());
    let response = service
        .oneshot(post("/api/items", "short but valid"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        "POST /api/items  short but valid"
    );
}

#[tokio::test]
async fn body_read_error_fails_secure_with_500() {
    // A body that yields one frame, then errors.
    struct FailingBody {
        yielded: bool,
    }

    impl http_body::Body for FailingBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.yielded {
                return Poll::Ready(Some(Err(io::Error::other("body blew up"))));
            }
            self.yielded = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"hi")))))
        }
    }

    // Required by the `Service` bounds; never reached because the body errors.
    impl From<Bytes> for FailingBody {
        fn from(_bytes: Bytes) -> Self {
            Self { yielded: false }
        }
    }

    let service = GuardLayer::new(default_config()).layer(BoxCloneService::new(tower::service_fn(
        |_request: Request<FailingBody>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                b"never reached",
            ))))
        },
    )));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/items")
        .body(FailingBody { yielded: false })
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_text(response).await, FAILURE_MESSAGE);
}

#[tokio::test]
async fn inner_service_errors_are_propagated_not_swallowed() {
    let service = GuardLayer::new(default_config()).layer(BoxCloneService::new(tower::service_fn(
        |_request: Request<Full<Bytes>>| async {
            Err::<Response<Full<Bytes>>, _>(io::Error::other("upstream down"))
        },
    )));
    let error = service
        .oneshot(get("/health"))
        .await
        .expect_err("inner error must propagate");
    assert_eq!(error.to_string(), "upstream down");
}

#[tokio::test]
async fn concurrent_requests_are_screened_independently() {
    let service = GuardLayer::new(default_config()).layer(echo());

    let handles: Vec<_> = (0..24)
        .map(|index| {
            let service = service.clone();
            tokio::spawn(async move {
                let request = if index % 2 == 0 {
                    get("/health")
                } else {
                    post("/api/comment", "<script>alert(1)</script>")
                };
                service.oneshot(request).await.expect("response").status()
            })
        })
        .collect();

    for (index, handle) in handles.into_iter().enumerate() {
        let status = handle.await.expect("task");
        if index % 2 == 0 {
            assert_eq!(status, StatusCode::OK, "benign request {index}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "threat request {index}");
        }
    }
}

#[tokio::test]
async fn poll_ready_forwards_to_the_inner_service() {
    let mut service = GuardLayer::new(default_config()).layer(echo());
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Service::poll_ready(&mut service, &mut cx) {
        std::task::Poll::Ready(result) => result.expect("ready"),
        std::task::Poll::Pending => panic!("echo service is always ready"),
    }
}

#[tokio::test]
async fn custom_header_name_is_case_insensitive_on_the_exclusion_list() {
    // `HeaderMap` normalizes names to lowercase; scanning decisions must not
    // depend on the casing the client sent.
    let service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("X-Custom", "benign value")
        .header(HeaderName::from_static("user-agent"), "guard-tests/0.1")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}
