//! Short-circuit responses emitted by the guard.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, RETRY_AFTER};
use http::{Response, StatusCode};
use http_body_util::Full;

/// Detail message carried by the `400 Bad Request` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the IP gate's `403 Forbidden` response.
pub const FORBIDDEN_MESSAGE: &str = "Forbidden";

/// Detail message carried by the ban stage's `403 Forbidden` response.
pub const BANNED_MESSAGE: &str = "IP address banned";

/// Detail message carried by the `403 Forbidden` response when a detected
/// threat crossed an auto-ban threshold and the ban fired on this request.
pub const ACTIVITY_BANNED_MESSAGE: &str = "IP has been banned";

/// Detail message carried by the `429 Too Many Requests` response.
pub const RATE_LIMITED_MESSAGE: &str = "Too many requests";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500` response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

pub(crate) fn blocked() -> Response<Full<Bytes>> {
    plain_text(StatusCode::BAD_REQUEST, BLOCKED_MESSAGE)
}

pub(crate) fn forbidden() -> Response<Full<Bytes>> {
    plain_text(StatusCode::FORBIDDEN, FORBIDDEN_MESSAGE)
}

/// The ban stage's denial: a live ban on the client IP.
pub(crate) fn banned_ip() -> Response<Full<Bytes>> {
    plain_text(StatusCode::FORBIDDEN, BANNED_MESSAGE)
}

/// The auto-ban engine's denial: the detected threat crossed a threshold and
/// the ban fired on this very request.
pub(crate) fn activity_banned() -> Response<Full<Bytes>> {
    plain_text(StatusCode::FORBIDDEN, ACTIVITY_BANNED_MESSAGE)
}

/// The rate limiter's denial, carrying `Retry-After: <window seconds>` the
/// way the references do.
pub(crate) fn rate_limited(retry_after: u64) -> Response<Full<Bytes>> {
    let mut response = plain_text(StatusCode::TOO_MANY_REQUESTS, RATE_LIMITED_MESSAGE);
    if let Ok(value) = retry_after.to_string().parse() {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

pub(crate) fn oversize() -> Response<Full<Bytes>> {
    plain_text(StatusCode::PAYLOAD_TOO_LARGE, OVERSIZE_MESSAGE)
}

pub(crate) fn failure() -> Response<Full<Bytes>> {
    plain_text(StatusCode::INTERNAL_SERVER_ERROR, FAILURE_MESSAGE)
}

/// The ecosystem's error shape: the bare message as the body,
/// `text/plain; charset=utf-8` (same as the Python family).
fn plain_text(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(message.as_bytes())))
        .expect("static status and header values are always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_bytes<B>(body: B) -> Bytes
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        body.collect().await.expect("body").to_bytes()
    }

    #[tokio::test]
    async fn blocked_response_shape() {
        let response = blocked();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, BLOCKED_MESSAGE);
    }

    #[tokio::test]
    async fn forbidden_response_shape() {
        let response = forbidden();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, FORBIDDEN_MESSAGE);
    }

    #[tokio::test]
    async fn banned_response_shape() {
        let response = banned_ip();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_bytes(response.into_body()).await, BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn activity_banned_response_shape() {
        let response = activity_banned();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_bytes(response.into_body()).await,
            ACTIVITY_BANNED_MESSAGE
        );
    }

    #[tokio::test]
    async fn rate_limited_response_shape_carries_retry_after() {
        let response = rate_limited(90);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(RETRY_AFTER).expect("retry after"),
            "90"
        );
        assert_eq!(body_bytes(response.into_body()).await, RATE_LIMITED_MESSAGE);
    }

    #[tokio::test]
    async fn oversize_response_shape() {
        let response = oversize();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, OVERSIZE_MESSAGE);
    }

    #[tokio::test]
    async fn failure_response_shape() {
        let response = failure();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, FAILURE_MESSAGE);
    }
}
