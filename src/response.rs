//! Short-circuit responses emitted by the guard.

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Response, StatusCode};
use http_body_util::Full;

/// Detail message carried by the `403 Forbidden` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500` response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

pub(crate) fn blocked() -> Response<Full<Bytes>> {
    plain_text(StatusCode::FORBIDDEN, BLOCKED_MESSAGE)
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
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, BLOCKED_MESSAGE);
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
