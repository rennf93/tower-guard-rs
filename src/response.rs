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
    json(StatusCode::FORBIDDEN, BLOCKED_MESSAGE)
}

pub(crate) fn oversize() -> Response<Full<Bytes>> {
    json(StatusCode::PAYLOAD_TOO_LARGE, OVERSIZE_MESSAGE)
}

pub(crate) fn failure() -> Response<Full<Bytes>> {
    json(StatusCode::INTERNAL_SERVER_ERROR, FAILURE_MESSAGE)
}

/// The ecosystem's JSON error shape: a `detail` field, `application/json`.
fn json(status: StatusCode, detail: &'static str) -> Response<Full<Bytes>> {
    let body = Bytes::from(format!(r#"{{"detail":"{detail}"}}"#));
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .expect("static status and header values are always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_response_shape() {
        let response = blocked();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "application/json"
        );
    }

    #[test]
    fn oversize_response_shape() {
        let response = oversize();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn failure_response_shape() {
        let response = failure();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
