//! Minimal guarded service: [`GuardLayer`] wrapped around a tiny hand-rolled
//! router, served over hyper.
//!
//! Routes:
//!
//! | Route | Guard | Behavior |
//! |---|---|---|
//! | `GET /health` | excluded | `200 ok`, served before the guard |
//! | `GET /` | guarded | `200` greeting |
//! | `GET /search?q=...` | guarded | `200`, or `400` when the query trips the engine |
//! | `POST /echo` | guarded | echoes the body, or `400`/`413` from the guard |
//!
//! The `/health` branch runs before the guard, mirroring the excluded-path
//! behavior the Python distro's pipeline provides for configured paths: the
//! adapter itself scans every request it sees, so exclusion is a routing
//! decision, not a guard option.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower::{Layer, Service};
use tower_guard_rs::{GuardBody, GuardLayer, GuardService, default_config};

/// The application listen address, overridable for container runs.
const DEFAULT_ADDR: &str = "0.0.0.0:8080";

/// The guard-generated or forwarded response body.
type GuardResponseBody = GuardBody<Full<Bytes>>;

/// Request body handed to the guard.
///
/// [`GuardService`] rebuilds the request body from buffered bytes after a
/// clean scan (`B: From<Bytes>`), and hyper hands us `Incoming` on the wire.
/// This enum satisfies both.
pub enum AppBody {
    /// The body as it arrived from the socket.
    Wire(Incoming),
    /// A body rebuilt from buffered bytes (or an empty body).
    Buffered(Full<Bytes>),
}

impl Body for AppBody {
    type Data = Bytes;
    type Error = tower_guard_rs::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Wire(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map_err(|error| Box::new(error) as tower_guard_rs::BoxError),
            Self::Buffered(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map_err(|error: std::convert::Infallible| match error {}),
        }
    }
}

impl From<Bytes> for AppBody {
    fn from(bytes: Bytes) -> Self {
        Self::Buffered(Full::new(bytes))
    }
}

/// The guarded application: the router wrapped in [`GuardLayer`], plus the
/// unguarded `/health` branch in front of it.
#[derive(Clone)]
struct App {
    guarded: GuardService<Router>,
}

impl Service<Request<AppBody>> for App {
    type Response = Response<GuardResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.guarded.poll_ready(cx)
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        // Excluded path: answered before the guard sees the request.
        if request.uri().path() == "/health" {
            let response = plain_response(StatusCode::OK, "ok\n");
            return Box::pin(async move { Ok(Response::map(response, GuardBody::Passthrough)) });
        }
        Box::pin(self.guarded.call(request))
    }
}

/// Maps hyper's wire body into [`AppBody`].
#[derive(Clone)]
struct BodyMapped {
    inner: App,
}

impl Service<Request<Incoming>> for BodyMapped {
    type Response = Response<GuardResponseBody>;
    type Error = Infallible;
    type Future = <App as Service<Request<AppBody>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        self.inner.call(request.map(AppBody::Wire))
    }
}

/// The tiny router the guard wraps.
#[derive(Clone, Copy)]
struct Router;

impl Service<Request<AppBody>> for Router {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = read_body(body).await;
            match (parts.method, parts.uri.path()) {
                (http::Method::GET, "/") => Ok(plain_response(
                    StatusCode::OK,
                    "tower-guard-rs simple app\n",
                )),
                (http::Method::GET, "/search") => Ok(plain_response(StatusCode::OK, "search ok\n")),
                (http::Method::POST, "/echo") => Ok(plain_response_bytes(StatusCode::OK, &bytes)),
                _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found\n")),
            }
        })
    }
}

async fn read_body(body: AppBody) -> Bytes {
    match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    }
}

fn plain_response(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    plain_response_bytes(status, text.as_bytes())
}

fn plain_response_bytes(status: StatusCode, bytes: &[u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(bytes)))
        .expect("static response parts")
}

#[tokio::main]
async fn main() {
    let addr: std::net::SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_string())
        .parse()
        .expect("APP_ADDR must be a socket address");

    let app = App {
        guarded: GuardLayer::new(default_config()).layer(Router),
    };

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {addr}: {error}"));
    eprintln!("tower-guard-rs simple app listening on {addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("accept failed: {error}");
                continue;
            }
        };
        let app = BodyMapped { inner: app.clone() };
        tokio::spawn(async move {
            let _ = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                .await;
        });
    }
}
