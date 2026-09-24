# Installation

## Requirements

- Rust 1.92 or later (the crate uses edition 2024)
- tower 0.5

## Add the crate

```bash
cargo add tower-guard-rs
```

or add it to your `Cargo.toml` directly:

```toml
[dependencies]
tower-guard-rs = "1.0.0"
tower = "0.5"
```

`tower-guard-rs` `1.0.0` depends on `guard-core-engine` `4.0.4`, the
published detection engine crate. The adapter's version pin stays in lockstep
with the published engine release.

## Verify the installation

A minimal program that wraps a tiny service with the guard layer:

```rust
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use std::convert::Infallible;
use tower::{Layer, Service, ServiceExt};

#[tokio::main]
async fn main() {
    let upstream = tower::service_fn(|_request: Request<Full<Bytes>>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("hello"))))
    });

    let mut service = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config())
        .layer(upstream);

    let request = Request::builder()
        .uri("/hello")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), 200);
}
```

A request with a malicious query string, for example
`/files/../../etc/passwd`, is blocked with `403 Forbidden` and a
`{"detail":"Suspicious activity detected"}` body.

## Building from source

The repository itself consumes the engine as a local path dependency on a
sibling `guard-core-rs` checkout (see the repository README), so building the
repository workspace locally requires that checkout to exist. Downstream
applications that depend on the published crate are not affected: crates.io
resolves `guard-core-engine` automatically.
