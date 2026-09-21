//! # tower-guard-rs
//!
//! Application-layer security middleware for
//! [tower](https://github.com/tower-rs/tower)-based services, part of the
//! [Guard ecosystem](https://github.com/rennf93). Works with any framework
//! built on `tower::Service`, including
//! [axum](https://github.com/tokio-rs/axum),
//! [hyper](https://github.com/hyperium/hyper), and
//! [warp](https://github.com/seanmonstar/warp).
//!
//! ## Status: scaffold
//!
//! This crate is an intentionally minimal scaffold. The Guard Rust engine
//! ([guard-core-rs](https://github.com/rennf93/guard-core-rs)) is not yet a
//! published, consumable crate, so there is no integration code here yet.
//! What this scaffold establishes is package metadata, CI governance, and
//! the integration contract documented below, so the engine can be wired in
//! with minimal friction.
//!
//! Per the ecosystem boundary rules, adapter crates hold all framework glue
//! and no security logic: detection, rate limiting, and IP policy live in
//! the engine, never here.
//!
//! ## Planned integration: `tower::Layer` + `tower::Service`
//!
//! The adapter will provide a `GuardLayer` implementing `tower::Layer`,
//! whose `layer` method wraps the inner service in a `GuardService`
//! implementing `Service<http::Request<B>>` for request bodies `B`. In
//! `call`, that service runs the Guard pipeline (IP reputation, rate
//! limiting, penetration-attempt detection, security headers) and either
//! short-circuits with a Guard-generated `http::Response` or forwards to
//! the inner service, inspecting the response on the way out. Unlike the
//! axum adapter, this crate stays framework-agnostic: it depends only on
//! tower and http types, so any tower-compatible stack can use it.
//!
//! The adapter will expose the layer roughly as follows (illustrative only;
//! the engine API does not exist yet):
//!
//! ```ignore
//! // Ignored on purpose: tower and http are not dependencies of this
//! // scaffold, so this example cannot compile yet. It documents the shape
//! // the integration will take.
//! use http::Request;
//! use tower::Layer;
//!
//! #[derive(Clone)]
//! pub struct GuardLayer {
//!     // engine configuration
//! }
//!
//! pub struct GuardService<S> {
//!     inner: S,
//! }
//!
//! impl<S> Layer<S> for GuardLayer {
//!     type Service = GuardService<S>;
//!
//!     fn layer(&self, inner: S) -> Self::Service {
//!         GuardService { inner }
//!     }
//! }
//! ```
//!
//! The `Service<Request<B>>` implementation for `GuardService` (not shown)
//! is where request inspection and short-circuiting happen.
//!
//! ## Placeholder API
//!
//! [`add`] exists only so the scaffold has a testable public symbol while
//! the real API surface is designed. It will be removed when the engine
//! integration lands.

/// Placeholder smoke-test symbol for the scaffold.
///
/// It exists only so the crate has a testable public item while the real
/// API surface is designed; it will be removed when the engine integration
/// lands.
///
/// # Example
///
/// ```
/// assert_eq!(tower_guard_rs::add(2, 2), 4);
/// ```
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
