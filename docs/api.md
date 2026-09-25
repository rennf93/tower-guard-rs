# API reference

The public surface of `tower_guard_rs` `1.0.0`. The full crate documentation
is also in `src/lib.rs` (build it with `cargo doc --open`).

## Middleware

### `GuardLayer`

The tower layer entry point. It implements `tower::Layer` over
`http::Request<B>`; wrap any `Service<Request<B>>` with
`Layer::layer`:

```rust
use tower::Layer;

let layer = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config());
let service = layer.layer(my_service);
```

Constructors and builders:

| Method | Description |
|---|---|
| `GuardLayer::new(config: DetectConfig)` | Build a layer from an engine `DetectConfig`. The body buffering cap starts at `config.max_full_scan_bytes` |
| `GuardLayer::with_defaults()` | Build a layer with `default_config()` |
| `.with_body_cap(body_cap: usize)` | Replace the body buffering cap, in bytes. A body larger than the cap is rejected with `413`. A cap of `0` rejects every request that carries a non-empty body |

### `GuardService`

The `tower::Service` produced by `GuardLayer`. It screens a
`http::Request<B>` by running one engine call per request view and, on a
clean pass, hands the inner service a rebuilt request whose body is
byte-identical to what the client sent (bodies are buffered under the cap and
rebuilt via `B: From<Bytes>`). The inner service must be `Clone + Send`
(tower's standard `Buffer`-style sharing).

### `GuardBody`

The response body type emitted by `GuardService`, nameable because it
appears in the service's `Response` association:

```rust
pub enum GuardBody<B> {
    Passthrough(B),
    Generated(Full<Bytes>),
}
```

Either the inner service's response body, forwarded untouched (`Passthrough`),
or a Guard-generated plain-text body for a short-circuited response (`403`,
`413`, or `500`, `Generated`). It implements `http_body::Body`.

### `BoxError`

`Box<dyn Error + Send + Sync>`, the boxed error type used by `GuardBody`.
Identical to `tower::BoxError`; redefined so the body type does not force a
`tower` re-export onto downstream type signatures.

## Configuration

### `default_config()`

Returns the reference default `DetectConfig`:

| Knob | Value |
|---|---|
| `max_content_length` | `10_000` |
| `max_full_scan_bytes` | `262_144` |
| `preserve_attack_patterns` | `true` |
| `semantic_threshold` | `0.7` |
| `threat_score_threshold` | `1.0` |

### `DetectConfig`

Re-exported from `guard_core_engine::detect`. Fields:

| Field | Type | Meaning |
|---|---|---|
| `max_content_length` | `usize` | Semantic budget and truncation budget |
| `max_full_scan_bytes` | `usize` | Preprocessor full-scan cap (also the default body cap) |
| `preserve_attack_patterns` | `bool` | Keep attack patterns in the processed view |
| `semantic_threshold` | `f64` | Semantic analysis threshold |
| `threat_score_threshold` | `f64` | Threat score threshold for a verdict |

## Behavior

### What it inspects

One engine call per request view:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not scanned.

### Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `403 Forbidden` | `Suspicious activity detected` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The adapter is fail-secure: any failure to complete the security check
answers `500`, never an uninspected passthrough. Engine panics are caught
with `catch_unwind` (note that `panic = "abort"` in a release profile
disables that recovery).

### Constants

Re-exported refusal message bodies:

| Constant | Value |
|---|---|
| `BLOCKED_MESSAGE` | `"Suspicious activity detected"` |
| `OVERSIZE_MESSAGE` | `"Payload too large"` |
| `FAILURE_MESSAGE` | `"Security check failed"` |

### Engine re-exports

`DetectConfig`, `DetectVerdict`, and `Threat` are re-exported from
`guard_core_engine::detect`. A `DetectVerdict` carries `is_threat`, a
`threat_score`, and the list of `Threat` findings (regex or semantic).
