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
| `.with_ip_gate(ip_gate: IpGateConfig)` | Install the global IP gate (see below) |

### `GuardClientIp`

The extension type the IP gate reads the client IP from:

```rust
pub struct GuardClientIp(pub IpAddr);
```

The tower `Service` surface is framework-neutral, so nothing inserts it
automatically. axum applications map `ConnectInfo<SocketAddr>` into it
(axum-guard-rs ships `client_ip_layer()` for exactly that); a proxy frontend
can insert its resolved client IP instead. A request without the extension is
not attributed: the gate does not run, and detection still screens the
request.

### The IP gate: `IpGateConfig`

Built with `IpGateConfig::new(whitelist, blacklist, exempt_ips)`, which fails
closed on an invalid entry (`IpGateError` names the list and the entry):

```rust
use tower_guard_rs::IpGateConfig;

let gate = IpGateConfig::new(
    [] as [&str; 0],
    ["203.0.113.9"],
    ["198.51.100.7", "198.51.100.16/28"],
)
.expect("valid lists");
let layer = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config())
    .with_ip_gate(gate);
```

Evaluation order mirrors the reference engine: with a non-empty `whitelist`,
an IP matching neither the whitelist nor `exempt_ips` is denied; otherwise a
`blacklist` hit is denied. Both denials answer `403 Forbidden` with
`Forbidden` before body buffering. A passed request gets an
`IpGateDecision { is_whitelisted, is_exempt }` inserted into its request
extensions so downstream handlers can read the skip state.

**exempt_ips vs whitelist.** `exempt_ips` is noise reduction for
known-friendly automation (monitoring probes, VPN egress, a partner's
server), not immunity: it sets the same skip state a whitelist match sets but
never adds a deny path, and it never opens the whitelist gate. The blacklist,
route rules, and detection still apply to exempt IPs - an attack payload from
an exempt IP is still `403 Suspicious activity detected`. The Rust family
ships no rate limiter, user-agent filter, cloud-provider blocker, or
violation counter yet; a stage that lands later must skip exactly what the
reference skips for a whitelist match (`is_whitelisted || is_exempt`) and
never skip detection.

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
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
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
| `FORBIDDEN_MESSAGE` | `"Forbidden"` |
| `OVERSIZE_MESSAGE` | `"Payload too large"` |
| `FAILURE_MESSAGE` | `"Security check failed"` |

### Engine re-exports

`DetectConfig`, `DetectVerdict`, and `Threat` are re-exported from
`guard_core_engine::detect`. A `DetectVerdict` carries `is_threat`, a
`threat_score`, and the list of `Threat` findings (regex or semantic).

`IpGateConfig`, `IpGateDecision`, `IpGateDenial`, `IpGateError`, and
`IpGateVerdict` are re-exported from `guard_core_engine::ip_gate`.
