# Rust performance module: Web frameworks (axum / actix-web / hyper)
> Load when a Rust HTTP server is detected — `axum`, `actix-web`, `warp`, `hyper`, `tower`/`tower-http` — see the module map in `../rust.md`. Core lanes + Runtime & build notes live in `../rust.md`; this file is the Web frameworks lens only.

## Web frameworks (axum / actix-web / hyper)

> Scope: the request path through axum, actix-web, warp, and the underlying hyper/tower stack. The
> recurring theme is: share state through `Arc` (not deep-clone), reuse connection pools and clients
> built at startup, keep the per-request extractor and middleware chain lean, stream rather than buffer
> large bodies and responses, and never block the async executor. Failures here compound linearly with
> concurrency — each footgun that costs 1 ms at 1 req/s costs 1 s of executor time at 1000 req/s.

- **Application state cloned per-request without `Arc`**: axum's `State<S>` and actix-web's
  `Data<T>` clone the inner value on every request dispatch. If `S`/`T` is a large struct that
  derives `Clone`, every request performs a deep copy — config maps, client handles, caches and all.
  The correct idiom is `State<Arc<AppState>>`/`Data<Arc<AppState>>`: the clone is a single atomic
  refcount increment (verify against the currency brief for your version).

- **HTTP client or connection pool built inside a handler**: constructing a `reqwest::Client`, a
  database pool, or any resource that owns TCP connections inside a handler rebuilds the pool on
  every request — paying TLS handshake and allocator cost each time. Build once at startup and share
  via state; cross-reference the `database` module for pool-sizing guidance and the **Data access &
  I/O** lane in `../rust.md` for the general missing-pooling signal (verify against the currency
  brief for your version).

- **Extractor ordering and the cost of body extraction**: axum and actix-web run extractors in
  declaration order; a body extractor (`Json<T>`, `Bytes`, `String`) must buffer and deserialize the
  entire request body before the handler is entered — cross-reference the `serde-serialization`
  module for deserialization cost. Cheap rejection extractors (auth token, `Content-Type` guard,
  content-length limit) should precede body extractors in the parameter list so malformed or
  unauthorized requests are rejected before the expensive read occurs (verify against the currency
  brief for your version).

- **Tower middleware applied globally rather than scoped**: every `tower`/`tower-http` layer (tracing
  span allocation, per-request auth DB lookup, compression, request logging) wraps every request that
  reaches the router, including health checks and 404 paths. Heavy per-request work in a global layer
  compounds at scale; scope layers to the specific route groups or services that need them using axum
  `Router::layer` vs `Router::route_layer` semantics (verify against the currency brief for your
  version).

- **Buffering large request bodies or responses in memory**: reading an entire request body into
  `Bytes` or `String` before processing, or assembling a large response `Vec<u8>` before writing,
  spikes resident memory proportional to body size × concurrency. Use `axum::body::Body` streaming
  /`StreamBody` for large uploads, chunked response bodies for large payloads, and configure a
  `RequestBodyLimit` layer to bound maximum inbound allocation and prevent unbounded-allocation DoS
  (verify against the currency brief for your version).

- **Blocking or CPU-bound work executed directly in an async handler**: CPU-intensive work (image
  transformation, cryptographic operations, large serialization batches) or synchronous I/O called
  from inside `.await`-able handler code blocks the Tokio worker thread for the duration, starving
  other tasks; cross-reference the **Concurrency** lane in `../rust.md` and the `async-tokio` module
  — offload via `tokio::task::spawn_blocking` or hand off to a `rayon` pool (verify against the
  currency brief for your version).

- **actix-web's per-worker state duplication**: actix-web runs N independent single-threaded workers,
  each initialized with its own copy of the app factory closure; `Data<T>` is internally an
  `Arc<T>`, so pointer-sharing across workers is correct — but if the factory closure constructs
  fresh resources (a new pool, a new in-memory cache) per worker rather than cloning an `Arc` built
  once before `HttpServer::new`, each worker holds a separate, non-coordinated resource instance.
  `!Send` types are permissible per-worker but cannot be shared; anything that must be shared across
  workers needs `Arc`-wrapped thread-safe types (verify against the currency brief for your version).

- **`Json(value)` response serialization on every hot response**: returning `Json(value)` in axum or
  actix-web re-serializes the value on every response; for payloads that are static or infrequently
  changing this is avoidable overhead — cross-reference the `serde-serialization` module for
  serialization cost signals. Consider caching pre-serialized `Bytes` for reference data, applying
  field projection/pagination to large collection responses, and measuring whether `simd-json` or
  a pre-serialized pool wins on your hot path (verify against the currency brief for your version).

- **Missing request timeouts and no keep-alive/HTTP2 consideration**: a hyper/tower server with no
  timeout layer lets a slow or stalled client pin a task and its associated memory for an unbounded
  duration; `tower-http`'s `TimeoutLayer` or `tower::ServiceBuilder` timeout bounds this. Separately,
  HTTP/1.1 keep-alive and HTTP/2 multiplexing (available through hyper's native HTTP/2 support)
  reduce per-request connection setup cost on high-fanout paths; verify that your deployment topology
  allows each and that TLS configuration does not inadvertently disable negotiation (verify against
  the currency brief for your version).
