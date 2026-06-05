# Go performance module: gRPC (grpc-go / protobuf)
> Load when `google.golang.org/grpc` or `google.golang.org/protobuf` (`.proto` files / generated `*.pb.go`) is detected — see the module map in `../go.md`. Core lanes + Runtime & GC notes live in `../go.md`; this file is the gRPC lens only.

## gRPC (grpc-go / protobuf)

> Covers **grpc-go** (`google.golang.org/grpc`), its protobuf runtime
> (`google.golang.org/protobuf`), and **connect-go** as a sibling transport where relevant.
> Bullets are *conditions to look for*. The recurring themes are `ClientConn` reuse across
> calls, streaming or batch RPCs to cut per-call round-trips, message sizing relative to
> compression and the default receive limit, and per-RPC deadline discipline.

- **`grpc.ClientConn` created per-call or per-request**: a `ClientConn` negotiates TLS, runs
  HTTP/2 connection setup, starts background health-check and keepalive goroutines, and
  multiplexes many concurrent RPCs on a single TCP connection — it is expensive to establish
  and fully goroutine-safe. Creating one per RPC (or per inbound request) serializes connection
  setup, blows the goroutine budget, and prevents HTTP/2 multiplexing gains. Reuse a
  long-lived singleton (or a small keyed pool for distinct targets) and let the channel
  manage its own subchannels (verify against the currency brief for your version).

- **Unary RPC in a loop instead of streaming or a batch message**: calling a unary RPC once
  per item pays per-call framing, header compression, and a full round-trip each iteration.
  Use **client/server streaming** (or a repeated-field batch request) to amortize that cost —
  the stream establishes call state once and pipelines messages without re-incurring the RPC
  handshake per item. In connect-go, the same tradeoff applies via `Connect` streaming
  handlers (verify against the currency brief for your version).

- **Single `ClientConn` behind an L4 load balancer with no resolver/balancer configured**: a
  single HTTP/2 connection pins all RPCs to one backend TCP connection, bypassing the LB
  entirely — all traffic lands on one server. Configure a proper gRPC resolver and a
  client-side balancer (e.g., `roundrobin` via `grpc.WithDefaultServiceConfig`) so each
  subchannel can reach a distinct backend, or use a look-aside LB. Verify what resolver the
  target URI scheme maps to and whether `round_robin` is the right policy for the deployment
  (verify against the currency brief for your version).

- **Message size bumped past the default receive limit, or large payloads not streamed**:
  `MaxRecvMsgSize` defaults to 4 MiB (verify against the currency brief for your version);
  silently hitting it produces an error rather than a performance degradation, but the common
  "fix" of raising it masks the real problem. Large payloads should stream in chunks rather
  than be buffered as a single proto message — this bounds memory on both ends and avoids
  forcing the GC to reclaim one giant allocation per call (cross-reference the core **Memory &
  allocation** lane). Also look for repeated marshal/unmarshal of the same proto value in the
  same request path — proto marshal allocates; reuse message objects where the code flow
  allows.

- **Compression applied indiscriminately or absent for large payloads**: gRPC gzip
  (`grpc.UseCompressor(gzip.Name)` on the call, or `grpc.WithDefaultCallOptions` on the
  client) compresses every message — beneficial for large text-heavy protos over WAN but
  wastes CPU on small messages or already-compressed binary content. Conversely, leaving
  compression off for multi-KB payloads over metered or high-latency links wastes bandwidth.
  Match compression to median payload size and link characteristics; the `zstd` compressor
  (if registered) often gives a better speed/ratio tradeoff than gzip (verify against the
  currency brief for your version).

- **Keepalive parameters mistuned for the network environment**: absent keepalive, idle
  `ClientConn`s through NAT or cloud LBs silently drop — the next RPC fails with a transport
  error instead of probing and reconnecting. Conversely, `keepalive.ClientParameters` with
  a very short `Time` or `Timeout` trips the server's `keepalive.EnforcementPolicy`
  (minimum ping interval) and causes GOAWAY / ENHANCE_YOUR_CALM, churning connections.
  Look for `keepalive.ClientParameters` / `keepalive.ServerParameters` absent or with
  `Time` shorter than the server's `MinTime` enforcement (verify against the currency brief
  for your version).

- **RPCs launched without a `context` deadline or without deadline propagation**: a unary or
  streaming RPC started with `context.Background()` (no deadline attached) can block its
  goroutine indefinitely if the server stalls — the goroutine is leaked until the process
  exits. Always derive a per-call context with `context.WithTimeout` or
  `context.WithDeadline`, and propagate an inbound deadline downstream rather than
  substituting a fresh one. A missing deadline also means the server cannot detect
  client-side cancellation and may do wasted work (cross-reference the core **Concurrency &
  parallelization** lane).

- **Heavy per-RPC interceptor allocations or deep interceptor chains**: unary and stream
  interceptors run on every RPC. Interceptors that allocate a `map`, `[]string`, or log
  buffer per call add steady GC pressure at high QPS. Order matters too — auth interceptors
  that reject unauthenticated calls placed *after* expensive tracing interceptors do work
  that will be discarded. Look for interceptors that marshal/unmarshal the full message for
  logging, or that call `fmt.Sprintf` / structured-log functions constructing transient
  objects on every RPC (cross-reference the core **Memory & allocation** lane).

- **Unbounded per-RPC goroutine work with no concurrency cap**: grpc-go spawns one goroutine
  per inbound RPC stream; `MaxConcurrentStreams` (verify against the currency brief for your
  version) caps streams per connection but not total across connections. Expensive
  synchronous work inside a server handler (DB queries, downstream RPCs, heavy CPU) with no
  semaphore or worker-pool limit lets high inbound RPS exhaust goroutine memory and
  downstream connection pools simultaneously. Apply a semaphore or bounded worker pool for
  downstream fan-out, and propagate context cancellation so work is shed when the caller
  has already given up (cross-reference the core **Concurrency & parallelization** lane).
