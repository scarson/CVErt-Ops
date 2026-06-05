# Go performance module: HTTP servers & web frameworks (net/http / gin / echo / fiber / chi)
> Load when `net/http` HTTP servers, `github.com/gin-gonic/gin`, `github.com/labstack/echo`,
> `github.com/gofiber/fiber`, or `github.com/go-chi/chi` is detected — see the module map in
> `../go.md`. Core lanes + Runtime & GC notes live in `../go.md`; this file is the HTTP servers
> & web frameworks lens only.

## HTTP servers & web frameworks (net/http / gin / echo / fiber / chi)

> Scope: the stdlib `net/http` server and four popular routers/frameworks — gin (radix-tree,
> `net/http`-compatible), echo (radix-tree, `net/http`-compatible), fiber (fasthttp-based,
> NOT `net/http`-compatible), and chi (stdlib-compatible lightweight router). The recurring
> theme is unset production-safety defaults, per-request allocation in hot handlers, and
> blocking work that holds a goroutine — and for fiber, unique lifecycle rules on its pooled
> context and `[]byte` values that have no equivalent in the other frameworks.

- **`http.Server` with no timeouts set**: an `http.Server` literal with `ReadTimeout`,
  `WriteTimeout`, `ReadHeaderTimeout`, and `IdleTimeout` all at their zero values never times
  out slow or stalled clients; this admits Slowloris-style resource exhaustion and lets
  goroutines pile up indefinitely — look for `http.ListenAndServe(addr, handler)` or a bare
  `http.Server{}` struct without timeout fields set (verify against the currency brief for
  your version).

- **`http.Client` or `http.Transport` created per request**: constructing a new `http.Client`
  or `http.Transport` per call bypasses connection pooling entirely — each request opens a
  fresh TCP connection and performs a new TLS handshake; the correct pattern is one long-lived
  client reused across goroutines. Also check `MaxIdleConnsPerHost` on the shared transport:
  its default is low relative to the concurrency typical production backends need, leaving
  keep-alive slots underutilised under high fan-out (verify against the currency brief for
  your version). Additionally, look for handlers that read `resp.Body` but do not drain and
  close it — undrained bodies prevent the connection from returning to the pool
  (cross-reference the **Data access & I/O** lane in `../go.md`).

- **Per-request allocation in hot handlers**: handlers that re-compile a regexp, re-parse a
  template, or re-construct a heavy struct on each invocation pay a fixed per-call cost that
  compounds under concurrency — hoist the work to package scope or a `sync.Once`. Middleware
  chains that allocate (per-request loggers, per-request UUID generators writing to an
  allocated string) add GC pressure on every request; reuse buffers via `sync.Pool` where the
  allocation is bounded and short-lived (cross-reference the **Memory & allocation** lane in
  `../go.md`).

- **Reading `r.Body` fully into memory vs streaming**: handlers that call `io.ReadAll(r.Body)`
  or `ioutil.ReadAll(r.Body)` buffer the entire request body before processing, which bounds
  throughput by available memory and raises peak allocation under concurrent load; prefer
  `json.NewDecoder(r.Body).Decode(&v)` for JSON ingest or `io.Copy` to forward the body
  downstream — both stream without materialising the full body (cross-reference the
  **Memory & allocation** lane in `../go.md`).

- **Buffering the response instead of streaming**: handlers that `json.Marshal` into a `[]byte`
  and then call `w.Write(b)` allocate an intermediate buffer and delay the first byte to the
  client; `json.NewEncoder(w).Encode(v)` writes directly to the `ResponseWriter` and is both
  lower-allocation and lower-latency for large payloads. For large file responses, use
  `http.ServeContent` or `io.Copy` rather than reading the file into a buffer first. When
  true streaming is needed (SSE, chunked JSON arrays), verify that `w.(http.Flusher).Flush()`
  is called and that no buffering middleware wraps the writer (cross-reference the
  **Data access & I/O** lane in `../go.md`).

- **Blocking work on the request goroutine without context propagation**: handlers performing
  DB queries, outbound HTTP calls, or any other I/O without forwarding `r.Context()` to the
  downstream call cannot be cancelled when the client disconnects — the goroutine (and any
  held resources) run to completion regardless; pass `r.Context()` (or a child derived from
  it) into every blocking call so client-disconnect cancellation propagates
  (cross-reference the **Concurrency & parallelization** lane in `../go.md`).

- **Middleware ordering and blanket cost**: expensive middleware applied globally — per-request
  body logging with allocation, gzip compression on every response regardless of payload size,
  per-request tracing spans on non-instrumented routes — runs even on requests that exit early
  (health checks, 404s); for gin/echo/chi, scope heavy middleware to the route groups that
  need it rather than mounting at the root. For gzip specifically, compression is harmful on
  already-compressed payloads (images, video, pre-compressed static assets) and on tiny
  payloads where CPU cost exceeds transmission savings — check that a minimum-size threshold
  and a content-type allowlist are configured (verify against the currency brief for your
  version).

- **gin `Context` retention past the handler; fiber `*fiber.Ctx` and `[]byte` retention past
  the handler**: gin pools `*gin.Context` — retaining a pointer to it (e.g., in a goroutine
  launched inside the handler, or in a closure stored on a struct) causes a data race when the
  pool recycles the context for the next request; copy any needed values out before the handler
  returns or call `c.Copy()` for a heap-allocated snapshot. fiber is built on fasthttp and has
  a fundamentally different lifecycle: `*fiber.Ctx` and all `[]byte` values it exposes
  (`c.Body()`, `c.Params(...)` as bytes, header byte slices) are reused by the fasthttp
  allocator after the handler returns — retaining any of them across the handler boundary or
  in a launched goroutine corrupts data silently; copy to a `string` or a separately allocated
  `[]byte` before the handler exits. fiber's API is also NOT compatible with `net/http`
  middleware or `context.Context` propagation patterns used by gin/echo/chi — stdlib-ecosystem
  middleware cannot be reused directly (verify against the currency brief for your version).

- **`MaxHeaderBytes` unset and HTTP/2 / h2c not intentionally configured**: the default
  `MaxHeaderBytes` on `http.Server` is permissive; leaving it unset allows clients to send
  very large header blocks that consume memory before the handler runs — set it explicitly for
  public-facing servers. For services behind a proxy that already terminates TLS, evaluate
  whether `h2c` (cleartext HTTP/2 via `golang.org/x/net/http2/h2c`) is appropriate to regain
  multiplexing and header compression on the internal leg; and for TLS servers, confirm that
  HTTP/2 is enabled (it is by default when using `ListenAndServeTLS` with a compatible
  handler, but custom `tls.Config` can inadvertently disable it) (verify against the currency
  brief for your version).
