# S10 Platform/infra glue — memory & allocation audit

**Date:** 2026-06-05
**Scope:** `cmd/cvert-ops/main.go`, `cmd/healthcheck/**`, `internal/{config,crypto,doctor,metrics,dbutil,log}/**`, `internal/api/{server,cors,readyz,spa,contract,metrics_middleware,log_middleware,middleware_cache,context}.go`, `internal/api/{feeds,ingest}.go`
**Lane:** memory & allocation

---

## Summary

Two genuine per-request allocation issues found on the hot API path. Startup allocations, health-probe handlers, and cold/worker paths are clean. The SPA handler's probe-then-serve double-open is low-frequency due to immutable caching on hashed assets. The rest of the glue (config, crypto, doctor, metrics definitions, dbutil) carries no per-request allocation concerns.

---

### MINOR Per-request `slog.Logger` heap allocation in `contextLoggerMiddleware`

**Location:** `internal/api/log_middleware.go:19`, `internal/log/context.go:27`

**Problem:** Every incoming request that has a `request_id` (i.e., all requests — `middleware.RequestID` always generates one) triggers `logpkg.Enrich(ctx, "request_id", reqID)`, which calls `slog.Logger.With(key, value)`. `slog.Logger.With` is documented to allocate and return a new `*slog.Logger` backed by a new handler that wraps the previous one with an extra attribute. The result is stored via `context.WithValue`, which allocates a new context node. Combined with the `r.WithContext(ctx)` call that follows (a shallow `*http.Request` copy), this chain produces three allocations on every request — the enriched logger, the context node, and the request copy — even on requests that never call `log.FromContext` (i.e., on any request that returns quickly without hitting an error path).

**Impact:** Hits every request on both the API sub-router and the health/infra routes. At modest load (1 000 req/s) these three small allocations add ~3 000 short-lived objects/s to the GC's write barrier and scanning workload. The objects are small (logger: ~64 bytes; context node: ~32 bytes; request copy: ~240 bytes) so the absolute heap pressure is low, but the allocation rate is not. The cost is proportional to request throughput and is purely overhead — the enriched logger is discarded on the majority of requests that complete without logging.

**Confidence:** Strong-static

**Effort:** Localized — the `contextLoggerMiddleware` function and `logpkg.Enrich` are small; the change is scoped to one middleware function.

**Verification plan:** Defer logger construction: store the raw `request_id` string directly on the context using a typed key, and build the enriched `*slog.Logger` lazily inside `log.FromContext` only on first call. This eliminates the per-request `Logger.With` and context node allocation for requests that never call `FromContext`. Correctness guard: the existing `TestEnrich_AddsField` and `TestWithLogger_RoundTrip` tests in `internal/log/context_test.go` pin the API; a new test should verify that `FromContext` on a context carrying only a raw request ID returns a logger already enriched with that ID.

---

### MINOR Per-request `statusWriter` struct allocation and `strconv.Itoa` string allocation in `httpMetricsMiddleware`

**Location:** `internal/api/metrics_middleware.go:39,48`

**Problem:** For every API request, the middleware allocates `&statusWriter{ResponseWriter: w, code: http.StatusOK}` to intercept the status code, then calls `strconv.Itoa(sw.code)` to produce a string label for Prometheus. `strconv.Itoa` always allocates a new string (there is no small-integer pool in Go's stdlib). HTTP status codes are limited to a small, fixed set (200, 201, 400, 401, 403, 404, 422, 429, 500, 503, …), so the same string is re-allocated thousands of times per second.

**Impact:** Two allocations per API request. The `statusWriter` struct is two pointer fields (~16 bytes on 64-bit); the status code string is 3 bytes. Both are short-lived. At 1 000 API req/s these add ~2 000 small allocations/s. The impact is low in absolute terms but the fix is trivial.

**Confidence:** Strong-static

**Effort:** Localized — `httpMetricsMiddleware` is a single function; the fix is a small status-code string lookup table (e.g., `var statusText = map[int]string{200:"200", 201:"201", ...}`) replacing `strconv.Itoa`. The `statusWriter` can be pooled with `sync.Pool` if profiling later shows GC pressure from it, though that is a lower-priority follow-up.

**Verification plan:** Replace `strconv.Itoa(sw.code)` with a precomputed string lookup for the ~10 status codes the API actually returns; fall back to `strconv.Itoa` for unexpected codes. Allocations for the common-path status codes drop to zero. Correctness guard: `TestHTTPMetricsMiddleware` (or an equivalent integration test that exercises the middleware) must confirm label values are unchanged.

---

## Suspected Bugs (for follow-up)

None.
