# S10 Platform/Infra Glue — Algorithmic Lane
**Date:** 2026-06-05
**Slice:** S10 — binary init, config, crypto setup, doctor checks, metrics, server wiring, global middleware
**Lane:** algorithmic

## Scope examined

- `cmd/cvert-ops/main.go`, `cmd/healthcheck/main.go`
- `internal/config/config.go`, `internal/config/reload.go`, `internal/config/reloadable.go`
- `internal/crypto/aes.go`
- `internal/doctor/doctor.go`, `internal/doctor/checks.go`
- `internal/metrics/` (all files)
- `internal/dbutil/null.go`
- `internal/log/context.go`
- `internal/api/server.go`, `internal/api/cors.go`, `internal/api/context.go`
- `internal/api/metrics_middleware.go`, `internal/api/log_middleware.go`
- `internal/api/middleware_cache.go`, `internal/api/middleware_csrf.go`
- `internal/api/middleware_auth.go`, `internal/api/middleware_apikey_query.go`
- `internal/api/middleware_rbac.go`
- `internal/api/feeds.go`, `internal/api/ingest.go`
- `internal/api/contract.go`, `internal/api/openapi_spec.go`
- `internal/secure/events.go`

---

## Findings

### MINOR — `rejectAPIKeyQueryParams` parses and allocates a full query-map on every request, including those with no query string

**Location:** `internal/api/middleware_apikey_query.go:37-49`

**Problem:** The middleware calls `r.URL.Query()` unconditionally on every request. `url.Values.Query()` parses the raw query string and allocates a `map[string][]string` on each call — even when the query string is empty. This allocation is then followed by a nested O(Q × 8) scan: for every query parameter in the request (Q), the inner loop walks all 8 entries in `sensitiveQueryParams` and calls `strings.ToLower` on each parameter name. The majority of API requests — authenticated GETs and POSTEDs JSON bodies — carry either zero query parameters (no parse needed at all) or a small number like `cursor`, `limit`, `status` that cannot match the sentinel list.

```go
query := r.URL.Query()            // allocates map[string][]string unconditionally
for param, values := range query {
    lower := strings.ToLower(param)
    for _, sensitive := range sensitiveQueryParams { // O(Q × 8)
        if lower == sensitive && hasNonEmptyValue(values) {
```

**Impact:** Reachability: every request through the `/api/v1` sub-router — this middleware is registered globally via `apiRouter.Use(rejectAPIKeyQueryParams)`. Frequency: every API request. Per-occurrence cost: one heap allocation (the `url.Values` map) plus 8 string comparisons per query parameter. For zero-query-string requests the allocation is wasted entirely. For busy deployments this is a steady drip of garbage that the GC must collect.

A fast-path guard — check `r.URL.RawQuery == ""` before parsing, and use a small map or switch for O(1) lookup instead of the linear scan — would eliminate the allocation on the common path entirely.

**Confidence:** Strong-static

**Effort:** Localized — change affects only this one function

**Verification plan:** The current check is purely structural (no database, no external state). The correctness guard is `internal/api/middleware_apikey_query_test.go` — run before and after the change and confirm all existing cases still pass. Confirm the alloc-per-call drop with `testing.AllocsPerRun` on a synthetic benchmark with an empty query string.

---

## Confirmed-cold items (examined, no finding)

- **Metrics cardinality:** All `prometheus.CounterVec` and `prometheus.HistogramVec` labels are bounded. HTTP metrics use `chi.RouteContext.RoutePattern()` (parameterised patterns, not raw paths) — cardinality equals the number of registered routes, not the number of requests. Feed metrics label on feed name (~8 values). Worker metrics label on job type (~7 values). Security events label on event type (~40 constants) × severity (3 values) = ≤120 time series. No unbounded-cardinality vectors present.

- **Security headers inline closure:** The three `w.Header().Set` calls in the anonymous closure in `server.go:189-196` are three map-insert operations on an already-allocated `http.Header`; the closure itself does not allocate. No finding.

- **`contextLoggerMiddleware`:** One context-key lookup (`middleware.GetReqID`) plus one conditional `log.Enrich` call (a `slog.Logger.With` allocation, already accepted as necessary for per-request log correlation). No algorithmic concern.

- **`noCacheMiddleware`:** Single header set; no allocation. No finding.

- **`csrfProtect`:** Method switch + one `r.Cookie` call on state-changing requests; no allocation beyond what `net/http` already performs for cookie parsing. No finding.

- **`httpMetricsMiddleware`:** `chi.RouteContext(r.Context()).RoutePattern()` reads from a context value already allocated by chi's router; `strconv.Itoa` on the status code (small integer, likely stack-escaped but not a concern at this frequency). No finding.

- **`orgRateLimiter`:** Mutex-protected map keyed by `uuid.UUID` (value type, no alloc); eviction runs at `evictTTL/2` interval in a background goroutine. Correct and cache-safe for tenant counts up to tens of thousands of orgs. No finding.

- **`crypto.Encrypt` / `crypto.Decrypt`:** `aes.NewCipher` + `cipher.NewGCM` are called on every encrypt/decrypt. Both allocate internally and are unavoidable per-call given the current stateless API shape. These are not on the per-request middleware path; they are invoked on SSO credential operations and key rotation, which are low-frequency. No finding.

- **`doctor.Run`:** Sequential loop over a bounded check slice; only invoked on demand by `/admin/doctor` or the CLI. No finding.

- **`metrics.DBPoolCollector`:** `Collect` reads from a snapshot struct; called only on Prometheus scrape. No finding.

- **`ingest.go` `ingestCVEIDPattern`:** Package-level compiled `regexp.Regexp`; `MatchString` is per-patch, not per-request middleware. No finding.

- **`retentionHandler`:** Constructs a `retention.Runner` on every job execution. This is a background worker job, not a request handler. No finding.

---

## Suspected Bugs (for follow-up)

None observed during this lane's reading.
