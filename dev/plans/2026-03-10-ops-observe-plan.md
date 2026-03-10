# Observe/Instrument Pillar — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enrich Prometheus metrics across 6 subsystems, add structured log correlation, move `/metrics` to a separate port, and provide Grafana dashboards + alerting rules.

**Architecture:** All metrics use `promauto.NewXxx()` in dedicated files under `internal/metrics/`, one per subsystem (matching existing `ai.go` pattern). DB pool uses custom `prometheus.Collector`. Log correlation via new `internal/log/` package with middleware. Metrics served on separate port via second `http.Server`.

**Tech Stack:** `prometheus/client_golang`, `slog`, chi middleware, Grafana JSON provisioning

**References:**
- Design: `dev/plans/2026-03-10-ops-observe-design.md`
- Testing pitfalls: `dev/testing-pitfalls.md` (referenced as `tp§N.N`)
- Existing pattern: `internal/metrics/ai.go`
- Middleware chain: `internal/api/server.go:154-183`

**CRITICAL — File Ownership:** This pillar ONLY creates/modifies files listed below. Do NOT touch `internal/api/admin_*.go`, `internal/feed/generic/`, `internal/secure/`, or `cmd/cvert-ops/doctor.go`.

---

## Batch 1: Metric Definitions (Pure Data, No Wiring)

### Task 1: HTTP Metrics

**Files:**
- Create: `internal/metrics/http.go`
- Create: `internal/metrics/http_test.go`

**Context:** Two metrics — request counter and duration histogram. The `route` label MUST use chi's route pattern (e.g., `/api/v1/orgs/{org_id}/cves/{cve_id}`), never actual URLs with UUIDs. This is enforced by the middleware (Task 7), but the metric definitions here must use the correct label names.

**Step 1: Write test that metric descriptors are registered**

```go
func TestHTTPMetricsRegistered(t *testing.T) {
    // Verify metrics can be collected without panic
    metrics.HTTPRequestsTotal.WithLabelValues("GET", "/api/v1/healthz", "200").Inc()
    metrics.HTTPRequestDuration.WithLabelValues("GET", "/api/v1/healthz").Observe(0.01)
}
```

Run: `go test ./internal/metrics/ -v -run TestHTTPMetrics -race`
Expected: FAIL — `HTTPRequestsTotal` undefined.

**Step 2: Implement**

```go
// ABOUTME: Prometheus metrics for HTTP request counting and latency.
// ABOUTME: Instrumented by the metrics middleware on the API sub-router.
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var HTTPRequestsTotal = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "cvertops_http_requests_total",
        Help: "Total HTTP requests by method, route pattern, and status code.",
    },
    []string{"method", "route", "status_code"},
)

var HTTPRequestDuration = promauto.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "cvertops_http_request_duration_seconds",
        Help:    "HTTP request duration by method and route pattern.",
        Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
    },
    []string{"method", "route"},
)
```

**Step 3: Run test → PASS**

**Step 4: Commit**

```bash
git add internal/metrics/http.go internal/metrics/http_test.go
git commit -m "feat(metrics): add HTTP request counter and duration histogram definitions"
```

### Task 2: Feed Metrics

**Files:**
- Create: `internal/metrics/feed.go`
- Create: `internal/metrics/feed_test.go`

**Context:** Six metrics. The two gauges (`feed_last_success_timestamp`, `feed_consecutive_failures`) are updated by the ingest handler (Task 9). The counters and histogram are updated at the same instrumentation points. All use `feed` as the only label.

**Step 1: Write test**

```go
func TestFeedMetricsRegistered(t *testing.T) {
    metrics.FeedItemsFetchedTotal.WithLabelValues("nvd").Inc()
    metrics.FeedItemsMergedTotal.WithLabelValues("nvd").Inc()
    metrics.FeedFetchDuration.WithLabelValues("nvd").Observe(5.0)
    metrics.FeedErrorsTotal.WithLabelValues("nvd").Inc()
    metrics.FeedLastSuccessTimestamp.WithLabelValues("nvd").SetToCurrentTime()
    metrics.FeedConsecutiveFailures.WithLabelValues("nvd").Set(0)
}
```

Run: `go test ./internal/metrics/ -v -run TestFeedMetrics -race`
Expected: FAIL

**Step 2: Implement**

```go
// ABOUTME: Prometheus metrics for feed ingestion health and throughput.
// ABOUTME: Instrumented by the ingest handler after each fetch-merge cycle.
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var FeedItemsFetchedTotal = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "cvertops_feed_items_fetched_total",
        Help: "Total items fetched from feed sources.",
    },
    []string{"feed"},
)

var FeedItemsMergedTotal = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "cvertops_feed_items_merged_total",
        Help: "Total items successfully merged into the CVE corpus.",
    },
    []string{"feed"},
)

var FeedFetchDuration = promauto.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "cvertops_feed_fetch_duration_seconds",
        Help:    "Duration of feed fetch operations.",
        Buckets: []float64{1, 5, 15, 30, 60, 120, 300},
    },
    []string{"feed"},
)

var FeedErrorsTotal = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "cvertops_feed_errors_total",
        Help: "Total feed fetch errors.",
    },
    []string{"feed"},
)

var FeedLastSuccessTimestamp = promauto.NewGaugeVec(
    prometheus.GaugeOpts{
        Name: "cvertops_feed_last_success_timestamp",
        Help: "Unix timestamp of the last successful feed fetch.",
    },
    []string{"feed"},
)

var FeedConsecutiveFailures = promauto.NewGaugeVec(
    prometheus.GaugeOpts{
        Name: "cvertops_feed_consecutive_failures",
        Help: "Current count of consecutive fetch failures per feed.",
    },
    []string{"feed"},
)
```

**Step 3: Run test → PASS**

**Step 4: Commit**

```bash
git add internal/metrics/feed.go internal/metrics/feed_test.go
git commit -m "feat(metrics): add feed ingestion health metric definitions"
```

### Task 3: Alert Metrics

**Files:**
- Create: `internal/metrics/alert.go`
- Create: `internal/metrics/alert_test.go`

**Context:** Three metrics with `path` label. Values: `realtime`, `batch`, `epss`.

**Step 1: Write test, Step 2: Implement**

Follow the exact pattern from Tasks 1-2. Metric names from design doc:
- `cvertops_alert_rules_evaluated_total` (Counter, `path`)
- `cvertops_alert_matches_total` (Counter, `path`)
- `cvertops_alert_evaluation_duration_seconds` (Histogram, `path`, buckets: `0.01, 0.05, 0.1, 0.5, 1, 5, 15`)

**Step 3: Run test → PASS. Step 4: Commit.**

### Task 4: Notification Metrics

**Files:**
- Create: `internal/metrics/notification.go`
- Create: `internal/metrics/notification_test.go`

**Context:** Two metrics. `channel_type` values: `webhook`, `email`. `status` values: `success`, `failure`, `exhausted`.

Metric names:
- `cvertops_notification_deliveries_total` (Counter, `channel_type`, `status`)
- `cvertops_notification_delivery_duration_seconds` (Histogram, `channel_type`, buckets: `0.1, 0.5, 1, 2, 5, 10, 30`)

Follow Tasks 1-2 pattern. Commit.

### Task 5: Worker Metrics

**Files:**
- Create: `internal/metrics/worker.go`
- Create: `internal/metrics/worker_test.go`

**Context:** Three metrics. `job_type` label. `status` values: `success`, `failure`.

Metric names:
- `cvertops_worker_jobs_claimed_total` (Counter, `job_type`)
- `cvertops_worker_jobs_completed_total` (Counter, `job_type`, `status`)
- `cvertops_worker_job_duration_seconds` (Histogram, `job_type`, buckets: `0.01, 0.1, 0.5, 1, 5, 15, 60, 300`)

Follow Tasks 1-2 pattern. Commit.

### Task 6: DB Pool Collector

**Files:**
- Create: `internal/metrics/db.go`
- Create: `internal/metrics/db_test.go`

**Context:** This is DIFFERENT from the other metrics. Uses custom `prometheus.Collector` interface, NOT `promauto`. The `Collect()` method calls `pool.Stat()` on each Prometheus scrape — always-fresh data, no polling goroutine. Registered during server init when the pool is available.

**CRITICAL (tp§13.6):** Tests MUST use an isolated `prometheus.Registry` — never the default registry (races with other tests).

**Step 1: Write test**

```go
func TestDBPoolCollector(t *testing.T) {
    // Use a real pgxpool or a mock that implements the Stat() interface.
    // Register with isolated registry.
    reg := prometheus.NewRegistry()
    collector := metrics.NewDBPoolCollector(pool)
    reg.MustRegister(collector)

    // Gather and verify 4 metric families exist.
    mfs, err := reg.Gather()
    require.NoError(t, err)
    names := make(map[string]bool)
    for _, mf := range mfs {
        names[mf.GetName()] = true
    }
    assert.True(t, names["cvertops_db_pool_acquired_conns"])
    assert.True(t, names["cvertops_db_pool_idle_conns"])
    assert.True(t, names["cvertops_db_pool_max_conns"])
    assert.True(t, names["cvertops_db_pool_total_conns"])
}
```

**Step 2: Implement**

The collector wraps a `PoolStatter` interface (for testability):

```go
// ABOUTME: Prometheus collector for pgxpool connection stats.
// ABOUTME: Reports pool utilization as gauges on each scrape — no polling goroutine.
package metrics

// PoolStatter is the subset of pgxpool.Pool used by the collector.
type PoolStatter interface {
    Stat() *pgxpool.Stat
}

type DBPoolCollector struct {
    pool PoolStatter
    acquiredDesc *prometheus.Desc
    idleDesc     *prometheus.Desc
    maxDesc      *prometheus.Desc
    totalDesc    *prometheus.Desc
}

func NewDBPoolCollector(pool PoolStatter) *DBPoolCollector { ... }
func (c *DBPoolCollector) Describe(ch chan<- *prometheus.Desc) { ... }
func (c *DBPoolCollector) Collect(ch chan<- prometheus.Metric) {
    stat := c.pool.Stat()
    ch <- prometheus.MustNewConstMetric(c.acquiredDesc, prometheus.GaugeValue, float64(stat.AcquiredConns()))
    ch <- prometheus.MustNewConstMetric(c.idleDesc, prometheus.GaugeValue, float64(stat.IdleConns()))
    ch <- prometheus.MustNewConstMetric(c.maxDesc, prometheus.GaugeValue, float64(stat.MaxConns()))
    ch <- prometheus.MustNewConstMetric(c.totalDesc, prometheus.GaugeValue, float64(stat.TotalConns()))
}
```

**Step 3: Run test → PASS with `-race`**

**Step 4: Commit**

```bash
git add internal/metrics/db.go internal/metrics/db_test.go
git commit -m "feat(metrics): add DB pool collector using prometheus.Collector interface"
```

---

## Batch 2: Log Correlation

### Task 7: Log Context Package

**Files:**
- Create: `internal/log/context.go`
- Create: `internal/log/context_test.go`

**Context:** Three helpers: `FromContext`, `WithLogger`, `Enrich`. `FromContext` falls back to `slog.Default()` if no logger in context. Phase 8B adds the middleware and helpers only — existing `slog.InfoContext` calls are NOT migrated (design doc §2).

**Step 1: Write tests**

```go
func TestFromContext_FallsBackToDefault(t *testing.T) {
    logger := log.FromContext(context.Background())
    assert.NotNil(t, logger)
}

func TestWithLogger_RoundTrip(t *testing.T) {
    custom := slog.New(slog.NewJSONHandler(io.Discard, nil))
    ctx := log.WithLogger(context.Background(), custom)
    got := log.FromContext(ctx)
    assert.Equal(t, custom, got)
}

func TestEnrich_AddsField(t *testing.T) {
    var buf bytes.Buffer
    handler := slog.NewJSONHandler(&buf, nil)
    logger := slog.New(handler)
    ctx := log.WithLogger(context.Background(), logger)
    ctx = log.Enrich(ctx, "request_id", "abc-123")
    log.FromContext(ctx).Info("test message")
    assert.Contains(t, buf.String(), "abc-123")
}
```

**Step 2: Implement**

```go
// ABOUTME: Context-aware slog helpers for structured log correlation.
// ABOUTME: Middleware injects request_id, org_id, user_id; handlers use FromContext.
package log

type ctxKey struct{}

func FromContext(ctx context.Context) *slog.Logger {
    if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
        return l
    }
    return slog.Default()
}

func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
    return context.WithValue(ctx, ctxKey{}, l)
}

func Enrich(ctx context.Context, key string, value any) context.Context {
    return WithLogger(ctx, FromContext(ctx).With(key, value))
}
```

**Step 3: Run test → PASS. Step 4: Commit.**

### Task 8: Context Logger Middleware

**Files:**
- Create: `internal/api/log_middleware.go`
- Create: `internal/api/log_middleware_test.go`
- Modify: `internal/api/server.go:177` — insert middleware after RequestID

**Context:** Middleware registered immediately after the existing Request ID middleware in `server.go` (after line 177 in current code). It extracts `request_id` from chi context, creates enriched logger, stores in context.

The design doc says org_id/user_id enrichment goes in `RequireAuthenticated` middleware path — NOT in this middleware. This middleware only adds `request_id`.

**Step 1: Write test**

```go
func TestContextLoggerMiddleware_InjectsRequestID(t *testing.T) {
    var buf bytes.Buffer
    handler := slog.NewJSONHandler(&buf, nil)
    slog.SetDefault(slog.New(handler))
    defer slog.SetDefault(slog.Default()) // restore

    r := chi.NewRouter()
    r.Use(middleware.RequestID)
    r.Use(contextLoggerMiddleware)
    r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
        log.FromContext(r.Context()).Info("hello")
        w.WriteHeader(200)
    })

    req := httptest.NewRequest("GET", "/test", nil)
    rec := httptest.NewRecorder()
    r.ServeHTTP(rec, req)

    assert.Contains(t, buf.String(), "request_id")
}
```

**Step 2: Implement the middleware**

```go
// ABOUTME: Middleware that injects a request-scoped slog logger into the context.
// ABOUTME: Enriches the logger with request_id from chi's RequestID middleware.
package api

func contextLoggerMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        reqID := middleware.GetReqID(ctx)
        if reqID != "" {
            ctx = logpkg.Enrich(ctx, "request_id", reqID)
        }
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Step 3: Wire into server.go**

Insert `r.Use(contextLoggerMiddleware)` after line 177 (after `r.Use(clientIPMiddleware)`), before `r.Use(middleware.RequestSize(...))`.

**Step 4: Run test → PASS. Step 5: Commit.**



---

## Batch 3: Metrics Port & Instrumentation Wiring

### Task 9: Separate Metrics Port

**Files:**
- Modify: `internal/api/server.go` — remove `/metrics` handler from main router, add `MetricsHandler()` method
- Modify: `internal/config/config.go` — add `MetricsPort` field
- Modify: `cmd/cvert-ops/main.go` — start second `http.Server` for metrics
- Create: `internal/api/metrics_server_test.go`

**Context:** Metrics served on `METRICS_PORT` (default `9090`). Operators bind to localhost or internal network. The main port never exposes `/metrics`. The metrics server shares the same graceful shutdown sequence.

**Step 1: Add config field**

In `internal/config/config.go`, add:
```go
MetricsPort string `env:"METRICS_PORT" envDefault:"9090"`
```

**Step 2: Remove `/metrics` from main router**

In `server.go`, remove the line:
```go
r.Handle("/metrics", promhttp.Handler())
```

**Step 3: Start metrics server in `runServe`**

In `cmd/cvert-ops/main.go`, after creating the main `http.Server`, create a second one:

```go
metricsMux := http.NewServeMux()
metricsMux.Handle("/metrics", promhttp.Handler())
metricsSrv := &http.Server{
    Addr:              ":" + cfg.MetricsPort,
    Handler:           metricsMux,
    ReadHeaderTimeout: 5 * time.Second,
}
go func() {
    slog.Info("metrics server started", "addr", metricsSrv.Addr)
    if err := metricsSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
        slog.Error("metrics server error", "error", err)
    }
}()
```

Add graceful shutdown for metrics server alongside the main server shutdown.

**Step 4: Test**

Write a test that starts both servers and verifies `/metrics` returns 200 on the metrics port and 404 on the main port.

**Step 5: Run test → PASS. Step 6: Commit.**

### Task 10: Feed Metric Instrumentation

**Files:**
- Modify: `internal/ingest/handler.go` — add metric recording calls

**Context:** Add metric updates at these points in the ingest handler (design doc §1 "Instrumentation Points"):
- After each `mergeFn` call: increment `FeedItemsFetchedTotal` and `FeedItemsMergedTotal`
- After Fetch: observe `FeedFetchDuration`
- On error: increment `FeedErrorsTotal`
- After `UpsertFeedSyncState`: set `FeedLastSuccessTimestamp` and `FeedConsecutiveFailures`

**CRITICAL (tp§9.6):** Metrics must be updated AFTER the database write succeeds, not before. A metric that reports success before the cursor is persisted gives false confidence.

**Step 1: Read `internal/ingest/handler.go` fully** to understand where to insert calls.

**Step 2: Add metric calls** at the identified points. Import `internal/metrics`.

**Step 3: Run existing ingest handler tests** to verify no regressions:
Run: `go test ./internal/ingest/ -v -race`

**Step 4: Commit**

```bash
git add internal/ingest/handler.go
git commit -m "feat(metrics): instrument feed ingest handler with Prometheus counters and gauges"
```

### Task 11: HTTP Metrics Middleware

**Files:**
- Create: `internal/api/metrics_middleware.go`
- Create: `internal/api/metrics_middleware_test.go`
- Modify: `internal/api/server.go` — register on API sub-router

**Context:** CRITICAL cardinality control (design doc §1, tp§13.6): The `route` label MUST use `chi.RouteContext(r.Context()).RoutePattern()` — never the actual URL. The middleware MUST be on the API sub-router (after route matching), NOT on the root router. If registered on the root router, `RoutePattern()` returns empty string before route matching.

**Step 1: Write test — verify no UUID in route label**

```go
func TestMetricsMiddleware_UsesRoutePattern(t *testing.T) {
    reg := prometheus.NewRegistry()
    // Create isolated counter/histogram registered with this registry
    // Hit /api/v1/orgs/{org_id}/cves with a real UUID
    // Gather metrics, assert route label is "/api/v1/orgs/{org_id}/cves" not the actual UUID path
}
```

**Step 2: Implement**

The middleware wraps `http.ResponseWriter` to capture status code, records both metrics after `next.ServeHTTP` returns.

**Step 3: Wire into server.go** on `apiRouter` (the chi sub-router), NOT `r` (root router).

**Step 4: Run test → PASS. Step 5: Commit.**

### Task 12: Alert & Notification & Worker Metric Instrumentation

**Files:**
- Modify: `internal/alert/evaluator.go` — add metric calls at evaluation start/end
- Modify: `internal/notify/worker.go` — add metric calls after each `deliver()` call
- Modify: `internal/worker/pool.go` — add metric calls after job claim and completion

**Context:** These are small additions — 3-5 lines per file. Import `internal/metrics` and call `.WithLabelValues(...).Inc()` or `.Observe()` at the points specified in the design doc §1 "Instrumentation Points" table.

**Step 1: Read each file to identify exact insertion points.**

**Step 2: Add metric calls.** For alert evaluator, use `path` label values: `realtime`, `batch`, `epss`. For notification, use `channel_type` and `status`. For worker, use `job_type` and `status`.

**Step 3: Run existing tests** for each package:
```bash
go test ./internal/alert/ -v -race
go test ./internal/notify/ -v -race
go test ./internal/worker/ -v -race
```

**Step 4: Commit**

```bash
git add internal/alert/evaluator.go internal/notify/worker.go internal/worker/pool.go
git commit -m "feat(metrics): instrument alert evaluator, notification worker, and job pool"
```

### Task 13: DB Pool Collector Registration

**Files:**
- Modify: `cmd/cvert-ops/main.go` — register `DBPoolCollector` after pool creation

**Context:** Register the collector from Task 6 during server init, after `newPool()` returns.

```go
dbCollector := metrics.NewDBPoolCollector(db)
prometheus.MustRegister(dbCollector)
```

**Step 1: Add registration. Step 2: Run tests. Step 3: Commit.**

---

## Batch 4: Grafana Dashboards, Alerting Rules & Collector Configs

### Task 14: System Overview Dashboard

**Files:**
- Create: `deploy/grafana/dashboards/system-overview.json`

**Context:** Raw Grafana provisioning JSON. Template variables: `$job` (default `cvertops`), `$instance`. Six panels with exact PromQL from design doc §4.

Generate valid Grafana dashboard JSON with panels for:
1. Request Rate: `sum(rate(cvertops_http_requests_total{job="$job"}[5m]))`
2. Error Rate (5xx): `sum(rate(cvertops_http_requests_total{job="$job",status_code=~"5.."}[5m]))`
3. Latency p50/p95/p99: `histogram_quantile(0.95, ...)`
4. DB Pool Utilization: `acquired / max`
5. Goroutine Count: `go_goroutines{job="$job"}`
6. Process Memory: `process_resident_memory_bytes{job="$job"}`

**Commit after creation.**

### Task 15: Feed Health Dashboard

**Files:**
- Create: `deploy/grafana/dashboards/feed-health.json`

Five panels per design doc §4. **Commit.**

### Task 16: Alerts & Delivery Dashboard

**Files:**
- Create: `deploy/grafana/dashboards/alerts-delivery.json`

Five panels per design doc §4. **Commit.**

### Task 17: Alerting Rules

**Files:**
- Create: `deploy/grafana/alerts.yml`

**Context:** Prometheus alerting rules format. Six alerts from design doc §6:
- `FeedStale`: `time() - cvertops_feed_last_success_timestamp > 7200` (warning, 15m)
- `FeedConsecutiveFailures`: `> 5` (critical, 5m)
- `HighErrorRate`: `rate(5xx) / rate(total) > 0.05` (critical, 5m)
- `SlowResponses`: `histogram_quantile p95 > 2` (warning, 10m)
- `DeliveryBacklog`: `claimed - completed > 100` (warning, 15m)
- `DBPoolExhaustion`: `acquired / max > 0.9` (critical, 5m)

**Commit.**

### Task 18: Collector Reference Configs

**Files:**
- Create: `deploy/grafana/alloy-config.alloy`
- Create: `deploy/grafana/prometheus.yml`

**Context:** Reference configs per design doc §5. Alloy config for Grafana Cloud/remote-write. Prometheus config for self-hosted scrape. Both target `localhost:9090/metrics`. These are templates operators adapt — include comments explaining what to customize.

**Commit.**

---

## Batch 5: Final Verification

### Task 19: Full Test Suite

**Step 1:** Run `go test ./... -race -count=1`
**Step 2:** Run `golangci-lint run`
**Step 3:** Fix any issues.
**Step 4:** Final commit if needed.

---

## Subagent Failure Modes to Watch For

| Risk | What goes wrong | Mitigation |
|------|----------------|------------|
| Route label cardinality explosion (tp§13.6) | UUID appears in metric `route` label | Task 11 test explicitly asserts no UUID in labels; middleware uses `RoutePattern()` |
| Metrics middleware on wrong router | Middleware on root router → empty route pattern | Task 11 specifies API sub-router, NOT root |
| DB pool collector race (tp§13.6) | Tests use default registry → race with other tests | Task 6 specifies isolated `prometheus.Registry` |
| Existing slog calls migrated | Agent migrates existing `slog.InfoContext` calls | Design doc explicitly says "Phase 8B adds middleware + helpers only. Existing slog calls NOT migrated" |
| Dashboard JSON invalid | Agent generates malformed Grafana JSON | Agent should generate from the exact PromQL in the design doc |
| Feed gauge metrics at wrong point | Metrics updated before DB write succeeds | Task 10 specifies "AFTER database write succeeds" |
| Agent touches files owned by other pillars | E.g., creates admin endpoints or modifies `feeds.go` | File ownership table in overview doc; explicit warning at top of plan |
| Prometheus import collision | `promauto` counters with same name registered twice | Each metric file is a separate subsystem; agent must not duplicate names from `ai.go` |
