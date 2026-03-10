# Observe/Instrument — Design

**Date:** 2026-03-10
**Status:** Design approved
**Pillar:** Observe/Instrument
**Prerequisites:** None (Phase 1 — parallel with Operate and Extend)
**Overview doc:** `2026-03-10-ops-maturity-overview.md`

## Current State

- Prometheus `/metrics` endpoint exists — only AI metrics (`internal/metrics/ai.go`) and feed scheduler counters registered
- slog JSON logging configured (`LOG_LEVEL`, `LOG_FORMAT` env vars)
- `/healthz` does a DB ping, returns ok/degraded
- Request ID generated via chi middleware, returned in `X-Request-Id` header, but **not injected into slog context** — logs cannot be correlated to requests
- No Grafana dashboards, alerting rules, or SLO definitions
- Compatible with both Grafana Cloud and self-hosted Grafana/Prometheus/Loki stacks

## 1. Metric Enrichment

### Naming Convention

`cvertops_<subsystem>_<metric>_<unit>` following Prometheus best practices:
- `_total` suffix for counters
- `_seconds` for durations
- `_bytes` for sizes
- snake_case throughout

### Registration Pattern

All metrics use `promauto.NewXxx()` in dedicated files under `internal/metrics/`, one file per subsystem. Each file exports package-level variables. Matches the existing pattern in `internal/metrics/ai.go`.

### Metrics by Subsystem

#### `internal/metrics/http.go`

| Metric | Type | Labels | Histogram Buckets |
|--------|------|--------|-------------------|
| `cvertops_http_requests_total` | Counter | `method`, `route`, `status_code` | — |
| `cvertops_http_request_duration_seconds` | Histogram | `method`, `route` | 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 |

**Cardinality control (critical):** The `route` label MUST use chi's route pattern (e.g., `/api/v1/orgs/{org_id}/cves/{cve_id}`) — never the actual URL with UUIDs. The metrics middleware calls `chi.RouteContext(r.Context()).RoutePattern()` in the response wrapper's `WriteHeader` method, after chi has resolved the route. The middleware MUST be registered on the API sub-router (after route matching), not on the root router.

#### `internal/metrics/feed.go`

| Metric | Type | Labels | Histogram Buckets |
|--------|------|--------|-------------------|
| `cvertops_feed_items_fetched_total` | Counter | `feed` | — |
| `cvertops_feed_items_merged_total` | Counter | `feed` | — |
| `cvertops_feed_fetch_duration_seconds` | Histogram | `feed` | 1, 5, 15, 30, 60, 120, 300 |
| `cvertops_feed_errors_total` | Counter | `feed` | — |
| `cvertops_feed_last_success_timestamp` | Gauge | `feed` | — |
| `cvertops_feed_consecutive_failures` | Gauge | `feed` | — |

The last two gauges are updated by the ingest handler alongside the existing `feed_sync_state` DB write.

#### `internal/metrics/alert.go`

| Metric | Type | Labels | Histogram Buckets |
|--------|------|--------|-------------------|
| `cvertops_alert_rules_evaluated_total` | Counter | `path` | — |
| `cvertops_alert_matches_total` | Counter | `path` | — |
| `cvertops_alert_evaluation_duration_seconds` | Histogram | `path` | 0.01, 0.05, 0.1, 0.5, 1, 5, 15 |

`path` values: `realtime`, `batch`, `epss`.

#### `internal/metrics/notification.go`

| Metric | Type | Labels | Histogram Buckets |
|--------|------|--------|-------------------|
| `cvertops_notification_deliveries_total` | Counter | `channel_type`, `status` | — |
| `cvertops_notification_delivery_duration_seconds` | Histogram | `channel_type` | 0.1, 0.5, 1, 2, 5, 10, 30 |

`channel_type` values: `webhook`, `email`. `status` values: `success`, `failure`, `exhausted`.

#### `internal/metrics/worker.go`

| Metric | Type | Labels | Histogram Buckets |
|--------|------|--------|-------------------|
| `cvertops_worker_jobs_claimed_total` | Counter | `job_type` | — |
| `cvertops_worker_jobs_completed_total` | Counter | `job_type`, `status` | — |
| `cvertops_worker_job_duration_seconds` | Histogram | `job_type` | 0.01, 0.1, 0.5, 1, 5, 15, 60, 300 |

`status` values: `success`, `failure`.

#### `internal/metrics/db.go`

| Metric | Type | Labels |
|--------|------|--------|
| `cvertops_db_pool_acquired_conns` | Gauge | — |
| `cvertops_db_pool_idle_conns` | Gauge | — |
| `cvertops_db_pool_max_conns` | Gauge | — |
| `cvertops_db_pool_total_conns` | Gauge | — |

**Implementation:** Custom `prometheus.Collector` interface (NOT `promauto`). The `Collect()` method calls `pool.Stat()` on each Prometheus scrape — no polling goroutine, always-fresh data. Registered during server init when the pool is available. Access pool via `store.Pool()` which returns `*pgxpool.Pool`.

### Instrumentation Points

Where to add metric recording calls (the metrics middleware handles HTTP; these are for non-HTTP subsystems):

| Subsystem | File to modify | Where to add |
|-----------|----------------|--------------|
| Feed ingestion | `internal/ingest/handler.go` | After each `mergeFn` call (items), after Fetch (duration), on error |
| Feed gauges | `internal/ingest/handler.go` | After `UpsertFeedSyncState` (last_success, consecutive_failures) |
| Alert evaluation | `internal/alert/evaluator.go` | Start/end of each evaluation path |
| Notification | `internal/notify/worker.go` | After each `deliver()` call (count + duration by channel_type) |
| Worker | `internal/worker/pool.go` | After each job claim and completion |

## 2. Log Correlation

### Problem

Request ID exists in response headers but not in log entries. An operator looking at a log line has no way to connect it to a specific request or user.

### Solution

New package: `internal/log/context.go`

Provides:
- `FromContext(ctx context.Context) *slog.Logger` — retrieves the enriched logger from context, falls back to `slog.Default()`
- `WithLogger(ctx context.Context, logger *slog.Logger) context.Context` — stores a logger in context
- `Enrich(ctx context.Context, key string, value any) context.Context` — adds a field to the context logger

### Middleware

`ContextLogger` middleware, registered immediately after the existing Request ID middleware in `server.go` (after line 177 in current code). It:
1. Extracts `request_id` from chi's context
2. Creates `slog.Default().With("request_id", reqID)`
3. Stores the enriched logger in context via `log.WithLogger()`

For org-scoped routes, the existing auth/RBAC middleware already resolves `org_id` and `user_id`. After those middlewares run, a second enrichment step adds `org_id` and `user_id` to the context logger. This goes in the existing `RequireAuthenticated` middleware path — not a separate middleware.

### Migration Scope

Phase 1 adds the middleware and helpers only. Existing `slog.InfoContext(ctx, ...)` calls are NOT migrated to `log.FromContext(ctx).Info(...)` in this phase. A follow-up mechanical PR can do that incrementally.

## 3. `/metrics` Endpoint Security

Serve metrics on a separate port: `METRICS_PORT` env var (default `9090`). Operators bind this to localhost or an internal network. The main port never exposes `/metrics`.

Implementation: a second `http.Server` in `server.go` listening on `METRICS_PORT` with only the `promhttp.Handler()` route. Shares the same graceful shutdown sequence as the main server.

The existing `/metrics` handler on the main port is removed.

## 4. Grafana Dashboard Definitions

Three dashboard JSON files in `deploy/grafana/dashboards/`. Written as raw Grafana provisioning JSON (no Jsonnet/grafonnet dependency).

All dashboards use Grafana template variables:
- `$job` (default: `cvertops`) — Prometheus job label
- `$instance` — for multi-instance filtering

### System Overview Dashboard

| Panel | PromQL |
|-------|--------|
| Request Rate | `sum(rate(cvertops_http_requests_total{job="$job"}[5m]))` |
| Error Rate (5xx) | `sum(rate(cvertops_http_requests_total{job="$job",status_code=~"5.."}[5m]))` |
| Latency p50/p95/p99 | `histogram_quantile(0.95, sum(rate(cvertops_http_request_duration_seconds_bucket{job="$job"}[5m])) by (le))` |
| DB Pool Utilization | `cvertops_db_pool_acquired_conns{job="$job"} / cvertops_db_pool_max_conns{job="$job"}` |
| Goroutine Count | `go_goroutines{job="$job"}` |
| Process Memory | `process_resident_memory_bytes{job="$job"}` |

### Feed Health Dashboard

| Panel | PromQL |
|-------|--------|
| Items Merged (per feed) | `sum(rate(cvertops_feed_items_merged_total{job="$job"}[1h])) by (feed)` |
| Fetch Duration (per feed) | `histogram_quantile(0.95, sum(rate(cvertops_feed_fetch_duration_seconds_bucket{job="$job"}[1h])) by (le, feed))` |
| Error Rate (per feed) | `sum(rate(cvertops_feed_errors_total{job="$job"}[1h])) by (feed)` |
| Time Since Last Success | `time() - cvertops_feed_last_success_timestamp{job="$job"}` |
| Consecutive Failures | `cvertops_feed_consecutive_failures{job="$job"}` |

### Alerts & Delivery Dashboard

| Panel | PromQL |
|-------|--------|
| Evaluation Rate by Path | `sum(rate(cvertops_alert_rules_evaluated_total{job="$job"}[5m])) by (path)` |
| Match Rate | `sum(rate(cvertops_alert_matches_total{job="$job"}[5m])) by (path)` |
| Delivery Success/Failure | `sum(rate(cvertops_notification_deliveries_total{job="$job"}[5m])) by (channel_type, status)` |
| Delivery Latency p95 | `histogram_quantile(0.95, sum(rate(cvertops_notification_delivery_duration_seconds_bucket{job="$job"}[5m])) by (le, channel_type))` |
| Worker Job Duration | `histogram_quantile(0.95, sum(rate(cvertops_worker_job_duration_seconds_bucket{job="$job"}[5m])) by (le, job_type))` |

## 5. Collector Reference Configs

### `deploy/grafana/alloy-config.alloy`

For Grafana Cloud or remote-write setups:
- `prometheus.scrape` component targeting `localhost:9090/metrics` (metrics port)
- `loki.source.file` for stderr JSON log tailing (or `local.file_match` for log files)
- `prometheus.remote_write` to configurable endpoint
- `loki.write` to configurable endpoint
- Labels: `job="cvertops"`, `instance`, `environment`

### `deploy/grafana/prometheus.yml`

For self-hosted Prometheus scrape:
- Standard scrape config targeting `localhost:9090/metrics`
- Scrape interval: 15s
- Same label scheme

Both are reference configs — operators adapt them to their infrastructure.

## 6. SLO Definitions & Alerting Rules

### `deploy/grafana/alerts.yml`

Prometheus alerting rules format (compatible with Grafana Cloud Alerting and self-hosted Prometheus Alertmanager):

| Alert | Condition | Severity | For |
|-------|-----------|----------|-----|
| `FeedStale` | `time() - cvertops_feed_last_success_timestamp > 7200` | warning | 15m |
| `FeedConsecutiveFailures` | `cvertops_feed_consecutive_failures > 5` | critical | 5m |
| `HighErrorRate` | `rate(5xx) / rate(total) > 0.05` | critical | 5m |
| `SlowResponses` | `histogram_quantile(0.95, ...) > 2` | warning | 10m |
| `DeliveryBacklog` | `claimed - completed > 100` | warning | 15m |
| `DBPoolExhaustion` | `acquired / max > 0.9` | critical | 5m |

### SLO Targets (documented, not code-enforced)

| SLO | Target |
|-----|--------|
| Feed freshness | Each feed succeeds at least once per 2h |
| API availability | < 5% 5xx error rate |
| API latency | p95 < 2s |
| Notification delivery | Attempt within 5min of alert event creation |

## What We Won't Build

- OpenTelemetry / distributed tracing (structured logs with correlation IDs cover single-binary architecture)
- Custom metrics UI in the application (Grafana is the visualization layer)
- Log aggregation within the app (stdout JSON → Loki/Alloy)
- Automated SLO enforcement or error budgets

## Subagent Risk Areas

| Risk | Mitigation |
|------|------------|
| Metric naming inconsistency | Exact metric names, labels, and buckets specified in tables above. Agent copies, doesn't invent. |
| Route label cardinality explosion | `route` label MUST use `chi.RouteContext().RoutePattern()`. Middleware on API sub-router, not root. Test: assert no UUID appears in any metric label. |
| Histogram bucket mismatch | Exact bucket values specified per metric type above. |
| Middleware ordering | HTTP metrics middleware on API v1 sub-router (after route matching). Log correlation middleware after RequestID (after line 177 in current server.go). |
| pgxpool collector pattern | `prometheus.Collector` interface, not `promauto`. `Describe()` + `Collect()` calling `pool.Stat()`. |
| Dashboard JSON verbosity | Exact panel titles, PromQL queries, and variables specified above. Agent generates JSON from specs. |
| Log migration scope creep | Phase 1 adds middleware + helpers only. Existing slog calls NOT migrated. |
| Prometheus race conditions | `-race` flag on all metric tests. `promauto` for counters/histograms (goroutine-safe). DB pool collector uses isolated registry in tests. (testing-pitfalls §13.6) |
| Feed gauge metrics | `cvertops_feed_last_success_timestamp` and `cvertops_feed_consecutive_failures` are new gauges updated by ingest handler. Must be added alongside existing DB writes. |
