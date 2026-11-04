# Phase 8B — Observe Pillar

**Branch:** `phase-8b-observe` (worktree, concurrent with 8C/8D)
**Plan:** `dev/plans/2026-03-10-phase8-ops-observe-plan.md`
**PR:** #12 → merged to dev; #15 merged 8B/8C/8D to main

## What was built

5 batches across 19 tasks implementing the "Observe" pillar — Prometheus metrics across 6 subsystems, structured log correlation, separate metrics port, and Grafana dashboards:

1. **Metric definitions** (`internal/metrics/`) — 6 subsystem packages: HTTP (request counter + duration histogram), Feed (ingestion health), Alert (evaluation counters), Notification (delivery counters), Worker (job lifecycle), DB (pool collector via `PoolStatter` interface)
2. **Log correlation** (`internal/log/context.go`) — Context-aware slog helpers: `FromContext` fallback, `WithLogger` roundtrip, `Enrich` for adding fields. Request ID correlation middleware in `internal/api/log_middleware.go`
3. **Metrics port separation** — `/metrics` moved from main router to separate HTTP server on `METRICS_PORT` (default `9090`). Also added to standalone `worker` command
4. **Subsystem instrumentation** — Feed ingest handler, alert evaluator, notification worker, job pool, and DB pool collector all wired with metric calls. HTTP metrics middleware with cardinality-safe route labels
5. **Grafana dashboards & configs** — 3 dashboards (system overview, feed health, alerts & delivery) in `deploy/grafana/dashboards/`. Alerting rules in `deploy/grafana/alerts.yml`. Reference configs for Alloy and Prometheus

## Key decisions

- **DB Pool Collector uses `PoolStatter` interface:** Custom `PoolStats` struct instead of directly depending on `pgxpool.Stat`, with a pgxpool adapter for registration.
- **`statusWriter` includes `Unwrap()` method:** So `http.ResponseController` can discover `http.Flusher` and `http.Hijacker` on the underlying writer.
- **HTTP metrics middleware takes metrics as parameters:** `httpMetricsMiddleware(reqTotal, reqDuration)` rather than package-level vars — enables isolated-registry testing without cardinality collisions.
- **Retry-path metrics after DB write:** Moved per `tp§9.6` — metrics must reflect committed state, not optimistic state.

## Gotchas

- **Middleware ordering matters:** Review fix corrected ordering and added doc comments to metric vars.
- **`statusWriter` needed `Unwrap()`:** Required for compatibility with chi's response writer middleware chain.
- **Retry-path metrics placement:** Initially placed before `RetryDelivery` DB write, had to be moved after per testing-pitfalls §9.6.
- **Worker command also needs metrics:** The standalone `worker` cobra command needed its own metrics server + DB pool collector registration.

## Tests

| File | Tests |
|------|-------|
| `internal/metrics/*_test.go` | 6 (1 per subsystem) |
| `internal/log/context_test.go` | 3 (FromContext fallback, WithLogger roundtrip, Enrich) |
| `internal/api/log_middleware_test.go` | 1 |
| `internal/api/metrics_middleware_test.go` | 2 |
| `internal/api/metrics_server_test.go` | 1 |
| **Total** | **13** |

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean (post-review fixes in `2bbec79`)
- **Go unit tests:** 13/13 pass across metrics, log, and API middleware packages
