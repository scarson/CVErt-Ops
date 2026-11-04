# Phase 5B — Retention Cleanup with Bounded-Batch Deletes

> **Date:** 2026-03-01
> **Commits:** `80808c6`..`234df6b` on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`

## What was built

| Feature | Files | Description |
|---|---|---|
| Retention indexes migration | `migrations/000026_retention_indexes.{up,down}.sql` | `CREATE INDEX CONCURRENTLY` on `cve_raw_payloads(ingested_at)`, `feed_fetch_log(started_at)`, `job_queue(finished_at) WHERE status IN ('succeeded','dead')` |
| Retention config | `internal/config/config.go` | Env vars for per-table retention windows: `RETENTION_RAW_PAYLOAD_DAYS`, `RETENTION_FEED_FETCH_LOG_DAYS`, `RETENTION_JOB_QUEUE_HOURS`, etc. |
| Retention sqlc queries | `internal/store/queries/retention.sql`, `internal/store/retention.go` | 9 bounded-batch DELETE queries using `WITH doomed AS (SELECT ... LIMIT batch_size) DELETE ... USING doomed` pattern |
| Retention runner | `internal/retention/runner.go` | Bounded-batch delete loop per table with max runtime deadline. Two phases: global tables (no org filtering), then tier-gated tables (grouped by per-org retention window) |
| Worker scheduling | `cmd/cvert-ops/main.go`, `internal/notify/worker.go` | Retention job registered as `retention_cleanup` handler, scheduled via `notify.Worker` ticker |

## Key implementation decisions

- **Bounded-batch delete pattern** — `WITH doomed AS (SELECT ... ORDER BY ts LIMIT batch_size) DELETE ... USING doomed`. Prevents long-running transactions and lock contention
- **Max runtime deadline** — Runner checks wall-clock time between batches, stops if deadline exceeded
- **Tier-gated retention windows** — Org-scoped tables group orgs by effective retention window via `tier.Resolver`. Orgs with unlimited retention (`days < 0`) are skipped
- **Error isolation** — Per-table errors are logged but don't stop the run

## Tests added

| Test | File | What it verifies |
|---|---|---|
| Retention store integration | `internal/store/retention_test.go` | All 9 bounded-batch deletes against real Postgres — batch limits, cutoff filtering |
| Runner unit tests | `internal/retention/runner_test.go` | Batch looping, max runtime, disabled skip, context cancellation, tier-gated grouping |
| Error isolation test | `internal/retention/runner_test.go` | Failing table doesn't prevent subsequent tables from being cleaned |

## Quality checks

- All tests pass (`go test ./...`)
- Code review remediation: removed dead AI cleanup code, added error isolation test, relocated `HasPendingOrRunningJob`
