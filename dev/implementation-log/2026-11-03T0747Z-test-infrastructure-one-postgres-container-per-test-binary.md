# Test Infrastructure — One Postgres Container per Test Binary

> **Date:** 2026-11-03
> **Commits:** on `test/shared-postgres-container` (branched from `fix/admin-reindex`)

## What was built

| Feature | Files | Description |
|---|---|---|
| Shared container + template clone | `internal/testutil/postgres.go` | The first `NewTestDB` call in a test binary starts one Postgres container and migrates a template database (`cvert_ops_template`). Every `NewTestDB` call then runs `CREATE DATABASE ... TEMPLATE` (~100 ms) and drops that database with `FORCE` at cleanup. The 650+ call sites are unchanged. |
| `testutil.Run` | `internal/testutil/postgres.go`, `*/main_test.go` (14 packages) | `TestMain` in every package that uses `NewTestDB` calls `os.Exit(testutil.Run(m))`, which terminates the container after the tests. `NewTestDB` fails with instructions if a package lacks it. |
| Server settings | `internal/testutil/postgres.go` | `max_connections=1000`, `synchronous_commit=off`, `full_page_writes=off` (the module already sets `fsync=off`): one server now serves every parallel test in a binary. |
| Flake fixes | `internal/notify/worker_test.go`, `internal/feed/breaker_test.go`, `internal/api/ingest_test.go`, `internal/api/auth_test.go`, `internal/api/org_ratelimit.go` | Digest tests stamp CVEs with the database clock; the breaker-open test uses an open timeout it cannot reach; the ingest rate test freezes the limiter clock; the login rate test uses an hourly refill like the register test. `orgRateLimiter.Allow` now refills by the limiter's injected clock, as `AllowN` already did. |
| CLAUDE.md | `CLAUDE.md` | The suite-runtime note describes the per-binary container, the required `TestMain`, and the new timings; the leftover-containers note covers the shared container. |
| Owner sweep integration | `internal/testutil/owner.go`, `internal/testutil/postgres.go` | The owner labels and orphan sweep from the owner-liveness work (#149) now apply to the shared container: `ownerOption()` is `ownedContainer` without a `testing.TB`, and `startCluster` adds its labels to the defaults. `startCluster` terminates a container that `tcpostgres.Run` returns together with an error (created but never ready). `startPostgres`, the per-test start, is gone. |

## Key implementation decisions

- **Container per test binary, not one reused machine-wide container** — Sam's choice. Each `go test` process owns its container, so concurrent runs by several sessions stay isolated, and a binary killed by a timeout panic leaks one container instead of hundreds. Reuse-by-name would skip container start-up entirely but share one server across worktrees and agents.
- **Template database, not truncation** — cloning gives each test an empty, fully migrated database with no ordering or cleanup coupling between parallel tests; truncating shared tables would serialize them.
- **Cleanup order** — the `DROP DATABASE` cleanup is registered before the pools, so it runs after they close (cleanups run last-in first-out); `WITH (FORCE)` ends any connection a test leaked.

## Gotchas discovered

- **`internal/feed/epss` and `internal/merge` cannot put `TestMain` in their internal test package** — `testutil` imports both (SeedCorpus, the merge pipeline), so their `main_test.go` uses the external test package.
- **Cluster-wide views now see other tests** — with one server per binary, `pg_locks`, `pg_stat_activity` and `pg_database` include other tests' databases. The rebuild deadlock test filters `pg_locks` by the current database's OID.
- **Faster runs exposed timing flakes** — packages now run their tests far more concurrently, so tests that raced a real clock (100 ms breaker timeout, one-token-per-second rate limit, host vs container clock) failed. Each now controls its clock.

## Quality checks

- **Full suite timing (Windows, Docker Desktop, several sessions sharing the daemon):** 189–384 s total at `-timeout=600s`, against ~16 minutes before; `internal/api` 108–220 s, against 1112 s.
- **Tests:** full suite passes, all 35 packages (at `f830bef`, before merging the owner-sweep work; rerun after the merge recorded in the PR).
- **New tests:** `TestNewTestDB_IsolatedDatabasesShareOneCluster`, `TestNewTestDB_DropsDatabaseAtCleanup`, `TestStartCluster_RemovesContainerThatFailsToStart` (replaces the per-test start's equivalent), `TestCheckRunner_RequiresRun`, `TestOrgRateLimiter_AllowUsesInjectedClock`; `TestIngestHandler_RateLimitCountsAsNRequests` rewritten to test N-token counting (mutation-checked).
