# Purge removed watchlist items

## What was built

- The daily retention job hard-deletes `watchlist_items` rows whose `deleted_at` is older than `RETENTION_WATCHLIST_ITEMS_DAYS` (default 30). Live items are never touched. Removing an item and `PUT /orgs/{org_id}/watchlists/{id}/items` (replace all items) both soft-delete rows, and nothing purged them before; a member alternating two disjoint 10,000-item lists could add 10,000 removed rows per request.
- Migration `000054_watchlist_items_retention`: `GRANT DELETE ON watchlist_items TO cvert_ops_app`, and a partial index `watchlist_items_deleted_at_idx ON watchlist_items (deleted_at) WHERE deleted_at IS NOT NULL` for the purge.
- `store.CleanupWatchlistItems` (bounded-batch CTE delete, `withBypassTx`, all orgs), wired into `retention.Runner` after `security_events` as a global-cutoff table.
- PLAN.md §21.2 row and §21.3 required-index entry; `.env.example` and `docker/compose.prod.yml` carry the new variable.

## Key decisions

- **Minimum window of 7 days.** The batch and EPSS evaluators read CVE items removed since their cursor to resolve the removed CVEs' alert events (`getWatchlistCVEChangesSince` in `internal/alert/evaluator.go`). The EPSS evaluator runs daily and can hold its cursor for three runs, so the run that advances it reads items removed up to about four days earlier. A configured value below 7 is raised to 7 and the runner logs a warning each run. A purged row that the evaluator never read leaves its alert event unresolved.
- **Default of 30 days.** Long enough to cover a worker outage of weeks, short enough that the replace-all abuse case is bounded to about a month of rows per org.
- **Not tier-gated.** The rows are internal state with no user-facing history (no endpoint lists removed items), so a per-tier override has no use.
- **New partial index instead of the existing `watchlist_items_cve_changed_idx`.** That index is on the expression `GREATEST(created_at, deleted_at)` and covers only `item_type = 'cve'`; the purge covers all item types and filters on `deleted_at`. `EXPLAIN` on a test database confirmed the planner uses the new index for `deleted_at < cutoff` (a strict comparison implies the index's `IS NOT NULL` predicate).

## Gotchas

- Compose deployments already allowed the delete: `docker/init-app-role.sh` sets `ALTER DEFAULT PRIVILEGES ... GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cvert_ops_app`. The explicit grant matters for installs that create the app role another way, and for the test template database, which has no default privileges. The down migration's `REVOKE` therefore also removes the default-privilege grant on compose installs; no code other than the purge deletes from this table.
- The existing retention tests run as the superuser `db.Store`, which would pass without the grant. The new store test uses `db.AppStore` (`cvert_ops_app`); without migration 000054 it fails with `permission denied for table watchlist_items (SQLSTATE 42501)`.
- No migration grants anything on `security_events` to `cvert_ops_app`, and `ai_usage_counters` is granted `SELECT, INSERT, UPDATE` only (migration 000020); outside compose installs, where default privileges do not apply, their retention cleanups would fail as the app role. Not changed here.

## Quality checks

- `go test ./internal/store/ -run 'TestCleanupWatchlistItems'` as `cvert_ops_app`: fails without migration 000054 (permission denied), passes with it. Covers batch size, a removed CVE item and a removed package item 40 days old purged, an item removed 5 days ago and a live item kept.
- `go test ./internal/retention/`: 13 tests pass, including the 30-day window and the 7-day minimum (with the warning captured and checked).
- `go test ./internal/store/ -run 'TestCleanup|Watchlist'`, `./internal/config/`, `./docker/`, `./migrations/`: pass.
- One-off checks, not committed: `EXPLAIN` of the purge uses `watchlist_items_deleted_at_idx`; down then up on a migrated database removes and restores both the grant and the index.
- `golangci-lint run` on `internal/retention`, `internal/store`, `internal/config`, `cmd`: 0 issues.
