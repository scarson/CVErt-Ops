# Phase 2b — Watchlists, Alert DSL, Evaluator, HTTP Handlers

> **Dates:** 2026-02-27 – 2026-02-28
> **Branch:** `dev`
> **Commits:** `c24160d` (migrations), `1a8e606` (store), `e63cb84` (DSL), `2544226` (evaluator), `40fd8b5` (handlers), `552a68d` (refinements)
> **Deliverables:** Migrations 000013-000016, store layer, DSL compiler, alert evaluator, HTTP handler layer for watchlists + alert rules + alert events

## Files created / modified

| File | Purpose |
|---|---|
| `migrations/000013_create_watchlists.{up,down}.sql` | `watchlists` + `watchlist_items` tables, RLS, indexes |
| `migrations/000014_create_alert_rules.{up,down}.sql` | `alert_rules` table, RLS, check constraint on status |
| `migrations/000015_create_alert_rule_runs.{up,down}.sql` | `alert_rule_runs` table for run telemetry |
| `migrations/000016_create_alert_events.{up,down}.sql` | `alert_events` table, `UNIQUE(org_id, rule_id, cve_id, material_hash)` |
| `internal/store/watchlist.go` | Watchlist + item CRUD with `withOrgTx` |
| `internal/store/alert_rule.go` | Alert rule CRUD, run tracking, event insert/resolve/list |
| `internal/store/queries/alert_rules.sql` | sqlc queries for all alert rule operations |
| `internal/alert/dsl/` | DSL types, parser, validator, compiler (49 tests) |
| `internal/alert/evaluator.go` | `Evaluator`: realtime/batch/EPSS paths, activation scan, zombie sweep, dry-run |
| `internal/alert/rule_cache.go` | Thread-safe in-memory cache of compiled rules |
| `internal/api/watchlists.go` | CRUD + item management HTTP handlers |
| `internal/api/alert_rules.go` | Create/get/list/patch/delete/validate/dry-run handlers |
| `internal/api/alert_events.go` | List handler with `?rule_id=` + `?cve_id=` filters |
| `internal/api/server.go` | All Phase 2b routes registered + `SetAlertDeps` |
| `cmd/cvert-ops/main.go` | Wire alert cache + evaluator into server, bump `expectedSchemaVersion` to 16 |

## Key implementation decisions

**Three evaluation paths (PLAN.md §10.5):**
- **Realtime** (`EvaluateRule`): fires on CVE upsert when `material_hash` changes. Called with a candidate set already narrowed to the changed CVE.
- **Batch** (`EvaluateBatch`): periodic job over `date_modified_canonical > last_cursor`. Skips rules with `is_epss_only = true`. Uses `candidateCap = 5000` guard.
- **EPSS** (`EvaluateEPSS`): daily job over `date_epss_updated > last_cursor`. Only runs rules with `has_epss_condition = true`.
- All paths: filter `cves.status NOT IN ('rejected', 'withdrawn')`.

**Activation flow:** Handler creates rule with `status='activating'` → returns 202. Worker (`EvaluateActivation`) does the full backfill scan, then transitions to `'active'`. The HTTP path never runs a scan inline.

**`alert_events` dedup:** `INSERT ... ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING RETURNING id`. If `id` is nil in Go (`sql.ErrNoRows`), the event already existed — no fan-out. This is the "exactly-once" guarantee.

**`bypassTx` vs `readTx` vs `withOrgTx`:**
- `withOrgTx`: org-scoped transactions for all API handler paths; sets `app.org_id`.
- `bypassTx`: worker-only; sets `app.bypass_rls='on'`. **MUST NOT be called from HTTP handlers.**
- `readTx` (new): `BeginTx(ReadOnly: true)` + always `ROLLBACK`. Used for dry-run evaluation from API paths — safe, no side effects, no RLS bypass.

**Atomic PATCH status transition:** `UpdateAlertRule` SQL includes `status = $10` so content update and status→`'activating'` happen in one transaction. Previously it was two calls (`UpdateAlertRule` + `SetAlertRuleStatus`), creating a window for inconsistency.

**Open-mode auto-org:** Only the first registered user gets an auto-org (`priorCount == 0`). Subsequent users need to create their own org via `POST /api/v1/orgs` or be invited. Cross-org isolation tests must account for this: "Bob's empty list" tests can't use Bob's orgID if Bob hasn't created an org.

**UpdateAlertRuleParams.Status:** Adding `Status string` to the store wrapper + SQL required running `sqlc generate` and fixing the existing `TestUpdateAlertRule` store test (which was passing the Go zero value `""` — now rejected by the DB check constraint).

**sqlc note — `UpdateAlertRuleParams` conflict:** The store wrapper and the generated package both define `UpdateAlertRuleParams`. The wrapper type is in `internal/store` and the generated type is in `internal/store/generated`. The wrapper passes through to the generated type internally. This is the standard pattern used throughout this codebase.

## Quality check results

**pitfall-check:** Found 1 issue (DryRun used `bypassTx` — RLS bypass from API handler is a security violation). Fixed by adding `readTx` helper.
**plan-check (§9, §10, §16):** Found missing dry-run HTTP endpoint (PLAN.md §10.6). Fixed by adding `dryRunHandler`.
**security-review:** Found non-atomic PATCH status transition. Fixed by including `Status` in `UpdateAlertRuleParams`.
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.

## Test coverage

| Test file | New tests | Coverage |
|---|---|---|
| `internal/alert/dsl/*_test.go` | 49 | Parse, validate, compile, all operators, EPSS detection |
| `internal/alert/evaluator_test.go` | Multiple | Activation scan, zombie sweep, batch eval |
| `internal/api/watchlists_test.go` | Multiple | CRUD, item management, RBAC |
| `internal/api/alert_rules_test.go` | Multiple | CRUD, draft, validate, invalid DSL (create + patch), cross-org isolation, viewer RBAC |
| `internal/api/alert_events_test.go` | Multiple | List, rule_id filter, cve_id filter, cross-org isolation |

## Open items for Phase 3

- [x] Notification delivery (PLAN.md §11): webhook channels, email, Slack; delivery worker — Phase 3a/3b
- [x] `POST /api/v1/orgs/{org_id}/notification-channels` CRUD — Phase 3a
- [x] Fan-out: `sync.WaitGroup` per-channel, independent error recording (no `errgroup`) — Phase 3a
- [x] Outbound webhook: `doyensec/safeurl` client, redirect disabled, 10s timeout
- [x] Scheduled reports / digests (PLAN.md §12) — Phase 3b
