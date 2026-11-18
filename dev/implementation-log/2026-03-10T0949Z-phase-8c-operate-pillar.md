# Phase 8C — Operate Pillar

**Branch:** `phase-8c-operate` (worktree: `.worktrees/phase-8c-operate`)
**Plan:** `dev/plans/2026-03-10-ops-operate-plan.md`

## What was built

9 batches across 22 tasks implementing the "Operate" pillar:

1. **Health endpoints** — `/healthz` (liveness, no dependencies), `/readyz` (readiness: DB ping + migration check)
2. **Auto-migrate + version** — Advisory-locked auto-migration on `serve` startup; `/api/v1/admin/version` with ldflags injection
3. **Doctor framework** — `Check` interface, 9 health checks (DB connectivity, migration currency, DB role, RLS enforcement, encryption sentinel, JWT config, SMTP, disk, feed schedule), CLI `cvert-ops doctor` command, API endpoint
4. **Admin org/user management** — `disabled_at`/`locked_at`/`failed_login_count`/`force_password_reset` migration; admin list/patch/suspend/unsuspend orgs; admin list/disable/enable/unlock/reset-password users; disabled-user middleware check
5. **Admin feed/delivery/system** — Feed status with pause/resume/trigger; delivery list with retry/bulk-retry; audit log listing; config/doctor/version admin endpoints
6. **Docker production compose** — `compose.prod.yml` overlay with resource limits, log rotation, Caddy reverse proxy, production env defaults
7. **Admin UI** — 7 Vue pages (Dashboard, Orgs, Users, Feeds, Deliveries, Audit Log, System), route guard (`requiresAdmin`), sidebar guard (`isSiteAdmin`)
8. **Deployment docs** — 4 guides (getting-started, production, upgrading, TLS) + 4 runbooks (feed-failure, delivery-failure, db-recovery, upgrade-checklist)
9. **Final verification** — Go lint clean (except 3 pre-existing gosec false positives in `secure/events.go`), frontend build/lint/type-check/421 tests clean

## Key decisions

- **`sql.NullTime` → `*time.Time` in API-facing structs:** `sql.NullTime` serializes as `{"Time":"...","Valid":true}` not `null`. Created `fromNullTime()` converter pattern for all admin row types.
- **`adminOrgResponse` wrapper:** `generated.Organization` has no json tags (sqlc-generated). Created a separate response struct for the PATCH handler.
- **Caddy in Docker Compose:** Included as optional `--profile app` service for automatic ACME TLS. Not mandatory — operators can use nginx/ALB/etc.
- **Doctor `Check` interface:** Designed for extensibility — Secure pillar can register additional checks without modifying doctor core.
- **Auto-migrate advisory lock:** Uses `pg_advisory_lock(hashtext('cvert-ops-migrate'))` to prevent multiple instances from migrating concurrently.

## Gotchas

- **Select empty string value:** shadcn-vue `<SelectItem value="">` doesn't work — reka-ui requires non-empty `AcceptableValue`. Used `'all'` as sentinel and mapped to empty string in the fetch logic.
- **Pre-existing test failure:** `TestLoad_Defaults` in `config_test.go` expects `RegistrationMode` default `"open"` but code default is `"invite-only"`. Not introduced by this branch.
- **`-race` not available on Windows without CGO_ENABLED=1.** Integration tests (store, merge, notify) require Docker/testcontainers.

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** 3 pre-existing gosec false positives only
- **Frontend type-check:** Clean
- **Frontend lint (oxlint + eslint):** Clean
- **Frontend build (Vite):** Clean
- **Frontend tests (Vitest):** 421/421 pass across 32 test files
- **Go unit tests:** All Phase 8C packages pass (api, doctor, auth, crypto, tier, worker, secure, alert, cmd)
