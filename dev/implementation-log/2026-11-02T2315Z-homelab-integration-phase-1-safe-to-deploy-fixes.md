# Homelab Integration Phase 1 — Safe-to-Deploy Fixes

> **Date:** 2026-11-02
> **Commits:** `b7fc407`..HEAD on `claude/safe-to-deploy-fixes` (branched from dev `2dcffc8`)
> **Source:** homelab integration requirements review (`2026-11-02-cvert-ops-integration-requirements.md`, outside the repo), phase "safe to deploy"

## What was built

| Fix | Files | Description |
|---|---|---|
| Readiness schema version | `migrations/version.go`, `cmd/cvert-ops/main.go`, `cmd/cvert-ops/doctor.go` | `migrations.LatestVersion` walks the embedded migrations with golang-migrate's `iofs` driver; replaces the hand-maintained constant (39 against 45 migrations) that made `/readyz` report not-ready |
| API keys on admin routes | `internal/api/middleware_site_admin.go` | `RequireSiteAdmin` returns 403 for any API-key request; before, a viewer key created by the site admin had full `/api/v1/admin` access |
| Channel test headers | `internal/notify/webhook.go`, `worker.go`, `internal/api/channels.go` | `notify.ChannelWebhookConfig` builds the delivery config from a stored channel for both the worker and `POST /channels/{id}/test`; the test endpoint had read `config.headers` instead of `config.custom_headers` |
| Audit writer in serve | `cmd/cvert-ops/main.go` | `newAPIServer` constructs `audit.Writer` (never set in production, so no handler mutation was audited) and serve flushes it before the pool closes |
| Acting API key in audit rows | `migrations/000046_*`, `internal/store/audit.go`, `admin_system.go`, `internal/audit/writer.go`, `internal/api/{context,middleware_auth,server,audit_log}.go` | `audit_log.api_key_id` (nullable, not a FK), filled from `ctxAPIKeyID` by `srv.auditLog`, returned as `api_key_id` by both audit-log endpoints |

## Key implementation decisions

- **Reject keys on admin routes outright** rather than adding a `site_admin` flag to keys. No caller needs key-based admin access yet.
- **No `actor_type` column**: a non-null `api_key_id` identifies key actions, and a null `actor_id` identifies system actions.
- **Audit wiring tested through the composition function**: `newAPIServer` is extracted from `runServe` so a test can create a channel through the production server and observe the `audit_log` row. Making `api.NewServer` require a writer would have touched about 60 test call sites.

## Gotchas discovered

- **DB-16 hit again**: a semicolon in a migration comment split the statement under `MultiStatementEnabled`. The `migration` skill's pre-write checklist does not include this item.
- **`ListAuditEntries` needs both time bounds**: `created_at <= @before` with a zero `Before` matches nothing.
- **Ryuk dies with exit 1 after a Docker Desktop restart** (engine 28.1.1, ryuk 0.13.0, testcontainers-go 0.42.0), while the same image runs fine via `docker run`. Workaround: `TESTCONTAINERS_RYUK_DISABLED=true`, as CI already does. Root cause not found.
- **`sqlc generate` rewrites every generated file with LF endings** in a CRLF checkout. Only three files had content changes, and only those were staged.
- **Found, not fixed:** `POST /admin/reindex` enqueues a NULL payload (500 on `job_queue.payload NOT NULL`), and no worker handles `system_reindex`. Admin org and user mutations make no audit calls.

## Quality checks

- **golangci-lint:** 0 issues on changed packages
- **Tests:** affected packages pass with `TESTCONTAINERS_RYUK_DISABLED=true`: `internal/api` (595s), `internal/store` (377s), `internal/audit`, `internal/doctor`, `migrations`, `cmd/cvert-ops`; `internal/notify` passed separately. Full suite not run.
- **New tests:** `TestLatestVersion_*` (3), `TestRequireSiteAdmin_APIKey_403` (viewer, member, admin), `TestAdminRoutes_APIKey_403` (23 routes plus a session-cookie control), `TestChannelWebhookConfig_CustomHeadersReachReceiver`, `TestNewAPIServer_AuditsMutations`, `TestAuditLog_RecordsActingAPIKey`
