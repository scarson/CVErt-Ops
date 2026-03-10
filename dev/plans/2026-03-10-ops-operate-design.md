# Operate — Design

**Date:** 2026-03-10
**Status:** Design approved
**Pillar:** Operate
**Prerequisites:** Phase 0 (system_settings migration, admin middleware verification)
**Overview doc:** `2026-03-10-ops-maturity-overview.md`

## Current State

- `/healthz` exists — DB ping only, returns ok/degraded
- `cvert-ops migrate` subcommand exists but isn't auto-run on startup
- Site admin flag (`is_site_admin`) exists on users, enforced by `RequireSiteAdmin()` middleware
- Feed admin endpoints exist (`GET /admin/feeds`, `POST /admin/feeds/{feed}/run`)
- Docker Compose for dev (Postgres + Mailpit + Caddy), `--profile app` for full stack
- No `/readyz`, no `doctor` CLI, no admin UI beyond feed status, no deployment guide

## Design Principle

Admins handle everything inside the application. Operators handle infrastructure only. If an admin needs to call an operator to retry a failed webhook delivery, the product has failed.

**Operator-only (CLI/shell):** Backup/restore, view runtime config, run migrations manually.
**Everything else:** Available to site admins via API and UI.

## 1. Health & Version Endpoints

### `/healthz` (liveness)

"Is the process alive?" Kubernetes uses this to decide whether to restart the pod.

- No external dependencies checked
- Returns `200 {"status":"alive"}`
- Always succeeds unless the process is deadlocked
- No auth required

### `/readyz` (readiness)

"Can this instance accept traffic?" Kubernetes uses this to decide whether to route traffic.

Checks:
- Database connectivity (ping + latency)
- Migration currency (expected schema version matches actual)
- Worker pool running (goroutine count > 0)

Returns `200` if all pass, `503` if any critical check fails:
```json
{
  "status": "ready",
  "checks": {
    "database": {"status": "up", "latency_ms": 2},
    "migrations": {"status": "current", "version": 67},
    "worker": {"status": "running", "goroutines": 4}
  }
}
```
No auth required.

### `GET /api/v1/admin/version`

Returns build metadata (requires site admin auth):
```json
{
  "version": "1.2.0",
  "commit": "abc123",
  "build_time": "2026-03-09T14:00:00Z",
  "go_version": "go1.26"
}
```

Set via `ldflags` at build time: `-ldflags "-X main.version=... -X main.commit=... -X main.buildTime=..."`. The Dockerfile and CI workflow must pass these flags. Also displayed in the admin UI header/footer.

### Replaces existing `/healthz`

The current `/healthz` does too much for liveness and too little for readiness. Replace it with the split above.

## 2. Auto-Migrate on Startup

Modify `cvert-ops serve` to run pending migrations before starting the HTTP server.

### Sequence

1. Connect to database
2. Acquire Postgres advisory lock: `pg_advisory_lock(hashtext('cvertops-migrate'))`
3. Run pending migrations (up only)
4. Release advisory lock
5. Start HTTP server + worker pool

The advisory lock hash (`hashtext('cvertops-migrate')`) MUST be distinct from the merge pipeline's FNV advisory lock and any other locks.

### Escape hatch

`--skip-auto-migrate` flag on `serve`. For operators who run migrations via separate init container or CI step.

### Rollback

Auto-migrate only runs `up`. Rollbacks remain manual: `cvert-ops migrate --down 1`.

## 3. `cvert-ops doctor`

New cobra subcommand + `GET /api/v1/admin/doctor` (same checks, JSON response).

### system_settings Table (Phase 0)

Migration creates: `system_settings (key TEXT PRIMARY KEY, value BYTEA, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`.

On first `cvert-ops serve` startup, the encryption sentinel is written: encrypt a known plaintext with the current AES key, store as `key='encryption_sentinel'`. Doctor decrypts and verifies on each run.

### Checks

Each check returns `(status string, message string, error)` where status is `pass`, `warn`, or `fail`.

| Check | What it verifies |
|-------|------------------|
| **Database connectivity** | Can connect, latency < 1s |
| **Migration currency** | Schema version matches embedded migrations |
| **DB role permissions** | App role has `NOBYPASSRLS`, no `SUPERUSER` (query `pg_roles`) |
| **RLS enforcement** | All org-scoped tables have `relrowsecurity = true` (query `pg_class`) |
| **Encryption sentinel** | Decrypt sentinel from `system_settings`. Fails if key changed without rotation. |
| **JWT configuration** | `len(JWT_SECRET) >= 32`, algorithm is HS256. If `JWT_SECRET_PREVIOUS` set, also >= 32 bytes. |
| **Security headers** | HTTP GET to own `/healthz`, verify `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`. **API doctor mode only** (server running). CLI skips this check. |
| **SSRF protection** | Call safeurl's URL validation with `http://169.254.169.254/` and `http://127.0.0.1:8080/`. Verify both rejected. No actual HTTP request made. |
| **CORS configuration** | If `CORS_ALLOWED_ORIGINS` contains `*` and cookie auth is enabled, warn. (testing-pitfalls §5.1) |
| **SMTP connectivity** | If SMTP configured, test connection (5s timeout, no send). |
| **Disk/temp space** | Writable temp directory exists |
| **Feed schedule** | All configured feeds have a valid schedule and aren't permanently failing. Also validates generic feed configs if `CVERTOPS_FEEDS_DIR` is set (light validation: YAML parses, required fields present). |

### CLI output

Colored pass/warn/fail per check, summary line. Exit code 0 if all pass, 1 if any warn/fail.

### API output

JSON array of check results. 200 if all pass, 503 if any fail.

### Doctor Check Interface

The Secure pillar will add additional checks (§3.5 of Secure design). Doctor exposes a `Check` interface:

```go
type Check interface {
    Name() string
    Run(ctx context.Context) (status string, message string, err error)
}
```

Operate registers the checks above. Secure registers its own checks using the same interface.

## 4. Site Admin Capabilities

### Transaction Helper Rule

All admin store methods that query across orgs MUST use `withBypassTx`. Admin is not a member of target orgs — `withOrgTx` would scope to the admin's org, returning wrong results.

### Org Management

- `GET /api/v1/admin/orgs` — List all orgs. Fields: id, name, tier, member_count, created_at, last_activity_at. `last_activity_at` derived from `MAX(users.last_login_at)` via join through `org_members`. Keyset-paginated.
- `PATCH /api/v1/admin/orgs/{org_id}` — Update tier, suspend/unsuspend.
- `GET /api/v1/admin/orgs/{org_id}/usage` — Resource counts: rules, watchlists, members, channels.

### User Management

- `GET /api/v1/admin/users` — List all users. Fields: id, email, display_name, org_memberships, last_login_at, locked, disabled. Keyset-paginated.
- `POST /api/v1/admin/users/{user_id}/unlock` — Unlock locked account. Returns 404 if user doesn't exist (NOT silent 204).
- `POST /api/v1/admin/users/{user_id}/disable` — Disable account (sets `disabled_at`). Returns 404 if not found.
- `POST /api/v1/admin/users/{user_id}/enable` — Re-enable disabled account. Returns 404 if not found.
- `POST /api/v1/admin/users/{user_id}/reset-password` — Force password reset on next login (sets flag, doesn't email). Returns 404 if not found.

**Disabled user handling:** `disabled_at` timestamp on users table. Auth middleware's user lookup query adds `AND disabled_at IS NULL`. Disabled users get 401 on their next API request — no token blacklist needed.

### Feed Management (extend existing)

- `POST /api/v1/admin/feeds/{feed}/pause` — Pause schedule.
- `POST /api/v1/admin/feeds/{feed}/resume` — Resume schedule.
- `GET /api/v1/admin/feeds/{feed}/logs` — Paginated fetch logs.

### Notification Delivery

- `GET /api/v1/admin/deliveries` — List failed/stale deliveries across orgs. Filterable by org, channel_type, status. Keyset-paginated.
- `POST /api/v1/admin/deliveries/{id}/retry` — Retry one. Returns 404 if not found, 409 if not in retryable state (`failed` or `dead_letter`).
- `POST /api/v1/admin/deliveries/retry-failed` — Bulk retry. Accepts `limit` parameter (default 100, max 1000). Response: `{"retried": 47, "remaining": 203}`. Prevents webhook amplification.

### System

- `GET /api/v1/admin/doctor` — Run doctor checks (JSON).
- `GET /api/v1/admin/version` — Build metadata.
- `POST /api/v1/admin/reindex` — Trigger search index rebuild (202 Accepted, async via job queue).
- `GET /api/v1/admin/config` — Runtime config, secrets redacted. Shows which optional features are configured vs unconfigured (e.g., "SMTP: configured", "Gemini API: not configured").
- `GET /api/v1/admin/audit-log` — Cross-org audit log. Filterable by org, user, event_type, date range. Keyset-paginated. Uses `withBypassTx`.

## 5. Admin UI

New `/admin` section in the Vue frontend, guarded by site admin role check. Split into a separate implementation batch from the backend API.

### Pages

| Page | Pattern to follow (existing file) |
|------|-----------------------------------|
| **Dashboard** | New layout — summary cards (org count, feed status, delivery failures, doctor results) + recent activity list |
| **Organizations** | Follow `MembersView` — data table + search + tier badges + suspend toggle + usage drill-down |
| **Users** | Follow `MembersView` — data table + search + lock/disabled status badges + unlock/disable/enable/reset actions |
| **Feed Status** | Extend existing `FeedStatusView` — add pause/resume buttons, force-run, log viewer with pagination |
| **Deliveries** | Follow `MembersView` — data table + filters (org, channel, status) + retry action buttons |
| **Audit Log** | Follow CVE search pattern — data table + filter sidebar + date range picker |
| **System** | Read-only cards: config display (redacted), doctor results (run on-demand), version info |

Each page references a specific existing page as its template. The agent clones the pattern and adapts it — no creative UI decisions. Use existing shadcn-vue components.

## 6. Docker Compose Production Profile

`docker/compose.prod.yml` — overlay on the dev compose using `docker compose -f ... -f ...` merge.

Contents:
- Caddy with automatic TLS (production Caddyfile)
- Resource limits on all containers
- Restart policies (`unless-stopped`)
- Log driver config (json-file with max-size/max-file rotation)
- Named volumes for Postgres data persistence
- Network isolation (metrics port on internal network only)
- Health checks with appropriate intervals

**Must NOT modify the existing `docker/compose.yml`.**

## 7. Deployment Guide & Runbooks

`docs/deployment/` directory:

| Document | Content |
|----------|---------|
| `getting-started.md` | Quickstart: Docker Compose, env vars, first admin user, verify with `doctor` |
| `production.md` | Production hardening: TLS termination (Caddy/nginx/ALB examples), backup strategy, resource sizing, monitoring setup |
| `upgrading.md` | Version upgrade procedure: backup → pull → restart → auto-migrate runs → verify with `doctor`. How to rollback. |
| `tls.md` | TLS termination options: Caddy (built-in ACME), nginx, AWS ALB, Azure App Gateway. End-to-end TLS with `--tls-cert`/`--tls-key` flags. ACME integration via post-renewal hooks. `TRUSTED_PROXIES` config. |
| `runbooks/feed-failure.md` | Feed adapter failure diagnosis and recovery |
| `runbooks/delivery-failure.md` | Notification delivery failure diagnosis |
| `runbooks/db-recovery.md` | Database backup/restore procedures |
| `runbooks/upgrade-checklist.md` | Step-by-step pre/post upgrade verification |

**Note:** `runbooks/secret-rotation.md` is a Secure pillar deliverable, not Operate.

## What We Won't Build

- Kubernetes manifests or Helm charts (operators adapt Docker Compose; a half-baked Helm chart is worse than none)
- Built-in backup tooling (pg_dump is standard; we document it)
- Multi-instance coordination (single-instance Phase 1; scaling docs come with SaaS)

## Subagent Risk Areas

| Risk | Mitigation |
|------|------------|
| Admin API scope creep | Exact endpoints with request/response shapes listed above. Implement only what's listed. |
| Admin UI consistency | Each page specifies which existing page to clone as template, by filename. |
| Admin UI scope | Backend API and frontend UI are separate task batches. API first, UI second. Can be parallel agents. |
| Doctor false positives | Each check has a pass test AND a fail test. SSRF check uses safeurl validation, not actual HTTP. Security headers check: API mode only, CLI skips. |
| Auto-migrate race condition | Advisory lock with dedicated hash. Test: two concurrent startups, exactly one migrates. Test: migration failure mid-way still releases lock. (testing-pitfalls §1.1, §1.4) |
| Health endpoint contract | Exact JSON response schemas specified. Tests assert structure, not just status codes. Tests cover degraded states (DB down, migrations pending). |
| Admin auth bypass | Every admin endpoint tested with non-admin → 403, unauthenticated → 401. (testing-pitfalls §11.1) |
| Delivery retry idempotency | Retry only if status IN ('failed', 'dead_letter'). Returns 409 if in-progress. (testing-pitfalls §1.5) |
| Silent success on missing resources | All admin POST actions return 404 for nonexistent targets — never silent 204. (testing-pitfalls §3.4) |
| Cross-org transaction helpers | All admin store methods use `withBypassTx`. Tests verify cross-org visibility. (testing-pitfalls §7.1) |
| Error path testing | Every admin endpoint has explicit error-path tests — DB failure, invalid input, missing resource. (testing-pitfalls §3.2) |
| Docker Compose prod profile | Must NOT modify existing dev compose.yml. Separate override file only. |
| Disabled user JWT gap | Auth middleware user lookup adds `disabled_at IS NULL`. Test: disable user, next API call returns 401. |
| system_settings migration | Phase 0 deliverable. Follows project conventions (concurrent index if applicable, ABOUTME header). |
| Version via ldflags | Dockerfile and CI must pass `-ldflags`. Test: version endpoint returns non-empty values when built with flags, returns "dev" or similar when not. |
