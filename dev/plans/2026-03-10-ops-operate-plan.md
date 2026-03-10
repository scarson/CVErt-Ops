# Operate Pillar — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Health endpoints, auto-migrate on startup, `cvert-ops doctor` CLI + API, site admin API + UI, Docker production profile, and deployment documentation.

**Architecture:** Health endpoints on main router (no auth). Admin endpoints in admin route group (existing `RequireSiteAdmin`). Doctor uses a `Check` interface so Secure pillar can register checks later. Admin UI is a separate batch from backend API.

**Tech Stack:** Go, chi, huma, cobra, sqlc, Vue 3 + shadcn-vue, Docker Compose

**References:**
- Design: `dev/plans/2026-03-10-ops-operate-design.md`
- Testing pitfalls: `dev/testing-pitfalls.md` (referenced as `tp§N.N`)
- Server: `internal/api/server.go`
- Main: `cmd/cvert-ops/main.go`

**CRITICAL — File Ownership:** This pillar creates `internal/api/admin_*.go`, `cmd/cvert-ops/doctor.go`, admin UI views, and Docker prod profile. Do NOT touch `internal/metrics/*.go` (Observe), `internal/feed/generic/` (Extend), `internal/secure/` (Secure), or `internal/log/` (Observe).

---

## Batch 1: Health & Version Endpoints

### Task 1: Replace `/healthz` with Liveness-Only

**Files:**
- Modify: `internal/api/server.go:186` — replace existing `/healthz`
- Modify: `internal/api/server.go:436-465` — rewrite `healthzHandler`

**Context:** Current `/healthz` does DB ping — too much for liveness, not enough for readiness. Replace with a simple `200 {"status":"alive"}` — no external dependencies checked.

**Step 1: Write test**

```go
func TestHealthzHandler_ReturnsAlive(t *testing.T) {
    // No DB needed — liveness doesn't check anything
    req := httptest.NewRequest("GET", "/healthz", nil)
    rec := httptest.NewRecorder()
    healthzHandler().ServeHTTP(rec, req)
    assert.Equal(t, 200, rec.Code)
    var resp map[string]string
    json.NewDecoder(rec.Body).Decode(&resp)
    assert.Equal(t, "alive", resp["status"])
}
```

**Step 2: Implement** — remove `db *pgxpool.Pool` parameter, return static response.

**Step 3: Update `server.go` to use parameterless `healthzHandler()`.

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 2: `/readyz` Readiness Endpoint

**Files:**
- Create: `internal/api/readyz.go`
- Create: `internal/api/readyz_test.go`
- Modify: `internal/api/server.go` — register `/readyz`

**Context:** Three checks: DB connectivity (ping + latency), migration currency, worker pool running. Returns 200 if all pass, 503 if any critical check fails. No auth required.

**Migration currency:** Query `schema_migrations` for current version, compare against `expectedSchemaVersion` (from `cmd/cvert-ops/main.go`). This means the readyz handler needs access to the expected version — pass it during construction or define it in a shared location.

**Step 1: Write tests**

- Test all checks pass → 200 with JSON showing all "up"/"current"/"running"
- Test DB ping fails → 503 with `database.status = "down"` (tp§8.1)
- Test migration version mismatch → 503 with `migrations.status = "behind"`

**Step 2: Implement.** The handler takes `db *pgxpool.Pool` and `expectedVersion int`. Worker goroutine count can be checked via `runtime.NumGoroutine()` (crude but sufficient for readiness — the design says `goroutines > 0`).

**Step 3: Wire into server.go.** Register alongside `/healthz`: `r.Get("/readyz", readyzHandler(db, expectedSchemaVersion))`. Import the version constant or pass it via Server struct.

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 3: `GET /api/v1/admin/version`

**Files:**
- Create: `internal/api/admin_version.go`
- Create: `internal/api/admin_version_test.go`
- Modify: `internal/api/server.go:214-220` — add route in admin group

**Context:** Returns build metadata. Set via `ldflags`: `-X main.version=... -X main.commit=... -X main.buildTime=...`. The handler reads package-level vars. When not set by ldflags, default to `"dev"`.

**Step 1: Write test**

- Site admin → 200 with version JSON
- Non-admin → 403 (tp§11.1)
- Unauthenticated → 401 (tp§11.1)
- Version fields present (may be "dev" in tests)

**Step 2: Implement.** Define package-level vars in `cmd/cvert-ops/main.go`:
```go
var (
    version   = "dev"
    commit    = "unknown"
    buildTime = "unknown"
)
```

Pass to server via `Server` struct or a `VersionInfo` struct set before `Handler()` is called.

**Step 3: Add route in admin group. Step 4: Run tests → PASS. Step 5: Commit.**

---

## Batch 2: Auto-Migrate on Startup

### Task 4: Auto-Migrate in `serve` Command

**Files:**
- Modify: `cmd/cvert-ops/main.go` — add migration before HTTP server start in `runServe`

**Context:** Before starting the HTTP server:
1. Acquire advisory lock: `pg_advisory_lock(hashtext('cvertops-migrate'))`
2. Run pending migrations (up only)
3. Release advisory lock

The advisory lock hash MUST be distinct from the merge pipeline's FNV advisory lock. Use `hashtext('cvertops-migrate')` which returns a stable int.

Escape hatch: `--skip-auto-migrate` flag on `serve` command.

**Step 1: Add `--skip-auto-migrate` flag**

```go
func serveCmd() *cobra.Command {
    cmd := &cobra.Command{...}
    cmd.Flags().Bool("skip-auto-migrate", false, "Skip automatic migrations on startup")
    return cmd
}
```

**Step 2: Implement auto-migrate function**

```go
func autoMigrate(ctx context.Context, cfg *config.Config) error {
    // Use a separate DB connection for migration (may need DDL privileges)
    // Acquire: SELECT pg_advisory_lock(hashtext('cvertops-migrate'))
    // Run migrations using same pattern as runMigrate()
    // Release: SELECT pg_advisory_unlock(hashtext('cvertops-migrate'))
}
```

**Step 3: Wire into `runServe`** — call after `newPool()`, before `api.NewServer()`.

**Step 4: Test**

- Auto-migrate runs and applies pending migrations (tp§1.1, tp§1.4: advisory lock)
- `--skip-auto-migrate` flag skips migration
- Lock released even on error (use `defer`)

**Step 5: Commit.**

---

## Batch 3: Doctor Framework + CLI

### Task 5: Doctor Check Interface & Checks

**Files:**
- Create: `internal/doctor/doctor.go` — Check interface + runner
- Create: `internal/doctor/checks.go` — all Operate checks
- Create: `internal/doctor/doctor_test.go`

**Context:** The `Check` interface is consumed by both Operate (its own checks) and Secure (adds checks later). The interface is simple:

```go
type Check interface {
    Name() string
    Run(ctx context.Context) (status string, message string, err error)
}
```

Status values: `pass`, `warn`, `fail`.

**Operate checks to implement (from design doc §3):**

| # | Check | What it verifies |
|---|-------|-----------------|
| 1 | Database connectivity | Can connect, latency < 1s |
| 2 | Migration currency | Schema version matches embedded migrations |
| 3 | DB role permissions | `NOBYPASSRLS`, no `SUPERUSER` (query `pg_roles`) |
| 4 | RLS enforcement | All org-scoped tables have `relrowsecurity = true` |
| 5 | Encryption sentinel | Decrypt sentinel from `system_settings` (skip if no sentinel) |
| 6 | JWT configuration | `len(JWT_SECRET) >= 32`, algorithm is HS256 |
| 7 | SMTP connectivity | If SMTP configured, test connection (5s timeout, no send) |
| 8 | Disk/temp space | Writable temp directory exists |
| 9 | Feed schedule | All configured feeds have valid schedule, not permanently failing |

**Checks 3-6 are also specified in the Secure design.** The Operate pillar implements them here. If the Secure pillar adds duplicate checks, they'll be deduplicated during integration (Phase 3). Implement them as part of the doctor package now.

**CRITICAL for Check 5 (encryption sentinel):** The sentinel is written on first `serve` startup (after auto-migrate). The doctor check decrypts it. If no sentinel exists yet, the check should `warn` ("encryption sentinel not initialized — run `serve` once") rather than `fail`.

**CRITICAL for Check 7 (SMTP, tp§8.1):** Don't send any email. Just dial the SMTP host with a 5s timeout. If SMTP isn't configured, skip (return `pass` with "SMTP not configured").

**Step 1: Write tests for each check** — both pass and fail paths.

- DB connectivity: mock/real connection → pass; timeout → fail
- Migration currency: matching version → pass; mismatch → warn
- RLS: real DB with RLS enabled → pass (or check via query mock)
- JWT: secret >= 32 bytes → pass; < 32 → fail
- SMTP not configured → pass (skip)
- Feed schedule: all feeds healthy → pass; permanently failing feed → warn

**Step 2: Implement each check.**

**Step 3: Implement the runner** that collects all checks, runs them, returns structured results.

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 6: `cvert-ops doctor` CLI Subcommand

**Files:**
- Create: `cmd/cvert-ops/doctor.go`
- Modify: `cmd/cvert-ops/main.go` — add `root.AddCommand(doctorCmd())`

**Context:** CLI output: colored pass/warn/fail per check, summary line. Exit code 0 if all pass, 1 if any warn/fail. Connects to DB, runs checks, prints results.

**Step 1: Implement `doctorCmd()`** following the pattern of `migrateCmd()` — load config, connect to DB, create checks, run.

**Step 2: Test** by running `go run ./cmd/cvert-ops doctor` against dev DB.

**Step 3: Commit.**

### Task 7: `GET /api/v1/admin/doctor` API Endpoint

**Files:**
- Create: `internal/api/admin_doctor.go`
- Create: `internal/api/admin_doctor_test.go`
- Modify: `internal/api/server.go` — add route in admin group

**Context:** Same checks as CLI, JSON response. 200 if all pass, 503 if any fail. This endpoint also runs the "Security headers" check (HTTP GET to own `/healthz`) since the server is running.

**Step 1: Write test** — admin auth required (tp§11.1), returns check results JSON.

**Step 2: Implement.** The handler constructs checks (same as CLI) and runs them.

**Step 3: Wire route. Step 4: Run tests → PASS. Step 5: Commit.**

---

## Batch 4: Site Admin API — Org & User Management

### Task 8: Admin Org Management

**Files:**
- Create: `internal/api/admin_orgs.go`
- Create: `internal/api/admin_orgs_test.go`
- Create: sqlc queries as needed in `internal/store/queries/admin_*.sql`
- Modify: `internal/api/server.go` — add routes in admin group

**Context:** Three endpoints per design doc §4:
- `GET /api/v1/admin/orgs` — list all orgs with `last_activity_at` (keyset-paginated)
- `PATCH /api/v1/admin/orgs/{org_id}` — update tier, suspend/unsuspend
- `GET /api/v1/admin/orgs/{org_id}/usage` — resource counts

**CRITICAL (tp§7.1):** All admin store methods MUST use `withBypassTx`. Admin is not a member of target orgs — `withOrgTx` would scope to admin's org.

**Step 1: Write sqlc queries.** Use `withBypassTx` pattern.

**Step 2: Write tests** for each endpoint:
- Admin → 200 with data
- Non-admin → 403
- List: verify keyset pagination (tp§4.3)
- PATCH: verify tier update persists
- Usage: verify counts are accurate

**Step 3: Implement handlers. Step 4: Wire routes. Step 5: Run tests → PASS. Step 6: Commit.**

### Task 9: Admin User Management

**Files:**
- Create: `internal/api/admin_users.go`
- Create: `internal/api/admin_users_test.go`
- Create: migration for `disabled_at` column on users table
- Modify: auth middleware — add `AND disabled_at IS NULL` to user lookup

**Context:** Five endpoints per design doc §4:
- `GET /api/v1/admin/users` — list all users (keyset-paginated)
- `POST /api/v1/admin/users/{user_id}/unlock` — unlock locked account (404 if not found, tp§3.4)
- `POST /api/v1/admin/users/{user_id}/disable` — set `disabled_at` (404 if not found)
- `POST /api/v1/admin/users/{user_id}/enable` — clear `disabled_at` (404 if not found)
- `POST /api/v1/admin/users/{user_id}/reset-password` — set force-reset flag (404 if not found)

**CRITICAL — Disabled user JWT gap:** Auth middleware's user lookup query MUST add `AND disabled_at IS NULL`. Test: disable user → next API call returns 401 (tp§11.1).

**Step 1: Create migration** for `disabled_at TIMESTAMPTZ` column on users table.

**Step 2: Write tests** for each endpoint — including 404 for nonexistent user (tp§3.4).

**Step 3: Implement handlers + store methods (all `withBypassTx`).

**Step 4: Modify auth middleware** to filter disabled users.

**Step 5: Test disabled user flow** — disable, verify 401. Step 6: Commit.**

---

## Batch 5: Site Admin API — Feed & Delivery Management

### Task 10: Admin Feed Management

**Files:**
- Create: `internal/api/admin_feeds.go` (or extend existing)
- Create: `internal/api/admin_feeds_test.go`
- Modify: `internal/api/server.go` — add routes

**Context:** Three new endpoints (extend existing feed admin):
- `POST /api/v1/admin/feeds/{feed}/pause` — pause schedule
- `POST /api/v1/admin/feeds/{feed}/resume` — resume schedule
- `GET /api/v1/admin/feeds/{feed}/logs` — paginated fetch logs

**Step 1: Write tests. Step 2: Implement. Step 3: Wire routes. Step 4: Commit.**

### Task 11: Admin Delivery Management

**Files:**
- Create: `internal/api/admin_deliveries.go`
- Create: `internal/api/admin_deliveries_test.go`
- Modify: `internal/api/server.go` — add routes

**Context:** Three endpoints:
- `GET /api/v1/admin/deliveries` — list failed/stale across orgs (filterable, keyset-paginated, `withBypassTx`)
- `POST /api/v1/admin/deliveries/{id}/retry` — retry one (404 if not found, 409 if not retryable, tp§1.5)
- `POST /api/v1/admin/deliveries/retry-failed` — bulk retry (limit param, default 100, max 1000)

**CRITICAL (tp§1.5):** Retry only if status IN ('failed', 'dead_letter'). Returns 409 if in-progress.

**Step 1: Write tests — including 409 for in-progress delivery. Step 2: Implement. Step 3: Commit.**

### Task 12: Admin System Endpoints

**Files:**
- Create: `internal/api/admin_system.go`
- Create: `internal/api/admin_system_test.go`

**Context:** Remaining admin endpoints:
- `POST /api/v1/admin/reindex` — trigger search index rebuild (202 Accepted, async)
- `GET /api/v1/admin/config` — runtime config, secrets redacted
- `GET /api/v1/admin/audit-log` — cross-org audit log (keyset-paginated, `withBypassTx`)

**Step 1: Write tests. Step 2: Implement. Step 3: Commit.**

---

## Batch 6: Docker Production Profile

### Task 13: `docker/compose.prod.yml`

**Files:**
- Create: `docker/compose.prod.yml`

**Context:** Overlay on dev compose using `docker compose -f docker/compose.yml -f docker/compose.prod.yml`. MUST NOT modify existing `docker/compose.yml`.

Contents per design doc §6:
- Caddy with automatic TLS (production Caddyfile)
- Resource limits on all containers
- Restart policies (`unless-stopped`)
- Log driver config (json-file with max-size/max-file rotation)
- Named volumes for Postgres data persistence
- Network isolation (metrics port on internal network only)
- Health checks with appropriate intervals

**Step 1: Write the compose file. Step 2: Validate with `docker compose -f ... -f ... config`. Step 3: Commit.**

---

## Batch 7: Admin UI

**Context:** Separate batch from backend. Seven pages, each cloning a specific existing page as template per design doc §5. Use existing shadcn-vue components.

### Task 14: Admin Route Guard & Layout

**Files:**
- Create: `web/src/views/admin/AdminLayout.vue`
- Create: `web/src/router/admin.ts` (or add to existing router)

**Context:** `/admin` section guarded by site admin role check. Read existing `MembersView.vue` to understand the layout pattern. The admin layout includes navigation sidebar with links to all admin pages.

**Step 1: Implement route guard. Step 2: Implement layout. Step 3: Commit.**

### Task 15-20: Admin Pages (Dashboard, Orgs, Users, Feed Status, Deliveries, Audit Log, System)

Each page follows an existing page as template (specified in design doc §5):
- **Dashboard** — summary cards + recent activity (new layout)
- **Organizations** — follows `MembersView` pattern
- **Users** — follows `MembersView` pattern
- **Feed Status** — extends existing `FeedStatusView`
- **Deliveries** — follows `MembersView` pattern
- **Audit Log** — follows CVE search pattern
- **System** — read-only cards (config, doctor, version)

Each page is one task. For each:
1. Read the template page to understand patterns
2. Create the admin page adapting the pattern to admin data
3. Connect to the admin API endpoints built in Batches 4-5
4. Test basic rendering and data flow
5. Commit

---

## Batch 8: Deployment Documentation

### Task 21: Deployment Docs

**Files:**
- Create: `docs/deployment/getting-started.md`
- Create: `docs/deployment/production.md`
- Create: `docs/deployment/upgrading.md`
- Create: `docs/deployment/tls.md`
- Create: `docs/deployment/runbooks/feed-failure.md`
- Create: `docs/deployment/runbooks/delivery-failure.md`
- Create: `docs/deployment/runbooks/db-recovery.md`
- Create: `docs/deployment/runbooks/upgrade-checklist.md`

**Context:** Content specified in design doc §7. Each document covers the exact topics listed. `runbooks/secret-rotation.md` is a Secure pillar deliverable — do NOT create it here.

**Step 1: Write docs. Step 2: Commit.**

---

## Batch 9: Final Verification

### Task 22: Full Test Suite & Lint

**Step 1:** `go test ./... -race -count=1`
**Step 2:** `golangci-lint run`
**Step 3:** `cd web && npm run build && npm run lint`
**Step 4:** Fix issues. Final commit.

---

## Subagent Failure Modes to Watch For

| Risk | What goes wrong | Mitigation |
|------|----------------|------------|
| Admin store uses `withOrgTx` (tp§7.1) | Cross-org queries return wrong data | Every admin store method MUST use `withBypassTx` — explicit in Tasks 8-12 |
| Silent 204 on missing resources (tp§3.4) | Admin actions appear to succeed on nonexistent targets | All POST admin actions return 404 for nonexistent targets — tested explicitly |
| Disabled user JWT gap | Disabled user can still make API calls | Task 9 modifies auth middleware and tests the flow end-to-end |
| Auto-migrate races (tp§1.1, §1.4) | Two instances both run migrations | Task 4 uses advisory lock with distinct hash |
| Docker compose.prod modifies dev compose | Dev workflow breaks | Task 13 explicitly: "MUST NOT modify existing compose.yml" |
| Admin UI creative decisions | Agent invents UI patterns instead of cloning | Each page specifies exact template to follow |
| Delivery retry idempotency (tp§1.5) | Re-retry of in-progress delivery | Task 11 tests 409 for in-progress status |
| expectedSchemaVersion stale (tp§5.4) | Startup warning on every boot | Version bumped after all migrations |
| Version endpoint leaks info to non-admin | Build metadata exposed publicly | Task 3 tests non-admin → 403 |
| Doctor false positive on missing sentinel | Encryption sentinel doesn't exist yet | Task 5 specifies warn (not fail) when sentinel missing |
