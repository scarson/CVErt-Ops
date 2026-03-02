# Phase 5 — Hardening & SaaS Readiness: Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add tier enforcement with per-org rate limiting, automated data retention cleanup, append-only audit log with secret redaction, and generic OIDC SSO.

**Architecture:** Four sequential work streams — tier enforcement (foundation), data retention (uses tiers), audit log (uses retention), generic OIDC (uses tier gating + audit). Each stream is a set of TDD tasks with frequent commits.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, huma/chi, `coreos/go-oidc/v3`, `crypto/aes` (GCM), testcontainers-go

**Design doc:** `dev/plans/2026-03-01-phase5-hardening-saas-readiness-design.md`

**Key codebase patterns (reference these throughout):**
- Migrations: `migrations/000025_*.{up,down}.sql`, `-- migrate:no-transaction` first line, `CREATE INDEX CONCURRENTLY IF NOT EXISTS`
- Store: `internal/store/store.go` — `withOrgTx`, `withBypassTx`, `WorkerTx`, `OrgTx`
- sqlc queries: `internal/store/queries/*.sql` → generates `internal/store/generated/*.sql.go`
- Context values: `ctxOrgID`, `ctxUserID`, `ctxRole`, `ctxClientIP` in `internal/api/context.go`
- Test DB: `internal/testutil/postgres.go` — `NewTestDB(t)` returns `TestDB{Store, AppStore}`
- Route registration: `internal/api/server.go` `Handler()` method
- Dependency injection: `Set*Deps()` methods, not constructor params
- Worker ticker pattern: `internal/notify/worker.go` `Start()` select-loop

---

## Phase 5A: Tier Enforcement

### Task 1: Migration — Add tier columns to organizations

**Files:**
- Create: `migrations/000025_org_tier.up.sql`
- Create: `migrations/000025_org_tier.down.sql`

**Step 1: Write the up migration**

Note: No `-- migrate:no-transaction` needed — this migration has no `CREATE INDEX CONCURRENTLY`.

```sql
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'free';
ALTER TABLE organizations ADD CONSTRAINT organizations_tier_check CHECK (tier IN ('free', 'pro', 'enterprise'));
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier_overrides JSONB NOT NULL DEFAULT '{}';
```

**Step 2: Write the down migration**

```sql
ALTER TABLE organizations DROP COLUMN IF EXISTS tier_overrides;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_tier_check;
ALTER TABLE organizations DROP COLUMN IF EXISTS tier;
```

**Step 3: Run migration**

Run: `cd /c/Users/Sam/Code/CVErt-Ops && go run ./cmd/cvert-ops migrate`
Expected: Migration 000025 applied successfully.

**Step 4: Verify with rollback test**

Run: `migrate -path migrations -database "$DATABASE_URL" down 1 && migrate -path migrations -database "$DATABASE_URL" up`
Expected: Clean rollback and re-apply.

**Step 5: Commit**

```bash
git add migrations/000025_org_tier.up.sql migrations/000025_org_tier.down.sql
git commit -m "migration: add tier + tier_overrides to organizations"
```

---

### Task 2: Tier Resolver package — TDD

**Files:**
- Create: `internal/tier/resolver.go`
- Create: `internal/tier/resolver_test.go`

**Step 1: Write failing tests**

```go
// internal/tier/resolver_test.go
package tier

import "testing"

func TestIntLimit(t *testing.T) {
    tests := []struct {
        name       string
        tier       string
        overrides  map[string]any
        limitName  string
        free, pro, enterprise int
        want       int
    }{
        {"free default", "free", nil, "max_alert_rules", 5, 50, -1, 5},
        {"pro default", "pro", nil, "max_alert_rules", 5, 50, -1, 50},
        {"enterprise default", "enterprise", nil, "max_alert_rules", 5, 50, -1, -1},
        {"unknown tier falls back to free", "unknown", nil, "max_alert_rules", 5, 50, -1, 5},
        {"override takes precedence", "free", map[string]any{"max_alert_rules": float64(100)}, "max_alert_rules", 5, 50, -1, 100},
        {"override zero is valid", "pro", map[string]any{"max_alert_rules": float64(0)}, "max_alert_rules", 5, 50, -1, 0},
        {"wrong key ignored", "pro", map[string]any{"wrong_key": float64(99)}, "max_alert_rules", 5, 50, -1, 50},
        {"empty overrides map", "pro", map[string]any{}, "max_alert_rules", 5, 50, -1, 50},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            r := Resolver{Tier: tt.tier, Overrides: tt.overrides}
            got := r.IntLimit(tt.limitName, tt.free, tt.pro, tt.enterprise)
            if got != tt.want {
                t.Errorf("IntLimit() = %d, want %d", got, tt.want)
            }
        })
    }
}

func TestBoolFlag(t *testing.T) {
    tests := []struct {
        name      string
        tier      string
        overrides map[string]any
        flagName  string
        free, pro, enterprise bool
        want      bool
    }{
        {"free no email", "free", nil, "channels_email", false, true, true, false},
        {"pro has email", "pro", nil, "channels_email", false, true, true, true},
        {"override enables for free", "free", map[string]any{"channels_email": true}, "channels_email", false, true, true, true},
        {"override disables for pro", "pro", map[string]any{"channels_email": false}, "channels_email", false, true, true, false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            r := Resolver{Tier: tt.tier, Overrides: tt.overrides}
            got := r.BoolFlag(tt.flagName, tt.free, tt.pro, tt.enterprise)
            if got != tt.want {
                t.Errorf("BoolFlag() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tier/... -v`
Expected: FAIL — package does not exist yet.

**Step 3: Write minimal implementation**

```go
// internal/tier/resolver.go
// ABOUTME: Resolves tier-gated limits and feature flags for organizations.
// ABOUTME: Precedence: per-org override → tier default → free fallback.
package tier

// Resolver resolves tier-gated limits for a single organization.
type Resolver struct {
    Tier      string         // "free", "pro", "enterprise"
    Overrides map[string]any // from organizations.tier_overrides JSONB
}

// IntLimit returns the effective integer limit. -1 means unlimited.
func (r *Resolver) IntLimit(name string, free, pro, enterprise int) int {
    if r.Overrides != nil {
        if v, ok := r.Overrides[name]; ok {
            if f, ok := v.(float64); ok {
                return int(f)
            }
        }
    }
    switch r.Tier {
    case "pro":
        return pro
    case "enterprise":
        return enterprise
    default:
        return free
    }
}

// BoolFlag returns the effective boolean flag.
func (r *Resolver) BoolFlag(name string, free, pro, enterprise bool) bool {
    if r.Overrides != nil {
        if v, ok := r.Overrides[name]; ok {
            if b, ok := v.(bool); ok {
                return b
            }
        }
    }
    switch r.Tier {
    case "pro":
        return pro
    case "enterprise":
        return enterprise
    default:
        return free
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tier/... -v`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/tier/...`
Expected: 0 issues.

**Step 6: Commit**

```bash
git add internal/tier/
git commit -m "feat(tier): resolver with override precedence — TDD"
```

---

### Task 3: Store — Org tier queries (sqlc)

**Files:**
- Modify: `internal/store/queries/org.sql` — add queries
- Modify: `internal/store/store.go` or create `internal/store/org.go` — add wrapper methods
- Run: `sqlc generate`

**Step 1: Add sqlc queries to `internal/store/queries/org.sql`**

Append these queries (check existing file first for naming patterns):

```sql
-- name: GetOrgTier :one
SELECT tier, tier_overrides FROM organizations WHERE id = $1;

-- name: UpdateOrgTier :exec
UPDATE organizations SET tier = $2 WHERE id = $1;

-- name: CountAlertRulesByOrg :one
SELECT COUNT(*) FROM alert_rules WHERE org_id = $1 AND deleted_at IS NULL;

-- name: CountWatchlistsByOrg :one
SELECT COUNT(*) FROM watchlists WHERE org_id = $1 AND deleted_at IS NULL;

-- name: CountMembersByOrg :one
SELECT COUNT(*) FROM org_members WHERE org_id = $1;

-- name: ListAllOrgs :many
SELECT id, tier, tier_overrides FROM organizations;
```

**Step 2: Regenerate sqlc**

Run: `sqlc generate`
Expected: No errors. New files in `internal/store/generated/`.

**Step 3: Write store wrapper methods**

Create `internal/store/org.go` (or add to existing file). **Transaction helper selection matters here:**
- `GetOrgTier`, `UpdateOrgTier`, `ListAllOrgs` → use `withBypassTx` (called from middleware/workers, before org context is set)
- `CountAlertRulesByOrg`, `CountWatchlistsByOrg`, `CountMembersByOrg` → use `withOrgTx` (called from handlers where `app.org_id` is already set — these tables have RLS)

```go
// withBypassTx — called from middleware/workers (no org context yet)
func (s *Store) GetOrgTier(ctx context.Context, orgID uuid.UUID) (string, map[string]any, error)
func (s *Store) UpdateOrgTier(ctx context.Context, orgID uuid.UUID, tier string) error
func (s *Store) ListAllOrgs(ctx context.Context) ([]OrgTierRow, error)

// withOrgTx — called from handlers (org context set, RLS active)
func (s *Store) CountAlertRulesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
func (s *Store) CountWatchlistsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
func (s *Store) CountMembersByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
```

**Step 4: Write integration tests**

Create `internal/store/org_tier_test.go` using `testutil.NewTestDB(t)`:

```go
func TestGetOrgTier(t *testing.T)         // default tier is "free", empty overrides
func TestUpdateOrgTier(t *testing.T)      // update to "pro", verify read-back
func TestCountAlertRulesByOrg(t *testing.T) // create rules via AppStore, verify count (soft-deleted excluded)
func TestCountWatchlistsByOrg(t *testing.T) // create watchlists, verify count
func TestCountMembersByOrg(t *testing.T)  // verify member count (org creator = 1)
func TestListAllOrgs(t *testing.T)        // create 2 orgs, verify both returned with tier info
```

Note: Count* tests should use `db.AppStore` (RLS-constrained) to verify they work under `withOrgTx`. `ListAllOrgs` should use `db.Store` (bypass) since it's cross-org.

**Step 5: Run tests**

Run: `go test ./internal/store/ -run "TestGetOrgTier|TestUpdateOrgTier|TestCount|TestListAllOrgs" -v`
Expected: All PASS.

**Step 6: Verify compilation + commit**

Run: `go build ./...`

```bash
git add internal/store/queries/org.sql internal/store/generated/ internal/store/org.go internal/store/org_tier_test.go
git commit -m "feat(store): org tier + count queries with integration tests — sqlc"
```

---

### Task 4: Per-org API rate limiter — TDD

**Files:**
- Create: `internal/api/org_ratelimit.go`
- Create: `internal/api/org_ratelimit_test.go`

**Step 1: Write failing tests**

Test file: `internal/api/org_ratelimit_test.go` (in `package api` — white-box, same as `ratelimit_test.go`).

Model after existing `internal/api/ratelimit_test.go`. The rate limiter tests construct a partial `&Server{...}` with `//nolint:exhaustruct` — no need for a full test server.

```go
func TestOrgRateLimiter_Allow(t *testing.T) {
    lim := newOrgRateLimiter(testClock)
    orgA := uuid.New()
    // Allow at rate=10/s, burst=10
    for i := 0; i < 10; i++ {
        assert.True(t, lim.Allow(orgA, 10, 10))
    }
    assert.False(t, lim.Allow(orgA, 10, 10)) // 11th denied
}

func TestOrgRateLimiter_DifferentOrgs(t *testing.T)    // org A exhausted, org B still allowed
func TestOrgRateLimiter_RateChange(t *testing.T)       // tier change creates new limiter
func TestOrgRateLimiter_Eviction(t *testing.T)         // advance clock past idle TTL, verify map entry evicted
```

The `orgRateLimiter` should accept a `now func() time.Time` for testable clock injection (needed for eviction tests).

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run TestOrgRateLimiter -v`
Expected: FAIL — type does not exist.

**Step 3: Write implementation**

```go
// internal/api/org_ratelimit.go
// ABOUTME: Per-org API rate limiter keyed by organization UUID.
// ABOUTME: Supports different rates per org (tier-resolved) with idle eviction.
package api
```

Same pattern as `ipRateLimiter` but:
- `Allow(orgID string, limit rate.Limit, burst int) bool` — accepts tier-resolved rate
- If stored limiter's `Limit()` differs from requested, replace it
- `now` function injected for testing
- Eviction goroutine same as `ipRateLimiter`

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -run TestOrgRateLimiter -v`
Expected: All PASS.

**Step 5: Commit**

```bash
git add internal/api/org_ratelimit.go internal/api/org_ratelimit_test.go
git commit -m "feat(api): per-org rate limiter with tier-aware rates — TDD"
```

---

### Task 5a: Tier context middleware — TDD

**Files:**
- Modify: `internal/api/context.go` — add `ctxTierResolver` context key
- Create: `internal/api/middleware_tier.go` — tier resolution middleware (NOT `middleware.go` — that file doesn't exist; RBAC middleware is in `middleware_rbac.go`)
- Create: `internal/api/middleware_tier_test.go` — test for tier middleware

**Step 1: Write failing test**

Test that org-scoped requests have `tier.Resolver` in context with correct tier and overrides.
- Set org tier=pro in DB → make request → verify resolver in context has Tier="pro"
- Set org tier_overrides=`{"max_alert_rules": 10}` → verify resolver has override

**Step 2: Run test, verify failure**

**Step 3: Implement**

Add `ctxTierResolver` to `context.go`. Create a new chi middleware function in `middleware_tier.go` that loads org tier via `store.GetOrgTier()` and constructs `tier.Resolver`, injecting it into context. This middleware should be placed AFTER the org context middleware (which sets `ctxOrgID`) in the middleware chain.

**Step 4: Run tests, verify pass. Commit.**

```bash
git add internal/api/context.go internal/api/middleware_tier.go internal/api/middleware_tier_test.go
git commit -m "feat(api): tier resolution middleware — injects Resolver into context — TDD"
```

---

### Task 5b: Resource limit gating in handlers — TDD

**Files:**
- Modify: handler files: `internal/api/alert_rules.go`, `internal/api/watchlists.go`, `internal/api/members.go` (or wherever these handlers live)

**Step 1: Write failing tests**

Test file: `internal/api/tier_gating_test.go` (in `package api` — white-box).

**Test setup pattern:**
1. `db := testutil.NewTestDB(t)` — get test DB
2. `srv, ts := newRegisterServer(t, db, "open")` — get test server
3. `doRegister()` + `doLogin()` → get auth cookie via `cookieValue(resp, "access_token")`
4. Set org tier in DB: `db.Store.UpdateOrgTier(ctx, orgID, "free")` (bypass RLS via Store, not AppStore)
5. Create resources via API calls (e.g., POST alert rules) — all mutations need `X-Requested-By: CVErt-Ops` header
6. Verify 6th creation returns 403

Tests:
- Create org with tier=free → create 5 alert rules (succeed) → create 6th (fail 403)
- Create org with tier=pro → create 50 alert rules (succeed)
- Create org with tier_overrides `{"max_alert_rules": 10}` → limit is 10, not 5
- Same pattern for watchlists (3/20) and members (5/25)

**Step 2: Run tests, verify failure**

**Step 3: Implement handler tier checks**

In each handler's create path, before the mutation. These are chi handlers — use `http.Error` + `return`, **not** huma error returns:
```go
resolver, _ := r.Context().Value(ctxTierResolver).(*tier.Resolver)
limit := resolver.IntLimit("max_alert_rules", 5, 50, -1)
if limit >= 0 {
    count, _ := srv.store.CountAlertRulesByOrg(r.Context(), orgID)
    if count >= int64(limit) {
        http.Error(w, "tier limit: max alert rules reached", http.StatusForbidden)
        return
    }
}
```

**Step 4: Run tests, verify pass. Commit.**

```bash
git commit -m "feat(api): resource count tier gating — alert rules, watchlists, members — TDD"
```

---

### Task 5c: Channel type gating — TDD

**Files:**
- Modify: `internal/api/channels.go` (or wherever channel create handler lives)

**Step 1: Write failing tests**

- Free tier org → create webhook channel (succeed) → create email channel (fail 403)
- Pro tier org → create email channel (succeed)
- Free tier org with override `{"channels_email": true}` → create email channel (succeed)

**Step 2: Run tests, verify failure**

**Step 3: Implement**

In channel create handler, after parsing channel type. Chi handler — use `http.Error` + `return`:
```go
resolver, _ := r.Context().Value(ctxTierResolver).(*tier.Resolver)
if !resolver.BoolFlag("channels_"+channelType, false, true, true) {
    http.Error(w, "tier limit: channel type not available", http.StatusForbidden)
    return
}
```

**Step 4: Run tests, verify pass. Commit.**

```bash
git commit -m "feat(api): channel type tier gating — free restricted to webhook — TDD"
```

---

### Task 5d: Per-org API rate limiter middleware wiring — TDD

**Files:**
- Modify: `internal/api/server.go` — add `orgRateLimiter` field, wire middleware

**Step 1: Write failing test**

Test that rapid requests from one org get 429 while another org is unaffected.

**Step 2: Run test, verify failure**

**Step 3: Wire org rate limiter middleware in `Handler()`**

After auth middleware, before routes. Read tier resolver from context, resolve rate via `resolver.IntLimit("api_rate_limit", 60, 300, 1000)`, call `orgRateLimiter.Allow(orgID, resolvedRate, burst)`.

**Step 4: Run full test suite + linter**

Run: `go test ./... && golangci-lint run`
Expected: All pass, 0 lint issues.

**Step 5: Commit**

```bash
git commit -m "feat(api): per-org rate limiter middleware wired — TDD"
```

---

> **REVIEW CHECKPOINT 1** — Pause here for review. Verify tier middleware is correctly placed in the middleware chain, all resource limits use the resolver (not hardcoded), rate limiter handles tier changes, and all existing tests still pass.

---

### Task 6: Wire AI quotas to real tiers

**Files:**
- Modify: `internal/api/ai.go` — replace hardcoded "free" with tier from context
- Modify: `internal/api/ai_test.go` — add tier-aware quota tests

**Step 1: Write failing test**

Add test: create org with tier=pro → AI NL search limit is 100 (not 10).

**Step 2: Run test, verify failure**

**Step 3: Modify `ai.go` handlers**

Replace the hardcoded `"free"` string in `ai.ResolveLimit()` calls with `resolver.Tier` from context. The resolver is already in context from Task 5.

**Step 4: Run tests, verify pass**

**Step 5: Commit**

```bash
git add internal/api/ai.go internal/api/ai_test.go
git commit -m "feat(ai): wire quota resolution to real org tier"
```

---

### Task 7: Tier read API endpoint

**Files:**
- Modify: `internal/api/server.go` — register route
- Create: `internal/api/org_tier.go` — handler
- Create: `internal/api/org_tier_test.go` — tests

**Step 1: Write failing test**

Test file: `internal/api/org_tier_test.go` (in `package api`).

Test `GET /api/v1/orgs/{org_id}/tier` returns tier info for all roles (viewer and above).

Expected response shape:
```json
{
  "tier": "free",
  "limits": {
    "max_alert_rules": {"limit": 5, "used": 2},
    "max_watchlists": {"limit": 3, "used": 1},
    "max_members": {"limit": 5, "used": 1},
    "api_rate_limit": {"limit": 60},
    "channels_email": {"allowed": false},
    "channels_webhook": {"allowed": true}
  }
}
```

**Step 2: Write handler**

Returns current tier, resolved limits (all limit names with their effective values), and current usage counts (for countable resources).

**Step 3: Wire route in `Handler()`**

Under the org-scoped router, add `r.Get("/tier", ...)` with `RequireOrgRole(RoleViewer)`.

**Step 4: Run tests, verify pass. Run full suite. Commit.**

```bash
git commit -m "feat(api): GET org tier endpoint with resolved limits"
```

---

## Phase 5B: Data Retention Automation

### Task 8: Migration — Retention indexes

**Files:**
- Create: `migrations/000026_retention_indexes.up.sql`
- Create: `migrations/000026_retention_indexes.down.sql`

**Step 1: Write up migration**

```sql
-- migrate:no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_raw_payloads_ingested_at_idx
    ON cve_raw_payloads (ingested_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS feed_fetch_log_started_at_idx
    ON feed_fetch_log (started_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS job_queue_cleanup_idx
    ON job_queue (finished_at) WHERE status IN ('succeeded', 'dead');
```

**Step 2: Write down migration**

```sql
-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS job_queue_cleanup_idx;
DROP INDEX CONCURRENTLY IF EXISTS feed_fetch_log_started_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS cve_raw_payloads_ingested_at_idx;
```

**Step 3: Run migration, verify, commit**

```bash
git commit -m "migration: retention cleanup indexes for Phase 5"
```

---

### Task 9: Config — Retention env vars

**Files:**
- Modify: `internal/config/config.go` — add retention fields

**Step 1: Add config fields**

**Important:** `RetentionCleanupEnabled` and `RetentionCleanupBatchSize` already exist in `config.go` (added in Phase 4). Do NOT re-add them. Only add the new per-table retention window fields:

```go
// ── Data retention (per-table windows — add below existing RetentionCleanup* fields) ──
RetentionRawPayloadDays        int  `env:"RETENTION_RAW_PAYLOAD_DAYS"        envDefault:"90"`
RetentionFeedFetchLogDays      int  `env:"RETENTION_FEED_FETCH_LOG_DAYS"     envDefault:"90"`
RetentionAlertEventsDays       int  `env:"RETENTION_ALERT_EVENTS_DAYS"       envDefault:"365"`
RetentionNotifDeliveriesDays   int  `env:"RETENTION_NOTIFICATION_DELIVERIES_DAYS" envDefault:"90"`
RetentionAuditLogDays          int  `env:"RETENTION_AUDIT_LOG_DAYS"          envDefault:"365"`
RetentionJobQueueHours         int  `env:"RETENTION_JOB_QUEUE_HOURS"        envDefault:"24"`
RetentionMaxRuntimeSeconds     int  `env:"RETENTION_MAX_RUNTIME_SECONDS"    envDefault:"300"`
```

**Step 2: Verify compilation**

Run: `go build ./...`

**Step 3: Commit**

```bash
git commit -m "config: add retention window env vars for all tables"
```

---

### Task 10a: Store — Retention cleanup sqlc queries + store wrappers

> **TDD note:** This task writes sqlc queries and thin store wrappers (no business logic). Tests are in Task 10b, which must be completed immediately after. Do NOT proceed past Task 10b without green tests.

**Files:**
- Create: `internal/store/queries/retention.sql` — sqlc queries for bounded-batch DELETE
- Create: `internal/store/retention.go` — wrapper methods

**Step 1: Write sqlc queries for bounded-batch delete**

`internal/store/queries/retention.sql`:

```sql
-- name: CleanupCveRawPayloads :execrows
WITH doomed AS (
    SELECT id FROM cve_raw_payloads
    WHERE ingested_at < @cutoff::timestamptz
    ORDER BY ingested_at LIMIT @batch_size::int
)
DELETE FROM cve_raw_payloads p USING doomed WHERE p.id = doomed.id;

-- name: CleanupFeedFetchLog :execrows
WITH doomed AS (
    SELECT id FROM feed_fetch_log
    WHERE started_at < @cutoff::timestamptz
    ORDER BY started_at LIMIT @batch_size::int
)
DELETE FROM feed_fetch_log f USING doomed WHERE f.id = doomed.id;

-- name: CleanupAlertEvents :execrows
WITH doomed AS (
    SELECT id FROM alert_events
    WHERE org_id = ANY(@org_ids::uuid[]) AND first_fired_at < @cutoff::timestamptz
    ORDER BY first_fired_at LIMIT @batch_size::int
)
DELETE FROM alert_events ae USING doomed WHERE ae.id = doomed.id;

-- name: CleanupNotificationDeliveries :execrows
WITH doomed AS (
    SELECT id FROM notification_deliveries
    WHERE org_id = ANY(@org_ids::uuid[]) AND created_at < @cutoff::timestamptz
    ORDER BY created_at LIMIT @batch_size::int
)
DELETE FROM notification_deliveries nd USING doomed WHERE nd.id = doomed.id;

-- name: CleanupJobQueue :execrows
WITH doomed AS (
    SELECT id FROM job_queue
    WHERE status IN ('succeeded', 'dead') AND finished_at < @cutoff::timestamptz
    ORDER BY finished_at LIMIT @batch_size::int
)
DELETE FROM job_queue jq USING doomed WHERE jq.id = doomed.id;

-- name: CleanupRefreshTokens :execrows
WITH doomed AS (
    SELECT id FROM refresh_tokens
    WHERE expires_at < @cutoff::timestamptz
    ORDER BY expires_at LIMIT @batch_size::int
)
DELETE FROM refresh_tokens rt USING doomed WHERE rt.id = doomed.id;

-- name: CleanupAIRequestLog :execrows
WITH doomed AS (
    SELECT id FROM ai_request_log
    WHERE created_at < @cutoff::timestamptz
    ORDER BY created_at LIMIT @batch_size::int
)
DELETE FROM ai_request_log arl USING doomed WHERE arl.id = doomed.id;

-- name: CleanupAICache :execrows
WITH doomed AS (
    SELECT id FROM ai_cache
    WHERE expires_at < @cutoff::timestamptz
    ORDER BY expires_at LIMIT @batch_size::int
)
DELETE FROM ai_cache ac USING doomed WHERE ac.id = doomed.id;

-- name: CleanupAIUsageCounters :execrows
WITH doomed AS (
    SELECT id FROM ai_usage_counters
    WHERE window = 'daily' AND counter_date < @cutoff::date
    ORDER BY counter_date LIMIT @batch_size::int
)
DELETE FROM ai_usage_counters auc USING doomed WHERE auc.id = doomed.id;
```

Notes:
- `CleanupRefreshTokens`: 60-second grace computed by caller (`cutoff = now() - 60s`). Bounded-batch for consistency and first-run backlog safety.
- `CleanupAICache`: Uses `expires_at` (TTL-based expiry, not age-based).
- `CleanupAIUsageCounters`: Only deletes `window='daily'` rows; monthly rows are kept indefinitely per design doc.

**Step 2: Run `sqlc generate`, verify compilation**

Run: `sqlc generate && go build ./...`

**Step 3: Write store wrapper methods in `internal/store/retention.go`**

Each wraps the generated query with `withBypassTx` (retention operates across all orgs — these are background worker operations that need to bypass RLS). Note: even though `withBypassTx` provides `*generated.Queries` (sqlc) rather than `pgx.Tx`, it's correct here because all retention queries are sqlc-generated. `WorkerTx` would give `pgx.Tx` which we don't need.

**Step 4: Verify compilation, commit**

```bash
git add internal/store/queries/retention.sql internal/store/generated/ internal/store/retention.go
git commit -m "feat(store): retention cleanup sqlc queries + wrappers"
```

---

### Task 10b: Store — Retention cleanup integration tests

**Files:**
- Create: `internal/store/retention_test.go`

**Step 1: Write integration tests**

Use `testutil.NewTestDB(t)`. Most retention tables (cve_raw_payloads, feed_fetch_log, job_queue, etc.) have no API for inserting test data, so use raw SQL via `db.Store` to insert rows with explicit timestamps:

```go
// Example: insert old + recent rows into cve_raw_payloads
_, err := db.Store.Pool().Exec(ctx,
    `INSERT INTO cve_raw_payloads (cve_id, feed_name, payload, ingested_at)
     VALUES ($1, $2, $3, $4)`,
    "CVE-2024-0001", "nvd", `{}`, time.Now().Add(-100*24*time.Hour),
)
```

For org-scoped tables (alert_events, notification_deliveries), you'll need to create an org + org member first via the store to satisfy FK constraints. Use `db.Store` (bypass) for setup, since these inserts are cross-org setup.

For each table:
- Insert rows with explicit timestamps (some old, some recent)
- Call cleanup with a cutoff
- Verify old rows deleted, recent rows retained
- Test batch size limiting (insert more than batch_size old rows, verify only batch_size deleted per call)

Key tests:
- `TestCleanupCveRawPayloads` — basic old/recent split
- `TestCleanupFeedFetchLog` — basic old/recent split
- `TestCleanupAlertEvents_OrgFilter` — only specified org_ids cleaned
- `TestCleanupNotificationDeliveries_OrgFilter` — same pattern
- `TestCleanupJobQueue_StatusFilter` — insert pending + running + succeeded + dead rows, verify only succeeded/dead deleted
- `TestCleanupRefreshTokens_GraceWindow` — insert token expired 30s ago (retained) and 90s ago (deleted)
- `TestCleanupAIRequestLog` — basic old/recent split
- `TestCleanupAICache_TTL` — expired entries cleaned, non-expired retained
- `TestCleanupAIUsageCounters_DailyOnly` — daily rows cleaned, monthly rows preserved
- `TestCleanup_BatchSizeLimit` — insert 20 old rows, batch_size=5, verify only 5 deleted per call

**Step 2: Run tests**

Run: `go test ./internal/store/ -run TestCleanup -v`
Expected: All PASS.

**Step 3: Commit**

```bash
git add internal/store/retention_test.go
git commit -m "test(store): retention cleanup integration tests"
```

---

### Task 10c: Retention runner implementation

> **TDD note:** This task writes the runner implementation. Tests are in Task 10d, which must be completed immediately after. Do NOT proceed past Task 10d without green tests.

**Files:**
- Create: `internal/retention/runner.go`

**Step 1: Write retention runner**

```go
// internal/retention/runner.go
// ABOUTME: Scheduled retention cleanup job that deletes old data per §21.
// ABOUTME: Runs as a job_queue entry with bounded-batch deletes per table.
package retention

type RunnerConfig struct {
    Enabled           bool
    BatchSize         int
    MaxRuntimeSeconds int
    // Per-table defaults (global tables)
    RawPayloadDays     int
    FeedFetchLogDays   int
    JobQueueHours      int
    AILogRetentionDays int
    AICacheTTL         time.Duration // for ai_cache; caller computes cutoff from TTL
    // Per-table defaults (tier-gated tables — these are fallback defaults)
    AlertEventsDays  int
    NotifDelivDays   int
    AuditLogDays     int
}

type Runner struct {
    store  *store.Store
    cfg    RunnerConfig
    log    *slog.Logger
    now    func() time.Time // injectable for tests
}

func NewRunner(s *store.Store, cfg RunnerConfig, log *slog.Logger) *Runner

func (r *Runner) Run(ctx context.Context) error
```

`Run()` iterates tables, calling bounded-batch delete in a loop per table until 0 rows or max runtime hit. Logs per-table results (rows deleted, duration). Errors per table are logged but don't stop the run.

For tier-gated tables (alert_events, notification_deliveries, audit_log): loads all orgs via `store.ListAllOrgs()` (added in Task 3), groups by retention window using `tier.Resolver`, runs per-group cleanup with the group's resolved retention window.

**Step 2: Verify compilation**

Run: `go build ./...`

**Step 3: Commit**

```bash
git add internal/retention/
git commit -m "feat(retention): runner with bounded-batch deletes and tier-aware windows"
```

---

### Task 10d: Retention runner tests

**Files:**
- Create: `internal/retention/runner_test.go`

**Step 1: Write runner tests**

Uses `testutil.NewTestDB(t)` and injectable `now` clock.

- `TestRunner_AllTables` — seeds data across all tables, runs once, verifies cleanup
- `TestRunner_MaxRuntime` — uses a very short max runtime (e.g., 1ms), verifies it stops before completing all tables
- `TestRunner_Disabled` — `Enabled=false` → no deletions, no errors
- `TestRunner_ErrorIsolation` — use context cancellation mid-table, verify other tables still cleaned
- `TestRunner_PerOrgGroup` — two orgs with different tiers (free=90d, enterprise=365d), seed data at boundary timestamps, verify per-org retention windows honored (enterprise retains longer than free)
- `TestRunner_AICleanup` — verify ai_request_log, ai_cache, ai_usage_counters all cleaned
- `TestRunner_BatchLoop` — insert 25 old rows, batch_size=10, verify all 25 eventually deleted (runner loops)

**Step 2: Run all retention tests**

Run: `go test ./internal/store/... ./internal/retention/... -v`
Expected: All PASS.

**Step 3: Commit**

```bash
git add internal/retention/runner_test.go
git commit -m "test(retention): runner unit + integration tests — TDD"
```

---

> **REVIEW CHECKPOINT 2** — Pause here for review. Verify retention queries cover all design doc targets, runner handles tier-gated vs global tables correctly, batch loop terminates properly, and AI cleanup migration is ready.

---

### Task 11: Job scheduling + migrate AI cleanup — TDD

**Architecture context:** This project has TWO separate worker systems:
1. **`notify.Worker`** (`internal/notify/worker.go`) — ticker-based select-loop that runs periodic jobs (feed sync, alert evaluation, notification delivery, AI cleanup). Each job runs as a ticker in the `Start()` method.
2. **`worker.Pool`** (`internal/worker/pool.go`) — `job_queue` table-backed pool with `Register("queue_name", handler)` for on-demand jobs.

The retention job should be scheduled via a **ticker in `notify.Worker`** (like the existing AI cleanup ticker). The ticker enqueues a `retention_cleanup` job into `job_queue`, and `worker.Pool` executes it (to benefit from the pool's single-execution guarantees via `lock_key`).

**Files:**
- Modify: `internal/notify/worker.go` — replace AI cleanup ticker with retention job scheduling ticker
- Modify: `internal/notify/worker_test.go` — update tests
- Modify: `internal/api/server.go` or `cmd/cvert-ops/serve.go` — register retention handler on `worker.Pool`

**Step 1: Write test for retention job scheduling**

Test that the `notify.Worker` ticker enqueues a `retention_cleanup` job into `job_queue`, and doesn't double-enqueue if one is pending.

**Step 2: Write test verifying AI cleanup removal**

Test that `RunAICleanupOnce` is removed (or the method now delegates to the retention runner). Existing AI cleanup tests that use `RunAICleanupOnce()` will need updating.

**Step 3: Implement**

In `notify.Worker.Start()` select-loop, replace `aiCleanupTicker` with `retentionTicker` (daily = `24 * time.Hour`). On tick:
1. Check if `job_queue` has a pending/running `retention_cleanup` job
2. If not, enqueue one with `lock_key = 'cleanup:retention'`

Register `retention_cleanup` job type on `worker.Pool` — the handler calls `retention.Runner.Run()`.

Remove `aiCleanupTicker` and `runAICleanup` method from `notify.Worker`. The AI cache and request log cleanup is now handled by the retention runner (Task 10c).

**Step 4: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS. Existing AI cleanup tests may need updating to use the retention runner instead.

**Step 5: Commit**

```bash
git commit -m "feat(worker): retention job scheduling via notify.Worker ticker + worker.Pool handler"
```

---

## Phase 5C: Audit Log

### Task 12: Migration — audit_log table

**Files:**
- Create: `migrations/000027_audit_log.up.sql`
- Create: `migrations/000027_audit_log.down.sql`

**Step 1: Write up migration**

Use the exact schema from the design doc. Key points:
- `org_id` and `actor_id` are NOT FKs
- `actor_email` is nullable
- `CHECK (action IN ('create', 'update', 'delete'))`
- RLS with dual-escape policy
- Autovacuum tuning (fillfactor=80)
- `GRANT SELECT, INSERT, DELETE ON audit_log TO cvert_ops_app` — no UPDATE

**Step 2: Write down migration**

Drop policy, disable RLS, drop table.

**Step 3: Run migration, verify, commit**

```bash
git commit -m "migration: audit_log table with RLS and autovacuum tuning"
```

---

### Task 13: Secret redaction — TDD

**Files:**
- Create: `internal/audit/redact.go`
- Create: `internal/audit/redact_test.go`

**Step 1: Write failing tests**

Test `redactSecrets(entityType string, state map[string]any) map[string]any`:

```go
func TestRedactSecrets_FieldNames(t *testing.T)       // all keyword matches
func TestRedactSecrets_CaseInsensitive(t *testing.T)  // "Signing_Secret"
func TestRedactSecrets_SubstringMatch(t *testing.T)   // "webhook_signing_secret"
func TestRedactSecrets_NestedJSON(t *testing.T)        // nested objects
func TestRedactSecrets_ChannelURL(t *testing.T)        // domain-only for "channel" entity
func TestRedactSecrets_PreservesNonSecret(t *testing.T)
func TestRedactSecrets_NilState(t *testing.T)          // nil input → nil output
func TestRedactSecrets_EmptyMap(t *testing.T)          // empty → empty
```

**Step 2: Run tests, verify failure**

**Step 3: Implement `redactSecrets`**

Keywords (case-insensitive substring match): `secret`, `password`, `api_key`, `token`, `private_key`, `key_hash`.

For `entityType == "channel"` and key `"url"`: extract scheme+host, replace path with `***`.

Recursive for nested `map[string]any` values.

**Step 4: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(audit): write-time secret redaction — TDD"
```

---

### Task 14: Audit writer + sqlc queries — TDD

**Files:**
- Create: `internal/store/queries/audit_log.sql`
- Create: `internal/audit/writer.go`
- Create: `internal/audit/writer_test.go`

**Step 1: Write sqlc queries**

```sql
-- name: InsertAuditEntry :exec
INSERT INTO audit_log (org_id, actor_id, actor_email, action, entity_type, entity_id, entity_name, success, old_state, new_state, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: ListAuditEntries :many
SELECT * FROM audit_log
WHERE org_id = @org_id::uuid
  AND (@entity_type::text = '' OR entity_type = @entity_type::text)
  AND (@action::text = '' OR action = @action::text)
  AND (@actor_id::uuid IS NULL OR actor_id = @actor_id::uuid)
  AND created_at >= @after::timestamptz
  AND created_at <= @before::timestamptz
  AND (
      @cursor_created_at::timestamptz IS NULL
      OR (created_at, id) < (@cursor_created_at::timestamptz, @cursor_id::uuid)
  )
ORDER BY created_at DESC, id DESC
LIMIT @page_size::int;
```

The `ListAuditEntries` query uses keyset cursor pagination on `(created_at, id)` — Task 16 will consume this for the audit API endpoint. The `@cursor_created_at IS NULL` branch handles the first page (no cursor).

**Step 2: Run `sqlc generate`**

**Step 3: Write audit Entry type and Writer**

```go
// internal/audit/writer.go
// ABOUTME: Appends audit log entries with write-time secret redaction.
// ABOUTME: Non-blocking — errors are logged, never propagated to callers.
package audit

// Entry represents a single audit log event. Callers construct this and pass to Writer.Log().
type Entry struct {
    OrgID      uuid.UUID
    ActorID    *uuid.UUID     // nil for system actions (retention, feed sync)
    ActorEmail string         // empty for system actions
    Action     string         // "create", "update", "delete"
    EntityType string         // "alert_rule", "channel", "watchlist", "member", "saved_search", "sso_connection"
    EntityID   string         // UUID or other identifier
    EntityName string         // denormalized for readability after entity deletion
    Success    bool           // false for 403 denied mutations
    OldState   any            // pre-mutation snapshot (nil for create)
    NewState   any            // post-mutation snapshot (nil for delete)
    Metadata   map[string]any // optional extra context
}

type Writer struct {
    store *store.Store
    log   *slog.Logger
}

func NewWriter(s *store.Store, log *slog.Logger) *Writer

func (w *Writer) Log(ctx context.Context, entry Entry) {
    // 1. Apply redactSecrets to OldState and NewState
    // 2. Marshal to JSONB
    // 3. Insert via store
    // 4. On error: log, don't propagate
}
```

**Step 4: Write failing integration tests FIRST, then implement Writer**

Using `testutil.NewTestDB(t)` — write all tests before implementing `Writer`:
- `TestWriter_CreateAction` — old=nil, new populated, verify row in DB
- `TestWriter_UpdateAction` — both old and new, verify redaction applied
- `TestWriter_DeleteAction` — old populated, new=nil
- `TestWriter_DeniedAction` — success=false, both nil
- `TestWriter_SystemAction` — actor_id=nil, actor_email=nil
- `TestWriter_NonBlocking` — inject broken store, verify no panic/error returned

Run tests to verify they fail (Writer not implemented yet). Then implement `Writer.Log()` and re-run to verify pass.

**Step 5: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(audit): writer with non-blocking inserts + sqlc queries — TDD"
```

---

### Task 15: Audit log integration into handlers

**Files:**
- Modify: `internal/api/server.go` — add `audit *audit.Writer` field + `SetAuditDeps` method
- Modify: handlers that need auditing (check which files contain the relevant handlers)

**Step 1: Write integration tests**

For each audited entity (alert_rules, channels, watchlists, members, saved_searches):
- Create entity → verify audit entry with action=create, success=true
- Update entity → verify audit entry with action=update, old_state populated
- Delete entity → verify audit entry with action=delete
- Tier-gated denial (e.g., free tier exceeding limit) → verify audit entry with success=false

For channels specifically: verify `signing_secret` is `[REDACTED]` in audit entry.

**Design note on RBAC failures:** RBAC failures (wrong role) are rejected in `middleware_rbac.go` before the handler executes, so handlers cannot audit them. Two options:
1. Add audit logging to RBAC middleware itself (has org_id and actor context, but no entity info)
2. Only audit tier-gated denials (which happen in handlers and have full entity context)

**Decision: Option 2** — audit tier-gated denials in handlers (where we have entity context). RBAC denials are already logged via slog in the middleware. If RBAC audit entries are needed later, the middleware can be extended.

**Step 2: Implement**

In each handler's create/update/delete path:
1. For update/delete: capture old state before mutation
2. After successful mutation: `srv.audit.Log(ctx, entry)`
3. For tier-gated denials (403 from tier check): `srv.audit.Log(ctx, Entry{Success: false, Action: "create", Metadata: map[string]any{"reason": "tier_limit"}})`

Wire `audit.Writer` into `Server` via `SetAuditDeps(w *audit.Writer)`.

**Step 3: Run full test suite. Commit.**

```bash
git commit -m "feat(api): audit log integration in all mutation handlers"
```

---

> **REVIEW CHECKPOINT 3** — Pause here for review. Verify audit entries are created for all mutation types (create/update/delete), secret redaction works for channel secrets, failed auth produces success=false entries, and non-blocking behavior is confirmed.

### Task 16: Audit log API endpoint — TDD

**Files:**
- Create: `internal/api/audit.go` — handler
- Create: `internal/api/audit_test.go` — tests
- Modify: `internal/api/server.go` — register route

**Step 1: Write failing tests**

```go
func TestAuditAPI_RBAC(t *testing.T)              // owner/admin OK, member/viewer 403
func TestAuditAPI_TierGating(t *testing.T)         // non-Enterprise 403
func TestAuditAPI_Pagination(t *testing.T)         // cursor pagination
func TestAuditAPI_Filters(t *testing.T)            // entity_type, action, actor_id, date range
func TestAuditAPI_CrossOrgIsolation(t *testing.T)  // RLS prevents cross-org access
```

**Step 2: Implement handler**

`GET /api/v1/orgs/{org_id}/audit-log` with:
- `RequireOrgRole(RoleAdmin)` middleware
- Tier check: `resolver.Tier != "enterprise"` → 403
- Filter params from query string
- Cursor pagination on `(created_at, id)`

**Step 3: Wire route, run tests, lint, commit**

```bash
git commit -m "feat(api): audit log list endpoint with RBAC + tier gating — TDD"
```

---

### Task 17: Add audit_log to retention runner — TDD

**Files:**
- Modify: `internal/store/queries/retention.sql` — add CleanupAuditLog query
- Modify: `internal/store/retention.go` — add store wrapper
- Modify: `internal/retention/runner.go` — add audit_log table to tier-gated cleanup
- Modify: `internal/retention/runner_test.go` — test audit retention

**Step 1: Add sqlc query**

Append to `internal/store/queries/retention.sql`:

```sql
-- name: CleanupAuditLog :execrows
WITH doomed AS (
    SELECT id FROM audit_log
    WHERE org_id = ANY(@org_ids::uuid[]) AND created_at < @cutoff::timestamptz
    ORDER BY created_at LIMIT @batch_size::int
)
DELETE FROM audit_log al USING doomed WHERE al.id = doomed.id;
```

Note: audit_log is tier-gated (same pattern as `CleanupAlertEvents` and `CleanupNotificationDeliveries`). The runner groups orgs by their resolved `AuditLogDays` retention window.

**Step 2: Run `sqlc generate`, add store wrapper**

Add `CleanupAuditLog` wrapper to `internal/store/retention.go` using `withBypassTx`.

**Step 3: Write failing tests**

Add to `internal/retention/runner_test.go`:
- `TestRunner_AuditLogRetention` — insert audit entries for two orgs with different tiers, verify per-org windows honored
- `TestRunner_AuditLogBatchSize` — verify bounded-batch works for audit_log

Add to `internal/store/retention_test.go`:
- `TestCleanupAuditLog_OrgFilter` — only specified org_ids cleaned, entries from other orgs untouched

**Step 4: Update runner to include audit_log in tier-gated table loop**

**Step 5: Run tests, verify pass**

Run: `go test ./internal/store/... ./internal/retention/... -run "Audit" -v`
Expected: All PASS.

**Step 6: Commit**

```bash
git add internal/store/queries/retention.sql internal/store/generated/ internal/store/retention.go internal/store/retention_test.go internal/retention/runner.go internal/retention/runner_test.go
git commit -m "feat(retention): include audit_log in tier-gated retention cleanup — TDD"
```

---

## Phase 5D: Generic OIDC

### Task 18: AES-256-GCM encryption — TDD

**Files:**
- Create: `internal/crypto/aes.go`
- Create: `internal/crypto/aes_test.go`

**Step 1: Write failing tests**

```go
func TestAESGCM_RoundTrip(t *testing.T)
func TestAESGCM_UniqueNonce(t *testing.T)
func TestAESGCM_TamperedCiphertext(t *testing.T)
func TestAESGCM_WrongKey(t *testing.T)
func TestAESGCM_EmptyPlaintext(t *testing.T)
func TestAESGCM_InvalidKeyLength(t *testing.T)
```

**Step 2: Implement**

```go
// internal/crypto/aes.go
// ABOUTME: AES-256-GCM authenticated encryption for storing secrets at rest.
// ABOUTME: Nonce-prepended ciphertext format: nonce (12 bytes) || ciphertext.
package crypto

func Encrypt(key [32]byte, plaintext []byte) ([]byte, error)
func Decrypt(key [32]byte, ciphertext []byte) ([]byte, error)
```

Use `crypto/aes` + `crypto/cipher` GCM mode. `crypto/rand` for nonce.

**Step 3: Run tests, lint, commit.**

```bash
git commit -m "feat(crypto): AES-256-GCM encrypt/decrypt — TDD"
```

---

### Task 19: Migration — SSO tables

**Files:**
- Create: `migrations/000028_sso_connections.up.sql`
- Create: `migrations/000028_sso_connections.down.sql`

Use exact schema from design doc. Key points:
- `sso_connections`: `org_id UNIQUE REFERENCES organizations(id) ON DELETE CASCADE`
- `sso_email_domains`: `org_id` denormalized, `domain TEXT PRIMARY KEY`
- Both tables get RLS with dual-escape policy
- `sso_email_domains` gets indexes on `sso_connection_id` and `org_id`

**Commit:**

```bash
git commit -m "migration: sso_connections + sso_email_domains with RLS"
```

---

### Task 20: Config — SSO encryption key

**Files:**
- Modify: `internal/config/config.go` — add `SSOEncryptionKey`

```go
// ── SSO ──────────────────────────────────────────────────────────────────────
SSOEncryptionKey string `env:"SSO_ENCRYPTION_KEY"` // 32-byte key; required if SSO is used
```

Add to `LogValue()` masked output. Commit.

```bash
git commit -m "config: add SSO_ENCRYPTION_KEY for OIDC client secret encryption"
```

---

### Task 21: Store — SSO queries + CRUD — TDD

**Files:**
- Create: `internal/store/queries/sso.sql`
- Create: `internal/store/sso.go`
- Create: `internal/store/sso_test.go`

**Step 1: Write sqlc queries**

```sql
-- name: CreateSSOConnection :one
INSERT INTO sso_connections (org_id, display_name, issuer_url, client_id, client_secret_enc, scopes, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: GetSSOConnection :one
SELECT * FROM sso_connections WHERE org_id = $1;

-- name: UpdateSSOConnection :exec
UPDATE sso_connections SET display_name = $2, issuer_url = $3, client_id = $4,
    client_secret_enc = $5, scopes = $6, enabled = $7, updated_at = now()
WHERE org_id = $1;

-- name: DeleteSSOConnection :exec
DELETE FROM sso_connections WHERE org_id = $1;

-- name: UpsertSSOEmailDomains :exec
-- (called after bulk replace of domains)
INSERT INTO sso_email_domains (domain, sso_connection_id, org_id)
VALUES ($1, $2, $3);

-- name: DeleteSSOEmailDomains :exec
DELETE FROM sso_email_domains WHERE sso_connection_id = $1;

-- name: LookupSSOByDomain :one
SELECT sc.id, sc.org_id, sc.display_name, sc.issuer_url, sc.client_id, sc.scopes, sc.enabled
FROM sso_email_domains sed
JOIN sso_connections sc ON sed.sso_connection_id = sc.id
WHERE sed.domain = $1 AND sc.enabled = true;

-- name: GetSSOConnectionByID :one
SELECT * FROM sso_connections WHERE id = $1;
```

**Step 2: Run `sqlc generate`**

**Step 3: Write store wrappers + integration tests**

Test CRUD, domain uniqueness, cascade delete, domain lookup.

**Step 4: Commit**

```bash
git commit -m "feat(store): SSO connection + email domain queries — TDD"
```

---

### Task 22: SSO connection CRUD handlers — TDD

**Files:**
- Create: `internal/api/sso.go`
- Create: `internal/api/sso_test.go`
- Modify: `internal/api/server.go` — register routes

**Step 1: Write failing tests**

```go
func TestSSOConnection_CRUD(t *testing.T)          // owner create/get/update/delete
func TestSSOConnection_RBAC(t *testing.T)          // non-owner 403
func TestSSOConnection_TierGating(t *testing.T)    // non-Enterprise 403
func TestSSOConnection_SecretMasked(t *testing.T)  // GET returns masked secret
func TestSSOConnection_SecretEncrypted(t *testing.T) // DB contains ciphertext
func TestSSOConnection_UniquePerOrg(t *testing.T)  // second create fails
func TestEmailDomain_Uniqueness(t *testing.T)       // two orgs same domain fails
func TestEmailDomain_Cascade(t *testing.T)          // delete connection → domains gone
```

**Step 2: Implement handlers**

POST/GET/PATCH/DELETE on `/api/v1/orgs/{org_id}/sso`:
- Tier gate: `resolver.Tier != "enterprise"` → 403
- RBAC: `RequireOrgRole(RoleOwner)`
- Encrypt client_secret on write using `crypto.Encrypt(key, secret)`
- Decrypt on read for internal use only — GET response masks with `"***"`
- PUT `/api/v1/orgs/{org_id}/sso/domains` — bulk replace domains

**Step 3: Wire routes, run tests, lint, commit**

```bash
git commit -m "feat(api): SSO connection CRUD with tier gating + encryption — TDD"
```

---

### Task 23: Email domain discovery endpoint — TDD

**Files:**
- Modify: `internal/api/sso.go` — add discover handler
- Modify: `internal/api/sso_test.go` — add tests

**Step 1: Write failing tests**

```go
func TestDiscover_MatchingDomain(t *testing.T)    // returns SSO connection info
func TestDiscover_UnknownDomain(t *testing.T)     // returns empty
func TestDiscover_RateLimited(t *testing.T)       // unauthenticated rate limiting
func TestDiscover_DisabledConnection(t *testing.T) // enabled=false not returned
```

**Step 2: Implement**

`POST /api/v1/auth/discover` — public (no auth), rate limited by IP:
- Extract domain from email
- Look up via `store.LookupSSOByDomain(domain)`
- If found: return `{display_name, connection_id}`
- If not: return empty object

Wire on the auth routes (before auth middleware).

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): email domain discovery for SSO — TDD"
```

---

### Task 24: OIDC login + callback flow — TDD

**Files:**
- Create: `internal/api/oauth_oidc.go`
- Create: `internal/api/oauth_oidc_test.go`
- Modify: `internal/api/server.go` — register routes + add provider cache

This is the most complex task. The mock IdP setup is the hardest part.

**Step 1: Create mock OIDC IdP test helper**

In `internal/testutil/mock_oidc.go`. This is the hardest part — get this right before writing any tests.

The mock IdP is an `httptest.Server` that serves three endpoints:

1. `GET /.well-known/openid-configuration` — returns JSON:
   ```json
   {
     "issuer": "<mock server URL>",
     "authorization_endpoint": "<mock>/authorize",
     "token_endpoint": "<mock>/token",
     "jwks_uri": "<mock>/keys",
     "id_token_signing_alg_values_supported": ["RS256"],
     "subject_types_supported": ["public"],
     "response_types_supported": ["code"]
   }
   ```

2. `POST /token` — exchanges auth code for tokens. Returns:
   ```json
   {"access_token": "mock", "token_type": "Bearer", "id_token": "<signed JWT>"}
   ```
   The `id_token` is a real JWT signed with the test RSA private key, containing configurable `sub`, `iss` (mock server URL), `aud` (client_id), `nonce`, `exp`, `iat` claims.

3. `GET /keys` — returns JWKS with the test RSA public key in JWK format.

Helper signature:
```go
type MockOIDC struct {
    Server   *httptest.Server
    Sub      string          // configurable subject claim
    ClientID string          // expected client_id
}
func NewMockOIDC(t *testing.T) *MockOIDC
```

Use `crypto/rsa.GenerateKey` (2048-bit) at init time. Convert public key to JWK using `go-jose/v4` or manually construct the JWK JSON. Sign ID tokens with `golang-jwt/jwt/v5` using `jwt.SigningMethodRS256`.

The test flow simulates: login handler redirects to IdP → test extracts state/nonce from redirect URL → test calls callback with code + state → mock IdP returns ID token → callback verifies and issues session JWT.

**Step 2: Write failing tests**

```go
func TestOIDCFlow_Success(t *testing.T)              // full flow: login → callback → JWT issued
func TestOIDCFlow_NoIdentity(t *testing.T)           // valid auth but no linked identity → error
func TestOIDCFlow_CSRFMismatch(t *testing.T)         // tampered state → error
func TestOIDCFlow_DisabledConnection(t *testing.T)   // disabled → error
func TestOIDCFlow_CrossOrgIsolation(t *testing.T)    // same sub, different connection
```

**Step 3: Implement login handler**

`GET /api/v1/auth/oidc/{connection_id}/login`:
1. Load SSO connection by ID
2. Check `enabled`
3. Create OIDC provider (lazy-cached in `sync.Map`)
4. Generate state (CSRF token + connection_id encoded)
5. Generate nonce
6. Set state cookie, nonce cookie
7. Redirect to IdP authorization URL

**Step 4: Implement callback handler**

`GET /api/v1/auth/oidc/callback`:
1. Validate state cookie, extract connection_id
2. Load SSO connection
3. Exchange code for tokens
4. Verify ID token (issuer, nonce, expiry)
5. Extract `sub`
6. Look up `user_identities(provider='oidc:{connection_id}', provider_user_id=sub)`
7. If found → issue JWT + refresh token (same as Google/GitHub flows)
8. If not found → return error "Contact your administrator"

**Step 5: Wire routes**

Register on auth router (public, no auth middleware):
- `/auth/oidc/:connection_id/login`
- `/auth/oidc/callback`

**Step 6: Run tests, lint, commit**

```bash
git commit -m "feat(api): OIDC login + callback flow with mock IdP — TDD"
```

---

> **REVIEW CHECKPOINT 4** — Pause here for review. This is the most complex task. Verify: mock IdP test helper issues valid JWTs with configurable claims, CSRF state encodes connection_id correctly, provider cache works, identity matching uses `sub` claim (never email), provider key is `'oidc:{connection_id}'`, disabled connections are rejected, and cross-org isolation is tested.

### Task 25: Identity linking — TDD

**Files:**
- Modify: `internal/api/oauth_oidc.go` — add link handler
- Modify: `internal/api/oauth_oidc_test.go` — add tests

**Step 1: Write failing tests**

```go
func TestIdentityLinking_Success(t *testing.T)       // member links SSO identity
func TestIdentityLinking_AlreadyLinked(t *testing.T) // double-link returns error
```

**Step 2: Implement**

`POST /api/v1/orgs/{org_id}/sso/link`:
1. Requires authenticated user + org membership
2. Loads SSO connection for org
3. Initiates OIDC flow (same as login but callback creates `user_identities` record instead of logging in)
4. Callback path: `oidc_link_callback` — creates identity record, returns success

**Step 3: Run tests, lint, commit**

```bash
git commit -m "feat(api): SSO identity linking for existing org members — TDD"
```

---

### Task 26: Audit logging for SSO operations

**Files:**
- Modify: `internal/api/sso.go` — add audit calls to CRUD handlers
- Modify: `internal/api/oauth_oidc.go` — add audit for login/link

Add `srv.audit.Log()` calls for SSO connection create/update/delete and identity linking. Client secret redacted via existing `redactSecrets`.

Test that audit entries are created for SSO operations.

```bash
git commit -m "feat(api): audit logging for SSO operations"
```

---

## Final Steps

### Task 27: Full test suite + linter + plan check

**Step 1: Run full test suite**

Run: `go test ./... -v -count=1`
Expected: ALL PASS. Zero failures.

**Step 2: Run linter**

Run: `golangci-lint run`
Expected: 0 issues.

**Step 3: Run plan-check and pitfall-check skills**

Use `/plan-check` on PLAN.md §7.2 (SSO), §14 (tiers), §17 (audit log), §21 (retention).
Use `/pitfall-check` on all new code.

**Step 4: Update `dev/implementation-log.md`**

Document what was built, key decisions, gotchas, test coverage.

**Step 5: Final commit**

```bash
git commit -m "docs: Phase 5 implementation log"
```

---

## Task Dependency Graph

```
Phase 5A: Tier Enforcement
  Task 1 (migration: tier columns)
    └→ Task 2 (tier resolver)            ─┐
    └→ Task 3 (store: tier queries)       ├─ can run in parallel
       └→ Task 4 (org rate limiter)      ─┘
       └→ Task 5a (tier context middleware)
            └→ Task 5b (resource limit gating)
            └→ Task 5c (channel type gating)
            └→ Task 5d (org rate limiter wiring)
            └→ Task 6 (AI quota wiring)
            └→ Task 7 (tier read API)
  ── REVIEW CHECKPOINT 1 ──

Phase 5B: Data Retention (independent of 5A until 10c)
  Task 8 (migration: retention indexes)  ─┐
  Task 9 (config: retention vars)         ├─ can run in parallel
       └→ Task 10a (sqlc queries + wrappers)
            └→ Task 10b (store integration tests)
            └→ Task 10c (retention runner — needs tier.Resolver from Task 2)
                 └→ Task 10d (runner tests)
                      └→ Task 11 (job scheduling + AI cleanup migration)
  ── REVIEW CHECKPOINT 2 ──

Phase 5C: Audit Log (depends on Task 2 for tier gating)
  Task 12 (migration: audit_log)
    └→ Task 13 (secret redaction)
         └→ Task 14 (audit writer + sqlc)
              └→ Task 15 (handler integration)
              └→ Task 16 (audit API — needs tier resolver)
              └→ Task 17 (retention integration — needs runner from 10c)
  ── REVIEW CHECKPOINT 3 (after Task 15) ──

Phase 5D: Generic OIDC (depends on Task 5a for tier gating, Task 14 for audit)
  Task 18 (AES-256-GCM — independent, can start early)
    └→ Task 19 (migration: SSO tables)
         └→ Task 20 (config: SSO key)
              └→ Task 21 (store: SSO queries)
                   └→ Task 22 (SSO CRUD handlers)
                   └→ Task 23 (email domain discovery)
                   └→ Task 24 (OIDC flow)
  ── REVIEW CHECKPOINT 4 (after Task 24) ──
                        └→ Task 25 (identity linking)
                        └→ Task 26 (audit for SSO)

  Task 27 (final verification) — depends on all above
```

### Parallelism Opportunities for Subagent Execution

Within each phase, tasks are mostly sequential. However, across phases:
- **Tasks 2, 3, 4** can run in parallel (tier resolver, store queries, org rate limiter are independent)
- **Tasks 8 + 9** can run in parallel with late Phase 5A tasks (6, 7)
- **Task 18** (AES crypto) is completely independent — can start any time
- **Task 13** (secret redaction) is independent of store/migration work — can start once Task 12 is done

### Review Checkpoint Summary

| Checkpoint | After Task | What to verify |
|------------|-----------|----------------|
| 1 | 5d | Middleware chain, resolver usage, rate limiter, existing tests green |
| 2 | 10d | All retention targets covered, tier-gated grouping, batch loop, AI migration |
| 3 | 15 | Audit entries for all mutations, redaction, success=false, non-blocking |
| 4 | 24 | Mock IdP, CSRF+connection_id encoding, provider cache, sub-based matching, cross-org |
