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

```sql
-- migrate:no-transaction

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'free';
ALTER TABLE organizations ADD CONSTRAINT organizations_tier_check CHECK (tier IN ('free', 'pro', 'enterprise'));
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier_overrides JSONB NOT NULL DEFAULT '{}';
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

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
```

**Step 2: Regenerate sqlc**

Run: `sqlc generate`
Expected: No errors. New files in `internal/store/generated/`.

**Step 3: Write store wrapper methods**

Create `internal/store/org.go` (or add to existing file) with methods that call generated queries via `withBypassTx` (org tier is read in auth middleware, before org context is set):

```go
func (s *Store) GetOrgTier(ctx context.Context, orgID uuid.UUID) (string, map[string]any, error)
func (s *Store) UpdateOrgTier(ctx context.Context, orgID uuid.UUID, tier string) error
func (s *Store) CountAlertRulesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
func (s *Store) CountWatchlistsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
func (s *Store) CountMembersByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
```

**Step 4: Verify compilation**

Run: `go build ./...`
Expected: No errors.

**Step 5: Commit**

```bash
git add internal/store/queries/org.sql internal/store/generated/ internal/store/org.go
git commit -m "feat(store): org tier queries — sqlc"
```

---

### Task 4: Per-org API rate limiter — TDD

**Files:**
- Create: `internal/api/org_ratelimit.go`
- Create: `internal/api/org_ratelimit_test.go`

**Step 1: Write failing tests**

Model after existing `internal/api/ratelimit_test.go`. Key tests:

```go
func TestOrgRateLimiter_Allow(t *testing.T)           // basic allow/deny
func TestOrgRateLimiter_DifferentOrgs(t *testing.T)    // org A doesn't affect B
func TestOrgRateLimiter_RateChange(t *testing.T)       // tier change creates new limiter
func TestOrgRateLimiter_Eviction(t *testing.T)         // idle orgs evicted
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

### Task 5: Tier context middleware + handler gating — TDD

**Files:**
- Modify: `internal/api/context.go` — add `ctxTierResolver` context key
- Modify: `internal/api/server.go` — add `orgRateLimiter` field, wire middleware
- Create or modify: `internal/api/middleware.go` — tier resolution middleware
- Modify: handler files for gating: `internal/api/alert_rules.go`, `internal/api/watchlists.go`, `internal/api/channels.go`, `internal/api/members.go` (or wherever these handlers live)

**Step 1: Write integration tests for tier gating**

In the appropriate test files (e.g., `internal/api/alert_rules_test.go`), add tests:
- Create org with tier=free → create 5 alert rules (succeed) → create 6th (fail 403)
- Create org with tier=pro → create 50 alert rules (succeed)
- Create org with tier_overrides `{"max_alert_rules": 10}` → limit is 10, not 5

Same pattern for watchlists (3/20), members (5/25), channel types (free can't create email/Slack).

**Step 2: Run tests to verify they fail**

Expected: FAIL — no tier resolution in context, no limit checks in handlers.

**Step 3: Implement tier resolution middleware**

Add `ctxTierResolver` to context.go. In the org-scoped middleware (where `ctxOrgID` is set), also load org tier via `store.GetOrgTier()` and construct `tier.Resolver`, injecting it into context.

**Step 4: Implement handler tier checks**

In each handler's create path, before the mutation:
```go
resolver, _ := r.Context().Value(ctxTierResolver).(*tier.Resolver)
limit := resolver.IntLimit("max_alert_rules", 5, 50, -1)
if limit >= 0 {
    count, _ := srv.store.CountAlertRulesByOrg(ctx, orgID)
    if count >= int64(limit) {
        return nil, huma.Error403Forbidden("tier limit: max alert rules reached")
    }
}
```

**Step 5: Wire org rate limiter middleware in `Handler()`**

After auth middleware, before routes. Read tier resolver from context, call `orgRateLimiter.Allow(orgID, resolvedRate, burst)`.

**Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/... -v`
Expected: All PASS (existing + new tier tests).

**Step 7: Run full test suite + linter**

Run: `go test ./... && golangci-lint run`
Expected: All pass, 0 lint issues.

**Step 8: Commit**

```bash
git add internal/api/
git commit -m "feat(api): tier enforcement — context middleware + handler gating — TDD"
```

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

Test `GET /api/v1/orgs/{org_id}/tier` returns `{tier, limits}` for all roles.

**Step 2: Write handler**

Returns current tier, resolved limits (all limit names with their effective values), and current usage counts.

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
    ON job_queue (updated_at) WHERE status IN ('succeeded', 'dead');
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

```go
// ── Data retention ───────────────────────────────────────────────────────────
RetentionCleanupEnabled        bool `env:"RETENTION_CLEANUP_ENABLED"         envDefault:"true"`
RetentionCleanupBatchSize      int  `env:"RETENTION_CLEANUP_BATCH_SIZE"      envDefault:"10000"`
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

### Task 10: Store — Retention cleanup queries + runner — TDD

**Files:**
- Create: `internal/store/queries/retention.sql` — sqlc queries for bounded-batch DELETE
- Create: `internal/store/retention.go` — wrapper methods
- Create: `internal/store/retention_test.go` — integration tests
- Create: `internal/retention/runner.go` — the retention job runner
- Create: `internal/retention/runner_test.go` — runner tests

This is the largest task. Break it into sub-steps:

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
    WHERE status IN ('succeeded', 'dead') AND updated_at < @cutoff::timestamptz
    ORDER BY updated_at LIMIT @batch_size::int
)
DELETE FROM job_queue jq USING doomed WHERE jq.id = doomed.id;

-- name: CleanupRefreshTokens :execrows
DELETE FROM refresh_tokens WHERE expires_at < @cutoff::timestamptz;
```

Note: `CleanupRefreshTokens` doesn't need bounded-batch — token table is small. The 60-second grace is computed by the caller: `cutoff = now() - 60s`.

**Step 2: Run `sqlc generate`, verify compilation**

**Step 3: Write store wrapper methods in `internal/store/retention.go`**

Each wraps the generated query with `withBypassTx` (retention operates across all orgs).

**Step 4: Write integration tests in `internal/store/retention_test.go`**

Use `testutil.NewTestDB(t)`. For each table:
- Insert rows with explicit timestamps (some old, some recent)
- Call cleanup with a cutoff
- Verify old rows deleted, recent rows retained
- Test batch size limiting (insert more than batch_size old rows, verify only batch_size deleted per call)

Key tests:
- `TestCleanupJobQueue_StatusFilter` — insert pending + running + succeeded + dead rows, verify only succeeded/dead deleted
- `TestCleanupRefreshTokens_GraceWindow` — insert token expired 30s ago (retained) and 90s ago (deleted)
- `TestCleanupAlertEvents_OrgFilter` — only specified org_ids cleaned

**Step 5: Write retention runner in `internal/retention/runner.go`**

```go
// ABOUTME: Scheduled retention cleanup job that deletes old data per §21.
// ABOUTME: Runs as a job_queue entry with bounded-batch deletes per table.
package retention

type RunnerConfig struct {
    Enabled           bool
    BatchSize         int
    MaxRuntimeSeconds int
    // Per-table defaults
    RawPayloadDays    int
    FeedFetchLogDays  int
    AlertEventsDays   int
    NotifDelivDays    int
    AuditLogDays      int
    JobQueueHours     int
    AILogRetentionDays int
}

type Runner struct {
    store  *store.Store
    cfg    RunnerConfig
    log    *slog.Logger
    now    func() time.Time // injectable for tests
}

func (r *Runner) Run(ctx context.Context) error
```

`Run()` iterates tables, calling bounded-batch delete in a loop per table until 0 rows or max runtime hit. Logs per-table results. Errors per table are logged but don't stop the run.

For tier-gated tables (alert_events, notification_deliveries, audit_log): loads all orgs, groups by retention window via `tier.Resolver`, runs per-group cleanup.

**Step 6: Write runner tests in `internal/retention/runner_test.go`**

- `TestRunner_AllTables` — seeds data across all tables, runs once, verifies cleanup
- `TestRunner_MaxRuntime` — uses a very short max runtime, verifies it stops
- `TestRunner_Disabled` — `Enabled=false` → no deletions
- `TestRunner_ErrorIsolation` — use context cancellation mid-table, verify other tables still cleaned
- `TestRunner_PerOrgGroup` — two orgs with different tiers, verify per-org retention windows

**Step 7: Run all tests**

Run: `go test ./internal/store/... ./internal/retention/... -v`
Expected: All PASS.

**Step 8: Commit**

```bash
git commit -m "feat(retention): bounded-batch cleanup runner for all tables — TDD"
```

---

### Task 11: Job scheduling + migrate AI cleanup — TDD

**Files:**
- Modify: `internal/notify/worker.go` — add retention job scheduling ticker, remove AI cleanup ticker
- Modify: `internal/notify/worker_test.go` — update tests
- Modify: `internal/api/server.go` — wire retention runner

**Step 1: Write test for retention job scheduling**

Test that the worker ticker enqueues a `retention_cleanup` job, and doesn't double-enqueue if one is pending.

**Step 2: Write test verifying AI cleanup removal**

Test that `RunAICleanupOnce` is removed (or the method now delegates to the retention runner).

**Step 3: Implement**

In the worker's `Start()` select-loop, add a `retentionTicker` (daily = `24 * time.Hour`). On tick:
1. Check if `job_queue` has a pending/running `retention_cleanup` job
2. If not, enqueue one with `lock_key = 'cleanup:retention'`

The job executor (in the worker's claim loop) recognizes `retention_cleanup` job type and calls `retention.Runner.Run()`.

Remove `aiCleanupTicker` and `runAICleanup` method. The AI cache and request log cleanup is now handled by the retention runner.

**Step 4: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS. Existing AI cleanup tests may need updating to use the retention runner instead.

**Step 5: Commit**

```bash
git commit -m "feat(worker): retention job scheduling + migrate AI cleanup to retention runner"
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
ORDER BY created_at DESC, id DESC
LIMIT @page_size::int;
```

**Step 2: Run `sqlc generate`**

**Step 3: Write audit Writer**

```go
// internal/audit/writer.go
// ABOUTME: Appends audit log entries with write-time secret redaction.
// ABOUTME: Non-blocking — errors are logged, never propagated to callers.
package audit

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

**Step 4: Write integration tests**

Using `testutil.NewTestDB(t)`:
- `TestWriter_CreateAction` — old=nil, new populated, verify row in DB
- `TestWriter_UpdateAction` — both old and new, verify redaction applied
- `TestWriter_DeleteAction` — old populated, new=nil
- `TestWriter_DeniedAction` — success=false, both nil
- `TestWriter_SystemAction` — actor_id=nil, actor_email=nil
- `TestWriter_NonBlocking` — inject broken store, verify no panic/error returned

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
- Failed auth (wrong role) → verify audit entry with success=false

For channels specifically: verify `signing_secret` is `[REDACTED]` in audit entry.

**Step 2: Implement**

In each handler's create/update/delete path:
1. For update/delete: capture old state before mutation
2. After successful mutation: `srv.audit.Log(ctx, entry)`
3. For failed auth (403): `srv.audit.Log(ctx, Entry{Success: false, ...})`

Wire `audit.Writer` into `Server` via `SetAuditDeps(w *audit.Writer)`.

**Step 3: Run full test suite. Commit.**

```bash
git commit -m "feat(api): audit log integration in all mutation handlers"
```

---

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

### Task 17: Add audit_log to retention runner

**Files:**
- Modify: `internal/store/queries/retention.sql` — add CleanupAuditLog query
- Modify: `internal/retention/runner.go` — add audit_log table
- Modify: `internal/retention/runner_test.go` — test audit retention

**Step 1: Add query, update runner, test. Commit.**

```bash
git commit -m "feat(retention): include audit_log in retention cleanup"
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

In `internal/testutil/mock_oidc.go`:
- `httptest.Server` serving `/.well-known/openid-configuration`, `/token`, `/keys` (JWKS)
- Issues valid JWTs signed with a test RSA key
- Configurable `sub` claim

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
Task 1 (migration: tier columns)
  └→ Task 2 (tier resolver)
  └→ Task 3 (store: tier queries)
       └→ Task 4 (org rate limiter)
       └→ Task 5 (tier middleware + handler gating)
            └→ Task 6 (AI quota wiring)
            └→ Task 7 (tier read API)

Task 8 (migration: retention indexes)
  └→ Task 9 (config: retention vars)
       └→ Task 10 (store + runner)
            └→ Task 11 (job scheduling + AI cleanup migration)

Task 12 (migration: audit_log)
  └→ Task 13 (secret redaction)
       └→ Task 14 (audit writer + sqlc)
            └→ Task 15 (handler integration)
            └→ Task 16 (audit API)
            └→ Task 17 (retention integration)

Task 18 (AES-256-GCM)
  └→ Task 19 (migration: SSO tables)
       └→ Task 20 (config: SSO key)
            └→ Task 21 (store: SSO queries)
                 └→ Task 22 (SSO CRUD handlers)
                 └→ Task 23 (email domain discovery)
                 └→ Task 24 (OIDC flow)
                      └→ Task 25 (identity linking)
                      └→ Task 26 (audit for SSO)

Task 27 (final verification) — depends on all above
```
