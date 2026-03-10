# Phase 0 — Shared Foundation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver four small, targeted changes that multiple Phase 1 pillars depend on — done sequentially before spawning parallel agents.

**Architecture:** Phase 0 is a prerequisite gate. Each item is independent but small enough to do in one session. All changes land on `dev` branch before Phase 1 starts.

**Tech Stack:** Go, PostgreSQL, golang-migrate, cobra

**References:**
- Design: `dev/plans/2026-03-10-ops-maturity-overview.md` §Phase 0
- Testing pitfalls: `dev/testing-pitfalls.md` (referenced as `tp§N.N`)

---

## Task 1: `system_settings` Migration

**Files:**
- Create: `migrations/000034_create_system_settings.up.sql`
- Create: `migrations/000034_create_system_settings.down.sql`
- Modify: `cmd/cvert-ops/main.go:529` — bump `expectedSchemaVersion` from 30 → 34 (after all Phase 0 migrations land)

**Context for agent:** The `system_settings` table stores system-level key-value pairs (encryption sentinel, future system metadata). It is NOT org-scoped — no RLS, no `org_id`. Used by the Operate pillar's doctor command and the Secure pillar's encryption sentinel check.

**Step 1: Write the up migration**

```sql
-- system_settings stores system-level key-value configuration and sentinels.
-- Not org-scoped: no RLS policy. Accessed only by site admins and CLI tools.
CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT        PRIMARY KEY,
    value      BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

No concurrent index needed — this is just a `CREATE TABLE` with a PK. No `-- migrate:no-transaction` header.

**Step 2: Write the down migration**

```sql
DROP TABLE IF EXISTS system_settings;
```

**Step 3: Run migration and verify**

Run: `go run ./cmd/cvert-ops migrate`
Expected: migration 34 applied successfully.

Verify: `SELECT * FROM system_settings;` returns 0 rows (table exists, empty).

**Step 4: Commit**

```bash
git add migrations/000034_create_system_settings.up.sql migrations/000034_create_system_settings.down.sql
git commit -m "feat(migrate): add system_settings table for doctor encryption sentinel"
```

---

## Task 2: Verify `RequireSiteAdmin()` Middleware

**Files:**
- Read: `internal/api/server.go:214-220` — admin route group
- Read: `internal/api/middleware.go` (or wherever `RequireSiteAdmin` is defined)
- Test: (verification only — no new code unless something is broken)

**Context for agent:** All four pillars add admin endpoints. Verify that:
1. `RequireSiteAdmin()` middleware exists and checks `users.is_site_admin`
2. It returns 403 for non-admin users
3. It returns 401 for unauthenticated requests
4. The admin route group in `server.go` already applies both `RequireAuthenticated()` and `RequireSiteAdmin()`

**Step 1: Locate and read the middleware**

Search for `RequireSiteAdmin` in `internal/api/`. Read the implementation. Verify it:
- Extracts user from context (set by `RequireAuthenticated`)
- Checks `is_site_admin` flag
- Returns 403 if not admin

**Step 2: Verify existing test coverage**

Search for test files covering `RequireSiteAdmin`. Confirm tests exist for:
- Non-admin user → 403 (tp§11.1)
- Unauthenticated → 401 (tp§11.1)
- Admin user → passes through

**Step 3: If tests are missing, write them**

Only if the verification in Steps 1-2 reveals gaps. The admin route group at `server.go:214-220` already uses both middlewares — verify this by reading the code.

**Step 4: Commit (only if changes were made)**

```bash
git commit -m "test(api): verify RequireSiteAdmin middleware coverage"
```

---

## Task 3: Security Event Type Constants

**Files:**
- Create: `internal/secure/events.go`

**Context for agent:** The Secure pillar's security event pipeline needs a central registry of event type constants. Creating this in Phase 0 means the Observe pillar can reference these constants for Prometheus metric labels if needed, and the Secure pillar doesn't need to create the package from scratch.

**Step 1: Create the `internal/secure/` package**

```go
// ABOUTME: Central registry of security event type constants for the security event pipeline.
// ABOUTME: Used by security event writers, Prometheus metric labels, and admin API filters.
package secure

// Security event type constants. These are the canonical values stored in
// security_events.event_type and used as Prometheus metric labels.
const (
	EventAuthLoginFailed           = "auth.login_failed"
	EventAuthLoginSuccess          = "auth.login_success"
	EventAuthAccountLocked         = "auth.account_locked"
	EventAuthAccountUnlocked       = "auth.account_unlocked"
	EventAuthPasswordResetReq      = "auth.password_reset_requested"
	EventAuthPasswordChanged       = "auth.password_changed"
	EventAuthTokenReuseDetected    = "auth.token_reuse_detected"
	EventAuthAPIKeyCreated         = "auth.api_key_created"
	EventAuthAPIKeyUsedAfterRevoke = "auth.api_key_used_after_revocation"
	EventAdminUserDisabled         = "admin.user_disabled"
	EventAdminConfigReloaded       = "admin.config_reloaded"
	EventAdminBulkRetryTriggered   = "admin.bulk_retry_triggered"
)

// Severity levels for security events.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// EventSeverity maps each event type to its default severity level.
var EventSeverity = map[string]string{
	EventAuthLoginFailed:           SeverityInfo,
	EventAuthLoginSuccess:          SeverityInfo,
	EventAuthAccountLocked:         SeverityWarning,
	EventAuthAccountUnlocked:       SeverityInfo,
	EventAuthPasswordResetReq:      SeverityInfo,
	EventAuthPasswordChanged:       SeverityInfo,
	EventAuthTokenReuseDetected:    SeverityCritical,
	EventAuthAPIKeyCreated:         SeverityInfo,
	EventAuthAPIKeyUsedAfterRevoke: SeverityWarning,
	EventAdminUserDisabled:         SeverityWarning,
	EventAdminConfigReloaded:       SeverityInfo,
	EventAdminBulkRetryTriggered:   SeverityInfo,
}
```

**Step 2: Write a test that verifies the severity map is exhaustive**

Create `internal/secure/events_test.go`:

```go
func TestEventSeverityMapIsExhaustive(t *testing.T) {
    // Use reflection or manual list to verify every Event* constant
    // has an entry in EventSeverity.
    allEvents := []string{
        secure.EventAuthLoginFailed,
        secure.EventAuthLoginSuccess,
        // ... all constants
    }
    for _, e := range allEvents {
        if _, ok := secure.EventSeverity[e]; !ok {
            t.Errorf("EventSeverity missing entry for %q", e)
        }
    }
}
```

**Step 3: Run test**

Run: `go test ./internal/secure/ -v -run TestEventSeverity`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/secure/events.go internal/secure/events_test.go
git commit -m "feat(secure): add security event type constants and severity map"
```

---

## Task 4: Custom Source Precedence Tier in Merge Pipeline

**Files:**
- Modify: `internal/merge/resolve.go:31-40` — add custom sources to end of each priority list
- Create: `internal/merge/resolve_custom_test.go` — tests for custom source precedence
- Modify: `internal/merge/resolve.go:18-27` — add `SourceCustom` sentinel (or use helper function)

**Context for agent:** The Extend pillar's generic feed adapter and inbound webhook both produce sources with custom names (e.g., `"internal-scanner"`). These sources need to participate in the merge resolution but at the lowest precedence — below all built-in sources. The current `resolve()` function uses explicit priority lists (`statusPriority`, `cvssPriority`, `pkgPriority`). Sources NOT in those lists already fall through to the `otherSources()` helper — they contribute to union fields (CWEs, references, packages, CPEs) but never win scalar precedence. This is already the correct behavior for custom sources.

**CRITICAL:** Do NOT modify `KnownFeeds` in `internal/ingest/feeds.go`. Do NOT modify `NewAdapter` in `internal/ingest/feeds.go`. Custom feeds bypass the factory entirely — the Extend pillar handles their instantiation.

**What actually needs to change:** The `resolve()` function's `otherSources()` helper already handles unknown source names by letting them contribute to union fields without winning scalar precedence. Verify this is correct by:

1. Reading `resolve.go` fully to understand `otherSources()` behavior
2. Writing explicit tests proving custom sources behave correctly

**Step 1: Write failing tests**

Create `internal/merge/resolve_custom_test.go`:

```go
// Test: custom source provides CVSS 8.0, NVD provides 7.5 → NVD wins (7.5)
func TestResolve_CustomSourceCVSSLosesToNVD(t *testing.T) { ... }

// Test: custom source is the ONLY source for a CVE → its values are used
func TestResolve_CustomSourceOnlySource(t *testing.T) { ... }

// Test: custom source contributes references to the union
func TestResolve_CustomSourceReferencesInUnion(t *testing.T) { ... }

// Test: custom source contributes affected packages to the union
func TestResolve_CustomSourcePackagesInUnion(t *testing.T) { ... }
```

The first test is the design doc's explicit requirement: "generic feed patches CVE with CVSS 8.0, NVD patches same CVE with 7.5 → canonical record shows 7.5 (NVD wins)."

**Step 2: Run tests to verify they pass (or fail if `otherSources` has a bug)**

Run: `go test ./internal/merge/ -v -run TestResolve_Custom -race`
Expected: All PASS — because `otherSources` already handles unknown source names correctly.

If any test FAILS, investigate and fix `resolve.go` before proceeding. The fix should be minimal — adding custom sources to the tail of priority lists or adjusting `otherSources`.

**Step 3: Add `IsReservedSourceName` helper to `internal/ingest/feeds.go`**

Both the Extend pillar's config validation and the inbound webhook handler need to check if a source name collides with built-in feed names. Add a helper:

```go
// IsReservedSourceName returns true if the given name collides with a
// built-in feed name. Used by generic feed config validation and the
// inbound webhook handler to reject reserved names.
func IsReservedSourceName(name string) bool {
	return IsKnownFeed(name)
}
```

This is a trivial wrapper but provides a semantic name for the validation.

**Step 4: Test the helper**

```go
func TestIsReservedSourceName(t *testing.T) {
    for _, name := range KnownFeeds {
        if !IsReservedSourceName(name) {
            t.Errorf("expected %q to be reserved", name)
        }
    }
    if IsReservedSourceName("internal-scanner") {
        t.Error("expected 'internal-scanner' to NOT be reserved")
    }
}
```

**Step 5: Commit**

```bash
git add internal/merge/resolve_custom_test.go internal/ingest/feeds.go
git commit -m "feat(merge): verify custom source precedence tier and add reserved name helper"
```

---

## Task 5: Bump `expectedSchemaVersion` and Final Verification

**Files:**
- Modify: `cmd/cvert-ops/main.go:529` — update `expectedSchemaVersion`

**Step 1: Count total migrations after Phase 0**

Phase 0 adds migration 34 (system_settings). The current highest is 33 (email_verification_tokens). Update:

```go
const expectedSchemaVersion = 34
```

**Step 2: Run full test suite**

Run: `go test ./... -race -count=1`
Expected: All tests pass. No regressions from Phase 0 changes.

**Step 3: Commit**

```bash
git add cmd/cvert-ops/main.go
git commit -m "chore: bump expectedSchemaVersion to 34 for Phase 0 system_settings migration"
```

---

## Subagent Failure Modes to Watch For

| Risk | What goes wrong | Mitigation |
|------|----------------|------------|
| Agent modifies `KnownFeeds` or `NewAdapter` | Design explicitly says NOT to modify these | Task 4 instructions are explicit: "Do NOT modify" |
| Agent creates org-scoped system_settings | Table is system-level, no org_id, no RLS | Task 1 instructions specify "NOT org-scoped" |
| Agent skips custom precedence tests | Tests are the primary deliverable for Task 4 | Task 4 requires specific test scenarios from design doc |
| Agent adds too many migrations | Only one migration (000034) in Phase 0 | Task 1 explicitly names the migration number |
| Agent forgets to bump expectedSchemaVersion | Causes startup warning (tp§5.4) | Task 5 is dedicated to this |
