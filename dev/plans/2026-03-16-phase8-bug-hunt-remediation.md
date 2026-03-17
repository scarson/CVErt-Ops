# Phase 8 Bug Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 12 confirmed bugs from the Phase 8 (Operational Maturity) bug hunt.

**Architecture:** Fixes are grouped by file ownership to enable parallel subagent execution. Six agents, each with a non-overlapping set of files. Auth hardening (Agent B) is the largest group — three sequential fixes touching auth.go and auth.sql.

**Tech Stack:** Go 1.26, sqlc, squirrel, PostgreSQL, Vue 3 + TypeScript, Vitest

**Bug hunt source:** `dev/bug-hunts/2026-03-16-phase8-consolidated.md`

---

## Pre-Implementation Requirements (ALL agents)

**Every agent MUST do the following before writing any code:**

1. Invoke the `superpowers:test-driven-development` skill and follow its methodology for every fix
2. Read `dev/testing-pitfalls.md` in full — it contains checklist items that directly apply to these fixes
3. Read `dev/implementation-pitfalls.md` for Go/Postgres conventions
4. Read `CLAUDE.md` for project rules (especially: TDD, naming, comments, commit frequency)

**Every agent MUST do the following after each task (or after a logical batch of closely-related subtasks within a task):**

1. Review all new/modified tests against `dev/testing-pitfalls.md` — specifically check the sections called out in each task below. If any checklist item applies and is not covered by a test, add the test before moving on.
2. Run `go test ./...` (or the relevant package tests) and confirm all pass
3. Run `golangci-lint run` on changed packages and fix any issues
4. Commit with a descriptive message

---

## Agent Assignment & File Ownership

| Agent | Tasks | Owned Files (no other agent may touch) |
|-------|-------|---------------------------------------|
| **A: Feed Management** | 1, 2 | `internal/ingest/scheduler.go`, `internal/ingest/feeds.go`, `internal/api/feeds.go`, `internal/api/server.go` (feed route registration only) |
| **B: Auth Hardening** | 3, 4, 6 | `internal/api/auth.go`, `internal/api/lockout.go`, `internal/api/middleware_auth.go`, `internal/store/queries/auth.sql`, `internal/store/auth.go`, `internal/store/generated/auth.sql.go` (via sqlc generate) |
| **C: Health Checks** | 5, 8 | `web/src/views/admin/AdminSystemView.vue`, `internal/api/readyz.go`, `internal/doctor/checks.go` |
| **D: Admin Orgs** | 7 | `internal/api/admin_orgs.go`, `internal/store/admin_org.go` |
| **E: Generic Adapter** | 9 | `internal/feed/generic/adapter.go` |
| **F: Small Fixes** | 10, 11 | `internal/api/admin_deliveries.go`, `cmd/cvert-ops/validate.go` |

**Agents A, B, C, D, E, F can all run in parallel.** Within Agent B, tasks 3→4→6 must be sequential (shared files, each builds on the previous).

---

## Task 1: Scheduler Paused Feed Check (S1)

**Agent:** A — Feed Management
**Bug:** `internal/ingest/scheduler.go:126-148` — `maybeEnqueue` never checks `state.PausedAt`
**Testing pitfalls to review:** §14 ("Scheduler respects pause/disable flags"), §13 ("Admin flag enforcement at all entry points")

**Files:**
- Modify: `internal/ingest/scheduler.go:133-148` (add PausedAt check)
- Test: `internal/ingest/scheduler_test.go` (new test cases; read existing file first for patterns)

### Step 1: Write failing test

Add a test to the existing scheduler test file. The test must:
- Create a `FeedSyncState` with `PausedAt` set to a non-nil time
- Configure the mock store to return this state from `GetFeedSyncState`
- Call `maybeEnqueue` (via `tick` or `Start` with a short context)
- Assert that `EnqueueJob` was NOT called
- Also assert that the `jobsSkipped` counter was incremented with reason `"paused"`

The test name should be `TestScheduler_SkipsPausedFeed`.

Also add a companion test `TestScheduler_RunsResumedFeed` that:
- Creates a `FeedSyncState` with `PausedAt = nil` and `LastSuccessAt` far in the past
- Asserts `EnqueueJob` WAS called

### Step 2: Run test to verify it fails

```bash
go test ./internal/ingest/ -run TestScheduler_SkipsPausedFeed -v
```
Expected: FAIL — the job is enqueued despite PausedAt being set.

### Step 3: Implement the fix

In `internal/ingest/scheduler.go`, function `maybeEnqueue`, add a pause check immediately after the backoff check (after line 139, before the not-due check):

```go
// Skip if paused.
if state.PausedAt != nil {
    s.jobsSkipped.WithLabelValues(entry.FeedName, "paused").Inc()
    slog.Debug("feed paused", "feed", entry.FeedName, "paused_at", *state.PausedAt)
    return
}
```

This goes inside the `if state != nil {` block, after the backoff check and before the not-due check.

### Step 4: Run test to verify it passes

```bash
go test ./internal/ingest/ -run TestScheduler_ -v
```
Expected: ALL scheduler tests pass.

### Step 5: Run full package tests and lint

```bash
go test ./internal/ingest/ -count=1
golangci-lint run ./internal/ingest/
```

### Step 6: Commit

```
fix(ingest): scheduler respects paused_at flag

The scheduler's maybeEnqueue checked backoff and interval timing but
never checked PausedAt, making the feed pause/resume feature non-functional.
```

---

## Task 2: Generic Feeds Visible in Admin API (S2)

**Agent:** A — Feed Management
**Bug:** `internal/api/feeds.go` — all admin feed handlers gate on `ingest.IsKnownFeed()` which only includes built-in feeds
**Testing pitfalls to review:** §13 ("Registry completeness for extensible systems")

**Files:**
- Modify: `internal/ingest/feeds.go` (add feed registry)
- Modify: `internal/api/feeds.go` (use registry instead of `IsKnownFeed`)
- Modify: `internal/api/server.go` (pass generic feed names during server setup — find where generic feeds are registered and add a call to register them)
- Test: existing feed admin test files + new tests

### Design

The problem is that `KnownFeeds` is a hardcoded slice and `IsKnownFeed` only checks it. Generic feed names (loaded from YAML in `main.go`) are never registered.

**Approach:** Add a `RegisterFeed(name string)` function to `internal/ingest/feeds.go` that appends to a registry. Call it from `main.go` when loading generic feed configs. Change `IsKnownFeed` to check both the hardcoded list AND the registered list. Change `listFeedsHandler` to include registered feeds.

Do NOT change `KnownFeeds` itself (it's used by `IsReservedSourceName` to prevent generic feeds from colliding with built-in names). Instead, add a separate `registeredFeeds` slice.

### Step 1: Write failing test

Create a test that:
1. Calls `RegisterFeed("custom-vendor")`
2. Asserts `IsKnownFeed("custom-vendor")` returns true
3. Asserts `IsReservedSourceName("custom-vendor")` returns false (generic feeds are NOT reserved)
4. Asserts `AllFeedNames()` returns built-in feeds + "custom-vendor"

Also write an API-level test that:
1. Registers a generic feed name
2. Calls `GET /admin/feeds` and asserts the generic feed appears in the list
3. Calls `POST /admin/feeds/custom-vendor/trigger` and asserts it doesn't return "unknown feed"

### Step 2: Run test to verify it fails

### Step 3: Implement

In `internal/ingest/feeds.go`:

```go
var (
    registeredFeeds []string
    feedMu          sync.Mutex
)

// RegisterFeed adds a generic feed name to the feed registry.
// Must be called before server start (during init in main.go).
func RegisterFeed(name string) {
    feedMu.Lock()
    defer feedMu.Unlock()
    registeredFeeds = append(registeredFeeds, name)
}

// AllFeedNames returns built-in feeds plus any registered generic feeds.
func AllFeedNames() []string {
    feedMu.Lock()
    defer feedMu.Unlock()
    all := make([]string, 0, len(KnownFeeds)+len(registeredFeeds))
    all = append(all, KnownFeeds...)
    all = append(all, registeredFeeds...)
    return all
}

// IsKnownFeed returns true if feedName is a built-in OR registered feed.
func IsKnownFeed(feedName string) bool {
    for _, f := range KnownFeeds {
        if f == feedName {
            return true
        }
    }
    feedMu.Lock()
    defer feedMu.Unlock()
    for _, f := range registeredFeeds {
        if f == feedName {
            return true
        }
    }
    return false
}

// IsReservedSourceName returns true if the name collides with a BUILT-IN feed.
// Generic feeds are NOT reserved — only built-in feeds are.
func IsReservedSourceName(name string) bool {
    for _, f := range KnownFeeds {
        if f == name {
            return true
        }
    }
    return false
}
```

**IMPORTANT:** `IsReservedSourceName` must NOT check `registeredFeeds` — it must only check `KnownFeeds`. This is the semantic distinction: reserved means "collides with a built-in", not "already registered".

In `internal/api/feeds.go`, change `listFeedsHandler` to iterate `ingest.AllFeedNames()` instead of `ingest.KnownFeeds`:

```go
entries := make([]FeedStatusEntry, 0, len(ingest.AllFeedNames()))
for _, feedName := range ingest.AllFeedNames() {
```

In `cmd/cvert-ops/main.go` (or wherever generic feed configs are loaded), find where `scheduler.AddEntries(genericEntries)` is called and add a loop before it:

```go
for _, cfg := range genericConfigs {
    ingest.RegisterFeed(cfg.Name)
}
```

Read `cmd/cvert-ops/main.go` to find the exact location — search for `AddEntries` or `generic.LoadDir`.

**Add a `ResetRegistry()` test helper** for use in tests so registered feeds don't leak between test cases:

```go
// ResetRegistry clears registered feeds. Test use only.
func ResetRegistry() {
    feedMu.Lock()
    defer feedMu.Unlock()
    registeredFeeds = nil
}
```

### Step 4: Run tests, lint, commit

---

## Task 3: Login Handler Checks disabled_at (S3)

**Agent:** B — Auth Hardening
**Bug:** `internal/api/auth.go:221-308` — loginHandler issues tokens for disabled users
**Testing pitfalls to review:** §13 ("Admin flag enforcement at all entry points"), §11 ("Anti-enumeration timing"), §3 ("Information leakage via error codes")

**Files:**
- Modify: `internal/api/auth.go` (loginHandler)
- Test: `internal/api/auth_test.go` or existing login test file

### Design

Add a `disabled_at` check in `loginHandler` AFTER `GetUserByEmail` returns a valid user but BEFORE password verification. Return the same "invalid credentials" error as a nonexistent user, with the same timing normalization (run argon2 against dummy hash). This prevents information leakage about disabled accounts.

**CRITICAL:** The check must go AFTER user lookup but BEFORE `acquireArgon2` for password verification. To maintain timing normalization, the disabled-user path must still run argon2 against the dummy hash (same as the nonexistent-user path). This prevents an attacker from distinguishing "disabled" from "nonexistent" via response timing.

### Step 1: Write failing test

```go
func TestLogin_DisabledUser_Returns401(t *testing.T) {
    // Setup: create a user, then disable them (set disabled_at)
    // Attempt login with correct credentials
    // Assert: 401 "invalid credentials" (NOT 200 with cookies)
    // Assert: response body matches the nonexistent-user 401 response
    // (same error message, similar timing)
}
```

Also test that lockout still records the failure for disabled users (so brute-forcing disabled accounts still triggers lockout).

### Step 2: Run test to verify it fails (currently returns 200)

### Step 3: Implement

In `loginHandler`, after the user lookup succeeds (after line 231) and before the lockout check:

```go
// Reject disabled users with the same response as nonexistent users
// to prevent account status enumeration.
if user != nil && user.DisabledAt.Valid {
    if !srv.acquireArgon2() {
        return nil, huma.Error503ServiceUnavailable("server busy, please retry")
    }
    func() {
        defer srv.releaseArgon2()
        _, _ = auth.VerifyPassword(input.Body.Password, dummyPasswordHash)
    }()
    srv.lockout.RecordFailure(input.Body.Email)
    return nil, huma.Error401Unauthorized("invalid credentials")
}
```

**IMPORTANT:** This block must look identical to the `user == nil` path (lines 253-263) to prevent timing attacks. Same argon2 dummy verification, same lockout recording, same error message.

**Check `user.DisabledAt` type:** It's `sql.NullTime` on the generated model. Verify by reading `internal/store/generated/models.go` — the User struct. The check is `user.DisabledAt.Valid` (not `user.DisabledAt != nil`).

### Step 4: Run tests, lint, commit

---

## Task 4: force_password_reset Enforcement (S4)

**Agent:** B — Auth Hardening (sequential after Task 3)
**Bug:** `force_password_reset` flag is set by admin but never checked anywhere
**Testing pitfalls to review:** §13 ("Admin flag enforcement at all entry points")

**Files:**
- Modify: `internal/store/queries/auth.sql` (new query)
- Run: `sqlc generate` after SQL changes
- Modify: `internal/store/auth.go` (new store method)
- Modify: `internal/api/middleware_auth.go` (check flag, restrict endpoints)
- Modify: `internal/api/auth.go` (changePasswordHandler clears flag)
- Test: middleware test file, auth test file

### Design

**New query:** Replace `IsUserEnabled` with `GetUserAuthStatus` that returns both `disabled_at IS NULL AS enabled` and `force_password_reset` in a single query. This avoids an extra DB round trip.

**Middleware change:** `RequireAuthenticated` currently calls `IsUserEnabled`. Change it to call `GetUserAuthStatus`. If `!enabled`, reject with 401. If `force_password_reset` is true AND the request path is NOT one of the allowed paths, reject with 403 and a specific error body `{"title": "Password change required", "detail": "Your password must be changed before continuing", "type": "password_change_required"}`.

**Allowed paths during force_password_reset:** `/api/v1/auth/change-password`, `/api/v1/auth/me`, `/api/v1/auth/logout`. Use `strings.HasSuffix` on the URL path since huma may add the base path.

**changePasswordHandler change:** After successfully changing the password, clear the `force_password_reset` flag. Add a new sqlc query `ClearForcePasswordReset` and call it.

### Step 1: Write the sqlc queries

In `internal/store/queries/auth.sql`, add:

```sql
-- name: GetUserAuthStatus :one
-- Returns enabled status and force_password_reset flag. Used by auth middleware.
SELECT
  CAST(disabled_at IS NULL AS boolean) AS enabled,
  force_password_reset
FROM users WHERE id = $1;

-- name: ClearForcePasswordReset :exec
UPDATE users SET force_password_reset = false WHERE id = $1;
```

Run `sqlc generate` to regenerate Go code.

### Step 2: Write the store method

In `internal/store/auth.go`, add:

```go
// UserAuthStatus holds the auth-relevant flags for a user.
type UserAuthStatus struct {
    Enabled            bool
    ForcePasswordReset bool
}

// GetUserAuthStatus returns the enabled and force_password_reset status for a user.
func (s *Store) GetUserAuthStatus(ctx context.Context, userID uuid.UUID) (*UserAuthStatus, error) {
    var status UserAuthStatus
    err := s.withBypassTx(ctx, func(q *generated.Queries) error {
        row, err := q.GetUserAuthStatus(ctx, userID)
        if err != nil {
            return err
        }
        status.Enabled = row.Enabled
        status.ForcePasswordReset = row.ForcePasswordReset
        return nil
    })
    if err != nil {
        return nil, fmt.Errorf("get user auth status: %w", err)
    }
    return &status, nil
}

// ClearForcePasswordReset clears the force_password_reset flag for a user.
func (s *Store) ClearForcePasswordReset(ctx context.Context, userID uuid.UUID) error {
    return s.withBypassTx(ctx, func(q *generated.Queries) error {
        return q.ClearForcePasswordReset(ctx, userID)
    })
}
```

### Step 3: Write failing middleware test

```go
func TestRequireAuthenticated_ForcePasswordReset_BlocksNonAuthEndpoints(t *testing.T) {
    // Setup: user with force_password_reset=true, valid JWT
    // Request to a non-auth endpoint (e.g., /api/v1/orgs/...)
    // Assert: 403 with body containing "password_change_required"
}

func TestRequireAuthenticated_ForcePasswordReset_AllowsChangePassword(t *testing.T) {
    // Setup: user with force_password_reset=true, valid JWT
    // Request to /api/v1/auth/change-password
    // Assert: request passes through middleware (200 or handler-level response)
}

func TestRequireAuthenticated_ForcePasswordReset_AllowsMe(t *testing.T) {
    // Setup: user with force_password_reset=true, valid JWT
    // Request to /api/v1/auth/me
    // Assert: request passes through middleware
}
```

### Step 4: Implement middleware change

In `internal/api/middleware_auth.go`, in the JWT cookie auth path, replace:

```go
enabled, err := srv.store.IsUserEnabled(r.Context(), claims.UserID)
```

with:

```go
authStatus, err := srv.store.GetUserAuthStatus(r.Context(), claims.UserID)
```

Then check both flags:

```go
if err != nil {
    slog.ErrorContext(r.Context(), "auth: check user status", "user_id", claims.UserID, "error", err)
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
if !authStatus.Enabled {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
if authStatus.ForcePasswordReset {
    path := r.URL.Path
    allowed := strings.HasSuffix(path, "/auth/change-password") ||
        strings.HasSuffix(path, "/auth/me") ||
        strings.HasSuffix(path, "/auth/logout")
    if !allowed {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusForbidden)
        _ = json.NewEncoder(w).Encode(map[string]string{
            "title":  "Password change required",
            "detail": "Your password must be changed before continuing",
            "type":   "password_change_required",
        })
        return
    }
}
```

**IMPORTANT:** Also update the API key auth path (`tryAPIKeyAuth`). Currently it calls `IsUserEnabled` — change it to `GetUserAuthStatus` with the same logic. API key users with `force_password_reset=true` should probably be allowed through (they can't change their password via API key), but `!enabled` must still block. Think about this: an admin forces password reset on a user who has API keys. The API keys should probably still work until the user logs in and changes their password. **Decision: API key auth checks `enabled` only, not `force_password_reset`.** Document this in a comment.

### Step 5: Write failing test for changePasswordHandler clearing the flag

```go
func TestChangePassword_ClearsForcePasswordReset(t *testing.T) {
    // Setup: user with force_password_reset=true
    // Call change-password with valid current + new password
    // Assert: force_password_reset is now false in DB
    // Assert: subsequent request to a non-auth endpoint succeeds (not 403)
}
```

### Step 6: Implement changePasswordHandler change

In `internal/api/auth.go`, in `changePasswordHandler`, after the successful `UpdatePasswordHash` call (line 587), add:

```go
// Clear force_password_reset if it was set.
if err := srv.store.ClearForcePasswordReset(ctx, user.ID); err != nil {
    slog.ErrorContext(ctx, "change-password: clear force reset", "error", err)
    // Non-fatal — password is already changed.
}
```

### Step 7: Also update /auth/me to include force_password_reset

In `internal/api/auth.go`, the `meOutput` struct and `meHandler` should include the `force_password_reset` flag so the frontend knows to show the password change form:

Add to `meOutput.Body`:
```go
ForcePasswordReset bool `json:"force_password_reset"`
```

In `meHandler`, after getting the user:
```go
out.Body.ForcePasswordReset = user.ForcePasswordReset
```

Check the `generated.User` struct to confirm `ForcePasswordReset` is a `bool` field (not `sql.NullBool`). Read `internal/store/generated/models.go` to verify.

### Step 8: Run all tests, lint, commit

**Commit message:**
```
feat(auth): enforce force_password_reset via middleware

Adds GetUserAuthStatus query combining enabled + force_password_reset
checks. Middleware returns 403 for non-auth endpoints when the flag
is set. changePasswordHandler clears the flag on success. /auth/me
now includes the flag for frontend routing.
```

---

## Task 5: Doctor 503 Response Handling (S5)

**Agent:** C — Health Checks
**Bug:** `web/src/views/admin/AdminSystemView.vue:54,76` — `resp.ok` discards 503 responses
**Testing pitfalls to review:** §12 ("Non-2xx success responses")

**Files:**
- Modify: `web/src/views/admin/AdminSystemView.vue`
- Test: `web/src/views/admin/__tests__/AdminSystemView.test.ts` (create if it doesn't exist; check first)

### Step 1: Write failing test

Create a Vitest test that:
1. Mocks `fetch` to return a 503 response with valid JSON doctor results
2. Mounts `AdminSystemView`
3. Asserts that `doctor.value` is populated (not null)
4. Asserts the health check card renders with the unhealthy status

Also test the "Run" button path:
1. Mock `fetch` for the doctor endpoint to return 503 with JSON
2. Click the Run button
3. Assert `doctor.value` is updated

### Step 2: Run test to verify it fails

```bash
cd web && npm run test:unit -- --run AdminSystemView
```

### Step 3: Implement

In `AdminSystemView.vue`, change both `fetchAll()` and `runDoctor()`:

Replace:
```typescript
if (doctorResp.ok) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}
```

With:
```typescript
if (doctorResp.status === 200 || doctorResp.status === 503) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}
```

Apply this change in BOTH places (line ~54 in `fetchAll` and line ~76 in `runDoctor`).

### Step 4: Run tests, lint, commit

```bash
cd web && npm run test:unit -- --run AdminSystemView
cd web && npm run lint
```

---

## Task 6: DB-Backed Account Lockout (S6)

**Agent:** B — Auth Hardening (sequential after Task 4)
**Bug:** `internal/api/lockout.go` — in-memory only, DB columns disconnected
**Testing pitfalls to review:** §13 ("In-memory vs DB state consistency"), §2 ("Cleanup and eviction"), §1 ("Concurrency & TOCTOU")

This is the largest task. The in-memory `lockoutManager` must be replaced with DB-backed state using the existing `locked_at` and `failed_login_count` columns from migration 000036.

**Files:**
- Modify: `internal/store/queries/auth.sql` (new queries)
- Run: `sqlc generate`
- Modify: `internal/store/auth.go` (new store methods)
- Rewrite: `internal/api/lockout.go` (DB-backed implementation)
- Modify: `internal/api/auth.go` (use new lockout interface)
- Modify: `internal/api/admin_users.go` (admin unlock uses same mechanism)
- Test: lockout test file, auth test file

### Design

**New sqlc queries:**

```sql
-- name: RecordLoginFailure :one
-- Atomically increments failed_login_count and sets locked_at if threshold reached.
UPDATE users
SET failed_login_count = failed_login_count + 1,
    locked_at = CASE
        WHEN failed_login_count + 1 >= @threshold::int THEN COALESCE(locked_at, now())
        ELSE locked_at
    END
WHERE id = (SELECT id FROM users WHERE email = @email)
RETURNING failed_login_count, locked_at;

-- name: RecordLoginSuccess :exec
-- Resets lockout state after a successful login.
UPDATE users SET failed_login_count = 0, locked_at = NULL WHERE email = @email;

-- name: GetLoginLockoutState :one
-- Returns lockout state for a user by email.
SELECT failed_login_count, locked_at FROM users WHERE email = @email;
```

**IMPORTANT:** These queries use `email` not `user_id` because the lockout check happens before we know if the user exists. For nonexistent users, the query returns `sql.ErrNoRows` — treat this as "not locked" (the timing normalization already handles nonexistent users).

**New store methods:**

```go
type LoginLockoutState struct {
    FailedCount int32
    LockedAt    *time.Time
}

func (s *Store) RecordLoginFailure(ctx context.Context, email string, threshold int) (*LoginLockoutState, error)
func (s *Store) RecordLoginSuccess(ctx context.Context, email string) error
func (s *Store) GetLoginLockoutState(ctx context.Context, email string) (*LoginLockoutState, error)
```

**Rewrite lockout.go:**

Replace the in-memory `lockoutManager` with a `dbLockoutManager` that wraps the store methods. Keep the same interface methods (`Check`, `RecordFailure`, `RecordSuccess`) so the loginHandler changes are minimal.

```go
type lockoutManager struct {
    store     lockoutStore
    threshold int
    duration  time.Duration
}

type lockoutStore interface {
    RecordLoginFailure(ctx context.Context, email string, threshold int) (*store.LoginLockoutState, error)
    RecordLoginSuccess(ctx context.Context, email string) error
    GetLoginLockoutState(ctx context.Context, email string) (*store.LoginLockoutState, error)
}
```

**CRITICAL design detail:** `Check` now needs a `context.Context` parameter (for DB access). The call site in `loginHandler` must be updated. Similarly, `RecordFailure` and `RecordSuccess` need context.

The `Check` method:
1. Calls `GetLoginLockoutState(ctx, email)`
2. If `sql.ErrNoRows`, return `allowed=true` (user doesn't exist — timing normalization handles this)
3. If `locked_at` is non-nil and `time.Since(locked_at) < duration`, return `allowed=false, retryAfter`
4. If `locked_at` is non-nil but expired, call `RecordLoginSuccess` to reset (auto-unlock on expiry), return `allowed=true`

The `RecordFailure` method:
1. Calls `RecordLoginFailure(ctx, email, threshold)`
2. For nonexistent users (`sql.ErrNoRows`), this is a no-op (can't lock a nonexistent account)

**Admin unlock compatibility:** The existing `AdminUnlockUser` query (`UPDATE users SET locked_at = NULL, failed_login_count = 0`) now correctly resets the actual enforcement state. No changes needed to admin handlers.

**Remove from lockout.go:**
- The `map[string]*loginAttempt` in-memory state
- The `cleanupLoop` goroutine
- The `done` channel
- The `evictStale` method
- The `Len()` test helper
- The `Stop()` method

**Keep:** The `lockoutManager` struct name and its method signatures (updated to accept `ctx`).

### Step 1: Write sqlc queries and generate

### Step 2: Write store methods

### Step 3: Write failing tests for DB-backed lockout

Test cases:
1. `TestDBLockout_AllowsFirstAttempt` — no prior failures, Check returns allowed
2. `TestDBLockout_LocksAfterThreshold` — N failures, Check returns locked with retryAfter
3. `TestDBLockout_AutoUnlocksAfterDuration` — locked, wait for duration, Check returns allowed
4. `TestDBLockout_SuccessResetsCounter` — some failures, then success, then Check returns allowed
5. `TestDBLockout_NonexistentUserAllowed` — unknown email, Check returns allowed (no panic/error)
6. `TestDBLockout_AdminUnlockWorks` — locked user, admin calls AdminUnlockUser, Check returns allowed
7. `TestDBLockout_CaseInsensitiveEmail` — failures for `Admin@Example.com` count toward `admin@example.com` (§2 from testing-pitfalls)

**IMPORTANT for test 7:** The sqlc queries use `WHERE email = @email`. Emails in the DB are stored lowercase (enforced at registration). The lockout manager should normalize email to lowercase before querying. This matches the existing in-memory lockout which does `email = strings.ToLower(email)`.

### Step 4: Implement lockout.go rewrite

### Step 5: Update loginHandler

Change the method signatures in `loginHandler`:
- `srv.lockout.Check(input.Body.Email)` → `srv.lockout.Check(ctx, input.Body.Email)`
- `srv.lockout.RecordFailure(input.Body.Email)` → `srv.lockout.RecordFailure(ctx, input.Body.Email)`
- `srv.lockout.RecordSuccess(input.Body.Email)` → `srv.lockout.RecordSuccess(ctx, input.Body.Email)`

Update the `newLockoutManager` call in server initialization (find it in `server.go` or wherever the server is constructed).

### Step 6: Update server initialization

The `lockoutManager` no longer needs `now func() time.Time` (no in-memory clock). It needs the store. Update the server struct and constructor.

Remove the `srv.lockout.Stop()` call from server shutdown (no background goroutine to stop).

### Step 7: Update existing lockout tests

The existing tests in `internal/api/lockout_test.go` use the in-memory implementation with injected clocks. They need to be rewritten for the DB-backed version. The tests should use `testutil.SetupTestDB` (or whatever the test DB helper is — read `internal/testutil/postgres.go` first).

**If integration tests against a real DB are not practical** (e.g., the existing lockout tests are pure unit tests), create a mock `lockoutStore` interface for unit testing the lockout logic, PLUS integration tests that verify the actual SQL queries work.

### Step 8: Run all tests, lint, commit

```
feat(auth): replace in-memory lockout with DB-backed implementation

The lockoutManager now uses the existing locked_at and failed_login_count
DB columns. This fixes: lockout state lost on restart, per-instance state
in multi-instance deployments, and admin unlock clearing columns the login
flow never wrote.
```

---

## Task 7: Atomic Org PATCH + Consistent Response Shapes (M1 + M3)

**Agent:** D — Admin Orgs
**Bug M1:** `internal/api/admin_orgs.go:89-168` — tier and suspend in separate transactions
**Bug M3:** List returns `AdminOrgRow` (with `member_count`/`last_activity_at`), PATCH returns `adminOrgResponse` (without them)
**Testing pitfalls to review:** §7 ("Transaction helper compliance"), §3 ("Partial failure in multi-step flows")

**Files:**
- Modify: `internal/store/admin_org.go` (new atomic method)
- Modify: `internal/api/admin_orgs.go` (use atomic method + consistent response)
- Test: existing admin org test files

### Design

**M1 fix:** Create a single store method `AdminPatchOrg` that accepts both `tier *string` and `suspend *bool` and applies them in one `withBypassRawTx` transaction. The handler calls this once instead of separate `AdminUpdateOrgTier` + `AdminSuspendOrg`.

**M3 fix:** The list handler currently does `writeList(w, orgs, nextCursor)` which serializes `AdminOrgRow` directly. The PATCH handler maps through `toAdminOrgResponse` which drops `member_count` and `last_activity_at`. Fix: add `member_count` and `last_activity_at` to `adminOrgResponse` and use `toAdminOrgResponse` in both handlers. The PATCH re-fetch query should join to get member_count and last_activity_at (use the same query as the list).

**Alternative simpler approach for M3:** Have the list handler also use `toAdminOrgResponse` mapping. Add `MemberCount` and `LastActivityAt` fields to `adminOrgResponse`. This way both endpoints return the same shape.

### Step 1: Write failing test for atomicity

```go
func TestAdminPatchOrg_AtomicTierAndSuspend(t *testing.T) {
    // Create an org
    // PATCH with both tier="pro" and suspend=true
    // Verify both changes applied
    // Verify response includes both fields updated
}
```

### Step 2: Write failing test for consistent response shape

```go
func TestAdminListOrgs_ResponseShape_MatchesPatch(t *testing.T) {
    // Create an org
    // GET /admin/orgs — capture response fields
    // PATCH /admin/orgs/{id} — capture response fields
    // Assert both responses have the same set of JSON keys
}
```

### Step 3: Implement `AdminPatchOrg` in store

In `internal/store/admin_org.go`:

```go
// AdminPatchOrgParams holds the optional fields for an org PATCH.
type AdminPatchOrgParams struct {
    Tier    *string
    Suspend *bool
}

// AdminPatchOrg atomically applies tier and/or suspend changes to an org.
func (s *Store) AdminPatchOrg(ctx context.Context, orgID uuid.UUID, params AdminPatchOrgParams) (*AdminOrgRow, error) {
    var result AdminOrgRow
    err := s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
        if params.Tier != nil {
            _, err := tx.ExecContext(ctx,
                "UPDATE organizations SET tier = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL",
                *params.Tier, orgID)
            if err != nil {
                return fmt.Errorf("update tier: %w", err)
            }
        }
        if params.Suspend != nil {
            if *params.Suspend {
                _, err := tx.ExecContext(ctx,
                    "UPDATE organizations SET suspended_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL AND suspended_at IS NULL",
                    orgID)
                if err != nil {
                    return fmt.Errorf("suspend org: %w", err)
                }
            } else {
                _, err := tx.ExecContext(ctx,
                    "UPDATE organizations SET suspended_at = NULL, updated_at = now() WHERE id = $1 AND deleted_at IS NULL AND suspended_at IS NOT NULL",
                    orgID)
                if err != nil {
                    return fmt.Errorf("unsuspend org: %w", err)
                }
            }
        }
        // Re-fetch within the same transaction with member_count + last_activity_at
        row := tx.QueryRowContext(ctx, `
            SELECT o.id, o.name, o.tier, COUNT(om.user_id), o.created_at, o.suspended_at, MAX(u.last_login_at)
            FROM organizations o
            LEFT JOIN org_members om ON om.org_id = o.id
            LEFT JOIN users u ON u.id = om.user_id
            WHERE o.id = $1
            GROUP BY o.id`, orgID)
        var suspendedAt sql.NullTime
        var lastActivityAt sql.NullTime
        err := row.Scan(&result.ID, &result.Name, &result.Tier, &result.MemberCount,
            &result.CreatedAt, &suspendedAt, &lastActivityAt)
        if err != nil {
            return fmt.Errorf("re-fetch org: %w", err)
        }
        result.SuspendedAt = fromNullTime(suspendedAt)
        result.LastActivityAt = fromNullTime(lastActivityAt)
        return nil
    })
    return &result, err
}
```

### Step 4: Update handler to use new method and consistent response

In `internal/api/admin_orgs.go`:
1. Update `adminOrgResponse` to include `MemberCount` and `LastActivityAt`
2. Update `toAdminOrgResponse` to accept `AdminOrgRow` (not `*generated.Organization`)
3. Update `adminPatchOrgHandler` to call `AdminPatchOrg` once
4. Update `adminListOrgsHandler` to map through the updated `toAdminOrgResponse`

### Step 5: Run tests, lint, commit

---

## Task 8: readyz + Doctor Dirty Flag Check (M2)

**Agent:** C — Health Checks
**Bug:** `internal/api/readyz.go:46-48` and `internal/doctor/checks.go:63-65` — don't check `dirty` column
**Testing pitfalls to review:** §5 ("Schema version drift")

**Files:**
- Modify: `internal/api/readyz.go`
- Modify: `internal/doctor/checks.go`
- Test: `internal/api/readyz_test.go`, `internal/doctor/doctor_test.go`

### Step 1: Write failing tests

For readyz:
```go
func TestReadyz_DirtyMigration_Returns503(t *testing.T) {
    // Setup: INSERT INTO schema_migrations (version, dirty) VALUES (38, true)
    // Call /readyz
    // Assert: 503 with migration status "dirty"
}
```

For doctor:
```go
func TestMigrationCheck_Dirty_ReturnsFail(t *testing.T) {
    // Setup: INSERT INTO schema_migrations (version, dirty) VALUES (38, true)
    // Run MigrationCheck
    // Assert: status is StatusFail with message mentioning "dirty"
}
```

### Step 2: Run tests to verify they fail

### Step 3: Implement

In `internal/api/readyz.go`, change the migration check query:

```go
var migDirty bool
err := db.QueryRow(r.Context(),
    "SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1",
).Scan(&migVersion, &migDirty)
```

Then add a dirty check:
```go
if err != nil {
    // ... existing error handling
} else if migDirty {
    migStatus = "dirty"
    ready = false
} else if migVersion != expectedSchemaVersion {
    // ... existing behind check
}
```

Add `"dirty"` to the response `migrations` object:
```go
"migrations": map[string]any{
    "status":  migStatus,
    "version": migVersion,
    "dirty":   migDirty,
},
```

In `internal/doctor/checks.go`, same pattern:

```go
var version int
var dirty bool
err := c.DB.QueryRow(ctx,
    "SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1",
).Scan(&version, &dirty)
```

```go
if dirty {
    return StatusFail, fmt.Sprintf("schema version %d is dirty (migration failed mid-apply)", version), nil
}
```

### Step 4: Run tests, lint, commit

---

## Task 9: Generic Adapter Streaming Parse (M4)

**Agent:** E — Generic Adapter
**Bug:** `internal/feed/generic/adapter.go:126` — reads entire response (up to 50MB) into memory
**Testing pitfalls to review:** §9 ("Feed Data Quality"), §2 ("Stream error recovery")

**Files:**
- Modify: `internal/feed/generic/adapter.go`
- Test: `internal/feed/generic/adapter_test.go`

### Design

The current code does `io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))` then uses `gjson.GetBytes(body, root)` to find the array and `gjson.ForEach` to iterate. The `nextPage` function also needs the full `body` for cursor-path extraction.

**Approach:** Use `json.Decoder` to stream to the root array, then decode each element as `json.RawMessage` and use `gjson` per-element. This eliminates holding the entire response in memory.

**Complication:** The root path can be nested (e.g., `"data.items"`), and `nextPage` for cursor-type pagination needs to read a sibling field (e.g., `"data.next_cursor"`). With streaming, you can't go back to read siblings after passing them.

**Solution:** Two-phase approach:
1. **Simple root paths** (no dots — single level like `"vulnerabilities"`): use streaming. Read the cursor metadata from a sibling key before entering the array. This handles the majority of real-world APIs.
2. **Complex root paths** (dots — nested like `"data.items"`): fall back to buffered read. These are rare and typically small payloads from vendor-specific APIs.

**Implementation:**

Add `fetchJSONStream` method for simple roots:

```go
func (a *Adapter) fetchJSONStream(ctx context.Context, resp *http.Response, cur *cursor) (*feed.FetchResult, error) {
    dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize))

    var patches []feed.CanonicalPatch
    var rawCount int
    var nextCursorValue string // for cursor-type pagination

    // Navigate the top-level object, looking for the root key and optional cursor key.
    if _, err := dec.Token(); err != nil { // opening {
        return nil, fmt.Errorf("generic %s: expected object start: %w", a.cfg.Name, err)
    }

    for dec.More() {
        tok, err := dec.Token()
        if err != nil {
            return nil, fmt.Errorf("generic %s: read key: %w", a.cfg.Name, err)
        }
        key, ok := tok.(string)
        if !ok {
            continue
        }

        if key == a.cfg.Mapping.Root {
            // This is the array we want to stream
            if _, err := dec.Token(); err != nil { // opening [
                return nil, fmt.Errorf("generic %s: expected array start: %w", a.cfg.Name, err)
            }
            for dec.More() {
                var raw json.RawMessage
                if err := dec.Decode(&raw); err != nil {
                    return nil, fmt.Errorf("generic %s: decode element: %w", a.cfg.Name, err)
                }
                rawCount++
                record := gjson.ParseBytes(raw)
                p := a.mapRecord(record)
                if p.CVEID != "" {
                    patches = append(patches, p)
                }
            }
            if _, err := dec.Token(); err != nil { // closing ]
                return nil, fmt.Errorf("generic %s: expected array end: %w", a.cfg.Name, err)
            }
        } else if a.cfg.Pagination.Type == "cursor" && key == a.cfg.Pagination.CursorPath {
            // Read cursor value from sibling field
            var val string
            if err := dec.Decode(&val); err != nil {
                // Try as generic value
                var raw json.RawMessage
                if err2 := dec.Decode(&raw); err2 == nil {
                    val = gjson.ParseBytes(raw).String()
                }
            }
            nextCursorValue = val
        } else {
            // Skip this value
            var discard json.RawMessage
            if err := dec.Decode(&discard); err != nil {
                return nil, fmt.Errorf("generic %s: skip value for key %q: %w", a.cfg.Name, key, err)
            }
        }
    }

    // Build pagination result
    lastPage, nextCur := a.nextPageFromStream(resp.Header, cur, rawCount, nextCursorValue)
    nextCurJSON, _ := json.Marshal(nextCur)
    return &feed.FetchResult{
        Patches:    patches,
        SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
        NextCursor: nextCurJSON,
        LastPage:   lastPage,
    }, nil
}
```

**Dispatcher in `fetchJSON`:**

```go
func (a *Adapter) fetchJSON(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
    // ... existing request building, auth, response validation ...

    // Stream for simple (single-level) root paths; buffer for nested paths.
    if !strings.Contains(a.cfg.Mapping.Root, ".") {
        return a.fetchJSONStream(ctx, resp, &cur)
    }
    return a.fetchJSONBuffered(ctx, resp, &cur)
}
```

Rename the existing body-reading logic to `fetchJSONBuffered`.

**`nextPageFromStream`:** Extracts pagination from headers and the cursor value read during streaming (for cursor-type). For offset and link-header pagination, the existing `nextPage` logic applies (link-header uses `resp.Header`, offset uses `rawCount`). Only cursor-type pagination needs the `nextCursorValue` from the stream.

### Step 1: Write failing test for streaming path

```go
func TestAdapter_FetchJSON_StreamingSimpleRoot(t *testing.T) {
    // Create a large-ish test server response with a simple root path
    // e.g., {"vulnerabilities": [{...}, {...}, ...]}
    // Verify all records are parsed correctly
    // Verify memory usage is bounded (can approximate by checking that
    // the adapter doesn't call ReadAll — or just verify functional correctness)
}

func TestAdapter_FetchJSON_BufferedNestedRoot(t *testing.T) {
    // Test server with nested root: {"data": {"items": [{...}]}}
    // Verify it falls back to buffered path and still works
}

func TestAdapter_FetchJSON_StreamingWithCursorPagination(t *testing.T) {
    // Test server: {"next_cursor": "abc123", "results": [{...}]}
    // Verify cursor is extracted from sibling field during streaming
}
```

### Step 2: Implement as described above

### Step 3: Run tests including all existing generic adapter tests to verify no regressions

```bash
go test ./internal/feed/generic/ -v -count=1
```

### Step 4: Lint and commit

---

## Task 10: Delivery Bulk Retry Limit Cleanup (M5)

**Agent:** F — Small Fixes
**Bug:** `internal/api/admin_deliveries.go:114-134` — dual limit sources with different ranges
**Testing pitfalls to review:** §4 ("Validation Symmetry")

**Files:**
- Modify: `internal/api/admin_deliveries.go`
- Test: existing delivery test file

### Step 1: Write failing test

```go
func TestBulkRetryDeliveries_IgnoresBodyLimit(t *testing.T) {
    // POST /admin/deliveries/retry-failed?limit=50
    // with body {"limit": 999}
    // Assert: limit used is 50 (query param wins, body ignored)
}
```

### Step 2: Implement

Remove the JSON body parsing from `adminBulkRetryDeliveriesHandler`. The limit should come from the query param only:

Delete lines 119-135 (the `if r.ContentLength > 0` block). The handler becomes simply:

```go
func (srv *Server) adminBulkRetryDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
    limit, ok := parseLimitParam(w, r, 100, 1000)
    if !ok {
        return
    }

    n, err := srv.store.AdminBulkRetryFailed(r.Context(), limit)
    // ... rest unchanged
}
```

Note: Keep the max at 1000 for the query param (change from the current `parseLimitParam(w, r, 100, 1000)` — this is already correct). The JSON body was the only path that allowed values above the query param's range, which was the confusing part.

### Step 3: Run tests, lint, commit

---

## Task 11: validate-feeds --dry-run Error (M8)

**Agent:** F — Small Fixes
**Bug:** `cmd/cvert-ops/validate.go:49-51` — `--dry-run` logs "not yet implemented" but exits 0
**Testing pitfalls to review:** §3 ("Error swallowing")

**Files:**
- Modify: `cmd/cvert-ops/validate.go`
- Test: `cmd/cvert-ops/validate_test.go`

### Step 1: Write failing test

```go
func TestValidateFeeds_DryRunReturnsError(t *testing.T) {
    // Setup: valid feed configs in a temp dir
    // Call runValidateFeeds(dir, true)
    // Assert: returns an error (not nil)
    // Assert: error message mentions "not implemented"
}
```

### Step 2: Implement

Change the `dryRun` block to return an error:

```go
if dryRun {
    return fmt.Errorf("--dry-run is not yet implemented; omit the flag to validate config syntax only")
}
```

This goes AFTER the config validation passes (so the user still gets syntax validation), but BEFORE the "OK" message. The user gets: configs are valid, but connectivity testing isn't available yet.

### Step 3: Run tests, lint, commit

---

## Verification Checklist (run after ALL tasks complete)

```bash
# Full test suite
go test ./... -count=1

# Frontend tests
cd web && npm run test:unit

# Frontend lint
cd web && npm run lint

# Go lint
golangci-lint run

# Type check frontend
cd web && npm run type-check
```

## Post-Implementation

After all agents complete:
1. Run the full verification checklist above
2. Review all changes with `git diff dev`
3. Update `dev/implementation-log.md` with a summary of what was fixed
4. Consider running the bug hunter trio again on the changed files as a regression check
