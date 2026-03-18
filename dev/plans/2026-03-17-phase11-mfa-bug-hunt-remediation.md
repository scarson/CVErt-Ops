# Phase 11 MFA Bug Hunt Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 12 confirmed bugs and 2 design decisions from the Phase 11 MFA bug hunt, covering a critical MFA bypass, stale token versioning, missing token validation, non-atomic operations, and API contract deviations.

**Architecture:** All fixes are in the Go backend (no frontend changes). The MFA system uses JWT-based restricted sessions ("pending tokens") to gate multi-step authentication flows. Fixes touch the API handler layer (`internal/api/`), store layer (`internal/store/`), JWT layer (`internal/auth/`), and SQL queries. The password reset MFA bypass (B1) is the highest priority — it allows authentication without MFA via the forgot-password flow.

**Tech Stack:** Go 1.26, PostgreSQL 15+, `golang-jwt/jwt/v5`, `pquerna/otp`, huma/chi (HTTP), sqlc (queries), `internal/crypto` (AES-256-GCM).

**Source:** `dev/bug-hunts/2026-03-17-phase11-mfa-consolidated.md`

---

## Mandatory Agent Instructions

**EVERY agent executing tasks from this plan MUST follow these instructions exactly.**

### Before Starting Any Work

1. Read the `superpowers:test-driven-development` skill (`Skill` tool) and follow it for ALL implementation.
2. Read `dev/testing-pitfalls.md` in full. Keep its checklist in mind for every test you write.
3. Read `dev/implementation-pitfalls.md` §2.17 (transaction helper selection). Directly relevant.
4. Read the design doc: `dev/plans/2026-03-16-phase11-mfa-totp-email-otp-design.md` — the authoritative specification for all MFA behavior.

### After Every Logical Group of Tasks

You MUST carefully review the batch of work from multiple perspectives and revise/refine as appropriate. Repeat this review loop (you must do a minimum of three review rounds; if you still find substantive issues in the third review, keep going with additional rounds until there are no findings) until you're confident there aren't any more issues. Then update your private journal and continue onto the next tasks.

**Mandatory QA check:** Before completing each batch, review your tests against `dev/testing-pitfalls.md`. Specifically check:
- §1 (Concurrency & TOCTOU) — TOTP replay, recovery code consumption
- §3 (Error Path Differentiation) — anti-enumeration on MFA verify, error response format
- §7 (Transaction & Store) — correct transaction helper usage in every store method
- §11 (Security Enforcement) — RBAC on admin endpoints, constant-time comparisons, token_version validation

### After Normal Final Verification Steps

You MUST carefully review the work across ALL batches from multiple perspectives and revise/refine as appropriate. Repeat this review loop (you must do a minimum of three review rounds; if you still find substantive issues in the third review, keep going with additional rounds until there are no findings) until you're confident there aren't any more issues, then proceed with /finishing-a-development-branch

---

## Task Grouping Strategy

Tasks are grouped by file-conflict risk. Tasks within a group may touch the same files and MUST be executed sequentially. Groups that touch disjoint files CAN be parallelized.

- **Group A** (Tasks 1-4): `internal/api/auth.go`, `internal/api/auth_mfa.go` — pending token and enrollment flow fixes
- **Group B** (Task 5): `internal/api/auth_password_reset.go` — MFA bypass fix (independent file)
- **Group C** (Task 6): `internal/store/org.go` — transaction helper fix (independent file)
- **Group D** (Task 7): `internal/api/admin_mfa.go`, `internal/store/mfa.go` — admin reset atomicity
- **Group E** (Tasks 8-9): `internal/api/auth_mfa.go`, `internal/store/mfa.go`, `internal/store/queries/mfa.sql` — TOTP replay + email OTP exhaustion (overlaps Group A on auth_mfa.go — must run AFTER Group A)
- **Group F** (Task 10): `internal/auth/jwt.go` — dual-key rotation (independent file)
- **Group G** (Tasks 11-12): `internal/api/auth_mfa.go` — minor fixes (overlaps Groups A/E — must run AFTER both)

**Recommended execution order:** B → C → A → D → F → E → G (or parallel where noted)

---

## Group B: Password Reset MFA Bypass (Critical)

### Task 1: Add MFA gating to password reset completion (B1)

**Bug:** `resetPasswordHandler` changes the password and returns 200 with no MFA check. The design doc (§ Password Reset Interaction) explicitly states MFA status must be checked after forgot-password completion. An attacker with email access bypasses TOTP entirely.

**Files:**
- Modify: `internal/api/auth_password_reset.go` — add MFA gating after password change
- Modify: `internal/api/auth_password_reset_test.go` — add MFA gating tests
- Reference: `internal/api/auth.go:398-464` — existing login MFA gating logic to mirror

**BEFORE starting work:**
1. Read the skill at `superpowers:test-driven-development` (or invoke /test-driven-development)
2. Read `dev/testing-pitfalls.md`
3. Read `internal/api/auth.go:395-490` — this is the login handler's MFA gating logic. The password reset handler must implement the same checks.
4. Read the design doc § "Password Reset Interaction" for the exact specification.

**Current behavior:**
```go
// internal/api/auth_password_reset.go:220-236
if err := srv.store.UpdatePasswordHash(ctx, tok.UserID, newHash, 1); err != nil { ... }
// ... emit event ...
return &resetPasswordOutput{}, nil  // ← No MFA check, no session tokens
```

**Desired behavior (from design doc):**
After password change succeeds:
1. Check `UserHasMFACredentials(ctx, tok.UserID)` — if true, issue pending token with `["mfa_challenge"]` and the user's enrolled method list
2. If no MFA enrolled, check `UserMFARequired()` — if mandated, issue pending token with `["mfa_enrollment_required"]`
3. If neither → return bare 200 (current behavior — no session tokens, client must log in)

**Step 1: Write failing tests**

Add tests to `internal/api/auth_password_reset_test.go`:

1. `TestResetPassword_WithMFAEnrolled_ReturnsPendingToken` — register user, enroll TOTP, request password reset, complete reset → response must include `pending: ["mfa_challenge"]`, `methods: ["totp"]`, and a `mfa_pending_token` Set-Cookie header. Must NOT include access/refresh tokens.

2. `TestResetPassword_NoMFA_Mandated_ReturnsPendingToken` — register user, set site-wide MFA requirement, request password reset, complete reset → response must include `pending: ["mfa_enrollment_required"]` and a `mfa_pending_token` Set-Cookie header.

3. `TestResetPassword_NoMFA_NotRequired_ReturnsEmpty` — register user (no MFA, not mandated), complete reset → response is bare 200 with no pending token (current behavior preserved).

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run "TestResetPassword_(WithMFA|NoMFA)" -v -count=1`
Expected: FAIL — current handler returns no pending/methods fields and no pending token cookie.

**Step 3: Implement the fix**

Modify `resetPasswordHandler` in `internal/api/auth_password_reset.go`:
- Change `resetPasswordOutput` struct to include `SetCookie []string`, `Body.Pending []string`, and `Body.Methods []string` (matching `loginOutput` pattern)
- After `UpdatePasswordHash` succeeds, add the same MFA gating logic as `loginHandler` (auth.go:398-464):
  - Call `srv.store.UserHasMFACredentials(ctx, tok.UserID)` — if true, build `pending = ["mfa_challenge"]` and get enrolled methods
  - Else call `srv.store.UserMFARequired(ctx, tok.UserID, isSiteAdmin, mfaCfg)` — if true, `pending = ["mfa_enrollment_required"]`
  - If `len(pending) > 0`: re-read user via `GetUserByID` to get current `token_version` (it was just incremented), issue pending token, set cookies
  - If `len(pending) == 0`: return bare 200 (no session tokens — same as current)
- Do NOT issue full auth tokens from password reset even without MFA — the design doc treats password reset as a "prove identity" step, not a "start session" step

**Important:** The `token_version` used for the pending token MUST be the post-increment value. Call `GetUserByID` after `UpdatePasswordHash` to get the current version. Do NOT reuse any pre-increment value.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -run "TestResetPassword" -v -count=1`
Expected: All password reset tests PASS.

**Step 5: Run full test suite**

Run: `go test ./internal/api/... -count=1`
Expected: PASS — no regressions.

**Step 6: Commit**

```bash
git add internal/api/auth_password_reset.go internal/api/auth_password_reset_test.go
git commit -m "fix(security): add MFA gating to password reset completion (B1)

The forgot-password flow changed the password and returned without
checking MFA status, allowing an attacker with email access to bypass
TOTP entirely. Now checks MFA enrollment and mandate status after
password change, issuing a pending token when MFA is required.

Mirrors the login handler's MFA gating logic per the Phase 11 design
doc § Password Reset Interaction."
```

**BEFORE marking this task complete:**
1. Review tests against `dev/testing-pitfalls.md` §3 (anti-enumeration) and §11 (security enforcement)
2. Verify test coverage: is the MFA-enrolled path tested? The mandated-but-not-enrolled path? The no-MFA path?
3. Run `go test ./internal/api/... -count=1` and confirm green

---

## Group C: Transaction Helper Compliance

### Task 2: Wrap UpdateOrg and UpdateOrgMFASettings in transaction helpers (B6)

**Bug:** `UpdateOrg` (line 28) and `UpdateOrgMFASettings` (line 40) in `internal/store/org.go` use `s.q` directly, bypassing transaction helpers. Every other org-mutation method in the file uses `withOrgTx` or `withBypassTx`. This means these queries run without statement timeout enforcement.

**Files:**
- Modify: `internal/store/org.go:28-54` — wrap both methods in `withBypassTx`
- Modify: `internal/store/mfa_test.go` or create test if needed — verify transaction helper usage
- Reference: `internal/store/org.go:58` (`CreateOrgWithOwner`) — canonical `withBypassTx` pattern

**BEFORE starting work:**
1. Read the skill at `superpowers:test-driven-development`
2. Read `dev/testing-pitfalls.md` §7 (Transaction & Store Conventions)
3. Read `dev/implementation-pitfalls.md` §2.17 (transaction helper selection)

**Step 1: Write failing test (if applicable)**

These methods already have indirect test coverage through integration tests. The fix is a mechanical refactor to use the correct pattern. Write a targeted test that verifies the methods work correctly after the refactor:

Add to the existing org store tests a test that calls `UpdateOrgMFASettings` and verifies the returned org has the correct MFA settings. If such a test already exists, skip this step.

**Step 2: Implement the fix**

Change `UpdateOrg`:
```go
func (s *Store) UpdateOrg(ctx context.Context, id uuid.UUID, name string) (*generated.Organization, error) {
	var result *generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.UpdateOrg(ctx, generated.UpdateOrgParams{ID: id, Name: name})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("update org: %w", err)
	}
	return result, nil
}
```

Change `UpdateOrgMFASettings` with the same pattern — wrap `s.q.UpdateOrgMFASettings` in `s.withBypassTx`. Use `withBypassTx` (not `withOrgTx`) because `organizations` table has no RLS and the caller is updating the org itself, not querying within org context.

**Step 3: Run tests**

Run: `go test ./internal/store/... -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1`
Expected: PASS — no regressions in handlers that call these methods.

**Step 4: Commit**

```bash
git add internal/store/org.go
git commit -m "fix(store): wrap UpdateOrg and UpdateOrgMFASettings in withBypassTx (B6)

Both methods used s.q directly, bypassing statement timeout enforcement.
Every other org-mutation method uses a transaction helper. Wrapped in
withBypassTx for consistency."
```

---

## Group A: Pending Token and Enrollment Flow Fixes

### Task 3: Fix stale token_version in pending token after password change (B2)

**Bug:** `changePasswordHandler` in restricted mode calls `UpdatePasswordHash` (which increments `token_version`) then reissues the pending token using the OLD `pendingClaims.TokenVersion`. The reissued token's `tv` claim doesn't match the DB.

**Files:**
- Modify: `internal/api/auth.go:897-913` — re-read user after password update
- Modify: `internal/api/auth_test.go` — add test for token_version freshness

**BEFORE starting work:**
1. Read the skill at `superpowers:test-driven-development`
2. Read `dev/testing-pitfalls.md` §11 ("Multi-step restricted session state consistency")
3. Read `internal/api/auth.go:897-925` — the full restricted session branch

**Step 1: Write failing test**

Add test `TestChangePassword_RestrictedSession_PendingTokenHasFreshTokenVersion`:
1. Register user, set `force_password_reset = true` and enroll a pending requirement so `pending = ["password_reset", "mfa_enrollment_required"]`
2. Login → get pending token
3. Call change-password with new password
4. Decode the reissued pending token from the response cookie
5. Assert the `tv` claim equals the user's current `token_version` in the DB (which is the original + 1)

**Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run "TestChangePassword_RestrictedSession_PendingTokenHasFreshTokenVersion" -v -count=1`
Expected: FAIL — the `tv` claim in the reissued token is the pre-increment value.

**Step 3: Implement the fix**

In `changePasswordHandler`, after the `UpdatePasswordHash` call and before reissuing the pending token (around line 900):

```go
// Re-read user to get the incremented token_version.
freshUser, ruErr := srv.store.GetUserByID(ctx, userID)
if ruErr != nil || freshUser == nil {
	slog.ErrorContext(ctx, "change-password: re-read user for tv", "error", ruErr)
	return nil, huma.Error500InternalServerError("internal error")
}
```

Then change line 904 from:
```go
token, ptErr := auth.IssuePendingToken(
	[]byte(srv.cfg.JWTSecret), userID, pendingClaims.TokenVersion,
	remaining, nil, srv.cfg.MFAPendingTokenTTL,
)
```
to:
```go
token, ptErr := auth.IssuePendingToken(
	[]byte(srv.cfg.JWTSecret), userID, int(freshUser.TokenVersion),
	remaining, nil, srv.cfg.MFAPendingTokenTTL,
)
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestChangePassword" -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1`
Expected: PASS — no regressions.

**Step 5: Commit**

```bash
git add internal/api/auth.go internal/api/auth_test.go
git commit -m "fix(auth): use fresh token_version in reissued pending token (B2)

changePasswordHandler used the pre-increment token_version when
reissuing the pending token after password change. Now re-reads
the user to get the post-increment version."
```

### Task 4: Enforce pending order in resolveEnrollmentUserID (B3)

**Bug:** `resolveEnrollmentUserID` checks if `"mfa_enrollment_required"` exists ANYWHERE in the pending array via a for loop, allowing users to skip earlier steps (e.g., `password_reset`).

**Files:**
- Modify: `internal/api/auth_mfa.go:1149-1173` — check `Pending[0]` not loop
- Modify: `internal/api/auth_mfa_test.go` — add order enforcement test

**BEFORE starting work:**
1. Read the skill at `superpowers:test-driven-development`
2. Read `internal/api/auth_mfa.go:1149-1173` — current implementation
3. Read `internal/api/auth.go:322` — `validatePendingToken` which correctly checks `Pending[0]`

**Step 1: Write failing test**

Add test `TestEnrollment_RejectsOutOfOrderPending`:
1. Create a pending token with `pending = ["password_reset", "mfa_enrollment_required"]` (password_reset first)
2. Attempt to call a TOTP enrollment endpoint with this token
3. Assert 401 — enrollment must not proceed when `mfa_enrollment_required` is not `Pending[0]`

Add test `TestEnrollment_AcceptsCorrectOrder`:
1. Create a pending token with `pending = ["mfa_enrollment_required"]` (only item)
2. Attempt to call TOTP enrollment setup
3. Assert success (200/201)

**Step 2: Run tests to verify the first fails**

Run: `go test ./internal/api/ -run "TestEnrollment_Rejects" -v -count=1`
Expected: FAIL — current code accepts out-of-order pending.

**Step 3: Implement the fix**

Change `resolveEnrollmentUserID` from:
```go
for _, p := range claims.Pending {
	if p == "mfa_enrollment_required" {
		return claims.UserID, nil
	}
}
```
to:
```go
if len(claims.Pending) > 0 && claims.Pending[0] == "mfa_enrollment_required" {
	return claims.UserID, nil
}
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestEnrollment_(Rejects|Accepts)" -v -count=1`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "fix(mfa): enforce pending step order in enrollment endpoints (B3)

resolveEnrollmentUserID searched the entire pending array for
mfa_enrollment_required, allowing users to skip earlier steps like
password_reset. Now checks Pending[0] only, matching the ordering
contract enforced by other handlers."
```

### Task 5: Add token_version validation to resolveEnrollmentUserID (B4)

**Bug:** `resolveEnrollmentUserID` accepts pending tokens without checking `token_version` against the DB. Admin actions that increment `token_version` don't invalidate active enrollment sessions.

**Files:**
- Modify: `internal/api/auth_mfa.go:1149-1173` — add user lookup + tv validation
- Modify: `internal/api/auth_mfa_test.go` — add tv validation test

**BEFORE starting work:**
1. Read `internal/api/auth_mfa.go:177-184` — the `mfaVerifyHandler` pattern for tv validation
2. This task modifies the same function as Task 4 — execute after Task 4

**Step 1: Write failing test**

Add test `TestEnrollment_RejectsStaleTokenVersion`:
1. Register user, set up a pending enrollment session
2. Increment user's `token_version` (simulating admin MFA reset)
3. Attempt enrollment with the now-stale pending token
4. Assert 401

**Step 2: Run test to verify it fails**

Expected: FAIL — current code skips tv validation.

**Step 3: Implement the fix**

After the `Pending[0]` check (from Task 4), add:
```go
if len(claims.Pending) > 0 && claims.Pending[0] == "mfa_enrollment_required" {
	// Validate token_version against DB.
	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return uuid.Nil, huma.Error401Unauthorized("authentication required")
	}
	if int(user.TokenVersion) != claims.TokenVersion {
		return uuid.Nil, huma.Error401Unauthorized("session invalidated — please log in again")
	}
	return claims.UserID, nil
}
```

Note: `resolveEnrollmentUserID` currently takes `(accessToken, pendingToken string)` but needs `context.Context` for the DB call. Update the signature to `(ctx context.Context, accessToken, pendingToken string)` and update all callers.

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestEnrollment" -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 5: Commit**

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "fix(mfa): validate token_version in enrollment endpoints (B4)

resolveEnrollmentUserID skipped token_version validation, unlike
mfaVerifyHandler. Admin actions that increment token_version now
correctly invalidate active enrollment sessions."
```

### Task 6: Issue full auth tokens on enrollment completion (B5)

**Bug:** `clearEnrollmentPending` only clears the pending token cookie when all items are cleared — it never issues access/refresh tokens. Users completing MFA enrollment as their sole pending step must re-login.

**Files:**
- Modify: `internal/api/auth_mfa.go:1216-1236` — refactor to accept context and issue tokens
- Modify: `internal/api/auth_mfa.go` — update callers (`mfaTOTPConfirmHandler`, `mfaEmailOTPConfirmHandler`)
- Modify: `internal/api/auth_mfa_test.go` or `auth_mfa_integration_test.go` — add completion token test

**BEFORE starting work:**
1. Read `internal/api/auth_mfa.go:1216-1236` — current `clearEnrollmentPending`
2. Read `internal/api/auth_mfa.go:267-295` — `mfaVerifyHandler`'s full-token issuance pattern (the model to follow)
3. Read `internal/api/auth.go:916-928` — `changePasswordHandler`'s full-token issuance pattern (another model)

**Step 1: Write failing test**

Add test `TestEnrollment_IssuesFullTokensOnCompletion`:
1. Register user, force MFA enrollment (no other pending items)
2. Login → get pending token with `["mfa_enrollment_required"]`
3. Complete TOTP enrollment (setup + confirm)
4. Assert response includes `access_token` and `refresh_token` Set-Cookie headers
5. Assert the pending token cookie is cleared

**Step 2: Run test to verify it fails**

Expected: FAIL — current code clears the pending cookie but doesn't issue auth tokens.

**Step 3: Implement the fix**

Change `clearEnrollmentPending` signature from:
```go
func (srv *Server) clearEnrollmentPending(pendingToken string) []string
```
to:
```go
func (srv *Server) clearEnrollmentPending(ctx context.Context, pendingToken string) ([]string, error)
```

When `remaining` is empty:
```go
if len(remaining) == 0 {
	// All pending items cleared — issue full auth tokens.
	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "mfa: enrollment complete, re-read user", "error", err)
		return nil, fmt.Errorf("re-read user: %w", err)
	}
	authCookies, tokErr := srv.issueFullAuthTokens(ctx, user)
	if tokErr != nil {
		return nil, tokErr
	}
	// Clear both enrollment and pending cookies, add auth cookies.
	cookies := append(authCookies, clearPendingTokenCookie(srv.cfg.CookieSecure))
	return cookies, nil
}
```

Update all callers to pass `ctx` and handle the error return.

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestEnrollment" -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 5: Commit**

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go internal/api/auth_mfa_integration_test.go
git commit -m "fix(mfa): issue full auth tokens on enrollment completion (B5)

clearEnrollmentPending only cleared the pending cookie when all items
were resolved, forcing users to re-login. Now issues access + refresh
tokens, matching mfaVerifyHandler's completion behavior."
```

**Review checkpoint — Group A complete:**
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives and revise/refine as appropriate. Repeat this review loop (you must do a minimum of three review rounds; if you still find substantive issues in the third review, keep going with additional rounds until there are no findings) until you're confident there aren't any more issues. Then update your private journal and continue onto the next tasks.

---

## Group D: Admin Reset Atomicity

### Task 7: Make admin MFA reset atomic and remove redundant delete (B7)

**Bug:** `adminResetMFAHandler` runs 5 sequential store operations in separate transactions. `DeleteRememberDeviceTokens` is redundant after `DeleteAllUserChallenges`. Partial failure leaves inconsistent state.

**Files:**
- Modify: `internal/store/mfa.go` — add `ResetUserMFA` atomic store method
- Modify: `internal/store/queries/mfa.sql` — no new SQL needed (reuse existing queries within transaction)
- Modify: `internal/api/admin_mfa.go:54-81` — replace 5 calls with single `ResetUserMFA`
- Modify: `internal/store/mfa_test.go` — add test for atomic reset
- Modify: `internal/api/admin_mfa_test.go` — verify behavior unchanged

**BEFORE starting work:**
1. Read the skill at `superpowers:test-driven-development`
2. Read `internal/store/mfa.go:206-246` — `VerifyRecoveryCode` as the model for multi-operation `withBypassTx`
3. Read `internal/api/admin_mfa.go:54-81` — current handler

**Step 1: Write failing test for new store method**

Add test `TestStore_ResetUserMFA` to `internal/store/mfa_test.go`:
1. Create user, enroll TOTP, generate recovery codes, create email OTP challenge, create remember-device token
2. Call `store.ResetUserMFA(ctx, userID)`
3. Assert: no credentials, no recovery codes, no challenges, token_version incremented by 1
4. Assert: the method returns no error

**Step 2: Run test to verify it fails**

Expected: FAIL — `ResetUserMFA` doesn't exist yet.

**Step 3: Implement the store method**

Add to `internal/store/mfa.go`:
```go
// ResetUserMFA atomically removes all MFA state for a user and increments
// token_version to invalidate all sessions. All operations run in a single
// transaction to prevent inconsistent intermediate states.
func (s *Store) ResetUserMFA(ctx context.Context, userID uuid.UUID) (int32, error) {
	var newVersion int32
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		if _, err := q.DeleteAllMFACredentials(ctx, userID); err != nil {
			return err
		}
		if _, err := q.DeleteAllRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		if _, err := q.DeleteAllUserChallenges(ctx, userID); err != nil {
			return err
		}
		var err error
		newVersion, err = q.IncrementTokenVersion(ctx, userID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("reset user mfa: %w", err)
	}
	return newVersion, nil
}
```

Note: No `DeleteRememberDeviceTokens` call — `DeleteAllUserChallenges` already deletes all challenge types including `remember_device`.

**Step 4: Run store test**

Run: `go test ./internal/store/ -run "TestStore_ResetUserMFA" -v -count=1`
Expected: PASS.

**Step 5: Update admin handler**

Replace the 5 sequential calls in `adminResetMFAHandler` with:
```go
if _, err := srv.store.ResetUserMFA(r.Context(), targetID); err != nil {
	slog.ErrorContext(r.Context(), "admin reset-mfa: reset", "error", err)
	writeProblem(w, http.StatusInternalServerError, "internal error")
	return
}
```

**Step 6: Run admin tests**

Run: `go test ./internal/api/ -run "TestAdmin.*MFA" -v -count=1`
Expected: PASS — behavior unchanged, just atomic now.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 7: Commit**

```bash
git add internal/store/mfa.go internal/store/mfa_test.go internal/api/admin_mfa.go internal/api/admin_mfa_test.go
git commit -m "fix(mfa): make admin MFA reset atomic, remove redundant delete (B7)

The admin reset handler ran 5 sequential store operations in separate
transactions. Consolidated into a single ResetUserMFA method that runs
all deletions + token_version increment in one transaction. Removed
redundant DeleteRememberDeviceTokens (already covered by
DeleteAllUserChallenges)."
```

**Review checkpoint — Group D complete.**

---

## Group F: Dual-Key JWT Rotation

### Task 8: Add dual-key rotation support to ParsePendingToken and ParseEnrollmentToken (D2)

**Bug/Design:** `ParsePendingToken` and `ParseEnrollmentToken` take a single secret, unlike `ParseAccessToken`/`ParseRefreshToken` which support dual-key rotation. During JWT secret rotation, any user mid-MFA-flow is locked out.

**Files:**
- Modify: `internal/auth/jwt.go` — add `previousSecret` parameter to both functions
- Modify: `internal/auth/jwt_test.go` — add dual-key rotation tests
- Modify: `internal/api/auth_mfa.go` — update callers to pass previous secret
- Modify: `internal/api/auth.go` — update callers to pass previous secret

**BEFORE starting work:**
1. Read `internal/auth/jwt.go:50-78` — `ParseAccessToken` dual-key pattern (the model)
2. Read all callers of `ParsePendingToken` and `ParseEnrollmentToken` via grep

**Step 1: Write failing tests**

Add to `internal/auth/jwt_test.go`:

`TestParsePendingToken_DualKey`: Issue token with old secret, parse with new secret as active + old secret as previous → should succeed.

`TestParseEnrollmentToken_DualKey`: Same pattern.

`TestParsePendingToken_DualKey_ExpiredStillFails`: Issue expired token with old secret, parse with dual key → should still fail (only signature errors trigger fallback, not expiry).

**Step 2: Run tests to verify they fail**

Expected: FAIL — current functions don't accept `previousSecret`.

**Step 3: Implement the fix**

Change `ParsePendingToken` signature from:
```go
func ParsePendingToken(tokenStr string, secret []byte) (*PendingClaims, error)
```
to:
```go
func ParsePendingToken(tokenStr string, activeSecret []byte, previousSecret []byte) (*PendingClaims, error)
```

Add the same dual-key fallback logic as `ParseAccessToken`:
```go
if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
	fallbackClaims := &PendingClaims{}
	_, err2 := jwt.ParseWithClaims(tokenStr, fallbackClaims, func(_ *jwt.Token) (any, error) {
		return previousSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err2 == nil {
		return fallbackClaims, nil
	}
	return nil, fmt.Errorf("parse pending token: %w", err2)
}
```

Do the same for `ParseEnrollmentToken`.

Update all callers:
- `validatePendingToken` in `auth_mfa.go` and `auth.go` — pass `jwtPreviousSecret(srv.cfg)` as second arg
- `resolveEnrollmentUserID` — pass previous secret
- `clearEnrollmentPending` — pass previous secret
- Any other callers found via grep

**Step 4: Run tests**

Run: `go test ./internal/auth/ -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 5: Commit**

```bash
git add internal/auth/jwt.go internal/auth/jwt_test.go internal/api/auth_mfa.go internal/api/auth.go
git commit -m "feat(auth): add dual-key rotation to pending and enrollment tokens (D2)

ParsePendingToken and ParseEnrollmentToken now accept a previousSecret
parameter for zero-downtime JWT secret rotation, matching the existing
pattern in ParseAccessToken and ParseRefreshToken."
```

---

## Group E: TOTP Replay Prevention + Email OTP Exhaustion

### Task 9: Fix TOTP replay prevention — account for skew and add FOR UPDATE lock (B9 + D3)

**Bug:** TOTP replay prevention stores `currentStep` as `lastUsedStep`, but with `Skew: 1` the library accepts codes from `currentStep ± 1`. A code valid for step N+1 can be replayed in the next 30-second window. Additionally, no `FOR UPDATE` lock prevents concurrent replay.

**Files:**
- Modify: `internal/store/queries/mfa.sql` — add `GetMFACredentialByUserAndMethodForUpdate` query
- Run: `sqlc generate` after SQL change
- Modify: `internal/store/mfa.go` — add `VerifyAndUpdateTOTPStep` atomic store method
- Modify: `internal/api/auth_mfa.go:362-406` — refactor `verifyTOTP` to use atomic store method
- Modify: `internal/api/auth_mfa_test.go` — add replay prevention tests

**BEFORE starting work:**
1. Read `internal/store/queries/mfa.sql` — existing queries
2. Read `internal/store/mfa.go:203-246` — `VerifyRecoveryCode` as the model for `FOR UPDATE` + atomic check+update
3. Read `internal/api/auth_mfa.go:362-406` — current `verifyTOTP`
4. **Security context:** Real-time phishing proxies (evilginx-style) capture and replay TOTP codes within seconds. The 30-second window is exploitable. The `FOR UPDATE` lock + storing `currentStep + skew` eliminates this.

**Step 1: Write failing tests**

Add tests to `internal/api/auth_mfa_test.go`:

`TestTOTP_ReplayPrevention_SkewWindow`:
1. Enroll TOTP for a user
2. Generate a valid code, verify it successfully
3. Immediately attempt to verify the same code again
4. Assert the second attempt returns false (replay blocked)
5. The key: set `lastUsedStep` to `currentStep + 1` (skew maximum) to prove the window is correctly blocked

`TestTOTP_ConcurrentReplay`:
1. Enroll TOTP for a user
2. Launch two goroutines that simultaneously attempt to verify the same valid code
3. Assert exactly one succeeds — the `FOR UPDATE` lock ensures serialization

**Step 2: Run tests to verify they fail**

Expected: At least one test should demonstrate the replay gap.

**Step 3: Add SQL query**

Add to `internal/store/queries/mfa.sql`:
```sql
-- name: GetMFACredentialByUserAndMethodForUpdate :one
SELECT * FROM mfa_credentials WHERE user_id = $1 AND method = $2 FOR UPDATE;
```

Run: `sqlc generate`

**Step 4: Add atomic store method**

Add to `internal/store/mfa.go`:
```go
// VerifyAndUpdateTOTPStep atomically checks and updates the TOTP last_used_step.
// Uses FOR UPDATE to prevent concurrent replay. Returns true if the step
// is fresh (not replayed). The maxStep parameter should be currentStep + skew
// to account for the TOTP validation window.
func (s *Store) VerifyAndUpdateTOTPStep(ctx context.Context, userID uuid.UUID, maxStep int64) (bool, error) {
	var ok bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		cred, err := q.GetMFACredentialByUserAndMethodForUpdate(ctx, generated.GetMFACredentialByUserAndMethodForUpdateParams{
			UserID: userID,
			Method: "totp",
		})
		if err != nil {
			return err
		}
		if cred.LastUsedStep.Valid && cred.LastUsedStep.Int64 >= maxStep {
			ok = false
			return nil
		}
		if err := q.UpdateMFACredentialLastUsed(ctx, generated.UpdateMFACredentialLastUsedParams{
			ID:           cred.ID,
			LastUsedStep: sql.NullInt64{Int64: maxStep, Valid: true},
		}); err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("verify totp step: %w", err)
	}
	return ok, nil
}
```

**Step 5: Refactor verifyTOTP**

In `internal/api/auth_mfa.go`, change `verifyTOTP` to:
1. Keep the existing credential fetch and TOTP validation (lines 363-392)
2. Replace the step check + update (lines 394-403) with a call to the new atomic store method:

```go
// Atomic replay prevention with FOR UPDATE lock.
// Store maxStep = currentStep + skew to block replays across the entire acceptance window.
maxStep := (now.Unix() / 30) + int64(totpValidateOpts.Skew)
fresh, stepErr := srv.store.VerifyAndUpdateTOTPStep(ctx, userID, maxStep)
if stepErr != nil {
	return false, fmt.Errorf("totp step check: %w", stepErr)
}
if !fresh {
	return false, nil // replay
}
return true, nil
```

Remove the old `UpdateMFACredentialLastUsed` call and the separate `GetMFACredentialByUserAndMethod` call. The credential for decryption still needs to be fetched outside the lock transaction (the encrypted secret is needed before the step check). Keep the existing `GetMFACredentialByUserAndMethod` for secret retrieval, then use `VerifyAndUpdateTOTPStep` for the atomic step check.

**Step 6: Run tests**

Run: `go test ./internal/api/ -run "TestTOTP" -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 7: Commit**

```bash
git add internal/store/queries/mfa.sql internal/store/generated/ internal/store/mfa.go internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "fix(mfa): TOTP replay prevention — FOR UPDATE lock + skew-aware step (B9+D3)

The replay check stored currentStep but TOTP validation with Skew:1
accepts currentStep±1, leaving a 30-second replay window exploitable
by real-time phishing proxies. Now stores currentStep+skew as the
maximum step and uses FOR UPDATE to serialize concurrent attempts."
```

### Task 10: Emit EventMFAChallengeExhausted on email OTP max attempts (B8)

**Bug:** `VerifyEmailOTPChallenge` returns `(bool, error)` — when max attempts are reached, it deletes the challenge and returns `false, nil`, indistinguishable from wrong-code. The `EventMFAChallengeExhausted` constant is dead code.

**Files:**
- Modify: `internal/store/mfa.go:325-364` — add `exhausted` return value
- Modify: `internal/api/auth_mfa.go` — emit event on exhaustion
- Modify: `internal/store/mfa_test.go` — test exhaustion return
- Modify: `internal/api/auth_mfa_test.go` — test event emission

**BEFORE starting work:**
1. Read `dev/testing-pitfalls.md` §7 ("Defined event/error constants must be emitted")
2. Read `internal/store/mfa.go:325-364` — current implementation
3. Read `internal/secure/events.go:25` — the dead constant

**Step 1: Write failing test**

Add test `TestStore_VerifyEmailOTP_ExhaustedReturnsBool` to `internal/store/mfa_test.go`:
1. Create email OTP challenge
2. Call `VerifyEmailOTPChallenge` with wrong codes until `maxAttempts` is reached
3. Assert the final call returns `(false, true, nil)` — the new `exhausted` return

**Step 2: Run test to verify it fails**

Expected: FAIL — method returns `(bool, error)`, not `(bool, bool, error)`.

**Step 3: Implement the store fix**

Change `VerifyEmailOTPChallenge` signature from:
```go
func (s *Store) VerifyEmailOTPChallenge(ctx context.Context, userID uuid.UUID, codeHash string, maxAttempts int32) (bool, error)
```
to:
```go
func (s *Store) VerifyEmailOTPChallenge(ctx context.Context, userID uuid.UUID, codeHash string, maxAttempts int32) (matched bool, exhausted bool, err error)
```

In the wrong-code branch, when `attempts >= maxAttempts`, set `exhausted = true`.

Update the handler (`verifyEmailOTP` in `auth_mfa.go`) to accept the new return, and emit `EventMFAChallengeExhausted` when `exhausted` is true:
```go
matched, exhausted, err := srv.store.VerifyEmailOTPChallenge(ctx, userID, codeHash, maxAttempts)
if err != nil {
	return false, err
}
if exhausted && srv.eventWriter != nil {
	srv.eventWriter.Write(ctx, secure.Event{
		Type:     secure.EventMFAChallengeExhausted,
		Severity: secure.SeverityWarning,
		ActorIP:  clientIP(ctx),
		UserID:   &userID,
	})
}
return matched, nil
```

**Step 4: Run tests**

Run: `go test ./internal/store/ -run "TestStore_VerifyEmailOTP" -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 5: Commit**

```bash
git add internal/store/mfa.go internal/store/mfa_test.go internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "fix(mfa): emit EventMFAChallengeExhausted on email OTP max attempts (B8)

VerifyEmailOTPChallenge now returns an exhausted bool to distinguish
max-attempts exhaustion from a simple wrong code. The handler emits
EventMFAChallengeExhausted, which was previously a dead constant."
```

**Review checkpoint — Group E complete.**

---

## Group G: Minor Fixes

### Task 11: Fix enrollment cookie path and email OTP TTL refresh (B10 + B11)

**Files:**
- Modify: `internal/api/auth_mfa.go:1193` — change cookie path to `/api/v1/auth/mfa`
- Modify: `internal/api/auth_mfa.go:1207` — same path in `clearEnrollmentCookie`
- Modify: `internal/api/auth_mfa.go:720-775` — reissue pending token in email OTP setup handler
- Modify: `internal/api/auth_mfa_test.go` — verify cookie path and TTL refresh

**Step 1: Write tests**

`TestEnrollmentCookie_Path`: Assert the enrollment token cookie has path `/api/v1/auth/mfa`.

`TestEmailOTPSetup_ReissuesPendingTokenTTL`: When called from a restricted session, assert the response includes a reissued pending token cookie (fresh TTL).

**Step 2: Implement fixes**

B11 — Change `enrollmentTokenCookies` and `clearEnrollmentCookie`:
```go
Path: "/api/v1/auth/mfa",
```

B10 — In `mfaEmailOTPSetupHandler`, when the user has a pending enrollment session, reissue the pending token with fresh TTL in the response (mirror `mfaChallengeHandler:134-141`). This requires passing the pending token through to the handler and calling `reissuePendingTokenCookies`.

**Step 3: Run tests**

Run: `go test ./internal/api/ -run "TestEnrollment|TestEmailOTP" -v -count=1`
Expected: PASS.

**Step 4: Commit**

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "fix(mfa): enrollment cookie path + email OTP pending token TTL refresh (B10+B11)

Narrowed enrollment cookie path from /api/v1/auth to /api/v1/auth/mfa
per design spec. Email OTP enrollment setup now reissues the pending
token with fresh TTL to prevent expiry during the setup-confirm window."
```

### Task 12: Change required_reasons to structured objects (B12)

**Bug:** API returns `required_reasons` as `[]string` (flat tags) instead of the design-specified `[{source, org_name}]` structured objects.

**Files:**
- Modify: `internal/api/auth_mfa.go:857-909` — change `RequiredReasons` type
- Modify: `internal/api/auth_mfa.go:1241-1290` — refactor `buildMFARequiredReasons` to return structs with org names
- Modify: `internal/store/mfa.go` or `internal/store/org.go` — may need store method to get org names for mandate reasons
- Modify: `internal/api/auth_mfa_test.go` — update assertions

**BEFORE starting work:**
1. Read design doc § "GET /api/v1/auth/mfa/methods" response format — specifies `[{ "source": "org_policy", "org_name": "Acme Corp" }]`
2. Read `internal/api/auth_mfa.go:1241-1290` — current `buildMFARequiredReasons`
3. Read store methods `UserInMFARequiredOrg`, `UserHasMFARequirement` — check if they return org context
4. No frontend consumers exist (verified by grep) — safe to change the API contract

**Step 1: Write failing test**

`TestMFAMethods_RequiredReasons_StructuredFormat`:
1. Create user in org with `mfa_required_all = true`
2. Call GET `/api/v1/auth/mfa/methods`
3. Assert `required_reasons` is `[{"source": "org_policy", "org_name": "<org-name>"}]`

**Step 2: Implement the fix**

Define a struct:
```go
type mfaRequiredReason struct {
	Source  string `json:"source"   doc:"Reason source (site_admin, org_owner, org_policy, per_member, db_error)"`
	OrgName string `json:"org_name,omitempty" doc:"Org name (for org_policy and per_member reasons)"`
}
```

Change `RequiredReasons` field from `[]string` to `[]mfaRequiredReason`.

Refactor `buildMFARequiredReasons` to return `[]mfaRequiredReason`. For `org_policy` and `per_member` reasons, the store methods need to return org names. Check if `UserInMFARequiredOrg` and `UserHasMFARequirement` can be modified to return org info, or add new queries that join with the `organizations` table.

For `site_admin` and `org_owner` reasons, `OrgName` is empty (these are user-level, not org-specific).

**Step 3: Run tests**

Run: `go test ./internal/api/ -run "TestMFAMethods" -v -count=1`
Expected: PASS.

Run: `go test ./internal/api/... -count=1` — no regressions.

**Step 4: Commit**

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go internal/store/mfa.go internal/store/queries/mfa.sql internal/store/generated/
git commit -m "fix(api): change required_reasons to structured objects per design spec (B12)

API now returns required_reasons as [{source, org_name}] instead of
flat strings. Users in multiple orgs can identify which org mandates
MFA. No frontend consumers existed — safe API contract change."
```

**Review checkpoint — Group G complete.**

---

## Final Verification

After all tasks are complete:

1. Run full test suite: `go test ./... -count=1`
2. Run linter: `golangci-lint run`
3. Run `sqlc generate` and verify no diff
4. Run the `/pitfall-check` skill on all modified files
5. Verify all 12 bugs and 2 design decisions are addressed

---

## Appendix: Testing Pitfalls Relevance

The following `dev/testing-pitfalls.md` sections are directly relevant to this fix plan:

| Section | Relevant Tasks | What to Watch For |
|---------|---------------|-------------------|
| §1 (Concurrency) | Task 9 (TOTP replay) | Concurrent TOTP verification must serialize via FOR UPDATE |
| §3 (Error Path) | Task 1 (password reset) | Anti-enumeration: don't leak MFA status via different error codes |
| §7 (Transaction) | Tasks 2, 7 | Transaction helper compliance, defined event constants emitted |
| §11 (Security) | Tasks 3-6, 8 | Token version validation, step ordering, session integrity |
