# Phase 11 MFA Bug Hunt — Consolidated Findings

**Date:** 2026-03-17
**Scope:** Phase 11 MFA implementation (TOTP, email OTP, recovery codes, restricted sessions, 3-layer enforcement, remember-device, admin management, cleanup worker). Delivered via PR #44 (Tasks 1-9, foundation) and PR #50 (Tasks 10-23, handlers). 28 source files.
**Hunters:** Exploratory, Holistic, Multipass

---

## Confirmed Bugs

### B1. Password reset flow does not gate on MFA (MFA bypass)
**Consensus:** Multipass found; verified by consolidation against design doc
**Location:** internal/api/auth_password_reset.go:182-237
**Evidence:** The design doc (§ Password Reset Interaction) explicitly states: "After a forgot-password flow completes (user proved identity via email token), MFA status is checked: Has MFA credentials → issue pending token with `["mfa_challenge"]`". The actual `resetPasswordHandler` changes the password and returns `resetPasswordOutput{}` with no MFA check, no pending token, and no session tokens. The design doc calls out: "This prevents password reset from being an MFA bypass."
**Impact:** An attacker who gains access to the email account can reset the password and fully authenticate without completing MFA challenge. This defeats TOTP enrollment entirely. Critical severity.
**Blast radius:** `auth_password_reset.go` only — needs MFA credential lookup + pending token issuance added. No other callers affected.
**Fix approach:** After password change succeeds, check `GetMFACredentials` for enrolled methods. If enrolled → issue pending token with `["mfa_challenge"]`. If not enrolled but mandated → issue pending token with `["mfa_enrollment_required"]`. If neither → return bare 200 (current behavior). Mirrors the login flow's MFA gating logic.
**Note:** This file is from Phase 6A and was not modified in Phase 11 — it's a missing implementation that the Phase 11 design doc specified but was never built.

### B2. Stale token_version in pending token after password change
**Consensus:** All three hunters found this (3/3). Strong signal.
**Location:** internal/api/auth.go:903-904
**Evidence:** `changePasswordHandler` calls `UpdatePasswordHash` (line 858) which atomically increments `token_version` in the DB. Then on line 903-904, it reissues the pending token using `pendingClaims.TokenVersion` — the OLD value from before the increment. The `mfaVerifyHandler` at line 182 validates `int(user.TokenVersion) != claims.TokenVersion`. The enrollment path (`resolveEnrollmentUserID`) currently skips token_version validation (see B4), so enrollment works by accident — but the token is semantically wrong.
**Impact:** Users with `["password_reset", "mfa_enrollment_required"]` pending will get locked out after completing password reset once B4 is fixed. Even without B4 fix, the token has a stale version claim. Significant severity.
**Blast radius:** Single line fix in `auth.go`. After `UpdatePasswordHash`, re-read user to get the incremented `token_version`.
**Fix approach:** After `UpdatePasswordHash` and before reissuing the pending token, call `GetUserByID` to get the current `token_version` (same pattern used on line 916-921 for the "all pending cleared" branch). Pass `int(user.TokenVersion)` to `IssuePendingToken`.

### B3. Enrollment endpoints skip pending order enforcement
**Consensus:** Exploratory found; verified by consolidation
**Location:** internal/api/auth_mfa.go:1149-1173 (resolveEnrollmentUserID)
**Evidence:** `resolveEnrollmentUserID` checks whether `"mfa_enrollment_required"` exists ANYWHERE in the pending array (iterating with `for _, p := range claims.Pending`), not that it is `Pending[0]`. The design doc specifies fixed completion order: `mfa_challenge` → `password_reset` → `mfa_enrollment_required`. Other handlers enforce ordering by checking `Pending[0]` (e.g., `validatePendingToken` checks `claims.Pending[0] != expectedStep`).
**Impact:** A user with `["password_reset", "mfa_enrollment_required"]` can skip password reset and go directly to MFA enrollment — the exact scenario ordering was designed to prevent. Significant severity.
**Blast radius:** Single function fix in `auth_mfa.go`.
**Fix approach:** Change the loop to check `claims.Pending[0] == "mfa_enrollment_required"` instead of searching the entire array.

### B4. resolveEnrollmentUserID does not validate token_version
**Consensus:** Multipass found; Holistic noted as design concern (2/3)
**Location:** internal/api/auth_mfa.go:1149-1173
**Evidence:** For enrollment endpoints, `resolveEnrollmentUserID` accepts the pending token without checking `token_version` against the DB. Compare with `mfaVerifyHandler` (line 178-183) which explicitly checks `int(user.TokenVersion) != claims.TokenVersion`. An admin could `IncrementTokenVersion` (e.g., via MFA reset) while the user has an active enrollment session, and the stale pending token would still be accepted.
**Impact:** Enrollment proceeds with an invalidated session. Session invalidation guarantee is broken for enrollment endpoints. Significant severity.
**Blast radius:** `resolveEnrollmentUserID` needs to look up the user and validate `token_version`. All enrollment handlers that call it inherit the fix.
**Fix approach:** After extracting `claims.UserID` from the pending token, call `GetUserByID` and verify `int(user.TokenVersion) == claims.TokenVersion`. Return 401 on mismatch.

### B5. clearEnrollmentPending fails to issue full auth tokens on completion
**Consensus:** Holistic and Multipass found (2/3)
**Location:** internal/api/auth_mfa.go:1216-1236
**Evidence:** When all pending items are cleared, `clearEnrollmentPending` only clears the pending token cookie — it never issues access/refresh tokens. The code acknowledges this in a comment (line 1233-1234). Compare with `mfaVerifyHandler` (line 279-285) which properly calls `issueFullAuthTokens`, and `changePasswordHandler` (line 916-928) which re-reads the user and issues full tokens.
**Impact:** Users completing `mfa_enrollment_required` as their sole pending step get kicked to login with no session. Poor UX — they just proved their identity. Significant severity.
**Blast radius:** `clearEnrollmentPending` needs refactoring to accept context and issue tokens. Callers (`mfaTOTPConfirmHandler`, `mfaEmailOTPConfirmHandler`) need to pass context.
**Fix approach:** Change `clearEnrollmentPending` signature to accept `context.Context` and return both cookies and an error. When `remaining` is empty, look up the user by `claims.UserID` and call `issueFullAuthTokens`. Match the pattern in `mfaVerifyHandler`.

### B6. UpdateOrgMFASettings and UpdateOrg bypass transaction helpers
**Consensus:** Exploratory found; Multipass noted as design concern (2/3)
**Location:** internal/store/org.go:28-54
**Evidence:** Both `UpdateOrg` (line 28) and `UpdateOrgMFASettings` (line 40) call `s.q.UpdateOrgMFASettings()`/`s.q.UpdateOrg()` directly without any transaction helper. Every other org-mutation method in the file uses `withOrgTx` or `withBypassTx`. The convention (CLAUDE.md + implementation-pitfalls.md): "Never query s.db directly in store methods — always use a transaction helper."
**Impact:** No RLS issue (organizations table has no RLS), but queries run without statement timeout enforcement. Under DB contention, could hold a pool connection indefinitely. Minor-to-significant severity.
**Blast radius:** Two functions in `org.go`. No callers affected by the change.
**Fix approach:** Wrap both in `withBypassTx` (org mutations don't need RLS context — org_id IS the row being updated, not a filter).

### B7. Admin MFA reset is non-atomic with redundant operation
**Consensus:** All three hunters found (3/3)
**Location:** internal/api/admin_mfa.go:54-81
**Evidence:** Five sequential store operations each in their own `withBypassTx`. `DeleteAllUserChallenges` (line 65, `DELETE FROM mfa_challenges WHERE user_id = $1`) already removes all challenge types including `remember_device`. `DeleteRememberDeviceTokens` (line 70) then deletes 0 rows. If the process crashes between operations (e.g., after deleting credentials but before incrementing token_version), the user is left with MFA destroyed but active sessions still valid.
**Impact:** Redundant DB call (harmless). Non-atomic aggregate operation leaves inconsistent state on partial failure (minor — admin can retry). Minor severity.
**Blast radius:** Single handler. Fix requires a new store method that wraps all deletions + version increment in one transaction.
**Fix approach:** (1) Remove redundant `DeleteRememberDeviceTokens` call. (2) Create a `ResetUserMFA(ctx, userID)` store method that performs all operations in a single `withBypassTx` transaction.

### B8. EventMFAChallengeExhausted never emitted (dead event constant)
**Consensus:** Holistic found; verified by consolidation (1/3 but code-verified)
**Location:** internal/secure/events.go:25 (constant), internal/store/mfa.go:325-364 (root cause)
**Evidence:** `EventMFAChallengeExhausted` is defined and registered in the severity map but never emitted. Root cause: `VerifyEmailOTPChallenge` returns `(bool, error)` — when max attempts are reached, it deletes the challenge and returns `false, nil`, indistinguishable from wrong-code failure. The handler always emits `EventMFAVerifyFailed`.
**Impact:** Security audit gap — admins cannot detect brute-force MFA exhaustion via monitoring. Minor severity.
**Blast radius:** `VerifyEmailOTPChallenge` return signature changes → callers in `auth_mfa.go` need to handle the new return value.
**Fix approach:** Add an `exhausted bool` return to `VerifyEmailOTPChallenge`. Emit `EventMFAChallengeExhausted` in the handler when exhausted is true.

### B9. TOTP replay prevention doesn't account for skew window
**Consensus:** Holistic found (1/3 but logic-verified)
**Location:** internal/api/auth_mfa.go:394-401
**Evidence:** Replay prevention stores `currentStep = now.Unix() / 30`. With `Skew: 1`, the library accepts codes for steps `currentStep-1`, `currentStep`, and `currentStep+1`. A code for step N+1 is accepted when currentStep=N, and `lastUsedStep` is set to N. When currentStep advances to N+1, the same code is still valid (it's now the "current" step code), and `lastUsedStep=N < N+1` passes the replay check. The code could be replayed once within the next 30-second window.
**Impact:** A TOTP code can potentially be replayed once within a ~30-second window after first use. Minor severity — practical exploitation requires intercepting the code AND replaying within 30 seconds.
**Blast radius:** Single line change in `auth_mfa.go`.
**Fix approach:** Store `currentStep + 1` (the highest possible accepted step given skew) as `lastUsedStep`, guaranteeing no replay within the acceptance window.

### B10. Email OTP enrollment doesn't reissue pending token with fresh TTL
**Consensus:** Multipass found (1/3 but pattern-verified)
**Location:** internal/api/auth_mfa.go:720-775 (mfaEmailOTPSetupHandler)
**Evidence:** When called from a restricted enrollment session, the handler returns without reissuing the pending token. The pending token has a 5-minute TTL. If setup is triggered near expiry, the token may expire before the email arrives and the user confirms. Compare with `mfaChallengeHandler` (line 134-141) which reissues the pending token with fresh TTL.
**Impact:** Race condition where pending token expires during email OTP enrollment, forcing restart. Minor severity.
**Blast radius:** Single handler change.
**Fix approach:** Reissue the pending token with fresh TTL in the response, mirroring `mfaChallengeHandler`.

### B11. Enrollment cookie path wider than design spec
**Consensus:** Exploratory and Multipass found (2/3)
**Location:** internal/api/auth_mfa.go:1193
**Evidence:** Design doc specifies enrollment cookie path as `/api/v1/auth/mfa`. Implementation uses `/api/v1/auth`. The enrollment cookie (containing encrypted TOTP secret reference) is sent with all auth requests, not just MFA endpoints.
**Impact:** Slightly increased attack surface — enrollment token transmitted with unnecessary requests. Minimal practical risk (short-lived, HttpOnly, signed JWT). Minor severity.
**Blast radius:** Single constant change.
**Fix approach:** Change path to `/api/v1/auth/mfa`. Also update `clearEnrollmentCookie` path to match.

### B12. required_reasons returns flat strings instead of structured objects
**Consensus:** Multipass found (1/3 but design doc is unambiguous)
**Location:** internal/api/auth_mfa.go:871 (struct) and 1241-1280 (buildMFARequiredReasons)
**Evidence:** Design doc specifies `required_reasons` as `[{ "source": "org_policy", "org_name": "Acme Corp" }]`. Implementation returns `[]string` — flat tags like `"site_admin"`, `"org_policy"`.
**Impact:** Users in multiple orgs cannot identify which org mandates MFA. API contract deviates from design spec. Minor severity.
**Blast radius:** Struct change + `buildMFARequiredReasons` needs to return org context. May need additional store query to get org names.
**Fix approach:** Change `RequiredReasons` to a struct slice with `Source` and `OrgName` fields. Update `buildMFARequiredReasons` to include org names from the mandate check queries.

---

## Design Decisions Requiring User Input

### D1. Shared email OTP rate limit counter between login and enrollment
**Location:** Rate limit check in both `mfaChallengeHandler` and `mfaEmailOTPSetupHandler`
**The concern:** Login MFA challenges and enrollment MFA challenges share the same `MFAEmailOTPMaxPerHour` counter per user. Enrollment spam can block legitimate login challenges (and vice versa).
**Why this needs a decision:** Separating counters could be exploited to double the effective rate limit; keeping them shared could create UX friction. Both are defensible.
**Options:**
  - A) Keep shared (current): simpler, prevents total abuse across contexts, minor UX friction
  - B) Separate counters: better UX, but doubles effective email volume per user per hour
**Recommendation:** Keep shared (option A). The rate limit exists to prevent email abuse, not to gate user flows. A user hitting the limit across both contexts is sending too many emails regardless.

### D2. Pending/enrollment tokens lack dual-key rotation support
**Location:** internal/auth/jwt.go — ParsePendingToken and ParseEnrollmentToken take single secret
**The concern:** During JWT secret rotation, `ParseAccessToken` and `ParseRefreshToken` accept both active and previous secrets for zero-downtime rotation. Pending and enrollment tokens do not — any user mid-MFA-flow during rotation is locked out.
**Why this needs a decision:** The window is narrow (5 minutes max for pending tokens) but it's an architectural inconsistency. Adding dual-key support is straightforward but adds complexity.
**Options:**
  - A) Add dual-key support now: consistency, no edge-case lockouts during rotation
  - B) Defer: narrow window, low risk, less code
**Recommendation:** Add dual-key support (option A). The pattern already exists in `ParseAccessToken` — it's a small change for consistency.

### D3. TOTP verification lacks FOR UPDATE lock (race window)
**Location:** internal/api/auth_mfa.go:362-406 (verifyTOTP)
**The concern:** TOTP verification validates code, checks `last_used_step`, then updates `last_used_step` in separate store calls. Two concurrent requests with the same valid TOTP code could both pass the check. Recovery code verification uses `FOR UPDATE SKIP LOCKED` but TOTP does not.
**Why this needs a decision:** The race window is extremely narrow (~30s TOTP window + concurrent request timing). Adding `FOR UPDATE` would require a new store method and transaction restructuring. The practical risk is very low.
**Options:**
  - A) Add FOR UPDATE lock: architecturally consistent, eliminates race
  - B) Accept the race: extremely narrow window, practical exploitation nearly impossible
**Recommendation:** Accept the race (option B) for now. The 30-second TOTP window combined with the step-based replay check (which B9 tightens further) makes practical exploitation improbable. The code is already capturing `now` once to prevent clock-boundary races.

---

## False Positives

None identified. All unique findings were verified against the source code and design doc.

---

## Bugs Outside Primary Scope

### O1. Password reset MFA bypass (B1 above)
**Location:** internal/api/auth_password_reset.go:182-237
**Blast radius:** Single file. Needs MFA credential lookup + conditional pending token issuance. Same pattern as login flow MFA gating.
**Recommendation:** Include in fix plan — this is a critical security gap specified in the Phase 11 design doc that was never implemented. The file itself is from Phase 6A but the MFA gating requirement is Phase 11 scope.

### O2. UpdateOrg bypasses transaction helpers (B6 partially)
**Location:** internal/store/org.go:28-36
**Blast radius:** Single function, pre-existing (Phase 2). No callers affected.
**Recommendation:** Fix alongside `UpdateOrgMFASettings` since they're adjacent code with the same issue.