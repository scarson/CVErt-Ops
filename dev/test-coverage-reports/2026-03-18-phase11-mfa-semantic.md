# Phase 11 MFA Semantic Coverage Review

**Scope:** 4B-E and 5 -- semantic analysis of MFA packages
**Date:** 2026-03-18
**Reviewer:** Claude (subagent)

## Files Analyzed

**Source:**
- `internal/store/mfa.go` (696 lines, 34 methods)
- `internal/api/auth_mfa.go` (~1450 lines, 10+ handlers)
- `internal/api/admin_mfa.go` (~435 lines, 6 handlers)
- `internal/api/auth.go` (login handler MFA gating, ~270 lines)
- `internal/api/auth_password_reset.go` (MFA gating after reset, ~307 lines)
- `internal/api/middleware_auth.go` (pending token restriction, 156 lines)
- `internal/auth/jwt.go` (PendingClaims, EnrollmentClaims, dual-key, 282 lines)

**Tests:**
- `internal/store/mfa_test.go` (~1400 lines)
- `internal/api/auth_mfa_test.go` (~1400 lines)
- `internal/api/auth_mfa_integration_test.go` (~671 lines)
- `internal/api/admin_mfa_test.go` (~469 lines)
- `internal/api/auth_password_reset_test.go` (~610 lines)
- `internal/auth/jwt_test.go` (~889 lines)

---

## 4B: Right-Function-Called Analysis

### B1. VerifyAndUpdateTOTPStep -- correct function, correct arguments
**Source:** auth_mfa.go verify handler calls srv.store.VerifyAndUpdateTOTPStep(ctx, claims.UserID, maxStep) where maxStep = int64(currentStep) + int64(totpValidateOpts.Skew).

**Assessment:** CORRECT. The maxStep calculation accounts for the TOTP skew window. The function uses GetMFACredentialByUserAndMethodForUpdate (FOR UPDATE lock) and compares lastUsedStep >= maxStep -- this correctly prevents replay within and beyond the skew window.

**Test verification:** TestMFAVerifyTOTPReplay tests this by generating a TOTP code, using it once (200), logging in again and submitting the same code (expecting 401). This is a genuine replay test.

### B2. VerifyRecoveryCode -- correct function in verify handler
**Source:** auth_mfa.go verify handler calls srv.store.VerifyRecoveryCode(ctx, claims.UserID, input.Body.Code).

**Assessment:** CORRECT. The code passes the raw recovery code (not pre-hashed). The store method handles normalization (lowercase, strip dashes) and hashing internally.

### B3. VerifyEmailOTPChallenge -- hash before comparison
**Source:** auth_mfa.go verify handler computes codeHash := sha256Hex(input.Body.Code) then calls srv.store.VerifyEmailOTPChallenge with the hash.

**Assessment:** CORRECT. The handler hashes the user-supplied code before passing to the store, which uses subtle.ConstantTimeCompare against the stored hash.

### B4. UserMFARequired vs UserHasMFACredentials -- correct distinction in login handler
**Source:** auth.go login handler checks UserHasMFACredentials first (enrolled?), then UserMFARequired (mandated?).

**Assessment:** CORRECT. These are different questions correctly applied. resetPasswordHandler mirrors the same logic.

### B5. checkAdminMFAPermission -- correct role hierarchy
**Source:** admin_mfa.go enforces: site admin > owner > admin > member hierarchy.

**Assessment:** CORRECT.

### B6. buildMFARequiredReasons -- correct store method calls
**Source:** auth_mfa.go calls UserMFARequiredOrgNames (org-wide policy) and UserMFARequirementOrgNames (per-member). Different queries for different policy sources.

**Assessment:** CORRECT.

### B7. ssoEncryptionKey / ssoEncryptionKeyPrevious -- TOTP confirm handler
**Source:** mfaTOTPConfirmHandler tries current key first, falls back to previous key. Test TestTOTPConfirmDecryptsWithPreviousKey verifies this.

**Assessment:** CORRECT.

### B8. FINDING -- AdminForcePasswordReset is not atomic
**Source:** adminForcePasswordResetHandler (admin_mfa.go:83-169) makes three separate store calls (set flag, increment token_version, delete device tokens). If step 2 fails, flag is set but sessions not invalidated.

**Severity:** Correctness. TestAdminForcePasswordReset only checks the flag is set, not session invalidation or device token cleanup.


---

## 4C: TOCTOU Windows

### C1. Recovery code verification + consumption -- SAFE
VerifyRecoveryCode uses FOR UPDATE SKIP LOCKED within withBypassTx. Both TestRecoveryCode_ConcurrentConsumption (store) and TestConcurrentRecoveryCodeUse (API) verify exactly-one-success semantics.

### C2. TOTP step validation + update -- SAFE
VerifyAndUpdateTOTPStep uses FOR UPDATE (blocking) within withBypassTx. Serializes concurrent TOTP verifications correctly.

### C3. Email OTP challenge verification + deletion -- SAFE
VerifyEmailOTPChallenge uses FOR UPDATE SKIP LOCKED. TestMFAChallenge_ConcurrentVerification confirms exactly-one-success.

### C4. MFA requirement check during login to token issuance -- ACCEPTABLE RISK
Window is milliseconds within a single HTTP request. Mitigated by token_version invalidation.

### C5. Remember device token validation to use -- SAFE
Single-request scope, local variable flag.

### C6. Admin MFA reset while user is mid-verification -- SAFE
token_version mechanism protects. TestMFAVerifyTokenVersionMismatch verifies stale pending tokens are rejected.

### C7. FINDING -- Email OTP rate limit check is TOCTOU-vulnerable
Count-then-insert pattern in mfaChallengeHandler allows concurrent requests to exceed rate limit. Low severity -- bounded by HTTP-level rate limiter. Similar to password reset TOCTOU (Accepted risk A10).

---

## 4D: Defense-in-Depth

### D1. Pending tokens restricted from protected endpoints -- TESTED
RequireAuthenticated middleware only accepts access_token cookie or Bearer API key.
**GAP:** No explicit test sends pending token value in access_token cookie to verify rejection.

### D2. Enrollment tokens restricted -- TESTED
TestTOTPConfirmWithoutSetup and TestEnrollmentCookie_Path verify structural restrictions.

### D3. MFA enforcement at multiple layers -- PARTIALLY TESTED
Login handler enforces MFA. No per-request MFA check after access token issued (by design, short-lived tokens).

### D4. Admin permission checks -- WELL TESTED
Owner->member, admin->member, admin->owner, member->admin, self-target, admin->admin all tested.
**GAP:** No viewer role test. No site admin bypass test (admin_mfa.go:419 IsSiteAdmin path).

### D5. Rate limits -- PARTIALLY TESTED
**GAP:** No API-level test triggers email OTP rate limit and verifies the response.

---

## 4E: Store-Layer Independence

### E1. VerifyAndUpdateTOTPStep -- 0% in store tests
Covered by API tests. GAP: boundary conditions (first use with NULL step, exact equality) untested.

### E2. UserMFARequiredOrgNames / UserMFARequirementOrgNames -- 0% in store tests
Partially covered by API. GAP: multi-org scenarios untested.

### E3. AllUserOrgsAllowRememberDevice / MinRememberDeviceDays -- 0% in store tests
**Security-relevant GAP.** These gate device token allowance and expiry. No test for multi-org most-restrictive policy.

### E4. UserMFARequired -- org-owner and per-member paths untested
API tests cover site-admin and org-wide. Two of four enforcement layers have no test coverage.

### E5. ResetUserMFA -- incomplete assertion coverage
API test verifies credential deletion but not recovery code/challenge deletion or token version increment.


---

## 5: Assertion Quality Audit

### Strong assertions (exemplary patterns)
- TestMFAVerifyWithRemainingPending -- checks exact pending list AND absence of access_token
- TestFullForcedPasswordResetWithMFA -- multi-step state machine with intermediate state checks
- TestConcurrentRecoveryCodeUse -- atomic counter for exactly-one-success
- TestLoginWithMFAEnrolled -- checks presence of pending token AND absence of access token

### Assertion gaps
- TestMFAVerifyWrongCode -- checks 401 but not absence of access_token
- TestMFAChallengeInvalidToken -- garbage input only, no well-formed-but-wrong-key token
- TestAdminMFAReset -- checks 1 of 4 side effects of ResetUserMFA
- TestAdminForcePasswordReset -- checks 1 of 3 side effects
- TestEmailOTPConfirm -- bypasses challenge handler, injects challenge directly

### Critical finding: No security event tests
All MFA handlers emit secure.Event entries, but ServerDeps{} provides nil eventWriter. Event emission code paths are never exercised, meaning event types, severities, and payloads are completely untested.

---

## Gap Summary

| Category | Count |
|----------|-------|
| Security-Critical | 6 |
| Correctness | 7 |
| Nice-to-Have | 4 |
| Assertion Quality | 3 |
| **Total** | **20** |

### Security-Critical Gaps (6)
1. No test for pending token used as access token -- middleware_auth.go -- source: semantic
2. No site admin bypass test for admin MFA -- admin_mfa.go:419 -- source: semantic
3. No viewer role test for admin MFA endpoints -- server.go:306-309 -- source: semantic
4. AllUserOrgsAllowRememberDevice untested -- store/mfa.go:670-681 -- source: semantic
5. MinRememberDeviceDays untested -- store/mfa.go:685-696 -- source: semantic
6. No security event emission tests -- auth_mfa.go multiple -- source: assertion

### Correctness Gaps (7)
7. AdminForcePasswordReset non-atomic -- admin_mfa.go:129-147 -- source: semantic
8. TestAdminMFAReset incomplete assertions -- admin_mfa_test.go:99-107 -- source: assertion
9. TestAdminForcePasswordReset incomplete assertions -- admin_mfa_test.go:191-198 -- source: assertion
10. VerifyAndUpdateTOTPStep no direct store test -- store/mfa.go:91-118 -- source: semantic
11. UserMFARequired org-owner/per-member untested -- store/mfa.go:620-652 -- source: semantic
12. Email OTP rate limit not API-tested -- auth_mfa.go challenge handler -- source: semantic
13. Email OTP rate limit TOCTOU -- auth_mfa.go -- source: semantic

### Nice-to-Have (4)
14. TestMFAVerifyWrongCode missing access_token absence check -- source: assertion
15. TestMFAChallengeInvalidToken garbage-input only -- source: assertion
16. TestEmailOTPConfirm bypasses challenge handler -- source: assertion
17. No multi-org test for MFA org name queries -- source: semantic

### Assertion Quality Issues (3)
18. Security event payloads untested -- source: assertion
19. ResetUserMFA assertions incomplete -- source: assertion
20. Force password reset assertions incomplete -- source: assertion

---

## Key Observations

### TOCTOU Analysis Summary
All critical TOCTOU windows (recovery code double-consumption, TOTP replay, email OTP double-verification) are properly protected with database-level locking (FOR UPDATE and FOR UPDATE SKIP LOCKED) and tested with concurrent goroutine tests at both store and API layers. The email OTP rate-limit TOCTOU is acceptable risk (bounded by HTTP-level rate limiter).

### Cross-Handler Consistency
The admin MFA handlers follow a consistent pattern: extract context, parse target, self-target check, RBAC check, perform action, emit event, audit log. All four handlers follow this pattern consistently. No cross-handler violation detected.

### Store-Layer Independence Summary
Five store methods have 0% direct store test coverage: VerifyAndUpdateTOTPStep, UserMFARequiredOrgNames, UserMFARequirementOrgNames, AllUserOrgsAllowRememberDevice, MinRememberDeviceDays. The last two are most concerning because they gate security decisions (device token allowance/expiry) and API tests do not exercise multi-org edge cases.

### Assertion Quality Pattern
Integration tests in auth_mfa_integration_test.go have the strongest assertions (complete state transitions). Unit tests sometimes check only HTTP status without verifying token absence or side-effect completeness. Admin tests verify primary outcome but miss secondary outcomes (token version increment, cascade deletions).
