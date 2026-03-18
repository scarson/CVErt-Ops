# Phase 11 MFA Test Coverage — Consolidated Findings

**Date:** 2026-03-18
**Scope:** Phase 11 MFA (TOTP, Email OTP, Recovery Codes, Enforcement, Admin Controls) including bug hunt remediation
**Methodology:** Hybrid (Go coverage tools + semantic analysis + security checklist matrix)

---

## Coverage Baseline

Coverage was collected per-package using `-coverpkg=./internal/...` to capture cross-package exercised code. The "Combined" column merges store + API test coverage (store methods are exercised by both store unit tests and API integration tests).

### Store Layer (`internal/store/mfa.go`)

| Function | Store Tests | API Tests | Combined |
|----------|------------|-----------|----------|
| CreateMFACredential | 100.0% | — | 100.0% |
| GetMFACredentialsByUserID | 87.5% | — | 87.5% |
| GetMFACredentialByUserAndMethod | 80.0% | — | 80.0% |
| UpdateMFACredentialLastUsed | 100.0% | — | 100.0% |
| **VerifyAndUpdateTOTPStep** | **0.0%** | 80.0% | 80.0% |
| DeleteMFACredential | 87.5% | — | 87.5% |
| DeleteAllMFACredentials | 87.5% | — | 87.5% |
| UserHasMFACredentials | 87.5% | — | 87.5% |
| CountMFACredentialsByUser | 87.5% | — | 87.5% |
| generateRecoveryCode | 87.5% | — | 87.5% |
| hashRecoveryCode | 100.0% | — | 100.0% |
| GenerateRecoveryCodes | 80.0% | — | 80.0% |
| VerifyRecoveryCode | 78.3% | — | 78.3% |
| RegenerateRecoveryCodes | 76.5% | — | 76.5% |
| DeleteAllRecoveryCodes | 100.0% | — | 100.0% |
| CountUnusedRecoveryCodes | 87.5% | — | 87.5% |
| ResetUserMFA | 68.8% | — | 68.8% |
| CreateEmailOTPChallenge | 80.0% | — | 80.0% |
| VerifyEmailOTPChallenge | 77.3% | — | 77.3% |
| CreateRememberDeviceToken | 100.0% | — | 100.0% |
| ValidateRememberDeviceToken | 84.6% | — | 84.6% |
| DeleteRememberDeviceTokens | 100.0% | — | 100.0% |
| DeleteAllUserChallenges | 100.0% | — | 100.0% |
| CountRecentEmailOTPChallenges | 87.5% | — | 87.5% |
| DeleteExpiredChallenges | 87.5% | — | 87.5% |
| CreateMFARequirement | 100.0% | — | 100.0% |
| DeleteMFARequirement | 100.0% | — | 100.0% |
| GetMFARequirementsByOrg | 87.5% | — | 87.5% |
| UserHasMFARequirement | 87.5% | — | 87.5% |
| UserInMFARequiredOrg | 87.5% | — | 87.5% |
| **UserMFARequiredOrgNames** | **0.0%** | 87.5% | 87.5% |
| **UserMFARequirementOrgNames** | **0.0%** | 87.5% | 87.5% |
| UserMFARequired | 82.4% | — | 82.4% |
| IsOrgOwner | 87.5% | — | 87.5% |
| **AllUserOrgsAllowRememberDevice** | **0.0%** | 87.5% | 87.5% |
| **MinRememberDeviceDays** | **0.0%** | 87.5% | 87.5% |
| UpdateOrgMFASettings | 83.3% | — | 83.3% |
| AdminForcePasswordReset | **0.0%** | 87.5% | 87.5% |

### Auth Layer (`internal/auth/jwt.go`)

| Function | Coverage |
|----------|----------|
| IssueAccessToken | 85.7% |
| ParseAccessToken | 100.0% |
| IssueRefreshToken | 85.7% |
| ParseRefreshToken | 100.0% |
| IssuePendingToken | 85.7% |
| ParsePendingToken | 100.0% |
| IssueEnrollmentToken | 85.7% |
| ParseEnrollmentToken | 76.9% |

### API Layer (`internal/api/auth_mfa.go`)

| Function | Coverage |
|----------|----------|
| mfaChallengeHandler | 60.9% |
| mfaVerifyHandler | 75.0% |
| validatePendingToken | 75.0% |
| reissuePendingTokenCookies | 80.0% |
| issueFullAuthTokens | 57.1% |
| verifyTOTP | 76.0% |
| verifyEmailOTP | 75.0% |
| generateEmailOTPCode | 75.0% |
| generateSecureToken | 75.0% |
| **sendMFAOTPEmail** | **37.5%** |
| removePendingItem | 100.0% |
| issueRememberDeviceToken | 76.5% |
| mfaTOTPSetupHandler | 65.7% |
| mfaTOTPConfirmHandler | 62.5% |
| mfaEmailOTPSetupHandler | 63.2% |
| **mfaEmailOTPConfirmHandler** | **48.4%** |
| mfaMethodsHandler | 75.0% |
| mfaRemoveMethodHandler | 54.8% |
| mfaRegenerateCodesHandler | 70.0% |
| reauthenticatePassword | 66.7% |
| checkNotAlreadyEnrolled | 71.4% |
| generateFirstEnrollmentRecoveryCodes | 53.8% |
| resolveEnrollmentUserID | 93.3% |
| resolveAccessTokenUserID | 66.7% |
| clearEnrollmentPending | 50.0% |
| buildMFARequiredReasons | 50.0% |

### API Layer (`internal/api/admin_mfa.go`)

| Function | Coverage |
|----------|----------|
| adminResetMFAHandler | 53.8% |
| **adminForcePasswordResetHandler** | **44.2%** |
| adminRequireMFAHandler | 61.5% |
| adminUnrequireMFAHandler | 57.7% |
| adminUpdateOrgMFASettingsHandler | 57.4% |
| checkAdminMFAPermission | 59.1% |

### Modified Auth Endpoints

| Function | Coverage |
|----------|----------|
| loginHandler | 71.5% |
| refreshHandler | 72.4% |
| refreshGrace | 53.3% |
| issueRefreshPair | 50.0% |
| meHandler | 77.8% |
| changePasswordHandler | 69.0% |
| resetPasswordHandler | 66.2% |

---

## Security Checklist Matrix

### MFA Auth Endpoints (pending token / enrollment token based)

| Endpoint | Auth | Auth Denied | Rate Limit | Input Val | Security Events | Neg Cases |
|----------|------|-------------|------------|-----------|-----------------|-----------|
| POST /auth/mfa/challenge | Tested | Tested | Global ✅ | Tested (enum) | **NOT TESTED** | ✅ |
| POST /auth/mfa/verify | Tested | Tested | Global ✅ | Tested | **NOT TESTED** | ✅ (replay, wrong code, version mismatch) |
| POST /auth/mfa/totp/setup | Tested | Tested (double enroll) | N/A | Tested | **NOT TESTED** | ✅ |
| POST /auth/mfa/totp/confirm | Tested | Tested (wrong code, no setup) | N/A | Tested | **NOT TESTED** | ✅ |
| POST /auth/mfa/email-otp/setup | Tested | Tested (already enrolled) | N/A | Tested | **NOT TESTED** | ✅ |
| POST /auth/mfa/email-otp/confirm | Tested | Partial | N/A | Partial | **NOT TESTED** | **PARTIAL** (48.4% coverage) |
| GET /auth/mfa/methods | Tested | — | N/A | N/A | **NOT TESTED** | ✅ |
| DELETE /auth/mfa/methods/{method} | Tested | Tested (wrong pw, last method) | N/A | Tested | **NOT TESTED** | ✅ |
| POST /auth/mfa/recovery-codes/regenerate | Tested | Tested (no MFA, wrong pw) | N/A | Tested | **NOT TESTED** | ✅ |

### Admin MFA Endpoints (org-scoped, authenticated)

| Endpoint | Auth | RBAC | Self-Target | Input Val | Security Events | Cross-Org |
|----------|------|------|-------------|-----------|-----------------|-----------|
| POST .../reset-mfa | ✅ | ✅ owner, admin, admin→owner✗, member✗ | ✅ | ✅ | **NOT TESTED** | **NOT TESTED** |
| POST .../force-password-reset | ✅ | ✅ owner, member✗ | **NOT TESTED** | ✅ | **NOT TESTED** | **NOT TESTED** |
| POST .../require-mfa | ✅ | ✅ owner, admin→admin✗, member✗ | ✅ | ✅ | **NOT TESTED** | **NOT TESTED** |
| DELETE .../require-mfa | ✅ | owner only | ✅ | ✅ | **NOT TESTED** | **NOT TESTED** |
| PATCH .../mfa-settings | ✅ | ✅ owner, member✗ | N/A | ✅ (range) | **NOT TESTED** | **NOT TESTED** |

### Modified Auth Endpoints (MFA integration)

| Endpoint | MFA Gating | Pending Token | Force Reset | Device Token | Neg Cases |
|----------|------------|---------------|-------------|--------------|-----------|
| POST /auth/login | ✅ | ✅ | ✅ | ✅ | ✅ |
| POST /auth/password/reset | ✅ | ✅ (MFA enrolled, mandated, not required) | — | — | ✅ |
| POST /auth/refresh | — | — | — | — | ✅ |

---

## Confirmed Security-Critical Gaps

### SC1. Zero security event assertions across ALL MFA tests

**Location:** All MFA test files (auth_mfa_test.go, admin_mfa_test.go, auth_mfa_integration_test.go)
**Source:** security matrix
**Evidence:** Production code emits 77 security events via `srv.eventWriter.Write()` across auth_mfa.go (57 events) and admin_mfa.go (20 events). The test server is constructed with `ServerDeps{}` which leaves eventWriter nil. All `if srv.eventWriter != nil` guards silently skip event emission in tests. Zero test files reference eventWriter, secure.Event, or any Event* constant.
**22 security event types defined for MFA — none verified in tests:**
- EventMFAChallengeIssued, EventMFAChallengeVerified, EventMFAChallengeVerifyFailed
- EventMFAEmailOTPRateLimited, EventMFAChallengeExhausted (pitfall §7 explicitly flagged this)
- EventMFATOTPEnrolled, EventMFAEmailOTPEnrolled, EventMFAMethodRemoved
- EventMFARecoveryCodesRegenerated, EventMFARecoveryCodeUsed
- EventMFARememberDeviceIssued, EventMFAAdminReset
- EventAuthPasswordResetForced, EventMFARequirementAdded, EventMFARequirementRemoved
- etc.
**Fix approach:** Inject a test event writer (channel or slice-based collector) in `newMFAServer()`. Add assertions in key tests that the correct event type is emitted with correct metadata.

### SC2. No cross-org isolation tests for admin MFA endpoints

**Location:** internal/api/admin_mfa_test.go
**Source:** security matrix
**Evidence:** All admin MFA tests (reset-mfa, force-password-reset, require-mfa, unrequire-mfa, mfa-settings) operate within a single org. No test attempts to have org A's admin act on org B's member. The middleware should reject this, but it's unverified.
**Fix approach:** Add cross-org test: create two orgs, have org A's owner attempt to reset MFA for org B's member — expect 403/404.

### SC3. adminForcePasswordResetHandler self-target not tested (44.2% coverage)

**Location:** internal/api/admin_mfa.go:104 (self-target check), :124 (OAuth-only check)
**Source:** coverage matrix
**Evidence:** `TestAdminForcePasswordReset` tests owner→member (success) and `TestAdminForcePasswordResetByMember` tests member→admin (denied). Missing: self-target rejection (line 104: `if callerID == targetID`), OAuth-only account rejection (line 124: `if !user.PasswordHash.Valid`), admin→admin same-level denial, non-existent target user (line 120: `if user == nil`).
**Fix approach:** Add tests for self-target (400), OAuth-only (400), admin→admin (403), non-existent user (404).

### SC4. mfaEmailOTPConfirmHandler at 48.4% — over half of branches untested

**Location:** internal/api/auth_mfa.go:825
**Source:** coverage baseline
**Evidence:** This handler confirms email OTP enrollment. At 48.4% coverage, more than half of its branches are untested. Key untested paths likely include: invalid enrollment token, wrong code, expired challenge, rate limit exceeded, already-enrolled method collision, recovery code generation failure.
**Fix approach:** Add explicit tests for each error branch in the confirm handler.

### SC5. No test verifies pending token rejected as access token

**Location:** internal/api/middleware_auth.go (RequireAuthenticated)
**Source:** semantic analysis (subagent)
**Evidence:** RequireAuthenticated middleware only accepts access_token cookie or Bearer API key. Pending tokens have a different claim structure and should be rejected. No test sends a pending token value in the access_token cookie to verify rejection by the middleware. This is a defense-in-depth gap — if a bug allowed pending token acceptance as an access token, MFA could be bypassed entirely.
**Fix approach:** Add a test that logs in, gets a pending token (MFA-gated login), then sends that value as an access_token cookie to a protected endpoint — expect 401.

### SC6. Site admin and viewer role paths untested in admin MFA

**Location:** internal/api/admin_mfa.go:397 (checkAdminMFAPermission, line 419 IsSiteAdmin path)
**Source:** semantic analysis (subagent) + coverage (59.1%)
**Evidence:** `checkAdminMFAPermission` has a site admin bypass path (line 419) that allows site admins to act on any user in any org. This path is never tested. Additionally, no viewer role test exists for admin MFA endpoints — viewers should be rejected by the admin+ middleware, but this is unverified.
**Fix approach:** Add site admin test (site admin resets MFA for a user they don't share an org with — expect 200) and viewer test (viewer attempts reset-mfa — expect 403).

### SC7. Admin action side-effect assertions incomplete

**Location:** admin_mfa_test.go:99-107 (TestAdminMFAReset), :191-198 (TestAdminForcePasswordReset)
**Source:** semantic analysis (subagent)
**Evidence:** `TestAdminMFAReset` only verifies credential deletion (1 of 4 side effects). Missing assertions: recovery codes deleted, challenges deleted, token_version incremented. `TestAdminForcePasswordReset` only verifies the flag is set (1 of 3 side effects). Missing: token_version incremented, device tokens deleted.
**Fix approach:** Add assertions for all side effects in both tests.

### SC8. Remember-device multi-org most-restrictive policy untested

**Location:** internal/store/mfa.go:670 (AllUserOrgsAllowRememberDevice), :685 (MinRememberDeviceDays)
**Source:** semantic analysis (subagent)
**Evidence:** These functions gate whether remember-device tokens are allowed and their expiry. `AllUserOrgsAllowRememberDevice` returns true only if ALL orgs allow it. `MinRememberDeviceDays` returns the minimum across all orgs. No test exercises the multi-org most-restrictive policy (user in org A with 30 days + org B with 14 days should get 14 days; user in org A allowing + org B disallowing should get false).
**Fix approach:** Add multi-org store tests exercising the most-restrictive-wins logic.

### SC9. sendMFAOTPEmail at 37.5% — email delivery error paths untested

**Location:** internal/api/auth_mfa.go:445
**Source:** coverage baseline
**Evidence:** `sendMFAOTPEmail` is at 37.5% — the only covered path is the "SMTP not configured" early return. The actual email rendering and sending paths are never exercised. Per testing-pitfalls §8: "SMTP/webhook failure reporting: test the failure path."
**Fix approach:** This is partially by design (test servers have no SMTP config). Consider testing with SMTP configured but using a mock transport, or testing the rendering path separately via `notify.RenderMFAOTP`.

### SC10. ParseEnrollmentToken missing fundamental JWT security tests

**Location:** internal/auth/jwt.go:253 (ParseEnrollmentToken), internal/auth/jwt_test.go
**Source:** coverage-guided triage (subagent)
**Evidence:** Access, refresh, and pending tokens all have comprehensive security tests: round-trip, expiry rejection, wrong secret, alg:none, RS256 confusion, wrong algorithm. ParseEnrollmentToken at 76.9% has ONLY the dual-key rotation test. The enrollment token carries the encrypted TOTP secret — if algorithm confusion attacks worked, an attacker could forge enrollment tokens.
**Fix approach:** Add tests matching the other token types: round-trip, expiry, wrong secret, alg:none, RS256.

### SC11. UserMFARequired RequiredOrgOwners path untested

**Location:** internal/store/mfa.go:620-652 (UserMFARequired, layer 2a)
**Source:** coverage-guided triage (subagent)
**Evidence:** `UserMFARequired` has a 4-layer enforcement model: site admin, org owners, org-wide, per-member. Layer 2a ("org owners must have MFA" site config) has zero test coverage. The store test `TestUserMFARequired_OrgOwnerRequired` tests org-wide mfa_required_all, not the RequiredOrgOwners site config path. A bug silently disabling this mandate would be invisible.
**Fix approach:** Add store test: create org with user as owner, set site config RequiredOrgOwners=true, verify UserMFARequired returns true.

### SC12. Enrollment token user mismatch not tested (cross-user enrollment attack)

**Location:** internal/api/auth_mfa.go:637-638 (mfaTOTPConfirmHandler)
**Source:** coverage-guided triage (subagent)
**Evidence:** `mfaTOTPConfirmHandler` checks `enrollClaims.UserID != userID` to prevent User A from completing User B's TOTP enrollment. This guard prevents a cross-user enrollment attack where an attacker could bind their authenticator to a victim's account. No test exercises this check.
**Fix approach:** Add test: create two users, start TOTP setup as user A, try to confirm as user B — expect 401.

### TOCTOU Assessment (from semantic analysis)

All critical TOCTOU windows are **properly protected**:
- Recovery codes: `FOR UPDATE SKIP LOCKED` — tested with concurrent goroutines at store + API layers
- TOTP: `FOR UPDATE` (blocking) — tested with concurrent barrier pattern
- Email OTP: `FOR UPDATE SKIP LOCKED` — tested with concurrent verification

**Minor accepted risk:** Email OTP rate limit uses count-then-insert pattern (TOCTOU-vulnerable under concurrent requests). Low severity — bounded by HTTP-level rate limiter. Same pattern as password reset TOCTOU (previously accepted).

---

## Confirmed Correctness Gaps

### C1. Store-level tests missing for 5 MFA methods (0% store coverage)

**Location:** internal/store/mfa.go
**Source:** coverage baseline
**Evidence:** `VerifyAndUpdateTOTPStep`, `UserMFARequiredOrgNames`, `UserMFARequirementOrgNames`, `AllUserOrgsAllowRememberDevice`, `MinRememberDeviceDays` all show 0% in store tests. They are tested only indirectly via API integration tests. Per testing-pitfalls §7: "Every public method on `*Store` needs at least one test that calls it directly."
**Fix approach:** Add direct store tests for each. Particularly important for `VerifyAndUpdateTOTPStep` which has the FOR UPDATE lock logic — a direct test can verify replay prevention at the store layer without HTTP roundtrip overhead.

### C2. adminUnrequireMFA RBAC incomplete

**Location:** internal/api/admin_mfa_test.go
**Source:** security matrix
**Evidence:** `TestAdminUnrequireMFA` only tests owner→member (success) and self-target (denied). Missing: admin→member (should succeed), admin→admin (should fail), member→anyone (should fail). `TestAdminRequireMFA` has much better RBAC coverage — the unrequire path should match.
**Fix approach:** Add RBAC tests matching the require-mfa pattern: admin→member success, admin→admin denial, member denial.

### C3. buildMFARequiredReasons at 50% — structured response format partially tested

**Location:** internal/api/auth_mfa.go:1306
**Source:** coverage baseline
**Evidence:** `buildMFARequiredReasons` constructs the structured reason objects (source + org names) returned by the /mfa/methods endpoint. At 50% coverage, error paths and multi-org scenarios are likely untested. The bug hunt remediation (B12) changed this from strings to structured objects — the test may only cover the basic case.
**Fix approach:** Test with multiple orgs, site-wide requirement, per-member requirement, and DB error fallback path.

### C4. clearEnrollmentPending at 50% — enrollment completion path partially tested

**Location:** internal/api/auth_mfa.go:1272
**Source:** coverage baseline
**Evidence:** `clearEnrollmentPending` handles the transition from enrollment pending token to full auth tokens. At 50% coverage, the critical "last pending item cleared → issue full tokens" path may not be fully tested. Per testing-pitfalls §11: "Full auth token issuance on restricted session completion."
**Fix approach:** Verify that the TestEnrollment_IssuesFullTokensOnCompletion test adequately covers all branches of clearEnrollmentPending.

### C5. refreshGrace at 53.3% and issueRefreshPair at 50%

**Location:** internal/api/auth.go:606, :631
**Source:** coverage baseline
**Evidence:** These functions handle refresh token rotation with a grace window for concurrent requests. At ~50% coverage, error paths and edge cases in the refresh flow are undertested.
**Fix approach:** Test refresh token reuse within grace window, reuse after grace window expires, and error paths.

### C6. checkAdminMFAPermission at 59.1% — site admin path likely untested

**Location:** internal/api/admin_mfa.go:397
**Source:** coverage baseline
**Evidence:** `checkAdminMFAPermission` implements a 3-tier RBAC check: site admin (can target anyone), owner (can target members/admins), admin (can target members only). At 59.1%, the site admin path is likely not exercised in tests.
**Fix approach:** Add a test with a site admin targeting a member in an org they don't belong to.

---

## Production Bugs Discovered

None discovered in this coverage cycle. The Phase 11 bug hunt remediation (12 fixes) appears to have addressed the code bugs. The gaps found here are test coverage gaps, not code bugs.

---

## Design Decisions Requiring User Input

### D1. Security event testing strategy

**The concern:** 77 security event emissions across MFA code have zero test assertions. Adding assertions for all 22 event types across all handlers is substantial work.
**Why this needs a decision:** Trade-off between thoroughness and effort. A test event writer is needed regardless.
**Options:**
1. **Full coverage:** Create event writer test infrastructure + assert on every security event type in at least one test → ~20 new assertions, high value for a security product
2. **Critical-only:** Assert on the 6 most security-critical events (admin reset, password reset forced, MFA verification success/failure, rate limiting, recovery code used) → ~8 new assertions
3. **Infrastructure only:** Create the test event writer but defer assertions to a future pass → low effort, enables future tests
**Recommendation:** Option 1 — this is a security product and audit trail completeness is a core requirement. The test event writer infrastructure is needed regardless, and once built, individual assertions are trivial.

### D2. Store-level test independence vs API-level coverage

**The concern:** 5 store methods have 0% direct coverage but 80-87.5% via API tests. testing-pitfalls §7 says every public store method needs direct tests.
**Why this needs a decision:** The API tests do exercise these methods, but through HTTP roundtrips that add noise and can't isolate store-level edge cases (error wrapping, transaction helper usage).
**Options:**
1. **Add direct store tests for all 5** → ensures store-layer bugs are caught independently
2. **Add direct store tests only for VerifyAndUpdateTOTPStep** (the most complex, with FOR UPDATE lock) → targeted effort on highest risk
3. **Accept API-level coverage** for the simpler methods (org name queries, min days) and only add store tests for VerifyAndUpdateTOTPStep
**Recommendation:** Option 3 — `VerifyAndUpdateTOTPStep` is the only one with complex transactional behavior worth testing directly. The org name/remember-device methods are straightforward queries adequately exercised by API tests.

### D3. Cross-org admin endpoint testing scope

**The concern:** Admin MFA endpoints (5 endpoints) have no cross-org tests at API level. Store-level RLS tests exist for mfa_requirements.
**Why this needs a decision:** These endpoints use org-scoped middleware (RequireOrgMember) which is independently tested. Adding cross-org tests for each endpoint is duplicating middleware tests.
**Options:**
1. **Add cross-org test for each admin endpoint** (5 tests) → comprehensive but redundant with middleware tests
2. **Add one cross-org test for the most critical endpoint** (reset-mfa) as a smoke test → validates the middleware integration without redundancy
3. **Skip** — rely on middleware tests for org isolation
**Recommendation:** Option 2 — one cross-org test for reset-mfa confirms the middleware is actually wired to these routes. This catches "forgot to add RequireOrgMember middleware" bugs that middleware unit tests can't detect.

---

## False Positives

### FP1. 87.5% "gap" on many store methods is consistent

**Why invalid:** The ~12.5% gap across many store methods (GetMFACredentialsByUserID, DeleteMFACredential, etc.) is the same uncovered branch in all cases: the error return from the transaction helper wrapper. This is infrastructure error handling, not a missing business logic test. The `withBypassTx` error path is tested once in the transaction helper tests.

### FP2. Triage agent: "remember-device feature zero API test coverage"

**Why invalid:** `TestRememberDeviceFlow` (auth_mfa_test.go:1447) tests the full remember-device flow: `remember_device:true` in verify request, device token cookie extraction, and login MFA bypass via `mfa_device_token` cookie. `TestRememberDeviceOrgDisallowed` and `TestRememberDeviceInvalidatedOnPasswordChange` add negative cases.

### FP3. Triage agent: "mandate-blocks-removal untested"

**Why invalid:** `TestMFARemoveLastMethodBlocked` (auth_mfa_test.go:1301) tests exactly this: sets org mfa_required_all=true, enrolls TOTP, tries to remove the last method — asserts 403.

### FP4. Triage agent: "resetPasswordHandler MFA gating not directly tested"

**Why invalid:** `TestResetPassword_WithMFAEnrolled_ReturnsPendingToken` and `TestPasswordResetDoesNotBypassMFA` (integration test) both test MFA gating after password reset.

### FP5. Triage agent: "mfaRegenerateCodesHandler no MFA enrolled rejection"

**Why invalid:** `TestRecoveryCodeRegenerateNoMFA` tests this exact scenario — user with no MFA tries to regenerate codes.

### FP6. Issue* token functions at 85.7%

**Why invalid:** The ~14.3% uncovered branch in all Issue* functions (IssueAccessToken, IssueRefreshToken, IssuePendingToken, IssueEnrollmentToken) is the `jwt.NewWithClaims().SignedString()` error path, which only fails on impossible conditions (nil key). Not worth testing.

---

## Assertion Quality Issues

### A1. Security event payloads untested

**Location:** All MFA handlers (auth_mfa.go, admin_mfa.go)
**Evidence:** Subsumes SC1 — the event writer is nil in tests, so event types, severities, actor IPs, user IDs, org IDs, and detail maps are all untested. Once the test event writer infrastructure exists (SC1), each event assertion should verify the full payload, not just the event type.

### A2. TestAdminMFAReset — only credential deletion verified (1 of 4 side effects)

**Location:** admin_mfa_test.go:99-107
**Evidence:** `ResetUserMFA` atomically deletes credentials, recovery codes, challenges, and increments token_version. The test only checks `UserHasMFACredentials == false`. Missing assertions: recovery codes deleted (`CountUnusedRecoveryCodes == 0`), challenges deleted, token_version incremented (old tokens should be rejected on next login).

### A3. TestAdminForcePasswordReset — only flag verified (1 of 3 side effects)

**Location:** admin_mfa_test.go:191-198
**Evidence:** `adminForcePasswordResetHandler` sets force_password_reset=true, calls `IncrementTokenVersion`, and calls `DeleteRememberDeviceTokens`. The test only checks `ForcePasswordReset == true`. Missing: token_version incremented (existing sessions invalidated), device tokens deleted.

### A4. TestMFAVerifyWrongCode — missing access_token absence check

**Location:** auth_mfa_test.go
**Evidence:** Test verifies 401 status code on wrong MFA code, but doesn't assert the absence of access_token and refresh_token cookies. A bug that issued auth cookies despite 401 status would pass this test.

### A5. TestMFAChallengeInvalidToken — garbage input only

**Location:** auth_mfa_test.go
**Evidence:** Test sends `"garbage"` as the pending token. This tests the "malformed JWT" path but not the "well-formed JWT signed with wrong key" path or "expired but otherwise valid" path, which exercise different code branches in `ParsePendingToken`.

---

## Nice-to-Have

### N1. formatTTL edge cases

**Location:** internal/api/auth_password_reset.go:23 (76.9% coverage)
**Evidence:** Missing duration format branches — likely the hours-only and minutes-only display paths.

### N2. reauthenticatePassword with disabled user

**Location:** internal/api/auth_mfa.go:1126 (66.7% coverage)
**Evidence:** Tests cover correct password and wrong password cases. Missing: disabled user account, OAuth-only account with no password hash.

### N3. resolveAccessTokenUserID with invalid access token

**Location:** internal/api/auth_mfa.go:1231 (66.7% coverage)
**Evidence:** Missing: expired token, malformed token, wrong-secret token. These exercise the fallback to pending token resolution.

### N4. Email OTP rate limit 429 response at API level

**Location:** internal/api/auth_mfa.go:86 (mfaChallengeHandler, 60.9% coverage)
**Evidence:** The store-level rate limit counting is tested (`TestMFAChallenge_RateLimiting`), but no API test exceeds `MFAEmailOTPMaxPerHour` and verifies the 429 response from the challenge handler.

### N5. mfaRemoveMethodHandler with non-existent method type

**Location:** internal/api/auth_mfa.go:972 (54.8% coverage)
**Evidence:** Tests cover: valid removal, wrong password, last-method-blocked. Missing: method type that doesn't exist (e.g., `DELETE /auth/mfa/methods/sms`) — should return 404 or similar.

### N6. generateFirstEnrollmentRecoveryCodes — second enrollment skip

**Location:** internal/api/auth_mfa.go:1170 (53.8% coverage)
**Evidence:** This function generates recovery codes on first MFA enrollment but skips generation if codes already exist (second method enrollment). The skip path is untested.

### N7. mfaEmailOTPSetupHandler — rate limiting at API level

**Location:** internal/api/auth_mfa.go:760 (63.2% coverage)
**Evidence:** Same as N4 — the email OTP setup handler has a rate limit check that mirrors the challenge handler, but no test exceeds it.

### N8. VerifyRecoveryCode — already-used code at store level

**Location:** internal/store/mfa.go:239 (78.3% coverage)
**Evidence:** No store test submits a code that was valid but already consumed (used_at IS NOT NULL). Concurrent double-consumption IS tested, but the simple "reuse a used code" path is not. The `WHERE used_at IS NULL` clause in the query is only tested indirectly.

### N9. GenerateRecoveryCodes — no verify-after-generate test

**Location:** internal/store/mfa.go:208 (80.0% coverage)
**Evidence:** Tests verify 10 codes are generated, but no test generates codes then immediately verifies one — confirming the hash round-trip works end-to-end at the store level.

### N10. UpdateOrgMFASettings — org-not-found path

**Location:** internal/store/org.go:50 (83.3% coverage)
**Evidence:** No test calls `UpdateOrgMFASettings` with a non-existent org ID to verify the error path.

---

## Key Observations

1. **Security events are the biggest systematic gap.** 77 event emissions, 0 assertions. This is consistent with the test infrastructure: `newMFAServer()` passes `ServerDeps{}` which leaves `eventWriter` nil. All event code is behind nil guards, so it silently becomes dead code in tests.

2. **Admin endpoint coverage is consistently lower (44-61%) than auth endpoint coverage (50-75%).** The admin tests exist but only cover the happy path + one negative case. The auth tests are more thorough with multiple negative cases.

3. **Cross-handler consistency is good.** Rate limiting is correctly applied to all unauthenticated flows (login, register, MFA challenge/verify, password reset) but not to authenticated admin endpoints. Cookie handling patterns are consistent across all MFA endpoints.

4. **The bug hunt remediation was effective.** All 12 bugs found in the Phase 11 bug hunt were fixed, and most have regression tests. The remaining gaps are in coverage breadth (more negative cases, more error branches) rather than fundamental design issues.

5. **Store methods tested only through API integration tests** is a pattern that works for simple queries but misses store-layer-specific concerns (error wrapping, transaction helper selection, FOR UPDATE lock behavior).

---

## Test Gap Analysis

### SC1. Zero security event assertions — Why missed

**Why missed:** The test infrastructure (`newMFAServer`) passes `ServerDeps{}` with no event writer. All 77 event emissions are guarded by `if srv.eventWriter != nil`, so they silently become no-ops. The tests pass regardless of whether events are emitted correctly, incorrectly, or not at all. This is a test infrastructure gap, not a code gap — the events are implemented correctly, they're just invisible to tests.
**Pitfall coverage:** Covered by testing-pitfalls §7: "Defined event/error constants must be emitted." The pitfall specifically calls out `EventMFAChallengeExhausted` as a found bug — the constant was defined but never emitted. This was fixed in the bug hunt remediation (B8), but no test was added to prevent regression.
**Catch test:** Inject a `chan secure.Event`-based event writer into `newMFAServer`. In each test that triggers a security event, read from the channel and assert event type + metadata. For SC1, a representative test: `TestMFAVerifyTOTP` should assert `EventMFAChallengeVerified` with the correct user ID.

### SC2. No cross-org admin endpoint tests — Why missed

**Why missed:** The admin MFA tests all operate within a single org using `setupAdminMFATest`. The test helper creates one org with owner/admin/member. No second org is created, so cross-org attempts are never made. The middleware (RequireOrgMember) rejects cross-org requests, but this is only tested in middleware unit tests — the admin MFA routes' middleware wiring is unverified.
**Pitfall coverage:** Covered by testing-pitfalls §10: "Cross-tenant visibility assertion" and "Per-user resource isolation." The principle applies — we need to verify that the middleware is actually wired to these routes.
**Catch test:** Create two orgs. Have org A's owner attempt `POST /orgs/{orgB}/members/{memberB}/reset-mfa`. Expect 403 or 404.

### SC3. adminForcePasswordReset self-target untested — Why missed

**Why missed:** Tests exist for the happy path (owner→member) and one negative case (member→admin). The self-target check is a simple `if callerID == targetID` guard that was likely considered "obviously correct" and not tested. The OAuth-only check is an edge case that requires setting up an OAuth-only user, which the test helpers don't support.
**Pitfall coverage:** Covered by testing-pitfalls §11: "Security check enforcement across similar endpoints." The reset-mfa endpoint HAS a self-target test — force-password-reset should match.
**Catch test:** Have owner attempt `POST .../force-password-reset` targeting themselves. Expect 400 with "cannot force password reset on yourself".

### SC4. mfaEmailOTPConfirmHandler at 48.4% — Why missed

**Why missed:** The `TestEmailOTPConfirm` test covers the happy path (valid enrollment token, correct code, successful confirmation). But the handler has many error branches: invalid enrollment token, wrong code, expired challenge, rate limit exceeded, already-enrolled collision, recovery code generation failure. These negative branches weren't written as separate tests.
**Pitfall coverage:** One-off — the handler has many branches specific to the email OTP enrollment flow. No general pitfall covers this.
**Catch test:** Add tests: wrong code (401), expired challenge (401), already enrolled (409), invalid enrollment token (401).

### SC5. Pending token as access token — Why missed

**Why missed:** The middleware (`RequireAuthenticated`) parses `access_token` cookies using `ParseAccessToken`. A pending token in the access_token cookie should fail parsing because the claim structure differs. But nobody wrote a test that explicitly proves this rejection. The assumption is "different claim types = different parsing" — but that's an assumption, not a verified property.
**Pitfall coverage:** Covered by testing-pitfalls §11: "Security check enforcement across similar endpoints." MFA introduced new token types that share the same transport (cookies) — each must be rejected by the wrong parser.
**Catch test:** Login with MFA enrolled → get pending token → set it as `access_token` cookie → hit a protected endpoint → expect 401.

### SC7. Admin action side-effects — Why missed

**Why missed:** Test authors verified the primary outcome (MFA cleared, flag set) but didn't trace all side effects of the store operations. `ResetUserMFA` performs 4 deletions + version increment in one transaction — the test only checks one. This is a common "assert the main thing, forget the ancillary things" pattern.
**Pitfall coverage:** Not directly covered by existing pitfalls. **Candidate addition:** "When a store method has multiple side effects (deletes + version increment), test ALL side effects — not just the primary one."
**Catch test:** After reset-mfa: check `CountUnusedRecoveryCodes == 0`, check `UserHasMFACredentials == false` (already done), attempt login with old token (expect rejection from version increment).

### SC8. Remember-device multi-org policy — Why missed

**Why missed:** `TestRememberDeviceFlow` uses a single org. The most-restrictive-wins SQL logic (`bool_and()` for allowed, `MIN()` for days) is never exercised with multiple orgs. A bug returning `bool_or()` instead of `bool_and()` would pass all tests.
**Pitfall coverage:** Covered by testing-pitfalls §10: "Cross-tenant visibility assertion." The multi-org policy is a cross-tenant concern.
**Catch test:** Create user in org A (30 days, allowed) + org B (14 days, disallowed). Verify `AllUserOrgsAllowRememberDevice == false` and `MinRememberDeviceDays == 14`.

### SC10. ParseEnrollmentToken JWT tests — Why missed

**Why missed:** The enrollment token was added during Phase 11 implementation. The other three token types (access, refresh, pending) had their security test suites built incrementally over earlier phases. Enrollment token only got a dual-key test because that was the novel feature at the time. The standard security tests (alg:none, expiry, wrong secret) were not copied from the template.
**Pitfall coverage:** Covered by testing-pitfalls §11: "JWT algorithm confusion — test alg:none and unexpected algorithms."
**Catch test:** Copy test patterns from `TestPendingTokenRejectsExpired`, `TestPendingTokenRejectsAlgNone`, `TestPendingTokenRejectsWrongSecret`, `TestPendingTokenRejectsWrongAlgorithm` — adapting for enrollment token.

### SC11. UserMFARequired RequiredOrgOwners — Why missed

**Why missed:** `TestUserMFARequired_OrgOwnerRequired` (store/mfa_test.go) is misleadingly named — it tests org-wide `mfa_required_all`, not the "org owners must have MFA" site config (`RequiredOrgOwners`). The config field may not even exist yet or may be wired differently. This needs verification against the actual `UserMFARequired` implementation.
**Pitfall coverage:** Covered by testing-pitfalls §11: "Multi-layer authorization negative cases."
**Catch test:** Set site config `RequiredOrgOwners=true`, create user as org owner, verify `UserMFARequired` returns true with source "site_config_org_owners".

### SC12. Enrollment token user mismatch — Why missed

**Why missed:** The cross-user enrollment attack is an obscure threat model — user A starts TOTP setup, user B tries to confirm with A's enrollment token. The guard exists (`enrollClaims.UserID != userID`), but the test would require two authenticated users and cookie swapping, which the test helpers don't readily support.
**Pitfall coverage:** Not directly covered. **Candidate addition:** "When a multi-step flow uses bearer tokens, test that swapping tokens between users is rejected."
**Catch test:** User A starts TOTP setup (gets enrollment cookie). User B attempts TOTP confirm with A's enrollment cookie + a valid TOTP code → expect 401.

### C1. Store-level tests missing for VerifyAndUpdateTOTPStep — Why missed

**Why missed:** `VerifyAndUpdateTOTPStep` uses a `FOR UPDATE` lock for replay prevention, which was added during the bug hunt remediation (B9). The API test `TestTOTP_VerifyAndUpdateTOTPStep_Store` exists but runs through the API layer. No direct store test isolates the lock behavior.
**Pitfall coverage:** Covered by testing-pitfalls §7: "Direct tests for every public store method." Explicitly calls out MFA methods.
**Catch test:** Direct store test: create a credential, call `VerifyAndUpdateTOTPStep` with step N (expect true), call again with same step (expect false — replay), call with step N+1 (expect true — fresh).

### C2. adminUnrequireMFA RBAC — Why missed

**Why missed:** `TestAdminRequireMFA` has thorough RBAC coverage (owner, admin→admin, member, self-target). `TestAdminUnrequireMFA` was likely written as a quick mirror test — success + self-target — without copying the full RBAC matrix from the require path.
**Pitfall coverage:** Covered by testing-pitfalls §4: "Create vs Update/PATCH — when testing PATCH, test every invalid input that create rejects."
**Catch test:** Add admin→member (success), admin→admin (403), member→anyone (403) matching the require-mfa RBAC matrix.

### C3. buildMFARequiredReasons — Why missed

**Why missed:** `TestMFAMethods_RequiredReasons_StructuredFormat` was added during bug hunt remediation (B12) and tests the basic structured format. Multi-org scenarios and the DB error fallback path weren't included.
**Pitfall coverage:** One-off.
**Catch test:** Create user in two orgs with different policies. Verify `required_reasons` contains entries from both orgs with correct source labels.

### Testing Pitfalls Updates

**Two additions made to `dev/testing-pitfalls.md`:**

1. **§7: Multi-side-effect operations must assert ALL effects (from SC7)** — Added to Transaction & Store Conventions. When a store method performs multiple side effects, test ALL of them. Cites TestAdminMFAReset (1/4 effects) and TestAdminForcePasswordReset (1/3 effects).

2. **§11: Cross-user token swapping in multi-step flows (from SC12)** — Added to Security Enforcement Testing. When a multi-step flow issues user-bound tokens, test that completing another user's flow is rejected. Distinct from the existing "Token type enforcement" pitfall (which covers wrong *type*, not wrong *user*). Cites mfaTOTPConfirmHandler enrollment token user mismatch.

**Existing pitfall already covers SC5:** §11 "Token type enforcement across session types" (added by Sam) covers the pending-token-as-access-token gap. Marked with `🔥 Found in review`.
