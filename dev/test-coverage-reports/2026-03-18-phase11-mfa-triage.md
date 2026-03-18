# Phase 11 MFA Coverage-Guided Triage

Date: 2026-03-18

## Coverage Baseline

| Package | Key Functions | Coverage Range |
|---------|--------------|----------------|
| internal/store (mfa.go) | 37 functions | 68.8%-100% |
| internal/store (admin_user.go) | 1 function | 87.5% |
| internal/store (auth.go) | 3 functions | 82.4%-87.5% |
| internal/store (org.go) | 1 function | 83.3% |
| internal/auth (jwt.go) | 8 functions | 76.9%-100% |
| internal/api (auth_mfa.go) | 29 functions | 37.5%-100% |
| internal/api (admin_mfa.go) | 6 functions | 44.2%-61.5% |
| internal/api (auth.go) | 6 functions | 50.0%-77.8% |
| internal/api (auth_password_reset.go) | 3 functions | 66.2%-76.9% |
| internal/api (middleware_auth.go) | 4 functions | 62.1%-100% |

## Well-Covered Areas

- **JWT security fundamentals:** All four token types have thorough algorithm pinning, expiry enforcement, and dual-key rotation tests. jwt_test.go is a model for security-focused testing (except enrollment tokens which are weaker).
- **Core MFA verify flows:** TOTP, email OTP, and recovery code verify all have E2E API tests. Replay prevention, token version mismatch, and concurrent recovery code double-consumption are all tested.
- **RBAC hierarchy enforcement:** Admin MFA handlers have thorough owner > admin > member tests including admin-targets-admin (403) and self-target (400).
- **Full integration flows:** auth_mfa_integration_test.go covers multi-step scenarios: full TOTP login, email OTP flow, recovery code flow, forced password reset with MFA, and enrollment mandate.

## Production Bugs Discovered

None. The code appears correct. All gaps are test coverage gaps, not code bugs.

## Security-Critical Gaps (14)

1. **VerifyAndUpdateTOTPStep -- no store-level atomicity test** -- internal/store/mfa.go:91-118 -- No direct store test for first-use, fresh-step, replay, or concurrent FOR UPDATE serialization. API test covers replay but not atomicity guarantee independently. -- source: coverage
2. **VerifyRecoveryCode -- no already-used code store test** -- internal/store/mfa.go:239-279 -- No test submits a code that was valid but already consumed. Concurrent double-consumption IS tested. -- source: coverage
3. **ResetUserMFA -- token_version increment not verified** -- internal/store/mfa.go:339-362 -- TestAdminMFAReset checks hasMFA==false but never verifies token_version was incremented. Sessions could remain valid after MFA reset. -- source: semantic
4. **UserMFARequired -- RequiredOrgOwners path untested** -- internal/store/mfa.go:620-652 -- Layer 2a (org owners must have MFA) is never exercised in any test. A bug here would silently disable the site-wide org-owner MFA mandate. -- source: coverage
5. **ParseEnrollmentToken -- missing fundamental security tests** -- internal/auth/jwt.go:253-281 -- Only dual-key test exists. No round-trip, expiry rejection, wrong secret, alg:none, or RS256 tests. All other token types have these. -- source: coverage
6. **mfaChallengeHandler -- email OTP rate limiting untested at API level** -- internal/api/auth_mfa.go:86-96 -- Rate limit check at store level IS tested, but the handler 429 response path for exceeding MFAEmailOTPMaxPerHour is not. -- source: coverage
7. **mfaVerifyHandler -- remember-device token issuance untested** -- internal/api/auth_mfa.go:289-304 -- No test submits remember_device:true. The device token cookie issuance, store creation, org-allow check, and most-restrictive-days policy are all untested. -- source: coverage
8. **mfaTOTPConfirmHandler -- enrollment token user mismatch untested** -- internal/api/auth_mfa.go:637-638 -- The enrollClaims.UserID != userID check prevents cross-user enrollment attacks. No test verifies this guard. -- source: coverage
9. **mfaEmailOTPSetupHandler -- rate limiting untested** -- internal/api/auth_mfa.go:760-769 -- Same as challenge handler: count >= MFAEmailOTPMaxPerHour -> 429 is never tested at API level. -- source: coverage
10. **mfaRemoveMethodHandler -- mandate-blocks-removal untested** -- internal/api/auth_mfa.go:1004-1014 -- The critical safety check (cannot remove last MFA method when MFA is mandated, returns 403) is completely untested. -- source: coverage
11. **buildMFARequiredReasons -- fail-closed on DB errors untested** -- internal/api/auth_mfa.go:1349-1354 -- When all DB calls fail, function should return db_error reason to force MFA. This fail-closed behavior is untested. -- source: coverage
12. **checkAdminMFAPermission -- site admin bypass untested** -- internal/api/admin_mfa.go:419-421 -- No test creates a site admin and verifies they can target owners. The entire site admin bypass path is uncovered. -- source: coverage
13. **loginHandler -- remember-device MFA bypass untested** -- internal/api/auth.go:408-428 -- A valid mfa_device_token cookie should skip MFA challenge. This entire feature path has zero test coverage. -- source: coverage
14. **resetPasswordHandler -- MFA gating not directly tested** -- internal/api/auth_password_reset.go:247-281 -- The handler mirrors login MFA gating post-reset but no test calls the reset endpoint and verifies pending token MFA status. -- source: coverage

## Correctness Gaps (15)

1. **GenerateRecoveryCodes -- no verify-after-generate test** -- internal/store/mfa.go:208-234
2. **UserMFARequiredOrgNames -- no direct store test** -- internal/store/mfa.go:583-594
3. **UserMFARequirementOrgNames -- no direct store test** -- internal/store/mfa.go:597-608
4. **AllUserOrgsAllowRememberDevice -- no multi-org store test** -- internal/store/mfa.go:670-681
5. **MinRememberDeviceDays -- no direct store test** -- internal/store/mfa.go:685-696
6. **AdminForcePasswordReset -- no direct store test** -- internal/store/admin_user.go:150-161
7. **GetUserAuthStatus -- no direct store test** -- internal/store/auth.go:236-251
8. **adminForcePasswordResetHandler -- OAuth-only guard untested** -- internal/api/admin_mfa.go:124-126
9. **sendMFAOTPEmail -- SMTP-configured path untested** -- internal/api/auth_mfa.go:445-468
10. **generateFirstEnrollmentRecoveryCodes -- second enrollment skip untested** -- internal/api/auth_mfa.go:1170-1193
11. **mfaMethodsHandler -- required_reasons field not verified** -- internal/api/auth_mfa.go:925-959
12. **clearEnrollmentPending -- remaining-items path untested** -- internal/api/auth_mfa.go:1278-1285
13. **UpdateOrgMFASettings -- org-not-found path untested** -- internal/store/org.go:50-72
14. **mfaRegenerateCodesHandler -- no MFA enrolled rejection untested** -- internal/api/auth_mfa.go:1092-1094
15. **RequireAuthenticated -- MFA path exemption during force_password_reset** -- internal/api/middleware_auth.go:85

## Nice-to-Have (18)

1. GetMFACredentialsByUserID error path -- internal/store/mfa.go:50-52
2. GetMFACredentialByUserAndMethod error wrapper -- internal/store/mfa.go:71-73
3. DeleteMFACredential error path -- internal/store/mfa.go:132-134
4. DeleteAllMFACredentials error path -- internal/store/mfa.go:147-149
5. UserHasMFACredentials error path -- internal/store/mfa.go:161-163
6. CountMFACredentialsByUser error path -- internal/store/mfa.go:175-177
7. generateRecoveryCode crypto/rand error -- internal/store/mfa.go:189-191
8. CountUnusedRecoveryCodes error path -- internal/store/mfa.go:330-332
9. DeleteExpiredChallenges error path -- internal/store/mfa.go:507-509
10. GetMFARequirementsByOrg error path -- internal/store/mfa.go:546-548
11. UserHasMFARequirement error path -- internal/store/mfa.go:561-563
12. UserInMFARequiredOrg error path -- internal/store/mfa.go:576-578
13. IsOrgOwner error path -- internal/store/mfa.go:662-664
14. IssueAccessToken signing error -- internal/auth/jwt.go:40-42
15. IssueRefreshToken signing error -- internal/auth/jwt.go:108-110
16. IssuePendingToken signing error -- internal/auth/jwt.go:180-182
17. IssueEnrollmentToken signing error -- internal/auth/jwt.go:244-246
18. formatTTL untested duration branches -- internal/api/auth_password_reset.go:23-42

## Assertion Quality Issues (3)

1. **TestAdminMFAReset -- does not verify session invalidation** -- admin_mfa_test.go:70-107 -- Checks hasMFA==false but never verifies token_version was incremented. Old sessions could remain valid. -- source: assertion
2. **TestAdminForcePasswordReset -- does not verify session invalidation** -- admin_mfa_test.go:172-199 -- Checks ForcePasswordReset==true but does not verify IncrementTokenVersion. Old tokens should be rejected. -- source: assertion
3. **mfaVerifyHandler tests -- no test verifies remember-device cookie** -- All verify tests omit remember_device:true. Device token cookie path/SameSite/HttpOnly/MaxAge never verified. -- source: assertion

## Key Observations

### Systematic Gaps

- **Remember-device feature completely untested at API level**: Neither token issuance (mfaVerifyHandler) nor MFA bypass (loginHandler) paths are tested. Zero API-level coverage for this entire feature.
- **7 store functions have 0% direct store tests** (API-only coverage): VerifyAndUpdateTOTPStep, UserMFARequiredOrgNames, UserMFARequirementOrgNames, AllUserOrgsAllowRememberDevice, MinRememberDeviceDays, AdminForcePasswordReset. API tests exercise happy paths but miss error branches and edge cases.
- **ParseEnrollmentToken is the weakest JWT token type**: Access, refresh, pending tokens have comprehensive security tests. Enrollment tokens have only a dual-key test.

### TOCTOU Windows

1. **Enrollment race (mfaTOTPConfirmHandler):** Double checkNotAlreadyEnrolled (before setup, before confirm) guards against concurrent enrollment. Race window is small (5min TTL). **Low risk.**
2. **Rate limit TOCTOU (challenge/setup handlers):** Count-then-insert for email OTP rate limiting. Bounded by IP rate limiter. **Accepted risk.**
3. **Remember-device at login:** Device token could be deleted between validation and session issuance. **Low risk.**

### Cross-Handler Pattern

All admin MFA handlers follow consistent pattern: extract context -> parse target -> self-check -> RBAC -> business op -> event + audit. No missing steps detected. adminUpdateOrgMFASettingsHandler intentionally diverges (uses route middleware instead of checkAdminMFAPermission).

## Gap Context

| Category | Gaps | Action |
|----------|------|--------|
| Security-critical | 14 | Add targeted security tests |
| Correctness | 15 | Add specific test cases |
| Nice-to-have | 18 | Low priority, error paths |
| Assertion quality | 3 | Strengthen existing tests |
| **Total** | **50** | |
