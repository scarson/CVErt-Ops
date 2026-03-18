# Phase 8 Security-Critical Coverage Review: api, auth, crypto

Date: 2026-03-18
Packages: internal/api (308 functions), internal/auth (12 functions), internal/crypto (4 functions)

---

## 1. Executive Summary

| Severity | Count |
|----------|-------|
| Security-critical | 18 |
| Correctness | 14 |
| Nice-to-have | 8 |
| Assertion quality | 6 |
| Total findings | 46 |

---

## 2. Package: internal/crypto (4 functions, avg 88.9%)

### Findings

[CRYPTO-1] Encrypt error paths uncovered (nice-to-have) - Effectively unreachable with valid 32-byte key.

[CRYPTO-2] Decrypt structural error paths uncovered (nice-to-have) - Similar unreachable paths.

[CRYPTO-3] DecryptWithFallback tests are strong (pass) - Exemplary test design including truncated-ciphertext fallback prevention.

[CRYPTO-4] isGCMAuthError uses string matching (correctness) - Checks our own wrapper, not stdlib. Low risk.

---

## 3. Package: internal/auth (12 functions, avg 90.0%)

### Findings

[AUTH-1] JWT Parse functions have excellent security test coverage (pass) - All token types tested for round-trip, expired, wrong-algorithm, alg:none, wrong-secret, dual-key rotation.

[AUTH-2] ParseEnrollmentToken fallback-fails path uncovered (correctness) - No UnknownKeyRejects test unlike other token types.

[AUTH-3] Issue*Token SignedString error paths uncovered (nice-to-have) - HMAC-SHA256 never fails for valid keys.

[AUTH-4] VerifyPassword base64 decode errors partially untested (correctness) - Missing invalid base64 salt/key test cases.

[AUTH-5] VerifyPassword uses constant-time compare (pass) - Correct assertions on both positive and negative cases.

---

## 4. Package: internal/api -- Security-Critical Handlers

### 4.1 Zero-Coverage (0%) - 19 functions

[API-1] adminConfigHandler at 0% -- secrets leak risk (security-critical). No test verifies secrets are redacted.

[API-2] admin user management endpoints all at 0% (security-critical). adminDisableUser self-disable prevention, adminUnlockUser lockout bypass, adminResetPassword all untested.

[API-3] adminListDeliveries and adminRetryDelivery at 0% (security-critical). Cross-org data access, no authz test.

### 4.2 Partial Coverage

[API-4] loginHandler at 71.5% (security-critical). Disabled user path, MFA enrollment-required, remember-device cookie bypass uncovered.

[API-5] refreshHandler 72.4% + refreshGrace 53.3% + issueRefreshPair 50% (security-critical). Theft detection, grace window edge cases uncovered.

[API-6] tryAPIKeyAuth at 62.1% (security-critical). Revoked-key security event and disabled-user API key rejection untested.

[API-7] RequireAuthenticated disabled-user at 85.3% (security-critical). Only incidentally exercised, no dedicated test.

[API-8] jwtPreviousSecretBytes at 66.7% (correctness). Startup config fallback untested.

### 4.3 MFA Handlers

[API-9] sendMFAOTPEmail at 37.5% (security-critical). Only SMTP-not-configured path covered.

[API-10] mfaEmailOTPConfirmHandler at 48.4% (security-critical). Success paths uncovered.

[API-11] mfaRemoveMethodHandler at 54.8% (security-critical). Security downgrade risk, removal paths uncovered.

[API-12] buildMFARequiredReasons at 50% (security-critical). Fail-closed DB error logic untested.

[API-13] clearEnrollmentPending at 50% (correctness).

### 4.4 SSO Handlers

[API-14] ssoEncryptionKeyPrevious at 72.7% (security-critical). Fallback path untested.

[API-15] patchSSOHandler at 45.3% (security-critical). Client secret re-encryption untested.

[API-16] createSSOHandler at 55.3% (security-critical). Encryption paths partially uncovered.

### 4.5 Other Handlers

[API-17] createInvitationHandler at 54.5% (correctness).
[API-18] updateMemberRoleHandler at 54.5% (correctness).
[API-19] listAlertRulesHandler at 43.6% (correctness).
[API-20] bindRuleChannelHandler/unbindRuleChannelHandler at 52.0% (correctness).
[API-21] replayDeliveryHandler at 50% (correctness).
[API-22] Report handlers at 42-48% (correctness).

---

## 5. Assertion Quality Audit

[AQ-1] adminBulkRetryDeliveries test -- limit not actually verified.
[AQ-2] lockout integration test -- timing-dependent, missing counter-reset test.
[AQ-3] API key tests -- missing disabled-user rejection test.
[AQ-4] ForcePasswordReset -- missing /auth/logout allowlist test.
[AQ-5] adminSecurityEventsHandler -- side-effect coverage only, no dedicated test.
[AQ-6] admin_mfa tests -- strong RBAC assertions (pass).

---

## 6. Semantic Analysis

[SEM-1] loginHandler double-query MFA check (correctness, low risk).
[SEM-2] tryAPIKeyAuth function selection (pass).
[SEM-3] rotateSecretHandler TOCTOU (pass).
[SEM-4] adminDisableUserHandler TOCTOU (pass).
[SEM-5] Handlers do not recheck disabled-user status (security-critical).
[SEM-6] ForcePasswordReset allowlist uses string suffix matching (security-critical, fragile but not exploitable).
[SEM-7] lockoutManager.Check fails open on DB errors (security-critical, no regression test).

---

## 7. Production Bug Candidates

[BUG-1] No production bugs found in auth/crypto packages.
[BUG-2] lockout fail-open design assumption should have a regression test.

---

## 8. Priority Remediation

### P0 -- Security-Critical
1. Add tests for admin user management endpoints
2. Add test for adminConfigHandler secret redaction
3. Add test for redactSecret
4. Add test for tryAPIKeyAuth revoked-key detection
5. Add test for API key auth with disabled user
6. Add test for buildMFARequiredReasons fail-closed behavior
7. Add test for refreshHandler theft detection path

### P1 -- Correctness
8. Add ParseEnrollmentToken unknown-key rejection test
9. Add VerifyPassword invalid-base64 test cases
10. Add admin delivery list/retry tests
11. Add ForcePasswordReset /auth/logout allowlist test
12. Add dedicated disabled-user middleware test

### P2 -- Nice-to-Have
13. Add parseQueryDate unit tests
14. Add pauseFeedHandler/resumeFeedHandler tests
15. Add AddHealthCheck test