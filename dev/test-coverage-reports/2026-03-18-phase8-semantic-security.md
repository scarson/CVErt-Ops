# Phase 8 Semantic Security Analysis

> **Date:** 2026-03-18
> **Scope:** Security-critical code across Phase 8 packages
> **Sections:** 4B-E (semantic analysis) + 5 (assertion quality audit)

---

## Summary

| Severity | Count |
|----------|-------|
| Security-critical | 12 |
| Correctness | 8 |
| Nice-to-have | 3 |
| Assertion quality | 5 |
| **Total** | **28** |

---

## 4B -- Right-function-called Analysis

### Auth middleware reads from configHolder correctly

The jwtSecret() and jwtPreviousSecretBytes() methods on Server correctly read from srv.configHolder.Load() first, falling back to srv.cfg. Test TestRequireAuthenticated_ReadsFromConfigHolder verifies this end-to-end.

**Verdict:** Correctly tested. The hot-reload config indirection pitfall (testing-pitfalls 15) is covered.

### Store methods use correct transaction helpers

All security event store methods correctly use withBypassTx. MFA credential/recovery/challenge methods use withBypassTx. MFA requirements use withOrgTx. No wrong-function-called issues found.

### adminForcePasswordResetHandler calls IncrementTokenVersion separately

In admin_mfa.go:137, the handler calls IncrementTokenVersion and DeleteRememberDeviceTokens in separate transactions -- see TOCTOU-1.

---

## 4C -- TOCTOU Windows

### TOCTOU-1: adminForcePasswordResetHandler -- non-atomic multi-step

admin_mfa.go:130-147 performs three separate operations in independent transactions. Architecturally inconsistent with ResetUserMFA which uses a single transaction.

**Severity:** Correctness.

### TOCTOU-2: Email OTP challenge rate limiting (count-then-insert)

store/mfa.go:482 CountRecentEmailOTPChallenges counts first, then the handler creates. Concurrent requests can exceed the limit.

**Severity:** Security-critical -- exact pattern from testing-pitfalls 1.

### TOCTOU-3 and TOCTOU-4: TOTP replay and recovery codes are correctly atomic.

---

## 4D -- Defense-in-depth Analysis

### DID-1: Disabled user JWT rejection -- middleware test gap

No test verifies a disabled user with a valid JWT cookie is rejected at the middleware level (not just at login). **Severity:** Security-critical.

### DID-2: Site admin bypass in admin MFA RBAC -- untested path

checkAdminMFAPermission has a site admin bypass (lines 413-421) with no test. **Severity:** Security-critical.

---

## 4E -- Store-layer Independence

- InsertSecurityEvent: no direct store test (indirectly via EventWriter)
- ListSecurityEvents: no direct store test (indirectly via API handler)
- AdminDisableUser/EnableUser/UnlockUser/ForcePasswordReset: no store tests
- DeleteAllRecoveryCodes: indirect only via RegenerateRecoveryCodes
- CountMFACredentialsByUser: no direct test

---

## Security-Critical Gaps (12)

1. No middleware test for disabled user JWT rejection -- source: semantic
2. No test for site admin bypass in admin MFA RBAC -- source: semantic
3. Email OTP rate limit bypass under concurrency -- source: semantic (TOCTOU)
4. No store-level test for InsertSecurityEvent -- source: semantic
5. No store-level test for ListSecurityEvents -- source: semantic
6. Admin security events test lacks field-level assertions -- source: assertion
7. No unauthenticated->401 test for admin security events -- source: semantic
8. No unauthenticated->401 test for admin reload-config -- source: semantic
9. No admin user management handler tests (admin_users_test.go missing) -- source: coverage
10. adminDisableUserHandler self-disable check untested -- source: semantic
11. Admin enable/unlock/reset-password no idempotency tests -- source: semantic
12. No test for disabled user rejection via API key auth path -- source: semantic

## Correctness Gaps (8)

1. adminForcePasswordResetHandler uses three separate transactions
2. No direct store test for AdminDisableUser
3. No direct store test for AdminEnableUser
4. No direct store test for AdminUnlockUser
5. No direct store test for AdminForcePasswordReset
6. No direct store test for DeleteAllRecoveryCodes
7. No direct store test for CountMFACredentialsByUser
8. No direct store test for AdminListUsers with cursor pagination

## Nice-to-Have (3)

1. Rate limiter eviction test uses loose threshold
2. No test for SIEM syslog format change after config reload
3. cefEscape function not tested with pipe character

## Assertion Quality Issues (5)

1. TestAdminSecurityEvents_ReturnsEvents asserts count only, not fields
2. TestEventRateLimiter_TTLEviction loose threshold
3. Config reload consumer tests cover JWT only (SMTP/syslog missing)
4. TestAdminForcePasswordReset does not verify session invalidation
5. TestAdminMFAReset does not verify challenges are deleted

---

## Production Bugs Discovered

No new production bugs. Two cross-handler pattern violations found:
- adminEnableUserHandler does NOT emit any security event (siblings do)
- adminResetPasswordHandler does NOT emit any security event

These are in untested code (no admin_users_test.go).

---

## What is Well-Covered

- JWT dual-key rotation: excellent coverage across all four token types
- Crypto DecryptWithFallback: all key combinations with error discrimination
- Admin MFA RBAC hierarchy: comprehensive permutation testing
- Config hot-reload merge semantics: absent fields preserve baseline values
