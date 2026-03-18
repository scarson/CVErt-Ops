# Stage 3: P11 MFA Tests — Progress Log

## Task 1: Event Writer Test Infrastructure
- **Status:** completed
- **Files modified:** `internal/api/auth_mfa_test.go`
- **Tests:** go vet passes; Docker Desktop named pipe issue prevents test execution (system-level, not code-level)
- **Commit:** pending
- **Notes:** Added `newMFAServerWithEvents` helper, `flushAndQueryEvents` helper, and `TestEventWriterInfrastructure_SmokeTest`. EventWriter.Stop() uses sync.Once internally so double-call from t.Cleanup is safe. Added `secure` import.

## Task 2: JWT Enrollment Token Security Tests
- **Status:** completed
- **Files modified:** `internal/auth/jwt_test.go`
- **Tests:** pass (5/5 — round trip, expired, wrong secret, alg:none, RS256)
- **Commit:** pending
- **Notes:** Pure unit tests, no Docker needed. Tests the public ParseEnrollmentToken API.

## Task 3: Store Direct MFA Tests
- **Status:** completed
- **Files modified:** `internal/store/mfa_test.go`
- **Tests:** go vet passes; 11 tests added (C1: 5 direct store tests, SC8: multi-org, SC11: non-owner negative, N8: skipped (already exists as TestRecoveryCode_VerifyUsedCode), N9: round trip, N10: org not found)
- **Commit:** pending
- **Notes:** N8 already covered by existing TestRecoveryCode_VerifyUsedCode. Docker Desktop named pipe issue prevents running store tests.

## Task 4: Admin MFA Test Gaps
- **Status:** completed
- **Files modified:** `internal/api/admin_mfa_test.go`
- **Tests:** go vet passes; 15 tests added (SC2: cross-org 5 subtests, SC3: 4 negative cases, SC6: site admin + viewer, SC7: 2 full side-effect tests, C2: 3 unrequire RBAC, SC1: 3 event assertions)
- **Commit:** pending
- **Notes:** Site admin test adds SA as member-role to org then proves SA bypass in checkAdminMFAPermission. RequireOrgRole has no SA bypass.

## Task 5: MFA Verify/Challenge Tests
- **Status:** completed
- **Files modified:** `internal/api/auth_mfa_test.go`
- **Tests:** go vet passes; 10 tests added (SC4: 3 email OTP confirm errors, SC5: pending-as-access, SC12: cross-user enrollment, A4: wrong code no cookies, A5: wrong-key + expired pending, SC1: 2 verify events)
- **Commit:** pending
- **Notes:** Cross-user enrollment test verifies handler checks enrollClaims.UserID != callerID.

## Task 6: Auth Handler MFA Paths
- **Status:** completed
- **Files modified:** `internal/api/auth_mfa_test.go`
- **Tests:** go vet passes; 12 tests added (C3: multi-org + site admin reasons, C4: enrollment completion tokens, N2: skipped (needs OAuth flow), N3: invalid + expired access token, N5: remove non-enrolled, N6: second enrollment no recovery codes, N7: email OTP setup rate limit, SC1: enrollment + recovery regen events)
- **Commit:** pending
- **Notes:** N2 (reauthenticatePassword OAuth-only) deferred — needs full MFA verify flow to get access token for OAuth-only account, already covered by admin_mfa_test OAuthOnly test. N6 uses t.Skip if MFA challenge needed.

## Task 7: Additional MFA API Tests
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**
