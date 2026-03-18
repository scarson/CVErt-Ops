# Bug Hunt Report — Phase 11: MFA (Exploratory)

## Scope

Phase 11 MFA implementation: TOTP enrollment/verification, email OTP challenges, one-time recovery codes, forced password reset via restricted JWT sessions, 3-layer enforcement, remember-device tokens, admin MFA management, periodic challenge cleanup worker.

**Files explored deeply (risk-prioritized):**
- internal/api/auth_mfa.go — MFA challenge/verify/enrollment/management handlers. High-risk: multi-step JWT flows, token version coordination, enrollment authorization.
- internal/api/auth.go — Login flow (MFA gating, pending token ordering, remember-device validation). High-risk: pending array construction, forced-reset interaction, change-password token version stale-read.
- internal/api/admin_mfa.go — Admin MFA reset, force-password-reset, per-member requirements, org MFA settings. High-risk: RBAC hierarchy, non-atomic multi-step deletion.
- internal/auth/jwt.go — JWT issuance/parsing for pending, enrollment, access, and refresh tokens. High-risk: dual-key rotation gap in pending/enrollment tokens.
- internal/store/mfa.go — Store methods for credentials, recovery codes, challenges, requirements. High-risk: transaction helper usage, mandate check layers.
- internal/store/org.go — UpdateOrgMFASettings store method. High-risk: bare query without transaction helper.
- internal/store/queries/mfa.sql — SQL queries for all MFA operations.
- migrations/000040_create_mfa_tables.up.sql — Schema definition.
- internal/api/middleware_auth.go — Auth middleware force-password-reset enforcement.
- internal/config/config.go — MFA config fields.

**Files read but not deeply explored:** internal/api/server.go (route registration), internal/store/queries/org.sql (UpdateOrgMFASettings SQL).

## Bugs

### 1. Stale token_version in pending token after password change breaks subsequent MFA steps

**Location:** internal/api/auth.go:903-906 (changePasswordHandler)
**Severity:** significant
**Evidence:**

When a user completes the password_reset step in a restricted session and still has remaining pending items (e.g., mfa_enrollment_required), the handler:

1. Calls srv.store.UpdatePasswordHash() which executes SET ... token_version = token_version + 1 (confirmed in internal/store/queries/auth.sql:24)
2. Reissues the pending token using the OLD pendingClaims.TokenVersion (the value from the incoming JWT, which is now stale because the DB was just incremented)

The mfaVerifyHandler at line 182 validates int(user.TokenVersion) != claims.TokenVersion and rejects mismatched tokens. The enrollment handlers (resolveEnrollmentUserID) do not currently validate token_version, but the mfa_challenge handler does. When Bug 1 and Bug 2 are both fixed (enrollment enforces ordering AND token_version), the stale version will cause immediate lockout.

Even without Bug 2 being fixed, the stale token_version means the pending token is semantically wrong — it claims a token version that no longer exists in the DB.

**Impact:** Users who have both password_reset and mfa_enrollment_required pending (the "no MFA, mandated, forced reset" case from the design doc) will be locked out after completing the password reset step. The reissued pending token is immediately invalid because its embedded token_version is stale. The user must fully re-login to recover.

### 2. Enrollment endpoints skip pending order enforcement, allowing step-skipping

**Location:** internal/api/auth_mfa.go:1149-1173 (resolveEnrollmentUserID)
**Severity:** significant
**Evidence:**

resolveEnrollmentUserID checks whether "mfa_enrollment_required" exists ANYWHERE in the pending array (line 1164-1167, iterating with a for loop), rather than checking that it is the FIRST item (Pending[0]).

But the design doc specifies a fixed completion order: mfa_challenge then password_reset then mfa_enrollment_required. The middleware and other handlers enforce that Pending[0] is the current gate (e.g., validatePendingToken at line 322 checks claims.Pending[0] != expectedStep).

**Impact:** A user whose pending array is ["password_reset", "mfa_enrollment_required"] can skip the password reset and go directly to MFA enrollment. The password-reset step was designed to be completed BEFORE enrollment (so the user changes the compromised password first). This allows a user with a compromised password to enroll MFA without first changing it — the exact scenario the ordering was designed to prevent.

### 3. UpdateOrgMFASettings bypasses transaction helpers — bare query on pool connection

**Location:** internal/store/org.go:40-54 (UpdateOrgMFASettings)
**Severity:** significant
**Evidence:**

UpdateOrgMFASettings calls s.q.UpdateOrgMFASettings() directly without any transaction helper (no withOrgTx, no withBypassTx). Every other org-mutation store method uses a transaction helper. The convention documented in implementation-pitfalls.md and CLAUDE.md states: "Never query s.db directly in store methods — always use a transaction helper." The reason is not just RLS — it is also statement timeout enforcement, connection pool management, and consistent error handling.

Note: UpdateOrg on line 28 has the same pattern (bare s.q). Both should be fixed.

**Impact:** No RLS bypass (organizations table has no RLS), but the query runs without statement timeout enforcement. Under database contention or lock waits, this query could hold a pool connection indefinitely.

### 4. Admin MFA reset is non-atomic — partial cleanup on intermediate failure

**Location:** internal/api/admin_mfa.go:55-81 (adminResetMFAHandler)
**Severity:** minor
**Evidence:**

The admin reset handler runs 5 sequential store operations, each in its own withBypassTx:
1. DeleteAllMFACredentials — returns on error
2. DeleteAllRecoveryCodes — returns on error
3. DeleteAllUserChallenges — returns on error
4. DeleteRememberDeviceTokens — returns on error
5. IncrementTokenVersion — returns on error

If step 3 fails (e.g., transient DB error), credentials and recovery codes are already deleted, but challenges and device tokens remain, and the token version has not been bumped. The user is in an inconsistent security state: MFA non-functional (credentials gone), recovery codes deleted, but old sessions still valid (token version not bumped) and remember-device tokens still work.

**Impact:** On partial failure, the user is in an inconsistent security state. A retry by the admin would complete the cleanup since DELETE is idempotent, but the intermediate state is security-concerning. The design doc specifies this as a single atomic operation.

## Design Concerns

### Pending token and enrollment token do not support dual-key rotation

ParsePendingToken and ParseEnrollmentToken each take a single secret parameter, unlike ParseAccessToken and ParseRefreshToken which take both activeSecret and previousSecret for zero-downtime key rotation. During a JWT secret rotation, any user mid-MFA-flow (within the 5-minute pending token window) will be locked out. This is a narrow window but an asymmetry in the JWT layer.

### Enrollment cookie path is wider than design spec

The enrollment token cookie is set with Path "/api/v1/auth" (line 1193) but the design doc specifies Path "/api/v1/auth/mfa". The wider path means the cookie is sent with all auth requests, not just MFA requests. Minimal security impact (short-lived, HttpOnly, signed JWT) but violates least-privilege for cookie paths.

### Rate limiting for email OTP during enrollment shares the same counter as login MFA

The email OTP rate limit (CountRecentEmailOTPChallenges) counts all email_otp challenges for the user regardless of context. A user who used 4 of their 5 hourly OTP attempts during login will only have 1 attempt remaining for enrollment. Arguably correct (prevents abuse) but could confuse users.
