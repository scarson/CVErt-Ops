# Bug Hunt Report — Phase 11: MFA (Multi-Pass)

## Scope
Packages/files analyzed: `internal/store/mfa.go`, `internal/api/auth_mfa.go`, `internal/api/admin_mfa.go`, `internal/api/auth.go` (login + change-password handlers), `internal/api/middleware_auth.go`, `internal/auth/jwt.go`, `internal/config/config.go`, `internal/notify/render.go`, `internal/secure/events.go`, `internal/worker/pool.go`, `internal/store/queries/mfa.sql`, `internal/store/queries/org.sql`, `migrations/000040_create_mfa_tables.up.sql`, `migrations/000040_create_mfa_tables.down.sql`, `cmd/cvert-ops/main.go`.

Design reference: `dev/plans/2026-03-16-phase11-mfa-totp-email-otp-design.md`

All five passes performed: Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

## Bugs

### 1. Password reset flow does not check MFA status (MFA bypass)
**Location:** `internal/api/auth_password_reset.go:181-237` (resetPasswordHandler)
**Severity:** critical
**Evidence:** The design doc (Authentication Flow, Password Reset Interaction) explicitly states: after a forgot-password flow completes, MFA status is checked and if the user has MFA credentials, a pending token with `["mfa_challenge"]` is issued. The actual `resetPasswordHandler` changes the password and returns a bare `resetPasswordOutput{}` with no MFA check, no pending token, and no session tokens. A user who completes a password reset via email token completely bypasses MFA.
**Impact:** An attacker who gains access to the email account can reset the password and fully authenticate without ever completing MFA challenge. This defeats the purpose of TOTP enrollment entirely.
**Found in:** Pass 1 -- Contract Violations

### 2. Change password in restricted session uses stale token_version for pending token reissue
**Location:** `internal/api/auth.go:900-913` (changePasswordHandler, restricted session branch)
**Severity:** significant
**Evidence:** After `UpdatePasswordHash` increments `token_version` (line 858), the handler reissues the pending token on line 903-905 using `pendingClaims.TokenVersion` -- the old token version from the pre-increment pending token. The next step (e.g., `mfa_enrollment_required`) validates `token_version` against the DB, which now has a higher value. The freshly issued pending token will fail validation on the next step.
**Impact:** Users with `["password_reset", "mfa_enrollment_required"]` pending will complete the password reset but be unable to proceed to MFA enrollment. They get stuck in a login loop.
**Found in:** Pass 3 -- Failure Mode Reasoning

### 3. Admin MFA reset deletes device tokens redundantly and non-atomically
**Location:** `internal/api/admin_mfa.go:54-74` (adminResetMFAHandler)
**Severity:** minor
**Evidence:** The handler calls both `DeleteAllUserChallenges` (line 65, which deletes ALL challenges including remember_device) and then separately `DeleteRememberDeviceTokens` (line 70). `DeleteAllUserChallenges` uses `DELETE FROM mfa_challenges WHERE user_id = $1` which already covers remember_device rows. More importantly, all four delete operations run as separate transactions (each in its own `withBypassTx`), not atomically. If the process crashes between deleting credentials and deleting recovery codes, the user is left with orphaned recovery codes but no MFA methods.
**Impact:** Orphaned state on partial failure. The redundant call is wasteful but not incorrect.
**Found in:** Pass 3 -- Failure Mode Reasoning

### 4. resolveEnrollmentUserID does not validate token_version against DB
**Location:** `internal/api/auth_mfa.go:1149-1173` (resolveEnrollmentUserID)
**Severity:** significant
**Evidence:** For enrollment endpoints (TOTP setup/confirm, email OTP setup/confirm), `resolveEnrollmentUserID` extracts the user ID from a pending enrollment token but never validates `token_version` against the DB. Compare this to `mfaVerifyHandler` (line 178-183) which explicitly checks `user.TokenVersion != claims.TokenVersion`. An admin could force-reset a user (incrementing token_version) while the user has an active enrollment session, and the stale pending token would still be accepted.
**Impact:** Enrollment proceeds with a stale/invalidated session. This violates the session invalidation guarantee that `IncrementTokenVersion` is supposed to enforce.
**Found in:** Pass 2 -- Cross-Sibling Pattern Violations

### 5. clearEnrollmentPending fails to issue full auth tokens when all pending items are cleared
**Location:** `internal/api/auth_mfa.go:1216-1236` (clearEnrollmentPending)
**Severity:** significant
**Evidence:** The comment on line 1233-1234 acknowledges the problem: it cannot issue full tokens because it lacks the user object. When the user completes enrollment and all pending items are cleared, the handler only clears the pending cookie -- it does NOT issue access/refresh tokens. Compare this to `mfaVerifyHandler` (line 279-285) which properly calls `issueFullAuthTokens` when remaining is empty. Compare also to `changePasswordHandler` (line 916-928) which re-reads the user and issues full tokens.
**Impact:** Users forced to enroll MFA (via `mfa_enrollment_required` pending) who succeed get kicked back to the login page with no session. They must re-enter credentials and complete MFA challenge again.
**Found in:** Pass 2 -- Cross-Sibling Pattern Violations

### 6. Email OTP enrollment setup does not reissue pending token with fresh TTL
**Location:** `internal/api/auth_mfa.go:720-775` (mfaEmailOTPSetupHandler)
**Severity:** minor
**Evidence:** When called from a restricted enrollment session, the email OTP setup handler returns an empty output (line 774). It does not reissue the pending token with a fresh TTL. The pending token has a 5-minute TTL. If the user triggers setup near expiry, the pending token may expire before the email arrives and the user submits the code. Compare with `mfaChallengeHandler` (line 134-141) which always reissues the pending token with fresh TTL.
**Impact:** Race condition where the pending token expires between email OTP setup and confirm during enrollment, forcing restart.
**Found in:** Pass 2 -- Cross-Sibling Pattern Violations

### 7. mfa_enrollment_token cookie path wider than design spec
**Location:** `internal/api/auth_mfa.go:1188-1200` (enrollmentTokenCookies)
**Severity:** minor
**Evidence:** The design doc specifies the enrollment cookie path as `/api/v1/auth/mfa`. The implementation sets the path to `/api/v1/auth` (line 1193). The enrollment cookie is sent with ALL auth requests rather than only MFA endpoints.
**Impact:** Slightly increased attack surface -- the enrollment token (containing encrypted TOTP secret) is transmitted with more requests than necessary.
**Found in:** Pass 1 -- Contract Violations

### 8. mfaMethodsOutput returns flat string reasons instead of structured objects per design spec
**Location:** `internal/api/auth_mfa.go:857-909` (mfaMethodsHandler, mfaMethodsOutput struct)
**Severity:** minor
**Evidence:** The design doc specifies `required_reasons` as an array of objects with `source` and `org_name` fields. The implementation returns `RequiredReasons []string` -- just string tags like `"site_admin"`, `"org_owner"`, `"org_policy"`, `"per_member"` without the associated org name.
**Impact:** Users in multiple orgs cannot tell which org mandates MFA. The enforcement is correct but the API response deviates from the design spec.
**Found in:** Pass 1 -- Contract Violations

## Design Concerns

### Non-atomic admin MFA reset
The `adminResetMFAHandler` performs 5 separate database operations (delete credentials, recovery codes, challenges, device tokens, increment token_version) each in its own `withBypassTx`. A failure partway through leaves orphaned state. A single transaction wrapping all operations would be more robust.

### TOTP replay prevention race window
The `verifyTOTP` function (auth_mfa.go:362-406) validates the code, checks `last_used_step`, then updates `last_used_step` -- all in separate store calls, each in their own transaction. Two concurrent requests with the same valid TOTP code could both pass the `last_used_step` check before either writes the update. The `FOR UPDATE SKIP LOCKED` pattern used for recovery codes is not applied to TOTP credential verification. In practice, the 30-second TOTP window makes this a narrow race, but it is architecturally inconsistent with the more careful recovery code handling.

### Password change invalidates pending token it just reissued
In `changePasswordHandler`, `UpdatePasswordHash` increments `token_version`, but the reissued pending token uses the old `token_version`. This is Bug #2, but also a design concern: any handler that both increments token_version AND reissues a pending token needs to use the post-increment version. The current architecture does not make this relationship obvious or enforced.

### UpdateOrgMFASettings uses direct s.q instead of transaction helper
`store/org.go:40-54`: `UpdateOrgMFASettings` calls `s.q.UpdateOrgMFASettings` directly on the non-transactional Queries object, unlike all other org-scoped methods which use `withOrgTx`. The query has a `WHERE deleted_at IS NULL` guard that provides safety, but this is inconsistent with the established pattern where org mutations always go through a transaction helper.
