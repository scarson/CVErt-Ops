# Fix — Change-Password Pending-Step Order

> **Date:** 2026-11-03
> **Branch:** `claude/change-password-pending-order`

`POST /auth/change-password` in restricted mode accepted a pending token when `password_reset` appeared anywhere in its pending list. Login for a user with MFA and `force_password_reset` issues `["mfa_challenge", "password_reset"]`, so a holder of the password alone could change it before passing MFA: the password changed, `force_password_reset` was cleared, remember-device tokens were deleted, and the real user was locked out. The handler now resolves the pending token through `validatePendingToken(token, "password_reset")`, which requires the step to be `Pending[0]`, as the MFA challenge and verify endpoints already do (phase 11 MFA design, "Fixed completion order (most sensitive first)").

## Other pending-token consumers

- **MFA challenge and verify** (`validatePendingToken(…, "mfa_challenge")`) and **enrollment setup/confirm via pending token** (`resolveEnrollmentUserID`) already require their step at `Pending[0]`.
- **Enrollment confirm trusted any pending cookie**: `clearEnrollmentPending`, called after TOTP and email OTP confirm, parsed the `mfa_pending_token` cookie without checking `Pending[0]`, the token version, or that the token's user was the user who enrolled. `resolveEnrollmentUserID` tries the access token first and never looked at the cookie then, so a request with one account's access token and another account's pending cookie removed `mfa_enrollment_required` from the second account's token and issued it full tokens without that account enrolling a factor. The email OTP setup handler likewise reissued any pending cookie with a fresh TTL. `resolveEnrollmentUserID` now also returns the pending claims, set only when the cookie passes `validateEnrollmentPendingToken` (next step `mfa_enrollment_required`, `token_version` equal to the DB value) and belongs to the resolved user. `clearEnrollmentPending` and the email OTP setup reissue act only on those claims. A cookie that fails these checks alongside a valid access token is ignored, not rejected, so a stale cookie from another login in the same browser does not block the signed-in user's own enrollment. Enrollment does not change `token_version`, so the claims validated before the credential is stored are still current when the step is cleared.
- **Stale pending tokens could change the password**: the restricted change-password path did not compare the pending token's `token_version` with the DB, unlike MFA verify and enrollment. It now returns 401 on a mismatch.

## Quality checks

- **golangci-lint:** 0 issues on `internal/api`
- **Tests:** `internal/api` password, forced-reset, enrollment-order and pending-token tests (40) pass with `TESTCONTAINERS_RYUK_DISABLED=true`, including `TestChangePassword_RestrictedSession_PendingTokenHasFreshTokenVersion` (pending `["password_reset", "mfa_enrollment_required"]`). Full suite not run.
- **New test:** `TestForcedPasswordReset_RejectsChangeBeforeMFA` — failed with 200 before the fix, passes with 401 after; also checks the password hash and `force_password_reset` are unchanged
- **Enrollment and token_version follow-up:** `internal/api` enrollment, email OTP, TOTP, change-password and forced-reset tests (47) pass. New tests, each seen failing first: `TestEnrollmentConfirm_IgnoresOtherUsersPendingToken` (another account's cookie got an access token), `TestEnrollmentConfirm_IgnoresOutOfOrderPendingToken`, `TestEmailOTPSetup_IgnoresOtherUsersPendingToken`, `TestChangePassword_RestrictedSession_RejectsStaleTokenVersion` (got 200)
