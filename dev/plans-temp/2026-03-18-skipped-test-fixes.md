# Skipped Test Fixes — 2026-03-18

## Fix 1: OTP Rate Limit Bug (commit f307d26)

**Problem:** `CreateEmailOTPChallenge` did DELETE all existing email_otp challenges
before INSERT. Since the rate limiter (`CountRecentEmailOTPChallenges`) counts rows
in `mfa_challenges`, and the delete wiped history every time, the count was always
0 or 1. The per-hour rate limit could never trigger.

**Root cause:** The DELETE was intended to enforce single-active-code, but it
destroyed the rate-limit audit trail.

**Fix:**
- Removed the `DeleteEmailOTPChallenges` call from `CreateEmailOTPChallenge` in
  `internal/store/mfa.go`. Challenges now accumulate in the table.
- Added `ORDER BY created_at DESC` to `GetActiveEmailOTPChallenge` and
  `GetActiveEmailOTPChallengeForUpdate` SQL queries so verification always checks
  the most recent code (not an arbitrary row).
- Updated the store test `TestMFAChallenge_RateLimiting` to expect count=3 after
  3 creates (was expecting count=1 due to the buggy delete).
- Regenerated sqlc.

**Files changed:**
- `internal/store/mfa.go` — removed delete call, updated comment
- `internal/store/queries/mfa.sql` — added ORDER BY to two queries
- `internal/store/generated/mfa.sql.go` — regenerated
- `internal/store/mfa_test.go` — fixed expected count
- `internal/api/auth_mfa_test.go` — un-skipped `TestEmailOTPSetup_RateLimit`

**Test un-skipped:** `TestEmailOTPSetup_RateLimit`

## Fix 2: MFA Reasons in PendingClaims (commit 4a7a4b6)

**Problem:** Users who need MFA enrollment get a pending token but can't call
`/auth/mfa/methods` (which requires a full access token) to see WHY MFA is
required (org policy, per-member mandate, site admin policy).

**Fix:**
- Added `MFARequiredReason` type to `internal/auth/jwt.go` with `Source` and
  `OrgName` fields.
- Added `Reasons []MFARequiredReason` field to `PendingClaims`.
- Added `reasons` parameter to `IssuePendingToken` — updated all 22 call sites
  across production code and tests.
- At login and password-reset, when pending includes `mfa_challenge` or
  `mfa_enrollment_required`, `buildMFARequiredReasons` is called and the results
  are embedded in the token.
- Removed the duplicate local `mfaRequiredReason` type from `auth_mfa.go`,
  replaced all references with `auth.MFARequiredReason`.
- Rewrote both skipped tests to parse the pending token's claims directly instead
  of calling `/auth/mfa/methods`.

**Files changed:**
- `internal/auth/jwt.go` — new type + field + parameter
- `internal/auth/jwt_test.go` — updated 9 call sites
- `internal/api/auth.go` — build reasons at login, pass to IssuePendingToken
- `internal/api/auth_mfa.go` — use auth.MFARequiredReason, pass reasons through reissue
- `internal/api/auth_mfa_test.go` — rewrote 2 tests, updated 7 call sites
- `internal/api/auth_password_reset.go` — build reasons, pass to IssuePendingToken
- `internal/api/middleware_auth_test.go` — updated 1 call site

**Tests un-skipped:**
- `TestMFAMethods_RequiredReasons_SiteAdmin`
- `TestMFAMethods_RequiredReasons_MultiOrg`

## Verification

All three previously-skipped tests pass. Full test suites for `internal/api`,
`internal/auth`, and `internal/store` pass with 0 failures.
