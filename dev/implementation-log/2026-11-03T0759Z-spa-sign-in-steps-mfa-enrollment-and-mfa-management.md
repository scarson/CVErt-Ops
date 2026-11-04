# SPA Sign-In Steps, MFA Enrollment and MFA Management

**Date:** 2026-11-03
**Branch:** `claude/spa-mfa-sign-in`
**Design:** `dev/plans/2026-11-03-spa-mfa-sign-in-design.md` (sign-in steps on `/login`, shared enrollment component, `/settings/account`, six backend session fixes)

## What was built

| Part | Files | Description |
|---|---|---|
| Session cookie hygiene | `internal/api/auth.go`, `auth_mfa.go`, `auth_password_reset.go`, `oauth_*.go` | Pending logins expire `access_token`/`refresh_token`; every full-token issuance and logout expire `mfa_pending_token`/`mfa_enroll_token` (`clearSignInCookies`) |
| Typed sign-in 401s | `internal/api/contract.go` (`typedProblem`), `auth.go`, `auth_mfa.go` | `urn:cvert:error:pending-session-invalid`, `invalid-code`, `invalid-password`, `enrollment-expired` |
| Backend fixes | `auth_mfa.go`, `auth.go`, `auth_password_reset.go` | TOTP setup renews the pending token; `/auth/me` reports `has_password`; forgot-password reset clears `force_password_reset` |
| Tests | `internal/api/auth_session_test.go` | 16 integration tests for the above |
| API client | `web/src/lib/api/client.ts`, `problems.ts` | Refresh skip list limited to sign-in endpoints; typed 401s pass through; 403 `password_change_required` handler |
| Auth store | `web/src/stores/auth.ts` | `pendingSteps`, `mfaMethods`, `signInEmail`, `signInNotice`; step actions (challenge, verify, forced change, finish, expire, cancel) |
| Sign-in steps | `web/src/views/LoginView.vue`, `web/src/components/auth/*` | MFA check, forced password change and mandatory enrollment rendered on `/login` |
| MFA components | `web/src/components/mfa/*` | `MfaEnrollment` (TOTP QR via `uqr`, secret key, email OTP), `RecoveryCodesDisplay` |
| Account page | `web/src/views/AccountView.vue`, `web/src/components/account/*`, router, `UserMenu.vue`, `main.ts` | Password change, MFA methods, recovery codes; forced-reset routing |

## Key implementation decisions

- **Steps stay on `/login`.** The pending token is an HttpOnly cookie and `methods` exist only in the login response, so a reload restarts at the password form.
- **Enrollment completes sign-in.** Confirm responses carry no `pending`; enrollment is always the last step, so a successful restricted confirm means full cookies are set.
- **Another user's pending cookie is ignored, not rejected**, following scarson/CVErt-Ops#145 (merged while this branch was open). This branch's first draft rejected the request instead.
- **`/auth/me` now refreshes on 401.** Before, a reload after the 15-minute access token expired showed a user with a valid refresh token as logged out.
- **`uqr`** renders the QR as an SVG data URL in an `<img>` (no `v-html`); dependency check passed (zero dependencies, MIT, no advisories).

## Gotchas discovered

- **The OpenAPI generator is `GENERATE_OPENAPI=1 go test ./internal/api -run '^TestOpenAPISpec$'`.** The served `/api/v1/openapi.json` alone lacks the spec-only Chi operations.
- **`npm install` on this host strips `libc` fields from `package-lock.json`** that a newer npm wrote; restore the lockfile instead of committing that churn.
- **The dev stack did not start** (`postgres:18-alpine` rejects the compose data mount; `serve` hung after migrations), so no in-browser check was possible.

## Quality checks

- **Go:** the 178 tests in the touched auth test files passed before the merge with dev (666 s); after the merge, 24 targeted tests (this branch's 16 plus the #143/#145 tests and the full TOTP, enrollment and forced-reset flows) pass. `golangci-lint` on `internal/api` reported only a G101 false positive on a problem-type URN, suppressed inline. Full `internal/api` suite and post-merge lint left to CI at Sam's request (host under load).
- **Web:** `npm run type-check` and `npm run lint` clean; before the merge the full unit suite passed (528 tests, no warnings); after the merge the 18 touched test files pass (205 tests).
