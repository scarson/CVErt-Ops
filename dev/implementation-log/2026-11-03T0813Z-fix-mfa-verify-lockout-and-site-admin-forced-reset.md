# Fix — MFA Verify Lockout and Site-Admin Forced Reset

> **Date:** 2026-11-03
> **Branch:** `claude/wonderful-kepler-bbbe0e` (from `dev` at `3dd8f62`)

Two backend gaps that the SPA MFA sign-in design review (`dev/plans/2026-11-03-spa-mfa-sign-in-design.md`, "Out of scope" section) left for a separate change.

## What was built

| Feature | Files | Description |
|---|---|---|
| Verify honors lockout | `internal/api/auth_mfa.go`, `internal/api/lockout.go` | `mfaVerifyHandler` calls `srv.lockout.Check` before checking a code and returns the login lockout 429 (shared `accountLockedError`); a wrong code that locks the account emits `auth.account_locked` |
| Password login keeps MFA failures | `internal/api/auth.go` | `loginHandler` resets the lockout counter only when no `mfa_challenge` is pending; `mfaVerifyHandler` resets it after the challenge passes |
| Shared forced reset | `internal/api/admin_mfa.go`, `internal/api/admin_users.go` | `srv.forcePasswordReset` sets the flag (an already-set flag is not an error), increments `token_version`, and deletes remember-device tokens; the org-level and site-admin handlers both use it |
| Site-admin reset guards | `internal/api/admin_users.go` | Rejects self-target and OAuth-only accounts with 400 and emits `auth.password_reset_forced`, as the org-level handler does |
| Tests | `internal/api/auth_mfa_lockout_test.go`, `internal/api/admin_users_test.go`, `internal/api/admin_mfa_test.go` | Verify refused while locked; re-login does not clear MFA failures; MFA success clears them; site-admin reset ends sessions, deletes device tokens, emits the event, rejects self and OAuth-only targets; repeated resets return 200 on both paths |

## Key implementation decisions

- **Login reset deferred, not a second counter** — password and MFA failures share `users.failed_login_count`. A verify-side check alone left a bypass: guess codes up to one below the threshold, log in again with the password, repeat. Deferring the reset closes it without a schema change. Cost: password typos before a successful password login now count against the MFA attempts that follow, until MFA passes.
- **No cap on TOTP challenge renewal** — `POST /auth/mfa/challenge {method:"totp"}` still reissues the pending token. With the lockout enforced on verify and kept across re-login, guesses are bounded per account (threshold per lockout duration), whatever the pending token's lifetime, and re-login with the password already yields a fresh token.

## Gotchas discovered

- The org-level `adminForcePasswordResetHandler` returned 500 on a second reset of the same user: the `AdminForcePasswordReset` query matches only `force_password_reset = false`, so a repeat gets `sql.ErrNoRows`. The shared helper treats that as success and still invalidates sessions.
- gosec G101 flags a const whose name contains "Password"; the problem-detail const is named `noNativeIdentityProblem`.

## Quality checks

- **golangci-lint run ./internal/api/...:** 0 issues
- **Tests:** each new test failed before its fix (verify returned 200 instead of 429; site-admin reset left `token_version` unchanged, kept device tokens, emitted no event, and accepted self and OAuth-only targets; org repeat returned 500).
