# SPA sign-in steps, MFA enrollment and MFA management — design

**Date:** 2026-11-03
**Branch:** `claude/spa-mfa-sign-in`, cut from `claude/openapi-statuses-and-artifacts-712d84` (the branch that first added the `/auth/mfa/*` types to `web/src/lib/api/schema.d.ts`).
**Backend reference:** `dev/plans/2026-03-16-phase11-mfa-totp-email-otp-design.md` — the MFA design the backend implements (pending-token model, fixed step order, enrollment flow, the frontend requirement to show both a QR code and the TOTP secret).

## Problem

`POST /auth/login` answers a user who has MFA, a forced password reset, or a mandated but missing MFA enrollment with `{ user_id, pending[], methods[] }` and an `mfa_pending_token` cookie instead of access and refresh cookies. `auth.login` in `web/src/stores/auth.ts` ignores `pending` and calls `GET /auth/me`, which returns 401 because there is no `access_token`, so LoginView shows "Login failed". No SPA code calls `/auth/change-password` or any `/auth/mfa/*` endpoint, so these users cannot sign in, and no user can enroll in or manage MFA.

A design review against the backend found six backend defects that the SPA cannot work around:

1. A pending login leaves an existing `access_token` cookie in place, and `resolveEnrollmentUserID` and `changePasswordHandler` read the access token before the pending token. With user A signed in and user B signing in from another tab, B's TOTP secret is enrolled on A's account and B receives a full session.
2. `/auth/mfa/verify`, the enrollment confirm endpoints, method removal and recovery-code regeneration return the same untyped 401 for "wrong code or password" and "session missing or expired".
3. `POST /auth/mfa/totp/setup` does not renew the 5-minute pending token (email OTP setup does), so a user reading the QR screen can run out of time.
4. `POST /auth/logout` does not clear `mfa_pending_token` or `mfa_enroll_token`, so a half-finished sign-in cannot be cancelled.
5. `GET /auth/me` does not say whether the account has a password, so the SPA cannot tell OAuth-only users that password-gated actions do not apply to them.
6. The forgot-password reset (`POST /auth/reset-password`) does not clear `force_password_reset`, so the user is made to change the password again.

## Requirements

**Requirements status: unconfirmed — revised after design review; user approved including backend defects 1–6 (2026-11-03).**

- **pending-sign-in** — A user whose login returns pending steps completes sign-in in the SPA, in the order the server returns, without leaving `/login`.
- **mfa-challenge** — The MFA step supports TOTP, email OTP (send and resend) and recovery codes, and offers remember-device when MFA is the last pending step.
- **forced-password-change** — During sign-in, a forced-reset user sets a new password without the current one. In a signed-in session flagged for reset, the user is routed to the account page and sets it there with the current one.
- **mandatory-enrollment** — A user who must have MFA can enroll TOTP or email OTP during sign-in.
- **mfa-management** — A signed-in user can view, add and remove MFA methods and regenerate recovery codes from `/settings/account`.
- **recovery-codes-once** — Recovery codes are shown once, with copy and download, and require an explicit acknowledgment; a missing code list produces a warning, not an empty list.
- **expired-session** — An expired or invalidated pending session returns the user to the password form with an explanation; a wrong code or password keeps the user on the current step.
- **cancel-sign-in** — A user can cancel a pending sign-in, which clears the pending and enrollment cookies.
- **session-isolation** — Enrollment and password change never act on a different user than the one completing the step.
- **checks-pass** — Built test-first; `npm run type-check`, `npm run test:unit -- --run`, `npm run lint`, `golangci-lint run` and the targeted Go tests pass.

## Design

### Backend changes

- **Cookie hygiene.** The pending branch of `loginHandler` and of the reset-password handler also expires `access_token` and `refresh_token`. Every path that issues full tokens (full login, MFA verify, password change, enrollment completion) also expires `mfa_pending_token` and `mfa_enroll_token`. `logoutHandler` expires all four cookies.
- **Another user's pending cookie is ignored.** When a valid access token is present, `resolveEnrollmentUserID` and `changePasswordHandler` act for the access token's user and neither use nor renew a pending token that belongs to someone else. This is the behaviour merged in scarson/CVErt-Ops#145 (bind enrollment pending tokens to the enrolling user); the cookie hygiene above makes the two cookies coexist only briefly.
- **Typed problems.** Huma handlers return problem `type` URNs on the 401s that the SPA must tell apart:
  - `urn:cvert:error:pending-session-invalid` — pending token missing, expired, at the wrong step, or with a stale `token_version` (challenge, verify, restricted enrollment, restricted password change).
  - `urn:cvert:error:invalid-code` — a wrong MFA or enrollment code.
  - `urn:cvert:error:invalid-password` — a wrong current password on re-authentication or password change.
  - `urn:cvert:error:enrollment-expired` — a missing or expired `mfa_enroll_token` on TOTP confirm.
  Access-token 401s keep the untyped form.
- **TOTP setup renews the pending token**, as email OTP setup already does.
- **`has_password`** is added to `MeOutputBody`.
- **Forgot-password reset clears `force_password_reset`**, as `changePasswordHandler` does.

`openapi.json` and `web/src/lib/api/schema.d.ts` are regenerated after these changes.

### API client (`web/src/lib/api/client.ts`)

- The 401-refresh middleware skips only endpoints where a refresh cannot help or must not run: `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/register`, `/auth/forgot-password`, `/auth/reset-password`, `/auth/verify-email`, `/auth/mfa/challenge`, `/auth/mfa/verify`. Everything else, including `/auth/me` and `/auth/mfa/methods`, is retried after a refresh. This keeps the account page working after the 15-minute access token expires.
- A 403 with problem type `password_change_required` calls a handler registered by the app, which routes to `/settings/account`.
- A helper `problemType(error)` returns the problem `type` so callers branch on the type, never on the status alone or the `detail` text.

### Auth store (`web/src/stores/auth.ts`)

- State: `pendingSteps: string[]`, `mfaMethods: string[]`. `login()` returns `{ success, pending, error }`; an empty or absent `pending` means the user is signed in and `fetchMe()` has run.
- Actions: `startMfaChallenge(method)`, `verifyMfa(method, code, rememberDevice)`, `changePassword({ currentPassword?, newPassword })`, the four enrollment calls, `fetchMfaMethods()`, `removeMfaMethod(method, password)`, `regenerateRecoveryCodes(password)`, `cancelSignIn()` (calls logout and resets the step state). Each step action stores the `pending` the server returns and calls `fetchMe()` when it is empty. Enrollment confirm responses carry no `pending`; because enrollment is always the last step in the server's fixed order, a successful restricted confirm completes sign-in.

### Sign-in steps (LoginView)

LoginView renders the password form while `pendingSteps` is empty and otherwise the component for `pendingSteps[0]`. A page refresh restarts at the password form: the pending token is an HttpOnly cookie the SPA cannot read, and the server lets the user sign in again. Each step has a Cancel action (`cancelSignIn`). When a step mounts, focus moves to its heading; errors render in an `aria-live` region.

- **`MfaChallengeStep`.** Method choice when more than one method is enrolled, defaulting to TOTP. Choosing TOTP calls `challenge {method: "totp"}`, which renews the pending token. Choosing email shows "Email me a code"; after sending it offers Resend and says only the newest code works. The 429 detail is shown as returned. "Use a recovery code" switches the input. Code inputs use `autocomplete="one-time-code"` and `inputmode="numeric"`; recovery codes are trimmed. "Remember this device for N days if your organization allows it" is shown only when `pendingSteps` is exactly `["mfa_challenge"]`. `invalid-code` keeps the user on the step; after the third failed email code the message says to request a new code. `pending-session-invalid` resets to the password form with "Your sign-in session expired. Sign in again."
- **`ForcedPasswordStep`.** New password and confirmation, at least 16 characters, with a hidden `autocomplete="username"` field carrying the email so password managers save the right entry.
- **`MfaEnrollStep`.** States that MFA is required and renders `MfaEnrollment` in restricted mode.

### Shared components

- **`MfaEnrollment`** (`web/src/components/mfa/`). Method choice limited to methods not yet enrolled.
  - TOTP: calls setup, renders the QR code as an `<img>` whose `src` is an SVG data URL built from `qr_code_uri` with `uqr`, offers "Can't scan? Show secret key" with a copy button, then a 6-digit confirmation. `enrollment-expired` restarts setup with a message that the previous code is no longer valid.
  - Email OTP: sends the code to the account address, then confirms it.
  - On success it emits the returned recovery codes (possibly none).
- **`RecoveryCodesDisplay`.** Lists the codes in a monospace grid with Copy all and Download `.txt` (a client-side Blob). Continue is disabled until "I have saved these codes" is checked. With no codes it shows a warning that codes could not be generated and points to Regenerate on the account page.

### Account page (`/settings/account`, `AccountView`)

Linked from the user menu; `requiresAuth: true`, `requiresOrg: false`.

- **Password section.** Current, new and confirm fields. On success the SPA signs the user out and shows "Password changed. Sign in again." (the backend bumps `token_version` without reissuing cookies, so the session would end at the next refresh). For `has_password: false` the section explains that the account signs in through an external provider.
- **Two-factor authentication section.** From `GET /auth/mfa/methods`: enrolled methods with enrollment dates, "Required by" reasons, an Add action that opens `MfaEnrollment`, and Remove behind `PasswordConfirmDialog`; a 403 for the last mandated method shows the server detail. For `has_password: false`, Remove and Regenerate are replaced by an explanation.
- **Recovery codes section.** Remaining count, with a warning at 2 or fewer, and Regenerate behind `PasswordConfirmDialog`, followed by `RecoveryCodesDisplay`.
- **Forced reset while signed in.** The router guard sends a user whose `/auth/me` reports `force_password_reset` to `/settings/account` for every route except it; the page then shows only the password section with an explanation.

### Dependency

`uqr` (UnJS, zero dependencies, a TypeScript port of Nayuki's reference QR encoder) renders the TOTP QR code. It passes `/dependency-check` before it is added.

## Decision log

- **sign-in-on-login-route** — **Decision:** sign-in steps render inside LoginView, switched on `pendingSteps[0]`. **Alternatives:** one route per step; a single `/login/continue` route. **Why:** the pending state cannot survive a reload (HttpOnly cookie, methods only in the login response), so any separate route needs a bounce back to `/login` on reload; keeping the steps on `/login` makes reload behave correctly with no guard logic. **Revisit if:** the backend exposes the pending state through an endpoint.
- **backend-fixes-in-scope** — **Decision:** fix backend defects 1–6 in this branch as separate test-first commits before the SPA commits. **Alternatives:** SPA-only work with client-side workarounds; a separate backend PR first. **Why:** without them the SPA either inherits the cross-account enrollment bug or branches on `detail` strings. Approved by Sam on 2026-11-03.
- **other-users-pending-cookie** — **Decision:** clear the other kind of session cookie on every login, and when an access token is present ignore a pending token that belongs to another user. **Alternatives:** reject the request with 401 when the two tokens name different users (this design's first draft); always prefer the pending token. **Why:** scarson/CVErt-Ops#145 merged the ignore behaviour while this work was in progress, reasoning that a stale cookie from another login in the same browser should not block the signed-in user's own enrollment; cookie clearing removes the cross-account enrollment either way, so this branch follows dev.
- **typed-401s** — **Decision:** problem `type` URNs on the ambiguous 401s. **Alternatives:** distinct status codes; matching on `detail`. **Why:** the project already uses `urn:cvert:error:*` types (`problemTypeTierLimit`); changing status codes would break the documented contract.
- **sign-out-after-password-change** — **Decision:** sign the user out after an account-page password change. **Alternatives:** keep the session; have the backend reissue tokens in normal mode. **Why:** the access token survives the `token_version` bump but refresh then fails within 15 minutes, which would look like a random logout. **Revisit if:** the backend reissues tokens on normal-mode password change.
- **qr-library** — **Decision:** `uqr`. **Alternatives:** `qrcode` (8.2k stars, three dependencies, no release since 2024-08); `qrcode-generator` (zero dependencies, ES5-era code, one maintainer); `qrcode.vue` (one maintainer); `qr` by paulmillr (one maintainer); `@vueuse/integrations` `useQRCode` (wraps the stale `qrcode`); no QR code (violates the phase 11 frontend requirement). **Why:** zero dependencies, derived from the most-reviewed encoder, 9.3M weekly downloads, and maintained mainly by VueUse's maintainer, whose code the SPA already ships via `@vueuse/core`. **Revisit if:** it is archived or a security advisory appears.
- **no-global-mfa-gate** — **Decision:** a mandate added mid-session is enforced at the next sign-in, not by a client-side gate. **Alternatives:** call `/auth/mfa/methods` on every session start and block the app until enrollment. **Why:** the backend enforces the mandate only at login, and a client-only gate adds a request per session without adding enforcement.

## Out of scope (follow-ups)

- **Password change before MFA:** `changePasswordHandler` accepted `password_reset` at any position in the pending list. Fixed separately in scarson/CVErt-Ops#143.
- **No lockout check on MFA verify:** `mfa/verify` never checks account lockout, and `challenge {method: "totp"}` renews the pending token without limit, so TOTP guessing is bounded only by the per-IP rate limit.
- **Site-admin forced reset leaves sessions alive:** it sets `force_password_reset` without bumping `token_version`.
- **OAuth sign-in skips MFA:** GitHub, Google and OIDC sign-in do not check MFA enrollment, the MFA mandate or `force_password_reset`.
- **Dev stack does not start:** `docker/compose.yml` cannot start `postgres:18-alpine`, and `serve` hangs after migrations against a fresh database. This blocked a live in-browser reproduction; the gap is confirmed from code and covered by Vitest tests.

## Verification

- Vitest component and store tests for every step, error type and account-page action, using the typed client mocked at the `fetch` boundary.
- Go tests for each backend change in `internal/api`, run with `TESTCONTAINERS_RYUK_DISABLED=true` on the targeted package.
- A manual in-browser pass once the dev stack starts.
