# Phase 6A — Security Hardening

> **Date:** 2026-03-08 to 2026-03-09
> **Commits:** `c9cbc62`..`67f348a` on `feature/phase6a-security-hardening` (22 commits, 60 files, +4902/-236)
> **Plan:** `dev/plans/2026-03-01-phase6-implementation-plan.md`

## What was built

| Feature | Files | Description |
|---|---|---|
| Password reset flow | `internal/api/auth_password_reset.go`, `internal/store/password_reset.go`, templates, `migrations/000031_*` | Forgot/reset endpoints. 32-byte `crypto/rand` tokens, SHA-256 hashed in DB. Rate limited (3/user/hour). Always returns 200 to prevent email enumeration. Increments `token_version` to invalidate sessions |
| First-user bootstrap fix | `internal/api/auth.go` | In invite-only mode, allow first user to register without invitation |
| Invitation email sending | `internal/api/orgs.go`, `internal/notify/render.go`, templates | Sends invitation emails via SMTP on `POST /invitations`. Best-effort |
| Invitation resend endpoint | `internal/api/orgs.go` | `POST /orgs/{org_id}/invitations/{id}/resend` — new token, extended expiry. Admin+ |
| Email verification flow | `internal/api/auth_email_verification.go`, `internal/store/email_verification.go`, templates, `migrations/000032_*`, `000033_*` | Verify + resend endpoints. `email_verified` boolean on users. Same token pattern as password reset. 24h TTL |
| Channel test endpoint | `internal/api/channels.go` | `POST /orgs/{org_id}/channels/{id}/test` — sends test notification. Delivery outcome in response body |
| Account lockout | `internal/api/lockout.go` | In-memory `lockoutManager` with configurable threshold/duration. Injectable clock. Background eviction goroutine |
| RBAC for channels | `internal/api/server.go` | Channel mutations elevated from `RoleMember` to `RoleAdmin` per PLAN.md §7.3 |
| CORS middleware | `internal/api/cors.go` | Config-driven origin allowlist. Rejects wildcard `*` (incompatible with credentials). Dev defaults |
| Frontend views | `ForgotPasswordView.vue`, `ResetPasswordView.vue`, `VerifyEmailView.vue` | Vue pages + auth store extensions + routes |

## Key implementation decisions

- **Tokens SHA-256 hashed** before DB storage. Lookup by hash via index scan
- **Email enumeration prevention** — `POST /auth/forgot-password` returns constant 200 regardless of outcome
- **Lockout is in-memory** — acceptable for single-binary deployment; would need Redis for multi-instance
- **Invitation resend generates new token** rather than re-sending original (which may have leaked)
- **Channel test always returns 200** — delivery outcome in JSON body, not HTTP status

## Tests added

| Test | File | What it verifies |
|---|---|---|
| Password reset store/handlers | `password_reset_test.go`, `auth_password_reset_test.go` | Create, lookup, rate limiting, enumeration-safe response, session invalidation |
| Email verification store/handlers | `email_verification_test.go`, `auth_email_verification_test.go` | Create, lookup, expired token, resend auth |
| Account lockout | `lockout_test.go`, `auth_lockout_test.go` | Threshold, unlock timing, eviction, concurrent access, integration with login |
| CORS middleware | `middleware_cors_test.go` | Allowed/blocked origins, dev defaults, wildcard rejection |
| Channel test/RBAC | `channel_test_notification_test.go`, `channels_test.go` | Test notification, RBAC enforcement |
| Invitation resend | `orgs_test.go` | Resend for pending, rejected for expired/accepted/cancelled |
| Frontend views | `ForgotPasswordView.test.ts`, `ResetPasswordView.test.ts`, `VerifyEmailView.test.ts` | Form flows |

## Quality checks

- `golangci-lint run` passes
- Code review remediation: `formatTTL` helper, `forgotPasswordResponse` constant, test file renames
- RBAC corrected to match PLAN.md §7.3
