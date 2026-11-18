# Phase 11 — MFA: TOTP + Email OTP

> **Date:** 2026-03-16 – 2026-03-17
> **Branches:** `worktree-phase11-mfa` (Tasks 1-9, PR #44) → `phase11-mfa-handlers` (Tasks 10-24, PR #50)
> **Plan:** `dev/plans/2026-03-16-phase11-mfa-totp-email-otp-plan.md`

## What was built

Complete MFA system: config fields, database migration (4 new tables + 3 org columns),
`pquerna/otp` TOTP dependency, store CRUD for credentials/recovery codes/challenges/requirements,
3-layer MFA mandate check, pending JWT tokens for restricted sessions, MFA challenge/verify
login flow, TOTP and email OTP enrollment, MFA management (list/remove methods, regenerate
recovery codes), remember-device, admin MFA reset, admin force-password-reset, per-member
MFA requirements, org-wide MFA settings, middleware MFA route gating, restricted password
change, security events, periodic challenge cleanup worker, and full end-to-end integration tests.

## Files created/modified

| File | Action | Tasks |
|------|--------|-------|
| `internal/config/config.go` | Modified | 1 |
| `internal/config/config_test.go` | Modified | 1 |
| `migrations/000040_create_mfa_tables.up.sql` | Created | 2 |
| `migrations/000040_create_mfa_tables.down.sql` | Created | 2 |
| `go.mod` / `go.sum` | Modified | 3 |
| `internal/store/queries/mfa.sql` | Created | 4-8 |
| `internal/store/generated/mfa.sql.go` | Generated | 4-8 |
| `internal/store/mfa.go` | Created | 4-8 |
| `internal/store/mfa_test.go` | Created | 4-8 |
| `internal/auth/jwt.go` | Modified | 9 |
| `internal/auth/jwt_test.go` | Modified | 9 |
| `internal/api/auth_mfa.go` | Created | 10-15, 20-21 |
| `internal/api/auth_mfa_test.go` | Created | 10-15, 20 |
| `internal/api/auth_mfa_integration_test.go` | Created | 23 |
| `internal/api/admin_mfa.go` | Created | 18-19, 21 |
| `internal/api/admin_mfa_test.go` | Created | 18-19 |
| `internal/api/auth.go` | Modified | 10, 17, 21 |
| `internal/api/auth_test.go` | Modified | 24 (fix) |
| `internal/api/middleware_auth.go` | Modified | 16 |
| `internal/secure/events.go` | Modified | 21 |
| `internal/secure/events_test.go` | Modified | 21 |
| `internal/worker/pool.go` | Modified | 22 |
| `cmd/cvert-ops/main.go` | Modified | 22 |
| `dev/testing-pitfalls.md` | Modified | review |

## Key implementation decisions

1. **Migration renumbered 000039 → 000040**: Phase 8E's secure-pillar migration landed on
   `dev` as 000039 after the MFA plan was written. Renumbered to avoid collision.

2. **4 global tables + 1 org-scoped**: `mfa_credentials`, `mfa_recovery_codes`, `mfa_challenges`
   are global (no RLS) — checked at login before org context is established. `mfa_requirements`
   is org-scoped with RLS policy matching the standard `app.org_id` / `app.bypass_rls` pattern.

3. **3-layer MFA mandate check** (`IsMFAMandated`): Checks site config → org `mfa_required_all`
   → per-member `mfa_requirements` row. Uses `withBypassTx` since it runs at login time.

4. **Recovery code design**: 8 codes per set, stored as argon2id hashes. Verification uses
   `SELECT FOR UPDATE SKIP LOCKED` to prevent double-consumption under concurrent requests.

5. **Pending JWT tokens**: `PendingClaims` carries a `Pending []string` array (e.g.,
   `["mfa_challenge", "password_reset"]`). Short-lived (5min default). Separate `EnrollmentClaims`
   for the `mfa_enrollment_required` flow. Both enforce `WithValidMethods` + `WithExpirationRequired`.

6. **TOTP secret encryption**: AES-256-GCM via `internal/crypto`. Database CHECK constraint
   enforces `secret_enc IS NOT NULL` for TOTP and `IS NULL` for email OTP.

7. **Dual-auth for enrollment endpoints**: `resolveEnrollmentUserID` accepts both
   `access_token` (authenticated users) and `mfa_pending_token` (users with
   `mfa_enrollment_required`). Enables mandated enrollment without full access.

8. **Single `time.Now()` for TOTP**: Captures `now` once for both validation and step
   calculation to prevent clock-boundary race across a 30-second boundary.

9. **Worker pool PeriodicTask**: Added `PeriodicTask` type to `worker.Pool` for fixed-interval
   tasks alongside job queue polling. Uses `time.NewTicker` with `defer ticker.Stop()`.

10. **Security event pipeline**: `eventWriter.Write(ctx, secure.Event{...})` for both huma
    and chi handlers. 22 MFA event constants with severity mappings.

11. **Fail-closed MFA enforcement**: `buildMFARequiredReasons` returns `["db_error"]` when
    DB checks fail, preventing false "not required" results from masking a mandate.

12. **RBAC hierarchy for admin MFA actions**: Owner can target admin/member, admin can target
    member only, site admin can target anyone. Self-target blocked with 400.

## Gotchas discovered

- **Migration numbering conflicts**: Concurrent branches cause collisions. Fix was a rename
  (no SQL changes) after merging `dev`.
- **`pquerna/otp` verified active**: Web-searched before adding — last release 2024, widely used.
- **`//nolint` inside function call args**: `replace_all` placed nolint comments inside
  Go function call argument lists, breaking syntax. Must extract to local variable first.
- **gosec G104 vs errcheck**: golangci-lint v2 `//nolint:errcheck` doesn't suppress
  gosec G104 — need `//nolint:errcheck,gosec` in test files.
- **Huma vs chi auth**: Huma routes use cookie-based auth from input structs; chi routes
  use `RequireAuthenticated()` middleware which also handles Bearer API keys. API key
  tests must target chi routes.
- **Test broken by MFA changes**: `TestMe_IncludesForcePasswordReset` assumed login still
  issues access tokens with `force_password_reset`. Updated to check `pending` field directly.

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean
- **Store tests:** All pass (credentials, recovery codes, challenges, requirements, mandate check)
- **JWT tests:** PendingClaims and EnrollmentClaims round-trip tests pass
- **MFA handler tests:** 44/44 pass (unit + integration)
- **Integration tests:** 8 end-to-end flows covering TOTP, email OTP, recovery codes,
  forced password reset, enrollment mandate, password reset MFA bypass prevention,
  API key MFA bypass, concurrent recovery code race condition
- **RBAC edge case tests:** Self-target (400) and same-level (403) rejection verified
- **Post-review cleanup** (PR #44): Fixed ABOUTME comments, removed dead imports,
  added RLS store tests for `mfa_requirements`
