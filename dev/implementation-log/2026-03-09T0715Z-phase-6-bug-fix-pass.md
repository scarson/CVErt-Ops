# Phase 6 Bug Fix Pass (2026-03-09)

25 findings from 6 bug hunt reports (3 exploratory, 2 holistic, 1 multipass), consolidated into a 13-task implementation plan. Executed via subagent-driven-development (5 batches).

## What was fixed

| Category | Fixes |
|---|---|
| TOCTOU / concurrency | Atomic password reset token consumption (`FOR UPDATE SKIP LOCKED`), bootstrap registration mutex, idempotent invitation accept (`ON CONFLICT DO NOTHING`), `COALESCE(accepted_at, now())` |
| Anti-enumeration | All `forgotPasswordHandler` post-lookup error paths return 200 (DB error, rate limit, token creation failure) |
| Memory / resource leaks | Lockout manager eviction goroutine with `Stop()` lifecycle, `t.Cleanup(m.Stop)` in all tests |
| Argon2 semaphore safety | `func(){defer release...}()` closures in `loginHandler`, `changePasswordHandler`, `resetPasswordHandler` |
| Validation gaps | Whitespace-only name rejection in PATCH channel, create/update org; case-insensitive email in lockout manager and invitation duplicate check |
| Rate limiting | Per-user email verification resend rate limit (429), SMTP failure error reporting (500 not false 200) |
| CORS | Wildcard origin `*` rejected when `AllowCredentials` is enabled |
| Transaction helpers | `CreateUser`, `CountUsers`, `UpdatePasswordHash`, `GetOrgByID` wrapped in `withBypassTx` |
| Invitation fixes | Duplicate pending check (409), cancel returns 404 if not found, nil org/inviter logging, audit entries for create/cancel/resend |
| Data lifecycle | `ListAllOrgs` excludes soft-deleted orgs (`WHERE deleted_at IS NULL`) |
| Config | Clear error when testing email channel without SMTP configured |

## Key implementation decisions

- **Per-batch (not per-task) subagent dispatch** — heavy file interdependencies (shared SQL files, sqlc regeneration ordering) would cause conflicts with per-task agents
- **429 for rate-limited resend** (not 200) — endpoint is authenticated, no anti-enumeration concern; distinct from password reset which uses 200 because it's unauthenticated
- **Bootstrap org failure non-fatal** — if `BootstrapFirstUserOrg` fails, user is still created and can log in; org can be created manually (B9 finding)
- **TOCTOU on invitation creation accepted** — `HasPendingInvitation` check-then-insert race is low risk (admin-only endpoint, narrow window, benign consequence)
- **sqlc `@param` syntax** — `lower(@email)` generates field name `Email` vs `lower($2)` which generates `Lower`

## Files changed

28 files, 1,120 insertions, 93 deletions across `internal/api/`, `internal/store/`, `internal/config/`

## Tests added

| Test | File | What it verifies |
|---|---|---|
| `TestLockout_CaseInsensitive` | `lockout_test.go` | Mixed-case emails count toward same lockout |
| `TestLockout_CleanupEvictsStaleEntries` | `lockout_test.go` | 100 stale entries evicted after TTL |
| `TestLockout_CleanupPreservesActiveLockouts` | `lockout_test.go` | Active lockouts survive cleanup |
| `TestResetPassword_ConcurrentUse` | `auth_password_reset_test.go` | Barrier pattern — exactly one of two concurrent resets succeeds |
| `TestResendVerification_RateLimit` | `auth_email_verification_test.go` | 429 after exceeding per-user token limit |
| `TestResendVerification_SMTPFailure` | `auth_email_verification_test.go` | 500 returned (not false 200) on SMTP failure |
| `TestCORSOrigins_WildcardRejected` | `cors_test.go` | Wildcard `*` filtered from origins |
| `TestCORSOrigins_WildcardAmongOthers` | `cors_test.go` | `*` filtered, valid origins preserved |
| `TestCORSMiddleware_WildcardReturnsNil` | `cors_test.go` | Middleware returns nil when only wildcard configured |
| `TestCORSOrigins_ValidOrigins` | `cors_test.go` | Non-wildcard origins pass through |
| `TestRegister_InviteOnly_ConcurrentBootstrap` | `auth_test.go` | Barrier pattern — concurrent bootstrap serialized by mutex |
| `TestAcceptInvitation_ConcurrentAccept` | `auth_test.go` | Barrier pattern — concurrent accept is idempotent |
| `TestPatchChannel_EmptyName_Rejected` | `channels_test.go` | Empty and whitespace-only names rejected (422) |
| `TestTestChannel_EmailNoSMTP` | `channels_test.go` | Clear error when SMTP not configured |
| `TestCreateOrg_WhitespaceName` | `orgs_test.go` | Whitespace-only name rejected |
| `TestUpdateOrg_WhitespaceName` | `orgs_test.go` | Whitespace-only name rejected |
| `TestCreateInvitation_DuplicatePending` | `orgs_test.go` | 409 on duplicate pending invitation |
| `TestCancelInvitation_NotFound` | `orgs_test.go` | 404 when invitation doesn't exist |

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** 0 issues
- **Unit tests:** 19/19 pass (lockout + CORS)
- **Integration tests:** Docker Desktop/testcontainers issue on Windows (pre-existing, not caused by changes)
