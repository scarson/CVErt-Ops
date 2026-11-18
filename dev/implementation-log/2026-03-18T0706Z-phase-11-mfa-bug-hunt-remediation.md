# Phase 11 MFA — Bug Hunt Remediation

> **Date:** 2026-03-18
> **Commits:** `c427225`..`15551e4` on `fix/phase11-mfa-bug-hunt` (PR #52, merged to dev)
> **Plan:** `dev/plans/2026-03-17-phase11-mfa-bug-hunt-remediation.md`
> **Source:** `dev/bug-hunts/2026-03-17-phase11-mfa-consolidated.md`

## What was built

| Fix | Files | Description |
|---|---|---|
| B1 (critical): Password reset MFA bypass | `auth_password_reset.go` | Forgot-password flow now checks MFA enrollment/mandate, issues pending token when MFA required |
| B2: Stale token_version in pending token | `auth.go` | Re-reads user after `UpdatePasswordHash` for post-increment `token_version` |
| B3: Enrollment pending order enforcement | `auth_mfa.go` | `resolveEnrollmentUserID` checks `Pending[0]` instead of scanning entire array |
| B4: token_version validation in enrollment | `auth_mfa.go` | `resolveEnrollmentUserID` validates `token_version` against DB; added `ctx` parameter + updated 4 callers |
| B5: Full auth tokens on enrollment completion | `auth_mfa.go` | `clearEnrollmentPending` issues access/refresh tokens when all pending items cleared |
| B6: Transaction helper compliance | `org.go` | `UpdateOrg` and `UpdateOrgMFASettings` wrapped in `withBypassTx` |
| B7: Atomic admin MFA reset | `mfa.go`, `admin_mfa.go` | New `ResetUserMFA` store method wraps all deletions + version increment in single tx; removed redundant `DeleteRememberDeviceTokens` |
| B8: Dead event constant | `mfa.go`, `auth_mfa.go` | `VerifyEmailOTPChallenge` returns `exhausted bool`; handler emits `EventMFAChallengeExhausted` |
| B9+D3: TOTP replay prevention | `mfa.sql`, `mfa.go`, `auth_mfa.go` | `FOR UPDATE` lock + `maxStep = currentStep + skew` closes 30s replay window |
| B10+B11: Cookie path + TTL refresh | `auth_mfa.go` | Enrollment cookie path narrowed to `/api/v1/auth/mfa`; email OTP setup reissues pending token |
| B12: Structured required_reasons | `mfa.sql`, `mfa.go`, `auth_mfa.go` | Returns `[{source, org_name}]` objects; new `UserMFARequiredOrgNames`/`UserMFARequirementOrgNames` queries |
| D2: Dual-key JWT rotation | `jwt.go`, `auth_mfa.go`, `auth.go` | `ParsePendingToken`/`ParseEnrollmentToken` accept `previousSecret` for zero-downtime rotation |

## Key implementation decisions

- **Two-fetch pattern for TOTP replay prevention** — unlocked read for TOTP validation, then `FOR UPDATE` locked read-modify-write for step check. Avoids holding lock during TOTP crypto.
- **`withBypassTx` for all new store methods** — `mfa_credentials`, `mfa_challenges`, `mfa_requirements` tables have no RLS; `withBypassTx` is correct per §2.17.
- **Parallel org-name queries for B12** — existing `UserInMFARequiredOrg`/`UserHasMFARequirement` return `bool` and are used by `UserMFARequired`. New queries return org names without changing existing method signatures.
- **Barrier pattern for concurrent TOTP test** — `ready := make(chan struct{})` + goroutines block on `<-ready` + `close(ready)` per `testing-pitfalls.md` §1.

## Gotchas discovered

- **Stale LSP diagnostics in worktrees** — VSCode gopls reported compilation errors (wrong arg counts, undefined methods) that didn't exist — `go build` and `go vet` passed clean every time. The worktree's gopls instance lagged behind file changes. Learned to always verify with `go build` before investigating diagnostic errors.
- **`CreateOrg` also bypasses transaction helpers** — Task 2 implementer discovered `CreateOrg` (line 19-25) uses `s.q` directly, same as `UpdateOrg`/`UpdateOrgMFASettings`. Noted for future fix but out of scope.

## Quality checks

- **go build ./...:** Clean (verified in worktree)
- **golangci-lint:** 0 issues
- **Tests:** Full suite green — 34 packages pass (`go test ./internal/... ./cmd/...`)
- **New tests:** ~1,600 lines across `auth_password_reset_test.go`, `auth_test.go`, `auth_mfa_test.go`, `mfa_test.go`, `jwt_test.go`
