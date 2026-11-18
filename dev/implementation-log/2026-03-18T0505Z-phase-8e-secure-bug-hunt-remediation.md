# Phase 8E (Secure) — Bug Hunt Remediation

> **Date:** 2026-03-18
> **Commits:** `2192617`..`2e0b523` on `fix/phase8e-bug-hunt-remediation` (PR #51, squash-merged to dev)
> **Plan:** `dev/plans/2026-03-17-phase8e-bug-hunt-remediation.md`
> **Source:** `dev/bug-hunts/2026-03-17-phase8e-consolidated.md`

## What was built

| Fix | Files | Description |
|---|---|---|
| B1: Config holder wiring (JWT) | `middleware_auth.go`, `auth.go`, `auth_mfa.go`, `auth_email_verification.go`, `oauth_*.go` | `jwtSecret()` and `jwtPreviousSecretBytes()` methods on `*Server` read from `configHolder` with fallback to `srv.cfg` — 26 call sites updated |
| B1: Config holder wiring (SSO) | `sso.go`, `admin_doctor.go` | `ssoEncryptionKey()` and `ssoEncryptionKeyPrevious()` read from `configHolder`; doctor handler wired to reflect current rotated state |
| B2: Secrets file merge | `reloadable.go`, `reload.go` | `LoadFromSecretsFile` accepts baseline `*ReloadableConfig`; partial files merge instead of full-replace; 6 string field guards added |
| B3+D4: SIEM syslog wiring | `config.go`, `reloadable.go`, `writer.go`, `main.go` | `SIEM_SYSLOG_ADDR`/`SIEM_SYSLOG_FORMAT` env vars; `SyslogWriter` wired at startup; `atomic.Pointer[SyslogWriter]` for race safety |
| B4: TOTP enrollment decrypt | `auth_mfa.go` | Enrollment confirm uses `DecryptWithFallback` for key rotation |
| B5+B6: Admin reload | `admin_reload.go`, `server.go`, `main.go` | Handler uses `ReloadConfig` (SIGHUP parity); error response sanitized |
| D3: GCM error gating | `aes.go` | `DecryptWithFallback` only falls back on GCM auth errors, not structural errors |
| O1: sqlc query sync | `security_events.sql` | Composite cursor `(created_at, id)` matches hand-written query |
| O2: SSO hex warning | `reloadable.go` | `slog.Warn` on invalid SSO hex at startup instead of silent zero |

## Key implementation decisions

- **Choke-point helpers for config holder** — rather than passing `configHolder` to 26 call sites, two methods (`jwtSecret()`, `jwtPreviousSecretBytes()`) on `*Server` act as choke points. SSO has the same pattern. Fallback to `srv.cfg` ensures existing tests pass without modification.
- **Pointer comparison for reload failure detection** — `ReloadConfig` doesn't return errors (recovers panics). Admin handler detects failure by comparing `configHolder.Load()` before and after. Works because `LoadFromSecretsFile` always allocates a fresh `*ReloadableConfig`.
- **Deep-copy byte slices in baseline merge** — struct value copy shares `[]byte` backing arrays. Added explicit `append([]byte(nil), ...)` for `JWTSecret` and `JWTSecretPrevious` to prevent latent mutation issues.
- **`isGCMAuthError` string matching** — Go's `crypto/cipher` has no sentinel error for GCM auth failure. Matching on our own `"gcm decrypt:"` prefix from `Decrypt` is reliable since we control both sides.
- **Feed rescan wiring deferred** — both SIGHUP and admin handler pass `nil` for rescan. Full integration (creating `generic.Loader`, updating worker pool factory) is future work.

## Gotchas discovered

- **Unconditional string field assignments break merge** — `rc.SMTPHost = kv["SMTP_HOST"]` returns `""` for absent keys, zeroing the baseline. Only fields with `if v, ok` guards are safe. Caught during plan review, not during implementation.
- **Stale LSP diagnostics in worktrees** — gopls repeatedly reported phantom compilation errors (wrong arg counts, undefined methods) that `go build` showed were non-existent. Every diagnostic was stale. Always verify with `go build` before investigating.
- **`web/dist/` missing in worktrees** — gitignored, so not copied. Placeholder `index.html` needed for `embed.go` to compile.
- **Double-close risk with syslog** — `EventWriter.Stop()` closes syslog; a `defer sw.Close()` in `main.go` would double-close. Only one owner should close.

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** 0 issues
- **Tests:** config (27), crypto (12), secure, API (full suite 223s) — all pass
- **New tests:** Hot-reload JWT test, 5 SSO config holder tests, admin rescan + error sanitization tests, TOTP key rotation test, GCM error gating test, concurrent SetSyslog race test, baseline merge tests
- **Code review:** 2 rounds — Round 1 found byte slice shallow copy (fixed); Round 2 (different angles) found no issues
