# Secure Pillar — Revised Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

> **Revision date:** 2026-03-16. This plan replaces `2026-03-10-phase8-ops-secure-plan.md`.
> It incorporates changes from:
> - Phase 8B-8D implementation (all landed and merged to main)
> - Phase 9 health review remediation (in progress)
> - Phase 9 Stage 3 API contract convergence (in progress)
> - Phase 8 bug hunt remediation plan (in progress)
> - Phase 9 bug hunt remediation plan (in progress)
>
> **Key changes from original plan:**
> - Doctor checks: 4 of 7 already exist in `internal/doctor/checks.go` (Phase 8C). This plan modifies 2 existing checks for dual-key support and adds only 3 new checks — no longer creates `internal/secure/checks.go`.
> - File ownership expanded: this plan now modifies `internal/doctor/checks.go` and creates `internal/metrics/security.go`.
> - Lockout manager reference removed: the Phase 8 bug hunt rewrites the in-memory lockout manager to DB-backed. The security event rate limiter must be self-contained.
> - Auth handler wiring updated: Phase 8 bug hunt changes login flow (disabled-user check before password verify), adds `GetUserAuthStatus` to middleware, and rewrites lockout to DB-backed. All event wiring targets post-remediation code.
> - API conventions updated: all new endpoints use `writeProblem`, `writeList`, `encodePageCursor` from `internal/api/contract.go`. Admin endpoints get spec-only Huma declarations.
> - Dependency injection: `ServerDeps` struct pattern for injecting new dependencies into `Server`.
> - `internal/metrics/security.go`: Observe pillar confirmed landed; security metrics go in the metrics package.

**Goal:** Dual-key JWT rotation, dual-key encryption rotation, SIGHUP config hot-reload, security event detection/alerting pipeline, and runtime security self-checks.

**Architecture:** `ReloadableConfig` struct behind `atomic.Pointer` for hot-reloadable fields. Security events in a separate `security_events` table (not audit_log). Dual-key try-current-then-previous pattern for both JWT and encryption. SIGHUP on Unix, admin API reload on all platforms.

**Tech Stack:** Go, `golang-jwt/jwt/v5`, `crypto/aes` + `cipher.GCM`, `sync/atomic`, `os/signal`, PostgreSQL

**References:**
- Design: `dev/plans/2026-03-10-ops-secure-design.md`
- Testing pitfalls: `dev/testing-pitfalls.md` (referenced as `tp§N.N`)
- Implementation pitfalls: `dev/implementation-pitfalls.md`
- Contract helpers: `internal/api/contract.go` (`writeProblem`, `writeList`, `encodePageCursor`, `decodePageCursor`)
- Doctor framework: `internal/doctor/doctor.go` (`Check` interface), `internal/doctor/checks.go` (existing checks)
- JWT: `internal/auth/jwt.go`
- AES: `internal/crypto/aes.go`
- Config: `internal/config/config.go`
- Main: `cmd/cvert-ops/main.go`
- Security events: `internal/secure/events.go` (Phase 8A)
- Server: `internal/api/server.go` (`Server` struct, `ServerDeps`, `NewServer`, admin route group)

**CRITICAL — File Ownership:** This pillar creates files in `internal/secure/`, `internal/metrics/security.go`, `cmd/cvert-ops/rotate.go`, and `docs/deployment/runbooks/secret-rotation.md`. It modifies `internal/auth/jwt.go`, `internal/crypto/aes.go`, `internal/config/config.go`, `cmd/cvert-ops/main.go`, `internal/api/server.go`, `internal/doctor/checks.go`, `internal/retention/runner.go`, and auth handler files in `internal/api/`. Do NOT touch `internal/metrics/http.go` or other existing metrics files (Observe), `internal/feed/generic/` (Extend), or `internal/doctor/doctor.go` (Operate core).

**CRITICAL — Cross-Pillar Dependencies (all resolved):**
- **From Operate (Phase 8C):** Doctor `Check` interface at `internal/doctor/doctor.go`. `StandardChecks()` at `internal/doctor/checks.go` with `StandardChecksConfig`. Both exist and are stable.
- **From Observe (Phase 8B):** Metrics package at `internal/metrics/`. Security metrics will be added as `internal/metrics/security.go` following the same pattern as `http.go`, `feed.go`, etc.
- **From Extend (Phase 8D):** `Rescan()` method at `internal/feed/generic/config.go` on `*Loader` receiver. Signature: `func (l *Loader) Rescan() ([]Config, []error)`.

---

## Pre-Implementation Requirements (ALL agents)

**Every agent MUST do the following before writing any code:**

1. Invoke the `superpowers:test-driven-development` skill and follow its methodology for every task
2. Read `dev/testing-pitfalls.md` in full — it contains checklist items that directly apply to these tasks
3. Read `dev/implementation-pitfalls.md` for Go/Postgres conventions
4. Read `CLAUDE.md` for project rules (especially: TDD, naming, comments, commit frequency)
5. Read `internal/api/contract.go` and `internal/api/contract_test.go` — understand the shared helpers before creating any API endpoint

**Every agent MUST do the following after each task:**

1. Review all new/modified tests against `dev/testing-pitfalls.md` — specifically check the sections called out in each task
2. Run `go test ./...` (or the relevant package tests) and confirm all pass
3. Run `golangci-lint run` on changed packages and fix any issues
4. Commit with a descriptive message

**IMPORTANT — Read before edit:** Every task lists files to modify. Read them FIRST before making changes. Line numbers in this plan are approximate — the Phase 8 and 9 bug hunt remediations may shift them. Always find the correct insertion point by reading the current file.

---

## Batch 1: Dual-Key JWT Rotation

### Task 1: Dual-Key JWT Verification

**Files:**
- Modify: `internal/auth/jwt.go` — modify `ParseAccessToken` and `ParseRefreshToken` to accept dual keys
- Modify: `internal/auth/jwt_test.go`

**Context:** Two keys: active (signs new tokens, validates first) and previous (validates only, optional). Verification logic: try `JWT_SECRET` first. If validation fails with a SIGNATURE error (not expiry, not claims error), try `JWT_SECRET_PREVIOUS`. If neither validates, reject. Signing always uses `JWT_SECRET`.

**CRITICAL:** Only retry on signature verification failure. If the token is expired (even with the previous key), it's expired — don't try the previous key. Error type checking via `jwt.ErrTokenSignatureInvalid`.

**Current signatures (read `internal/auth/jwt.go` to confirm these haven't changed):**
```go
func ParseAccessToken(tokenStr string, secret []byte) (*AccessClaims, error)
func ParseRefreshToken(tokenStr string, secret []byte) (*RefreshClaims, error)
func IssueAccessToken(secret []byte, userID uuid.UUID, tokenVersion int, ttl time.Duration) (string, error)
func IssueRefreshToken(secret []byte, userID uuid.UUID, tokenVersion int, jti uuid.UUID, ttl time.Duration) (string, error)
```

**Step 1: Write tests (from design doc critical test cases)**

```go
func TestParseAccessToken_ActiveKeyValidates(t *testing.T) {
    // Issue token with activeKey, parse with activeKey as active + any previousKey → succeeds
}
func TestParseAccessToken_PreviousKeyValidates(t *testing.T) {
    // Issue token with previousKey, parse with differentActiveKey as active + previousKey → succeeds
}
func TestParseAccessToken_UnknownKeyRejects(t *testing.T) {
    // Issue token with unknownKey, parse with active + previous (neither matches) → error
}
func TestParseAccessToken_ExpiredWithPreviousKeyRejects(t *testing.T) {
    // Issue token with previousKey but TTL=-1s (already expired)
    // Parse with activeKey + previousKey
    // MUST reject as expired, NOT try previous key for re-validation
    // The error.Is check for ErrTokenSignatureInvalid should NOT match on an expired token
}
func TestParseAccessToken_NoPreviousKeyConfigured(t *testing.T) {
    // Pass nil for previousSecret → only active key tried, no error from missing previous
}
func TestParseAccessToken_BothKeysSameValue(t *testing.T) {
    // activeKey == previousKey → works (no-op, harmless)
}
// Repeat the same test matrix for ParseRefreshToken:
func TestParseRefreshToken_ActiveKeyValidates(t *testing.T) { ... }
func TestParseRefreshToken_PreviousKeyValidates(t *testing.T) { ... }
func TestParseRefreshToken_UnknownKeyRejects(t *testing.T) { ... }
func TestParseRefreshToken_ExpiredWithPreviousKeyRejects(t *testing.T) { ... }
```

**Step 2: Implement**

Modify both `ParseAccessToken` and `ParseRefreshToken` to accept active + optional previous key. The pattern is identical for both — extract a helper if the duplication bothers you, but keep the public API signatures clear:

```go
func ParseAccessToken(tokenStr string, activeSecret []byte, previousSecret []byte) (*AccessClaims, error) {
    claims := &AccessClaims{}
    _, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
        return activeSecret, nil
    }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())

    if err == nil {
        return claims, nil
    }

    // Only try previous key on signature error — not expiry/claims
    if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
        claims2 := &AccessClaims{}
        _, err2 := jwt.ParseWithClaims(tokenStr, claims2, func(_ *jwt.Token) (any, error) {
            return previousSecret, nil
        }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
        if err2 == nil {
            return claims2, nil
        }
        return nil, err2 // return previous key's error (might be expiry)
    }

    return nil, err
}
```

Apply the same pattern to `ParseRefreshToken` (uses `RefreshClaims` instead of `AccessClaims`).

**Step 3: Update ALL callers to pass both keys**

The previous key comes from `srv.cfg.JWTSecretPrevious` (added in Task 2). For Task 1, use `nil` as the placeholder for previousSecret at all call sites — Task 2 will fill it in after adding the config field. This keeps the compile passing at every step.

**⛔ EXHAUSTIVE CALLER LIST — do NOT skip any. Read each file to confirm line numbers:**

| Caller | File | Current Call |
|--------|------|-------------|
| `RequireAuthenticated()` middleware | `internal/api/middleware_auth.go:36` | `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))` |
| `meHandler` | `internal/api/auth.go:481` | `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))` |
| `changePasswordHandler` | `internal/api/auth.go:541` | `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))` |
| `acceptInvitationHandler` | `internal/api/auth.go:655` | `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))` |
| `resendVerificationHandler` | `internal/api/auth_email_verification.go:100` | `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))` |
| `oidcLinkCallbackHandler` | `internal/api/oauth_oidc.go:330` | `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))` |
| `refreshHandler` | `internal/api/auth.go:333` | `auth.ParseRefreshToken(...)` |
| `logoutHandler` | `internal/api/auth.go:439` | `auth.ParseRefreshToken(...)` |

**For every caller:** Change `auth.ParseAccessToken(tokenStr, []byte(srv.cfg.JWTSecret))` to `auth.ParseAccessToken(tokenStr, []byte(srv.cfg.JWTSecret), nil)`. Same for `ParseRefreshToken`. The `nil` is the placeholder for `previousSecret` until Task 2 adds the config field.

**Step 4: Write test — refresh token flow across rotation**

```go
func TestRefreshTokenFlowAcrossRotation(t *testing.T) {
    // 1. Issue refresh token with oldKey
    // 2. Parse refresh token with newKey as active + oldKey as previous → succeeds
    // 3. Issue new access+refresh tokens with newKey
    // 4. Verify new tokens validate with newKey only
    // This is the most common rotation scenario
}
```

**Step 5: Run tests → PASS. Step 6: Commit.**

**Testing-pitfalls review for this task:**
- tp§11 "JWT algorithm confusion": existing tests already cover `alg: "none"` and wrong algorithm. Verify these still pass after dual-key changes.

### Task 2: Config Fields for Previous Keys

**Files:**
- Modify: `internal/config/config.go` — add `JWTSecretPrevious`, `SSOEncryptionKeyPrevious`

**Step 1: Read `internal/config/config.go`.** Find the auth-JWT section (currently has `JWTSecret string` and `JWTAlgorithm string`). Add the new fields adjacent:

```go
JWTSecretPrevious        string `env:"JWT_SECRET_PREVIOUS"`
```

Find the SSO section (currently has `SSOEncryptionKey string`). Add:

```go
SSOEncryptionKeyPrevious string `env:"SSO_ENCRYPTION_KEY_PREVIOUS"`
```

**Step 2: Update all `nil` placeholders from Task 1** to use the new config field:

Change every `auth.ParseAccessToken(tokenStr, []byte(srv.cfg.JWTSecret), nil)` to:

```go
auth.ParseAccessToken(tokenStr, []byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg))
```

Where `jwtPreviousSecret` is a small helper (add to `internal/api/middleware_auth.go` or a shared location):

```go
func jwtPreviousSecret(cfg *config.Config) []byte {
    if cfg.JWTSecretPrevious == "" {
        return nil
    }
    return []byte(cfg.JWTSecretPrevious)
}
```

**Do the same for `ParseRefreshToken` callers.**

**Step 3: Update `LogValue()` in config.go** to mask `JWTSecretPrevious` and `SSOEncryptionKeyPrevious` (follow the existing masking pattern for `JWTSecret`).

**Step 4: Commit.**

---

## Batch 2: Dual-Key Encryption Rotation

### Task 3: Dual-Key Decryption

**Files:**
- Modify: `internal/crypto/aes.go` — add `DecryptWithFallback`
- Modify: `internal/crypto/aes_test.go` (add tests)

**Context:** Try current key. If GCM authentication fails, try previous key. If both fail, error. No version byte, no format change.

**Current signatures (read `internal/crypto/aes.go` to confirm):**
```go
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error)
func Decrypt(key [32]byte, data []byte) ([]byte, error)
```

**Step 1: Write tests (from design doc)**

```go
func TestDecryptWithFallback_CurrentKeyWorks(t *testing.T) {
    // Encrypt with currentKey, decrypt with currentKey as current + any previousKey → succeeds
}
func TestDecryptWithFallback_PreviousKeyWorks(t *testing.T) {
    // Encrypt with oldKey, decrypt with newKey as current (fails GCM auth) + oldKey as previous → succeeds
}
func TestDecryptWithFallback_BothKeysWrong(t *testing.T) {
    // Encrypt with keyA, decrypt with keyB + keyC → returns error, NOT garbage
}
func TestDecryptWithFallback_NoPreviousKey(t *testing.T) {
    // previousKey is zero value [32]byte{} → only current key tried, no panic
}
```

**Step 2: Implement**

```go
func DecryptWithFallback(currentKey, previousKey [32]byte, data []byte) ([]byte, error) {
    plaintext, err := Decrypt(currentKey, data)
    if err == nil {
        return plaintext, nil
    }
    // Only try previous if it's a non-zero key
    if previousKey != [32]byte{} {
        plaintext, err2 := Decrypt(previousKey, data)
        if err2 == nil {
            return plaintext, nil
        }
        return nil, fmt.Errorf("decrypt with both keys failed: current: %w, previous: %v", err, err2)
    }
    return nil, err
}
```

**Step 3: Update all callers of `Decrypt` that handle SSO secrets**

**⛔ EXHAUSTIVE CALLER LIST — read each file to confirm:**

| Caller | File | Current Call |
|--------|------|-------------|
| SSO OIDC config build | `internal/api/oauth_oidc.go:56` | `crypto.Decrypt(key, conn.ClientSecretEnc)` |
| Doctor encryption sentinel | `internal/doctor/checks.go:178` | `crypto.Decrypt(c.Key, value)` |

Change both to `crypto.DecryptWithFallback(currentKey, previousKey, data)`. The previous key comes from `srv.cfg.SSOEncryptionKeyPrevious` (parsed to `[32]byte` using the same hex-decode pattern as the current key).

**DO NOT change these — they only use `Encrypt`, not `Decrypt`:**
- `internal/api/sso.go:146` — SSO create (encrypts new value with current key only — correct)
- `internal/api/sso.go:322` — SSO patch (encrypts new value with current key only — correct)

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 4: `cvert-ops rotate-encryption-key` Command

**Files:**
- Create: `cmd/cvert-ops/rotate.go`
- Modify: `cmd/cvert-ops/main.go` — add command to root

**Context:** Re-encrypts all values with current key so previous can be removed. Currently only: `sso_connections.client_secret_enc`. Runs in single transaction. Refuses if `SSO_ENCRYPTION_KEY_PREVIOUS` not set.

**Current cobra commands in main.go (read to confirm):** `serveCmd()`, `workerCmd()`, `migrateCmd()`, `importBulkCmd()`, `quotaCmd()`, `validateFeedsCmd()`, `doctorCmd()`. Add `rotateEncryptionKeyCmd()` in the same pattern.

**Step 1: Write tests**

```go
func TestRotateEncryptionKey_ReEncryptsAllValues(t *testing.T) {
    // 1. Insert SSO connections with client_secret_enc encrypted with oldKey
    // 2. Run rotate with currentKey + oldKey as previous
    // 3. Verify all values now decrypt with currentKey only
    // 4. Verify values do NOT decrypt with oldKey alone
}
func TestRotateEncryptionKey_RefusesWithoutPreviousKey(t *testing.T) {
    // SSO_ENCRYPTION_KEY_PREVIOUS not set → error returned, nothing changed
}
func TestRotateEncryptionKey_RollbackOnFailure(t *testing.T) {
    // Inject failure mid-batch (e.g., corrupt one row), verify transaction rolls back
    // All values still decrypt with old key (tp§3.3)
}
func TestRotateEncryptionKey_NoSSO_IsNoOp(t *testing.T) {
    // No sso_connections rows exist → succeeds with "0 rows re-encrypted" message
}
```

**Step 2: Implement.** Follow pattern of `migrateCmd()` in `cmd/cvert-ops/main.go`:
1. Load config
2. Open DB pool
3. Begin transaction
4. `SELECT id, client_secret_enc FROM sso_connections` (within the transaction)
5. For each row: `DecryptWithFallback(currentKey, previousKey, enc)` → `Encrypt(currentKey, plaintext)` → `UPDATE sso_connections SET client_secret_enc = $1 WHERE id = $2`
6. Commit transaction
7. Log count of re-encrypted rows

**⛔ SCOPE:** Only re-encrypt `sso_connections.client_secret_enc`. Do NOT guess other columns. If additional encrypted columns are added later, this command must be explicitly updated.

**Step 3: Bump `expectedSchemaVersion` if needed** — only if Task 8 (migration) has already been committed in this batch. If not, this is handled in Task 8.

**Step 4: Run tests → PASS. Step 5: Commit.**

---

## Batch 3: Config Hot-Reload via SIGHUP

### Task 5: ReloadableConfig with atomic.Pointer

**Files:**
- Create: `internal/config/reloadable.go`
- Create: `internal/config/reloadable_test.go`

**Context:** `ReloadableConfig` struct with ONLY hot-reloadable fields (design doc §3). This is a COMPLETE and EXHAUSTIVE list — do NOT add fields not listed here:

```go
// ABOUTME: Hot-reloadable configuration fields updated by SIGHUP or admin API.
// ABOUTME: Stored behind atomic.Pointer — readers never block, writers swap atomically.
package config

import "sync/atomic"

type ReloadableConfig struct {
    JWTSecret             []byte
    JWTSecretPrevious     []byte
    SSOEncryptionKey      [32]byte
    SSOEncryptionKeyPrev  [32]byte
    LogLevel              string
    SMTPHost              string
    SMTPPort              int
    SMTPFrom              string
    SMTPUsername          string
    SMTPPassword          string
    SMTPTLS               bool
    SIEMSyslogAddr        string // e.g., "udp://splunk:514"; empty = disabled
    SIEMSyslogFormat      string // "json" (default) or "cef"
}

// ConfigHolder provides atomic access to hot-reloadable configuration.
type ConfigHolder struct {
    ptr atomic.Pointer[ReloadableConfig]
}

func NewConfigHolder(initial *ReloadableConfig) *ConfigHolder { ... }
func (h *ConfigHolder) Load() *ReloadableConfig { ... }
func (h *ConfigHolder) Store(cfg *ReloadableConfig) { ... }
```

**⛔ NOT hot-reloadable (these require restart):** `DATABASE_URL`, `HTTP_PORT`, `METRICS_PORT`, `REGISTRATION_MODE`, `CORS_ALLOWED_ORIGINS`, `TRUSTED_PROXIES`, `COOKIE_SECURE`. Do NOT add these to `ReloadableConfig`.

**Step 1: Implement struct and atomic wrapper** (as above)

**Step 2: Implement `LoadFromSecretsFile(path string) (*ReloadableConfig, error)`**

Parse `CVERTOPS_SECRETS_FILE` — one `KEY=VALUE` per line. Comments (`#`) and empty lines skipped. Values trimmed. Validate:
- JWT secrets: if non-empty, must be >= 32 bytes
- SSO encryption keys: if non-empty, must be valid 64-char hex (decodes to 32 bytes)
- SMTP port: if non-empty, must be valid integer
- SIEM format: if non-empty, must be `"json"` or `"cef"`

Return error on invalid values — caller keeps old config.

**Step 3: Implement `LoadFromConfig(cfg *Config) *ReloadableConfig`**

Creates initial `ReloadableConfig` from the startup `Config` struct. Called once at startup to seed the `ConfigHolder`.

**Step 4: Write tests**

```go
func TestLoadFromSecretsFile_ValidFile(t *testing.T) {
    // Write a temp file with valid KEY=VALUE pairs → correct ReloadableConfig
}
func TestLoadFromSecretsFile_InvalidJWTSecret(t *testing.T) {
    // JWT_SECRET shorter than 32 bytes → error returned
}
func TestLoadFromSecretsFile_InvalidSSOKey(t *testing.T) {
    // SSO_ENCRYPTION_KEY not valid hex → error returned
}
func TestLoadFromSecretsFile_CommentsAndBlankLines(t *testing.T) {
    // Comments and blank lines skipped
}
func TestLoadFromSecretsFile_InvalidSIEMFormat(t *testing.T) {
    // SIEM_SYSLOG_FORMAT="xml" → error returned
}
func TestConfigHolder_LoadStoreAtomic(t *testing.T) {
    // Store new config, Load returns new config (consistent snapshot)
}
func TestConfigHolder_ConcurrentLoadStore(t *testing.T) {
    // Multiple goroutines calling Load while another calls Store → no race (run with -race)
}
```

**Step 5: Run tests → PASS. Step 6: Commit.**

### Task 6: SIGHUP Handler

**Files:**
- Create: `internal/config/sighup_unix.go` (build-tagged `//go:build !windows`)
- Create: `internal/config/sighup_unix_test.go`
- Modify: `cmd/cvert-ops/main.go` — start SIGHUP goroutine in `runServe`

**Context:**

**CRITICAL (design doc §3, biggest risk):** SIGHUP MUST use a SEPARATE `signal.Notify(sighupCh, syscall.SIGHUP)` channel with its own goroutine. It MUST NOT be added to the existing `signal.NotifyContext` for SIGTERM/SIGINT — that would cause SIGHUP to shut down the server.

**Current signal handling in main.go (read to confirm):**
```go
ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
defer stop()
```

The SIGHUP handler is a SEPARATE goroutine that runs alongside this. It does NOT interact with the shutdown context.

**Step 1: Implement SIGHUP handler function**

```go
// StartSIGHUPHandler listens for SIGHUP and reloads configuration.
// Returns a cancel function to stop the listener.
func StartSIGHUPHandler(holder *ConfigHolder, secretsFile string, rescan func()) func() {
    sighupCh := make(chan os.Signal, 1)
    signal.Notify(sighupCh, syscall.SIGHUP)
    done := make(chan struct{})

    go func() {
        for {
            select {
            case <-sighupCh:
                reloadConfig(holder, secretsFile, rescan)
            case <-done:
                signal.Stop(sighupCh)
                return
            }
        }
    }()

    return func() { close(done) }
}

func reloadConfig(holder *ConfigHolder, secretsFile string, rescan func()) {
    defer func() {
        if r := recover(); r != nil {
            slog.Error("config reload panicked", "panic", r)
        }
    }()

    if secretsFile == "" {
        slog.Info("SIGHUP received but CVERTOPS_SECRETS_FILE not configured — no-op")
        return
    }

    newCfg, err := LoadFromSecretsFile(secretsFile)
    if err != nil {
        slog.Error("config reload failed — keeping current config", "error", err)
        return
    }

    holder.Store(newCfg)
    slog.Info("config reloaded successfully")

    if rescan != nil {
        rescan()
    }
}
```

**Step 2: Write tests**

```go
func TestSIGHUP_ReloadsConfig(t *testing.T) {
    // Create ConfigHolder with initial config
    // Write secrets file with new values
    // Call reloadConfig directly (don't send actual SIGHUP in tests — flaky)
    // Verify holder.Load() returns new values
}
func TestSIGHUP_InvalidConfig_KeepsOld(t *testing.T) {
    // Write secrets file with invalid JWT_SECRET (< 32 bytes)
    // Call reloadConfig
    // Verify holder.Load() still returns OLD config
}
func TestSIGHUP_PanicRecovery(t *testing.T) {
    // Pass a secretsFile path that causes LoadFromSecretsFile to panic
    // (e.g., inject via a custom test that forces a panic)
    // Verify reloadConfig doesn't propagate the panic
    // Verify holder.Load() still returns old config (tp§2.4)
}
func TestSIGHUP_NoSecretsFile_NoOp(t *testing.T) {
    // secretsFile="" → logs info, config unchanged
}
func TestSIGHUP_CallsRescan(t *testing.T) {
    // Pass a rescan function that sets a flag
    // Call reloadConfig with valid secrets file
    // Verify rescan was called
}
```

**Step 3: Wire into `runServe` in main.go**

After creating `apiSrv` and before the `select` on `ctx.Done()`:

```go
// SIGHUP handler for config hot-reload (Unix only).
// This is a SEPARATE signal handler — do NOT add SIGHUP to the NotifyContext above.
stopSIGHUP := config.StartSIGHUPHandler(configHolder, cfg.SecretsFile, feedLoader.Rescan)
defer stopSIGHUP()
```

Where `feedLoader` is the `*generic.Loader` from Extend pillar's startup wiring. Read `runServe` to find where it's created.

**⛔ The `StartSIGHUPHandler` return value (cancel func) MUST be deferred.** The goroutine must stop on shutdown. (tp§14 "Goroutine shutdown path")

**Step 4: Add `SecretsFile` to `Config` struct** in `internal/config/config.go`:

```go
SecretsFile string `env:"CVERTOPS_SECRETS_FILE"`
```

**Step 5: Run tests → PASS. Step 6: Commit.**

### Task 7: Admin Reload API Endpoint

**Files:**
- Create: `internal/api/admin_reload.go`
- Create: `internal/api/admin_reload_test.go`
- Modify: `internal/api/server.go` — add route in admin group, add `ConfigHolder` to `ServerDeps`
- Modify: `internal/api/openapi_spec.go` — add spec-only Huma declaration

**Context:** `POST /api/v1/admin/reload-config` — cross-platform mechanism (Windows doesn't have SIGHUP). Re-reads secrets file. Does NOT accept secrets in request body (would put secrets in HTTP logs). Requires site admin auth (the admin group already has `RequireAuthenticated()` + `RequireSiteAdmin()` middleware).

**Dependency injection:** Add `ConfigHolder *config.ConfigHolder` to the `ServerDeps` struct in `server.go`. Read the current `ServerDeps` to see existing fields. The `Server` struct gets a corresponding `configHolder` field set in `NewServer`.

**Step 1: Write tests**

```go
func TestAdminReloadConfig_RequiresSiteAdmin(t *testing.T) {
    // Non-admin user → 403
}
func TestAdminReloadConfig_ReloadsFromSecretsFile(t *testing.T) {
    // Write a temp secrets file, configure server with it
    // POST /api/v1/admin/reload-config
    // Verify config holder has new values
}
func TestAdminReloadConfig_NoSecretsFile_NoOp(t *testing.T) {
    // No CVERTOPS_SECRETS_FILE configured → 200 with "no secrets file configured" message
}
func TestAdminReloadConfig_InvalidConfig_400(t *testing.T) {
    // Secrets file has invalid values → 400 with error detail, old config retained
}
```

**Step 2: Implement handler**

```go
func (srv *Server) adminReloadConfigHandler(w http.ResponseWriter, r *http.Request) {
    // Use the SAME reloadConfig logic as SIGHUP (call config.ReloadConfig or similar)
    // Return writeProblem on error, writeJSON on success
    // Log admin.config_reloaded security event (Task 11 will wire this)
}
```

**⛔ Use `writeProblem` for errors, NOT `http.Error`.** All new API endpoints in this plan MUST use the contract helpers from `internal/api/contract.go`.

**Step 3: Wire route in `server.go`'s admin group:**

```go
r.Post("/reload-config", srv.adminReloadConfigHandler)
```

**Step 4: Add spec-only Huma declaration in `openapi_spec.go`:**

Follow the existing pattern in `registerAllSpecOps`. Add a `registerAdminReloadSpecOps(api huma.API)` function.

**Step 5: Commit.**

---

## Batch 4: Security Events Pipeline

### Task 8: `security_events` Migration

**Files:**
- Create: `migrations/NNNNNN_create_security_events.up.sql`
- Create: `migrations/NNNNNN_create_security_events.down.sql`

**Context:** Determine the next migration number by listing `migrations/` directory. Currently the highest is `000038`. Use `000039` (or whatever is next when this executes).

**Up migration:**

```sql
-- migrate:no-transaction
CREATE TABLE IF NOT EXISTS security_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    actor_ip    TEXT,
    actor_email TEXT,
    user_id     UUID,
    org_id      UUID,
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_created_at
    ON security_events (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_type_created
    ON security_events (event_type, created_at);
```

**Down migration:**

```sql
-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_type_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_created_at;
DROP TABLE IF EXISTS security_events;
```

**⛔ BOTH files MUST start with `-- migrate:no-transaction` on the FIRST line.** `CREATE INDEX CONCURRENTLY` cannot run inside a transaction.

No RLS — system table, accessed only by site admins via `withBypassTx`.

**Step 1: Write migration files.**

**Step 2: Add sqlc queries for security_events.** Create `internal/store/queries/security_events.sql` with:

```sql
-- name: InsertSecurityEvent :exec
INSERT INTO security_events (event_type, severity, actor_ip, actor_email, user_id, org_id, details)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListSecurityEvents :many
SELECT id, event_type, severity, actor_ip, actor_email, user_id, org_id, details, created_at
FROM security_events
WHERE
    ($1::text IS NULL OR event_type = $1) AND
    ($2::text IS NULL OR severity = $2) AND
    ($3::text IS NULL OR actor_email = $3) AND
    ($4::timestamptz IS NULL OR created_at >= $4) AND
    ($5::timestamptz IS NULL OR created_at <= $5) AND
    ($6::timestamptz IS NULL OR created_at < $6)
ORDER BY created_at DESC, id DESC
LIMIT $7;
```

**Step 3: Run `sqlc generate`.**

**Step 4: Bump `expectedSchemaVersion` in `cmd/cvert-ops/main.go`.** Read the current value and increment by 1.

**Step 5: Commit.**

### Task 9: Security Event Writer

**Files:**
- Create: `internal/secure/writer.go`
- Create: `internal/secure/writer_test.go`
- Create: `internal/secure/ratelimit.go`
- Create: `internal/secure/ratelimit_test.go`

**Context:** Async, non-blocking event writes. `context.WithoutCancel(r.Context())`, fire-and-forget goroutine. Write failures logged to slog, never panic or affect request.

**Rate limiting on writes:** Max 10 events/minute per unique `(event_type, actor_ip)`. Excess → increment Prometheus counter (`cvertops_security_events_dropped_total`), don't write.

**⛔ IMPORTANT — Self-contained rate limiter:** The original plan referenced "same pattern as lockout manager." The lockout manager is being rewritten to DB-backed by Phase 8 bug hunt Task 6. The security event rate limiter MUST be implemented independently as an in-memory TTL-based map. Do NOT reference or import the lockout manager. The pattern is:

```go
// ABOUTME: In-memory rate limiter for security event writes.
// ABOUTME: TTL-based eviction prevents unbounded growth from distributed attacks.

type eventRateLimiter struct {
    mu      sync.Mutex
    buckets map[string]*bucket // key: "event_type|actor_ip"
    limit   int                // max events per window
    window  time.Duration      // sliding window size
    ttl     time.Duration      // evict entries older than this
    done    chan struct{}
}

type bucket struct {
    count    int
    windowStart time.Time
    lastSeen    time.Time
}
```

The rate limiter MUST have:
- A `Stop()` method that closes the `done` channel and stops the eviction goroutine (tp§14 "Goroutine shutdown path")
- A background goroutine that periodically evicts entries where `time.Since(lastSeen) > ttl`
- Thread-safe access via `sync.Mutex` (tp§1)

**Event struct passed to the writer:**

```go
type Event struct {
    Type       string    // from secure.Event* constants
    Severity   string    // from secure.Severity* constants
    ActorIP    string    // resolved client IP from clientIPMiddleware context
    ActorEmail string    // user email if known
    UserID     *uuid.UUID
    OrgID      *uuid.UUID
    Details    map[string]any
}
```

**Writer interface:**

```go
type EventWriter struct {
    store       *store.Store
    rateLimiter *eventRateLimiter
    syslog      *SyslogWriter // nil if not configured (Task 10)
    // Prometheus counters (Task 16 wires these)
}

func NewEventWriter(store *store.Store, opts ...WriterOption) *EventWriter { ... }
func (w *EventWriter) Write(ctx context.Context, event Event) { ... }
func (w *EventWriter) Stop() { ... }
```

The `Write` method:
1. Check rate limiter. If exceeded → increment Prometheus counter, return.
2. Launch goroutine with `context.WithoutCancel(ctx)`:
   a. Call store method to insert event (via `withBypassTx` — security_events has no RLS)
   b. If DB error → `slog.Error(...)`, do NOT panic
   c. If syslog writer configured → emit to syslog (also non-blocking)

**Step 1: Write tests**

```go
func TestSecurityEventWriter_WritesEvent(t *testing.T) {
    // Create writer with test DB
    // Write an event
    // Query security_events table, verify row exists with correct fields
}
func TestSecurityEventWriter_AsyncNonBlocking(t *testing.T) {
    // Verify Write() returns immediately (doesn't block on DB)
    // Use a slow-responding DB mock or channel synchronization
}
func TestSecurityEventWriter_DBErrorDoesNotPanic(t *testing.T) {
    // Use a closed DB pool (or mock that returns error)
    // Call Write() — must not panic
    // Verify slog output contains the error (tp§3.2)
}
func TestSecurityEventWriter_RateLimitsWrites(t *testing.T) {
    // Write 15 events from same (type, IP) within 1 minute
    // Verify only 10 rows in DB
}
func TestSecurityEventWriter_DifferentKeysNotLimited(t *testing.T) {
    // Write 10 events from IP-A and 10 from IP-B
    // Verify all 20 are written (different keys don't share limit)
}
func TestEventRateLimiter_TTLEviction(t *testing.T) {
    // Create rate limiter with ttl=100ms
    // Add 1000+ unique keys
    // Wait 200ms
    // Verify map size is bounded (tp§2.1)
}
func TestEventRateLimiter_Stop(t *testing.T) {
    // Call Stop(), verify eviction goroutine exits (tp§14)
}
```

**⛔ CRITICAL — actor_ip:** The `ActorIP` field in the `Event` struct MUST be populated from the resolved client IP context value set by `clientIPMiddleware` (respects `TRUSTED_PROXIES` and `X-Forwarded-For`). Read `internal/api/middleware_auth.go` to find the context key for client IP. Do NOT use `r.RemoteAddr` directly.

**Step 2: Implement writer and rate limiter.**

**Step 3: Add `EventWriter` to `ServerDeps`** in `server.go`. The `Server` struct gets an `eventWriter` field.

**Step 4: Wire `eventWriter.Stop()` into `Server.Close()`** so the rate limiter's eviction goroutine is stopped on shutdown.

**Step 5: Run tests → PASS. Step 6: Commit.**

**Testing-pitfalls review for this task:**
- tp§2.1: Bounded growth — rate limiter TTL eviction test with 1000+ keys ✓
- tp§2.4: Resource release on panic — writer catches panics in goroutine ✓
- tp§3.2: Error swallowing — DB error logged to slog, not silently dropped ✓
- tp§14: Goroutine shutdown — Stop() method closes done channel ✓

### Task 10: Syslog Output for SIEM Integration

**Files:**
- Create: `internal/secure/syslog.go`
- Create: `internal/secure/syslog_test.go`

**Context:** Optional structured syslog output for security events. Configured via `SIEM_SYSLOG_ADDR` (e.g., `udp://splunk-forwarder:514`). When configured, the event writer emits each event to syslog IN ADDITION TO the database write. Same async, non-blocking pattern — syslog failure is logged to slog but never affects the request or the DB write.

Two format options: `json` (RFC 5424 structured data, default) and `cef` (Common Event Format for ArcSight/Splunk).

Uses Go's `log/syslog` stdlib package. The writer holds an optional `*syslog.Writer` initialized at startup. If `SIEM_SYSLOG_ADDR` is empty, no syslog writer is created.

Rate limiting: shares the same per-`(event_type, actor_ip)` rate limiter as the DB writer. Events dropped by rate limiting are also not sent to syslog.

Hot-reloadable: `SIEM_SYSLOG_ADDR` and `SIEM_SYSLOG_FORMAT` are in `ReloadableConfig` (already added in Task 5). On SIGHUP, the syslog writer is recreated with the new address.

**⛔ Syslog is IN ADDITION TO the database write, not a replacement.** Both paths fire independently. A syslog failure does NOT prevent the DB write. A DB failure does NOT prevent the syslog write.

**Step 1: Write tests**

```go
func TestSyslogWriter_SendsEvent(t *testing.T) {
    // Start a UDP listener on localhost
    // Create syslog writer targeting it
    // Send a security event
    // Read from UDP listener, verify JSON payload arrived
}
func TestSyslogWriter_CEFFormat(t *testing.T) {
    // Same but with format=cef, verify CEF-formatted output
}
func TestSyslogWriter_Disabled(t *testing.T) {
    // No SIEM_SYSLOG_ADDR configured → NewSyslogWriter returns nil, no error
}
func TestSyslogWriter_UnreachableTarget(t *testing.T) {
    // Unreachable syslog target → Send returns error, does not panic
}
func TestSyslogWriter_RespectsSameRateLimit(t *testing.T) {
    // Rate-limited event → also not sent to syslog
    // (This is enforced by the event writer, not the syslog writer itself)
}
```

**Step 2: Implement.**

**Step 3: Wire into event writer** — the `EventWriter` holds an optional `*SyslogWriter`. After the DB write goroutine completes (or in parallel), if syslog is configured and the event was not rate-limited, emit to syslog.

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 11: Wire Security Events into Auth Handlers

**Files:** Multiple files in `internal/api/`. This is a systematic grep-and-wire task.

**⛔ IMPORTANT — Phase 8 and 9 bug hunt changes:** The auth handlers are being modified by the Phase 8 and 9 bug hunt remediations. Read each file BEFORE making changes. The key changes to be aware of:
- **Phase 8 bug hunt Task 3:** `loginHandler` in `auth.go` gains a disabled-user check BEFORE password verification. This is a new code path that should emit `auth.login_failed` with details noting the account is disabled.
- **Phase 8 bug hunt Task 4:** `middleware_auth.go` uses `GetUserAuthStatus` instead of `IsUserEnabled`. The middleware flow has additional branches.
- **Phase 8 bug hunt Task 6:** The lockout manager is DB-backed. `srv.lockout.Check(email)` signature changes to `srv.lockout.Check(ctx, email)`.
- **Phase 9 bug hunt Task 5:** Middleware uses `writeProblem` instead of `http.Error`.

**If the bug hunt remediations have NOT landed yet when this task executes:** Wire events into the current code, and the bug hunt changes will be merged later. The event writer calls are additive and won't conflict.

**Event wiring map — for each event type, the handler and insertion point:**

| Event Type | Handler Function | File | Where to Insert |
|------------|-----------------|------|-----------------|
| `auth.login_failed` | `loginHandler` | `auth.go` | After failed password check, after disabled-user check, after lockout rejection |
| `auth.login_success` | `loginHandler` | `auth.go` | After successful token issuance |
| `auth.account_locked` | `loginHandler` | `auth.go` | After lockout `RecordFailure` when threshold is reached |
| `auth.account_unlocked` | `adminUnlockUserHandler` | `admin_users.go` | After successful unlock |
| `auth.password_reset_requested` | `forgotPasswordHandler` | `auth.go` | After reset token created (regardless of whether email exists — no information leakage) |
| `auth.password_changed` | `changePasswordHandler`, `resetPasswordHandler` | `auth.go` | After successful password update |
| `auth.token_reuse_detected` | `refreshHandler` | `auth.go` | When refresh token reuse is detected (if implemented) |
| `auth.api_key_created` | `createAPIKeyHandler` | `apikeys.go` | After successful creation |
| `auth.api_key_used_after_revocation` | API key middleware path | `middleware_auth.go` | When a revoked API key is presented |
| `admin.user_disabled` | `adminDisableUserHandler` | `admin_users.go` | After successful disable |
| `admin.config_reloaded` | `adminReloadConfigHandler` | `admin_reload.go` | After successful reload (Task 7) |
| `admin.bulk_retry_triggered` | `adminBulkRetryHandler` | `admin_deliveries.go` | After successful bulk retry |

**Pattern for wiring:** At each insertion point, call:

```go
srv.eventWriter.Write(r.Context(), secure.Event{
    Type:       secure.EventAuthLoginFailed,
    Severity:   secure.SeverityInfo,
    ActorIP:    clientIP(r), // helper that reads from clientIPMiddleware context
    ActorEmail: email,       // if known
    UserID:     userID,      // if known, as *uuid.UUID
    Details:    map[string]any{"reason": "invalid password"},
})
```

**⛔ The `Write` call MUST pass `r.Context()`, not a new context.** The writer itself calls `context.WithoutCancel` internally. Passing `r.Context()` is correct — it allows the writer to extract the client IP from the context if stored there.

**⛔ Anti-enumeration: for `auth.login_failed` and `auth.password_reset_requested`**, log the event regardless of whether the user exists. Do NOT condition the event write on user existence — that would create an information leakage timing channel.

**Step 1: Read each file listed above. Confirm the handler function names and find the correct insertion points.**

**Step 2: Add `clientIP(r *http.Request) string` helper** in a shared location (e.g., `internal/api/helpers.go` or inline in each file). This reads the resolved IP from the context set by `clientIPMiddleware`. Read the middleware to find the exact context key.

**Step 3: Add event writer calls at each insertion point.**

**Step 4: Run existing auth tests to verify no regressions:** `go test ./internal/api/... -count=1 -race`

**Step 5: Commit.**

**Testing-pitfalls review for this task:**
- tp§13 "Admin flag enforcement at all entry points": The disabled-user path in loginHandler must also emit a security event.
- tp§3.2 "Error swallowing": The event write MUST not swallow errors — the writer logs them to slog.

### Task 12: Security Events Admin API

**Files:**
- Create: `internal/api/admin_security_events.go`
- Create: `internal/api/admin_security_events_test.go`
- Modify: `internal/api/server.go` — add route in admin group
- Modify: `internal/api/openapi_spec.go` — add spec-only Huma declaration

**Context:** `GET /api/v1/admin/security-events` — filterable by event_type, severity, date range, actor_email. Keyset-paginated. Requires site admin. Uses `withBypassTx`.

**⛔ MUST use shared contract helpers:**
- Response: `writeList(w, events, nextCursor)` from `contract.go`
- Errors: `writeProblem(w, status, detail)` from `contract.go`
- Cursor: `encodePageCursor(cursor)` / `decodePageCursor(s, &cursor)` from `contract.go`
- Limit: `parseLimitParam(w, r, 50, 100)` from `contract.go`

**Cursor struct:**

```go
type securityEventCursor struct {
    T  string `json:"t"`  // created_at as RFC3339Nano
    ID string `json:"id"` // event UUID
}
```

**Query params:** `event_type`, `severity`, `actor_email`, `since` (RFC3339), `until` (RFC3339), `cursor`, `limit`.

**Step 1: Write tests**

```go
func TestListSecurityEvents_RequiresSiteAdmin(t *testing.T) {
    // Non-admin → 403
}
func TestListSecurityEvents_ReturnsEvents(t *testing.T) {
    // Insert events, list, verify items + envelope format
}
func TestListSecurityEvents_FilterByType(t *testing.T) {
    // Insert mixed events, filter by event_type, verify only matching returned
}
func TestListSecurityEvents_Pagination(t *testing.T) {
    // Insert > limit events, verify cursor + second page
}
func TestListSecurityEvents_InvalidCursor(t *testing.T) {
    // Malformed cursor → 400 with writeProblem
}
func TestListSecurityEvents_EmptyResult(t *testing.T) {
    // No events → {"items": [], "next_cursor": ""} (not null)
}
```

**Step 2: Implement handler and sqlc query (if not already done in Task 8).**

**Step 3: Wire route:**

```go
r.Get("/security-events", srv.listSecurityEventsHandler)
```

**Step 4: Add spec-only Huma declaration.**

**Step 5: Commit.**

### Task 13: Security Events Retention

**Files:**
- Modify: `internal/config/config.go` — add `RetentionSecurityEventsDays int` field
- Modify: `internal/retention/runner.go` — add security_events cleanup

**Context:** 90 days default. Read `internal/retention/runner.go` to understand the current cleanup pattern. The `Config` struct has per-table retention fields (e.g., `RetentionAlertEventsDays`, `RetentionAuditLogDays`). Add `RetentionSecurityEventsDays` following the same pattern.

The `Run()` method has a section for global tables and a section for tier-gated tables. `security_events` is a global table (no RLS, not org-scoped), so add it to the global section.

**Step 1: Add config field:**

```go
RetentionSecurityEventsDays int `env:"RETENTION_SECURITY_EVENTS_DAYS" envDefault:"90"`
```

**Step 2: Add cleanup call in `Run()`** matching the existing global table pattern (e.g., similar to `feed_fetch_log` cleanup).

**Step 3: Write test** — insert events older than 90 days and verify cleanup removes them.

**Step 4: Commit.**

---

## Batch 5: Runtime Security Self-Checks

### Task 14: Security Doctor Checks — New Checks + Dual-Key Modifications

**Files:**
- Modify: `internal/doctor/checks.go` — modify 2 existing checks, add 3 new checks
- Modify: `internal/doctor/checks_test.go` — add tests for new checks and dual-key modifications

**⛔ IMPORTANT — Scope reduction from original plan:**

Phase 8C (Operate) already implemented these checks in `internal/doctor/checks.go`:
- `RLSCheck` — RLS enforcement ✓ already exists
- `DBRoleCheck` — DB role permissions ✓ already exists
- `EncryptionSentinelCheck` — encryption sentinel ✓ already exists (needs dual-key modification)
- `JWTCheck` — JWT configuration ✓ already exists (needs dual-key modification)

**Do NOT create `internal/secure/checks.go`.** All check implementations live in `internal/doctor/checks.go`.

**This task does 5 things:**

#### 14a: Modify `EncryptionSentinelCheck` for dual-key

The existing check at `internal/doctor/checks.go` has:

```go
type EncryptionSentinelCheck struct {
    DB  *pgxpool.Pool
    Key [32]byte
}
```

Add a `PreviousKey` field:

```go
type EncryptionSentinelCheck struct {
    DB          *pgxpool.Pool
    Key         [32]byte
    PreviousKey [32]byte // optional — zero value means no previous key
}
```

Change its `Run()` method to use `crypto.DecryptWithFallback(c.Key, c.PreviousKey, value)` instead of `crypto.Decrypt(c.Key, value)`.

**Test:** Encrypt sentinel with old key, verify check passes when old key is in `PreviousKey` slot.

#### 14b: Modify `JWTCheck` for dual-key

The existing check has:

```go
type JWTCheck struct {
    Secret string
}
```

Add a `PreviousSecret` field:

```go
type JWTCheck struct {
    Secret         string
    PreviousSecret string // optional — empty means no previous key
}
```

Change its `Run()` method: if `PreviousSecret` is non-empty and `len(PreviousSecret) < 32`, return `StatusWarn` with message about previous key being too short.

**Test:** Previous key set but < 32 bytes → warning.

#### 14c: Add `SecurityHeadersCheck` (NEW)

```go
type SecurityHeadersCheck struct {
    ServerAddr string // e.g., "http://localhost:8080" — only works in API mode
}
```

`Run()`: HTTP GET to `{ServerAddr}/healthz`. Verify response headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`

If any missing → `StatusFail`. If server not reachable → `StatusWarn` (may be running in CLI doctor mode).

**Tests:** both pass and fail paths. Use `httptest.NewServer` for the test fixture.

#### 14d: Add `SSRFProtectionCheck` (NEW)

```go
type SSRFProtectionCheck struct{}
```

`Run()`: Call safeurl's URL validation with `http://169.254.169.254/` and `http://127.0.0.1:8080/`. Verify both are rejected. No actual HTTP request made.

**Tests:** both pass (safeurl rejects) and fail (safeurl misconfigured).

#### 14e: Add `CORSCheck` (NEW)

```go
type CORSCheck struct {
    AllowedOrigins string
    CookieAuth     bool
}
```

`Run()`: If `AllowedOrigins` contains `*` and `CookieAuth` is true → `StatusWarn` with message. Otherwise → `StatusPass`.

**⛔ This is a WARN, not a FAIL.** (tp§5.1, design doc §5)

**Tests:** wildcard + cookies → warn. Specific origin + cookies → pass. Wildcard + no cookies → pass.

**Step 1: Write all tests. Step 2: Implement all checks. Step 3: Run tests → PASS. Step 4: Commit.**

### Task 15: Register Security Checks in StandardChecks

**Files:**
- Modify: `internal/doctor/checks.go` — update `StandardChecksConfig` and `StandardChecks()`

**Read `internal/doctor/checks.go` to see the current `StandardChecksConfig`:**

```go
type StandardChecksConfig struct {
    DB                    *pgxpool.Pool
    ExpectedSchemaVersion int
    SSOEncryptionKey      string
    JWTSecret             string
    SMTPHost              string
    SMTPPort              int
    SMTPUsername          string
}
```

**Step 1: Add new fields to `StandardChecksConfig`:**

```go
SSOEncryptionKeyPrevious string
JWTSecretPrevious        string
CORSAllowedOrigins       string
CookieAuth               bool
ServerAddr                string // empty in CLI mode, "http://localhost:{port}" in API mode
```

**Step 2: Update `StandardChecks()` function:**

- Pass `PreviousKey` to `EncryptionSentinelCheck`
- Pass `PreviousSecret` to `JWTCheck`
- Append `SecurityHeadersCheck`, `SSRFProtectionCheck`, `CORSCheck` to the returned slice

**Step 3: Update all callers of `StandardChecks`** to pass the new config fields. Search for `StandardChecks(` in the codebase — likely in `cmd/cvert-ops/main.go` (doctor command) and `internal/api/server.go` (doctor endpoint).

**Step 4: Commit.**

---

## Batch 6: Prometheus Metrics & Runbook

### Task 16: Security Event Prometheus Metrics

**Files:**
- Create: `internal/metrics/security.go`
- Create: `internal/metrics/security_test.go`

**Context:** Phase 8B (Observe) has landed. All metrics live in `internal/metrics/`. Follow the existing pattern (read `internal/metrics/http.go` or `internal/metrics/feed.go` for the style).

**Metrics to define:**

```go
var (
    SecurityEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "cvertops_security_events_total",
        Help: "Total security events recorded.",
    }, []string{"event_type", "severity"})

    SecurityEventsDropped = promauto.NewCounter(prometheus.CounterOpts{
        Name: "cvertops_security_events_dropped_total",
        Help: "Security events dropped by rate limiter.",
    })
)
```

**Step 1: Create metric definitions.**

**Step 2: Wire into event writer** — `SecurityEventsTotal.WithLabelValues(event.Type, event.Severity).Inc()` after successful write. `SecurityEventsDropped.Inc()` when rate-limited.

**Step 3: Add Grafana alert rule** in `deploy/grafana/alerts.yml`:

```yaml
- alert: SecurityCriticalEvent
  expr: rate(cvertops_security_events_total{severity="critical"}[5m]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: Critical security event detected
```

**Step 4: Write test** — verify counters increment correctly.

**Step 5: Commit.**

### Task 17: Secret Rotation Runbook

**Files:**
- Create: `docs/deployment/runbooks/secret-rotation.md`

**Context:** Step-by-step procedures from design doc §6:
- JWT key rotation (dual-key procedure)
- Encryption key rotation (dual-key + `rotate-encryption-key` command)
- Database credential rotation (requires restart)
- SMTP credential rotation (hot-reloadable)
- OAuth client secret rotation

Each procedure: prerequisites, exact commands, verification steps (run `doctor`), rollback.

**Step 1: Write runbook. Step 2: Commit.**

---

## Batch 7: Final Verification

### Task 18: Full Test Suite

**Step 1:** `go test ./... -count=1` (note: `-race` may not be available on Windows without CGO_ENABLED=1)
**Step 2:** `golangci-lint run`
**Step 3:** `cd web && npm run test:unit && npm run lint && npm run type-check`
**Step 4:** Fix any issues. Final commit.

---

## Subagent Failure Modes to Watch For

| # | Risk | What goes wrong | Mitigation |
|---|------|----------------|------------|
| 1 | SIGHUP added to shutdown context | Server shuts down on SIGHUP | Task 6: SEPARATE `signal.Notify` channel — most critical risk. Test: SIGHUP → server continues. |
| 2 | JWT dual-key retries on expiry | Expired token with old key should reject as expired | Task 1: `errors.Is(err, jwt.ErrTokenSignatureInvalid)` — only retry on signature error, not expiry. Test: expired token with previous key returns expiry error. |
| 3 | Encryption version byte added | Design says NO format change | Task 3: try-decrypt pattern, no wire format change. Do NOT add a version prefix to the ciphertext. |
| 4 | Security event blocks request | Async write failure affects login | Task 9: fire-and-forget goroutine with `context.WithoutCancel`. DB error logged to slog, never panics. Test: inject DB error, verify Write() returns immediately. |
| 5 | Rate limiter unbounded growth | 1000+ unique IPs fills memory | Task 9: TTL-based eviction, tested with 1000+ keys (tp§2.1). |
| 6 | Rate limiter modeled on lockout manager | Lockout manager is being rewritten to DB-backed | Task 9: SELF-CONTAINED implementation. Do NOT import or reference the lockout manager package. |
| 7 | Wrong IP in events | Uses `r.RemoteAddr` instead of resolved IP | Task 11: use `clientIPMiddleware` context value. Read the middleware to find the exact context key. |
| 8 | Missing ParseAccessToken callers | Agent only updates middleware, misses 5 other callers | Task 1: EXHAUSTIVE caller table with 8 entries. Agent must update ALL of them. |
| 9 | Missing Decrypt callers | Agent only updates SSO, misses doctor sentinel | Task 3: EXHAUSTIVE caller table. Agent must update `doctor/checks.go` too. |
| 10 | `rotate-encryption-key` scope creep | Agent guesses additional encrypted columns | Task 4: ONLY `sso_connections.client_secret_enc`. If agent encounters other BYTEA columns, they are NOT encrypted with this key. |
| 11 | `rotate-encryption-key` non-atomic | Partial failure leaves mixed state | Task 4: single transaction, rollback on error (tp§3.3). Test: inject failure mid-batch, verify rollback. |
| 12 | ReloadableConfig boundary creep | Agent makes non-reloadable fields hot-reloadable | Task 5: EXHAUSTIVE field list. `DATABASE_URL`, `HTTP_PORT`, `REGISTRATION_MODE`, `CORS_ALLOWED_ORIGINS` are explicitly listed as NOT reloadable. |
| 13 | Syslog replaces DB write | Agent makes syslog the only output | Task 10: syslog is IN ADDITION TO DB write. Both paths fire independently. |
| 14 | Syslog blocks request | Syslog send on request path | Task 10: same async pattern as DB write. Test: unreachable syslog, verify Write() returns immediately. |
| 15 | CORS check severity wrong | Agent fails instead of warns | Task 14e: `StatusWarn` not `StatusFail` (tp§5.1). |
| 16 | Windows SIGHUP compilation | Agent tries to use SIGHUP on Windows | Task 6: `//go:build !windows` on sighup_unix.go. Admin API reload works on all platforms. |
| 17 | Doctor checks duplicated | Agent creates `internal/secure/checks.go` with 7 checks | Task 14: 4 of 7 already exist in `doctor/checks.go`. Only 3 new + 2 modifications. DO NOT create `internal/secure/checks.go`. |
| 18 | Admin endpoint uses http.Error | Agent writes bare `http.Error` instead of contract helpers | Task 7, Task 12: ALL new endpoints use `writeProblem`, `writeList`, `encodePageCursor` from `contract.go`. |
| 19 | Admin endpoint missing spec-only Huma | Agent creates endpoint but no OpenAPI spec | Task 7, Task 12: spec-only Huma declaration required in `openapi_spec.go`. |
| 20 | ServerDeps not updated | Agent adds fields to Server but not ServerDeps | Task 7, Task 9: new dependencies (`ConfigHolder`, `EventWriter`) go through `ServerDeps` and are set in `NewServer`. |
| 21 | Rate limiter goroutine leaks | Agent doesn't wire Stop() into Server.Close() | Task 9: `eventWriter.Stop()` MUST be called in `Server.Close()`. Test cleanup must use `t.Cleanup(writer.Stop)` (tp§14). |
| 22 | Missing expectedSchemaVersion bump | Agent adds migration but doesn't bump the version constant | Task 8: explicitly calls out bumping `expectedSchemaVersion` in `cmd/cvert-ops/main.go`. |
| 23 | Missing sqlc generate | Agent adds SQL table but no sqlc queries | Task 8: explicitly includes sqlc query file and `sqlc generate` step. |
| 24 | Event wiring misses disabled-user path | Agent only wires events at the "wrong password" branch, not the disabled-user branch | Task 11: event wiring table shows `auth.login_failed` fires after BOTH failed password check AND disabled-user check. |
| 25 | Anti-enumeration leak via security events | Agent conditions event write on user existence | Task 11: `auth.login_failed` and `auth.password_reset_requested` fire REGARDLESS of whether the user exists. |
| 26 | Retention config missing envDefault | Agent adds config field without default → 0 days → all events deleted immediately | Task 13: `envDefault:"90"` explicitly specified. |
| 27 | Security event writer uses withOrgTx | Agent uses org-scoped transaction for a system table | Task 9: security_events has no RLS. Use `withBypassTx`. |

---

## Post-Implementation Review Findings (2026-03-17)

All 18 tasks implemented and committed (20 commits on `phase8e-secure`). Three review rounds with 4 parallel code-reviewer agents identified the following:

### Bugs found and fixed (commit `132c979`):

1. **Keyset pagination cursor ID unused in SQL WHERE** — `securityEventCursor` encoded `(T, ID)` but the SQL only used `created_at < $cursor_time`. Rows with identical timestamps were silently skipped. Fixed with composite predicate `(created_at < $6 OR (created_at = $6 AND id < $7))`.
2. **EventWriter + ConfigHolder not wired in main.go** — Both existed in the API layer and were nil-checked before use, but neither was instantiated or passed through `ServerDeps` in the `serve` command. All security event recording and admin config reload were dead code. Fixed by creating `secure.NewEventWriter(st)` and passing both to `ServerDeps`.
3. **CLI doctor always exits non-zero** — `SecurityHeadersCheck` returned `StatusWarn` in CLI mode (no `ServerAddr`), and the exit logic treated any warn as failure. Fixed to return `StatusPass` with skip message, matching SMTPCheck's pattern.
4. **Syslog comment falsely claimed RFC 3164** — Used RFC 3339 timestamps. Comment corrected.
5. **JWT test t.Logf instead of t.Errorf** — Assertion was silently passing. Fixed.

### Design-level issues for follow-up (not bugs, not fixed):

1. **SSO handlers read from static `srv.cfg`, not `configHolder`** — `ssoEncryptionKey()` and `ssoEncryptionKeyPrevious()` in `sso.go` resolve keys from the startup config, not from the hot-reloadable config holder. SSO encryption key rotation via SIGHUP or admin API reload has no effect on actual decryption until the process restarts. To fix: these helpers need to read from `srv.configHolder.Load()`.
2. **SSRFProtectionCheck is a static CIDR canary, not a production-config verification** — It hardcodes the same CIDRs that safeurl blocks and tests containment arithmetic. If safeurl is misconfigured (e.g., `AllowInternalConnections: true`), this check still passes. Consider wiring the check to attempt a `safeurl.Get` against the real client, or document the limitation explicitly.
3. **`DecryptWithFallback` zero-key sentinel + silent hex decode failure** — `LoadFromConfig` silently zeros invalid hex for SSO keys. An operator who misconfigures `SSO_ENCRYPTION_KEY_PREVIOUS` as non-hex gets no error, and `DecryptWithFallback` skips the zeroed key entirely. `LoadFromSecretsFile` does validate, so this only affects env-var-based config.

### Test coverage gap pattern:

The main.go wiring gap was undetectable by unit tests because API tests use `newAuthTestServer()` which constructs dependencies directly, bypassing the real startup path. Future phases should include an integration smoke test that verifies non-nil injection through the real entry point.
