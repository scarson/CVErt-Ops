# Phase 8E Bug Hunt Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 8 confirmed bugs from the Phase 8E (Secure pillar) bug hunt — wiring config hot-reload to consumers, fixing secrets file merge behavior, wiring SIEM syslog, and correcting several smaller issues.

**Architecture:** The primary fix is changing JWT/SSO helper functions to read from `srv.configHolder.Load()` instead of `srv.cfg` for hot-reloadable fields. The secrets file reload is changed to merge onto the startup config baseline. SIEM syslog gets wired into `main.go`. Several point fixes for crypto fallback, MFA decrypt, admin reload path, and stale SQL.

**Tech Stack:** Go, `golang-jwt/jwt/v5`, `crypto/aes` + `cipher.GCM`, `sync/atomic`, PostgreSQL, sqlc

**References:**
- Bug hunt consolidated report: `dev/bug-hunts/2026-03-17-phase8e-consolidated.md`
- Design: `dev/plans/2026-03-10-phase8-ops-secure-design.md`
- Testing pitfalls: `dev/testing-pitfalls.md`
- Implementation pitfalls: `dev/implementation-pitfalls.md`
- Config: `internal/config/config.go`, `internal/config/reloadable.go`, `internal/config/reload.go`
- JWT: `internal/auth/jwt.go`
- AES: `internal/crypto/aes.go`
- Syslog: `internal/secure/syslog.go`, `internal/secure/writer.go`
- Server: `internal/api/server.go`, `internal/api/middleware_auth.go`, `internal/api/sso.go`

**CRITICAL — File Ownership:** This plan modifies `internal/api/middleware_auth.go`, `internal/api/sso.go`, `internal/api/admin_reload.go`, `internal/config/reloadable.go`, `internal/config/reload.go`, `internal/config/config.go`, `internal/crypto/aes.go`, `internal/api/auth_mfa.go`, `internal/store/queries/security_events.sql`, `internal/secure/writer.go`, and `cmd/cvert-ops/main.go`.

---

## Pre-Implementation Requirements (ALL agents)

**Every agent MUST do the following before writing any code:**

1. Invoke the `superpowers:test-driven-development` skill and follow its methodology for every task
2. Read `dev/testing-pitfalls.md` in full — it contains checklist items that directly apply to these tasks
3. Read `dev/implementation-pitfalls.md` for Go/Postgres conventions
4. Read `CLAUDE.md` for project rules (especially: TDD, naming, comments, commit frequency)

**Every agent MUST do the following after each task:**

1. Review all new/modified tests against `dev/testing-pitfalls.md`
2. Run `go test ./...` (or the relevant package tests) and confirm all pass
3. Run `golangci-lint run` on changed packages and fix any issues
4. Commit with a descriptive message

**IMPORTANT — Read before edit:** Every task lists files to modify. Read them FIRST before making changes. Line numbers in this plan are approximate — always find the correct insertion point by reading the current file.

---

## Batch 1: Config Reload Correctness (B2 + B5 + B6)

These three bugs touch `internal/config/` and `internal/api/admin_reload.go`. Fix them first because Batch 2 (wiring the config holder) depends on the reload producing correct values.

### Task 1: Secrets file merge onto startup baseline (B2)

**Files:**
- Modify: `internal/config/reloadable.go` — change `LoadFromSecretsFile` to accept a baseline `*ReloadableConfig`
- Modify: `internal/config/reloadable_test.go` — add/update tests
- Modify: `internal/config/reload.go` — pass the baseline from the holder

**Context (bug B2):** `LoadFromSecretsFile` creates a fresh `ReloadableConfig{}` from scratch. Missing fields get zero values. A partial secrets file (e.g., only `JWT_SECRET`) would zero out SMTP, SSO, SIEM, and everything else. The fix: merge file values onto the startup config baseline so absent fields keep their startup values.

**Step 1: Write failing tests**

Add tests to `reloadable_test.go`:

```go
func TestLoadFromSecretsFile_MergesOntoBaseline(t *testing.T) {
    // Create a baseline with SMTP and SSO populated.
    baseline := &ReloadableConfig{
        JWTSecret:        []byte("original-jwt-secret-at-least-32-bytes!!"),
        SMTPHost:         "smtp.example.com",
        SMTPPort:         587,
        SSOEncryptionKey: [32]byte{1, 2, 3}, // non-zero
        SIEMSyslogAddr:   "udp://siem:514",
    }
    // Secrets file only contains JWT_SECRET.
    tmpFile := writeTempSecretsFile(t, "JWT_SECRET=new-jwt-secret-at-least-32-bytes!!")

    got, err := LoadFromSecretsFile(tmpFile, baseline)
    require.NoError(t, err)
    // JWT_SECRET was overwritten:
    assert.Equal(t, []byte("new-jwt-secret-at-least-32-bytes!!"), got.JWTSecret)
    // Other fields preserved from baseline:
    assert.Equal(t, "smtp.example.com", got.SMTPHost)
    assert.Equal(t, 587, got.SMTPPort)
    assert.Equal(t, [32]byte{1, 2, 3}, got.SSOEncryptionKey)
    assert.Equal(t, "udp://siem:514", got.SIEMSyslogAddr)
}

func TestLoadFromSecretsFile_NilBaselineCreatesFromScratch(t *testing.T) {
    // When baseline is nil (first startup before holder is seeded),
    // absent fields default to zero values.
    tmpFile := writeTempSecretsFile(t, "JWT_SECRET=new-jwt-secret-at-least-32-bytes!!")

    got, err := LoadFromSecretsFile(tmpFile, nil)
    require.NoError(t, err)
    assert.Equal(t, []byte("new-jwt-secret-at-least-32-bytes!!"), got.JWTSecret)
    assert.Equal(t, "", got.SMTPHost) // zero since no baseline
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run TestLoadFromSecretsFile_Merges -v`
Expected: FAIL — `LoadFromSecretsFile` signature doesn't accept baseline

**Step 3: Implement**

Change `LoadFromSecretsFile` signature from:
```go
func LoadFromSecretsFile(path string) (*ReloadableConfig, error)
```
to:
```go
func LoadFromSecretsFile(path string, baseline *ReloadableConfig) (*ReloadableConfig, error)
```

At the start of the function, instead of `rc := &ReloadableConfig{}`, do:
```go
// Start from a copy of the baseline so absent fields keep their current values.
var rc *ReloadableConfig
if baseline != nil {
    copy := *baseline
    rc = &copy
} else {
    rc = &ReloadableConfig{}
}
```

The rest of the function remains the same — it overwrites fields present in the file onto `rc`.

**Step 4: Update all callers of `LoadFromSecretsFile`**

There are exactly two callers:

1. `internal/config/reload.go:23` — `ReloadConfig`:
   ```go
   // Before:
   newCfg, err := LoadFromSecretsFile(secretsFile)
   // After:
   newCfg, err := LoadFromSecretsFile(secretsFile, holder.Load())
   ```

2. `internal/api/admin_reload.go:31` — `adminReloadConfigHandler`:
   ```go
   // Before:
   newCfg, err := config.LoadFromSecretsFile(secretsFile)
   // After:
   newCfg, err := config.LoadFromSecretsFile(secretsFile, srv.configHolder.Load())
   ```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -v && go test ./internal/api/ -run TestAdminReload -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/config/reloadable.go internal/config/reloadable_test.go internal/config/reload.go internal/api/admin_reload.go
git commit -m "fix(config): merge secrets file onto baseline — partial files no longer zero fields"
```

### Task 2: Admin reload uses `ReloadConfig` + sanitized error (B5 + B6)

**Files:**
- Modify: `internal/api/admin_reload.go` — use `ReloadConfig`, sanitize error
- Modify: `internal/api/admin_reload_test.go` — update tests
- Modify: `internal/api/server.go` — add `rescanFunc` field to `Server`

**Context (bug B5):** `adminReloadConfigHandler` calls `LoadFromSecretsFile` and `configHolder.Store` directly, bypassing `config.ReloadConfig()` which also calls the feed rescan function. On Windows (no SIGHUP), feed config changes are never re-scanned.

**Context (bug B6):** Line 34 returns `err.Error()` to the client, potentially leaking file paths.

**Step 1: Write failing test for rescan call**

Add to `admin_reload_test.go`:
```go
func TestAdminReloadConfig_CallsRescan(t *testing.T) {
    // Set up server with a rescan function that sets a flag.
    var rescanCalled atomic.Bool
    srv := newTestServerWithRescan(t, func() { rescanCalled.Store(true) })
    // Write a valid secrets file, POST /api/v1/admin/reload-config.
    // Assert rescanCalled is true.
}
```

Add to `admin_reload_test.go`:
```go
func TestAdminReloadConfig_DoesNotLeakErrorDetails(t *testing.T) {
    // Point CVERTOPS_SECRETS_FILE at a nonexistent path.
    // POST /api/v1/admin/reload-config.
    // Assert response body does NOT contain the file path.
    // Assert response body contains a generic message.
}
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement**

In `server.go`, add a field to `ServerDeps` and `Server`:
```go
// In ServerDeps:
RescanFunc func() // called after successful config reload

// In Server:
rescanFunc func{} // feed config rescan on hot-reload
```

Wire it in `NewServer`:
```go
srv.rescanFunc = deps.RescanFunc
```

In `main.go`, pass the rescan function when creating `ServerDeps`:
```go
// In runServe, after the feedLoader is available:
RescanFunc: feedLoader.Rescan, // nil if no feeds dir configured
```
If `feedLoader` doesn't exist (no `FeedsDir`), pass nil.

Rewrite `adminReloadConfigHandler` to use `ReloadConfig`:
```go
func (srv *Server) adminReloadConfigHandler(w http.ResponseWriter, r *http.Request) {
    secretsFile := srv.cfg.SecretsFile
    if secretsFile == "" {
        writeJSON(w, http.StatusOK, map[string]string{"message": "no secrets file configured"})
        return
    }

    if srv.configHolder == nil {
        slog.ErrorContext(r.Context(), "admin reload-config: config holder not initialized")
        writeProblem(w, http.StatusInternalServerError, "internal error")
        return
    }

    // Use ReloadConfig for parity with SIGHUP handler (includes rescan).
    // ReloadConfig logs errors internally and recovers panics.
    oldCfg := srv.configHolder.Load()
    config.ReloadConfig(srv.configHolder, secretsFile, srv.rescanFunc)
    newCfg := srv.configHolder.Load()

    // If the pointer didn't change, reload failed — config was kept.
    if oldCfg == newCfg {
        writeProblem(w, http.StatusBadRequest, "config reload failed: check server logs for details")
        return
    }

    if srv.eventWriter != nil {
        callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
        srv.eventWriter.Write(r.Context(), secure.Event{
            Type:     secure.EventAdminConfigReloaded,
            Severity: secure.SeverityInfo,
            ActorIP:  clientIP(r.Context()),
            UserID:   &callerID,
        })
    }

    writeJSON(w, http.StatusOK, map[string]string{"message": "config reloaded"})
}
```

**Important nuance:** `ReloadConfig` recovers panics and logs errors — it doesn't return an error. We detect failure by comparing the `configHolder` pointer before and after. If the pointer is the same object, reload failed (ReloadConfig only calls `Store` on success).

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -run TestAdminReload -v`

**Step 5: Commit**

```bash
git add internal/api/admin_reload.go internal/api/admin_reload_test.go internal/api/server.go cmd/cvert-ops/main.go
git commit -m "fix(reload): admin API uses ReloadConfig for SIGHUP parity + sanitize error"
```

**After Batch 1: Review loop**

```
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Batch 2: Wire Config Holder to JWT/SSO Consumers (B1)

This is the largest fix — changing ~30 call sites to read from the hot-reloadable config holder instead of the static startup config. The key insight is that there are **three helper choke points** that cover most call sites.

### Task 3: Wire JWT helpers to read from configHolder

**Files:**
- Modify: `internal/api/middleware_auth.go` — change `jwtPreviousSecret` helper
- Modify: `internal/api/server.go` — add `jwtSecret()` and `jwtPreviousSecretBytes()` methods on `Server`
- Modify: `internal/api/middleware_auth_test.go` — add hot-reload test
- Modify: `internal/api/auth.go` — update all `secret := []byte(srv.cfg.JWTSecret)` call sites
- Modify: `internal/api/auth_mfa.go` — update all JWT secret call sites
- Modify: `internal/api/auth_email_verification.go` — update ParseAccessToken call
- Modify: `internal/api/oauth_github.go` — update JWT secret
- Modify: `internal/api/oauth_google.go` — update JWT secret
- Modify: `internal/api/oauth_oidc.go` — update JWT secret

**Context (bug B1):** Every JWT sign/parse call reads `srv.cfg.JWTSecret` (static startup config). After this fix, they read from `srv.configHolder.Load()` so hot-reloaded keys take effect immediately.

**Strategy:** Create two methods on `*Server`:
1. `jwtSecret() []byte` — returns the active JWT secret from the config holder (falls back to `srv.cfg.JWTSecret` if the holder is nil or has empty JWTSecret)
2. `jwtPreviousSecretBytes() []byte` — replaces the current `jwtPreviousSecret(cfg)` free function

This minimizes diff across ~30 call sites: `[]byte(srv.cfg.JWTSecret)` becomes `srv.jwtSecret()`, and `jwtPreviousSecret(srv.cfg)` becomes `srv.jwtPreviousSecretBytes()`.

**Step 1: Write failing test**

Add to `middleware_auth_test.go`:
```go
func TestRequireAuthenticated_ReadsFromConfigHolder(t *testing.T) {
    // 1. Create server with JWTSecret="original" and a configHolder
    // 2. Issue token with "new-secret"
    // 3. Request with token → fails (signed with wrong key)
    // 4. Update configHolder with JWTSecret="new-secret"
    // 5. Request with same token → succeeds (holder was read)
}
```

**Step 2: Run test to verify it fails**

**Step 3: Implement**

In `middleware_auth.go`, replace the free function `jwtPreviousSecret(cfg)` with two methods on `*Server`:

```go
// jwtSecret returns the active JWT signing/verification secret.
// Reads from the hot-reloadable config holder if available;
// falls back to the startup config.
func (srv *Server) jwtSecret() []byte {
    if srv.configHolder != nil {
        if rc := srv.configHolder.Load(); rc != nil && len(rc.JWTSecret) > 0 {
            return rc.JWTSecret
        }
    }
    return []byte(srv.cfg.JWTSecret)
}

// jwtPreviousSecretBytes returns the previous JWT secret for dual-key
// rotation, or nil if no previous secret is configured.
func (srv *Server) jwtPreviousSecretBytes() []byte {
    if srv.configHolder != nil {
        if rc := srv.configHolder.Load(); rc != nil && len(rc.JWTSecretPrevious) > 0 {
            return rc.JWTSecretPrevious
        }
    }
    if srv.cfg.JWTSecretPrevious == "" {
        return nil
    }
    return []byte(srv.cfg.JWTSecretPrevious)
}
```

Delete the old `jwtPreviousSecret(cfg *config.Config)` free function.

**Step 4: Update ALL call sites**

This is a mechanical find-and-replace. The exhaustive list:

| File | Line (approx) | Before | After |
|------|---------------|--------|-------|
| `middleware_auth.go` | 48 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth.go` | 269 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `auth.go` | 555 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `auth.go` | 556 | `jwtPreviousSecret(srv.cfg)` | `srv.jwtPreviousSecretBytes()` |
| `auth.go` | 670 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth.go` | 713 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth.go` | 789 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth.go` | 795 | `[]byte(srv.cfg.JWTSecret)` | `srv.jwtSecret()` |
| `auth.go` | 904 | `[]byte(srv.cfg.JWTSecret)` | `srv.jwtSecret()` |
| `auth.go` | 993 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth_email_verification.go` | 100 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth_mfa.go` | 264 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `auth_mfa.go` | 318 | `[]byte(srv.cfg.JWTSecret)` | `srv.jwtSecret()` |
| `auth_mfa.go` | 330 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `auth_mfa.go` | 343 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `auth_mfa.go` | 579 | `jwtSecret := []byte(srv.cfg.JWTSecret)` | `jwtSecret := srv.jwtSecret()` |
| `auth_mfa.go` | 622 | `[]byte(srv.cfg.JWTSecret)` | `srv.jwtSecret()` |
| `auth_mfa.go` | 1150 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `auth_mfa.go` | 1154 | `jwtPreviousSecret(srv.cfg)` | `srv.jwtPreviousSecretBytes()` |
| `auth_mfa.go` | 1181 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |
| `auth_mfa.go` | 1219 | `[]byte(srv.cfg.JWTSecret)` | `srv.jwtSecret()` |
| `auth_mfa.go` | 1225 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `oauth_github.go` | 174 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `oauth_google.go` | 162 | `secret := []byte(srv.cfg.JWTSecret)` | `secret := srv.jwtSecret()` |
| `oauth_oidc.go` | 257 | `jwtSecret := []byte(srv.cfg.JWTSecret)` | `jwtSecret := srv.jwtSecret()` |
| `oauth_oidc.go` | 330 | `[]byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg)` | `srv.jwtSecret(), srv.jwtPreviousSecretBytes()` |

**⛔ AFTER completing the mechanical replacement, grep the entire `internal/api/` directory for any remaining `srv.cfg.JWTSecret` references.** There must be ZERO remaining references to `srv.cfg.JWTSecret` in production code (test files are OK since they construct configs directly). Also grep for `jwtPreviousSecret(` to confirm the old free function has no remaining callers.

**Step 5: Run full test suite**

Run: `go test ./internal/api/... -count=1`
Expected: PASS (all existing tests still work because `jwtSecret()` falls back to `srv.cfg`)

**Step 6: Commit**

```bash
git add internal/api/middleware_auth.go internal/api/auth.go internal/api/auth_mfa.go internal/api/auth_email_verification.go internal/api/oauth_github.go internal/api/oauth_google.go internal/api/oauth_oidc.go internal/api/middleware_auth_test.go
git commit -m "fix(auth): JWT handlers read from configHolder — hot-reload now functional"
```

### Task 4: Wire SSO encryption helpers to read from configHolder

**Files:**
- Modify: `internal/api/sso.go` — change `ssoEncryptionKey()` and `ssoEncryptionKeyPrevious()`
- Modify: `internal/api/admin_doctor.go` — wire doctor checks to configHolder

**Context:** `ssoEncryptionKey()` and `ssoEncryptionKeyPrevious()` read hex strings from `srv.cfg` and decode them. After this fix, they read the pre-decoded `[32]byte` from the config holder (which was decoded during `LoadFromSecretsFile` or `LoadFromConfig`).

**Step 1: Implement**

Change `ssoEncryptionKey()` in `sso.go`:
```go
func (srv *Server) ssoEncryptionKey() ([32]byte, error) {
    if srv.configHolder != nil {
        if rc := srv.configHolder.Load(); rc != nil && rc.SSOEncryptionKey != [32]byte{} {
            return rc.SSOEncryptionKey, nil
        }
    }
    // Fallback to startup config (hex decode).
    var key [32]byte
    raw, err := hex.DecodeString(srv.cfg.SSOEncryptionKey)
    if err != nil {
        return key, fmt.Errorf("SSO_ENCRYPTION_KEY: invalid hex: %w", err)
    }
    if len(raw) != 32 {
        return key, fmt.Errorf("SSO_ENCRYPTION_KEY: need 32 bytes, got %d", len(raw))
    }
    copy(key[:], raw)
    return key, nil
}
```

Change `ssoEncryptionKeyPrevious()`:
```go
func (srv *Server) ssoEncryptionKeyPrevious() [32]byte {
    if srv.configHolder != nil {
        if rc := srv.configHolder.Load(); rc != nil {
            return rc.SSOEncryptionKeyPrev
        }
    }
    // Fallback to startup config.
    var key [32]byte
    if srv.cfg.SSOEncryptionKeyPrevious == "" {
        return key
    }
    raw, err := hex.DecodeString(srv.cfg.SSOEncryptionKeyPrevious)
    if err != nil || len(raw) != 32 {
        return key
    }
    copy(key[:], raw)
    return key
}
```

Also update `admin_doctor.go` — the doctor checks should read from the holder too. Currently it passes `srv.cfg.JWTSecret` etc. to `StandardChecksConfig`. Read the current code and update it to pass from the config holder when available.

**Step 2: Run tests**

Run: `go test ./internal/api/... -count=1`
Expected: PASS

**Step 3: Verify no remaining references**

Grep `internal/api/` for `srv.cfg.SSOEncryptionKey` — should only remain in test files or fallback paths within the helpers themselves.

**Step 4: Commit**

```bash
git add internal/api/sso.go internal/api/admin_doctor.go
git commit -m "fix(sso): SSO encryption helpers read from configHolder — hot-reload functional"
```

**After Batch 2: Review loop**

```
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Batch 3: SIEM Syslog Wiring + SetSyslog Race Fix (B3 + D4)

### Task 5: Add SIEM env vars to Config + wire syslog in main.go

**Files:**
- Modify: `internal/config/config.go` — add `SIEMSyslogAddr`, `SIEMSyslogFormat`
- Modify: `internal/config/reloadable.go` — populate SIEM fields in `LoadFromConfig`
- Modify: `internal/secure/writer.go` — make `syslog` field an `atomic.Pointer[SyslogWriter]` (fixes D4 race)
- Modify: `internal/secure/writer_test.go` — test syslog integration
- Modify: `cmd/cvert-ops/main.go` — wire syslog at startup

**Context (bug B3):** `SyslogWriter` is fully implemented but never instantiated or connected. `SIEMSyslogAddr`/`SIEMSyslogFormat` exist on `ReloadableConfig` but not on the startup `Config`, so there's no way to configure them via env vars. (bug D4): `SetSyslog` writes `w.syslog` without synchronization while goroutines read it.

**Step 1: Add env vars to Config**

In `config.go`, add after the `SecretsFile` field:
```go
// ── SIEM — Syslog forwarding ────────────────────────────────────────────────
SIEMSyslogAddr   string `env:"SIEM_SYSLOG_ADDR"`   // e.g., "udp://splunk:514"; empty = disabled
SIEMSyslogFormat string `env:"SIEM_SYSLOG_FORMAT" envDefault:"json"` // "json" or "cef"
```

Update `LogValue()` to include them (non-sensitive, no masking needed).

**Step 2: Populate SIEM fields in `LoadFromConfig`**

In `reloadable.go`, in `LoadFromConfig`, add:
```go
rc.SIEMSyslogAddr = cfg.SIEMSyslogAddr
rc.SIEMSyslogFormat = cfg.SIEMSyslogFormat
```

**Step 3: Fix SetSyslog race — use atomic.Pointer**

In `writer.go`, change the `syslog` field:
```go
type EventWriter struct {
    store       *store.Store
    rateLimiter *eventRateLimiter
    syslog      atomic.Pointer[SyslogWriter]
    wg          sync.WaitGroup
}
```

Update `SetSyslog`:
```go
func (w *EventWriter) SetSyslog(sw *SyslogWriter) {
    w.syslog.Store(sw)
}
```

Update the read in `Write` goroutine:
```go
// Forward to syslog independently of DB result.
if sw := w.syslog.Load(); sw != nil {
    if sErr := sw.Send(event); sErr != nil {
        slog.Error("security event syslog send failed",
            "event_type", event.Type,
            "error", sErr,
        )
    }
}
```

**Step 4: Wire in main.go**

After creating `eventWriter`, before `apiSrv`:
```go
// Wire SIEM syslog forwarding if configured.
if cfg.SIEMSyslogAddr != "" {
    sw, sErr := secure.NewSyslogWriter(cfg.SIEMSyslogAddr, cfg.SIEMSyslogFormat)
    if sErr != nil {
        slog.Error("SIEM syslog initialization failed — events will only go to database", "error", sErr)
    } else if sw != nil {
        eventWriter.SetSyslog(sw)
        defer sw.Close()
        slog.Info("SIEM syslog forwarding enabled", "addr", cfg.SIEMSyslogAddr, "format", cfg.SIEMSyslogFormat)
    }
}
```

**Step 5: Write test for atomic syslog access**

In `writer_test.go`:
```go
func TestEventWriter_SetSyslogConcurrent(t *testing.T) {
    // Run with -race flag.
    // Create EventWriter, spawn goroutines calling Write,
    // concurrently call SetSyslog with a new SyslogWriter.
    // Must not race.
}
```

**Step 6: Run tests**

Run: `go test -race ./internal/secure/... -v && go test ./internal/config/... -v`

**Step 7: Commit**

```bash
git add internal/config/config.go internal/config/reloadable.go internal/secure/writer.go internal/secure/writer_test.go cmd/cvert-ops/main.go
git commit -m "fix(siem): wire syslog writer at startup + atomic.Pointer for SetSyslog race"
```

---

## Batch 4: Point Fixes (B4 + D3 + O1 + O2)

These are independent single-file fixes. They can be done in parallel if using subagent-driven development, or sequentially.

### Task 6: TOTP enrollment confirm uses DecryptWithFallback (B4)

**Files:**
- Modify: `internal/api/auth_mfa.go` — line 636
- Modify: `internal/api/auth_mfa_test.go` — add test for key rotation during enrollment

**Context:** Line 636 uses `crypto.Decrypt(encKey, enrollClaims.SecretEnc)` — single-key only. Other MFA paths (e.g., line 378) correctly use `crypto.DecryptWithFallback`. If the SSO encryption key is rotated between enrollment start and confirm, the confirm step fails.

**Step 1: Write failing test**

```go
func TestTOTPConfirm_DecryptsWithPreviousKey(t *testing.T) {
    // 1. Create an enrollment token whose SecretEnc was encrypted with oldKey
    // 2. Rotate keys: set currentKey=newKey, previousKey=oldKey
    // 3. Call the confirm handler
    // 4. Assert it succeeds (decrypts with fallback to previous key)
}
```

**Step 2: Implement**

Change line 636 from:
```go
secretBytes, err := crypto.Decrypt(encKey, enrollClaims.SecretEnc)
```
to:
```go
prevKey := srv.ssoEncryptionKeyPrevious()
secretBytes, err := crypto.DecryptWithFallback(encKey, prevKey, enrollClaims.SecretEnc)
```

**Step 3: Run tests**

Run: `go test ./internal/api/ -run TestTOTP -v`

**Step 4: Commit**

```bash
git add internal/api/auth_mfa.go internal/api/auth_mfa_test.go
git commit -m "fix(mfa): TOTP confirm uses DecryptWithFallback for key rotation"
```

### Task 7: DecryptWithFallback gates on GCM auth error only (D3)

**Files:**
- Modify: `internal/crypto/aes.go` — check error type before fallback
- Modify: `internal/crypto/aes_test.go` — add test for structural errors

**Context:** `DecryptWithFallback` falls back on ALL errors. It should only fall back on GCM authentication tag failure (indicating wrong key). Structural errors (truncated ciphertext, etc.) should fail immediately.

**Step 1: Write failing test**

```go
func TestDecryptWithFallback_TruncatedCiphertext_NoFallback(t *testing.T) {
    // Provide data that is too short for a nonce (< 12 bytes).
    // With a valid previous key, the function should NOT attempt
    // the previous key — it should fail immediately with "ciphertext too short".
    currentKey := [32]byte{1}
    previousKey := [32]byte{2}
    shortData := []byte("short")

    _, err := DecryptWithFallback(currentKey, previousKey, shortData)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "ciphertext too short")
    // Should NOT contain "both keys failed" — fallback was not attempted.
    assert.NotContains(t, err.Error(), "both keys failed")
}
```

**Step 2: Implement**

The GCM authentication failure in Go's `cipher` package manifests as `gcm.Open` returning an error. The error message from `cipher.gcmOpen` is "cipher: message authentication failed". We need to check for this specific error in the `Decrypt` return. However, the `crypto/cipher` package doesn't export a sentinel error — it returns a plain `error`.

**Approach:** Since `Decrypt` wraps the error with `fmt.Errorf("gcm decrypt: %w", err)`, and the only error from `gcm.Open` is the authentication failure, we can distinguish by checking whether `Decrypt` returned the "gcm decrypt:" prefix (authentication tag mismatch) vs other errors ("ciphertext too short", "aes new cipher:"). Only fall back if the error contains "gcm decrypt:".

```go
func DecryptWithFallback(currentKey, previousKey [32]byte, data []byte) ([]byte, error) {
    plaintext, err := Decrypt(currentKey, data)
    if err == nil {
        return plaintext, nil
    }

    // Only fall back on GCM authentication failure (wrong key).
    // Structural errors (truncated ciphertext, invalid key) fail fast.
    if previousKey != [32]byte{} && isGCMAuthError(err) {
        plaintext, err2 := Decrypt(previousKey, data)
        if err2 == nil {
            return plaintext, nil
        }
        return nil, fmt.Errorf("decrypt with both keys failed: current: %w, previous: %v", err, err2)
    }

    return nil, err
}

// isGCMAuthError returns true if the error is a GCM authentication tag mismatch,
// which indicates the ciphertext was encrypted with a different key.
func isGCMAuthError(err error) bool {
    return err != nil && strings.Contains(err.Error(), "gcm decrypt:")
}
```

Add `"strings"` to the import list.

**Step 3: Run tests**

Run: `go test ./internal/crypto/... -v`

**Step 4: Commit**

```bash
git add internal/crypto/aes.go internal/crypto/aes_test.go
git commit -m "fix(crypto): DecryptWithFallback gates on GCM auth error only"
```

### Task 8: Fix stale sqlc query for security events (O1)

**Files:**
- Modify: `internal/store/queries/security_events.sql` — add ID tiebreaker
- Regenerate: `internal/store/generated/security_events.sql.go` — run `sqlc generate`

**Context:** The sqlc query uses single-column cursor `created_at < $6` with 7 params. The hand-written query has composite cursor `(created_at, id)` with 8 params. The sqlc version is unused but stale.

**Step 1: Update the sqlc query**

Change `security_events.sql` `ListSecurityEvents` to match the hand-written query:
```sql
-- name: ListSecurityEvents :many
SELECT id, event_type, severity, actor_ip, actor_email, user_id, org_id, details, created_at
FROM security_events
WHERE
    ($1::text IS NULL OR event_type = $1) AND
    ($2::text IS NULL OR severity = $2) AND
    ($3::text IS NULL OR actor_email = $3) AND
    ($4::timestamptz IS NULL OR created_at >= $4) AND
    ($5::timestamptz IS NULL OR created_at <= $5) AND
    ($6::timestamptz IS NULL OR (created_at < $6 OR (created_at = $6 AND id < $7)))
ORDER BY created_at DESC, id DESC
LIMIT $8;
```

**Step 2: Regenerate**

Run: `sqlc generate`

**Step 3: Verify the generated code compiles**

Run: `go build ./internal/store/...`

**Step 4: Commit**

```bash
git add internal/store/queries/security_events.sql internal/store/generated/security_events.sql.go internal/store/generated/models.go
git commit -m "fix(store): sync sqlc security events query with hand-written composite cursor"
```

### Task 9: Add startup warning for invalid SSO hex keys (O2)

**Files:**
- Modify: `internal/config/reloadable.go` — add `slog.Warn` in `LoadFromConfig`

**Context:** `LoadFromConfig` silently zeros invalid hex for SSO keys with `if key, err := decodeHexKey(...); err == nil`. An operator who misconfigures `SSO_ENCRYPTION_KEY_PREVIOUS` gets no error.

**Step 1: Implement**

Change `LoadFromConfig` from:
```go
if key, err := decodeHexKey(cfg.SSOEncryptionKey, "SSO_ENCRYPTION_KEY"); err == nil {
    rc.SSOEncryptionKey = key
}
if key, err := decodeHexKey(cfg.SSOEncryptionKeyPrevious, "SSO_ENCRYPTION_KEY_PREVIOUS"); err == nil {
    rc.SSOEncryptionKeyPrev = key
}
```
to:
```go
if cfg.SSOEncryptionKey != "" {
    if key, err := decodeHexKey(cfg.SSOEncryptionKey, "SSO_ENCRYPTION_KEY"); err == nil {
        rc.SSOEncryptionKey = key
    } else {
        slog.Warn("invalid SSO_ENCRYPTION_KEY — SSO encryption will not work", "error", err)
    }
}
if cfg.SSOEncryptionKeyPrevious != "" {
    if key, err := decodeHexKey(cfg.SSOEncryptionKeyPrevious, "SSO_ENCRYPTION_KEY_PREVIOUS"); err == nil {
        rc.SSOEncryptionKeyPrev = key
    } else {
        slog.Warn("invalid SSO_ENCRYPTION_KEY_PREVIOUS — dual-key rotation will not work", "error", err)
    }
}
```

Only warn when the field is non-empty but invalid. Empty is fine (means "not configured").

**Step 2: Run tests**

Run: `go test ./internal/config/... -v`

**Step 3: Commit**

```bash
git add internal/config/reloadable.go
git commit -m "fix(config): warn on invalid SSO hex keys at startup instead of silent zero"
```

**After Batch 4: Review loop**

```
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Final: Run full test suite

Run: `go test ./... -count=1 && golangci-lint run`

Verify all tests pass and no lint issues.
