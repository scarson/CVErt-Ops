# Bug Hunt Report Phase 8E (Secure Pillar) Holistic Analysis

## Scope

Packages/files analyzed from PR #43:
- internal/auth/jwt.go, internal/crypto/aes.go, cmd/cvert-ops/rotate.go
- internal/config/config.go, reloadable.go, reload.go, sighup_unix.go, sighup_windows.go
- internal/api/admin_reload.go, admin_security_events.go, server.go, middleware_auth.go, auth.go
- internal/api/auth_email_verification.go, auth_password_reset.go, oauth_oidc.go, sso.go
- internal/secure/writer.go, ratelimit.go, syslog.go, events.go
- internal/metrics/security.go, internal/doctor/checks.go, internal/retention/runner.go
- internal/store/security_events.go, queries/security_events.sql
- migrations/000039_create_security_events.up.sql, cmd/cvert-ops/main.go, doctor.go

Approach: Read all source files into context, then reason about correctness across the full system. Focused on JWT/config state consistency, concurrency in the event pipeline, data flow correctness in hot-reload, crypto error handling in fallback paths.

## Bugs

### 1. JWT secret reads from static srv.cfg.JWTSecret -- never observes hot-reloaded secrets

**Location:** internal/api/middleware_auth.go:48, internal/api/auth.go:269,555,670,713,789,993, internal/api/auth_email_verification.go:100, internal/api/auth_mfa.go:264,318,330,343,579,622,1150,1181,1219,1225, internal/api/oauth_oidc.go:257,330, internal/api/oauth_github.go:174, internal/api/oauth_google.go:162

**Severity:** significant

**Evidence:** The admin reload handler at admin_reload.go:38 stores the new config in srv.configHolder, and ReloadConfig at reload.go:29 does the same. However, every JWT parse and issue call across the entire API layer reads from srv.cfg.JWTSecret (the static startup config), not from srv.configHolder.Load().JWTSecret. For example:

- middleware_auth.go:48: auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg))
- auth.go:269: secret := []byte(srv.cfg.JWTSecret)
- auth.go:555: secret := []byte(srv.cfg.JWTSecret)
- oauth_oidc.go:257: jwtSecret := []byte(srv.cfg.JWTSecret)

The jwtPreviousSecret() helper at middleware_auth.go:20-25 also reads from cfg.JWTSecretPrevious (the static startup config pointer).

**Impact:** Hot-reloading JWT secrets via SIGHUP or admin API is a no-op for actual JWT operations. The configHolder gets updated, but nothing reads from it. After a secrets file reload with a new JWT secret, new tokens are still signed with the old key. The entire JWT hot-reload feature is non-functional.

### 2. SSO encryption key reads from static srv.cfg -- never observes hot-reloaded keys

**Location:** internal/api/sso.go:71-97, internal/api/oauth_oidc.go:52-57

**Severity:** significant

**Evidence:** ssoEncryptionKey() at sso.go:71 reads srv.cfg.SSOEncryptionKey and ssoEncryptionKeyPrevious() at sso.go:86 reads srv.cfg.SSOEncryptionKeyPrevious -- both from the immutable startup config. The configHolder stores SSOEncryptionKey and SSOEncryptionKeyPrev but nothing in the SSO/OIDC code path reads from it.

**Impact:** Same as bug #1 but for AES encryption. Hot-reloading SSO encryption keys is non-functional.

### 3. Admin reload handler skips feed config rescan

**Location:** internal/api/admin_reload.go:31-51

**Severity:** minor

**Evidence:** The ReloadConfig function at reload.go:11 accepts a rescan func() parameter and calls it after a successful reload. The SIGHUP handler at sighup_unix.go:24 passes this through correctly. However, adminReloadConfigHandler at admin_reload.go:31 calls config.LoadFromSecretsFile and srv.configHolder.Store(newCfg) directly, bypassing ReloadConfig entirely. It never calls the feed rescan function.

**Impact:** Feed configuration file changes are re-scanned on SIGHUP (Unix) but not on admin API reload. This is an inconsistency between the two reload paths. On Windows (where SIGHUP does not exist), the admin API is the only reload mechanism, and it will never trigger feed config rescan.

### 4. DecryptWithFallback falls back on ALL errors, not just GCM authentication failure

**Location:** internal/crypto/aes.go:16-31

**Severity:** minor

**Evidence:** The DecryptWithFallback function tries Decrypt(currentKey, data), and if any error occurs (not just GCM authentication failure), it falls back to previousKey. Compare this with the JWT dual-key design at jwt.go:63 which explicitly checks errors.Is(err, jwt.ErrTokenSignatureInvalid) and only falls back on signature errors.

In the AES case, if data is too short (< 12 bytes), Decrypt returns "ciphertext too short". The fallback will also return the same error (since the data length does not change between attempts), doing unnecessary work with a confusing compound error message.

**Impact:** Low practical impact given AES-256 always succeeds with 32-byte keys, but violates the design principle established by the JWT implementation (only fall back on authentication/signature errors). The mismatch between JWT and AES fallback strategies is a fragile asymmetry.

### 5. LoadFromSecretsFile returns zero-value fields when keys are absent, silently clearing live config

**Location:** internal/config/reloadable.go:58-149, internal/config/reload.go:23-29

**Severity:** significant

**Evidence:** LoadFromSecretsFile returns a ReloadableConfig where unset fields retain their zero values. For example, if JWT_SECRET is missing from the secrets file, rc.JWTSecret is nil (empty []byte). At reload.go:29, holder.Store(newCfg) atomically replaces the entire config.

If the secrets file omits a field that was previously set via environment variables at startup (e.g., JWT_SECRET is in the env but not in the secrets file), the reload will replace the live config with one where JWTSecret is nil. This would break all JWT operations if the code actually read from the config holder (see bug #1 -- currently it does not, but once bug #1 is fixed, this becomes critical).

The admin reload handler at admin_reload.go:31-51 has the same problem -- it calls LoadFromSecretsFile directly and stores the result, potentially clearing values that were only set via env vars.

**Impact:** A secrets file that contains only the fields being rotated (e.g., just JWT_SECRET and JWT_SECRET_PREVIOUS) would zero out all other fields in the ReloadableConfig, including SMTP settings, SSO keys, and SIEM config. This is a data-loss-on-reload bug that would surface once the code is fixed to actually read from the config holder.

### 6. Keyset pagination SQL mismatch between hand-written and sqlc query

**Location:** internal/store/security_events.go:82-94 vs internal/store/queries/security_events.sql:5-16

**Severity:** minor

**Evidence:** The hand-written listSecurityEventsQuery at security_events.go:82 includes the composite cursor tiebreak with an id comparison, taking 8 parameters. The sqlc query file at queries/security_events.sql:5-16 has a simpler version without the id tiebreak, taking only 7 parameters.

**Impact:** The sqlc query is not currently used (the ListSecurityEvents store method uses the hand-written constant). But the stale sqlc definition could confuse maintainers or be accidentally adopted in a refactor, breaking pagination for rows with identical timestamps.

## Design Concerns

### Config holder not wired to consumers

The configHolder (config.Holder) is created and passed to ServerDeps, but its only consumers are the admin reload handler (which stores to it) and the SIGHUP handler (which stores to it via ReloadConfig). Nothing reads from it for operational decisions. This is the root cause of bugs #1, #2, and makes bug #5 latent rather than immediately visible. The hot-reload infrastructure is fully built but not connected to the code paths that need it.

To fix properly: either (a) all JWT/SSO code paths should read from configHolder.Load() instead of srv.cfg, or (b) ReloadConfig / the admin handler should mutate srv.cfg fields in-place (but that would require synchronization on *Config). Option (a) aligns with the atomic.Pointer design already in place.

### Secrets file is a full replace, not a merge

LoadFromSecretsFile returns a complete ReloadableConfig from the file contents alone. There is no merge with the current config or the startup config. This means operators must put all reloadable fields in the secrets file, not just the ones they want to change. This is surprising behavior for a SIGHUP reload mechanism and is likely to cause silent breakage in production (bug #5).

### SyslogWriter has no reconnect logic

syslog.go dials once at creation time. If the SIEM endpoint goes down and comes back, the SyslogWriter connection is dead permanently -- conn.Write will fail on every subsequent event, logging errors but never reconnecting. For a security event pipeline, silent permanent loss of syslog forwarding is a significant operational risk.

### Race condition window in EventWriter.SetSyslog

writer.go:48-49 sets w.syslog without synchronization. If SetSyslog is called concurrently with Write (e.g., during hot-reload of SIEM config), there is a data race on the w.syslog field -- the goroutine spawned by Write reads w.syslog at line 97, while SetSyslog writes it at line 49. In practice this is likely called once at startup, but the lack of synchronization makes it unsafe for hot-reload scenarios.
