# Bug Hunt Report — Phase 8E (Secure Pillar) Exploratory

## Scope

Depth-first exploration of Phase 8E (PR #43) focusing on the highest-risk areas:

**Deep exploration (primary focus):**
- `internal/config/reloadable.go` — hot-reloadable config holder, `LoadFromSecretsFile`, `LoadFromConfig`
- `internal/config/reload.go` — reload orchestration
- `internal/api/middleware_auth.go` — JWT dual-key wiring in auth middleware
- `internal/api/admin_reload.go` — admin reload endpoint
- `internal/api/sso.go` — SSO encryption key resolution (`ssoEncryptionKey`, `ssoEncryptionKeyPrevious`)
- `internal/api/oauth_oidc.go` — OIDC SSO dual-key AES decryption caller
- `internal/api/server.go` — ServerDeps, configHolder wiring
- `internal/api/auth.go` — all JWT issuance/parsing call sites
- `internal/secure/writer.go` — async event writer
- `cmd/cvert-ops/main.go` — startup wiring, configHolder/eventWriter/syslog initialization

**Secondary exploration:**
- `internal/auth/jwt.go` — dual-key parse logic
- `internal/crypto/aes.go` — dual-key decrypt logic
- `cmd/cvert-ops/rotate.go` — encryption key rotation CLI
- `internal/secure/ratelimit.go` — event rate limiter
- `internal/secure/syslog.go` — syslog writer
- `internal/store/security_events.go` — security event store methods
- `internal/doctor/checks.go` — doctor health checks
- `internal/retention/runner.go` — security event retention cleanup
- `internal/metrics/security.go` — Prometheus counters
- `internal/api/admin_security_events.go` — security events API
- `migrations/000039_create_security_events.up.sql` — table definition

## Bugs

### 1. Hot-reloaded config is never read — JWT and SSO operations ignore configHolder

**Location:** `internal/api/middleware_auth.go:48`, `internal/api/auth.go:269,555,670,713,789,795,904,993`, `internal/api/oauth_oidc.go:257,330`, `internal/api/oauth_github.go:174`, `internal/api/oauth_google.go:162`, `internal/api/auth_mfa.go:264,318,330,343,579,622,1150,1181,1219,1225`, `internal/api/auth_email_verification.go:100`, `internal/api/sso.go:73,88`

**Severity:** significant

**Evidence:** All JWT signing, parsing, and SSO encryption/decryption operations read from `srv.cfg` (the static startup config), never from `srv.configHolder` (the hot-reloadable config). For example:

- `middleware_auth.go:48` — `auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret), jwtPreviousSecret(srv.cfg))`
- `sso.go:73` — `hex.DecodeString(srv.cfg.SSOEncryptionKey)`
- `auth.go:269` — `secret := []byte(srv.cfg.JWTSecret)`

The admin reload endpoint (`admin_reload.go:38`) and SIGHUP handler (`reload.go:29`) both update `srv.configHolder`, but no auth-related code reads from it. The `configHolder` is stored, never consumed.

**Impact:** The entire config hot-reload feature for secrets (JWT and SSO keys) is non-functional. After a reload via SIGHUP or admin API, all JWT signing/validation and SSO decryption continue using the original startup values. An admin who performs a key rotation via the secrets file and triggers a reload will believe the rotation has taken effect, but it has not — the old keys are still in use until a full process restart. This also means the `jwtPreviousSecret` helper always returns the startup-time previous secret, so the dual-key rotation window doesn't actually shift on reload.

Note: the implementation plan itself identified this at line 1294 (`dev/plans/2026-03-16-phase8-ops-secure-v2-plan.md`) but the fix was not implemented.

### 2. LoadFromSecretsFile replaces entire config — partial secrets files zero out fields

**Location:** `internal/config/reloadable.go:58-148`

**Severity:** significant

**Evidence:** `LoadFromSecretsFile` creates a brand-new `ReloadableConfig` from scratch and only populates fields that are present in the secrets file. If the secrets file contains only `JWT_SECRET` (e.g., for a JWT rotation), all other fields are set to their zero values:
- `SSOEncryptionKey` becomes `[32]byte{}` (all zeros — treated as "no key")
- `SMTPHost`, `SMTPPort`, etc. become empty/zero
- `LogLevel` becomes empty

The `Holder.Store()` then atomically replaces the entire config with this partial version. Any component that later reads from the holder (currently none read it for auth, but the architecture expects them to) would see zeroed-out fields.

**Impact:** When bug #1 is fixed and auth operations start reading from `configHolder`, a partial secrets file reload will break SSO decryption (zero encryption key), SMTP delivery (zero host/port), and any other feature that depends on fields not present in the secrets file. A simple JWT rotation via secrets file would take down SSO and email delivery.

### 3. Syslog writer never wired at startup — SIEM forwarding is inoperative

**Location:** `cmd/cvert-ops/main.go:202-203`

**Severity:** significant

**Evidence:** The `EventWriter` is created at line 202 with `secure.NewEventWriter(st)`, and the syslog writer is set via `SetSyslog()`. But `SetSyslog` is never called from `main.go` or anywhere in the startup path. The `NewSyslogWriter` constructor and `SetSyslog` method exist, the `SIEMSyslogAddr` and `SIEMSyslogFormat` fields exist on `ReloadableConfig`, but no code reads these fields to construct and attach a `SyslogWriter`.

Additionally, `SIEMSyslogAddr` and `SIEMSyslogFormat` are not present on the startup `Config` struct at all — they only exist on `ReloadableConfig`. There is no env var binding for them, no way to configure them at startup.

**Impact:** The SIEM syslog forwarding feature (task from the plan) is completely non-functional. Security events are written to the database only. No events are forwarded to an external SIEM system regardless of configuration. The entire `syslog.go` implementation is dead code at runtime.

## Design Concerns

### Config holder read/write asymmetry

The `configHolder` pattern has a fundamental gap: it is written to on reload but never read by the components that should consume the reloaded values. The admin doctor handler (`admin_doctor.go:16-19`) also reads from `srv.cfg`, not `configHolder`. This creates a system where the reload machinery works perfectly in isolation but has no observable effect on behavior. A test that verifies "reload updates the holder" passes, but the system doesn't actually rotate keys until restart.

### SetSyslog race window

`EventWriter.SetSyslog()` writes `w.syslog` without synchronization, while `Write()` reads `w.syslog` inside spawned goroutines. If `SetSyslog` were called while write goroutines are in flight (e.g., during a config reload that reconnects syslog), this would be a data race. Currently unexploitable because `SetSyslog` is never called, but the API is unsafe for its intended use case of dynamic syslog reconfiguration on config reload.

### Secrets file is all-or-nothing

The secrets file reload is a full replacement, not a merge. This means operators must include ALL reloadable fields in the secrets file, even ones they're not rotating. This is error-prone — forgetting a field silently zeros it. A merge-with-previous-config approach would be safer for partial updates.
