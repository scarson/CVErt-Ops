# Secure — Design

**Date:** 2026-03-10
**Status:** Design approved
**Pillar:** Secure
**Prerequisites:** Phase 8B-8D complete (Observe metrics, Operate doctor framework, Extend rescan method)
**Overview doc:** `2026-03-10-ops-maturity-overview.md`

## Current State

- **JWT:** Single HS256 signing key from `JWT_SECRET` env var. Min 32 bytes at startup. 15-min access / 7-day refresh tokens. Token version claim for password-change invalidation. No multi-key support.
- **Encryption:** AES-256-GCM for SSO client secrets (`sso_connections.client_secret_enc`). Key from `SSO_ENCRYPTION_KEY` env var (32-byte hex). No key versioning — changing the key silently breaks all encrypted values.
- **Lockout:** In-memory only. 5 attempts / 15-min window. Lost on restart. No persistence, no cross-instance sharing.
- **Audit:** Persistent audit log for data mutations. But auth failures and lockouts are NOT logged to the audit table — only ephemeral slog output. No central event type constants.
- **Signal handling:** SIGTERM/SIGINT for shutdown only. No SIGHUP. Config changes require restart.

## 1. Dual-Key JWT Rotation

### Problem

Rotating `JWT_SECRET` today requires restart → all tokens immediately invalid → every user forced to re-login. Service disruption.

### Solution

Two keys: **active** (signs new tokens, validates first) and **previous** (validates only, optional).

```
JWT_SECRET=<current_key>              # signs new tokens, validates first
JWT_SECRET_PREVIOUS=<old_key>         # validates only, optional
```

### Verification Logic

In `auth/jwt.go`: try `JWT_SECRET` first. If validation fails with a **signature error** (not expiry, not claims error), try `JWT_SECRET_PREVIOUS`. If neither validates, reject. Signing always uses `JWT_SECRET`.

### Rotation Procedure

1. Generate new key
2. Move current `JWT_SECRET` value to `JWT_SECRET_PREVIOUS` in secrets file
3. Set new key as `JWT_SECRET`
4. Trigger reload (SIGHUP or admin API)
5. Wait for all old tokens to expire (max 7 days for refresh tokens, or force-invalidate by bumping all users' `token_version`)
6. Remove `JWT_SECRET_PREVIOUS`

### Why Not Key Ring / kid Header?

HS256 doesn't have a standard `kid` header convention. A custom `kid` claim adds complexity with no benefit over the two-key model. Two keys covers the rotation window.

### Why Not RS256/JWKS?

Asymmetric signing matters for microservices (key distribution without sharing secret). We're a single binary. HS256 is simpler, faster, appropriate. Revisit if SaaS multi-service architecture happens.

### Critical Test Cases

- Token signed with active key validates
- Token signed with previous key validates
- Token signed with unknown key rejects
- Expired token signed with previous key rejects (expiry error, not key error)
- **Refresh token flow across rotation:** user's refresh token (signed old key) → refresh endpoint → new access+refresh tokens signed with new key. This is the most common rotation scenario.
- No previous key configured: only active key tried, no error
- Both keys same value: works (no-op, harmless)

## 2. Dual-Key Encryption Rotation

### Problem

Changing `SSO_ENCRYPTION_KEY` silently breaks all encrypted SSO client secrets.

### Solution

Same try-current-then-previous pattern as JWT. No format change needed.

```
SSO_ENCRYPTION_KEY=<current_key>          # encrypts new values, decrypts first
SSO_ENCRYPTION_KEY_PREVIOUS=<old_key>     # decrypts only, optional
```

### Decryption Logic

AES-GCM authentication fails cleanly with the wrong key (authentication error, not garbage). So:
- Decrypt: try current key. If GCM authentication fails, try previous key. If both fail, error.
- Encrypt: always with current key.

**No version byte, no format change.** The existing wire format (`nonce || ciphertext`) stays as-is. This is simpler and already proven by the JWT dual-key model.

### `cvert-ops rotate-encryption-key`

New cobra subcommand (`cmd/cvert-ops/rotate.go`). Re-encrypts all values with the current key so the previous key can be removed.

Currently re-encrypts: **`sso_connections.client_secret_enc`** (the only encrypted column today). This is explicitly enumerated — if encryption extends to other columns later, the command is updated.

Behavior:
- Refuses to run if `SSO_ENCRYPTION_KEY_PREVIOUS` is not set
- Runs in a single transaction (SSO secrets are a small dataset, typically < 100 rows)
- On failure mid-transaction: rolls back, all values still decryptable with old key
- On success: all values re-encrypted, safe to remove previous key

### Critical Test Cases

- Encrypt with current, decrypt with current: works
- Value encrypted with old key: try current (fails), try previous (succeeds)
- Both keys wrong: returns error, not garbage
- rotate-encryption-key: all values re-encrypted, decryptable with current only
- rotate-encryption-key without previous key: refuses with clear error
- rotate-encryption-key partial failure: transaction rolls back, all values still decrypt with old key (testing-pitfalls §3.3)

## 3. Config Hot-Reload via SIGHUP / Secrets File

### Problem

Key rotation, SMTP credential changes, and other config updates require full restart today. Process env vars don't change after startup — `os.Getenv()` re-reads the process environment block, not the `.env` file on disk.

### Solution

`CVERTOPS_SECRETS_FILE` env var — path to a file containing reloadable secrets, one `KEY=VALUE` per line. On SIGHUP (Unix) or `POST /api/v1/admin/reload-config` (cross-platform), re-read this file.

### Hot-Reloadable Fields (via secrets file)

- `JWT_SECRET` + `JWT_SECRET_PREVIOUS`
- `SSO_ENCRYPTION_KEY` + `SSO_ENCRYPTION_KEY_PREVIOUS`
- `LOG_LEVEL`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`
- `SIEM_SYSLOG_ADDR`, `SIEM_SYSLOG_FORMAT`

### NOT Hot-Reloadable (require restart)

- `DATABASE_URL` (pool initialized once)
- `HTTP_PORT`, `METRICS_PORT` (listeners bound once)
- `REGISTRATION_MODE` (changes auth flow structure)

### Implementation

`ReloadableConfig` struct with only the hot-reloadable fields. Stored behind `atomic.Pointer[ReloadableConfig]`. All readers use `.Load()` — no mutex contention.

On startup: load from env vars. If `CVERTOPS_SECRETS_FILE` is also set, overlay values from the file (file wins).

On reload: re-read `CVERTOPS_SECRETS_FILE` only. Env vars are not re-read. If `CVERTOPS_SECRETS_FILE` is not set, reload is a no-op (logged as info).

### SIGHUP Handler

**CRITICAL:** SIGHUP MUST use a separate `signal.Notify(sighupCh, syscall.SIGHUP)` channel with its own goroutine. It MUST NOT be added to the existing `signal.NotifyContext` for SIGTERM/SIGINT — that would cause SIGHUP to shut down the server.

Handler sequence:
1. `defer func() { if r := recover(); r != nil { slog.Error("config reload panicked", ...) } }()`
2. Parse secrets file
3. Validate all fields (key lengths, formats)
4. If valid: `atomic.Pointer.Store(newConfig)` + log success with before/after diff (secrets redacted)
5. If invalid: log error with details, keep old config
6. If Extend pillar's `Rescan()` is available, call it to rescan `feeds.d/` directory

### Windows Compatibility

Windows doesn't have SIGHUP. Build-tag the SIGHUP goroutine with `//go:build !windows`.

`POST /api/v1/admin/reload-config` (requires site admin auth) is the cross-platform mechanism. It re-reads the secrets file — does NOT accept secrets in the request body (would put secrets in HTTP logs).

### Critical Test Cases

- SIGHUP reloads config, server continues running
- SIGTERM still shuts down (not affected by SIGHUP handler)
- Invalid new config: logs error, keeps old config
- Config parse panic: recovered, old config retained (testing-pitfalls §2.4)
- Mid-request config swap: current request finishes with old config, next request gets new
- Admin API reload: same behavior as SIGHUP
- No secrets file configured: reload is no-op, logged

## 4. Security Event Detection & Alerting

### Problem

Auth failures and lockouts are ephemeral slog output only. No persistent, queryable record. No alerting on suspicious patterns.

### security_events Table

```sql
CREATE TABLE security_events (
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

-- No RLS — system table, accessed only by site admins via withBypassTx
CREATE INDEX CONCURRENTLY idx_security_events_created_at ON security_events (created_at);
CREATE INDEX CONCURRENTLY idx_security_events_type_created ON security_events (event_type, created_at);
```

### Events Captured

| Event Type | Source | Severity |
|------------|--------|----------|
| `auth.login_failed` | Login handler | info |
| `auth.login_success` | Login handler | info |
| `auth.account_locked` | Lockout manager | warning |
| `auth.account_unlocked` | Admin action or timeout | info |
| `auth.password_reset_requested` | Forgot-password handler | info |
| `auth.password_changed` | Password change/reset handler | info |
| `auth.token_reuse_detected` | Refresh token rotation | critical |
| `auth.api_key_created` | API key handler | info |
| `auth.api_key_used_after_revocation` | API key middleware | warning |
| `admin.user_disabled` | Admin handler | warning |
| `admin.config_reloaded` | SIGHUP / admin reload handler | info |
| `admin.bulk_retry_triggered` | Delivery retry handler | info |

### Event Type Constants

Defined in `internal/secure/events.go` (Phase 8A deliverable). Central registry — no magic strings.

### actor_ip Resolution

MUST use the resolved client IP from `clientIPMiddleware` context (respects `TRUSTED_PROXIES` and `X-Forwarded-For`), NOT `r.RemoteAddr`. In a proxy/Docker setup, `RemoteAddr` shows the proxy IP.

### Write Pattern

Async, non-blocking: `context.WithoutCancel(r.Context())`, fire-and-forget goroutine. Security event logging must never slow down the request path or cause a login to fail.

Write failures logged to slog (last resort) but never panic or affect the request.

### Rate Limiting on Writes

Brute-force attacks could flood the table. Rate-limit event writes: max 10 events/minute per unique `(event_type, actor_ip)`. Excess events increment a Prometheus counter (`cvertops_security_events_dropped_total`) but aren't written.

Rate limiter is in-memory with **TTL-based eviction** (default 5 minutes). Prevents unbounded memory growth from distributed attacks. Same eviction pattern as the lockout manager. (testing-pitfalls §2.1)

### Retention

90 days default. Uses existing bounded-batch cleanup pattern. Added to the retention job configuration.

### Prometheus Metrics

`cvertops_security_events_total{event_type, severity}` — counter. If the Observe pillar has already landed, import from `internal/metrics/`. If not, register in `internal/secure/` with the same name/labels (Observe will deduplicate on merge).

Alert rule in `deploy/grafana/alerts.yml`: `SecurityCriticalEvent` fires when `rate(cvertops_security_events_total{severity="critical"}[5m]) > 0`.

### Syslog Output (SIEM Integration)

Optional structured syslog output for security events, enabling integration with Splunk, Elastic, Azure Sentinel, and any SIEM with a syslog receiver.

```
SIEM_SYSLOG_ADDR=udp://splunk-forwarder:514   # or tcp://, or empty to disable
SIEM_SYSLOG_FORMAT=json                        # json (default) or cef
```

When configured, the security event writer emits each event to the syslog destination in addition to (not instead of) the database write. Same async, non-blocking pattern — syslog failure is logged to slog but never affects the request or the DB write.

Format options:
- **JSON:** RFC 5424 structured data with the full event as a JSON payload. Universal — works with any modern SIEM log ingestion pipeline.
- **CEF (Common Event Format):** ArcSight/Splunk-native format for environments that prefer it.

Implementation: Go's `log/syslog` package (stdlib) for UDP/TCP syslog. The writer holds an optional `*syslog.Writer` initialized at startup from config. If `SIEM_SYSLOG_ADDR` is empty, no syslog writer is created.

Rate limiting: shares the same per-`(event_type, actor_ip)` rate limiter as the DB writer. Events dropped by rate limiting are also not sent to syslog.

Hot-reloadable: `SIEM_SYSLOG_ADDR` and `SIEM_SYSLOG_FORMAT` are added to `ReloadableConfig`. On SIGHUP, the syslog writer is recreated with the new address (old writer closed gracefully).

### Relationship to Audit Log

Security events are a SEPARATE table from `audit_log`. Different purpose, different retention, different consumers:
- `audit_log`: data mutations (who changed what). Org-scoped.
- `security_events`: authentication and access patterns (who tried what). System-scoped.

### Admin API

`GET /api/v1/admin/security-events` — Filterable by event_type, severity, date range, actor_email. Keyset-paginated. Requires site admin auth. Uses `withBypassTx`.

## 5. Runtime Security Self-Checks

Implemented in `internal/secure/checks.go`. Each check implements the `Check` interface from the Operate pillar's doctor framework.

If the Operate pillar hasn't landed yet, these are standalone functions with the same signature, testable in isolation.

| Check | Implementation |
|-------|----------------|
| **RLS enforcement** | Query `pg_class` + `pg_namespace` for all org-scoped tables. Verify `relrowsecurity = true`. |
| **DB role permissions** | Query `pg_roles WHERE rolname = current_user`. Verify `rolsuper = false`, `rolbypassrls = false`. |
| **Encryption sentinel** | Decrypt sentinel from `system_settings`. Fails if key changed without rotation. |
| **JWT configuration** | Verify `len(JWT_SECRET) >= 32`, algorithm is HS256. If `JWT_SECRET_PREVIOUS` set, verify >= 32 bytes. |
| **Security headers** | HTTP GET to own `/healthz`, verify headers. **API doctor mode only** — CLI skips (no server running). |
| **SSRF protection** | Call safeurl's URL validation with `http://169.254.169.254/` and `http://127.0.0.1:8080/`. Verify both rejected. No actual HTTP request. |
| **CORS configuration** | If `CORS_ALLOWED_ORIGINS` contains `*` and cookie auth enabled, warn. (testing-pitfalls §5.1) |

## 6. Secret Rotation Runbook

`docs/deployment/runbooks/secret-rotation.md` — step-by-step procedures for:

- **JWT key rotation** — dual-key procedure (§1 above)
- **Encryption key rotation** — dual-key + `rotate-encryption-key` command (§2 above)
- **Database credential rotation** — update secrets file → SIGHUP. Note: requires restart (DB pool initialized once).
- **SMTP credential rotation** — update secrets file → SIGHUP (hot-reloadable)
- **OAuth client secret rotation** — provider-side + update encrypted value via API

Each procedure includes: prerequisites, exact commands, verification steps (run `doctor`), rollback if something goes wrong.

## New Package Structure

`internal/secure/` — new package:
- `events.go` — event type constants, event writer, event rate limiter
- `syslog.go` — optional syslog output for SIEM integration
- `checks.go` — all doctor security checks
- `ratelimit.go` — event write rate limiter (in-memory, TTL-based eviction)

`cmd/cvert-ops/rotate.go` — rotate-encryption-key subcommand (follow pattern of existing subcommands like `cmd/cvert-ops/migrate.go`).

## What We Won't Build

- Persistent/distributed lockout (adequate for single-instance self-hosted)
- Token blacklist table (disabled user check in middleware + token version covers use cases)
- WAF / DDoS protection (infrastructure concern)
- Automated runtime vulnerability scanning (govulncheck in CI)
- GDPR/SOC 2 compliance documentation

## Subagent Risk Areas

| Risk | Mitigation |
|------|------------|
| Dual-key JWT verification order | Try active first. Try previous ONLY on signature error (not expiry/claims). Test: expired token with previous key still rejects as expired. Test: refresh token across key rotation produces new tokens with new key. |
| Encryption try-decrypt pattern | GCM auth failure = try next key. No version byte. Test: legacy blob decrypts after rotation. Mismatched key returns error, not garbage. |
| SIGHUP added to shutdown context | **CRITICAL:** Separate `signal.Notify` channel, NOT `signal.NotifyContext`. Test: SIGHUP → server continues. SIGTERM → server stops. |
| SIGHUP can't re-read env vars | Reload reads `CVERTOPS_SECRETS_FILE`, not `os.Getenv()`. Test: modify file, send SIGHUP, verify new values active. |
| SIGHUP handler panic | defer+recover wraps handler body. Test: malformed secrets file that causes parse panic → server continues with old config. (testing-pitfalls §2.4) |
| Security event rate limiter unbounded growth | TTL-based eviction matching lockout manager pattern. Test: 1000+ unique IPs, verify map bounded after TTL. (testing-pitfalls §2.1) |
| Wrong IP in security events | Use resolved IP from `clientIPMiddleware` context. Test: request via X-Forwarded-For, verify event records forwarded IP. |
| Security event async write failure | Write failures logged to slog, never affect request. Test: inject DB error, verify login succeeds and slog has error. (testing-pitfalls §3.2) |
| rotate-encryption-key atomicity | Single transaction. Test: inject failure mid-batch, verify rollback, all values decrypt with old key. (testing-pitfalls §3.3) |
| rotate-encryption-key scope | Plan enumerates exact column: `sso_connections.client_secret_enc`. Agent does not guess what else might be encrypted. |
| Security events vs audit log confusion | SEPARATE table. Different purpose. Agent must not merge them or write security events to audit_log. |
| Windows SIGHUP absence | `//go:build !windows` on SIGHUP goroutine. Admin API reload works on all platforms. Tests use admin API. |
| ReloadableConfig boundary | New `ReloadableConfig` struct with ONLY hot-reloadable fields. Existing `config.Config` unchanged. All readers use `atomic.Pointer.Load()`. |
| CORS doctor check | Warn on wildcard + credentials, not fail. (testing-pitfalls §5.1) |
| Syslog writer blocks request | Syslog output uses same async pattern as DB write. Syslog failure logged to slog, never affects request. Test: unreachable syslog target, verify login succeeds. |
| Syslog replaces DB write | Syslog is IN ADDITION TO database write, not a replacement. Both paths fire independently. |
