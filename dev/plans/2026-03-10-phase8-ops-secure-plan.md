# Secure Pillar — Implementation Plan

> **For Claude:** CRITICAL NOTE: This plan was never implemented and is maintained for historical reference only. It's superseded by dev\plans\2026-03-16-phase8-ops-secure-v2-plan.md.

> **⚠️ DEFERRED REVIEW NOTICE:** This plan was written alongside the Phase 8B-8D plans (Observe, Operate, Extend) but is designed to execute AFTER Phase 8B-8D completes. Before starting implementation, this plan MUST be reviewed and re-assessed in light of the Phase 8B-8D implementation. Specifically:
> - Verify the Operate pillar's doctor `Check` interface matches what this plan expects
> - Verify the Observe pillar's metrics package structure for the security event counter
> - Verify the Extend pillar's `Rescan()` method signature for SIGHUP wiring
> - Check for any Phase 8B-8D changes to `internal/api/server.go`, `internal/config/config.go`, or `cmd/cvert-ops/main.go` that affect this plan's modifications
> - Re-validate the `internal/auth/jwt.go` and `internal/crypto/aes.go` implementations haven't changed in ways that affect the dual-key approach
>
> **Do NOT start implementation without this review.** Phase 8B-8D may surface design changes that require plan adjustments.

**Goal:** Dual-key JWT rotation, dual-key encryption rotation, SIGHUP config hot-reload, security event detection/alerting pipeline, and runtime security self-checks.

**Architecture:** `ReloadableConfig` struct behind `atomic.Pointer` for hot-reloadable fields. Security events in a separate `security_events` table (not audit_log). Dual-key try-current-then-previous pattern for both JWT and encryption. SIGHUP on Unix, admin API reload on all platforms.

**Tech Stack:** Go, `golang-jwt/jwt/v5`, `crypto/aes` + `cipher.GCM`, `sync/atomic`, `os/signal`, PostgreSQL

**References:**
- Design: `dev/plans/2026-03-10-ops-secure-design.md`
- Testing pitfalls: `dev/testing-pitfalls.md` (referenced as `tp§N.N`)
- JWT: `internal/auth/jwt.go`
- AES: `internal/crypto/aes.go`
- Config: `internal/config/config.go`
- Main: `cmd/cvert-ops/main.go`
- Security events: `internal/secure/events.go` (Phase 8A)

**CRITICAL — File Ownership:** This pillar creates files in `internal/secure/`, `cmd/cvert-ops/rotate.go`, and `docs/deployment/runbooks/secret-rotation.md`. It modifies `internal/auth/jwt.go`, `internal/crypto/aes.go`, `internal/config/config.go`, `cmd/cvert-ops/main.go`, and `internal/api/server.go` (one admin route). Do NOT touch `internal/metrics/*.go` (Observe), `internal/feed/generic/` (Extend), `internal/doctor/` (Operate), or `internal/api/admin_*.go` (Operate).

**CRITICAL — Cross-Pillar Dependencies:**
- **From Operate:** Doctor `Check` interface for security self-checks. If not available, implement standalone functions with the same signature.
- **From Observe:** `cvertops_security_events_total` counter. If Observe's metrics package exists, import. If not, register in `internal/secure/` with the same name/labels.
- **From Extend:** `Rescan()` method called on SIGHUP. If not available, SIGHUP only reloads secrets.

---

## Batch 1: Dual-Key JWT Rotation

### Task 1: Dual-Key JWT Verification

**Files:**
- Modify: `internal/auth/jwt.go` — modify `ParseAccessToken` and add `ParseRefreshToken` dual-key support
- Modify: `internal/auth/jwt_test.go`

**Context:** Two keys: active (signs new tokens, validates first) and previous (validates only, optional). Verification logic: try `JWT_SECRET` first. If validation fails with a SIGNATURE error (not expiry, not claims error), try `JWT_SECRET_PREVIOUS`. If neither validates, reject. Signing always uses `JWT_SECRET`.

**CRITICAL:** Only retry on signature verification failure. If the token is expired (even with the previous key), it's expired — don't try the previous key. Error type checking via `jwt.ErrTokenSignatureInvalid`.

**Step 1: Write tests (from design doc critical test cases)**

```go
func TestParseAccessToken_ActiveKeyValidates(t *testing.T) { ... }
func TestParseAccessToken_PreviousKeyValidates(t *testing.T) { ... }
func TestParseAccessToken_UnknownKeyRejects(t *testing.T) { ... }
func TestParseAccessToken_ExpiredWithPreviousKeyRejects(t *testing.T) {
    // Token expired, signed with previous key → MUST reject as expired, NOT try previous key
}
func TestParseAccessToken_NoPreviousKeyConfigured(t *testing.T) {
    // Only active key tried, no error from missing previous
}
func TestParseAccessToken_BothKeysSameValue(t *testing.T) {
    // Works (no-op, harmless)
}
```

**Step 2: Implement**

Modify `ParseAccessToken` to accept active + optional previous key:

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

**CRITICAL:** Update ALL callers of `ParseAccessToken` to pass both keys. The previous key comes from config.

**Step 3: Write test — refresh token flow across rotation**

```go
func TestRefreshTokenFlowAcrossRotation(t *testing.T) {
    // User's refresh token signed with OLD key
    // Refresh endpoint → new access+refresh tokens signed with NEW key
    // This is the most common rotation scenario
}
```

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 2: Config Fields for Previous Keys

**Files:**
- Modify: `internal/config/config.go` — add `JWTSecretPrevious`, `SSOEncryptionKeyPrevious`

**Step 1: Add config fields:**

```go
JWTSecretPrevious          string `env:"JWT_SECRET_PREVIOUS"`
SSOEncryptionKeyPrevious   string `env:"SSO_ENCRYPTION_KEY_PREVIOUS"`
```

**Step 2: Commit.**

---

## Batch 2: Dual-Key Encryption Rotation

### Task 3: Dual-Key Decryption

**Files:**
- Modify: `internal/crypto/aes.go` — add `DecryptWithFallback`
- Create: `internal/crypto/aes_test.go` (if not exists, or add tests)

**Context:** Try current key. If GCM authentication fails, try previous key. If both fail, error. No version byte, no format change.

**Step 1: Write tests (from design doc)**

```go
func TestDecryptWithFallback_CurrentKeyWorks(t *testing.T) { ... }
func TestDecryptWithFallback_PreviousKeyWorks(t *testing.T) {
    // Value encrypted with OLD key → try current (fails GCM auth), try previous (succeeds)
}
func TestDecryptWithFallback_BothKeysWrong(t *testing.T) {
    // Returns error, NOT garbage
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

**Step 3: Update all callers** of `Decrypt` that handle SSO secrets to use `DecryptWithFallback`.

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 4: `cvert-ops rotate-encryption-key` Command

**Files:**
- Create: `cmd/cvert-ops/rotate.go`
- Modify: `cmd/cvert-ops/main.go` — add command

**Context:** Re-encrypts all values with current key so previous can be removed. Currently only: `sso_connections.client_secret_enc`. Runs in single transaction. Refuses if `SSO_ENCRYPTION_KEY_PREVIOUS` not set.

**Step 1: Write tests**

```go
func TestRotateEncryptionKey_ReEncryptsAllValues(t *testing.T) { ... }
func TestRotateEncryptionKey_RefusesWithoutPreviousKey(t *testing.T) { ... }
func TestRotateEncryptionKey_RollbackOnFailure(t *testing.T) {
    // Inject failure mid-batch, verify all values still decrypt with old key (tp§3.3)
}
```

**Step 2: Implement.** Follow pattern of `migrateCmd()`.

**Step 3: Run tests → PASS. Step 4: Commit.**

---

## Batch 3: Config Hot-Reload via SIGHUP

### Task 5: ReloadableConfig with atomic.Pointer

**Files:**
- Create: `internal/config/reloadable.go`
- Create: `internal/config/reloadable_test.go`

**Context:** `ReloadableConfig` struct with ONLY hot-reloadable fields (design doc §3):
- `JWT_SECRET` + `JWT_SECRET_PREVIOUS`
- `SSO_ENCRYPTION_KEY` + `SSO_ENCRYPTION_KEY_PREVIOUS`
- `LOG_LEVEL`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`

Stored behind `atomic.Pointer[ReloadableConfig]`. All readers use `.Load()`.

**Step 1: Implement struct and atomic wrapper**

```go
// ABOUTME: Hot-reloadable configuration fields updated by SIGHUP or admin API.
// ABOUTME: Stored behind atomic.Pointer — readers never block, writers swap atomically.
package config

type ReloadableConfig struct {
    JWTSecret             []byte
    JWTSecretPrevious     []byte
    SSOEncryptionKey      [32]byte
    SSOEncryptionKeyPrev  [32]byte
    LogLevel              string
    SMTPHost              string
    SMTPPort              int
    SMTPFrom              string
    SMTPUsername           string
    SMTPPassword           string
    SMTPTLS               bool
}
```

**Step 2: Implement secrets file parser**

Parse `CVERTOPS_SECRETS_FILE` — one `KEY=VALUE` per line. Comments (`#`) and empty lines skipped. Values trimmed.

**Step 3: Write tests**

- Parse valid secrets file → correct values
- Invalid values → error returned, old config retained
- Mid-request config swap: Load() returns consistent snapshot

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 6: SIGHUP Handler

**Files:**
- Create: `internal/config/sighup_unix.go` (build-tagged `//go:build !windows`)
- Create: `internal/config/sighup_unix_test.go`
- Modify: `cmd/cvert-ops/main.go` — start SIGHUP goroutine

**Context:**

**CRITICAL (design doc §3, biggest risk):** SIGHUP MUST use a SEPARATE `signal.Notify(sighupCh, syscall.SIGHUP)` channel with its own goroutine. It MUST NOT be added to the existing `signal.NotifyContext` for SIGTERM/SIGINT — that would cause SIGHUP to shut down the server.

**Step 1: Write test — SIGHUP reloads config, server continues**

**Step 2: Write test — SIGTERM still shuts down (not affected by SIGHUP handler)**

**Step 3: Write test — invalid new config: logs error, keeps old config**

**Step 4: Write test — config parse panic: recovered, old config retained (tp§2.4)**

```go
func TestSIGHUP_PanicRecovery(t *testing.T) {
    // Malformed secrets file that causes parse panic
    // Verify server continues with old config
}
```

**Step 5: Implement**

Handler sequence:
1. `defer func() { if r := recover(); r != nil { slog.Error("config reload panicked", ...) } }()`
2. Parse secrets file
3. Validate all fields (key lengths, formats)
4. If valid: `atomic.Pointer.Store(newConfig)` + log success with diff (secrets redacted)
5. If invalid: log error, keep old config
6. If Extend's `Rescan()` is available, call it to rescan `feeds.d/`

**Step 6: Run tests → PASS. Step 7: Commit.**

### Task 7: Admin Reload API Endpoint

**Files:**
- Create: `internal/api/admin_reload.go`
- Create: `internal/api/admin_reload_test.go`
- Modify: `internal/api/server.go` — add route in admin group

**Context:** `POST /api/v1/admin/reload-config` — cross-platform mechanism (Windows doesn't have SIGHUP). Re-reads secrets file. Does NOT accept secrets in request body (would put secrets in HTTP logs). Requires site admin auth.

**Step 1: Write tests — admin auth, same behavior as SIGHUP, no secrets file → no-op**

**Step 2: Implement. Step 3: Wire route. Step 4: Commit.**

---

## Batch 4: Security Events Pipeline

### Task 8: `security_events` Migration

**Files:**
- Create: `migrations/NNNNNN_create_security_events.up.sql`
- Create: `migrations/NNNNNN_create_security_events.down.sql`

**Context:** Per design doc §4:

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

No RLS — system table, accessed only by site admins via `withBypassTx`.

**Step 1: Write migration. Step 2: Run migration. Step 3: Commit.**

### Task 9: Security Event Writer

**Files:**
- Create: `internal/secure/writer.go`
- Create: `internal/secure/writer_test.go`

**Context:** Async, non-blocking event writes. `context.WithoutCancel(r.Context())`, fire-and-forget goroutine. Write failures logged to slog, never panic or affect request.

**Rate limiting on writes:** Max 10 events/minute per unique `(event_type, actor_ip)`. Excess → increment Prometheus counter (`cvertops_security_events_dropped_total`), don't write.

Rate limiter: in-memory with TTL-based eviction (default 5 minutes). Same pattern as lockout manager (tp§2.1 — prevents unbounded growth).

**Step 1: Write tests**

```go
func TestSecurityEventWriter_WritesEvent(t *testing.T) { ... }
func TestSecurityEventWriter_AsyncNonBlocking(t *testing.T) {
    // Verify write doesn't block the calling goroutine
}
func TestSecurityEventWriter_DBErrorDoesNotPanic(t *testing.T) {
    // Inject DB error, verify login succeeds and slog has error (tp§3.2)
}
func TestSecurityEventWriter_RateLimitsWrites(t *testing.T) {
    // 15 events from same (type, IP) → only 10 written
}
func TestSecurityEventWriter_TTLEviction(t *testing.T) {
    // 1000+ unique IPs, verify map bounded after TTL (tp§2.1)
}
```

**Step 2: Implement.**

**CRITICAL — actor_ip:** MUST use resolved client IP from `clientIPMiddleware` context (respects `TRUSTED_PROXIES` and `X-Forwarded-For`), NOT `r.RemoteAddr`.

**Step 3: Run tests → PASS. Step 4: Commit.**

### Task 10: Syslog Output for SIEM Integration

**Files:**
- Create: `internal/secure/syslog.go`
- Create: `internal/secure/syslog_test.go`

**Context:** Optional structured syslog output for security events, enabling integration with Splunk, Elastic, Azure Sentinel, etc. Configured via `SIEM_SYSLOG_ADDR` (e.g., `udp://splunk-forwarder:514`). When configured, the event writer emits each event to syslog IN ADDITION TO the database write. Same async, non-blocking pattern — syslog failure is logged to slog but never affects the request or the DB write.

Two format options: `json` (RFC 5424 structured data, default) and `cef` (Common Event Format for ArcSight/Splunk).

Uses Go's `log/syslog` stdlib package. The writer holds an optional `*syslog.Writer` initialized at startup. If `SIEM_SYSLOG_ADDR` is empty, no syslog writer is created.

Rate limiting: shares the same per-`(event_type, actor_ip)` rate limiter as the DB writer. Events dropped by rate limiting are also not sent to syslog.

Hot-reloadable: `SIEM_SYSLOG_ADDR` and `SIEM_SYSLOG_FORMAT` are in `ReloadableConfig`. On SIGHUP, the syslog writer is recreated with the new address.

**Step 1: Write tests**

```go
func TestSyslogWriter_SendsEvent(t *testing.T) {
    // Start a UDP listener, configure syslog writer to target it
    // Write a security event, verify it arrives at the listener as JSON
}
func TestSyslogWriter_CEFFormat(t *testing.T) {
    // Same but with format=cef, verify CEF-formatted output
}
func TestSyslogWriter_Disabled(t *testing.T) {
    // No SIEM_SYSLOG_ADDR configured → no syslog writer, no error
}
func TestSyslogWriter_UnreachableTarget(t *testing.T) {
    // Unreachable syslog target → error logged to slog, event still written to DB
}
func TestSyslogWriter_RespectsSameRateLimit(t *testing.T) {
    // Event dropped by rate limiter → also not sent to syslog
}
```

**Step 2: Implement.**

**Step 3: Wire into security event writer** — after DB write attempt, if syslog writer is configured and event was not rate-limited, emit to syslog.

**Step 4: Add config fields** to `ReloadableConfig`:
```go
SIEMSyslogAddr   string // e.g., "udp://splunk:514"
SIEMSyslogFormat string // "json" or "cef"
```

**Step 5: Run tests → PASS. Step 6: Commit.**

### Task 11: Wire Security Events into Auth Handlers

**Files:**
- Modify: `internal/api/login.go` (or wherever login handler lives)
- Modify: `internal/api/lockout.go`
- Modify: relevant auth handlers for each event type

**Context:** Wire the event writer into all handlers that produce security events (table in design doc §4). This is a systematic grep-and-wire task.

**Step 1: Identify all handlers** that should emit events (12 event types from Phase 8A constants).

**Step 2: Add event writer calls** to each handler.

**Step 3: Run existing auth tests** to verify no regressions.

**Step 4: Commit.**

### Task 12: Security Events Admin API

**Files:**
- Create: `internal/api/admin_security_events.go`
- Create: `internal/api/admin_security_events_test.go`
- Modify: `internal/api/server.go` — add route in admin group

**Context:** `GET /api/v1/admin/security-events` — filterable by event_type, severity, date range, actor_email. Keyset-paginated. Requires site admin. Uses `withBypassTx`.

**Step 1: Write tests. Step 2: Implement. Step 3: Wire route. Step 4: Commit.**

### Task 13: Security Events Retention

**Files:**
- Modify: `internal/retention/runner.go` — add security_events cleanup (90 days default)

**Step 1: Add to retention config. Step 2: Test. Step 3: Commit.**

---

## Batch 5: Runtime Security Self-Checks

### Task 14: Security Doctor Checks

**Files:**
- Create: `internal/secure/checks.go`
- Create: `internal/secure/checks_test.go`

**Context:** Seven checks from design doc §5. Each implements the `Check` interface from Operate's doctor framework (or standalone functions if doctor hasn't landed).

| Check | Implementation |
|-------|---------------|
| RLS enforcement | Query `pg_class` + `pg_namespace` for org-scoped tables |
| DB role permissions | Query `pg_roles WHERE rolname = current_user` |
| Encryption sentinel | Decrypt sentinel from `system_settings` |
| JWT configuration | Verify key length, algorithm |
| Security headers | HTTP GET to own `/healthz` (API mode only) |
| SSRF protection | Call safeurl validation with `169.254.169.254` and `127.0.0.1:8080` |
| CORS configuration | Warn if `*` + cookie auth (tp§5.1) |

**NOTE:** Some of these overlap with Operate's doctor checks. After Phase 8B-8D review, deduplicate — either Operate owns them all, or Secure registers additional ones. For now, implement as standalone functions that satisfy the `Check` interface.

**Step 1: Write tests** — both pass and fail path for each check.

**Step 2: Implement each check.**

**Step 3: Run tests → PASS. Step 4: Commit.**

### Task 15: Wire Security Checks into Doctor

**Files:**
- Modify: doctor registration (if Operate has landed)

**Context:** If Operate's doctor framework exists, register Secure's checks. If not, this task is deferred to Phase 8F integration.

**Step 1: Check if doctor package exists. Step 2: Register if available. Step 3: Commit.**

---

## Batch 6: Secret Rotation Runbook & Prometheus

### Task 16: Security Event Prometheus Metrics

**Files:**
- Create or modify: `internal/secure/metrics.go` (or import from Observe's metrics package)

**Context:** `cvertops_security_events_total{event_type, severity}` counter. If Observe has landed, import from `internal/metrics/`. If not, register here with the same name/labels (Observe will deduplicate on merge).

Also: alert rule in `deploy/grafana/alerts.yml`: `SecurityCriticalEvent` fires when `rate(cvertops_security_events_total{severity="critical"}[5m]) > 0`.

**Step 1: Register or import metric. Step 2: Add alert rule. Step 3: Commit.**

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

**Step 1:** `go test ./... -race -count=1`
**Step 2:** `golangci-lint run`
**Step 3:** Fix issues. Final commit.

---

## Subagent Failure Modes to Watch For

| Risk | What goes wrong | Mitigation |
|------|----------------|------------|
| SIGHUP added to shutdown context | Server shuts down on SIGHUP | Separate `signal.Notify` channel — most critical risk, explicit in Task 6 |
| JWT dual-key retries on expiry | Expired token with old key should reject as expired | Task 1 tests `errors.Is(err, jwt.ErrTokenSignatureInvalid)` specifically |
| Encryption version byte added | Design says NO format change | Task 3 uses try-decrypt pattern, no wire format change |
| Security event blocks request | Async write failure affects login | Task 9 tests fire-and-forget pattern with DB error injection |
| Rate limiter unbounded growth (tp§2.1) | 1000+ unique IPs fills memory | Task 9 tests TTL eviction with many unique IPs |
| Wrong IP in events | Uses `r.RemoteAddr` instead of resolved IP | Task 9 specifies `clientIPMiddleware` context |
| `rotate-encryption-key` non-atomic (tp§3.3) | Partial failure leaves mixed state | Task 4 tests rollback on injected failure |
| `rotate-encryption-key` scope creep | Agent guesses additional encrypted columns | Design enumerates ONLY `sso_connections.client_secret_enc` |
| ReloadableConfig boundary | Agent makes non-reloadable fields hot-reloadable | Task 5 lists exact fields from design doc (including SIEM_SYSLOG_*) |
| Syslog replaces DB write | Agent makes syslog the only output | Task 10 specifies syslog is IN ADDITION TO DB write, not a replacement |
| Syslog blocks request | Syslog send on request path | Task 10 uses same async pattern as DB write; tests verify non-blocking |
| CORS check severity | Agent fails instead of warns | Design says warn, not fail (tp§5.1) |
| Windows SIGHUP | Agent tries SIGHUP on Windows | Task 6 uses `//go:build !windows` |
| Phase 8B-8D not reviewed before starting | Plan assumptions may be stale | Deferred review notice at top of document |
