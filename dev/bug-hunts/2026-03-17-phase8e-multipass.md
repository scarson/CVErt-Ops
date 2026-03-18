# Bug Hunt Report: Phase 8E - Secure Pillar (Multi-Pass)

**Date:** 2026-03-17
**Scope:** PR #43 - dual-key JWT rotation, dual-key AES encryption rotation, config hot-reload (ReloadableConfig/SIGHUP/admin API), security event pipeline (async writer, rate limiter, syslog forwarding, Prometheus metrics), doctor security checks, retention policy for security events
**Method:** 5-pass analysis (contract violations, cross-sibling patterns, failure modes, concurrency, error propagation)
**Files examined:** Source files only (no test files)

---

## Findings Summary

| # | Severity | Category | Location | Title |
|---|----------|----------|----------|-------|
| 1 | **Significant** | Contract / Cross-sibling | middleware_auth.go, sso.go, ~25 call sites | JWT/SSO handlers read immutable srv.cfg, not configHolder -- hot-reload is non-functional |
| 2 | Minor | Dead code | syslog.go, main.go | SIEM syslog writer never wired -- SetSyslog never called |
| 3 | Minor | Contract | auth_mfa.go:636 | TOTP enrollment confirm uses crypto.Decrypt instead of DecryptWithFallback |
| 4 | **Significant** | Contract / Divergence | security_events.go vs security_events.sql | Hand-written SQL diverges from sqlc query -- missing ID tiebreaker in sqlc version |
| 5 | Minor | Error propagation | admin_reload.go:34 | Config reload error leaks internal details to HTTP response |
| 6 | **Significant** | Contract | aes.go | DecryptWithFallback falls back on ALL errors, not just GCM auth tag failures |

**Design Concerns:** 3 (see below)

---



## Bug Details



### Bug 1 (Significant): JWT/SSO handlers read srv.cfg, not configHolder



**Pass:** 1 (Contract violations) + 2 (Cross-sibling patterns)



**Location:** internal/api/middleware_auth.go (lines 29-37), internal/api/sso.go (lines 42-52), and approximately 25 other call sites across API handlers.



**Description:**

The entire config hot-reload infrastructure is correctly built:

- ReloadableConfig struct with JWT and SSO fields

- Holder with atomic.Pointer for lock-free reads

- LoadFromSecretsFile parsing all relevant fields

- SIGHUP handler calling ReloadConfig

- Admin API endpoint storing new config in configHolder



However, no API handler reads from the holder. Every handler reads srv.cfg (the immutable config passed at startup):



```go

// middleware_auth.go

func jwtPreviousSecret(cfg *config.Config) []byte {

    if cfg.JWTSecretPrevious == "" {

        return nil

    }

    return []byte(cfg.JWTSecretPrevious)

}

```



The configHolder is stored in ServerDeps and passed through to Server, but handlers never call srv.configHolder.Get(). This means:

- JWT secret rotation via hot-reload has no effect until process restart

- SSO encryption key rotation via hot-reload has no effect until process restart

- The admin reload API returns success but the new secrets are unused



**Note:** PLAN.md line 1294 documents this as a known gap: Phase 8E ships the reload infra; Phase 9 wires handlers to read from the holder. This is not a bug per se, but the code as-shipped could mislead operators into thinking rotation is effective without a restart.



**Impact:** Operators may rotate secrets via SIGHUP or admin API and believe rotation is complete, when in fact the old secrets remain active until the process is restarted.



**Recommendation:** At minimum, add a log warning when config is reloaded stating that handler wiring is pending. Alternatively, wire the ~25 call sites now.

---



### Bug 2 (Minor): SIEM syslog writer never wired



**Pass:** 2 (Cross-sibling patterns)



**Location:** internal/secure/syslog.go (entire file), internal/secure/writer.go (SetSyslog method), cmd/cvert-ops/main.go (line ~202), internal/config/config.go, internal/config/reloadable.go



**Description:**

The SyslogWriter is fully implemented with JSON and CEF format support over UDP/TCP. The EventWriter has a SetSyslog method to attach a syslog writer. The ReloadableConfig has SIEMSyslogAddr and SIEMSyslogFormat fields, and LoadFromSecretsFile correctly parses them.



However:

1. main.go creates the EventWriter but never calls SetSyslog

2. Config struct (the primary env-var config) has no SIEM_SYSLOG_ADDR or SIEM_SYSLOG_FORMAT fields

3. No code path instantiates SyslogWriter or connects it to the event pipeline

4. LoadFromConfig does not populate SIEMSyslogAddr/SIEMSyslogFormat from Config



The syslog forwarding feature is entirely dead code.



**Impact:** SIEM integration is non-functional. Operators cannot forward security events to external SIEM systems.



**Recommendation:** Wire syslog in main.go when env vars are set, and add SIEM_SYSLOG_ADDR/SIEM_SYSLOG_FORMAT to the Config struct.

---



### Bug 3 (Minor): TOTP enrollment confirm uses Decrypt instead of DecryptWithFallback



**Pass:** 1 (Contract violations)



**Location:** internal/api/auth_mfa.go:636



**Description:**

When confirming TOTP enrollment, the handler decrypts the provisional TOTP secret from the enrollment token using crypto.Decrypt:



```go

// Line 636

totpSecret, err := crypto.Decrypt(claims.SecretEnc, ssoKey)

```



However, at line 378 (a different MFA path), the code correctly uses crypto.DecryptWithFallback:



```go

// Line 378

totpSecret, err := crypto.DecryptWithFallback(row.SecretEnc, ssoKey, ssoPrev)

```



If the SSO encryption key is rotated between enrollment start (where the secret is encrypted into the enrollment token) and enrollment confirm (where it is decrypted), the confirm step will fail with a decryption error even though the enrollment token is still valid (it is JWT-signed, not AES-encrypted with the SSO key -- but the SecretEnc payload inside it IS encrypted with the SSO key).



**Impact:** TOTP enrollment that spans a key rotation will fail. The enrollment window is short (typically 5 minutes), so this is unlikely but possible during planned rotation events.



**Recommendation:** Change line 636 to use crypto.DecryptWithFallback(claims.SecretEnc, ssoKey, ssoPrev).

---



### Bug 4 (Significant): Hand-written SQL diverges from sqlc query



**Pass:** 1 (Contract violations)



**Location:** internal/store/security_events.go (hand-written listSecurityEventsQuery, 8 params with composite cursor) vs internal/store/queries/security_events.sql (sqlc query, 7 params without ID tiebreaker)



**Description:**

The hand-written query in security_events.go implements correct keyset pagination with a composite cursor (created_at, id):



```sql

WHERE (se.created_at, se.id) < ($7, $8)

ORDER BY se.created_at DESC, se.id DESC

```



The sqlc query in security_events.sql only uses a single-column cursor:



```sql

WHERE se.created_at < @cursor_created_at

ORDER BY se.created_at DESC

```



This means:

1. The sqlc-generated code has no ID tiebreaker, so events with identical created_at timestamps may be skipped or duplicated during pagination

2. The two query implementations have different parameter counts (7 vs 8) and different behavior

3. If anyone switches to the sqlc version (or if code generation runs), pagination will silently regress



**Impact:** If the sqlc query is used (or regenerated over the hand-written one), security events with identical timestamps will have inconsistent pagination behavior -- some events may be skipped or shown twice.



**Recommendation:** Update the sqlc query to include the ID tiebreaker to match the hand-written version. Or remove the sqlc version if the hand-written query is the canonical implementation.

---



### Bug 5 (Minor): Config reload error leaks internal details to HTTP response



**Pass:** 5 (Error propagation)



**Location:** internal/api/admin_reload.go:34



**Description:**

When the admin reload endpoint encounters an error, it returns the raw error message to the client:



```go

if err \!= nil {

    return nil, huma.Error422UnprocessableEntity("config reload failed", err)

}

```



The err from config.LoadFromSecretsFile or config.ReloadConfig may contain file paths, permission errors, or parse details that reveal internal system structure (e.g., open /etc/cvertops/secrets.json: permission denied).



**Impact:** Information disclosure to authenticated admin users. Low severity since the endpoint requires site-admin privileges, but defense-in-depth dictates not leaking internal paths.



**Recommendation:** Log the full error server-side, return a generic message to the client: config reload failed: check server logs for details.

---



### Bug 6 (Significant): DecryptWithFallback falls back on ALL errors



**Pass:** 3 (Failure modes)



**Location:** internal/crypto/aes.go, DecryptWithFallback function



**Description:**

DecryptWithFallback tries the current key first, then falls back to the previous key on ANY error:



```go

func DecryptWithFallback(ciphertext, currentKey, previousKey []byte) ([]byte, error) {

    plain, err := Decrypt(ciphertext, currentKey)

    if err == nil {

        return plain, nil

    }

    if previousKey == nil {

        return nil, err

    }

    return Decrypt(ciphertext, previousKey)

}

```



The function falls back on all errors, including:

- Corrupted ciphertext (nonce too short)

- Invalid key length (not 16/24/32 bytes)

- Memory allocation failures

- Any other non-auth-tag error



The doc comment says it is for key rotation, implying the fallback should only trigger when the current key produces a GCM authentication tag mismatch (meaning the data was encrypted with a different key). Falling back on structural errors (wrong nonce size, invalid key) masks real problems and may produce confusing secondary errors.



**Impact:** Corrupted data or misconfigured keys will silently attempt decryption with the previous key instead of failing fast, potentially producing misleading error messages that point to the wrong key.



**Recommendation:** Check for GCM authentication failure specifically before falling back. Other errors (invalid nonce, bad key length) should fail immediately without trying the previous key.

---



## Design Concerns



### DC-1: Hot-reload pipeline is incomplete end-to-end



The reload infrastructure is solid but the pipeline has gaps at both ends:

- **Input side:** Config struct lacks SIEM env vars, and LoadFromConfig does not populate all ReloadableConfig fields

- **Output side:** No handler reads from configHolder



This means the full flow (env var or secrets file -> ReloadableConfig -> Holder -> handler reads) is not connected. Each piece works in isolation but the system does not function as a whole.



### DC-2: Rate limiter key collision risk



eventRateLimiter uses fmt.Sprintf("%s:%s", eventType, actorKey) as the map key. If actorKey contains a colon (e.g., an IPv6 address like ::1), the composite key could theoretically collide with a different (eventType, actorKey) pair. In practice this is extremely unlikely but worth noting for a security-critical component.



### DC-3: No bypass_rls in ListSecurityEvents raw transaction



listSecurityEvents in internal/store/security_events.go uses a raw SQL query executed via s.db.Query. The security_events table has no RLS policies (it is a global table per migration 000039), so this is not currently a bug. However, if RLS were ever added to security_events, this query would silently return zero rows because it does not set app.org_id or bypass_rls. Worth documenting as a maintenance hazard.

---



## Pass-by-Pass Notes



### Pass 1: Contract Violations

- Verified JWT dual-key parsing correctly gates on jwt.ErrTokenSignatureInvalid

- Found PendingToken and EnrollmentToken parsers lack dual-key support (by design -- they are short-lived)

- Found Bug 3 (MFA decrypt mismatch) and Bug 4 (SQL divergence)



### Pass 2: Cross-Sibling Patterns

- Traced config flow from main.go through configHolder to handlers -- found Bug 1 (handlers ignore holder)

- Traced syslog wiring from config through writer -- found Bug 2 (dead code)

- Verified rotate.go CLI correctly re-encrypts all SSO secrets in a single transaction



### Pass 3: Failure Modes

- Analyzed DecryptWithFallback error paths -- found Bug 6 (overly broad fallback)

- Verified EventWriter correctly detaches context and handles goroutine lifecycle

- Verified retention runner correctly handles security_events as a global table



### Pass 4: Concurrency

- ReloadableConfig uses atomic.Pointer -- correct for lock-free concurrent reads

- EventWriter channel-based pipeline is clean; Close() drains correctly

- eventRateLimiter uses sync.Mutex protecting map access -- correct

- No concurrency bugs found



### Pass 5: Error Propagation

- Found Bug 5 (error leak in admin reload)

- Verified EventWriter.Write is fire-and-forget with proper error logging

- Verified doctor checks propagate errors correctly with appropriate severity levels
