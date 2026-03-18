# Phase 8E (Secure Pillar) Bug Hunt — Consolidated Findings

**Date:** 2026-03-17
**Scope:** PR #43 — dual-key JWT/AES rotation, config hot-reload, security event pipeline, doctor checks, retention
**Hunters:** Exploratory, Holistic, Multipass

---

## Confirmed Bugs

### B1. Hot-reloaded config is never consumed — JWT and SSO handlers read static `srv.cfg`

**Consensus:** All three hunters found this (highest consensus).
**Location:** `internal/api/middleware_auth.go:48`, `internal/api/auth.go` (9+ call sites), `internal/api/sso.go:71-97`, `internal/api/oauth_oidc.go:257,330`, `internal/api/auth_mfa.go` (12+ call sites), `internal/api/auth_email_verification.go:100`
**Evidence:** Every JWT sign/parse and SSO encrypt/decrypt call reads `srv.cfg.JWTSecret` / `srv.cfg.SSOEncryptionKey` (the immutable startup config), never `srv.configHolder.Load()`. The `configHolder` is written to by both the admin reload endpoint and the SIGHUP handler, but no consumer reads from it. The entire hot-reload pipeline (ConfigHolder, ReloadableConfig, atomic.Pointer, SIGHUP, admin API) is correctly built but disconnected from the handlers.
**Impact:** Config hot-reload for secrets is non-functional. Operators who rotate JWT/SSO keys via SIGHUP or admin API and see the "config reloaded" success response will believe the rotation is live, but old keys remain in use until process restart.
**Blast radius:** Fix requires updating ~30 call sites across the API layer to read from `srv.configHolder.Load()` instead of `srv.cfg`. The `jwtPreviousSecret()` and `ssoEncryptionKey()`/`ssoEncryptionKeyPrevious()` helper functions are the natural choke points — changing these 3 helpers covers most call sites.
**Note:** The plan itself documents this at line 1294 as a known follow-up: "Phase 8E ships the reload infra; Phase 9 wires handlers to read from the holder." This is an intentional phasing decision, not an oversight — but the code as-shipped can mislead operators.

### B2. `LoadFromSecretsFile` is full-replace — partial secrets files zero out fields

**Consensus:** All three hunters found this.
**Location:** `internal/config/reloadable.go:58-148`, `internal/config/reload.go:29`
**Evidence:** `LoadFromSecretsFile` creates a new `ReloadableConfig{}` and only populates fields present in the file. A secrets file containing only `JWT_SECRET` produces a config where `SSOEncryptionKey` is `[32]byte{}`, `SMTPHost` is empty, `SMTPPort` is 0, etc. `holder.Store(newCfg)` replaces the entire config atomically. Fields set at startup via env vars but absent from the secrets file are silently zeroed.
**Impact:** Currently masked by B1 (nothing reads from the holder), but once B1 is fixed, a partial secrets file reload will break SSO decryption, SMTP delivery, and any feature depending on fields not in the secrets file. A simple JWT rotation would take down SSO and email.
**Blast radius:** Fix is localized to `LoadFromSecretsFile` / `ReloadConfig`. Two approaches: (a) merge with current config (read `holder.Load()` as base, overlay file values), or (b) require the secrets file to be complete. Option (a) is more operator-friendly.

### B3. Syslog writer never wired — SIEM forwarding is dead code

**Consensus:** All three hunters found this.
**Location:** `cmd/cvert-ops/main.go` (missing wiring), `internal/secure/writer.go:48-50` (SetSyslog), `internal/secure/syslog.go` (implementation), `internal/config/config.go` (missing SIEM env vars)
**Evidence:** `NewEventWriter(st)` is created in `main.go` but `SetSyslog()` is never called anywhere in the startup path. Additionally, `SIEMSyslogAddr` and `SIEMSyslogFormat` only exist on `ReloadableConfig` — the startup `Config` struct has no corresponding env var bindings. `LoadFromConfig()` does not populate these fields. There is no code path that instantiates a `SyslogWriter`.
**Impact:** SIEM syslog integration is completely non-functional. The entire `syslog.go` implementation is unreachable dead code at runtime.
**Blast radius:** Fix requires: (1) add `SIEMSyslogAddr`/`SIEMSyslogFormat` env vars to `Config`, (2) populate them in `LoadFromConfig`, (3) wire `NewSyslogWriter` + `SetSyslog` in `main.go` startup when configured.

### B4. TOTP enrollment confirm uses `crypto.Decrypt` instead of `DecryptWithFallback`

**Consensus:** Multipass found this; other hunters did not flag it.
**Location:** `internal/api/auth_mfa.go:636`
**Evidence:** Line 636 calls `crypto.Decrypt(encKey, enrollClaims.SecretEnc)` — single-key only. Other MFA paths correctly use `crypto.DecryptWithFallback` (e.g., line 378). If the SSO encryption key is rotated between enrollment start (where the TOTP secret is encrypted into the enrollment token's `SecretEnc` field) and enrollment confirm (where it's decrypted), the confirm step fails even though the enrollment token is still valid.
**Impact:** TOTP enrollment spanning a key rotation will fail. The window is short (typically 5 minutes), so this is unlikely but possible during planned rotation events.
**Blast radius:** Single-line fix — change `crypto.Decrypt(encKey, ...)` to `crypto.DecryptWithFallback(encKey, ssoPrev, ...)`.

### B5. Admin reload handler bypasses `ReloadConfig` — skips feed rescan

**Consensus:** Holistic found this; multipass noted the path divergence.
**Location:** `internal/api/admin_reload.go:31-51`
**Evidence:** The handler calls `config.LoadFromSecretsFile` and `srv.configHolder.Store` directly, bypassing `config.ReloadConfig()` which would also call the `rescan` function. The SIGHUP handler correctly calls `ReloadConfig` (which calls rescan). On Windows where SIGHUP doesn't exist, the admin API is the only reload mechanism.
**Impact:** Feed configuration file changes are re-scanned on SIGHUP but not on admin API reload. Windows users have no way to trigger feed rescan without a process restart.
**Blast radius:** Small fix — change the handler to call `config.ReloadConfig(srv.configHolder, secretsFile, srv.rescanFunc)` or equivalent.

### B6. Admin reload error leaks internal details to HTTP response

**Consensus:** Multipass found this.
**Location:** `internal/api/admin_reload.go:34`
**Evidence:** Line 34: `writeProblem(w, http.StatusBadRequest, err.Error())` — the error from `LoadFromSecretsFile` may contain file paths, permission details, or parse errors that reveal internal system structure.
**Impact:** Information disclosure to authenticated site-admin users. Low severity given the admin-only access, but defense-in-depth principle applies.
**Blast radius:** Single-line fix — log the full error server-side, return generic message to client.

---

## Design Decisions Requiring User Input

### D1. Config holder wiring (B1) — fix now or keep as planned Phase 9 work?

**Location:** ~30 call sites across `internal/api/`
**The concern:** The hot-reload infrastructure is built but disconnected. The plan explicitly documents this as a Phase 9 follow-up (line 1294).
**Why this needs a decision:** Fixing now is substantial work (~30 call sites) but ensures the feature actually works end-to-end. Leaving it creates a period where operators can trigger "successful" reloads that have no effect, which is dangerous for a security product. The admin reload API returns HTTP 200 with "config reloaded" even though nothing actually changes.
**Options:**
  - A) Fix now — wire all call sites to read from `configHolder.Load()`. Ensures rotation works before shipping. ~30 call sites but 3 helper functions are the natural choke points.
  - B) Keep as Phase 9 — add prominent log warnings on reload ("WARNING: handler wiring pending, secrets will not take effect until restart"). Reduces operator confusion.
  - C) Disable the reload endpoints until wiring is complete — prevents false confidence.
**Recommendation:** Option A is safest for a security product. The choke-point helpers (`jwtPreviousSecret`, `ssoEncryptionKey`, `ssoEncryptionKeyPrevious`) make the fix tractable. Option B is acceptable if scope constraints are real.

### D2. Secrets file full-replace vs merge (B2) — which behavior is correct?

**Location:** `internal/config/reloadable.go:58-148`
**The concern:** A partial secrets file zeros out fields not present in the file.
**Why this needs a decision:** Full-replace is simpler and more predictable ("the file IS the config"), but requires operators to maintain a complete secrets file. Merge-with-current is more operator-friendly ("update only what you're rotating"), but introduces complexity around intentional field clearing.
**Options:**
  - A) Merge with current config — `LoadFromSecretsFile` takes `*Holder` and overlays only fields present in the file onto `holder.Load()`.
  - B) Keep full-replace, require complete file — document the requirement prominently. Add validation that critical fields (JWT secret, SSO key) are present.
  - C) Merge with startup config — overlay file values onto `LoadFromConfig(startupCfg)` baseline. This always has env-var defaults as the floor.
**Recommendation:** Option C — merge onto the startup config baseline. This ensures env-var-configured fields are never accidentally zeroed, while the secrets file can override specific fields for rotation.

### D3. `DecryptWithFallback` error gating — should it match JWT's pattern?

**Location:** `internal/crypto/aes.go:16-31`
**The concern:** Falls back on ALL errors, unlike JWT which gates on `ErrTokenSignatureInvalid`. The doc comment says "If GCM authentication fails" but the code doesn't check error type.
**Why this needs a decision:** For AES-GCM, the main "wrong key" error IS the GCM authentication tag failure. Other errors (truncated ciphertext, invalid key length) are structural and the fallback will fail the same way. The practical impact is minimal — but it masks structural problems behind confusing compound error messages.
**Options:**
  - A) Gate on GCM auth error only — match JWT pattern. More precise error reporting.
  - B) Keep as-is — the fallback only does one extra decrypt attempt, and structural errors will fail identically with both keys. Low practical risk.
**Recommendation:** Option A for consistency and cleaner error messages, but this is low priority.

### D4. SetSyslog race condition — fix proactively or defer?

**Location:** `internal/secure/writer.go:48-49` (write), `writer.go:97` (read in goroutine)
**The concern:** `w.syslog` is read/written without synchronization. If `SetSyslog` were called while write goroutines are in flight (e.g., during hot-reload reconnecting syslog), this is a data race.
**Why this needs a decision:** Currently unexploitable (SetSyslog is never called at runtime), but becomes a real race once syslog wiring (B3) and config reload wiring (B1) are fixed.
**Options:**
  - A) Fix now with `atomic.Pointer[SyslogWriter]` — prevent the race before wiring.
  - B) Fix when wiring syslog — address as part of B3 fix.
**Recommendation:** Option B — fix as part of the syslog wiring work. No race exists until SetSyslog is actually called at runtime.

---

## False Positives

### FP1. Rate limiter key collision with IPv6 colons

**Flagged by:** Multipass (DC-2)
**Why invalid:** The rate limiter key uses `event.Type + "|" + event.ActorIP` (pipe separator, not colon as initially reported). Even with colons in IPv6 addresses, the event type namespace is constrained (e.g., "login_failed", "auth_lockout") and does not contain pipes, so collision is impossible in practice.

### FP2. `ListSecurityEvents` missing `bypass_rls`

**Flagged by:** Multipass (DC-3)
**Why invalid:** `security_events` table has no RLS policies (migration 000039 confirms this). The table is global, not org-scoped. Using `s.db.Query` directly is correct for global tables. This is documented practice in the codebase.

---

## Bugs Outside Primary Scope

### O1. Stale sqlc query for security events — missing ID tiebreaker

**Location:** `internal/store/queries/security_events.sql:5-16` (sqlc) vs `internal/store/security_events.go:82-94` (hand-written)
**Evidence:** The hand-written query has composite cursor `(created_at, id)` with 8 params. The sqlc query uses single-column cursor `created_at < $6` with 7 params and no ID tiebreaker.
**Blast radius:** The sqlc version is unused (the hand-written query is the canonical implementation). However, a `sqlc generate` run or a refactor that switches to the generated code would silently regress pagination, potentially skipping or duplicating events with identical timestamps.
**Recommendation:** Update the sqlc query to match the hand-written version, or remove it if it serves no purpose.

### O2. `LoadFromConfig` silently zeros invalid SSO hex keys

**Location:** `internal/config/reloadable.go:167-172`
**Evidence:** `LoadFromConfig` uses `if key, err := decodeHexKey(...); err == nil` — invalid hex is silently ignored. An operator who misconfigures `SSO_ENCRYPTION_KEY_PREVIOUS` as non-hex gets no startup error; the field is silently zeroed, and `DecryptWithFallback` skips it entirely.
**Blast radius:** Startup-only path (not hot-reload). `LoadFromSecretsFile` correctly validates. Fix would be to log a warning on invalid hex at startup.
**Recommendation:** Add `slog.Warn` when hex decode fails at startup. Low priority.
