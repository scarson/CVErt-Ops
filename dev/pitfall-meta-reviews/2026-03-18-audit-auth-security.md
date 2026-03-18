# Pitfall Audit: Authentication & Security

**Date:** 2026-03-18
**Auditor:** audit-auth agent (Explore)
**Scope:** 21 pitfalls across JWT, OAuth/OIDC, API keys, argon2, SSRF, cookies, config
**Code paths:** `internal/auth/*`, `internal/api/auth*.go`, `internal/api/oauth_*.go`, `internal/api/sso.go`, `internal/notify/webhook.go`, `cmd/cvert-ops/main.go`, `internal/config/*`

---

## Summary Table

| ID | Title | Status | Evidence |
|---|---|---|---|
| 1.3 | GitHub Does Not Support OIDC | VALIDATED | `api/oauth_github.go` (raw OAuth2), `api/oauth_google.go` (go-oidc) |
| 1.4 | GitHub OAuth Scope (user:email) | VALIDATED | `api/server.go:124` — Scopes includes "user:email" |
| 3.1 | JWT Algorithm Confusion / alg:none | VALIDATED | `auth/jwt.go` — WithValidMethods([]string{"HS256"}) on ALL 4 parse functions |
| 3.2 | Argon2id OOM DOS (semaphore) | VALIDATED | `api/server.go:80,100,485-487` — non-blocking semaphore, default cap 5 |
| 3.3 | Blocking Semaphore → Starvation | VALIDATED | `api/server.go:487` — select/default pattern, never blocks |
| 3.4 | Refresh Token Infinite Cloning (JTI) | VALIDATED | `migrations/000006`, `api/auth.go:577-627` — JTI table + theft detection + 60s grace |
| 3.5 | OAuth2 CSRF (state + cookie) | VALIDATED | `api/oauth_helpers.go:22-56` — crypto random, HttpOnly, SameSite=Lax, one-time use |
| 3.6 | API Keys as JWTs (opaque + sha256) | VALIDATED | `auth/apikey.go:17-32` — `cvo_` prefix + 32 hex bytes, sha256 stored |
| 3.7 | Unbounded Request Body | VALIDATED | `api/server.go:214` — RequestSize(1<<20) globally before routes |
| 3.8 | Slowloris DOS (server timeouts) | VALIDATED | `main.go:299-301` — ReadHeaderTimeout:5s, ReadTimeout:15s, IdleTimeout:120s |
| 3.9 | Webhook HMAC Replay (timestamp) | VALIDATED | `notify/webhook.go:55-67` — X-CVErt-Timestamp + "timestamp.body" HMAC |
| 3.10 | API Key Timing Oracle | VALIDATED | `api/middleware_auth.go:131` — subtle.ConstantTimeCompare |
| 3.11 | Identity by Email (provider_user_id) | VALIDATED | GitHub: numeric ID, Google: sub claim, OIDC: sub+connection_id |
| 3.12 | bypassTx from API Handler | VALIDATED | bypassTx not exposed to API paths; RLS on all org-scoped tables |
| 8.1 | JWT_SECRET missing → fatal | VALIDATED | `main.go:778-780` — validateConfig fatals, min 32 bytes |
| 8.2 | redirect_uri from Host header | VALIDATED | All flows use config.ExternalURL, never r.Host |
| 8.3 | State cookie SameSite=Strict | VALIDATED | `oauth_helpers.go:30` — SameSite=Lax (NOT Strict) |
| 8.4 | OIDC nonce not verified | VALIDATED | `oauth_google.go:105-114`, `oauth_oidc.go:186-195` — constant-time compare |
| 8.5 | Webhook redirect SSRF | VALIDATED | `notify/client.go:18-19` — CheckRedirect returns http.ErrUseLastResponse |
| 8.6 | Webhook secret rotation | VALIDATED | Secondary signature + 24h grace via WEBHOOK_SECRET_GRACE_HOURS |
| 8.7 | Secure:true hardcoded cookies | VALIDATED | config.CookieSecure env var + startup validation for HTTPS |
| 8.8 | API key in query string | PARTIALLY IMPLEMENTED | Middleware only checks Bearer; no explicit 400 for query params |
| 13.5 | Config defaults match docs | VALIDATED | REGISTRATION_MODE="invite-only", COOKIE_SECURE validated at startup |

**Totals:** 20 VALIDATED, 1 PARTIALLY IMPLEMENTED (8.8), 0 UNIMPLEMENTED

---

## Detailed Findings

### 1.3 GitHub Does Not Support OIDC
**Status:** VALIDATED
**Evidence:** `internal/api/oauth_github.go` (raw OAuth2 + REST), `internal/api/oauth_google.go` (go-oidc)
**All instances checked:** GitHub, Google, generic OIDC — all use correct library per provider
**Notes:** Clean provider separation. GitHub uses golang.org/x/oauth2 + REST for /user and /user/emails.

### 1.4 GitHub OAuth Scope (user:email)
**Status:** VALIDATED
**Evidence:** `internal/api/server.go:124` — `Scopes: []string{"user:email"}`
**Notes:** Comment confirms "REQUIRED per PLAN.md §7.2"

### 3.1 JWT Algorithm Confusion
**Status:** VALIDATED
**Evidence:** `internal/auth/jwt.go` — lines 55, 68, 123-124, 195, 259-260, 271
**All instances checked:** ParseAccessToken, ParseRefreshToken, ParsePendingToken, ParseEnrollmentToken — ALL enforce WithValidMethods([]string{"HS256"}) + WithExpirationRequired()
**Notes:** After HR D2 remediation, these are deduplicated via generic helper. Pre-remediation: 4x copy-paste but all correct.

### 3.2 Argon2id OOM DOS
**Status:** VALIDATED
**Evidence:** `api/server.go:80,100` (semaphore init), `server.go:485-487` (acquire logic)
**All instances checked:** auth.go:149,280,336,356,826,844; auth_mfa.go:1135; auth_password_reset.go:214 — all call sites acquire before hashing
**Notes:** Non-blocking with immediate 503 on excess. Default capacity: cfg.Argon2MaxConcurrent (5).

### 3.3 Blocking Semaphore
**Status:** VALIDATED
**Evidence:** `api/server.go:487` — select/default pattern
**Notes:** Never blocks. Immediately returns false if no slots. Callers use defer for release.

### 3.4 Refresh Token Infinite Cloning
**Status:** VALIDATED
**Evidence:** `migrations/000006_create_refresh_tokens.up.sql` (JTI table), `api/auth.go:577-627` (theft detection)
**All instances checked:** JTI stored on issue, checked on refresh, replaced_by_jti chain, 60s grace window
**Notes:** Reuse detection fires EventAuthTokenReuseDetected + increments token_version.

### 3.5 OAuth2 CSRF
**Status:** VALIDATED
**Evidence:** `api/oauth_helpers.go:22-56`
**All instances checked:** GitHub (github.go:45-46,57), Google (google.go:46,60), OIDC (oauth_oidc.go:97-98,111)
**Notes:** 32 crypto random bytes, HttpOnly, SameSite=Lax, constant-time compare, deleted after use.

### 3.6 API Keys as JWTs
**Status:** VALIDATED
**Evidence:** `auth/apikey.go:17-32`
**Notes:** Opaque `cvo_` + 32 hex bytes. Only sha256(raw_key) stored. Completely decoupled from JWT.

### 3.7 Unbounded Request Body
**Status:** VALIDATED
**Evidence:** `api/server.go:214` — `r.Use(middleware.RequestSize(1 << 20))`
**Notes:** Registered globally before all routes.

### 3.8 Slowloris DOS
**Status:** VALIDATED
**Evidence:** `cmd/cvert-ops/main.go:299-301`
**All instances checked:** Main server (299-301), metrics server (311), worker metrics server (477)
**Notes:** ReadHeaderTimeout:5s, ReadTimeout:15s, IdleTimeout:120s on all servers.

### 3.9 Webhook HMAC Replay
**Status:** VALIDATED
**Evidence:** `notify/webhook.go:55-67`
**Notes:** X-CVErt-Timestamp header + HMAC over "timestamp.body". Secondary signature for rotation grace.

### 3.10 API Key Timing Oracle
**Status:** VALIDATED
**Evidence:** `api/middleware_auth.go:131`
**All instances checked:** API key auth (middleware_auth.go:131), state param (oauth_helpers.go:53), nonce (oauth_google.go:111, oauth_oidc.go:192)
**Notes:** subtle.ConstantTimeCompare used for all secret comparisons.

### 3.11 Identity by Email
**Status:** VALIDATED
**Evidence:** GitHub: oauth_github.go:128 (numeric user ID), Google: oauth_google.go:117 (sub claim), OIDC: oauth_oidc.go:244-245 (sub + connection_id)
**Notes:** Email is display attribute only — used for upsert but never for matching. Schema enforces (provider, provider_user_id) composite key.

### 3.12 bypassTx from API Handler
**Status:** VALIDATED
**Evidence:** bypassTx not exposed in handler-accessible API surface
**Notes:** RLS policies enforce org_id filtering on all org-scoped tables. Worker-only operations use WorkerTx.

### 8.1 JWT_SECRET Missing
**Status:** VALIDATED
**Evidence:** `cmd/cvert-ops/main.go:778-780`
**Notes:** validateConfig() fatals on missing or <32 byte JWT_SECRET.

### 8.2 redirect_uri from Host Header
**Status:** VALIDATED
**Evidence:** All redirect URIs use config.ExternalURL (server.go:122, server.go:150, oauth_oidc.go:228,237,309,319)
**Notes:** Never reads r.Host. Tests verify at server_test.go:86-107.

### 8.3 State Cookie SameSite
**Status:** VALIDATED
**Evidence:** `oauth_helpers.go:30` — SameSite=http.SameSiteLaxMode
**Notes:** Comment confirms "cross-site callback" requirement. Both state and nonce cookies use Lax.

### 8.4 OIDC Nonce Verification
**Status:** VALIDATED
**Evidence:** `oauth_google.go:105-114`, `oauth_oidc.go:186-195`
**Notes:** Both use constant-time compare against cookie-stored nonce.

### 8.5 Webhook Redirect SSRF
**Status:** VALIDATED
**Evidence:** `notify/client.go:18-19`
**Notes:** CheckRedirect returns http.ErrUseLastResponse. safeurl validates initial URL.

### 8.6 Webhook Secret Rotation
**Status:** VALIDATED
**Evidence:** notify/webhook.go:63-67, config.go:122
**Notes:** signing_secret_secondary + X-CVErtOps-Signature-Secondary header + 24h grace.

### 8.7 Cookie Secure Hardcoded
**Status:** VALIDATED
**Evidence:** config.go:43, main.go:784-785
**Notes:** COOKIE_SECURE env var, validated at startup for HTTPS environments.

### 8.8 API Key in Query String — PARTIALLY IMPLEMENTED
**Status:** PARTIALLY IMPLEMENTED
**Evidence:** `api/middleware_auth.go` — checks only Authorization: Bearer header
**Notes:** Middleware ignores query string params (doesn't extract API keys from them), so there's no security vulnerability — query string keys are simply ignored. However, the pitfall prescribes an explicit 400 rejection for `?api_key=`, `?token=`, `?key=`, `?access_token=` to prevent accidental logging exposure. This explicit rejection is NOT implemented. The fix is defensive (prevents users from accidentally putting secrets in URLs that get logged by proxies/CDNs).
**Assessment:** Low risk since query params are ignored, but the explicit rejection is a defense-in-depth measure worth adding.

### 13.5 Config Defaults Match Docs
**Status:** VALIDATED
**Evidence:** config.go:34 (REGISTRATION_MODE="invite-only"), main.go:784-785 (COOKIE_SECURE validation)
**Notes:** Defaults match PLAN.md and CLAUDE.md. Dangerous combinations validated at startup.

---

## New Discoveries

1. **Constant-time compare consistency** — used in 4+ locations (API keys, OAuth state, OIDC nonce). Well-established pattern.
2. **Semaphore release discipline** — all argon2 call sites use defer for semaphore release. No leak paths found.
3. **OAuth flow parity** — GitHub, Google, and generic OIDC all follow the same state/nonce/redirect pattern despite different underlying protocols.

---

## Assessment

The auth & security implementation is **excellent**. 20 of 21 pitfalls fully validated. The single partial implementation (8.8 — query string API key rejection) is low-risk since keys in query strings are ignored, not accepted. The pitfall's recommendation for explicit 400 rejection is a defense-in-depth measure that should be added but doesn't represent a security vulnerability.

Note: HR D2 remediation (JWT parse deduplication) will consolidate the 4x copy-paste of WithValidMethods/WithExpirationRequired into a generic helper, further reducing the surface area for this critical security check.
