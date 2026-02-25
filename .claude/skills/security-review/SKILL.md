---
name: security-review
description: Run a security review of CVErt Ops code against OWASP Top 10 and project-specific security requirements from PLAN.md §7 and §15. Use before merging any auth, webhook, tenant-isolation, or public API code. This is a security product — apply strict standards.
argument-hint: "[file-path or package — omit to review files in conversation context]"
---

# Security Review

Reviewing CVErt Ops code as a security product. Apply strict standards — this application manages vulnerability intelligence for security teams.

Target: **$ARGUMENTS** (or files in conversation context)

---

## Checklist

Work through each section. For each item: **✅ OK**, **❌ FAIL** (with file:line + fix), or **N/A**.

---

### 1. SQL Injection (OWASP A03:2021)

- [ ] All queries use `sqlc`-generated code or `squirrel` query builder — no `fmt.Sprintf` constructing SQL strings
- [ ] No `+` string concatenation to build query fragments
- [ ] Dynamic `IN` clauses use `= ANY($1::text[])` with a slice parameter — not looped positional placeholders
- [ ] `squirrel` always calls `.PlaceholderFormat(squirrel.Dollar).ToSql()` and passes returned args to pgx

---

### 2. Authentication (OWASP A07:2021)

- [ ] Every `jwt.ParseWithClaims` / `jwt.Parse` call includes `jwt.WithValidMethods([]string{"HS256"})` — prevents algorithm confusion (`alg: none`, RS256→HS256 swap)
- [ ] Every JWT parse includes `jwt.WithExpirationRequired()` — rejects tokens without `exp`
- [ ] `JWT_SECRET` validated at startup: minimum 32 bytes, `log.Fatalf` if missing or too short — never auto-generated
- [ ] `token_version` embedded in JWT claims and checked against `users.token_version` on refresh
- [ ] Refresh endpoint looks up `refresh_tokens` table by JTI before accepting

---

### 3. API Key Security (PLAN.md §7.1)

- [ ] API key stored only as `sha256(raw_key)` in `api_keys` table — raw key never persisted
- [ ] Hash comparison uses `crypto/subtle.ConstantTimeCompare` — **never** `==`, `bytes.Equal`, or `strings.Compare`
- [ ] Raw key shown exactly once in create response, then discarded
- [ ] API keys rejected in query string params (`?api_key=`, `?token=`, `?access_token=`)

---

### 4. Tenant Isolation / Authorization (OWASP A01:2021 + PLAN.md §6)

- [ ] Every org-scoped repository method has `orgID uuid.UUID` as a required parameter
- [ ] No org-scoped query runs without filtering by `orgID`
- [ ] Org ID extracted from **JWT claims**, not from user-controlled request body or URL (only the path `{org_id}` is allowed, and it must be validated against JWT claims)
- [ ] `SET LOCAL app.org_id = $1` called at the start of every org-scoped transaction
- [ ] Background worker code uses `workerTx` helper (sets `app.bypass_rls = 'on'`) — not the normal org-scoped transaction helper
- [ ] Child tables have `org_id` column — not relying on parent table's RLS alone

---

### 5. SSRF Prevention (OWASP A10:2021 + PLAN.md §11.3)

- [ ] All outbound webhook HTTP calls use a `doyensec/safeurl`-wrapped client
- [ ] Webhook URL validated against SSRF rules **at registration time** (not only at delivery time)
- [ ] HTTP redirect following disabled: `client.CheckRedirect = func(...) error { return http.ErrUseLastResponse }`
- [ ] `MaxConnsPerHost` set on transport (not unlimited)
- [ ] Webhook HTTP client has `Timeout: 10 * time.Second`
- [ ] DB transaction NOT held open during outbound webhook HTTP call

---

### 6. Input Validation (OWASP A03:2021 + PLAN.md §15)

- [ ] All request structs use huma struct tags (`minLength`, `maxLength`, `format:"uuid"`, `minimum`, `maximum`)
- [ ] Webhook URLs have additional handwritten SSRF validation beyond struct tags
- [ ] Regex alert patterns: `regexp.Compile` validated on save, max 256 chars enforced
- [ ] `PATCH` request structs use pointer types for ALL optional fields (`*bool`, `*string`, `*float64`) — not value types with `omitempty`
- [ ] Regex patterns validated at rule save time, not at evaluation time

---

### 7. Sensitive Data Exposure (OWASP A02:2021)

- [ ] `JWT_SECRET`, SMTP credentials, API key raw values, webhook signing secrets — never logged
- [ ] Config struct implements custom `String()` / `MarshalText()` to mask secret fields
- [ ] Webhook `signing_secret` and `signing_secret_secondary` not returned in GET responses
- [ ] `slog` handlers use `slog.LogValuer` on types containing sensitive data (or values are explicitly redacted)

---

### 8. OAuth / OIDC Security (PLAN.md §7.2)

- [ ] OAuth `state` parameter: 32 cryptographically random bytes per request — not reused, not hardcoded
- [ ] State stored in `HttpOnly, Secure, SameSite=Lax` cookie (Lax required — not Strict, which breaks OAuth callbacks)
- [ ] State cookie verified in callback; mismatch → 400, cookie deleted before code exchange
- [ ] `EXTERNAL_URL` env var used for redirect URIs — never `r.Host` or any request header
- [ ] GitHub flow does NOT use `coreos/go-oidc` (GitHub is not OIDC — no discovery endpoint)
- [ ] GitHub flow requests `user:email` scope explicitly
- [ ] Identity matched by `provider_user_id` (immutable), not by email (mutable, recyclable)
- [ ] Google OIDC: nonce generated, stored in cookie, verified against ID token `nonce` claim
- [ ] `Secure` cookie flag derived from config (`COOKIE_SECURE=true`) — never hardcoded

---

### 9. Webhook Delivery Security (PLAN.md §11.3)

- [ ] `X-CVErt-Timestamp: <unix-seconds>` header sent on every delivery
- [ ] `X-CVErtOps-Signature: sha256=<hex>` computed over `timestamp + "." + body`
- [ ] Signature secret rotation supported via `signing_secret_secondary` field
- [ ] Response body read and discarded: `io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))`
- [ ] Connection headers (`Host`, `Content-Length`) blocked from per-channel custom headers

---

### 10. Denial of Service Protection (PLAN.md §18.3)

- [ ] `http.Server.ReadHeaderTimeout` set (Slowloris protection)
- [ ] `http.Server.ReadTimeout` set
- [ ] `http.Server.IdleTimeout` set
- [ ] Global `middleware.RequestSize(1 << 20)` (1 MB) registered before routes
- [ ] Argon2 semaphore on login: non-blocking (`select { case sem <- struct{}{}: ... default: return 503 }`)

---

### 11. Concurrency Safety

- [ ] `errgroup` NOT used for notification fan-out (cancels siblings on first error — use `sync.WaitGroup`)
- [ ] Background goroutines spawned from HTTP handlers use `context.WithoutCancel(r.Context())`
- [ ] `time.NewTicker` used in polling loops — not `time.After` (timer leak)

---

### 12. Crypto & Randomness

- [ ] All random values for security (state params, JTI, API keys, nonces) use `crypto/rand`, not `math/rand`
- [ ] API key prefix is `cvo_` followed by 32+ crypto-random bytes, base58/hex-encoded
- [ ] HMAC uses `crypto/hmac` + `crypto/sha256` — not MD5, SHA1, or hand-rolled

---

## Summary

```
Total items checked: N
Critical failures (❌): X  — must fix before merge
Warnings:             Y
```

List all ❌ items sorted by risk (auth/injection > tenant isolation > SSRF > denial of service > crypto).
