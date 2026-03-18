# Section 3: Authentication & Security

> **Reader context:** "I'm working on auth, OAuth, JWT, API keys, or MFA"

This section covers pitfalls in authentication flows (JWT, OAuth/OIDC, API keys), password hashing, webhook signing, tenant isolation boundaries, and security-sensitive state management. For HTTP-layer security (request body limits, Slowloris, server timeouts), see Section 4 (API Design & HTTP).

---

## AUTH-1: GitHub Does Not Support OIDC

**The Flaw:** Section 7.2 specified `coreos/go-oidc/v3` for both GitHub and Google OAuth without distinguishing between them.

**Why It Matters:** GitHub does not implement OpenID Connect. It has no `.well-known/openid-configuration` discovery endpoint. Calling `oidc.NewProvider(ctx, "https://github.com")` returns a 404 immediately, failing at provider initialization before any user interaction occurs. An AI coding assistant given the spec as written would implement a GitHub OIDC flow that fails in every environment at the very first request.

**The Fix:** The implementation is split by provider:

| Provider | Library | Identity extraction |
|---|---|---|
| **Google** | `coreos/go-oidc/v3` (OIDC) | ID token claims: `sub`, `email`, `email_verified` |
| **GitHub** | `golang.org/x/oauth2` only (raw OAuth 2.0) | `GET https://api.github.com/user` (for numeric user ID) + `GET https://api.github.com/user/emails` (for primary verified email) |
| **Future enterprise OIDC** | `coreos/go-oidc/v3` | Configurable discovery URL |

GitHub-specific flow: exchange code for token -> call `/user` and `/user/emails` APIs -> find the entry with `primary: true, verified: true` -> upsert `user_identities`.

**The Lesson:** "OAuth" and "OIDC" are not interchangeable. OIDC adds an ID token and a `.well-known/openid-configuration` discovery endpoint on top of OAuth 2.0. GitHub supports OAuth 2.0 only. Always verify a provider's documentation before choosing a library. Many popular OAuth providers (GitHub, Twitter/X, Stripe) do not implement OIDC.

---

## AUTH-2: GitHub OAuth Scope Blackhole — `/user/emails` Requires `user:email` Scope

**The Flaw:** Section 7.2 correctly specified calling `https://api.github.com/user/emails` to retrieve the primary verified email after GitHub OAuth, but did not specify which OAuth scope grants that access.

**Why It Matters:** GitHub's default OAuth flow grants read access to public profile data only. The `/user/emails` endpoint requires the `user:email` scope to be explicitly requested. Without it, the endpoint returns an empty array for any GitHub user whose email is set to private — which is the GitHub default setting. This permanently blocks signup for the majority of GitHub users. An AI implementing `oauth2.Config` with standard defaults omits this scope entirely.

**The Fix:** The GitHub `oauth2.Config` must explicitly include `user:email`:
```go
githubOAuthConfig := &oauth2.Config{
    ClientID:     cfg.GitHubClientID,
    ClientSecret: cfg.GitHubClientSecret,
    RedirectURL:  cfg.GitHubCallbackURL,
    Endpoint:     github.Endpoint,
    Scopes:       []string{"user:email"}, // REQUIRED — do not omit
}
```
Note: `read:user` alone is insufficient. `user:email` is the specific scope for `/user/emails` access.

**The Lesson:** OAuth scopes control API access, and provider defaults are never "read everything." Always check the specific endpoint's documentation for required scopes — do not assume the default OAuth grant covers all the API calls you plan to make. For GitHub specifically, `/user/emails` is a separate permission from basic profile access and must be explicitly requested.

---

## AUTH-3: JWT Algorithm Confusion and `alg: none` Bypass

**The Flaw:** JWT parsing was not explicitly whitelisting the expected signing algorithm.

**Why It Matters:** Permissive JWT parsers enable two critical attacks:
- **Algorithm confusion:** Attacker changes `alg` in the header from RS256 to HS256, then signs with the server's public key used as the HMAC secret. The server verifies the signature — with the wrong key — and accepts the forged token.
- **`alg: none` bypass:** Attacker removes the signature entirely and sets `alg: none`. Naive parsers accept this as a valid unsigned token.

Either attack allows forging arbitrary JWT claims (user ID, org ID, roles) without knowing the signing secret.

**The Fix:**
```go
token, err := jwt.ParseWithClaims(tokenString, &Claims{}, keyFunc,
    jwt.WithValidMethods([]string{"HS256"}),
    jwt.WithExpirationRequired(),
)
```
`WithValidMethods` is mandatory on every parse call, including refresh token validation. `WithExpirationRequired` rejects tokens without an `exp` claim, preventing accidentally-issued non-expiring tokens from remaining permanently valid. The JWT secret must be at minimum 32 cryptographically random bytes, validated at startup.

**The Lesson:** JWT security requires explicit algorithm whitelisting at the parser level. `golang-jwt/jwt/v5` does not enforce this by default. `WithValidMethods` is a non-optional security control. Treat any unguarded `jwt.Parse` or `jwt.ParseWithClaims` call as a critical security bug. Add a static analysis check or linting rule to catch unguarded calls in CI.

---

## AUTH-4: Argon2id OOM Denial of Service — Concurrency Limiter Required

**The Flaw:** The argon2id configuration was documented (m=19456, t=2, p=1) but no concurrency guard was specified for the login endpoint.

**Why It Matters:** Each argon2id hash operation allocates ~19.5 MB of RAM. Without a concurrency cap, 50 concurrent unauthenticated login requests cause ~975 MB of simultaneous allocation. On the constrained hardware that homelab/self-hosted users run (Raspberry Pi, cheap VPS, shared NAS), this OOM-kills the container. This is a trivially mounted denial-of-service attack requiring no authentication and no special knowledge.

**The Fix:** A global non-blocking semaphore before the hashing function — excess requests are immediately rejected with 503, never queued (see AUTH-5 for why blocking is itself a DOS vector):
```go
// Initialized at server startup; configurable via ARGON2_MAX_CONCURRENT (default 5)
var argon2Sem = make(chan struct{}, cfg.Argon2MaxConcurrent)

func acquireArgon2Slot() bool {
    select {
    case argon2Sem <- struct{}{}:
        return true
    default:
        return false // reject immediately — do NOT block
    }
}
```
IP-based rate limiting on the login endpoint is the first line of defense; the semaphore is the backstop that bounds worst-case RAM consumption even if the rate limiter is bypassed.

**The Lesson:** Memory-hard password hashing algorithms are intentionally expensive. The same properties that make them resistant to offline cracking (high memory usage per operation) make them vectors for server-side OOM attacks when called concurrently without a guard. Any time you implement argon2id, bcrypt, or scrypt, add a concurrency limiter. The OWASP parameters are chosen for security, not for handling unbounded concurrent load. See AUTH-5 for the critical implementation detail: the semaphore must be non-blocking.

---

## AUTH-5: Blocking Semaphore Converts OOM-DOS into Connection-Starvation DOS

**The Flaw:** The prescribed argon2id semaphore used a blocking channel send (`sem <- struct{}{}`). The spec text said "excess requests block on the semaphore channel — they do not fail; they queue."

**Why It Matters:** Blocking is not safe. With 1,000 concurrent bad login requests and a semaphore cap of 5:
- 5 goroutines acquire slots and begin hashing
- 995 goroutines block indefinitely on `sem <- struct{}{}`
- Each blocked goroutine holds an open HTTP connection with its associated memory
- This exhausts the server's connection pool and starves all other API endpoints — including endpoints completely unrelated to authentication
- Legitimate users face multi-minute login timeouts while waiting behind the attacker in the queue

The OOM-DOS is fixed but replaced with a connection-starvation Layer 7 DOS of equivalent severity.

**The Fix:** Use a non-blocking `select/default` that immediately rejects requests when all slots are busy:
```go
select {
case argon2Sem <- struct{}{}:
    defer func() { <-argon2Sem }()
default:
    // Return 503 immediately with Retry-After header
    // Never block — blocked goroutines hold HTTP connections
    return huma.Error503ServiceUnavailable("server busy, retry shortly")
}
```
Legitimate users rarely have more than 1-2 simultaneous login attempts. The 503 response with `Retry-After` is the correct signal for a transient capacity constraint.

**The Lesson:** A concurrency gate that blocks rather than rejects converts a resource-exhaustion attack vector into a different resource-exhaustion attack vector. When designing concurrency controls for public-facing endpoints, always prefer fast-fail (reject with 503) over queuing. Queuing is appropriate for internal, bounded workloads — not for endpoints reachable by unauthenticated attackers. The system's overall concurrency is bounded by the connection pool, not by a single endpoint's semaphore.

---

## AUTH-6: Stateless Refresh Token "Infinite Cloning"

**The Flaw:** Refresh tokens were implemented as stateless JWTs. Token rotation was specified but the server never tracked which tokens had been "spent."

**Why It Matters:** If an attacker steals a user's refresh token, they exchange it for a new access+refresh pair. The legitimate user then exchanges the same (still-valid) original token for their own new pair. Both parties now hold valid, parallel token families. The server has no record that the original token was spent twice. The `token_version` mechanism cannot help — both attacker and victim hold tokens from the same valid family version. The theft is undetectable.

**The Fix:** Add a `refresh_tokens` table tracking `jti` (JWT ID), `user_id`, `token_version`, `expires_at`, `used_at`. At refresh: look up by `jti`; if `used_at IS NOT NULL` -> theft detected -> immediately increment `users.token_version` (invalidates all active sessions) -> return 401. If `used_at IS NULL` and version matches -> mark used, issue new pair with new `jti`.

**The Lesson:** Token rotation without server-side JTI tracking provides a false sense of security. "Rotating refresh tokens" only helps if the server can detect reuse of a spent token. Without a `refresh_tokens` table, stateless rotation merely issues new tokens to both the attacker and the legitimate user in parallel.

---

## AUTH-7: OAuth2 Login CSRF via Missing or Hardcoded `state` Parameter

**The Flaw:** OAuth2 flows were specified without mandating secure random `state` parameter generation and validation.

**Why It Matters:** An attacker initiates an OAuth authorization flow, captures the callback URL, and tricks a victim into clicking it (e.g., via a CSRF-vector page). If the server doesn't validate the `state` parameter against a per-session secret, the victim is silently logged into the attacker's account. Any watchlists, API keys, or credentials the victim then creates become accessible to the attacker.

**The Fix:** The `/auth/{provider}/login` endpoint generates 32 cryptographically random bytes, sets them as an `HttpOnly, Secure, SameSite=Lax` cookie with 5-minute expiration, and passes them to `AuthCodeURL`. The callback handler reads the cookie, validates it matches the `state` query parameter exactly, then deletes the cookie before exchanging the code. Returns `400` if missing, mismatched, or expired.

**The Lesson:** The OAuth2 `state` parameter exists specifically to prevent Login CSRF. Never hardcode `"state"` or generate a static value. Never omit validation in the callback. This is a well-documented OAuth2 security requirement that AI assistants frequently skip as a "minor detail."

---

## AUTH-8: API Keys Implemented as Long-Lived JWTs

**The Flaw:** API keys were not specified as distinct from JWTs, leaving the implementation open to treating them as long-lived JWT tokens.

**Why It Matters:** Long-lived JWTs as API keys: (a) cannot be individually revoked without a stateful blocklist — revoking one requires invalidating all JWTs with the same signing key; (b) rotating `JWT_SECRET` (due to compliance or suspected compromise) instantly invalidates every API key across every organization simultaneously, breaking all CI/CD pipelines and external integrations with a single config change.

**The Fix:** API keys must be opaque high-entropy strings (32 random bytes, base58/hex-encoded, prefixed `cvo_`). Only the `sha256(raw_key)` is stored in the `api_keys` table. Raw key shown once on creation, never stored. Authentication: compute `sha256(presented_key)` and look up the hash. Decoupled entirely from JWT infrastructure and `JWT_SECRET`.

**The Lesson:** "API key" and "long-lived JWT" are fundamentally different mechanisms. JWTs carry self-verifiable claims and expire by time. API keys are opaque credentials revoked by deleting a DB row. For systems where individual revocation and secret rotation independence matter (enterprise CI/CD, programmatic access), API keys must be opaque strings backed by a DB row.

---

## AUTH-9: Webhook HMAC Signatures Are Replayable Without Timestamp Binding

**The Flaw:** The webhook signature was specified as `HMAC-SHA256(body, secret)` with a single `X-CVErtOps-Signature` header. No timestamp was included in the signed payload.

**Why It Matters:** HMAC over just the body is replayable indefinitely. An attacker who intercepts a legitimate webhook delivery (e.g., via network tap, compromised CI/CD pipeline, or MITM on HTTP) captures the body and the `X-CVErtOps-Signature` header. They can re-POST this identical pair to the consumer endpoint at any time in the future, and the consumer's HMAC verification passes because the signature is still valid — nothing in the signed payload has changed. Attack consequences: duplicate alert processing, event flooding, triggering integrations (e.g., creating duplicate Jira tickets, sending repeated Slack notifications, re-triggering CI/CD pipelines) indefinitely. The attacker needs the intercepted message only once.

**The Fix:** Include a timestamp in the signed payload to bind the signature to a specific point in time. Two headers are required:
- `X-CVErt-Timestamp: <unix-seconds>` — current time at delivery
- `X-CVErtOps-Signature: sha256=<hex>` — HMAC-SHA256 over `timestamp + "." + body`

```go
ts := strconv.FormatInt(time.Now().Unix(), 10)
mac := hmac.New(sha256.New, []byte(secret))
mac.Write([]byte(ts + "." + string(body)))
sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
req.Header.Set("X-CVErt-Timestamp", ts)
req.Header.Set("X-CVErtOps-Signature", sig)
```

Consumers must: (1) parse the timestamp, (2) reject if `abs(now - timestamp) > 300s`, (3) verify the HMAC. A captured message replayed after 5 minutes fails step 2.

**The Lesson:** HMAC guarantees authenticity (the message came from someone who knows the secret) but not freshness. Without a timestamp, a valid HMAC is valid forever. This pattern — timestamp in signed payload + short acceptance window — is the standard replay prevention mechanism used by Stripe, GitHub webhooks, and AWS SNS. It is not optional for any webhook that triggers idempotency-sensitive actions.

---

## AUTH-10: API Key Hash Comparison Uses Short-Circuiting Equality — Timing Oracle

**The Flaw:** The API key authentication code computed `sha256(presented_key)` and compared it to the stored hash using `==` or `bytes.Equal`.

**Why It Matters:** Go's `==` operator on arrays and `bytes.Equal` both short-circuit: they return `false` immediately upon finding the first mismatching byte. An attacker who can make many API requests and measure response latency to nanosecond precision can distinguish "mismatched at byte 1" from "mismatched at byte 31" by comparing how long each response took. By probing systematically, the attacker can determine the stored hash byte-by-byte and eventually construct a key that produces that hash — forging authentication without knowing the original API key. Timing attacks on network-based systems are admittedly difficult to execute reliably due to network jitter, but for a security product, the correct behavior is mandatory regardless of practical exploit difficulty.

**The Fix:** Always use `crypto/subtle.ConstantTimeCompare` for any secret comparison:
```go
incomingHash := sha256.Sum256([]byte(presentedKey))
if subtle.ConstantTimeCompare(incomingHash[:], storedHash[:]) == 1 {
    // authenticated
}
```
`subtle.ConstantTimeCompare` processes all bytes of both slices every time, regardless of where the first mismatch occurs, emitting no timing signal. It is a one-line requirement that costs a negligible fixed amount of CPU.

**The Lesson:** Constant-time comparison is required for any code path that compares a secret or secret-derived value. The list includes: API key hashes, HMAC signatures (prefer `hmac.Equal` which uses `subtle.ConstantTimeCompare` internally), password hashes (handled by argon2id library, but the same principle applies), and CSRF tokens. The "hard to exploit over a network" argument is not a reason to skip it — it is a reason to use the secure implementation and not think about it again.

---

## AUTH-11: OIDC/OAuth Identity Matched by Email — Account Takeover via Email Recycling

**The Flaw:** The OAuth callback handler looked up existing identities in `user_identities` using the email address returned by the provider: `WHERE provider = $1 AND email = $2`.

**Why It Matters:** Email addresses are mutable and recyclable. When a user changes their email address at the provider (name change, corporate rebrand, company acquisition), the next login presents the new email. The lookup finds no match -> a new account is created -> the user loses all their watchlists, alert rules, API keys, and org memberships — they appear as a stranger to their own org. This is the benign failure mode. The critical failure mode: the old email address is released by the identity provider (common when companies dissolve or employees leave) and claimed by a different person. That person logs in via Google or GitHub -> the `email` lookup matches the original user's `user_identities` row -> the new person inherits the original user's CVErt Ops account, org membership, and all API keys. This is a complete account takeover via email recycling, requiring no exploit — just a standard OAuth flow.

**The Fix:** Identity matching MUST use the provider's immutable identifier:
- **Google OIDC:** `WHERE provider = 'google' AND provider_user_id = $sub` — the `sub` claim is an immutable numeric string unique to the Google Account, never reused even if the email changes.
- **GitHub OAuth:** `WHERE provider = 'github' AND provider_user_id = $github_numeric_id` — the numeric `id` from `GET /user` is immutable; username (`login`) and email are mutable.
- **Email update only:** After matching, `UPDATE user_identities SET email = $new_email WHERE provider = $p AND provider_user_id = $id` to keep display email current. Email is never used to find or link an identity.
- **`(provider, provider_user_id)` is the composite unique key** on `user_identities`, not `(provider, email)`.

**The Lesson:** In federated identity, "the user's email" is a display attribute — not an identity. Every OIDC-compliant provider exposes an immutable `sub` claim specifically for this purpose. GitHub exposes an immutable numeric user ID. Always anchor identity to the provider's immutable identifier. Email is mutable, recyclable, and therefore useless as an identity key in any security-sensitive system.

---

## AUTH-12: `bypassTx` / `workerTx` Called from API Handler — RLS Bypass from User-Controlled Request

**The Flaw:** The dry-run evaluation path reused `bypassTx` (the worker transaction helper) because the evaluator needed to read org-scoped tables. This appeared correct — it let the query see rows — without noticing that `bypassTx` sets `SET LOCAL app.bypass_rls = 'on'`.

**Why It Matters:** `bypassTx` is architecturally designated as worker-only. Calling it from an HTTP handler makes the handler's database queries bypass Row Level Security, running as if they have cross-tenant read access. If the alert rule ID in the URL belongs to a different org, the query succeeds and returns that org's data. The RBAC middleware checks that the authenticated user belongs to the org in the URL — but if the evaluator runs a `bypassTx`, it ignores `app.org_id` and can read rules from any org. This is a tenant isolation violation disguised as a query correctness fix.

The failure mode is subtle: `bypassTx` works correctly in worker paths (no org context, intentionally cross-tenant). In an API handler, it appears to work — the query returns data — but it silently bypasses the second layer of defense.

**The Fix:** API handlers that need to evaluate rules must use a different transaction:
- **Standard org-scoped queries:** `withOrgTx` — sets `app.org_id = $orgID`, RLS enforced
- **Read-only evaluation (dry-run):** `readTx` — opens `sql.TxOptions{ReadOnly: true}`, always defers ROLLBACK, never sets `bypass_rls`
- **`bypassTx` / `workerTx`:** ONLY in background worker goroutines, NEVER in HTTP handler call stacks

```go
// readTx — safe for API dry-run and read-only evaluation paths.
func (e *Evaluator) readTx(ctx context.Context, fn func(*sql.Tx) error) error {
    tx, err := e.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
    if err != nil {
        return fmt.Errorf("begin read tx: %w", err)
    }
    defer tx.Rollback() //nolint:errcheck
    return fn(tx)
}
```

The `readTx` helper intentionally omits `SET LOCAL app.org_id` — the RLS policy on org-scoped tables requires `app.org_id` to be set, so org-scoped queries return 0 rows (fail-closed) unless the caller has gone through `withOrgTx`. For evaluator reads that access global CVE tables (which have no RLS), `readTx` is sufficient.

**The Lesson:** Worker transaction helpers that bypass RLS are a high-blast-radius footgun when called from HTTP handlers. Name them to make the restriction obvious (`workerTx`, `bypassTx`), and add a grep-based linter rule or code comment that documents they must never appear in the `internal/api/` call stack. When an evaluation function requires database access, ask: "which transaction helper is safe here?" and default to the most restricted option.

---

## AUTH-13: JWT_SECRET Missing Must Fatal — Never Auto-Generate

If `JWT_SECRET` is missing or shorter than 32 bytes at startup, the server must `log.Fatalf` immediately. Auto-generating an ephemeral key means every restart invalidates all sessions, and a multi-instance deployment issues tokens that other instances cannot verify. Validate length and presence in `validateConfig`, not lazily on first use.

---

## AUTH-14: OAuth `redirect_uri` Built from Host Header — SSRF via Header Injection

**The Flaw:** The OAuth callback URL was constructed from `r.Host` or `r.Header.Get("Host")`: `redirectURI := fmt.Sprintf("https://%s/auth/callback", r.Host)`.

**Why It Matters:** The `Host` header is attacker-controlled. A request with `Host: evil.com` causes the OAuth flow to redirect the authorization code to `https://evil.com/auth/callback`. The attacker receives the valid authorization code, exchanges it for an access token at the real provider, and completes login as the victim. This is a critical SSRF/open-redirect that requires no authentication — anyone who can reach the login endpoint can exploit it.

**The Fix:** Use an `EXTERNAL_URL` environment variable set at deployment, never derive callback URLs from the request:
```go
redirectURI := fmt.Sprintf("%s/auth/%s/callback", cfg.ExternalURL, provider)
```
`EXTERNAL_URL` is validated at startup (must be a valid URL, must use HTTPS in production). The `Host` header is never read for URL construction in any auth flow.

**The Lesson:** Any URL derived from a request header (`Host`, `X-Forwarded-Host`, `Origin`) is attacker-controlled. OAuth callback URLs, password reset links, and email verification links must all use a server-configured base URL. This is not defense-in-depth — it is the primary defense.

---

## AUTH-15: OAuth State Cookie Must Be SameSite=Lax, Not Strict

The OAuth state cookie must use `SameSite=Lax`. `SameSite=Strict` prevents the browser from sending the cookie on the cross-site redirect back from the OAuth provider, causing every OAuth login to fail with a state mismatch. `Lax` allows the cookie on top-level navigations (which is what the OAuth redirect is) while still blocking cross-site POST requests.

---

## AUTH-16: OIDC Nonce Must Be Manually Verified

`coreos/go-oidc/v3` does not automatically verify the `nonce` claim in ID tokens. After calling `oidcVerifier.Verify()`, the application must manually compare the `nonce` claim from the ID token against the nonce stored in the session cookie. Without this check, an attacker can replay a captured ID token from a different session.

---

## AUTH-17: Webhook Redirect SSRF Bypass — `safeurl` Does Not Validate Redirects

**The Flaw:** The `doyensec/safeurl` client validates the initial webhook URL against SSRF deny lists (private IPs, link-local, cloud metadata endpoints), but Go's default `http.Client` follows up to 10 HTTP redirects automatically. Redirect targets are not re-validated.

**Why It Matters:** An attacker configures a webhook URL pointing to `https://attacker.com/redirect` which returns `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The initial URL passes `safeurl` validation. The redirect silently fetches cloud provider instance metadata, potentially exposing IAM credentials, API keys, and other secrets. The webhook response body (containing the metadata) may be logged or returned in delivery status. This bypasses every SSRF protection that only validates the initial URL.

**The Fix:** Disable redirect following entirely on the webhook HTTP client:
```go
client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse
}
```
`http.ErrUseLastResponse` causes `client.Do()` to return the redirect response without following it. The delivery worker records the 3xx status as a delivery failure. Webhook consumers that legitimately use redirects must update their endpoint URL — the security product must not follow redirects on outbound webhooks.

**The Lesson:** SSRF protection that validates only the initial URL is incomplete. Go's `http.Client` follows redirects by default, and each redirect target is a fresh SSRF opportunity. For any outbound HTTP call where the URL is user-configured (webhooks, callback URLs, integration endpoints), redirect following must be explicitly disabled. This is a defense-in-depth layer on top of `safeurl`, not a replacement for it.

---

## AUTH-18: Webhook Signing Secret Rotation Requires Grace Period

Webhook signing secrets must support rotation without a delivery gap. Add a `signing_secret_secondary` column to `notification_channels`. The `POST .../rotate-secret` endpoint generates a new secret, moves the current secret to `signing_secret_secondary`, and sets the new secret as primary. During the 24-hour grace period, deliveries sign with the primary secret and consumers can verify against either. After 24 hours, the secondary is NULLed. Without this, rotating a secret causes all in-flight deliveries to fail verification.

---

## AUTH-19: COOKIE_SECURE Must Not Be Hardcoded True

`COOKIE_SECURE` must be configurable via environment variable, defaulting to `true`. Hardcoding `Secure: true` on auth cookies breaks localhost development — browsers refuse to send `Secure` cookies over plain HTTP. At startup, if `COOKIE_SECURE=false` and `EXTERNAL_URL` starts with `https://` and `APP_ENV != development`, `validateConfig` must return an error. This prevents accidental insecure cookie configuration in production while allowing local development without TLS.

---

## AUTH-20: API Keys Must Only Be Accepted via Authorization Header

API keys must only be accepted in the `Authorization: Bearer <key>` header, never in query string parameters. Query strings are logged by proxies, CDNs, load balancers, browser history, and server access logs — all of which become credential exposure vectors. The middleware must explicitly reject requests containing `?api_key=`, `?token=`, `?key=`, or `?access_token=` with a `400 Bad Request` explaining that credentials must be sent in the Authorization header.

**Implementation note:** The current middleware ignores query parameters (safe — keys are not accepted from query strings), but does not actively reject requests that attempt to pass credentials via query string. This is a defense-in-depth gap: clients that mistakenly put keys in query strings will get authentication failures but no clear error message telling them why, and the key will already be logged by upstream infrastructure.

---

## AUTH-21: Security Configuration Defaults Must Match Documentation

**The Flaw:** Two health review findings exposed configuration defaults that contradicted the project's security documentation:
- `REGISTRATION_MODE` defaulted to `"open"` in code, while CLAUDE.md, PLAN.md, and README all documented `"invite-only"` as the default
- `COOKIE_SECURE` defaulted to `false` with no validation that it was `true` in production HTTPS deployments

**Why It Matters:** Operators who rely on documented defaults (or who omit env vars assuming safe defaults) deploy with weaker security than they expect. `REGISTRATION_MODE=open` allows unrestricted public signup on a security product. `COOKIE_SECURE=false` with HTTPS sends auth cookies over unencrypted connections if any HTTP path exists. These are not edge cases — they are the default behavior for every deployment that doesn't explicitly override them.

**The Fix:** For any configuration value that affects security behavior:

1. **The code default MUST match the documented default.** If docs say `invite-only`, the `envDefault` tag MUST say `"invite-only"`. Grep for the env var name across all documentation when setting defaults.
2. **Dangerous defaults MUST be validated at startup.** If `COOKIE_SECURE=false` and `EXTERNAL_URL` starts with `https://` and `APP_ENV != development`, `validateConfig` MUST return an error.
3. **`.env.example` MUST show the production-safe value**, with a comment explaining the dev override:
   ```env
   REGISTRATION_MODE=invite-only  # set to "open" only for local development
   COOKIE_SECURE=true             # set to false only for localhost without TLS
   ```

**When to check:** When adding any new configuration value that affects authentication, authorization, encryption, or tenant isolation. When changing a default value. When writing documentation that references a default.

**The Lesson:** Configuration defaults are the security posture of every deployment that doesn't override them — which is most deployments. A secure-by-default configuration is not optional for a security product. When documentation says one thing and code does another, the code wins — and the operator loses.

---

## AUTH-22: In-Memory Security State Maps Grow Without Bound and Lose State on Restart

**The Flaw:** The in-memory rate limiter / lockout tracker was specified as a `sync.Map[string]*rate.Limiter` keyed by IP address or email. No eviction mechanism was specified, keys were not normalized, and state was not persisted.

**Why It Matters:** Three independent failure modes compound:

1. **Unbounded growth:** Each unique client IP or email that ever touches the API produces one map entry (~200 bytes). A public API receiving 10,000 unique IPs per day accumulates 3.65 million entries per year (~730 MB of heap). On a homelab server with 1-2 GB RAM, this OOM-kills the process after months of operation. The OOM crash is attributed to "memory leak" with no obvious connection to the rate limiter because the growth is slow and the allocation is tiny per entry.

2. **Key normalization bypass:** Email-keyed security state (account lockout counters, password reset rate limits) can be bypassed via case variation. `victim@example.com` and `Victim@Example.com` are different map keys, each with their own counter. An attacker gets N attempts per case variation instead of N total.

3. **State lost on restart:** In-memory lockout state does not survive process restart. An attacker who triggers lockout can simply wait for the next deployment (or force a crash via AUTH-4) and retry immediately. For rate limiting this is acceptable; for security-critical lockout (brute force protection), it is not.

**The Fix:**
- **Eviction:** Use `github.com/hashicorp/golang-lru/v2/expirable` with a TTL (default 15 minutes via `RATE_LIMIT_EVICT_TTL` env var). TTL must be longer than the token refill window. Alternative: explicit background sweeper goroutine deleting entries idle beyond the TTL.
- **Key normalization:** `strings.ToLower(email)` before any map lookup on email-keyed state. IP addresses are already case-insensitive (IPv6 hex digits normalized by `net.ParseIP`).
- **Persistence for lockout:** Security-critical lockout state (failed login counters, account disabled flags) must be stored in the database, not just in-memory. Rate limiting can remain in-memory with TTL eviction — it is a performance optimization, not a security control.

**The Lesson:** Any in-memory cache without eviction is a memory leak with a very slow drip. For any map keyed by unbounded external input (IP addresses, user agents, emails), eviction is a correctness requirement for long-running processes. When the cache serves a security purpose (lockout), the state must survive restarts and the keys must be normalized to prevent bypass via trivial variations.

---

## AUTH-23: One-Time Tokens Must Be Consumed Atomically

**The Flaw:** Password reset tokens and invitation accepts are consumed non-atomically: read token -> perform action -> mark used, across separate transactions. Concurrent requests both pass the read gate.

**Why It Matters:** Two concurrent password resets with the same token both pass the "is this token valid?" check. Each proceeds to set a different password. The final password is non-deterministic — whichever transaction commits last wins. The user may be locked out with no indication of which password is active. For invitation accepts: two concurrent requests to accept the same invitation both pass the "is this invitation pending?" check. The second hits a unique constraint violation and returns 500 instead of an idempotent 200.

**The Fix:** `SELECT FOR UPDATE` to lock the token row, then perform the action and mark used in the same transaction. For idempotent operations, use `INSERT ... ON CONFLICT DO NOTHING`:

```go
// In a single transaction:
// 1. Lock the token row
row := tx.QueryRow("SELECT user_id, used_at FROM password_reset_tokens WHERE token_hash = $1 FOR UPDATE", tokenHash)
// 2. Check if already used
if usedAt.Valid {
    return ErrTokenAlreadyUsed
}
// 3. Perform the action (update password)
_, err = tx.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", newHash, userID)
// 4. Mark token as used
_, err = tx.Exec("UPDATE password_reset_tokens SET used_at = now() WHERE token_hash = $1", tokenHash)
// 5. Commit
```

**The Lesson:** One-time-use tokens MUST be marked consumed in the same transaction as the action they authorize. A check-then-act pattern across transactions is never atomic. The gap between "check" and "act" is a race condition window whose width is the network round-trip plus the action's execution time — easily exploitable with concurrent requests.

---

## AUTH-24: Security-Critical Code Must Not Be Copy-Pasted

**The Flaw:** JWT parsing logic — specifically the dual-key rotation flow (try active key -> check `ErrTokenSignatureInvalid` -> retry with previous key) — was copy-pasted across four `Parse` functions: `ParseAccessToken`, `ParseRefreshToken`, `ParsePasswordResetToken`, `ParseEmailVerificationToken`.

**Why It Matters:** A security fix applied to 3 of 4 instances creates an authentication bypass in the fourth. This is not hypothetical — code review fatigue across near-identical functions is a documented cause of security vulnerabilities. The more copies exist, the higher the probability that a future fix misses one. In this case, the consequence of a missed fix is that an attacker can forge one class of token (e.g., password reset tokens) while the other three are correctly protected.

**The Fix:** Extract a generic `parseToken[T jwt.Claims]` helper that encapsulates the dual-key rotation, algorithm whitelisting, and expiration requirement. Each public `Parse` function becomes a one-liner:

```go
func parseToken[T jwt.Claims](tokenString string, claims T, activeKey, previousKey []byte) (T, error) {
    token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc(activeKey),
        jwt.WithValidMethods([]string{"HS256"}),
        jwt.WithExpirationRequired(),
    )
    if err != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) && len(previousKey) > 0 {
        token, err = jwt.ParseWithClaims(tokenString, claims, keyFunc(previousKey),
            jwt.WithValidMethods([]string{"HS256"}),
            jwt.WithExpirationRequired(),
        )
    }
    // ...
}

func ParseAccessToken(tokenString string, keys KeyPair) (*AccessClaims, error) {
    return parseToken(tokenString, &AccessClaims{}, keys.Active, keys.Previous)
}
```

**The Lesson:** Security-critical logic MUST use shared helpers. If you find yourself copying auth, crypto, or validation code, stop and extract. The risk is not code quality — it is a security incident from a missed update. One function, one fix, one audit surface.

---

## AUTH-25: Enumeration-Safe Endpoints Must Audit Every Error Path

**The Flaw:** `forgotPasswordHandler` returns `200 OK` for unknown email addresses (correct anti-enumeration behavior), but returns `500 Internal Server Error` on database errors in user-specific queries (`CountRecentPasswordResetTokens`, `CreatePasswordResetToken`). These queries only execute when the email matches an existing user.

**Why It Matters:** An attacker sends two requests: one with `unknown@example.com` (gets 200), one with `victim@example.com` (gets 200 normally, but gets 500 if the DB has a transient error, or if the token table has a constraint violation). The attacker observing 500 vs 200 infers that `victim@example.com` exists in the system. A single conditional error path leaks the entire anti-enumeration guarantee. The guarantee is only as strong as the weakest error path.

**The Fix:** Return `200 OK` for ALL errors in the forgot-password flow. Log the actual error server-side at ERROR level for debugging, but never expose it to the client:

```go
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
    // ... parse email ...
    user, err := store.GetUserByEmail(ctx, email)
    if err != nil || user == nil {
        // Unknown email or DB error — return 200 either way
        respondSuccess(w)
        return
    }
    if err := store.CreatePasswordResetToken(ctx, user.ID); err != nil {
        // DB error on a user-specific query — still return 200
        slog.ErrorContext(ctx, "failed to create reset token", "err", err, "user_id", user.ID)
        respondSuccess(w)
        return
    }
    // ... send email ...
    respondSuccess(w)
}
```

**The Lesson:** In enumeration-safe endpoints, audit every error path for existence-conditioning. If any error can only occur for existing users, it leaks the guarantee. The fix is uniform: return the same response regardless of the error's cause. A single conditional error leaks the entire anti-enumeration design.

---

## Review Checklist

Use this checklist when implementing or reviewing authentication and security code:

- [ ] **JWT parsing:** Every `jwt.ParseWithClaims` call includes `jwt.WithValidMethods([]string{"HS256"})` and `jwt.WithExpirationRequired()`
- [ ] **API keys:** Opaque format (`cvo_` prefix), only `sha256(key)` stored, comparison via `subtle.ConstantTimeCompare`
- [ ] **OAuth state:** 32 random bytes, stored in `HttpOnly` + `SameSite=Lax` cookie, validated in callback, deleted after use
- [ ] **OIDC nonce:** Manually verified against cookie value after `oidcVerifier.Verify()` — `go-oidc` does not auto-verify
- [ ] **Argon2 semaphore:** Non-blocking (`select/default`), defers release, returns 503 on capacity
- [ ] **One-time tokens:** Consumed (`SELECT FOR UPDATE` + mark used) in the same transaction as the authorized action
- [ ] **Enumeration-safe endpoints:** Every error path returns the same status — no conditional 500s that leak user existence
- [ ] **Security code deduplication:** Auth/crypto/validation logic lives in shared helpers, never copy-pasted across functions
- [ ] **In-memory security state:** TTL-based eviction, keys normalized (`strings.ToLower` for emails), lockout state persisted to DB
- [ ] **Webhook signatures:** HMAC includes timestamp; consumer rejects `abs(now - timestamp) > 300s`
- [ ] **Webhook client:** Redirect following disabled (`CheckRedirect` returns `http.ErrUseLastResponse`)
- [ ] **OAuth redirect URIs:** Built from `EXTERNAL_URL` env var, never from `r.Host` or request headers
- [ ] **Identity matching:** Uses provider's immutable ID (`sub`, numeric `id`), never email
- [ ] **Transaction helpers:** `bypassTx` / `workerTx` never called from HTTP handler call stacks
- [ ] **Config defaults:** Code defaults match documentation; dangerous defaults validated at startup

---

### See Also
- Security enforcement test patterns: see testing-pitfalls.md Section 11
- Webhook SSRF in delivery path: see NOTIFY-X (Webhook Tarpitting)
- HTTP server timeouts (Slowloris): see API-3
