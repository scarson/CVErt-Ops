# Bug Hunt Report — Phase 6A Security Hardening (Multi-Pass)

## Scope
Files analyzed (source only — no tests):
- `internal/api/auth_password_reset.go`
- `internal/api/auth_email_verification.go`
- `internal/api/lockout.go`
- `internal/api/cors.go`
- `internal/api/auth.go`
- `internal/api/server.go`
- `internal/store/password_reset.go`
- `internal/store/email_verification.go`
- `internal/store/auth.go` (UpdatePasswordHash)
- `internal/config/config.go`
- `internal/notify/render.go`
- `internal/store/queries/password_reset.sql`
- `internal/store/queries/email_verification.sql`
- `internal/store/queries/auth.sql` (UpdatePasswordHash query)
- `web/src/views/ForgotPasswordView.vue`
- `web/src/views/ResetPasswordView.vue`
- `web/src/views/VerifyEmailView.vue`
- `web/src/stores/auth.ts`

All five passes performed.

## Bugs

### 1. Lockout map grows unbounded — memory exhaustion DoS
**Location:** `internal/api/lockout.go:20-21` (the `attempts` map)
**Severity:** significant
**Evidence:** The `lockoutManager.attempts` map only has two deletion paths: `RecordSuccess` (line 83, on successful login) and `Check` (line 57, when lockout expires AND the same email is checked again). There is no background sweep or eviction. An attacker sending login attempts for millions of unique, non-existent email addresses creates one `loginAttempt` entry per email. These entries are never cleaned up because:
1. Non-existent users never trigger `RecordSuccess`
2. `Check` only deletes entries when called for the same email after expiry — an attacker who never retries the same email leaves entries permanently

The IP rate limiter (10/min) provides some mitigation, but a distributed attack or slow-rate attack over time can still accumulate entries without bound.
**Impact:** Server memory exhaustion, leading to OOM kill. A single attacker at 10 req/min accumulates ~14,400 entries/day. A botnet amplifies this by orders of magnitude.
**Found in:** Pass 3 — Failure Mode Reasoning

---

### 2. TOCTOU race in resetPasswordHandler — concurrent token use
**Location:** `internal/api/auth_password_reset.go:176-207`
**Severity:** significant
**Evidence:** The handler performs three non-atomic steps:
1. `GetPasswordResetTokenByHash` (line 176) — reads token, checks `used_at IS NULL`
2. `UpdatePasswordHash` (line 197) — changes password, increments `token_version`
3. `MarkPasswordResetTokenUsed` (line 203) — sets `used_at`

Between steps 1 and 3, a concurrent request with the same token passes the `used_at IS NULL` check in the SQL query (line 11 of `password_reset.sql`). Both requests proceed to change the password and increment `token_version`. If both requests carry different `new_password` values (e.g., due to UI double-submit with latency), the final password is non-deterministic and `token_version` is incremented twice.

The fix is to use `SELECT ... FOR UPDATE` in `GetPasswordResetTokenByHash`, or combine the read + mark-used into a single `UPDATE ... WHERE used_at IS NULL RETURNING ...` statement.
**Impact:** Non-deterministic password after concurrent reset submissions; `token_version` double-incremented invalidates the freshly-issued session from the first request's login. Low practical likelihood (single user, single token), but this is security-critical code where correctness matters.
**Found in:** Pass 4 — Concurrency Reasoning

---

### 3. Missing `defer` on argon2 semaphore release in resetPasswordHandler
**Location:** `internal/api/auth_password_reset.go:186-190`
**Severity:** minor
**Evidence:** The resetPasswordHandler acquires the argon2 semaphore (line 186) and releases it explicitly (line 190):
```go
if !srv.acquireArgon2() {
    return nil, huma.Error503ServiceUnavailable("server busy, please retry")
}
newHash, err := auth.HashPassword(input.Body.NewPassword)
srv.releaseArgon2()
```
Compare to `registerHandler` (auth.go:134-137) which uses `defer`:
```go
if !srv.acquireArgon2() {
    return nil, huma.Error503ServiceUnavailable("server busy, please retry")
}
defer srv.releaseArgon2()
```
If `auth.HashPassword` panics, the semaphore slot leaks permanently. The same non-defer pattern appears in `loginHandler` (auth.go:243-247, 252-256) and `changePasswordHandler` (auth.go:532-536, 546-550).
**Impact:** On panic in `HashPassword` or `VerifyPassword`, one argon2 semaphore slot leaks. After `Argon2MaxConcurrent` panics (default 5), all subsequent password operations return 503. Requires server restart to recover. Panics are rare but the fix is trivial (`defer`).
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### 4. resendVerificationHandler claims "email sent" when sending failed
**Location:** `internal/api/auth_email_verification.go:119-126`
**Severity:** minor
**Evidence:** When `sendVerificationEmail` returns an error (SMTP down, render failure, etc.), the handler logs it but returns:
```go
return &resendVerificationOutput{Body: struct {
    Message string `json:"message"`
}{Message: "Verification email sent."}}, nil
```
The response claims "Verification email sent" when the email was NOT sent. The comment says "Non-fatal — return success to avoid leaking internal state" but the response message is factually incorrect.
**Impact:** User waits for an email that was never sent, with no indication of failure. Unlike `forgotPasswordHandler` (which uses a deliberately ambiguous message to prevent enumeration), `resendVerificationHandler` is authenticated — the server already knows who the user is, so there's no enumeration risk. The handler could return a generic error instead.
**Found in:** Pass 1 — Contract Violations

---

### 5. UpdatePasswordHash bypasses transaction helpers
**Location:** `internal/store/auth.go:87-96`
**Severity:** minor
**Evidence:** `UpdatePasswordHash` uses `s.q.UpdatePasswordHash(ctx, ...)` — querying through the non-transactional queries object. All sibling store methods in `password_reset.go` and `email_verification.go` use `s.withBypassTx(ctx, func(q *generated.Queries) error { ... })`. The codebase convention (CLAUDE.md) states: "Never query `s.db` directly in store methods — always use a transaction helper" and "use `withBypassTx` even if target table has no RLS."

`s.q` is bound to `s.db` (the pool), so this effectively queries outside any transaction helper.
**Impact:** If RLS policies are ever added to the `users` table, this method would fail because `app.bypass_rls` is never set. Currently functional because `users` has no RLS, but violates the project's defensive convention.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### 6. Concurrent forgot-password bypasses per-user rate limit
**Location:** `internal/api/auth_password_reset.go:93-100`
**Severity:** minor
**Evidence:** The per-user rate limit check is:
```go
count, err := srv.store.CountRecentPasswordResetTokens(ctx, user.ID, time.Now().Add(-1*time.Hour))
// ...
if int(count) >= srv.cfg.PasswordResetMaxPerHour {
    return out, nil
}
// ... later:
srv.store.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt)
```
The count check and token creation are not atomic. N concurrent requests arriving simultaneously all see `count < max` and all create tokens, resulting in N tokens when the limit is `PasswordResetMaxPerHour` (default 3). Subsequent requests are properly rate-limited.
**Impact:** A burst of concurrent requests can exceed the per-user rate limit by up to the concurrency factor. The IP rate limiter (10/min) bounds this. Low practical impact since all tokens go to the same legitimate email.
**Found in:** Pass 4 — Concurrency Reasoning

## Design Concerns

### Orphaned tokens on email delivery failure
`sendVerificationEmail` (auth_email_verification.go:131-170) creates a token in the DB before attempting email delivery. If email delivery fails (SMTP down, render error), the token remains in the DB unused until expiry cleanup. Similarly, `forgotPasswordHandler` creates the token before async email delivery. While not harmful (tokens expire), each failure leaves a row that counts against the per-user rate limit in the password reset case — meaning SMTP outages can silently consume a user's rate limit quota.

### Asymmetric email delivery patterns
Password reset emails are sent asynchronously (goroutine with `context.WithoutCancel`), which correctly normalizes response timing. Verification emails in `sendVerificationEmail` are sent synchronously, blocking the HTTP response. During registration (auth.go:186), this means SMTP latency directly affects registration response time. While this doesn't leak user existence (registration returns 409 for duplicates before reaching email sending), it creates inconsistent response time characteristics across the auth endpoints.

### TOCTOU in verifyEmailHandler (benign)
`verifyEmailHandler` has the same read-then-mark-used pattern as `resetPasswordHandler` (auth_email_verification.go:50-69). Concurrent requests with the same token can both verify the email. Since `SET email_verified = true` is idempotent and no `token_version` is involved, this is functionally harmless but worth noting for consistency.
