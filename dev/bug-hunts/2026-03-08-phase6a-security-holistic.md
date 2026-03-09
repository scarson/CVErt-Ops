# Bug Hunt Report — Phase 6A Security Hardening (Holistic)

## Scope
Analyzed all Phase 6A security hardening production source files:
- **Backend (Go):** `internal/api/auth_password_reset.go`, `auth_email_verification.go`, `lockout.go`, `cors.go`, `ratelimit.go`, `auth.go` (login handler); `internal/store/password_reset.go`, `email_verification.go`; `internal/store/queries/password_reset.sql`, `email_verification.sql`, `auth.sql`; `internal/config/config.go`; `internal/notify/render.go`
- **Frontend (Vue/TS):** `web/src/views/ForgotPasswordView.vue`, `ResetPasswordView.vue`, `VerifyEmailView.vue`; `web/src/stores/auth.ts`

Read every source file, then traced multi-step flows end-to-end: forgot-password → reset-password, email verification → resend, login with lockout, CORS middleware setup.

## Bugs

### 1. lockoutManager: unbounded memory growth for sub-threshold entries
**Location:** internal/api/lockout.go:66-79
**Severity:** significant
**Evidence:** `RecordFailure` inserts entries into the `attempts` map and increments their count. `Check` only deletes entries when `count >= threshold` and the lockout has expired (line 57). `RecordSuccess` deletes entries on successful login (line 85). But entries where `count < threshold` (e.g., 1-4 failures with default threshold of 5) are **never cleaned up** unless the same email succeeds a login.

An attacker (or normal traffic) spraying login attempts across many unique email addresses — staying below the lockout threshold — grows the map indefinitely. There is no background sweep, TTL, or size limit on the `attempts` map, unlike the `ipRateLimiter` which has `cleanupLoop()` with `evictTTL`.

**Impact:** Slow memory leak over days/weeks. In a long-running server, the map could grow to millions of entries. Each entry is small (~80 bytes for the struct + string key), so this would take sustained traffic to become critical, but it's unbounded.

### 2. resetPasswordHandler: incorrect safety reasoning allows token reuse if mark-used fails
**Location:** internal/api/auth_password_reset.go:203-207
**Severity:** minor
**Evidence:** The comment on line 205-206 reads: *"Worst case: token could be reused (but UpdatePasswordHash incremented token_version, so it's safe)."*

This reasoning is incorrect. `token_version` is checked when validating JWT sessions — it's not referenced by `GetPasswordResetTokenByHash` (see `password_reset.sql:9-11`: `WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`). If `MarkPasswordResetTokenUsed` fails (transient DB error), the token remains valid for reuse via the reset-password endpoint.

The `token_version` increment invalidates existing login sessions, but does **not** prevent a second password reset using the same token. An attacker who captured the token could re-use it within the TTL window to set their own password, even after the legitimate user already used it.

**Impact:** Low probability (requires `MarkPasswordResetTokenUsed` to fail while `UpdatePasswordHash` succeeds — both use `withBypassTx` to the same DB). But the false reasoning could lead to incorrect future decisions. The actual mitigation is the token TTL and the rarity of this partial-failure scenario.

### 3. forgotPasswordHandler: 500 errors from post-lookup queries leak user existence
**Location:** internal/api/auth_password_reset.go:94-97, 112-115
**Severity:** minor
**Evidence:** The handler is designed to always return 200 to prevent email enumeration (line 63-64). The early paths are correct: unknown user → 200, rate-limited user → 200. But two code paths return **500** that can **only be reached for existing users**:

1. `CountRecentPasswordResetTokens` error (line 94-97) — only runs after confirming user exists with a password hash
2. `CreatePasswordResetToken` error (line 112-115) — same

If the DB is intermittently failing on these specific queries, an attacker observing 500 vs 200 can infer user existence. The initial `GetUserByEmail` error at line 77 returns 500 for all emails (no leak), but these later 500s are user-existence-conditional.

**Impact:** Requires the DB to partially fail (serving GetUserByEmail but failing on CountRecentPasswordResetTokens). Very unlikely in practice, but violates the stated anti-enumeration invariant.

## Design Concerns

### CORS: no validation prevents wildcard origin with credentials
**Location:** internal/api/cors.go:20-27
If an operator sets `CORS_ALLOWED_ORIGINS=*`, `go-chi/cors` with `AllowCredentials: true` will reflect the requesting origin in `Access-Control-Allow-Origin`, effectively allowing any website to make credentialed cross-origin API requests. For a security product, consider validating that `*` is not used when `AllowCredentials` is true, or at minimum logging a warning.

### lockoutManager state is not shared across instances or restarts
**Location:** internal/api/lockout.go:18-24
The in-memory lockout map resets on process restart and isn't shared in a multi-instance deployment. An attacker could distribute login attempts across multiple backend instances (if load-balanced) to stay under the per-instance threshold, or simply wait for a deployment to reset all lockout state. This is likely acceptable for the current single-binary architecture but worth documenting for future horizontal scaling.

### Email verification: TOCTOU between token lookup and mark-used
**Location:** internal/api/auth_email_verification.go:50-68
Two concurrent requests with the same verification token can both succeed: both call `GetEmailVerificationTokenByHash` (which checks `used_at IS NULL`) before either marks the token as used. The impact is minimal since `SetEmailVerified` is idempotent (`UPDATE users SET email_verified = true`), but the pattern creates a window where a single-use token is effectively multi-use. The same TOCTOU exists in `resetPasswordHandler` (auth_password_reset.go:176-207), where concurrent use is slightly more concerning since it changes passwords.
