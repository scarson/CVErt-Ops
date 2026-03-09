# Bug Hunt Report — Phase 6A (Holistic)

## Scope

All Phase 6A production source files: password reset flow (handler, store, SQL, templates, migration), email verification flow (handler, store, SQL, templates, migration), account lockout manager, CORS middleware, login handler lockout integration, server route registration, frontend views (ForgotPassword, ResetPassword, VerifyEmail), auth store, and router config.

Approach: read every source file into context, then reason about cross-cutting correctness — token lifecycle, race conditions, brute-force resistance, and information leakage.

## Bugs

### 1. Lockout manager bypassed via email case variation

**Location:** internal/api/lockout.go:43, internal/api/auth.go:224,248,262
**Severity:** significant
**Evidence:** The lockout manager uses the raw `email` string from the request body as the map key:

```go
// lockout.go:43
a, ok := m.attempts[email]
```

```go
// auth.go:224 — Check uses input.Body.Email as-is
allowed, retryAfter := srv.lockout.Check(input.Body.Email)
// auth.go:248/262 — RecordFailure uses same raw email
srv.lockout.RecordFailure(input.Body.Email)
```

The DB lookup (`GetUserByEmail`) uses `WHERE email = $1` against a plain `text` column with no `LOWER()` or `citext`. However, email addresses are semantically case-insensitive in the domain part (RFC 5321) and conventionally in the local part.

An attacker can submit 5 failed logins with `victim@example.com`, then 5 more with `Victim@example.com`, then `VICTIM@example.com`, etc. Each casing gets its own lockout counter. If emails are stored lowercased in the DB, the case variations would miss the user lookup (returning "invalid credentials" via the dummy-hash path), so the actual brute-force window is limited. But if any email was stored with mixed case, or if a `LOWER()` lookup is ever added, this becomes a full lockout bypass.

**Impact:** The lockout mechanism provides weaker protection than intended. Whether it's exploitable today depends on whether the DB stores emails case-folded — but the lockout manager should normalize independently regardless.

### 2. Password reset token consumed non-atomically — concurrent use possible

**Location:** internal/api/auth_password_reset.go:176,197,203
**Severity:** minor
**Evidence:** `resetPasswordHandler` performs three operations in separate transactions:

1. `GetPasswordResetTokenByHash` — reads token (line 176, in its own `withBypassTx`)
2. `UpdatePasswordHash` — changes password and increments `token_version` (line 197, in its own `withBypassTx`)
3. `MarkPasswordResetTokenUsed` — marks token consumed (line 203, in its own `withBypassTx`)

Two concurrent requests with the same valid token can both pass step 1 (token is still `used_at IS NULL`), both compute an argon2 hash, and both execute step 2. The `token_version` gets incremented twice (N→N+2), and whichever `UpdatePasswordHash` executes last determines the actual password.

The code comment at line 205-207 acknowledges the non-atomicity of step 3 but frames it as "safe because token_version was incremented." The actual risk is in steps 1+2 being non-atomic — two different passwords could be set and the user wouldn't know which one won.

**Impact:** In practice, exploitability requires the attacker to possess the reset token (sent via email) AND race the legitimate user. Low practical risk, but the design is fragile. A `SELECT ... FOR UPDATE` or marking the token used within the same transaction as the password update would eliminate the race.

### 3. No per-user rate limit on email verification resend

**Location:** internal/api/auth_email_verification.go:92-127
**Severity:** minor
**Evidence:** `resendVerificationHandler` calls `checkAuthRateLimit` (IP-based) but has no per-user throttle equivalent to the password reset flow's `CountRecentPasswordResetTokens` check (auth_password_reset.go:93-100).

An authenticated user (or anyone with a valid access token) can call `POST /auth/resend-verification` repeatedly. Each call creates a new token row and triggers a synchronous SMTP send.

Compare with `forgotPasswordHandler`:
```go
// auth_password_reset.go:93-100
count, err := srv.store.CountRecentPasswordResetTokens(ctx, user.ID, ...)
if int(count) >= srv.cfg.PasswordResetMaxPerHour {
    return out, nil
}
```

No equivalent exists for email verification.

**Impact:** An attacker with a valid session could abuse this to send many emails to their own address (mail-bombing) and create unnecessary DB rows. Mitigated by IP rate limiting (10 req/min), but the per-user gap is inconsistent with the password reset pattern.

## Design Concerns

### Lockout map unbounded growth

**Location:** internal/api/lockout.go:20 (`attempts map[string]*loginAttempt`)

The lockout manager's map grows without bound. Entries are only removed on: (a) successful login (`RecordSuccess` → `delete`), or (b) expired lockout checked again (`Check` → `delete`). Failed logins for non-existent email addresses create entries that are never cleaned up via path (a), and path (b) only fires if someone queries that exact email again after lockout expiry.

An attacker sending login attempts for random email addresses at the IP rate limit (10/min) accumulates ~14,400 orphaned entries per day. Each entry is small (~100 bytes), so this isn't an immediate OOM risk, but there's no upper bound or periodic sweep. A background cleanup goroutine (e.g., every 15 minutes, delete entries where `lockedAt + duration < now`) would be a simple fix.

### Verification email sent synchronously in resend path

**Location:** internal/api/auth_email_verification.go:119 → `sendVerificationEmail` → `notify.EmailSend`

Unlike `forgotPasswordHandler` which sends email asynchronously in a goroutine (auth_password_reset.go:122-144), `sendVerificationEmail` performs synchronous SMTP. This means `resendVerificationHandler` blocks on SMTP delivery. Since this endpoint requires authentication and the user already knows their own verification status, there's no timing-oracle risk. But a slow or unreachable SMTP server will cause the endpoint to hang until the SMTP timeout, potentially tying up a server goroutine.

### Password reset and verification share no token-invalidation-on-use coordination

Both token types (password reset, email verification) follow the same pattern: read → act → mark used, with "mark used" being non-fatal. This means both flows accept the theoretical possibility of token replay within the TTL window if the mark-used step fails. For password reset, the `token_version` increment provides a secondary defense. For email verification, there's no equivalent — `SetEmailVerified` is idempotent (`SET email_verified = true`), so replay is harmless, but the asymmetry suggests these flows were designed independently rather than from a shared security pattern.
