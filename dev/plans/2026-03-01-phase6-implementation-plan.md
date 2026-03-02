# Phase 6: Backend Cleanup & Production Readiness

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close security gaps, add missing specced features, fix RBAC discrepancies, and reconcile PLAN.md with reality — making the backend production-ready.

**Architecture:** Phase 6 addresses findings from a systematic gap analysis (PLAN.md internal scan + API contract completeness audit). Security hardening tasks (password reset, email verification, account lockout, CORS) fill gaps that block production use. Missing specced features (channel test, admin feeds) complete the API contract. PLAN.md reconciliation brings the spec in line with the real implementation.

**Tech Stack:** Go 1.26, chi, huma, sqlc, go-mail (existing), go-chi/cors (new dependency)

**Prerequisites:** Phase 5 must be fully implemented before Phase 6 begins. Migration numbers in this plan use placeholders (`0000XX`) — replace with the next sequential number after Phase 5's last migration.

**Context for subagents:**
- Chi handlers use `http.Error(w, msg, status)` + `return`, NOT huma error returns
- Transaction helpers: `withBypassTx` for operations without org context, `withOrgTx` for handler-context queries
- Integration tests use `testutil.NewTestDB(t)` with testcontainers Postgres
- TDD is mandatory: RED → verify fail → GREEN → verify pass → refactor → commit
- Run `sqlc generate` after any `.sql` file changes, before `go build`
- Run `golangci-lint run` before committing
- All email templates follow the `{{define "subject"}}` / `{{define "body"}}` pattern in `internal/notify/templates/`
- `notify.EmailSend()` (`internal/notify/email.go`) is the shared SMTP sender — use it for transactional emails too

---

## Phase 6A: Security Hardening

### Task 1: Password reset flow

**Files:**
- Create: `migrations/0000XX_create_password_reset_tokens.up.sql` / `.down.sql`
- Create: `internal/store/queries/password_reset.sql`
- Modify: `internal/store/generated/` (sqlc regenerated)
- Create: `internal/store/password_reset.go`
- Create: `internal/store/password_reset_test.go`
- Create: `internal/notify/templates/email_password_reset.html.tmpl`
- Create: `internal/notify/templates/email_password_reset.txt.tmpl`
- Modify: `internal/notify/render.go` — add `RenderPasswordReset` function
- Modify: `internal/config/config.go` — add reset config fields
- Create: `internal/api/auth_password_reset.go` — handlers
- Create: `internal/api/auth_password_reset_test.go` — handler tests
- Modify: `internal/api/server.go` — register routes

**Design decisions:**
- Token: 32-byte `crypto/rand`, hex-encoded (64 chars) — same pattern as org invitations
- Storage: SHA-256 hash in DB, NOT plaintext (password reset tokens grant account access — higher sensitivity than invitation tokens)
- Expiry: 1 hour (configurable via `PASSWORD_RESET_TOKEN_TTL`)
- Rate limit: max 3 reset emails per user per hour (prevents abuse)
- Response: `POST /auth/forgot-password` ALWAYS returns 200 regardless of whether user exists (prevents email enumeration)
- On successful reset: increment `token_version` to invalidate all active sessions
- Token lookup: by hash (constant-time via database index scan, not application comparison)

**Step 1: Write migration**

```sql
-- migrate:no-transaction
-- ABOUTME: Creates password_reset_tokens for secure password recovery flow.
-- ABOUTME: Global table — no RLS (not org-scoped). Tokens stored as SHA-256 hash.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS password_reset_tokens_user_idx
    ON password_reset_tokens (user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS password_reset_tokens_hash_idx
    ON password_reset_tokens (token_hash);

GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens TO cvert_ops_app;
```

Down migration:
```sql
-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS password_reset_tokens_hash_idx;
DROP INDEX CONCURRENTLY IF EXISTS password_reset_tokens_user_idx;
DROP TABLE IF EXISTS password_reset_tokens;
```

Run: `go run ./cmd/cvert-ops migrate`
Expected: Migration applies cleanly.

**Step 2: Write sqlc queries**

Create `internal/store/queries/password_reset.sql`:

```sql
-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: GetPasswordResetTokenByHash :one
SELECT id, user_id, expires_at, used_at, created_at
FROM password_reset_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: MarkPasswordResetTokenUsed :exec
UPDATE password_reset_tokens SET used_at = now() WHERE id = $1;

-- name: CountRecentPasswordResetTokens :one
SELECT COUNT(*) FROM password_reset_tokens
WHERE user_id = $1 AND created_at > $2;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM password_reset_tokens WHERE expires_at < now();
```

Run: `sqlc generate && go build ./...`
Expected: No errors. New files in `internal/store/generated/`.

**Step 3: Write store wrapper methods**

Create `internal/store/password_reset.go` with methods using `withBypassTx` (no org context):

```go
func (s *Store) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error
func (s *Store) GetPasswordResetTokenByHash(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)
func (s *Store) MarkPasswordResetTokenUsed(ctx context.Context, tokenID uuid.UUID) error
func (s *Store) CountRecentPasswordResetTokens(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error)
func (s *Store) DeleteExpiredPasswordResetTokens(ctx context.Context) error
```

**Step 4: Write store integration tests**

Create `internal/store/password_reset_test.go` using `testutil.NewTestDB(t)`:

```go
func TestCreateAndGetPasswordResetToken(t *testing.T)  // create token, retrieve by hash
func TestGetPasswordResetToken_Expired(t *testing.T)    // expired token returns no rows
func TestGetPasswordResetToken_Used(t *testing.T)       // used token returns no rows
func TestMarkPasswordResetTokenUsed(t *testing.T)       // mark used, verify can't retrieve
func TestCountRecentPasswordResetTokens(t *testing.T)   // create 3 tokens, verify count=3
func TestDeleteExpiredPasswordResetTokens(t *testing.T) // create expired tokens, delete, verify gone
```

Test data: create a user via `db.Store` (bypass), then create tokens. Token hash = `sha256.Sum256([]byte("test-token"))`.

Run: `go test ./internal/store/ -run "TestCreateAndGetPasswordResetToken|TestGetPasswordResetToken|TestMarkPasswordResetTokenUsed|TestCountRecentPasswordResetTokens|TestDeleteExpiredPasswordResetTokens" -v`
Expected: All PASS.

**Step 5: Write email templates**

Create `internal/notify/templates/email_password_reset.html.tmpl`:

```html
{{define "subject"}}Reset your CVErt Ops password{{end}}
{{define "body"}}
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a2e;">Password Reset</h2>
  <p>Someone requested a password reset for your CVErt Ops account ({{.Email}}).</p>
  <p><a href="{{.ResetURL}}" style="display: inline-block; padding: 12px 24px; background-color: #1a1a2e; color: #ffffff; text-decoration: none; border-radius: 4px;">Reset Password</a></p>
  <p style="color: #666; font-size: 14px;">This link expires in {{.ExpiresIn}}. If you didn't request this, you can safely ignore this email.</p>
  <p style="color: #999; font-size: 12px;">If the button doesn't work, copy this URL: {{.ResetURL}}</p>
</body>
</html>
{{end}}
```

Create `internal/notify/templates/email_password_reset.txt.tmpl`:

```text
{{define "subject"}}Reset your CVErt Ops password{{end}}
{{define "body"}}
Password Reset
==============

Someone requested a password reset for your CVErt Ops account ({{.Email}}).

Reset your password: {{.ResetURL}}

This link expires in {{.ExpiresIn}}. If you didn't request this, you can safely ignore this email.
{{end}}
```

**Step 6: Add rendering function**

Modify `internal/notify/render.go`:

1. Add template data struct:
```go
type PasswordResetData struct {
    Email     string
    ResetURL  string
    ExpiresIn string // e.g., "1 hour"
}
```

2. Add parsed template variables (in `var` block):
```go
resetHTML  *htmltpl.Template
resetText  *texttpl.Template
```

3. Add to `init()`:
```go
resetHTML = htmltpl.Must(htmltpl.New("").Funcs(htmltpl.FuncMap(funcMap)).ParseFS(templateFS, "templates/email_password_reset.html.tmpl"))
resetText = texttpl.Must(texttpl.New("").Funcs(texttpl.FuncMap(funcMap)).ParseFS(templateFS, "templates/email_password_reset.txt.tmpl"))
```

4. Add render function:
```go
func RenderPasswordReset(data PasswordResetData) (string, string, string, error) {
    return renderPair(resetHTML, resetText, data)
}
```

**Step 7: Add config fields**

Modify `internal/config/config.go` — add below the Auth section:

```go
// ── Auth — Password Reset ────────────────────────────────────────────────
PasswordResetTokenTTL    time.Duration `env:"PASSWORD_RESET_TOKEN_TTL"     envDefault:"1h"`
PasswordResetMaxPerHour  int           `env:"PASSWORD_RESET_MAX_PER_HOUR"  envDefault:"3"`
```

**Step 8: Write failing handler tests**

Create `internal/api/auth_password_reset_test.go` (in `package api` — white-box, same as `auth_test.go`).

Test setup: `db := testutil.NewTestDB(t)` → `srv, ts := newRegisterServer(t, db, "open")` → `doRegister()` to create a user.

```go
func TestForgotPassword_ExistingUser(t *testing.T)
    // POST /api/v1/auth/forgot-password with registered email
    // Expect: 200 (always), token created in DB
    // Verify: password_reset_tokens table has a row for this user

func TestForgotPassword_NonexistentUser(t *testing.T)
    // POST with unknown email
    // Expect: 200 (no enumeration — same response as existing user)
    // Verify: no token created

func TestForgotPassword_RateLimit(t *testing.T)
    // POST 4 times for same email (max is 3/hr)
    // Expect: first 3 return 200, 4th returns 429

func TestResetPassword_ValidToken(t *testing.T)
    // Create user, create token via forgot-password, then POST /auth/reset-password
    // Expect: 200, password changed (verify by logging in with new password)
    // Verify: old sessions invalidated (refresh token no longer works)

func TestResetPassword_ExpiredToken(t *testing.T)
    // Insert token with past expires_at directly in DB
    // Expect: 400

func TestResetPassword_UsedToken(t *testing.T)
    // Use token once (success), try again
    // Expect: 400

func TestResetPassword_InvalidToken(t *testing.T)
    // POST with random token string
    // Expect: 400

func TestResetPassword_WeakPassword(t *testing.T)
    // POST with valid token but password < 16 chars
    // Expect: 400 (same validation as registration)
```

Run: `go test ./internal/api/ -run "TestForgotPassword|TestResetPassword" -v`
Expected: FAIL (handlers don't exist yet).

**Step 9: Implement handlers**

Create `internal/api/auth_password_reset.go`:

`POST /api/v1/auth/forgot-password`:
- Parse `{email: string}` from request body
- Look up user by email (via store) — if not found, return 200 anyway (timing normalization: run a dummy `time.Sleep` matching avg token-creation time)
- Check rate limit: `CountRecentPasswordResetTokens(ctx, userID, time.Now().Add(-1*time.Hour))`
- If over limit: return 429
- Generate 32-byte random token via `crypto/rand`
- Hash with `sha256.Sum256`, store in DB with expiry
- Build reset URL: `cfg.ExternalURL + "/reset-password?token=" + hex.EncodeToString(token)`
- Render email via `notify.RenderPasswordReset`
- Send via `notify.EmailSend` (synchronous — this is a transactional email, user is waiting)
- Return 200 with `{"message": "If an account with that email exists, a password reset link has been sent."}`

`POST /api/v1/auth/reset-password`:
- Parse `{token: string, new_password: string}` from request body
- Validate password (same rules as registration: >= 16 chars)
- Hash token with SHA-256, look up in DB
- If not found / expired / used: return 400
- Hash new password with argon2id (use the semaphore)
- Update user's `password_hash` in DB
- Increment `token_version` (invalidates all sessions)
- Mark token as used
- Return 200

**Step 10: Register routes**

Modify `internal/api/server.go` — register as huma routes alongside existing auth routes in `registerAuthRoutes`:

```go
// Password reset — public, no auth required
huma.Register(api, huma.Operation{
    OperationID: "forgot-password",
    Method:      http.MethodPost,
    Path:        "/api/v1/auth/forgot-password",
}, srv.forgotPasswordHandler)
huma.Register(api, huma.Operation{
    OperationID: "reset-password",
    Method:      http.MethodPost,
    Path:        "/api/v1/auth/reset-password",
}, srv.resetPasswordHandler)
```

**Important:** These are huma routes (like other auth routes), not chi routes. Auth routes use huma because they're public JSON API endpoints. Org-scoped routes use chi for per-route RBAC middleware.

**Step 11: Run tests, verify pass**

Run: `go test ./internal/api/ -run "TestForgotPassword|TestResetPassword" -v`
Expected: All PASS.

Run: `golangci-lint run`
Expected: No new warnings.

**Step 12: Commit**

```bash
git add migrations/0000XX_create_password_reset_tokens.* internal/store/queries/password_reset.sql internal/store/generated/ internal/store/password_reset.go internal/store/password_reset_test.go internal/notify/templates/email_password_reset.* internal/notify/render.go internal/config/config.go internal/api/auth_password_reset.go internal/api/auth_password_reset_test.go internal/api/server.go
git commit -m "feat(auth): password reset flow with rate limiting and session invalidation — TDD"
```

---

### Task 2: Email verification

**Files:**
- Create: `migrations/0000XX_add_email_verified_to_users.up.sql` / `.down.sql`
- Create: `migrations/0000XX_create_email_verification_tokens.up.sql` / `.down.sql`
- Create: `internal/store/queries/email_verification.sql`
- Modify: `internal/store/generated/` (sqlc regenerated)
- Create: `internal/store/email_verification.go`
- Create: `internal/store/email_verification_test.go`
- Create: `internal/notify/templates/email_verification.html.tmpl`
- Create: `internal/notify/templates/email_verification.txt.tmpl`
- Modify: `internal/notify/render.go` — add `RenderEmailVerification` function
- Modify: `internal/config/config.go` — add verification config
- Create: `internal/api/auth_email_verification.go`
- Create: `internal/api/auth_email_verification_test.go`
- Modify: `internal/api/server.go` — register routes
- Modify: `internal/api/auth.go` — send verification email on registration

**Design decisions:**
- Add `email_verified BOOLEAN NOT NULL DEFAULT false` to `users` table
- Invited users are auto-verified: invitation acceptance sets `email_verified = true`
- In `open` registration mode: send verification email automatically on registration
- In `invite-only` mode: verification is irrelevant (all users come through invitations)
- Login is NOT blocked for unverified users — we track the status for future use (e.g., UI warnings, feature gating) but don't enforce it now. Blocking login creates a terrible UX for self-hosted deployments where SMTP may not be configured
- Token: 32-byte random, SHA-256 hash stored (same pattern as password reset)
- Expiry: 24 hours (configurable)

**Step 1: Write migration — add email_verified column**

```sql
-- migrate:no-transaction
-- ABOUTME: Adds email_verified boolean to users table.
-- ABOUTME: Default false — existing users are unverified until they verify.

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
```

Down:
```sql
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
```

**Step 2: Write migration — email_verification_tokens table**

```sql
-- migrate:no-transaction
-- ABOUTME: Creates email_verification_tokens for email ownership verification.
-- ABOUTME: Global table — no RLS. Tokens stored as SHA-256 hash.

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT email_verification_tokens_pkey PRIMARY KEY (id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS email_verification_tokens_user_idx
    ON email_verification_tokens (user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS email_verification_tokens_hash_idx
    ON email_verification_tokens (token_hash);

GRANT SELECT, INSERT, UPDATE, DELETE ON email_verification_tokens TO cvert_ops_app;
```

Down:
```sql
-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS email_verification_tokens_hash_idx;
DROP INDEX CONCURRENTLY IF EXISTS email_verification_tokens_user_idx;
DROP TABLE IF EXISTS email_verification_tokens;
```

Run: `go run ./cmd/cvert-ops migrate`
Expected: Both migrations apply cleanly.

**Step 3: Write sqlc queries**

Create `internal/store/queries/email_verification.sql`:

```sql
-- name: CreateEmailVerificationToken :exec
INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: GetEmailVerificationTokenByHash :one
SELECT id, user_id, expires_at, used_at, created_at
FROM email_verification_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: MarkEmailVerificationTokenUsed :exec
UPDATE email_verification_tokens SET used_at = now() WHERE id = $1;

-- name: SetEmailVerified :exec
UPDATE users SET email_verified = true WHERE id = $1;

-- name: DeleteExpiredEmailVerificationTokens :exec
DELETE FROM email_verification_tokens WHERE expires_at < now();
```

Run: `sqlc generate && go build ./...`

**Step 4: Write store wrapper methods + integration tests**

Create `internal/store/email_verification.go` — all methods use `withBypassTx`:

```go
func (s *Store) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error
func (s *Store) GetEmailVerificationTokenByHash(ctx context.Context, tokenHash []byte) (*EmailVerificationToken, error)
func (s *Store) MarkEmailVerificationTokenUsed(ctx context.Context, tokenID uuid.UUID) error
func (s *Store) SetEmailVerified(ctx context.Context, userID uuid.UUID) error
func (s *Store) DeleteExpiredEmailVerificationTokens(ctx context.Context) error
```

Create `internal/store/email_verification_test.go`:

```go
func TestCreateAndGetEmailVerificationToken(t *testing.T)
func TestGetEmailVerificationToken_Expired(t *testing.T)
func TestSetEmailVerified(t *testing.T)  // verify email_verified flips from false to true
```

Run tests, verify pass.

**Step 5: Write email template**

Create `internal/notify/templates/email_verification.html.tmpl` and `.txt.tmpl` following the same pattern as password reset. Template data:

```go
type EmailVerificationData struct {
    Email     string
    VerifyURL string
    ExpiresIn string
}
```

Add `RenderEmailVerification` to `render.go`.

**Step 6: Add config fields**

```go
// ── Auth — Email Verification ────────────────────────────────────────────
EmailVerificationTokenTTL time.Duration `env:"EMAIL_VERIFICATION_TOKEN_TTL" envDefault:"24h"`
```

**Step 7: Write failing handler tests**

Create `internal/api/auth_email_verification_test.go`:

```go
func TestRegister_SendsVerificationEmail(t *testing.T)
    // Register in open mode
    // Verify: email_verified = false, verification token created in DB

func TestVerifyEmail_ValidToken(t *testing.T)
    // Register, extract token from DB, POST /auth/verify-email
    // Verify: email_verified = true, token marked used

func TestVerifyEmail_ExpiredToken(t *testing.T)
    // Expect: 400

func TestVerifyEmail_AlreadyUsedToken(t *testing.T)
    // Expect: 400

func TestResendVerification(t *testing.T)
    // POST /auth/resend-verification (authenticated)
    // Verify: new token created

func TestResendVerification_AlreadyVerified(t *testing.T)
    // Expect: 200 with message "already verified" (idempotent)

func TestInvitationAccept_AutoVerifies(t *testing.T)
    // Accept invitation, verify email_verified = true
```

**Step 8: Implement handlers**

Create `internal/api/auth_email_verification.go`:

`POST /api/v1/auth/verify-email` (public, no auth):
- Parse `{token: string}`
- Hash, look up, validate
- Set `email_verified = true` on user
- Mark token used
- Return 200

`POST /api/v1/auth/resend-verification` (authenticated):
- Get user from context
- If already verified: return 200 with "already verified"
- Generate new token, send email
- Return 200

Modify `internal/api/auth.go` registration handler:
- After successful registration in `open` mode: generate verification token, send verification email (in a goroutine — don't block registration response)
- Use `context.WithoutCancel(r.Context())` for the background goroutine

Modify invitation acceptance handler:
- After accepting invitation: set `email_verified = true`

**Step 9: Register routes, run tests, commit**

```bash
git commit -m "feat(auth): email verification with auto-verify on invitation accept — TDD"
```

---

### Task 3: Account lockout

**Files:**
- Create: `internal/api/lockout.go`
- Create: `internal/api/lockout_test.go`
- Modify: `internal/config/config.go` — add lockout config
- Modify: `internal/api/auth.go` — integrate lockout check into login handler

**Design decisions:**
- In-memory map: `email → {failCount, lockedUntil}` — sufficient for single-instance MVP
- For multi-instance deployments: can be upgraded to DB-backed later (YAGNI)
- Check lockout BEFORE argon2 verification (saves CPU on locked accounts)
- Still run timing normalization on locked accounts (prevent lockout status enumeration)
- Successful login resets the counter
- Config: `LOCKOUT_THRESHOLD` (default 5), `LOCKOUT_DURATION` (default 15m)
- Lockout response: 429 with `Retry-After` header (seconds until unlock)
- Thread-safe: `sync.Mutex` on the map

**Step 1: Write failing tests**

Create `internal/api/lockout_test.go` (in `package api` — white-box):

```go
func TestLockout_Allow(t *testing.T)
    // Fresh lockout manager, first attempt for email → allowed

func TestLockout_ThresholdReached(t *testing.T)
    // Record 5 failures, 6th check → locked
    // Verify: returns non-zero retryAfter duration

func TestLockout_ResetOnSuccess(t *testing.T)
    // Record 4 failures, then success → counter resets
    // Next failure is attempt 1, not 5

func TestLockout_Expiry(t *testing.T)
    // Record 5 failures, advance clock past lockout duration
    // Next check → allowed (lockout expired)

func TestLockout_DifferentEmails(t *testing.T)
    // Lock email A, email B still allowed
```

The lockout manager should accept a `now func() time.Time` for testable clock injection.

**Step 2: Implement lockout manager**

Create `internal/api/lockout.go`:

```go
type lockoutManager struct {
    mu        sync.Mutex
    attempts  map[string]*loginAttempt
    threshold int
    duration  time.Duration
    now       func() time.Time
}

type loginAttempt struct {
    count     int
    lockedAt  time.Time
}

func newLockoutManager(threshold int, duration time.Duration, now func() time.Time) *lockoutManager

// Check returns (allowed bool, retryAfter time.Duration).
// If locked, retryAfter is the remaining lockout time.
func (m *lockoutManager) Check(email string) (bool, time.Duration)

// RecordFailure increments the failure count for an email.
func (m *lockoutManager) RecordFailure(email string)

// RecordSuccess resets the failure count for an email.
func (m *lockoutManager) RecordSuccess(email string)
```

**Step 3: Run tests, verify pass**

**Step 4: Add config fields**

```go
// ── Auth — Account Lockout ───────────────────────────────────────────────
LockoutThreshold int           `env:"LOCKOUT_THRESHOLD" envDefault:"5"`
LockoutDuration  time.Duration `env:"LOCKOUT_DURATION"  envDefault:"15m"`
```

**Step 5: Write failing integration test**

Add to `internal/api/auth_test.go` (or create `internal/api/auth_lockout_test.go`):

```go
func TestLogin_AccountLockout(t *testing.T)
    // Register user, attempt login with wrong password 5 times
    // 6th attempt: expect 429 with Retry-After header
    // Wait for lockout to expire (use short duration in test config)
    // Next attempt with correct password: expect 200
```

**Step 6: Integrate into login handler**

Modify `internal/api/auth.go` login handler:
1. Before argon2 verification: `allowed, retryAfter := srv.lockout.Check(email)`
2. If not allowed: still do timing normalization (`time.Sleep` or dummy argon2), then return 429 with `Retry-After: retryAfter.Seconds()`
3. On password mismatch: `srv.lockout.RecordFailure(email)`
4. On success: `srv.lockout.RecordSuccess(email)`

Initialize `lockoutManager` in `Server` constructor.

**Step 7: Run full auth test suite, verify pass. Commit.**

```bash
git commit -m "feat(auth): account lockout after repeated failed login attempts — TDD"
```

---

### Task 4: CORS middleware

**Files:**
- Modify: `go.mod` / `go.sum` — add `github.com/go-chi/cors`
- Modify: `internal/config/config.go` — add CORS config
- Modify: `internal/api/server.go` — add CORS middleware
- Create: `internal/api/middleware_cors_test.go`

**Design decisions:**
- Use `github.com/go-chi/cors` — standard chi ecosystem CORS middleware
- Config: `CORS_ALLOWED_ORIGINS` (comma-separated, default empty = no CORS headers)
- If `CORS_ALLOWED_ORIGINS` is empty and `APP_ENV=development`: default to `http://localhost:3000,http://localhost:5173` (common frontend dev servers)
- If `CORS_ALLOWED_ORIGINS` is empty and `APP_ENV=production`: no CORS headers (API-only mode)
- CORS middleware MUST be placed AFTER security headers, BEFORE CSRF, at the router level (not the apiRouter level), so that preflight OPTIONS requests get security headers too
- Allowed methods: GET, POST, PATCH, PUT, DELETE, OPTIONS
- Allowed headers: `Content-Type, Authorization, X-Requested-By`
- Expose headers: `X-Request-ID`
- Max age: 300 (5 minutes)
- Credentials: true (needed for cookie-based auth)

**Step 1: Add dependency**

Run: `go get github.com/go-chi/cors`

**Step 2: Add config**

```go
// ── CORS ─────────────────────────────────────────────────────────────────
// Comma-separated allowed origins. Empty = no CORS in production;
// defaults to localhost:3000,localhost:5173 in development.
CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS"`
```

**Step 3: Write failing tests**

Create `internal/api/middleware_cors_test.go`:

```go
func TestCORS_PreflightAllowedOrigin(t *testing.T)
    // OPTIONS request with allowed Origin header
    // Expect: Access-Control-Allow-Origin set, 204 response

func TestCORS_PreflightDisallowedOrigin(t *testing.T)
    // OPTIONS request with non-allowed Origin
    // Expect: No Access-Control-Allow-Origin header

func TestCORS_ActualRequestWithCredentials(t *testing.T)
    // GET request with cookie + allowed Origin
    // Expect: Access-Control-Allow-Credentials: true

func TestCORS_NoConfigNoHeaders(t *testing.T)
    // Empty CORS_ALLOWED_ORIGINS in production mode
    // Expect: No CORS headers on any response

func TestCORS_DevelopmentDefaults(t *testing.T)
    // Empty CORS_ALLOWED_ORIGINS in development mode
    // Expect: localhost origins allowed
```

**Step 4: Implement CORS middleware**

Modify `internal/api/server.go` — add CORS middleware after security headers, before standard chi middleware:

```go
// ── CORS (must be before CSRF and auth) ─────────────────────────────────
if origins := srv.corsOrigins(); len(origins) > 0 {
    r.Use(cors.Handler(cors.Options{
        AllowedOrigins:   origins,
        AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-By"},
        ExposedHeaders:   []string{"X-Request-ID"},
        AllowCredentials: true,
        MaxAge:           300,
    }))
}
```

Add helper method on `Server`:
```go
func (srv *Server) corsOrigins() []string {
    if srv.cfg.CORSAllowedOrigins != "" {
        return strings.Split(srv.cfg.CORSAllowedOrigins, ",")
    }
    if srv.cfg.IsDevelopment() {
        return []string{"http://localhost:3000", "http://localhost:5173"}
    }
    return nil
}
```

**Step 5: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(api): CORS middleware with configurable allowed origins — TDD"
```

---

## Phase 6B: Missing Features & Broken Workflows

### Task 5: Fix invite-only first-user bootstrap

**Files:**
- Modify: `internal/api/auth.go` — allow first registration regardless of mode
- Modify: `internal/api/auth_test.go` — add test for invite-only bootstrap

**Context (CRITICAL):** When `REGISTRATION_MODE=invite-only`, the `registerHandler` returns 403 for ALL users unconditionally. But `BootstrapFirstUserOrg` (which creates the first org and grants owner role) runs inside the register handler. Result: an invite-only deployment has **no way to create its first user through the API.** The invite-only deployment model is completely non-functional.

**Design decision:** Allow the FIRST registration regardless of mode. The logic should be:
1. If `RegistrationMode == "open"` → allow registration
2. If `RegistrationMode == "invite-only"` AND no users exist yet → allow registration (bootstrap)
3. If `RegistrationMode == "invite-only"` AND users exist → return 403

This is the smallest fix and doesn't require a new CLI command.

**Step 1: Write failing test**

Add to `internal/api/auth_test.go`:

```go
func TestRegister_InviteOnlyBootstrap(t *testing.T)
    // Start server with REGISTRATION_MODE=invite-only
    // First registration attempt → expect 201 (bootstrap allowed)
    // Verify: user created, org created, user is owner

func TestRegister_InviteOnlyAfterBootstrap(t *testing.T)
    // Start server with REGISTRATION_MODE=invite-only
    // First registration → 201 (bootstrap)
    // Second registration → 403 (blocked — invite-only enforced after bootstrap)
```

Run: `go test ./internal/api/ -run "TestRegister_InviteOnly" -v`
Expected: FAIL (first test fails because current code returns 403).

**Step 2: Fix register handler**

In `internal/api/auth.go`, the registration check currently looks like:
```go
if srv.cfg.RegistrationMode != "open" {
    return nil, huma.Error403Forbidden("registration is disabled")
}
```

Change to:
```go
if srv.cfg.RegistrationMode != "open" {
    // Allow first user to bootstrap even in invite-only mode.
    userCount, err := srv.store.CountUsers(ctx)
    if err != nil || userCount > 0 {
        return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
    }
}
```

Add sqlc query: `-- name: CountUsers :one SELECT COUNT(*) FROM users;`
Add store wrapper: `func (s *Store) CountUsers(ctx context.Context) (int64, error)` using `withBypassTx`.

**Step 3: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "fix(auth): allow first-user bootstrap in invite-only mode"
```

---

### Task 6: Invitation email delivery

**Files:**
- Create: `internal/notify/templates/email_invitation.html.tmpl`
- Create: `internal/notify/templates/email_invitation.txt.tmpl`
- Modify: `internal/notify/render.go` — add `RenderInvitation` function
- Modify: `internal/api/orgs.go` — send email in `createInvitationHandler`
- Modify: `internal/api/orgs_test.go` or create `internal/api/invitation_email_test.go`

**Context (HIGH):** The invitation system creates DB records with tokens but NEVER sends an email. The Phase 2A design explicitly deferred email delivery to "Phase 3 — notifications" but it was never implemented in any phase. Admins must manually copy the invitation URL from the API response and share it out-of-band. The SMTP infrastructure (`notify.EmailSend`) already exists and works for alerts/digests.

**Design decisions:**
- Reuse existing `notify.EmailSend` and template infrastructure
- Invitation email includes: org name, inviter name, role, and invitation link
- Link format: `{EXTERNAL_URL}/invitations/{token}` (frontend route — the token is the same one stored in the DB)
- Send synchronously after creating the invitation record (transactional email — admin is waiting)
- On SMTP failure: log error, return 201 anyway (invitation record created — admin can resend or share link manually). Include a warning in the response if email failed.

**Step 1: Write email templates**

Create `internal/notify/templates/email_invitation.html.tmpl`:

```html
{{define "subject"}}You've been invited to join {{.OrgName}} on CVErt Ops{{end}}
{{define "body"}}
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a2e;">You're Invited</h2>
  <p>{{.InviterName}} has invited you to join <strong>{{.OrgName}}</strong> on CVErt Ops as a <strong>{{.Role}}</strong>.</p>
  <p><a href="{{.InviteURL}}" style="display: inline-block; padding: 12px 24px; background-color: #1a1a2e; color: #ffffff; text-decoration: none; border-radius: 4px;">Accept Invitation</a></p>
  <p style="color: #666; font-size: 14px;">This invitation expires on {{.ExpiresAt}}. If you don't have a CVErt Ops account, you'll need to create one first.</p>
  <p style="color: #999; font-size: 12px;">If the button doesn't work, copy this URL: {{.InviteURL}}</p>
</body>
</html>
{{end}}
```

Create matching `.txt.tmpl`.

**Step 2: Add rendering function**

Add to `internal/notify/render.go`:

```go
type InvitationData struct {
    OrgName     string
    InviterName string
    Role        string
    InviteURL   string
    ExpiresAt   string
}

func RenderInvitation(data InvitationData) (string, string, string, error) {
    return renderPair(inviteHTML, inviteText, data)
}
```

Add parsed template variables and init lines (same pattern as existing templates).

**Step 3: Write failing test**

```go
func TestCreateInvitation_SendsEmail(t *testing.T)
    // Create org, POST /invitations with email
    // Verify: invitation created in DB
    // Verify: response includes invitation data
    // Note: email sending verification depends on test SMTP availability.
    // At minimum, verify no panic/error from the email sending path.
```

**Step 4: Wire email sending into invitation handler**

In `internal/api/orgs.go` `createInvitationHandler`, after the invitation is successfully created in the DB:

```go
// Send invitation email (best-effort — don't fail the request if SMTP is down).
inviteURL := srv.cfg.ExternalURL + "/invitations/" + token
subject, htmlBody, textBody, err := notify.RenderInvitation(notify.InvitationData{
    OrgName:     org.Name,
    InviterName: inviter.DisplayName,
    Role:        inv.Role,
    InviteURL:   inviteURL,
    ExpiresAt:   inv.ExpiresAt.Format("January 2, 2006"),
})
if err == nil {
    smtpCfg := notify.SmtpConfig{
        Host: srv.cfg.SMTPHost, Port: srv.cfg.SMTPPort,
        From: srv.cfg.SMTPFrom, Username: srv.cfg.SMTPUsername,
        Password: srv.cfg.SMTPPassword, TLS: srv.cfg.SMTPTLS,
    }
    if emailErr := notify.EmailSend(r.Context(), smtpCfg, []string{inv.Email}, subject, htmlBody, textBody); emailErr != nil {
        slog.Warn("invitation email failed", "email", inv.Email, "error", emailErr)
    }
}
```

The handler will need access to the org name and inviter display name. Load these if not already in context.

**Step 5: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(api): send invitation emails via SMTP — TDD"
```

---

### Task 7: Channel test notification

**Files:**
- Create: `internal/api/channel_test_notification_test.go`
- Modify: `internal/api/channels.go` — add test handler
- Modify: `internal/api/server.go` — register route

**Design decisions:**
- Endpoint: `POST /api/v1/orgs/{org_id}/channels/{id}/test`
- Auth: `RoleAdmin` (matches channel CRUD — see Task 9)
- Sends a test payload through the channel synchronously
- Returns the delivery result (success/failure with error message)
- Does NOT create a `notification_deliveries` record (test, not real)
- Does NOT count against delivery quotas
- Webhook test: sends a JSON payload with `{"test": true, "message": "CVErt Ops test notification", "timestamp": "..."}`, signed with the channel's signing secret
- Email test: sends a simple "Test notification from CVErt Ops" email to channel recipients
- Rate limit: implicit via CSRF + auth (no additional rate limit needed for admin-only endpoint)

**Step 1: Write failing tests**

Create `internal/api/channel_test_notification_test.go`:

```go
func TestChannelTest_Webhook(t *testing.T)
    // Create org, create webhook channel pointing to httptest.Server
    // POST /channels/{id}/test
    // Verify: httptest.Server received the request with correct HMAC signature
    // Verify: response is 200 with success status

func TestChannelTest_Webhook_Unreachable(t *testing.T)
    // Create webhook channel pointing to unreachable host
    // POST /channels/{id}/test
    // Verify: response is 200 with failure status + error message
    // (200 not 500 — the endpoint worked, the channel delivery failed)

func TestChannelTest_Email(t *testing.T)
    // Create email channel
    // POST /channels/{id}/test
    // Verify: response is 200
    // (Email delivery verification depends on test SMTP — verify no error returned)

func TestChannelTest_NotFound(t *testing.T)
    // POST /channels/{nonexistent-id}/test
    // Verify: 404

func TestChannelTest_RequiresAdmin(t *testing.T)
    // Authenticated as viewer/member
    // Verify: 403
```

**Step 2: Implement handler**

Add to `internal/api/channels.go`:

```go
func (srv *Server) testChannelHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Extract channel ID from URL
    // 2. Load channel from store (including config and signing_secret)
    // 3. Build test payload
    // 4. Based on channel type:
    //    - webhook: use existing webhook delivery code (notify.WebhookSend or similar)
    //    - email: use notify.EmailSend with a test-specific subject/body
    // 5. Return JSON: {"success": bool, "error": "..." (if failed)}
}
```

**Important:** For webhook test, use the SAME `doyensec/safeurl` client and HMAC signing logic as real deliveries. Don't create a separate code path — reuse the existing delivery functions from `internal/notify/`.

**Step 3: Register route**

In `server.go`, inside the channels route group (after Task 7 fixes RBAC to admin):

```go
r.Post("/{id}/test", srv.testChannelHandler)
```

**Step 4: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(api): channel test notification endpoint — TDD"
```

---

### Task 8: Admin feed management endpoints

**Files:**
- Create: `internal/api/admin_feeds.go`
- Create: `internal/api/admin_feeds_test.go`
- Modify: `internal/api/server.go` — register admin routes
- Create: `internal/api/middleware_system_admin.go`
- Create: `internal/api/middleware_system_admin_test.go`

**Design decisions:**
- **Auth model:** These are global endpoints (feeds are not org-scoped). Access requires the user to be an admin or owner in at least one org. This is a pragmatic choice for self-hosted deployments where the instance operator is typically an org admin. For future SaaS, a dedicated super-admin role would be needed — but that's YAGNI now.
- New middleware: `requireSystemAdmin()` — checks `RequireAuthenticated()` first, then queries `org_members` for admin/owner role in any org
- `GET /api/v1/admin/feeds` — list all rows from `feed_sync_state` table
- `POST /api/v1/admin/feeds/{feed}/run` — enqueue a `feed_ingest` job for the specified feed via `worker.Pool`. Returns 202 Accepted. The job queue's `lock_key` prevents duplicate concurrent runs.
- Feed names must match a known adapter name (validate against a hardcoded list)

**Step 1: Write system admin middleware tests**

Create `internal/api/middleware_system_admin_test.go`:

```go
func TestSystemAdmin_OwnerAllowed(t *testing.T)
    // User is owner in an org → 200

func TestSystemAdmin_AdminAllowed(t *testing.T)
    // User is admin in an org → 200

func TestSystemAdmin_MemberDenied(t *testing.T)
    // User is only a member (no admin/owner role anywhere) → 403

func TestSystemAdmin_UnauthenticatedDenied(t *testing.T)
    // No auth → 401
```

**Step 2: Implement system admin middleware**

Create `internal/api/middleware_system_admin.go`:

```go
func (srv *Server) requireSystemAdmin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
        if !ok {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        // Query: SELECT EXISTS(SELECT 1 FROM org_members WHERE user_id = $1 AND role IN ('admin', 'owner'))
        isAdmin, err := srv.store.IsSystemAdmin(r.Context(), userID)
        if err != nil || !isAdmin {
            http.Error(w, "forbidden: system admin required", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

Add sqlc query and store method for `IsSystemAdmin`.

**Step 3: Write failing handler tests**

Create `internal/api/admin_feeds_test.go`:

```go
func TestAdminListFeeds(t *testing.T)
    // As system admin, GET /api/v1/admin/feeds
    // Verify: returns array of feed sync states

func TestAdminListFeeds_Unauthorized(t *testing.T)
    // As member (not admin) → 403

func TestAdminTriggerFeedRun(t *testing.T)
    // As system admin, POST /api/v1/admin/feeds/nvd/run
    // Verify: 202 Accepted, job enqueued in job_queue

func TestAdminTriggerFeedRun_UnknownFeed(t *testing.T)
    // POST /api/v1/admin/feeds/unknown/run
    // Verify: 400 (unknown feed name)

func TestAdminTriggerFeedRun_DuplicateRun(t *testing.T)
    // Trigger twice quickly
    // Verify: second returns 409 Conflict (already running/pending)
```

**Step 4: Implement handlers**

Create `internal/api/admin_feeds.go`:

```go
// Known feed adapter names — must match what's registered in the worker.
var knownFeeds = []string{"nvd", "mitre", "kev", "osv", "ghsa", "epss"}

func (srv *Server) listFeedsHandler(w http.ResponseWriter, r *http.Request)
    // Query feed_sync_state table, return all rows as JSON

func (srv *Server) triggerFeedRunHandler(w http.ResponseWriter, r *http.Request)
    // 1. Extract feed name from URL path
    // 2. Validate against knownFeeds
    // 3. Enqueue job: srv.store.EnqueueJob(ctx, "feed_ingest", 0, payload, "feed:"+feedName, 1, time.Now())
    //    lock_key prevents duplicate runs
    // 4. Return 202
```

Add sqlc query for listing all feed sync states:
```sql
-- name: ListFeedSyncStates :many
SELECT feed_name, cursor_json, last_success_at, last_attempt_at,
       consecutive_failures, last_error, backoff_until
FROM feed_sync_state
ORDER BY feed_name;
```

**Step 5: Register routes**

In `server.go`, add a new admin route group:

```go
// ── Admin routes (system-admin only, not org-scoped) ─────────────────────
apiRouter.Route("/admin", func(r chi.Router) {
    r.Use(srv.requireAuth)
    r.Use(srv.requireSystemAdmin)
    r.Get("/feeds", srv.listFeedsHandler)
    r.Post("/feeds/{feed}/run", srv.triggerFeedRunHandler)
})
```

**Step 6: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(api): admin feed management endpoints with system-admin auth — TDD"
```

---

### Task 9: Fix channel RBAC

**Files:**
- Modify: `internal/api/server.go` — change channel route auth from `RoleMember` to `RoleAdmin`
- Modify: `internal/api/channels_test.go` — update tests to verify admin requirement

**Context:** The PLAN.md §7.3 permission matrix explicitly says "CRUD notification channels" requires owner/admin. The current implementation allows `member` role. This is a bug — channels affect all org members (they receive notifications), so only admins should manage them.

**Step 1: Write failing test**

Add to channel tests (or create new test):

```go
func TestChannelCreate_MemberDenied(t *testing.T)
    // Authenticated as member (not admin), POST /channels
    // Verify: 403
```

Run test — expect it to PASS (current behavior allows member). This is a case where we need to verify the current behavior is wrong, then fix it.

Actually, write the test for the CORRECT behavior:
```go
func TestChannelCreate_RequiresAdmin(t *testing.T)
    // Create user with member role
    // POST /channels → expect 403
    // Promote to admin
    // POST /channels → expect 201
```

**Step 2: Fix route registration**

In `server.go`, find the channel routes and change the middleware group from the one using `RoleMember` to `RoleAdmin`:

The channels route group should use `RequireOrgRole(RoleAdmin)` for POST, PATCH, DELETE, rotate-secret, clear-secondary, and test. GET (list/detail) can remain at `RoleViewer`.

**Step 3: Run full channel test suite**

Run: `go test ./internal/api/ -run "TestChannel" -v`
Expected: All PASS (some existing tests may need their user role upgraded from member to admin).

**Step 4: Lint. Commit.**

```bash
git commit -m "fix(api): restrict channel CRUD to admin/owner role per PLAN.md §7.3"
```

---

## Phase 6C: PLAN.md Reconciliation

### Task 10: Update Appendix B

**Files:**
- Modify: `PLAN.md` — Appendix B section

**This task updates the endpoint specification to match reality. No code changes.**

**Step 1: Add missing implemented endpoints to Appendix B**

The following 21 endpoints exist in the implementation but are missing from Appendix B. Add them to the appropriate sections:

**Auth section — add:**
```
- `GET /api/v1/auth/me` — current user profile + org memberships (authenticated)
- `POST /api/v1/auth/change-password` — change password (authenticated, native auth only)
- `GET /api/v1/auth/invitations/{token}` — public invitation detail (no auth)
- `POST /api/v1/auth/invitations/{token}/accept` — accept invitation (authenticated)
- `POST /api/v1/auth/forgot-password` — request password reset (public)
- `POST /api/v1/auth/reset-password` — reset password with token (public)
- `POST /api/v1/auth/verify-email` — verify email with token (public)
- `POST /api/v1/auth/resend-verification` — resend verification email (authenticated)
```

**Org management section — add:**
```
- `POST /api/v1/orgs/{org_id}/invitations` — create invitation (admin/owner)
- `GET /api/v1/orgs/{org_id}/invitations` — list pending invitations (admin/owner)
- `DELETE /api/v1/orgs/{org_id}/invitations/{id}` — cancel invitation (admin/owner)
```

**Alert rules section — add:**
```
- `GET /api/v1/orgs/{org_id}/alert-rules/{id}/channels` — list channels bound to rule
- `PUT /api/v1/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}` — bind channel to rule
- `DELETE /api/v1/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}` — unbind channel
```

**Channels section — add:**
```
- `POST /api/v1/orgs/{org_id}/channels/{id}/rotate-secret` — rotate webhook signing secret (admin/owner)
- `POST /api/v1/orgs/{org_id}/channels/{id}/clear-secondary` — clear secondary signing secret (admin/owner)
```

**Reports section — add:**
```
- `GET /api/v1/orgs/{org_id}/reports/{id}/channels` — list channels bound to report
- `PUT /api/v1/orgs/{org_id}/reports/{id}/channels/{channel_id}` — bind channel to report
- `DELETE /api/v1/orgs/{org_id}/reports/{id}/channels/{channel_id}` — unbind channel
```

**Saved searches section — add:**
```
- `POST /api/v1/orgs/{org_id}/saved-searches/{id}/execute` — execute saved search
```

**Infrastructure section — add:**
```
- `GET /metrics` — Prometheus metrics endpoint (no auth)
```

**Step 2: Fix structural mismatches**

The implementation restructured some endpoints from the original spec. Update Appendix B to match the implementation (which is the better design):

a) **Alert events:** Replace `GET /api/v1/orgs/{org_id}/alert-rules/{id}/events` with:
```
- `GET /api/v1/orgs/{org_id}/alert-events` — list alert events (filters: ?rule_id=, ?cve_id=, ?last_match_state=, ?since=)
```
Add a note: "Flat org-level endpoint with optional filters, rather than nested under individual rules, for cross-rule querying."

b) **Deliveries:** Replace `GET .../channels/{id}/deliveries` and `POST .../channels/{id}/deliveries/{delivery_id}/replay` with:
```
- `GET /api/v1/orgs/{org_id}/deliveries` — list deliveries (filters: ?channel_id=, ?rule_id=, ?status=)
- `GET /api/v1/orgs/{org_id}/deliveries/{id}` — delivery detail
- `POST /api/v1/orgs/{org_id}/deliveries/{id}/replay` — re-enqueue failed delivery (admin/owner)
```

c) **Member invitation:** Replace `POST /api/v1/orgs/{org_id}/members` (invite) with the invitations endpoints listed above. Keep `POST /members` only if it has a non-invitation purpose (it doesn't — remove).

d) **Group member deletion:** Update spec to match implementation:
```
- `DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members/{user_id}` — remove member from group
```

e) **Watchlist item deletion:** Update spec to match implementation:
```
- `DELETE /api/v1/orgs/{org_id}/watchlists/{id}/items/{item_id}` — remove item
```

**Step 3: Update channel permissions note**

Update the channels section to note that CRUD requires admin/owner role (matching §7.3 and the Task 7 fix).

**Step 4: Verify consistency. Commit.**

```bash
git add PLAN.md
git commit -m "docs: reconcile Appendix B with implemented API — 21 endpoints added, mismatches fixed"
```

---

### Task 11: Fix PLAN.md internal inconsistencies

**Files:**
- Modify: `PLAN.md`

**Step 1: Fix CVE status enum (GAP-021)**

In §4.3, the `cves.status` definition lists `new|modified|analyzed|rejected|unknown`. Add `withdrawn` to the enum — it's used by OSV/GHSA for retracted advisories, and the evaluator (§10.3) already filters `NOT IN ('rejected', 'withdrawn')`.

Change to: `new|modified|analyzed|rejected|withdrawn|unknown`

**Step 2: Fix user_identities categorization (GAP-022)**

In §4.2, `user_identities` is listed under "Org/Tenant scoped" tables. Move it to the global/shared section — it links users to OAuth providers, not to orgs. It has no `org_id` column and no RLS.

**Step 3: Fix stale RLS note (GAP-019)**

In §19 research backlog, item 3 says RLS is "deferred to P1." §6.2 explicitly says RLS is implemented in Phase 2. Remove or correct the stale note in §19 to match §6.2.

**Step 4: Remove corrupt job_queue fragment (GAP-023)**

In §18.1, there's a truncated sentence ending mid-word and orphaned SQL fragments. Clean up the corrupted text.

**Step 5: Fix "Phase 6" references (GAP-020)**

§3.2 defers NVD attribution to "Phase 6 (UI)." Since §18 only defines Phases 0-5, and this Phase 6 document exists for backend cleanup (not UI), either:
- Change the reference to "deferred until frontend implementation"
- Or reference §20 (frontend) instead

**Step 6: Update §18 phase summary**

Add a Phase 6 entry to §18 summarizing what this phase covers, so the phase list is complete.

**Step 7: Commit.**

```bash
git add PLAN.md
git commit -m "docs: fix PLAN.md internal inconsistencies — status enum, categorization, stale notes"
```

---

## Appendix A: Deferred Items

The gap analysis identified the following items that are NOT addressed in Phase 6. Each is documented here with justification for deferral. These are genuine gaps or enhancements — none are blocked on design or dependencies, but they are lower priority than the Phase 6 tasks above.

### Security & Auth

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Single-session revocation (per-device logout) | GAP-007 | LOW | Current `token_version` increment logs out ALL devices. Per-device revocation requires a session table (JTI tracking per device). Not needed for MVP — global logout is acceptable. |
| JWT secret rotation strategy | GAP-036 | MEDIUM | Requires dual-secret grace period (like webhook signing). Important for production ops, but not a code feature — it's an operational procedure. Could be implemented as a config change (`JWT_SECRET_OLD` fallback) if needed. |

### Notifications

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Custom notification templates | GAP-008 | LOW | Only built-in templates in MVP. Custom templates add complexity (template storage, validation, sandboxed rendering). Not needed until enterprise customers request it. |
| Weekly digest report | GAP-009 | LOW | Daily digest exists. Weekly is a scheduling change + different aggregation window. Low effort but low value — daily covers the use case. |
| GHSA webhook integration | GAP-002 | LOW | Polling works fine. Webhooks reduce latency but add infrastructure complexity (public endpoint, signature verification, retry handling). |

### Data Model & Evaluation

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Ecosystem-aware CVSS precedence | GAP-005 | MEDIUM | For package-ecosystem CVEs, GHSA/OSV often has better CVSS than NVD. Current MVP uses static NVD-first precedence. Requires per-feed quality scoring — significant evaluator work. |
| EPSS re-crossing alerts | GAP-006 | MEDIUM | When EPSS drops below then re-crosses a threshold, the dedup key (`material_hash`) prevents re-firing. Requires per-(rule, CVE) EPSS state tracking. Complex evaluator change for an edge case. |
| Version range matching in watchlists | GAP-010 | MEDIUM | Watchlist items match on ecosystem + package name only. Version constraints require `Masterminds/semver/v3` integration, version comparison logic in the evaluator, and significant schema changes. Needs its own design phase. |
| CWE dictionary ingestion | GAP-016/027 | MEDIUM | CWE IDs are stored on CVEs. The dictionary provides human-readable names for FTS enrichment ("buffer overflow" → CWE-120). Improves search quality but not functional correctness. Self-contained — could be a quick follow-up. |

### Features

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| CVE annotations/assignment | GAP-025 | LOW | Assign CVEs to team members, add tags/notes. Useful workflow feature but not core alerting functionality. Schema exists in PLAN.md Appendix A but needs endpoint design. |
| Watchlist bootstrap templates | GAP-026 | LOW | Pre-built watchlist templates for common ecosystems. Nice onboarding UX but not blocking. Endpoints specced in Appendix B. |
| Generic OIDC/SAML (beyond Phase 5 SSO) | GAP-003 | LOW | Phase 5D implements SSO with OIDC. Generic SAML support (`crewjam/saml`) is enterprise-specific and can be added when demanded. |

### Operational

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Distributed tracing | GAP-004 | LOW | Structured log `request_id` is the interim solution. OpenTelemetry integration is useful for production debugging but not blocking. |
| Backup/restore documentation | GAP-035 | MEDIUM | Important for self-hosted operators but not code — it's documentation. Should be written alongside deployment docs. |
| Deployment documentation | GAP-042 | MEDIUM | Docker Compose production setup, env var reference, TLS guide, Kubernetes manifests. Important but not code. |
| System self-monitoring/alerting | GAP-041 | MEDIUM | Prometheus metrics exist. Alert rules on the application itself (feed stall, job queue depth, delivery failure rate) are operational configuration, not application code. |
| Health check depth (liveness vs readiness) | GAP-040 | MEDIUM | Current `/healthz` is basic. Kubernetes-ready probes with per-component health (DB, worker, job queue) would be useful. Relatively small effort — could be added as a follow-up task. |
| OpenAPI spec export | GAP-043 | LOW | Huma auto-generates OpenAPI spec at `/openapi.json`. May need versioning or static export. Low priority. |
| Graceful shutdown notification draining | GAP-044 | MEDIUM | Edge case: shutdown during webhook HTTP call leaves delivery in `processing` state. Stale lock detector handles recovery. Not urgent. |
| Migration rollback testing | GAP-045 | MEDIUM | Down migrations exist but aren't systematically tested. Important for production confidence but not a feature. |
| Search index rebuild admin endpoint | GAP-018 | LOW | Admin action to rebuild `cve_search_index`. Useful for recovery but rarely needed. |
| Admin feed re-run behavior details | GAP-017 | LOW | Partially addressed by Task 8. Full spec (cursor reset, full re-sync) needs design based on operator needs. |

### Billing & SaaS

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Billing hooks | GAP-014 | MEDIUM (SaaS) | Payment integration, billing cycles, downgrade handling. Entirely SaaS-specific — self-hosted deployments don't need this. Should be designed alongside SaaS launch. |
| NVD attribution notice | GAP-001 | MEDIUM | NVD Terms of Use require a display notice. Depends on frontend (UI element). Backend could serve the required text via an endpoint if needed. |

### Org Management

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Org deletion | GAP-037 | MEDIUM | Complex cascade implications (all org-scoped tables), data retention requirements, confirmation flow. Needs its own design. |
| Ownership transfer | GAP-038 | MEDIUM | Requires confirmation mechanism (email? two-step?), handling of declined transfers. Needs design. |

### API Design (from user journey trace)

| Item | Source | Severity | Why Deferred |
|------|--------|----------|--------------|
| "Which watchlists matched this CVE?" query | Journey 4 | MEDIUM | Alert events contain `rule_id` but not `watchlist_ids`. Getting from "CVE triggered alert" to "which watchlists are affected" requires N+1 API calls. Could be a computed field on alert event response or a dedicated endpoint. Needs design. |
| Unauthenticated CVE endpoint rate limiting | Journey 5 | MEDIUM | CVE endpoints are intentionally public per PLAN.md. But no per-IP rate limit on unauthenticated requests — an unauthenticated client can query the entire CVE corpus without throttling. Could add simple IP-based rate limiting to public routes. |
| On-demand report generation | Journey 3 | LOW | Only scheduled digest reports exist. No "generate a report right now" endpoint. By design per §12, but users want ad-hoc summaries during incident response. |

---

## Appendix B: Design Decisions Log

| Decision | Rationale |
|----------|-----------|
| Password reset tokens hashed (SHA-256), invitation tokens stored raw | Password reset tokens grant full account access; invitation tokens only allow joining an org with a pre-assigned role. Different threat models warrant different storage. |
| Email verification non-blocking (login allowed without verification) | Self-hosted deployments may not have SMTP configured. Blocking login on verification would lock out users. Status tracked for future feature gating. |
| Invited users auto-verified | Invitation acceptance proves the user owns the email (invitation was sent to that address). Requiring separate verification is redundant and annoying. |
| Account lockout in-memory, not DB-backed | Single-instance MVP. DB-backed lockout adds complexity for multi-instance deployments that don't exist yet. YAGNI. |
| Lockout check before argon2, with timing normalization | Saves CPU (argon2 is expensive) while preventing lockout status enumeration via timing side channel. |
| CORS defaults: localhost in dev, nothing in production | Safe default — production requires explicit configuration. Dev defaults match common frontend dev servers. |
| System admin = admin/owner in any org | Pragmatic for self-hosted. Instance operator is typically an org admin. SaaS would need a dedicated super-admin role. |
| Channel RBAC: admin not member | Channels affect all org members. PLAN.md §7.3 explicitly restricts channel management to admin/owner. The member-level access was a bug. |
| Admin feed re-run via job queue (async, 202) | Feed syncs can take minutes (NVD full sync). Synchronous response would time out. Job queue's lock_key prevents duplicate concurrent runs. |
| Invite-only bootstrap: allow first registration regardless of mode | The alternative (CLI `create-admin` command) requires shell access, which is more complex for containerized deployments. Allowing the first registration is the smallest fix, works in all deployment models, and is self-documenting (first user = admin). |
| Invitation email: best-effort, don't fail request on SMTP error | Invitation record is the source of truth. If SMTP fails, admin can share the link manually or resend. Failing the entire invitation because of a transient SMTP issue is worse UX. |
