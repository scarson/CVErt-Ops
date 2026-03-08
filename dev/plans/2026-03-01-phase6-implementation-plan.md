# Phase 6: Backend Cleanup & Production Readiness

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close security gaps, add missing specced features, fix RBAC discrepancies, and reconcile PLAN.md with reality — making the backend production-ready.

**Architecture:** Phase 6 addresses findings from a systematic gap analysis (PLAN.md internal scan + API contract completeness audit). Security hardening tasks (password reset, email verification, account lockout, CORS) fill gaps that block production use. Missing specced features (channel test, invitation emails) complete the API contract. PLAN.md reconciliation brings the spec in line with the real implementation.

**Tech Stack:** Go 1.26, chi, huma, sqlc, go-mail (existing), go-chi/cors (new dependency)

**Prerequisites:** Phase 5 is fully implemented. Latest migration is `000030_add_site_admin`. Phase 6 migrations start at 000031. Frontend (Vue 3 + Vite) is implemented and embedded in the Go binary via `web/` package.

**Context for subagents:**
- Auth routes use **huma** (`huma.Register` in `registerAuthRoutes`). Org-scoped routes use **chi** with per-route RBAC middleware. New auth endpoints (password reset, email verification) should follow the huma pattern.
- Transaction helpers: `withBypassTx` for operations without org context, `withOrgTx` for handler-context queries
- Integration tests use `testutil.NewTestDB(t)` with testcontainers Postgres
- TDD is mandatory: RED → verify fail → GREEN → verify pass → refactor → commit
- Run `sqlc generate` after any `.sql` file changes, before `go build`
- Run `golangci-lint run` before committing
- All email templates follow the `{{define "subject"}}` / `{{define "body"}}` pattern in `internal/notify/templates/`
- `notify.EmailSend()` (`internal/notify/email.go`) is the shared SMTP sender — use it for transactional emails too
- Site admin auth: `RequireSiteAdmin()` middleware checks `users.is_site_admin` flag (migration 000030). Admin feed endpoints already use this.
- Frontend dev: Vite proxies API calls to Go backend on :8080. In production, SPA is embedded (same origin). CORS is primarily for external API consumers.

---

## Phase 6A: Security Hardening

### Task 1: Password reset flow

**Files:**
- Create: `migrations/000031_create_password_reset_tokens.up.sql` / `.down.sql`
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
git add migrations/000031_create_password_reset_tokens.* internal/store/queries/password_reset.sql internal/store/generated/ internal/store/password_reset.go internal/store/password_reset_test.go internal/notify/templates/email_password_reset.* internal/notify/render.go internal/config/config.go internal/api/auth_password_reset.go internal/api/auth_password_reset_test.go internal/api/server.go
git commit -m "feat(auth): password reset flow with rate limiting and session invalidation — TDD"
```

---

### Task 2: Email verification

**Files:**
- Create: `migrations/000032_add_email_verified_to_users.up.sql` / `.down.sql`
- Create: `migrations/000033_create_email_verification_tokens.up.sql` / `.down.sql`
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

### Task 4: Frontend — password reset & email verification pages

**Depends on:** Task 1 (password reset backend), Task 2 (email verification backend)

**Files:**
- Create: `web/src/views/ForgotPasswordView.vue`
- Create: `web/src/views/ResetPasswordView.vue`
- Create: `web/src/views/VerifyEmailView.vue`
- Modify: `web/src/router/index.ts` — add 3 public routes
- Modify: `web/src/stores/auth.ts` — add API call methods
- Modify: `web/src/views/LoginView.vue` — add "Forgot password?" link

**Design decisions:**
- All 3 pages are public routes (`requiresAuth: false`, `layout: 'public'`)
- Follow the existing pattern from `LoginView.vue` and `RegisterView.vue` (Card + form layout, shadcn components)
- `ForgotPasswordView` — email input, calls `POST /api/v1/auth/forgot-password`, shows success message regardless of result
- `ResetPasswordView` — reads `token` from query param, new password + confirm inputs, calls `POST /api/v1/auth/reset-password`, redirects to login on success
- `VerifyEmailView` — reads `token` from query param, auto-submits on mount via `POST /api/v1/auth/verify-email`, shows success/error state
- No new UI components needed — reuse existing shadcn Card, Input, Label, Button

**Step 1: Add routes to router**

Add to the public routes section of `web/src/router/index.ts`:

```ts
{
  path: '/forgot-password',
  name: 'forgot-password',
  component: () => import('@/views/ForgotPasswordView.vue'),
  meta: { layout: 'public', requiresAuth: false, title: 'Forgot Password' },
},
{
  path: '/reset-password',
  name: 'reset-password',
  component: () => import('@/views/ResetPasswordView.vue'),
  meta: { layout: 'public', requiresAuth: false, title: 'Reset Password' },
},
{
  path: '/verify-email',
  name: 'verify-email',
  component: () => import('@/views/VerifyEmailView.vue'),
  meta: { layout: 'public', requiresAuth: false, title: 'Verify Email' },
},
```

**Step 2: Add store methods**

Add to `web/src/stores/auth.ts`:

```ts
async forgotPassword(email: string): Promise<{ success: boolean; error?: string }>
async resetPassword(token: string, newPassword: string): Promise<{ success: boolean; error?: string }>
async verifyEmail(token: string): Promise<{ success: boolean; error?: string }>
```

Each method calls the corresponding `POST /api/v1/auth/*` endpoint and returns a result object (same pattern as existing `login`/`register`).

**Step 3: Build ForgotPasswordView**

- Email input + submit button
- On submit: call `auth.forgotPassword(email)`
- Always show success message: "If an account with that email exists, a password reset link has been sent."
- Link back to login page

**Step 4: Build ResetPasswordView**

- Read `token` from `route.query.token`
- If no token in URL: show error with link to forgot-password
- New password + confirm password inputs (min 16 chars, matching)
- On submit: call `auth.resetPassword(token, password)`
- On success: show message + redirect to login after 3s
- On error: show error (expired/invalid token)

**Step 5: Build VerifyEmailView**

- Read `token` from `route.query.token`
- Auto-submit on `onMounted`: call `auth.verifyEmail(token)`
- Show loading state while verifying
- On success: "Email verified!" with link to login/dashboard
- On error: show error with "Resend verification" link (links to a future resend flow or dashboard)

**Step 6: Add "Forgot password?" link to LoginView**

Add a `RouterLink` to `/forgot-password` below the password field in `LoginView.vue`.

**Step 7: Run frontend tests and lint**

```bash
cd web && npm run type-check && npm run lint
```

**Step 8: Commit**

```bash
git add web/src/views/ForgotPasswordView.vue web/src/views/ResetPasswordView.vue web/src/views/VerifyEmailView.vue web/src/router/index.ts web/src/stores/auth.ts web/src/views/LoginView.vue
git commit -m "feat(frontend): password reset and email verification pages"
```

---

### Task 5: CORS middleware

**Files:**
- Modify: `go.mod` / `go.sum` — add `github.com/go-chi/cors`
- Modify: `internal/config/config.go` — add CORS config
- Modify: `internal/api/server.go` — add CORS middleware
- Create: `internal/api/middleware_cors_test.go`

**Context note:** The Vue 3 frontend is now implemented and embedded in the Go binary (`web/` package). In production, the SPA is served from the same origin (no CORS needed for the built-in UI). In dev, Vite proxies API calls to `:8080` (also no CORS needed). CORS is therefore primarily for external API consumers calling from browsers and non-standard deployment configurations. Still worth implementing — it's a small lift and the right default for a public API.

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

### Task 6: Fix invite-only first-user bootstrap

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

**NOTE:** The `CountUsers` store method already exists (`internal/store/auth.go:59`) with a sqlc query. No need to create it — just call `srv.store.CountUsers(ctx)` in the registration handler.

**Step 3: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "fix(auth): allow first-user bootstrap in invite-only mode"
```

---

### Task 7: Invitation email delivery

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

### Task 8: Channel test notification

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

In `server.go`, inside the channels route group (after Task 9 fixes RBAC to admin):

```go
r.Post("/{id}/test", srv.testChannelHandler)
```

**Step 4: Run tests, verify pass. Lint. Commit.**

```bash
git commit -m "feat(api): channel test notification endpoint — TDD"
```

---

### ~~Admin feed management endpoints~~ — DROPPED (already implemented)

> **Audit note (2026-03-08):** Originally planned as a task here, this was fully implemented during Phase 5f. Admin feed endpoints (`GET /admin/feeds`, `POST /admin/feeds/{feed}/run`) exist in `internal/api/feeds.go`, routes are registered in `server.go:199-200`, and auth uses `RequireSiteAdmin()` middleware backed by `users.is_site_admin` column (migration 000030). The auth model is better than what this plan originally specified ("admin in any org") — a dedicated site admin flag is more correct. Frontend feed status dashboard also exists. No action needed.

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

### Task 10: Reconcile Appendix B with implemented API

**Files:**
- Modify: `PLAN.md` — Appendix B section

**This task rewrites Appendix B to match the actual implemented API. No code changes.**

**Audit note (2026-03-08):** The original plan listed 21 missing endpoints, but 324 commits have landed since then — including SSO, audit logging, AI endpoints, delivery management, tier endpoints, and more. Four of the originally-listed endpoints (forgot-password, reset-password, verify-email, resend-verification) don't exist yet because they're from Phase 6A Tasks 1-2. This task should be done AFTER Phase 6A and 6B are complete, so it captures the final API surface.

**Approach:** Replace the current Appendix B with a comprehensive list derived from `server.go` route registrations, `auth.go` huma registrations, and `cves.go` huma registrations. The implementation is the source of truth — PLAN.md should match reality.

**Step 1: Rewrite Appendix B**

The full implemented API surface (as of Phase 6B completion) should include:

**Infrastructure (no auth):**
```
- `GET /healthz` — health check (DB ping)
- `GET /metrics` — Prometheus metrics
```

**Public / Global (no auth, huma):**
```
- `GET /api/v1/cves` — paginated search with filters/facets
- `GET /api/v1/cves/{cve_id}` — canonical CVE detail
- `GET /api/v1/cves/{cve_id}/sources` — per-source comparison
```

**Auth (huma, rate-limited):**
```
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me` — current user profile + org memberships
- `POST /api/v1/auth/change-password` — change password (authenticated)
- `GET /api/v1/auth/invitations/{token}` — public invitation detail
- `POST /api/v1/auth/invitations/{token}/accept` — accept invitation (authenticated)
- `GET /api/v1/auth/providers` — list available auth providers
- `POST /api/v1/auth/forgot-password` — request password reset (Phase 6A Task 1)
- `POST /api/v1/auth/reset-password` — reset password with token (Phase 6A Task 1)
- `POST /api/v1/auth/verify-email` — verify email with token (Phase 6A Task 2)
- `POST /api/v1/auth/resend-verification` — resend verification email (Phase 6A Task 2)
```

**SSO (chi, rate-limited/authenticated):**
```
- `POST /api/v1/auth/discover` — SSO email domain discovery (public, rate-limited)
- `GET /api/v1/auth/oauth/github` — GitHub OAuth init (redirect)
- `GET /api/v1/auth/oauth/github/callback` — GitHub OAuth callback
- `GET /api/v1/auth/oauth/google` — Google OIDC init (redirect)
- `GET /api/v1/auth/oauth/google/callback` — Google OIDC callback
- `GET /api/v1/auth/oidc/{connection_id}/login` — Generic OIDC SSO login
- `GET /api/v1/auth/oidc/callback` — Generic OIDC callback
- `GET /api/v1/auth/oidc/link-callback` — OIDC identity link callback
```

**Admin (site-admin only, chi):**
```
- `GET /api/v1/admin/feeds` — feed sync status
- `POST /api/v1/admin/feeds/{feed}/run` — trigger feed re-run (202 Accepted)
```

**Org management (role-gated, chi):**
```
- `POST /api/v1/orgs` — create org (authenticated)
- `GET /api/v1/orgs/{org_id}` — org detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}` — update org settings (admin+)
- `GET /api/v1/orgs/{org_id}/tier` — org tier + resolved limits (viewer+)
- `GET /api/v1/orgs/{org_id}/members` — list members (viewer+)
- `PATCH /api/v1/orgs/{org_id}/members/{user_id}` — update member role (admin+)
- `DELETE /api/v1/orgs/{org_id}/members/{user_id}` — remove member (admin+)
- `POST /api/v1/orgs/{org_id}/invitations` — create invitation (admin+)
- `GET /api/v1/orgs/{org_id}/invitations` — list pending invitations (admin+)
- `DELETE /api/v1/orgs/{org_id}/invitations/{id}` — cancel invitation (admin+)
```

**API keys:**
```
- `POST /api/v1/orgs/{org_id}/api-keys` — create API key (member+)
- `GET /api/v1/orgs/{org_id}/api-keys` — list API keys (viewer+)
- `DELETE /api/v1/orgs/{org_id}/api-keys/{id}` — revoke API key (viewer+)
```

**Watchlists:**
```
- `GET /api/v1/orgs/{org_id}/watchlists` — list (viewer+)
- `POST /api/v1/orgs/{org_id}/watchlists` — create (member+)
- `GET /api/v1/orgs/{org_id}/watchlists/{id}` — detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}/watchlists/{id}` — update (member+)
- `DELETE /api/v1/orgs/{org_id}/watchlists/{id}` — delete (member+)
- `GET /api/v1/orgs/{org_id}/watchlists/{id}/items` — list items (viewer+)
- `POST /api/v1/orgs/{org_id}/watchlists/{id}/items` — add item (member+)
- `DELETE /api/v1/orgs/{org_id}/watchlists/{id}/items/{item_id}` — remove item (member+)
```

**Notification channels (admin+ for mutations after Task 9 RBAC fix):**
```
- `GET /api/v1/orgs/{org_id}/channels` — list (viewer+)
- `POST /api/v1/orgs/{org_id}/channels` — create (admin+)
- `GET /api/v1/orgs/{org_id}/channels/{id}` — detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}/channels/{id}` — update (admin+)
- `DELETE /api/v1/orgs/{org_id}/channels/{id}` — delete (admin+)
- `POST /api/v1/orgs/{org_id}/channels/{id}/rotate-secret` — rotate webhook signing secret (admin+)
- `POST /api/v1/orgs/{org_id}/channels/{id}/clear-secondary` — clear secondary signing secret (admin+)
- `POST /api/v1/orgs/{org_id}/channels/{id}/test` — send test notification (Phase 6B Task 8, admin+)
```

**Alert rules:**
```
- `GET /api/v1/orgs/{org_id}/alert-rules` — list (viewer+)
- `POST /api/v1/orgs/{org_id}/alert-rules` — create (member+)
- `POST /api/v1/orgs/{org_id}/alert-rules/validate` — syntax validation (viewer+)
- `GET /api/v1/orgs/{org_id}/alert-rules/{id}` — detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}/alert-rules/{id}` — update (member+)
- `DELETE /api/v1/orgs/{org_id}/alert-rules/{id}` — delete (member+)
- `POST /api/v1/orgs/{org_id}/alert-rules/{id}/dry-run` — test against current data (viewer+)
- `GET /api/v1/orgs/{org_id}/alert-rules/{id}/channels` — list bound channels (viewer+)
- `PUT /api/v1/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}` — bind channel (member+)
- `DELETE /api/v1/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}` — unbind channel (member+)
```

**Alert events (flat, not nested under rules):**
```
- `GET /api/v1/orgs/{org_id}/alert-events` — list (viewer+, filters: ?rule_id=, ?cve_id=, ?last_match_state=, ?since=)
```

**Deliveries (flat, not nested under channels):**
```
- `GET /api/v1/orgs/{org_id}/deliveries` — list (viewer+, filters: ?channel_id=, ?rule_id=, ?status=)
- `GET /api/v1/orgs/{org_id}/deliveries/{id}` — detail (viewer+)
- `POST /api/v1/orgs/{org_id}/deliveries/{id}/replay` — re-enqueue failed delivery (admin+)
```

**Reports:**
```
- `GET /api/v1/orgs/{org_id}/reports` — list (viewer+)
- `POST /api/v1/orgs/{org_id}/reports` — create (member+)
- `GET /api/v1/orgs/{org_id}/reports/{id}` — detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}/reports/{id}` — update (member+)
- `DELETE /api/v1/orgs/{org_id}/reports/{id}` — delete (member+)
- `GET /api/v1/orgs/{org_id}/reports/{id}/channels` — list bound channels (viewer+)
- `PUT /api/v1/orgs/{org_id}/reports/{id}/channels/{channel_id}` — bind channel (member+)
- `DELETE /api/v1/orgs/{org_id}/reports/{id}/channels/{channel_id}` — unbind channel (member+)
```

**AI (viewer+):**
```
- `POST /api/v1/orgs/{org_id}/ai/nl-search` — natural language → CVE search
- `POST /api/v1/orgs/{org_id}/ai/summarize/{cve_id}` — CVE summarization
```

**Saved searches:**
```
- `GET /api/v1/orgs/{org_id}/saved-searches` — list (viewer+)
- `POST /api/v1/orgs/{org_id}/saved-searches` — create (member+)
- `GET /api/v1/orgs/{org_id}/saved-searches/{id}` — detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}/saved-searches/{id}` — update (member+)
- `DELETE /api/v1/orgs/{org_id}/saved-searches/{id}` — delete (member+)
- `POST /api/v1/orgs/{org_id}/saved-searches/{id}/execute` — execute (viewer+)
```

**Groups:**
```
- `GET /api/v1/orgs/{org_id}/groups` — list (viewer+)
- `POST /api/v1/orgs/{org_id}/groups` — create (admin+)
- `GET /api/v1/orgs/{org_id}/groups/{group_id}` — detail (viewer+)
- `PATCH /api/v1/orgs/{org_id}/groups/{group_id}` — update (admin+)
- `DELETE /api/v1/orgs/{org_id}/groups/{group_id}` — delete (admin+)
- `GET /api/v1/orgs/{org_id}/groups/{group_id}/members` — list members (viewer+)
- `POST /api/v1/orgs/{org_id}/groups/{group_id}/members` — add member (admin+)
- `DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members/{user_id}` — remove member (admin+)
```

**SSO connections (owner only, enterprise tier):**
```
- `POST /api/v1/orgs/{org_id}/sso` — create SSO connection (owner)
- `GET /api/v1/orgs/{org_id}/sso` — get SSO connection (owner)
- `PATCH /api/v1/orgs/{org_id}/sso` — update SSO connection (owner)
- `DELETE /api/v1/orgs/{org_id}/sso` — delete SSO connection (owner)
- `PUT /api/v1/orgs/{org_id}/sso/domains` — set email domains for SSO (owner)
- `GET /api/v1/orgs/{org_id}/sso/link` — init identity linking (member+)
```

**Audit log (admin+, enterprise tier):**
```
- `GET /api/v1/orgs/{org_id}/audit-log` — list audit entries (admin+)
```

**Step 2: Remove obsolete Appendix B entries**

Remove these specced-but-not-implemented entries that were replaced by better designs:
- `GET /api/v1/orgs/{org_id}/alert-rules/{id}/events` → replaced by flat `/alert-events`
- `GET /api/v1/orgs/{org_id}/channels/{id}/deliveries` → replaced by flat `/deliveries`
- `POST /api/v1/orgs/{org_id}/channels/{id}/deliveries/{delivery_id}/replay` → replaced by `/deliveries/{id}/replay`
- `GET/POST /api/v1/orgs/{org_id}/members` (invite via POST) → replaced by `/invitations` sub-resource

Remove specced-but-deferred items (already documented in Appendix A of this plan):
- `GET/PATCH /api/v1/orgs/{org_id}/cves/{cve_id}/annotations` (CVE annotations — deferred)
- `GET /api/v1/watchlist-templates` + `POST .../from-template` (watchlist templates — deferred)

**Step 3: Update channel permissions note**

Update the channels section to note that CRUD requires admin/owner role (matching §7.3 and the Task 9 fix).

**Step 4: Verify consistency. Commit.**

```bash
git add PLAN.md
git commit -m "docs: rewrite Appendix B to match implemented API — comprehensive endpoint inventory"
```

---

### Task 11: Fix PLAN.md internal inconsistencies

**Files:**
- Modify: `PLAN.md`

**Audit note (2026-03-08):** Two items from the original plan were false positives and have been removed:
- ~~GAP-022 (user_identities scope)~~: Already correctly listed under "Org/Tenant scoped" in §4.2.
- ~~GAP-019 (stale RLS note in §19)~~: The "deferred to P1" text is historical context in the resolved research backlog, not a stale requirement. §6.2 correctly documents the actual implementation.

**Step 1: Fix CVE status enum (GAP-021)**

In §4.3, the `cves.status` definition lists `new|modified|analyzed|rejected|unknown`. Add `withdrawn` to the enum — it's used by OSV/GHSA for retracted advisories, and the evaluator (§10.3) already filters `NOT IN ('rejected', 'withdrawn')`.

Change to: `new|modified|analyzed|rejected|withdrawn|unknown`

**Step 2: Remove corrupt job_queue fragment (GAP-023)**

In §18.1 (around lines 1637-1640), there are orphaned SQL fragments after the "Alternatives (revisit later)" bullet list:
```
ptz,
    last_error  text
);
```
These are leftover from a document corruption — the complete `job_queue` schema is correctly defined earlier in §18.1. Delete these orphaned lines and the dangling closing ``` fence.

**Step 3: Fix "Phase 6" references (GAP-020)**

§3.2 (line 209) defers NVD attribution to "Phase 6 (UI)." The frontend is now implemented. Change the reference to: "deferred until frontend implementation" or "see §20 (frontend)". Also fix the §18.3 comment "CSP — set per-response type when frontend is added (Phase 6+)" — the frontend is added; update this note.

**Step 4: Update §18 phase summary**

§18 currently defines Phases 0-5 only. Add entries for Phase 6 (this plan — backend cleanup & production readiness) and note that the frontend was implemented alongside Phase 5 work. Also expand Phase 5's description to reflect what was actually built (it currently just says "audit log, billing hooks, SSO" but Phase 5 also delivered tiering, data retention, vendor feed enrichment, and site admin).

Update Phase 5:
```
**Phase 5 — Hardening and SaaS readiness**
- Org tiering with resolved limits + tier-gated middleware
- Data retention automation (bounded-batch cleanup, tier-aware windows)
- Audit logging with non-blocking writes + secret redaction
- SSO/OIDC connections + email domain discovery + identity linking
- Vendor feed enrichment (MSRC, Red Hat) + site admin role for feed management
```

Add Phase 6:
```
**Phase 6 — Backend cleanup & production readiness**
- Security hardening: password reset, email verification, account lockout, CORS
- Missing workflows: invite-only bootstrap fix, invitation emails, channel test endpoint
- RBAC fix: channel mutations restricted to admin/owner per §7.3
- PLAN.md reconciliation: Appendix B rewrite, internal inconsistency fixes
```

**Step 5: Commit.**

```bash
git add PLAN.md
git commit -m "docs: fix PLAN.md internal inconsistencies — status enum, corrupt fragment, phase tracker"
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
| SAML SSO support | GAP-003 | LOW | Phase 5D implemented generic OIDC SSO with identity linking. SAML support (`crewjam/saml`) is enterprise-specific and can be added when demanded. |

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
| Admin feed re-run behavior details | GAP-017 | LOW | Basic trigger exists (Phase 5f admin feeds). Full spec (cursor reset, full re-sync) needs design based on operator needs. |

### Billing & SaaS

| Item | Gap Ref | Severity | Why Deferred |
|------|---------|----------|--------------|
| Billing hooks | GAP-014 | MEDIUM (SaaS) | Payment integration, billing cycles, downgrade handling. Entirely SaaS-specific — self-hosted deployments don't need this. Should be designed alongside SaaS launch. |
| NVD attribution notice | GAP-001 | LOW | NVD Terms of Use require a display notice. Frontend now exists — this is a small UI addition (footer text or about page). No backend work needed. |

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
| Site admin via `is_site_admin` flag (supersedes original "admin in any org" design) | Phase 5f implemented a dedicated `users.is_site_admin` boolean (migration 000030) with `RequireSiteAdmin()` middleware. Cleaner than the original plan's "admin/owner in any org" approach — separates site-level privileges from org-level RBAC. |
| Channel RBAC: admin not member | Channels affect all org members. PLAN.md §7.3 explicitly restricts channel management to admin/owner. The member-level access was a bug. |
| Admin feed re-run via job queue (async, 202) | Feed syncs can take minutes (NVD full sync). Synchronous response would time out. Job queue's lock_key prevents duplicate concurrent runs. |
| Invite-only bootstrap: allow first registration regardless of mode | The alternative (CLI `create-admin` command) requires shell access, which is more complex for containerized deployments. Allowing the first registration is the smallest fix, works in all deployment models, and is self-documenting (first user = admin). |
| Invitation email: best-effort, don't fail request on SMTP error | Invitation record is the source of truth. If SMTP fails, admin can share the link manually or resend. Failing the entire invitation because of a transient SMTP issue is worse UX. |
