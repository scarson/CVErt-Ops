# Phase 6 Bug Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 25 bugs identified by bug hunters across Phase 6A (security hardening) and Phase 6B (missing features). Two findings (A10, A11) are explicitly accepted/deferred — see notes in the relevant tasks.

**Test patterns:** Each test file has its own server constructor (e.g., `newPasswordResetServer(t)`, `newEmailVerificationServer(t)`). HTTP helpers use the pattern `doRegister(t, ctx, ts, email, password)` and manual `http.NewRequestWithContext`. Tests in this plan use pseudocode for readability — the executing engineer must adapt to match the existing helper patterns in each test file.

**Architecture:** All fixes are localized to existing files — no new packages. Fixes touch handlers, store methods, SQL queries, and middleware. Each task groups related findings by component to minimize context switching. Every fix follows TDD: write failing test first, then fix.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, huma, chi, argon2id

---

## Why Our Tests Missed These Bugs

Before diving in, understanding the test gaps prevents repeating them:

1. **No concurrency tests for multi-step flows** — Tests verified sequential behavior (submit token → success) but never tested two concurrent requests racing through the same flow. TOCTOU bugs (A3, B1, B2, A10) are invisible to sequential tests.

2. **No negative-property tests** — Tests verified "lockout works" but never verified "lockout cleans up after itself" or "lockout treats email case-insensitively." The absence of bad behavior isn't tested by testing the presence of good behavior.

3. **No error-path differentiation tests** — Tests checked "unknown user → 200" but never checked "DB error on known-user-specific query → also 200 (not 500)." Information leakage bugs (A5) live in the distinction between error paths.

4. **Validation asymmetry between create and update** — Create handlers were tested for empty names; PATCH handlers weren't tested with the same invalid inputs. The assumption was "if create validates, patch does too."

5. **No resource leak / growth tests** — The lockout map was tested for correctness but never for bounded growth. Long-running process properties (A1) need explicit tests.

6. **Mocked-away boundaries** — Some tests never hit the real DB concurrency behavior because each test runs in isolation. Concurrent accept (B2) needs a test that actually races two goroutines.

---

## Task 1: Lockout Manager — Cleanup + Case-Folding

**Fixes:** A1 (unbounded memory growth), A2 (email case bypass)

**Why tests missed it:** No test for memory growth over time. No test for case-insensitive email handling.

**Files:**
- Modify: `internal/api/lockout.go`
- Modify: `internal/api/server.go` (add Stop/cleanup lifecycle)
- Modify: `internal/api/lockout_test.go`

**Step 1: Write failing tests**

Add to `lockout_test.go`:

```go
func TestLockout_CaseInsensitive(t *testing.T) {
	// A2: email case variation should NOT bypass lockout
	now := time.Now()
	m := newLockoutManager(3, 15*time.Minute, func() time.Time { return now })

	m.RecordFailure("Victim@Example.com")
	m.RecordFailure("victim@example.com")
	m.RecordFailure("VICTIM@EXAMPLE.COM")

	// All three should count toward the SAME email — should be locked now
	allowed, _ := m.Check("victim@example.com")
	if allowed {
		t.Fatal("lockout should trigger regardless of email casing")
	}
}

func TestLockout_CleanupEvictsStaleEntries(t *testing.T) {
	// A1: sub-threshold entries must be cleaned up eventually.
	// The lockout manager takes a separate evictTTL (like ipRateLimiter).
	now := time.Now()
	evictTTL := 5 * time.Minute
	m := newLockoutManager(5, 15*time.Minute, evictTTL, func() time.Time { return now })

	// Create 100 entries with 1 failure each (below threshold)
	for i := 0; i < 100; i++ {
		m.RecordFailure(fmt.Sprintf("spam-%d@example.com", i))
	}

	if m.Len() != 100 {
		t.Fatalf("expected 100 entries, got %d", m.Len())
	}

	// Advance time past evictTTL and run cleanup
	now = now.Add(6 * time.Minute)
	m.evictStale()

	if m.Len() != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", m.Len())
	}
}

func TestLockout_CleanupPreservesActiveLockouts(t *testing.T) {
	now := time.Now()
	evictTTL := 5 * time.Minute
	m := newLockoutManager(3, 15*time.Minute, evictTTL, func() time.Time { return now })

	// Create a locked account (above threshold)
	for i := 0; i < 3; i++ {
		m.RecordFailure("locked@example.com")
	}
	// Create a stale sub-threshold entry
	m.RecordFailure("stale@example.com")

	// Advance time past evictTTL (stale entry > 5 min) but NOT past lockout duration (15 min)
	now = now.Add(6 * time.Minute)
	m.evictStale()

	// Active lockout should be preserved (still within lockout duration)
	allowed, _ := m.Check("locked@example.com")
	if allowed {
		t.Fatal("active lockout should survive cleanup")
	}

	// Stale sub-threshold entry should be evicted (lastActivity > evictTTL)
	if m.Len() != 1 {
		t.Fatalf("expected 1 entry (active lockout only), got %d", m.Len())
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run "TestLockout_CaseInsensitive|TestLockout_Cleanup" -v`
Expected: FAIL — `Len()` and `evictStale()` don't exist; case-insensitive test fails.

**Step 3: Implement fixes in lockout.go**

Changes to `lockout.go`:
1. Add `strings.ToLower(email)` in `Check`, `RecordFailure`, `RecordSuccess` — normalize map key.
2. Add `Len() int` method — returns `len(m.attempts)` under lock (for testing).
3. Add `evictTTL time.Duration` field to `lockoutManager` — separate from lockout `duration`, mirrors `ipRateLimiter.evictTTL`.
4. Add `evictStale()` method — removes entries where `lastActivity` is older than `evictTTL` and `count < threshold`. Also removes expired lockouts (`lockedAt + duration < now`).
5. Add `lastActivity time.Time` field to `loginAttempt` struct — set on every `RecordFailure`.
6. Add `cleanupLoop()` goroutine — runs `evictStale()` every `evictTTL/2`, mirrors `ipRateLimiter.cleanupLoop()`.
7. Add `done chan struct{}` field and `Stop()` method — mirrors `ipRateLimiter` pattern.
8. Update `newLockoutManager` signature to accept `evictTTL` parameter.

Changes to `server.go`:
9. Pass `evictTTL` to `newLockoutManager` (e.g., `lockoutDuration` as the evict TTL — entries idle longer than the lockout window can be safely evicted).
10. Start cleanup goroutine inside `newLockoutManager` constructor (like `newIPRateLimiter`).
11. Add `srv.lockout.Stop()` to `Server.Close()`.

**Update existing tests:** The `newLockoutManager` signature changes to include `evictTTL`. Update existing lockout test calls to pass the new parameter.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -run "TestLockout" -v`
Expected: All lockout tests PASS (including existing ones — case-folding must not break them).

**Step 5: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 6: Commit**

```bash
git add internal/api/lockout.go internal/api/lockout_test.go internal/api/server.go
git commit -m "fix(lockout): add cleanup goroutine and case-insensitive email keys

Fixes unbounded memory growth from sub-threshold entries (A1) and
lockout bypass via email case variation (A2)."
```

---

## Task 2: Password Reset — Atomic Token Consumption + Error Path Fixes

**Fixes:** A3 (TOCTOU on concurrent token use), A4 (incorrect safety comment), A5 (500 errors leak user existence)

**Accepted risk — A10 (concurrent forgot-password rate limit bypass):** The count-then-insert TOCTOU allows a burst of concurrent requests to exceed the per-user token limit. This is bounded by the IP rate limiter (10/min) and all tokens go to the same legitimate email. The fix would require `INSERT ... SELECT ... HAVING count < max` which adds complexity. Accept the race — document it with a code comment.

**Why tests missed it:** No concurrent test for token use. No test distinguishing 500 vs 200 on post-lookup DB errors. Sequential tests can't observe TOCTOU.

**Files:**
- Modify: `internal/store/queries/password_reset.sql` (new atomic query)
- Modify: `internal/store/password_reset.go` (new store method)
- Modify: `internal/api/auth_password_reset.go` (use atomic method, fix error paths)
- Modify: `internal/api/auth_password_reset_test.go`
- Run: `sqlc generate` after SQL changes

**Step 1: Write failing tests**

Add to `auth_password_reset_test.go`:

```go
func TestResetPassword_ConcurrentUse(t *testing.T) {
	// A3: Two concurrent reset-password requests with the same token should
	// not both succeed. The second should get "invalid or expired reset token".
	//
	// Adapt to match existing test patterns: use newPasswordResetServer(t),
	// doRegister(), and manual HTTP requests. Extract reset token from DB
	// (query password_reset_tokens by user_id, decode for the HTTP request).
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	// Register a user and request password reset.
	doRegister(t, ctx, ts, "concurrent@example.com", "password1234567890")
	// POST /auth/forgot-password
	// ... (manual HTTP request, same pattern as TestForgotPassword_ExistingUser)

	// Extract token hex from DB: query the token_hash, then use it directly
	// in the reset request (the handler accepts hex-encoded token, not the hash).
	// Alternative: query the raw token bytes from DB for testing.
	// NOTE: The actual token hex is only in the email. For test purposes,
	// insert a known token via DB helper or capture from Mailpit.

	// Race two reset requests using a barrier for reliable concurrency.
	ready := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready // wait for barrier
			// POST /auth/reset-password with token and new password
			// ... (manual HTTP request)
			results[idx] = resp.StatusCode
		}(i)
	}
	close(ready) // release both goroutines simultaneously
	wg.Wait()

	// Exactly one should succeed (200), one should fail (400).
	successes := 0
	for _, code := range results {
		if code == 200 {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d (status codes: %v)", successes, results)
	}
}
```

**Note on A5 (forgotPasswordHandler error paths):** This fix changes 500→200 on post-lookup DB errors. It's hard to test in integration without DB fault injection. The fix is verified by code inspection. Existing `TestForgotPassword_ExistingUser` and `_NonexistentUser` serve as regression tests for normal paths.

**Step 2: Run tests to verify the concurrent test fails**

Run: `go test ./internal/api/ -run "TestResetPassword_ConcurrentUse" -v -count=1`
Expected: FAIL — both requests succeed (both get 200).

**Step 3: Fix the SQL — atomic consume-and-return**

Add to `password_reset.sql`:

```sql
-- name: ConsumePasswordResetToken :one
-- Atomically marks a token as used and returns it, preventing concurrent use.
UPDATE password_reset_tokens
SET used_at = now()
WHERE id = (
    SELECT id FROM password_reset_tokens
    WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id, user_id, expires_at, used_at, created_at;
```

Run: `sqlc generate`

**Step 4: Update store method**

Add to `internal/store/password_reset.go`:

```go
// ConsumePasswordResetToken atomically looks up a valid token and marks it used.
// Returns (nil, nil) if the token doesn't exist, is expired, or was already consumed.
func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*generated.PasswordResetToken, error) {
	var tok *generated.PasswordResetToken
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.ConsumePasswordResetToken(ctx, tokenHash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tok = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("consume password reset token: %w", err)
	}
	return tok, nil
}
```

**Step 5: Update resetPasswordHandler to use atomic method**

Replace the three-step flow (lookup → update password → mark used) with:
1. `ConsumePasswordResetToken` (atomic lookup + mark used)
2. `UpdatePasswordHash` (change password)

Remove the separate `MarkPasswordResetTokenUsed` call and the incorrect safety comment (A4).

Updated `resetPasswordHandler` core logic:

```go
	// Atomically consume the token (lookup + mark used in one statement).
	tok, err := srv.store.ConsumePasswordResetToken(ctx, tokenHash[:])
	if err != nil {
		slog.ErrorContext(ctx, "reset-password: consume token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if tok == nil {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
	}

	// Hash the new password.
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	defer srv.releaseArgon2()  // A7: use defer (also fixes argon2 leak in this handler)
	newHash, err := auth.HashPassword(input.Body.NewPassword)
	if err != nil {
		slog.ErrorContext(ctx, "reset-password: hash password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Update the password (also increments token_version, invalidating all sessions).
	if err := srv.store.UpdatePasswordHash(ctx, tok.UserID, newHash, 1); err != nil {
		slog.ErrorContext(ctx, "reset-password: update password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
```

**Step 6: Fix forgotPasswordHandler error paths (A5)**

Change lines 94-96 and 112-114 to return `out, nil` instead of `huma.Error500`:

```go
	count, err := srv.store.CountRecentPasswordResetTokens(ctx, user.ID, time.Now().Add(-1*time.Hour))
	if err != nil {
		slog.ErrorContext(ctx, "forgot-password: count recent tokens", "error", err)
		return out, nil // Return 200 to preserve anti-enumeration invariant
	}
	// ...
	if err := srv.store.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		slog.ErrorContext(ctx, "forgot-password: create token", "error", err)
		return out, nil // Return 200 to preserve anti-enumeration invariant
	}
```

**Step 7: Run tests**

Run: `go test ./internal/api/ -run "TestResetPassword|TestForgotPassword" -v -count=1`
Expected: All PASS, including concurrent test.

**Step 8: Run linter**

Run: `golangci-lint run ./internal/api/ ./internal/store/`

**Step 9: Commit**

```bash
git add internal/store/queries/password_reset.sql internal/store/password_reset.go \
  internal/store/generated/ internal/api/auth_password_reset.go \
  internal/api/auth_password_reset_test.go
git commit -m "fix(auth): atomic password reset token consumption, fix enumeration leak

- A3: ConsumePasswordResetToken atomically marks token used (prevents TOCTOU)
- A4: Remove incorrect safety comment about token_version
- A5: forgotPasswordHandler returns 200 on all post-lookup errors
- A7: Use defer for argon2 release in resetPasswordHandler
- A10: Accept concurrent rate limit race (bounded by IP limiter) — added code comment"
```

---

## Task 3: Argon2 Semaphore — Defer Fix in Login and ChangePassword

**Fixes:** A7 (missing defer on argon2 release — remaining handlers)

**Why tests missed it:** Panics during argon2 operations are extremely rare; no panic-injection test existed.

**Files:**
- Modify: `internal/api/auth.go` (loginHandler, changePasswordHandler)
- Modify: `internal/api/auth_test.go`

**Step 1: Apply defer fix to loginHandler**

No new test needed — the fix is mechanical (`explicit release` → `defer`). Existing `TestLogin*` and `TestChangePassword*` tests serve as regression tests since they exercise the acquire/release paths.

**Step 1a: Apply defer fix to loginHandler**

In `auth.go`, the login handler has TWO argon2 sections. Both need `defer`, but since they're sequential within the same function, we need a helper pattern. The cleanest approach: wrap each section so `defer` scopes correctly.

Actually, looking at the code more carefully: the two argon2 sections in login are mutually exclusive (one for non-existent user timing normalization, one for actual verification). And in changePassword, the two calls are sequential. Since `defer` runs at function exit, not block exit, we can't naively add `defer` to both.

The fix for login: both branches are short — acquire, call, release, return. The release-then-return pattern is fine for the non-panic case; the risk is only on panic. Use inline functions:

```go
	// Timing normalization path
	if user == nil || !user.PasswordHash.Valid {
		if !srv.acquireArgon2() {
			return nil, huma.Error503ServiceUnavailable("server busy, please retry")
		}
		func() {
			defer srv.releaseArgon2()
			_, _ = auth.VerifyPassword(input.Body.Password, dummyPasswordHash)
		}()
		srv.lockout.RecordFailure(input.Body.Email)
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	// Actual verification path
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	var ok bool
	func() {
		defer srv.releaseArgon2()
		ok, err = auth.VerifyPassword(input.Body.Password, user.PasswordHash.String)
	}()
```

Same pattern for changePasswordHandler's two sequential argon2 calls.

**Step 2: Run tests**

Run: `go test ./internal/api/ -run "TestLogin|TestChangePassword" -v -count=1`
Expected: All PASS.

**Step 3: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 4: Commit**

```bash
git add internal/api/auth.go
git commit -m "fix(auth): use defer for argon2 semaphore release in login and change-password

Prevents permanent semaphore slot leak if HashPassword or VerifyPassword
panics. Uses inline func() to scope defer correctly for sequential calls."
```

---

## Task 4: Email Verification — Per-User Rate Limit + Error Response + Async Send

**Fixes:** A6 (no per-user rate limit on resend), A8 (claims "email sent" on failure)

**Intentionally not fixed — A11 (sync vs async email send):** Making `sendVerificationEmail` async would conflict with A8 (reporting errors to the user). The resend endpoint is authenticated — no timing-oracle risk. Keeping it synchronous is an intentional design choice. The asymmetry with forgot-password (async) is acceptable: forgot-password is unauthenticated (must normalize timing), resend-verification is authenticated (can block on SMTP).

**Why tests missed it:** No test for repeated resend attempts. No test checking response message when SMTP fails.

**Files:**
- Modify: `internal/store/queries/email_verification.sql` (add count query)
- Modify: `internal/store/email_verification.go` (add count method)
- Modify: `internal/api/auth_email_verification.go` (add rate limit, fix response, async send)
- Modify: `internal/api/auth_email_verification_test.go`
- Modify: `internal/config/config.go` (add `EmailVerificationMaxPerHour` if not present)
- Run: `sqlc generate`

**Step 1: Write failing tests**

Add to `auth_email_verification_test.go`:

```go
func TestResendVerification_RateLimit(t *testing.T) {
	// A6: per-user rate limit should prevent spam resends.
	// Adapt to use newEmailVerificationServer(t) and doRegister/doLogin patterns.
	//
	// IMPORTANT: Registration itself creates 1 verification token via
	// sendVerificationEmail(). Set EmailVerificationMaxPerHour = 4 so
	// the test can do 3 resends (total 4 tokens) before hitting the limit.
	// The 4th resend (5th token overall) should be rate-limited.
	db, ts := newEmailVerificationServerWithLimit(t, 4) // custom helper
	ctx := context.Background()

	doRegister(t, ctx, ts, "ratelimit@example.com", "password1234567890")
	accessToken := doLogin(t, ctx, ts, "ratelimit@example.com", "password1234567890")

	// Send 3 resends (tokens 2, 3, 4 — registration was token 1).
	for i := 0; i < 3; i++ {
		// POST /auth/resend-verification with access_token cookie
		// ... (manual HTTP request)
		if resp.StatusCode != 200 {
			t.Fatalf("resend %d: expected 200, got %d", i+1, resp.StatusCode)
		}
	}

	// The 4th resend (5th token total) should be rate-limited.
	// Returns 200 with rate-limit message (not 429 — consistent with
	// password reset pattern where rate-limited requests return 200).
	// ... (manual HTTP request)
	// Parse response body and check message != "Verification email sent."
}

func TestResendVerification_SMTPFailure_ReturnsError(t *testing.T) {
	// A8: when SMTP fails, the response should NOT claim "email sent".
	// This is an authenticated endpoint — no enumeration risk.
	//
	// Create a server with SMTP pointed at an invalid host.
	// Use port 0 to get immediate connection refused (not a slow timeout).
	db := testutil.NewTestDB(t)
	cfg := &config.Config{ /* ... standard fields ... */
		SMTPHost: "127.0.0.1",
		SMTPPort: 1, // port 1 — connection refused immediately
	}
	// ... build server, register user, login, call resend-verification ...
	// Assert response does NOT contain "Verification email sent"
	// and status is 500 (SMTP failure surfaced to authenticated user).
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run "TestResendVerification_RateLimit|TestResendVerification_SMTPFailure" -v -count=1`
Expected: FAIL — no per-user rate limit; "Verification email sent" returned on SMTP failure.

**Step 3: Add SQL query for counting recent verification tokens**

Add to `email_verification.sql`:

```sql
-- name: CountRecentEmailVerificationTokens :one
SELECT COUNT(*) FROM email_verification_tokens
WHERE user_id = $1 AND created_at > $2;
```

Run: `sqlc generate`

**Step 4: Add store method**

Add to `internal/store/email_verification.go`:

```go
// CountRecentEmailVerificationTokens returns how many tokens were created
// for the given user since the cutoff time.
func (s *Store) CountRecentEmailVerificationTokens(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	var count int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		count, err = q.CountRecentEmailVerificationTokens(ctx, generated.CountRecentEmailVerificationTokensParams{
			UserID:    userID,
			CreatedAt: since,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count recent email verification tokens: %w", err)
	}
	return count, nil
}
```

**Step 5: Update resendVerificationHandler**

1. Add per-user rate limit check (matching password reset pattern).
2. Return error when `sendVerificationEmail` fails (A8 — this is authenticated, no enumeration risk).

Updated handler:

```go
func (srv *Server) resendVerificationHandler(ctx context.Context, input *resendVerificationInput) (*resendVerificationOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}
	// ... parse token, get user (existing code) ...

	if user.EmailVerified {
		return &resendVerificationOutput{Body: struct {
			Message string `json:"message"`
		}{Message: "Email already verified."}}, nil
	}

	// Per-user rate limit (A6): match the password reset pattern.
	count, err := srv.store.CountRecentEmailVerificationTokens(ctx, user.ID, time.Now().Add(-1*time.Hour))
	if err != nil {
		slog.ErrorContext(ctx, "resend-verification: count recent tokens", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if int(count) >= srv.cfg.EmailVerificationMaxPerHour {
		return &resendVerificationOutput{Body: struct {
			Message string `json:"message"`
		}{Message: "Please wait before requesting another verification email."}}, nil
	}

	// Send verification email. Report failure to the authenticated user (A8).
	if err := srv.sendVerificationEmail(ctx, user.ID, user.Email); err != nil {
		slog.ErrorContext(ctx, "resend-verification: send email", "error", err)
		return nil, huma.Error500InternalServerError("failed to send verification email")
	}

	return &resendVerificationOutput{Body: struct {
		Message string `json:"message"`
	}{Message: "Verification email sent."}}, nil
}
```

**Step 6: Add config field if needed**

Check if `EmailVerificationMaxPerHour` exists in config. If not, add with default 3 (matching password reset).

**Step 7: Run tests**

Run: `go test ./internal/api/ -run "TestResendVerification" -v -count=1`
Expected: All PASS.

**Step 8: Run linter**

Run: `golangci-lint run ./internal/api/ ./internal/store/`

**Step 9: Commit**

```bash
git add internal/store/queries/email_verification.sql internal/store/email_verification.go \
  internal/store/generated/ internal/api/auth_email_verification.go \
  internal/api/auth_email_verification_test.go internal/config/config.go
git commit -m "fix(auth): add per-user rate limit to resend-verification, fix error response

- A6: CountRecentEmailVerificationTokens rate limit (matching password reset)
- A8: Return error instead of claiming email sent when SMTP fails (authenticated endpoint)
- A11: Intentionally kept synchronous (conflicts with A8; no timing-oracle risk)"
```

---

## Task 5: CORS — Validate Wildcard with Credentials

**Fixes:** A12 (wildcard origin with credentials)

**Why tests missed it:** Tests verified CORS worked with specific origins but never tested the dangerous `*` + credentials combination.

**Files:**
- Modify: `internal/api/cors.go`
- Modify: `internal/api/middleware_cors_test.go`

**Step 1: Write failing test**

Add to `middleware_cors_test.go`:

```go
func TestCORS_WildcardWithCredentials_Rejected(t *testing.T) {
	// A12: Setting CORS_ALLOWED_ORIGINS=* with AllowCredentials=true is dangerous.
	// The middleware should reject this configuration at startup.
	cfg := &config.Config{
		CORSAllowedOrigins: "*",
	}
	srv := &Server{cfg: cfg}
	middleware := srv.corsMiddleware()

	// Wildcard should be rejected — middleware should be nil or origins should be empty.
	if middleware != nil {
		t.Fatal("CORS middleware should reject wildcard origin (security risk with credentials)")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run "TestCORS_WildcardWithCredentials" -v`
Expected: FAIL — middleware is returned (wildcard is not rejected).

**Step 3: Fix corsOrigins to reject wildcard**

In `cors.go`, add validation in `corsOrigins()`:

```go
func (srv *Server) corsOrigins() []string {
	if srv.cfg.CORSAllowedOrigins != "" {
		parts := strings.Split(srv.cfg.CORSAllowedOrigins, ",")
		origins := make([]string, 0, len(parts))
		for _, p := range parts {
			o := strings.TrimSpace(p)
			if o == "*" {
				slog.Warn("CORS: wildcard origin '*' rejected — incompatible with AllowCredentials")
				continue
			}
			if o != "" {
				origins = append(origins, o)
			}
		}
		return origins
	}
	// ... dev defaults unchanged ...
}
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestCORS" -v`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 6: Commit**

```bash
git add internal/api/cors.go internal/api/middleware_cors_test.go
git commit -m "fix(cors): reject wildcard origin with credentials

Wildcard + AllowCredentials allows any website to make credentialed
cross-origin requests. Log warning and skip the wildcard entry."
```

---

## Task 6: Store Transaction Convention Fixes

**Fixes:** A9 (UpdatePasswordHash bypasses tx helpers), B12 (CountUsers, CreateUser, GetOrgByID bypass tx helpers)

**Why tests missed it:** These work correctly today because `users` and `organizations` don't have RLS. The convention violation is preventive — tests can't catch future breakage.

**Files:**
- Modify: `internal/store/auth.go`
- Modify: `internal/store/org.go`

**Step 1: Write test to verify convention**

This is a convention fix — existing tests serve as regression. No new failing test needed, but verify existing tests pass after the change.

**Step 2: Fix UpdatePasswordHash**

In `store/auth.go`, wrap in `withBypassTx`:

```go
func (s *Store) UpdatePasswordHash(ctx context.Context, id uuid.UUID, passwordHash string, hashVersion int) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpdatePasswordHash(ctx, generated.UpdatePasswordHashParams{
			ID:                  id,
			PasswordHash:        sql.NullString{String: passwordHash, Valid: passwordHash != ""},
			PasswordHashVersion: int32(hashVersion), //nolint:gosec // hashVersion is a small constant (1-255)
		})
	})
}
```

**Step 3: Fix CountUsers and CreateUser**

In `store/auth.go`:

```go
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountUsers(ctx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func (s *Store) CreateUser(ctx context.Context, email, displayName, passwordHash string, hashVersion int) (*generated.User, error) {
	var user *generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.CreateUser(ctx, generated.CreateUserParams{
			Email:               email,
			DisplayName:         displayName,
			PasswordHash:        sql.NullString{String: passwordHash, Valid: passwordHash != ""},
			PasswordHashVersion: int32(hashVersion), //nolint:gosec // hashVersion is a small constant (1-255)
		})
		if err != nil {
			return err
		}
		user = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}
```

**Step 4: Fix GetOrgByID**

In `store/org.go`:

```go
func (s *Store) GetOrgByID(ctx context.Context, id uuid.UUID) (*generated.Organization, error) {
	var org *generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetOrgByID(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		org = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get org by id: %w", err)
	}
	return org, nil
}
```

**Step 5: Run ALL tests**

Run: `go test ./internal/... -count=1`
Expected: All PASS. These are pure wrapping changes — no behavior change.

**Step 6: Run linter**

Run: `golangci-lint run ./internal/...`

**Step 7: Commit**

```bash
git add internal/store/auth.go internal/store/org.go
git commit -m "fix(store): wrap auth and org methods in transaction helpers

Convention compliance: CountUsers, CreateUser, UpdatePasswordHash,
GetOrgByID now use withBypassTx. Prevents breakage if RLS is added."
```

---

## Task 7: Bootstrap Race Fix

**Fixes:** B1 (first-user TOCTOU in invite-only mode), B4 (swallowed DB errors), B9 (500 after user committed)

**Why tests missed it:** `TestRegisterInviteOnlyBootstrap` only tests sequential registration. No concurrent test. DB error path never exercised.

**Files:**
- Modify: `internal/api/auth.go` (registerHandler)
- Modify: `internal/store/org.go` (BootstrapFirstUserOrg)
- Modify: `internal/api/auth_test.go`

**Step 1: Write failing test**

Add to `auth_test.go`:

```go
func TestRegister_InviteOnly_ConcurrentBootstrap(t *testing.T) {
	// B1: Two concurrent registrations on a fresh DB in invite-only mode
	// should result in exactly one registered user.
	// Adapt to use newRegisterServer(t, db, "invite-only") pattern.
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "invite-only")
	ctx := context.Background()

	// Use a barrier to ensure both goroutines race simultaneously.
	ready := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready // wait for barrier
			body := fmt.Sprintf(`{"email":"racer%d@example.com","password":"password1234567890"}`, idx)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := ts.Client().Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			results[idx] = resp.StatusCode
		}(i)
	}
	close(ready) // release both goroutines simultaneously
	wg.Wait()

	// Exactly one should succeed (201), one should be rejected (403).
	successes := 0
	for _, code := range results {
		if code == 201 {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful registration, got %d (codes: %v)", successes, results)
	}
}
```

**Note on B4:** `CountUsers` DB error logging is verified by code inspection — the fix adds `slog.ErrorContext` before returning 403. No runtime test needed.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run "TestRegister_InviteOnly_ConcurrentBootstrap" -v -count=5`
Expected: FAIL on at least some runs — both registrations succeed.

**Step 3: Fix the bootstrap race**

Use a server-level mutex to serialize the entire invite-only registration flow (CountUsers → CreateUser → BootstrapFirstUserOrg). This is the pragmatic fix: the race window only exists on the very first request to a fresh instance. The advisory lock in `BootstrapFirstUserOrg` + unique constraint on email provides safety in multi-instance deployments.

In `server.go`, add `bootstrapMu sync.Mutex` to the Server struct.

In `registerHandler`:

```go
	if srv.cfg.RegistrationMode != "open" {
		srv.bootstrapMu.Lock()
		userCount, err := srv.store.CountUsers(ctx)
		if err != nil {
			srv.bootstrapMu.Unlock()
			slog.ErrorContext(ctx, "register: count users", "error", err) // B4
			return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
		}
		if userCount > 0 {
			srv.bootstrapMu.Unlock()
			return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
		}
		// Hold mutex through user creation + bootstrap. Unlock after.
		defer srv.bootstrapMu.Unlock()
	}
```

This serializes the CountUsers → CreateUser → BootstrapFirstUserOrg flow on a single instance. In multi-instance deployments, the advisory lock in `BootstrapFirstUserOrg` + the unique constraint on email still provides safety.

For B9 (500 after user committed): wrap `BootstrapFirstUserOrg` error as non-fatal:

```go
	org, err := srv.store.BootstrapFirstUserOrg(ctx, user.ID, orgName)
	if err != nil {
		slog.ErrorContext(ctx, "register: bootstrap org", "error", err)
		// Non-fatal: user is created and can log in. Org can be created manually.
	}
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestRegister" -v -count=1`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 6: Commit**

```bash
git add internal/api/auth.go internal/api/server.go internal/api/auth_test.go
git commit -m "fix(auth): serialize invite-only bootstrap, log CountUsers errors

- B1: bootstrapMu serializes concurrent first-user registration
- B4: log CountUsers DB errors before returning 403
- B9: treat BootstrapFirstUserOrg failure as non-fatal (user can log in)"
```

---

## Task 8: Channel PATCH — Name Validation

**Fixes:** B3 (PATCH allows empty/whitespace name)

**Why tests missed it:** `TestPatchChannel_PartialUpdate` tested valid updates. No test for empty name on PATCH (only on create).

**Files:**
- Modify: `internal/api/channels.go`
- Modify: `internal/api/channels_test.go`

**Step 1: Write failing test**

Add to `channels_test.go`:

```go
func TestPatchChannel_EmptyName_Rejected(t *testing.T) {
	// B3: PATCH with empty or whitespace-only name should be rejected.
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	orgID, adminToken := createOrgAndGetToken(t, ts)
	channelID := createWebhookChannel(t, ts, orgID, adminToken, "valid-name", "https://example.com/hook")

	// Try patching with empty name
	emptyName := ""
	resp := patchChannel(t, ts, orgID, channelID, adminToken, &patchChannelBody{Name: &emptyName})
	if resp.StatusCode != 422 {
		t.Fatalf("expected 422 for empty name, got %d", resp.StatusCode)
	}

	// Try patching with whitespace-only name
	wsName := "   "
	resp = patchChannel(t, ts, orgID, channelID, adminToken, &patchChannelBody{Name: &wsName})
	if resp.StatusCode != 422 {
		t.Fatalf("expected 422 for whitespace name, got %d", resp.StatusCode)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run "TestPatchChannel_EmptyName" -v`
Expected: FAIL — returns 200 instead of 422.

**Step 3: Add validation to patchChannelHandler**

In `channels.go`, after `if req.Name != nil {`:

```go
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			http.Error(w, "name is required", http.StatusUnprocessableEntity)
			return
		}
		params.Name = *req.Name
	}
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestPatchChannel" -v`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 6: Commit**

```bash
git add internal/api/channels.go internal/api/channels_test.go
git commit -m "fix(channels): reject empty/whitespace name on PATCH

Matches create handler validation. Prevents channels with blank names."
```

---

## Task 9: Org Name Validation

**Fixes:** B6 (org create/update allow whitespace-only names)

**Why tests missed it:** `TestCreateOrg_EmptyName` tests `""` but not `"   "`.

**Files:**
- Modify: `internal/api/orgs.go`
- Modify: `internal/api/orgs_test.go`

**Step 1: Write failing tests**

Add to `orgs_test.go`:

```go
func TestCreateOrg_WhitespaceName(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	token := registerAndLogin(t, ts, "wstest@example.com", "password1234567890")

	resp := createOrg(t, ts, token, "   ")
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for whitespace-only name, got %d", resp.StatusCode)
	}
}

func TestUpdateOrg_WhitespaceName(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	token := registerAndLogin(t, ts, "wsupdate@example.com", "password1234567890")
	orgID := getFirstOrgID(t, ts, token)

	resp := updateOrg(t, ts, token, orgID, "   ")
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for whitespace-only name, got %d", resp.StatusCode)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run "TestCreateOrg_WhitespaceName|TestUpdateOrg_WhitespaceName" -v`
Expected: FAIL — returns 200/201 instead of 400.

**Step 3: Fix validation**

In `orgs.go`, change both handlers:

```go
// createOrgHandler
if strings.TrimSpace(req.Name) == "" {
    http.Error(w, "name is required", http.StatusBadRequest)
    return
}

// updateOrgHandler
if strings.TrimSpace(req.Name) == "" {
    http.Error(w, "name is required", http.StatusBadRequest)
    return
}
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestCreateOrg|TestUpdateOrg" -v`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 6: Commit**

```bash
git add internal/api/orgs.go internal/api/orgs_test.go
git commit -m "fix(orgs): reject whitespace-only org names on create and update

Uses TrimSpace to match channel create validation pattern."
```

---

## Task 10: Invitation Management Fixes

**Fixes:** B7 (duplicate invitations), B8 (cancel returns 204 for non-existent), B10 (sendInvitationEmail swallows nil), B13 (audit logging gaps)

**Why tests missed it:** `TestCancelInvitation_Success` only tests existing invitation. `TestCreateInvitation_Success` never re-invites same email. No test for nil org/inviter in email send. No audit log assertions for invitations.

**Files:**
- Modify: `internal/store/queries/org.sql` (add duplicate check query)
- Modify: `internal/store/org.go` (add store method, fix CancelInvitation)
- Modify: `internal/api/orgs.go` (duplicate check, cancel 404, nil logging, audit)
- Modify: `internal/api/orgs_test.go`
- Run: `sqlc generate`

**Step 1: Write failing tests**

Add to `orgs_test.go`:

```go
func TestCreateInvitation_DuplicatePending(t *testing.T) {
	// B7: Creating a second invitation for the same email should fail.
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	orgID, adminToken := createOrgAndGetAdminToken(t, ts)

	resp := createInvitation(t, ts, orgID, adminToken, "dupe@example.com", "member")
	if resp.StatusCode != 202 {
		t.Fatalf("first invitation: expected 202, got %d", resp.StatusCode)
	}

	resp = createInvitation(t, ts, orgID, adminToken, "dupe@example.com", "member")
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate invitation: expected 409, got %d", resp.StatusCode)
	}
}

func TestCancelInvitation_NotFound(t *testing.T) {
	// B8: Canceling a non-existent invitation should return 404.
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	orgID, adminToken := createOrgAndGetAdminToken(t, ts)
	fakeID := uuid.New().String()

	resp := cancelInvitation(t, ts, orgID, fakeID, adminToken)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for non-existent invitation, got %d", resp.StatusCode)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run "TestCreateInvitation_DuplicatePending|TestCancelInvitation_NotFound" -v`
Expected: FAIL — duplicate returns 202; non-existent cancel returns 204.

**Step 3: Add SQL query for pending invitation check**

Add to `org.sql`:

```sql
-- name: GetPendingInvitationByEmail :one
SELECT id FROM org_invitations
WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL AND expires_at > now()
LIMIT 1;
```

Change `DeleteOrgInvitation` to return affected row count:

```sql
-- name: DeleteOrgInvitation :execresult
DELETE FROM org_invitations WHERE id = $1 AND org_id = $2;
```

Run: `sqlc generate`

**Step 4: Add store methods**

Add to `org.go`:

```go
// HasPendingInvitation checks whether a pending, unexpired invitation exists
// for the given email in the given org.
func (s *Store) HasPendingInvitation(ctx context.Context, orgID uuid.UUID, email string) (bool, error) {
	var exists bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		_, err := q.GetPendingInvitationByEmail(ctx, generated.GetPendingInvitationByEmailParams{
			OrgID: orgID,
			Email: email,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		exists = true
		return nil
	})
	return exists, err
}
```

Update `CancelInvitation` to return whether a row was actually deleted:

```go
func (s *Store) CancelInvitation(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	var deleted bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		result, err := q.DeleteOrgInvitation(ctx, generated.DeleteOrgInvitationParams{
			OrgID: orgID,
			ID:    id,
		})
		if err != nil {
			return fmt.Errorf("cancel invitation: %w", err)
		}
		n, _ := result.RowsAffected()
		deleted = n > 0
		return nil
	})
	return deleted, err
}
```

**Step 5: Update createInvitationHandler**

Add duplicate check after tier gating, before token generation:

```go
	// Check for existing pending invitation (B7).
	hasPending, err := srv.store.HasPendingInvitation(r.Context(), orgID, req.Email)
	if err != nil {
		slog.ErrorContext(r.Context(), "check pending invitation", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if hasPending {
		http.Error(w, "a pending invitation already exists for this email — use resend instead", http.StatusConflict)
		return
	}
```

**Step 6: Update cancelInvitationHandler**

Use the new return value to detect non-existent invitations:

```go
	deleted, err := srv.store.CancelInvitation(r.Context(), orgID, invID)
	if err != nil {
		slog.ErrorContext(r.Context(), "cancel invitation", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !deleted {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
```

**Step 7: Fix sendInvitationEmail nil logging (B10)**

In `orgs.go`, change the silent return to a logged warning:

```go
	if org == nil || inviter == nil {
		slog.WarnContext(ctx, "invitation email: org or inviter not found",
			"org_nil", org == nil, "inviter_nil", inviter == nil,
			"org_id", orgID, "inviter_id", callerID)
		return
	}
```

**Step 8: Add audit logging for invitation management (B13)**

Add audit entries to `createInvitationHandler`, `cancelInvitationHandler`, and `resendInvitationHandler`. Follow the existing pattern from channel/member handlers:

```go
// In createInvitationHandler, after successful creation:
	if srv.auditWriter != nil {
		callerEmail, _ := r.Context().Value(ctxEmail).(string)
		srv.auditWriter.Log(r.Context(), audit.Entry{
			OrgID:      orgID,
			ActorID:    &callerID,
			ActorEmail: callerEmail,
			Action:     "create",
			EntityType: "invitation",
			EntityID:   inv.ID.String(),
			EntityName: inv.Email,
			Success:    true,
			NewState:   map[string]any{"email": inv.Email, "role": inv.Role},
		})
	}

// In cancelInvitationHandler, after successful delete:
	if srv.auditWriter != nil {
		callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
		callerEmail, _ := r.Context().Value(ctxEmail).(string)
		srv.auditWriter.Log(r.Context(), audit.Entry{
			OrgID:      orgID,
			ActorID:    &callerID,
			ActorEmail: callerEmail,
			Action:     "delete",
			EntityType: "invitation",
			EntityID:   invID.String(),
			Success:    true,
		})
	}
```

**Step 9: Run tests**

Run: `go test ./internal/api/ -run "TestCreateInvitation|TestCancelInvitation|TestResendInvitation" -v -count=1`
Expected: All PASS.

**Step 10: Run linter**

Run: `golangci-lint run ./internal/api/ ./internal/store/`

**Step 11: Commit**

```bash
git add internal/store/queries/org.sql internal/store/org.go internal/store/generated/ \
  internal/api/orgs.go internal/api/orgs_test.go
git commit -m "fix(invitations): duplicate detection, cancel 404, nil logging, audit

- B7: Reject duplicate pending invitations for same email+org (409)
- B8: Return 404 when canceling non-existent invitation
- B10: Log warning when org/inviter nil in sendInvitationEmail
- B13: Add audit entries for create, cancel, resend invitation"
```

---

## Task 11: Concurrent Invitation Accept Fix

**Fixes:** B2 (concurrent accept returns 500 instead of idempotent 200)

**Why tests missed it:** `TestAcceptInvitation_Idempotent` tests sequential double-accept. No concurrent test.

**Files:**
- Modify: `internal/store/queries/org.sql` (ON CONFLICT)
- Modify: `internal/store/org.go` (handle conflict)
- Modify: `internal/api/auth_test.go`
- Run: `sqlc generate`

**Step 1: Write failing test**

Add to `auth_test.go`:

```go
func TestAcceptInvitation_ConcurrentAccept(t *testing.T) {
	// B2: Two simultaneous accepts should both return 200, not 500.
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	adminToken := registerAndLogin(t, ts, "admin@example.com", "password1234567890")
	orgID := getFirstOrgID(t, ts, adminToken)

	// Create invitation
	invToken := createInvitationAndGetToken(t, ts, orgID, adminToken, "joiner@example.com", "member")

	// Register the invited user
	joinerToken := registerAndLogin(t, ts, "joiner@example.com", "password1234567890")

	// Race two accepts
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp := acceptInvitation(ts, invToken, joinerToken)
			results[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	// Both should succeed (200) — never 500.
	for i, code := range results {
		if code != 200 {
			t.Fatalf("accept %d: expected 200, got %d", i, code)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run "TestAcceptInvitation_ConcurrentAccept" -v -count=5`
Expected: FAIL on some runs — one request gets 500 from unique constraint violation.

**Step 3: Fix CreateOrgMember SQL**

Change `org.sql`:

```sql
-- name: CreateOrgMember :exec
INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO NOTHING;
```

Run: `sqlc generate`

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestAcceptInvitation" -v -count=1`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/store/ ./internal/api/`

**Step 6: Commit**

```bash
git add internal/store/queries/org.sql internal/store/generated/
git commit -m "fix(store): handle concurrent invitation accept with ON CONFLICT

CreateOrgMember uses ON CONFLICT DO NOTHING so double-accept returns
200 instead of 500 from unique constraint violation."
```

---

## Task 12: ListAllOrgs Soft-Delete Filter

**Fixes:** B5 (includes soft-deleted orgs)

**Why tests missed it:** Tests don't create and then soft-delete orgs before calling batch operations.

**Files:**
- Modify: `internal/store/queries/org.sql`
- Run: `sqlc generate`

**Step 1: Fix the SQL query**

Change `ListAllOrgs` in `org.sql`:

```sql
-- name: ListAllOrgs :many
SELECT id, tier, tier_overrides FROM organizations
WHERE deleted_at IS NULL;
```

Run: `sqlc generate`

**Step 2: Run tests**

Run: `go test ./internal/... -count=1`
Expected: All PASS.

**Step 3: Run linter**

Run: `golangci-lint run ./internal/...`

**Step 4: Commit**

```bash
git add internal/store/queries/org.sql internal/store/generated/
git commit -m "fix(store): exclude soft-deleted orgs from ListAllOrgs

Adds WHERE deleted_at IS NULL to match all other org queries."
```

---

## Task 13: testEmailChannel — SMTP Config Check

**Fixes:** B11 (cryptic error when SMTP not configured)

**Why tests missed it:** Test environment always has SMTP configured (Mailpit).

**Files:**
- Modify: `internal/api/channels.go`
- Modify: `internal/api/channels_test.go`

**Step 1: Write failing test**

Add to `channels_test.go`:

```go
func TestTestChannel_EmailNoSMTP(t *testing.T) {
	// B11: Testing an email channel without SMTP config should give a clear error.
	ts, cleanup := setupTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.SMTPHost = ""
	})
	defer cleanup()

	orgID, adminToken := createOrgAndGetToken(t, ts)
	channelID := createEmailChannel(t, ts, orgID, adminToken, "no-smtp", []string{"test@example.com"})

	resp := testChannel(t, ts, orgID, channelID, adminToken)
	body := readBody(t, resp)
	if !strings.Contains(strings.ToLower(body), "smtp") {
		t.Fatalf("expected SMTP-related error message, got: %s", body)
	}
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL — gets cryptic connection error instead of clear SMTP message.

**Step 3: Fix testEmailChannel**

Add SMTP check at the start:

```go
func (srv *Server) testEmailChannel(ctx context.Context, config json.RawMessage) error {
	if srv.cfg.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST to enable email delivery")
	}
	// ... rest unchanged ...
}
```

**Step 4: Run tests**

Run: `go test ./internal/api/ -run "TestTestChannel" -v`
Expected: All PASS.

**Step 5: Run linter**

Run: `golangci-lint run ./internal/api/`

**Step 6: Commit**

```bash
git add internal/api/channels.go internal/api/channels_test.go
git commit -m "fix(channels): return clear error when testing email channel without SMTP

Checks SMTPHost before attempting send, matching sendInvitationEmail pattern."
```

---

## Post-Completion

After all 13 tasks are complete:

1. Run full test suite: `go test ./internal/... -count=1 -race`
2. Run linter: `golangci-lint run ./internal/...`
3. Use `superpowers:verification-before-completion` to verify
4. Use `superpowers:finishing-a-development-branch` to push/PR
