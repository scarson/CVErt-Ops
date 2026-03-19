# Review Round 1: Test Quality

Reviewing all test code changes from `ea8e123..HEAD` (56-task remediation across 4 stages).
Approximately 5,122 added lines across test files.

---

## Critical Issues (tests that pass but don't actually test what they claim)

### C1: `TestRequireAuthenticated_PendingToken_RejectedAsAccess` does not assert anything

**File:** `internal/api/middleware_auth_test.go:696-736`

This test is supposed to verify that a pending/restricted JWT is rejected when presented as an
access token (testing-pitfalls 11: "Token type enforcement across session types"). However, the
test **never calls `t.Error` or `t.Fatal`**. It uses `t.Log` to document the behavior but does
not fail regardless of outcome:

```go
if rec.Code == http.StatusOK && reached {
    t.Log("WARNING: pending token was accepted as an access token -- this is a security concern")
    t.Log("The middleware does not differentiate pending tokens from access tokens")
    ...
}
t.Logf("pending token on normal endpoint: status=%d, handler_reached=%v", rec.Code, reached)
```

This means if the middleware accepts a pending token as a full access token -- an MFA bypass --
the test passes green. This is exactly the scenario described in testing-pitfalls 11 ("Token type
enforcement"), and the test's own comments acknowledge it as a security concern, yet it logs
instead of asserting. This is worse than no test, because it creates the false impression that
token type enforcement is tested.

**Recommendation:** Change `t.Log("WARNING:...")` to `t.Error(...)` or `t.Fatal(...)`. If
pending token rejection is not yet implemented in the middleware, the test should be written to
assert the expected-but-not-yet-implemented behavior and tracked as a known failure, not silently
passing.

### C2: `newAuthTestServer` and two `admin_system_test.go` tests discard `NewServer` error

**Files:**
- `internal/api/middleware_auth_test.go:59,61` (via `newAuthTestServer`)
- `internal/api/admin_system_test.go:46,117`

All use `srv, _ := NewServer(...)` discarding the error. Per testing-pitfalls 16: "Test setup
must not discard errors." If `NewServer` returns an error (e.g., config validation failure),
`srv` is nil, and the test panics on a nil dereference later with a misleading stack trace. The
real failure (config issue) is invisible.

```go
// middleware_auth_test.go
srv, _ = NewServer(db.Store, cfg, ServerDeps{})
// admin_system_test.go
srv, _ := NewServer(db.Store, cfg, ServerDeps{})
```

**Recommendation:** Change to:
```go
srv, err := NewServer(db.Store, cfg, ServerDeps{})
if err != nil {
    t.Fatalf("NewServer: %v", err)
}
```

The `newAuthTestServer` helper at line 54-65 is called by ~15 tests. Fixing it once fixes all
callers.

### C3: `breaker_test.go` uses `_, _ = cb.Execute(...)` discarding errors in setup

**File:** `internal/feed/breaker_test.go:21-23, 42-44`

```go
for i := 0; i < 3; i++ {
    _, _ = cb.Execute(func() (struct{}, error) {
        return struct{}{}, testErr
    })
}
```

The test intentionally triggers failures to trip the breaker, but discards the returned error
without checking that the execute call itself succeeded (not a panic or unexpected error type).
This is a minor violation of tp16 but acceptable in context since the errors are expected and
the subsequent assertion validates the breaker state. Noting for completeness.

---

## Major Issues (testing pitfall violations)

### M1: `breaker_test.go` uses `time.Sleep` for half-open transition (flaky test)

**File:** `internal/feed/breaker_test.go:49`

```go
time.Sleep(100 * time.Millisecond)
```

The test waits 100ms for a 50ms timeout to expire. On a loaded CI server this could be flaky --
the 2x margin is thin. Per testing-pitfalls 14 commentary on flaky patterns, time-dependent
assertions should use generous margins or test clock injection.

**Recommendation:** Either increase the sleep to 200ms+ (4x margin) or use the gobreaker
library's test hooks if available to inject time advancement.

### M2: `flushAndQueryEvents` calls `ew.Stop()` which is `sync.Once`-guarded

**File:** `internal/api/auth_mfa_test.go:2053`

The `flushAndQueryEvents` helper calls `ew.Stop()` to wait for async writes. Since `Stop()` is
guarded by `sync.Once`, only the first call per `EventWriter` instance actually waits. If a
test calls `flushAndQueryEvents` multiple times (e.g., two assertions in the same test function
after different actions), the second call returns immediately without waiting for events written
after the first `Stop()`.

Looking at usage: `TestAdminMFA_CrossOrg_Rejected` only calls it once. `TestAdminMFAReset_AllSideEffects`
only calls it once. So the current tests are safe, but this is a latent bug in the helper --
any future test that calls it twice in the same function will silently miss events.

**Recommendation:** Add a comment to `flushAndQueryEvents` warning that it can only be called
once per test, or restructure the helper to use a channel-based flush instead of Stop().

### M3: `store/mfa_test.go` concurrent recovery code test discards errors in goroutines

**File:** `internal/store/mfa_test.go:535`

```go
go func(idx int) {
    defer wg.Done()
    <-barrier
    ok, _, _ := s.VerifyRecoveryCode(ctx, user.ID, code)
    results[idx] = ok
}(i)
```

The third return value (error) from `VerifyRecoveryCode` is discarded. If the DB returns an
error during the concurrent race (connection pool exhaustion, deadlock), the test would record
`ok=false` for both goroutines and the assertion `results[0] == results[1]` would fail with a
misleading message ("both results = false") rather than surfacing the actual DB error.

**Recommendation:** Capture and assert errors:
```go
ok, _, err := s.VerifyRecoveryCode(ctx, user.ID, code)
if err != nil {
    t.Errorf("goroutine %d: VerifyRecoveryCode error: %v", idx, err)
}
```

### M4: `audit_integration_test.go` discards `json.NewDecoder().Decode()` errors

**Files:** `internal/api/audit_integration_test.go:97,218,345,567,662,794,884`

Multiple places use:
```go
json.NewDecoder(resp.Body).Decode(&rule) //nolint:errcheck,gosec // G104: test
```

If the decode fails (malformed response, wrong struct shape), the decoded struct is zero-valued
and subsequent assertions compare against zero, which may pass or fail for the wrong reason.
For example, if `rule.ID` is `""` (empty string from failed decode), and later `entry.EntityID != ruleID`
could pass if `EntityID` is also empty.

**Recommendation:** Check decode errors: `if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil { t.Fatalf(...) }`

### M5: Missing `t.Parallel()` on table-driven subtests in `TestAdminMFA_CrossOrg_Rejected`

**File:** `internal/api/admin_mfa_test.go:516`

```go
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // No t.Parallel() here, which is fine since they share ownerACookies
```

Not a bug per se (they share state), but worth noting that these subtests run sequentially. This
is actually correct since they share `ownerACookies` -- just confirming no issue.

### M6: No cross-user token swapping test for MFA enrollment (tp11)

**File:** `internal/api/auth_mfa_test.go`

Testing-pitfalls 11 ("Cross-user token swapping in multi-step flows") specifically calls out that
`mfaTOTPConfirmHandler` checks `enrollClaims.UserID != userID` but no test exercises this guard.
The remediation added extensive MFA tests but did not add a test where User A starts enrollment,
and User B attempts to complete it with User A's enrollment token.

**Recommendation:** Add a test that:
1. User A calls /auth/mfa/totp/setup, gets enrollment token
2. User B logs in, gets access token
3. User B calls /auth/mfa/totp/confirm with User A's enrollment token
4. Assert 401/403 rejection

---

## Minor Issues (style, missing edge cases)

### m1: `sso_test.go` also discards `NewServer` errors

**File:** `internal/api/sso_test.go:935,957,980,1006,1025`

Five instances of `srv, _ := NewServer(nil, cfg, ServerDeps{...})`. Same issue as C2 but in
SSO tests. These are pre-existing (not part of this remediation) but were visible in the grep
and should be tracked for future cleanup.

### m2: `client_test.go` asserts body truncation at exact boundary

**File:** `internal/feed/client_test.go:94`

```go
assert.Len(t, body, 256, "response body should be truncated to maxBytes")
```

This is a clean assertion. No issue.

### m3: `admin_users_test.go` user creation loop uses character conversion

**File:** `internal/api/admin_users_test.go:32`

```go
email := "listuser" + string(rune('0'+i)) + "@example.com"
```

For `i` in `range 3`, this produces `"listuser0@..."`, `"listuser1@..."`, `"listuser2@..."`.
This works but `fmt.Sprintf("listuser%d@example.com", i)` would be clearer.

### m4: Some `uuid.Parse` calls discard errors

**Files:** `internal/api/auth_mfa_test.go:124,157,179,298,466,800,1020,1073,...`

Pattern: `userID, _ := uuid.Parse(reg.UserID)`. Since `reg.UserID` comes from a successful
registration response, it's practically always valid. However, if the response format changes,
this would silently produce `uuid.Nil` instead of failing fast.

The remediation did fix this in some places (e.g., `auth_mfa_test.go:976` uses
`uuid.Parse(reg.UserID)` with error check), but many instances remain. This is minor but
contributes to tp16 debt.

### m5: `TestAdminListUsers_BasicPagination` has a fragile count assertion

**File:** `internal/api/admin_users_test.go:68-70`

```go
if len(body.Items) < 4 {
    t.Errorf("expected at least 4 users, got %d", len(body.Items))
}
```

Uses `< 4` instead of `== 4` because parallel tests may create additional users. This is a
reasonable defense against flakiness.

### m6: `TestAdminAuditLog_FilterByEntityType` has no assertion beyond status code

**File:** `internal/api/admin_system_test.go:241-277`

The test verifies the endpoint returns 200 with `entity_type=channel` filter but doesn't
verify the response body contains only channel-type entries (or is empty). It only asserts
the status code. A bug that ignores the filter and returns all entries would pass this test.

**Recommendation:** Decode the response and verify either (a) all entries have entity_type=channel,
or (b) the list is empty (acceptable on a fresh DB).

---

## Observations

### What was done well

1. **Comprehensive MFA test coverage.** The `auth_mfa_test.go` file (1041+ lines added in Stage 3,
   plus extensions in Stage 4) covers the full MFA lifecycle: enrollment, challenge, verify,
   replay prevention, concurrent replay (barrier pattern per tp1), token version mismatch,
   remember-device flow, key rotation, enrollment ordering enforcement, and full-token issuance
   on completion. This is thorough.

2. **Security event emission assertions.** The `newMFAServerWithEvents` / `flushAndQueryEvents`
   infrastructure is well-designed -- it uses a real EventWriter backed by the test DB, flushes
   async writes, and queries the `security_events` table. This avoids testing mocked behavior.

3. **Side-effect completeness in `TestAdminMFAReset_AllSideEffects` and
   `TestAdminForcePasswordReset_AllSideEffects`.** These tests assert ALL side effects
   (credentials deleted, recovery codes deleted, token_version incremented, security event emitted,
   remember-device tokens deleted). This directly addresses testing-pitfalls 7 ("Multi-side-effect
   operations must assert ALL effects").

4. **RBAC hierarchy coverage.** Admin MFA tests cover owner-can, admin-can-for-member,
   admin-cannot-for-owner, admin-cannot-for-admin, member-cannot, viewer-cannot, site-admin-bypass,
   and cross-org rejection. This is the kind of matrix coverage tp11 demands.

5. **Config secret redaction test.** `TestAdminConfigHandler_SecretsRedacted` compares each field
   against the actual secret value AND verifies it equals `"***"`. The complementary test
   `TestAdminConfigHandler_EmptySecrets_EmptyString` verifies empty secrets aren't redacted to
   `"***"`. This pair directly addresses tp5 ("Config endpoint secret redaction").

6. **Real DB throughout.** All tests use `testutil.NewTestDB(t)` with real Postgres. No mocks of
   store behavior. This aligns with the CLAUDE.md rule against testing mocked behavior.

7. **Error handling in Stage 4 F1 mass fix.** The mass fix across 27 files correctly converted
   `_, _ :=` patterns to `err` checks with `t.Fatalf`. The 11 syntax errors that were subsequently
   fixed (variable redeclaration, missing imports) appear to have been cleanly resolved.

8. **JWT security tests.** `internal/auth/jwt_test.go` covers algorithm pinning (RS256 rejected,
   alg:none rejected), dual-key rotation for all three token types (access, refresh, pending),
   expired token rejection, and error type discrimination (signature vs. expiry). This directly
   addresses tp11 ("JWT algorithm confusion").

9. **Feed client SSRF test.** `TestBuildFeedClient_BlocksPrivateIPs` exercises the production
   safeurl client against a loopback target, verifying SSRF blocking. This addresses tp8
   ("Production client configuration exercised in tests").

### Testing pitfalls not yet addressed by this remediation

The following testing-pitfalls items are NOT addressed by the remediation's new tests (some may
be covered by pre-existing tests not in this diff):

- **tp10 (per-user resource isolation):** No test verifies that User B cannot look up User A's
  remember-device token or MFA challenge using the same hash. The store tests create resources
  for a single user.
- **tp11 (cross-user token swapping):** See M6 above.
- **tp7 (transaction commit persistence verification):** Not addressed in this diff.
- **tp8 (no open DB transaction during external I/O):** Not addressed; webhook delivery tests
  are not part of this remediation.

### Stage 4 F1 mass error-fix assessment

The F1 task converted `_, _ :=` and `_ =` patterns to proper error checks across 27 test files.
Based on the diff, these changes are mechanical and correct. The subsequent 11 syntax error fixes
(variable redeclaration from `err :=` shadowing, missing imports for `require`) appear clean.
No evidence of introduced regressions beyond what was already fixed.
