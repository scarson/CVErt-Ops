# Phase 11 MFA Test Coverage Fix Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close all 36 test coverage gaps identified in the Phase 11 MFA coverage review.

**Architecture:** Test-only changes — no production code modifications unless absolutely necessary (Task 1 may require a minimal interface extraction). Build event writer test infrastructure first, then fill gaps by test file (store, JWT, admin API, MFA API, auth API). Group by file to minimize merge conflicts.

**Tech Stack:** Go tests, testutil.NewTestDB, httptest, real Postgres via testcontainers

**Findings Report:** `dev/test-coverage-reports/2026-03-18-phase11-mfa-consolidated.md`

**Testing Pitfalls:** `dev/testing-pitfalls.md` — read before every task

---

## Cross-Plan Sequencing

This plan is part of a coordinated three-plan remediation. See `dev\plans\2026-03-18-phase8-11-hr-remediation-sequencing.md` for the master execution order.

**This plan executes as Stage 3** — after HR code fixes (Stage 1) and P8 code fixes (Stage 2).

**Dependencies from Health Review (must be complete before this plan starts):**
- **HR C2** changed `secure/writer.go` — added a semaphore (capacity 50) and per-write timeout (10s). The `Write()` method now drops events when at capacity instead of spawning unbounded goroutines. **Task 1 (event writer test infrastructure) must account for this:** the semaphore capacity is high enough that tests should never hit the limit, but if a test somehow floods >50 concurrent events, some will be dropped and `flushAndQueryEvents` will find fewer events than expected. Keep test event volumes low (<10 per test) and this is a non-issue.
- **HR D2** refactored `ParseEnrollmentToken` (and all other Parse* functions) into a generic `parseTokenWithRotation` helper. The public API (`ParseEnrollmentToken(tokenStr, activeSecret, previousSecret)`) is unchanged. **Task 2 tests validate the refactored code** — if any test fails, it indicates a regression from the refactor.

**File conflicts with Phase 8 plan:**
- `admin_mfa_test.go`: This plan's Task 4 and P8 Task 16 both add tests. This plan runs first (Stage 3). P8 runs in Stage 4.
- `auth_test.go`: P8 Tasks 13+14 and this plan's Task 6 both add tests. Sequential execution — this plan's Task 6 first, P8 follows.

---

## Task 1: Event Writer Test Infrastructure (SC1 foundation)

**Findings closed:** SC1 (partial — infrastructure only; individual event assertions are in Tasks 4-7)

**Files to modify:** `internal/api/auth_mfa_test.go`

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

The `Server.eventWriter` field is `*secure.EventWriter` — a concrete struct type, not an interface. The `EventWriter.Write(ctx, Event)` method fires a background goroutine that writes to the DB via `store.InsertSecurityEvent`. All 77 event emissions in MFA handlers are guarded by `if srv.eventWriter != nil` — when `nil`, events are silently skipped.

Currently, `newMFAServer` creates the server with `ServerDeps{}` which leaves `eventWriter` nil. Tests pass but never verify event emission.

### Approach: Real EventWriter backed by the test DB

Since `eventWriter` is a concrete `*secure.EventWriter`, the simplest zero-production-change approach is:

1. Create a real `secure.EventWriter` backed by the test DB's store
2. Inject it via `ServerDeps{EventWriter: ew}`
3. After each test action, call `ew.Stop()` (which waits for pending writes via `wg.Wait()`) then query the `security_events` table directly to verify event emission

This avoids any production code changes. The test queries `security_events` after the handler completes. The `EventWriter.Stop()` call ensures all async goroutines have flushed before assertions run.

### Implementation

1. **Add `newMFAServerWithEvents` helper** to `internal/api/auth_mfa_test.go`:

```go
// newMFAServerWithEvents creates a test server with a real EventWriter.
// After test actions, call flushEvents() to wait for async writes,
// then call getEvents() to query the security_events table.
func newMFAServerWithEvents(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server, *secure.EventWriter) {
    t.Helper()
    cfg := &config.Config{
        // same fields as newMFAServer
        JWTSecret:               "mfa-test-secret-at-least-32-bytes",
        RegistrationMode:        "open",
        Argon2MaxConcurrent:     5,
        MFAEmailOTPTTL:          10 * time.Minute,
        MFAEmailOTPMaxPerHour:   5,
        MFAChallengeMaxAttempts: 3,
        MFAPendingTokenTTL:      5 * time.Minute,
        SSOEncryptionKey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }
    ew := secure.NewEventWriter(db.Store)
    srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew})
    if err != nil {
        t.Fatalf("NewServer: %v", err)
    }
    ts := httptest.NewServer(srv.Handler())
    t.Cleanup(ts.Close)
    t.Cleanup(srv.Close)
    return srv, ts, ew
}
```

2. **Add `flushAndQueryEvents` helper**:

```go
// flushAndQueryEvents waits for all async event writes to complete,
// then queries the security_events table for events matching the given type.
// Returns the matching events as a slice of maps.
func flushAndQueryEvents(t *testing.T, ew *secure.EventWriter, db *testutil.TestDB, eventType string) []map[string]any {
    t.Helper()
    ew.Stop() // waits for all pending goroutines
    // Query security_events table directly
    rows, err := db.Pool().Query(context.Background(),
        "SELECT event_type, severity, actor_ip, actor_email, user_id, org_id, details FROM security_events WHERE event_type = $1 ORDER BY created_at",
        eventType)
    if err != nil {
        t.Fatalf("query security_events: %v", err)
    }
    defer rows.Close()
    var events []map[string]any
    for rows.Next() {
        var evType, severity, actorIP, actorEmail string
        var userID, orgID *uuid.UUID
        var details map[string]any
        if err := rows.Scan(&evType, &severity, &actorIP, &actorEmail, &userID, &orgID, &details); err != nil {
            t.Fatalf("scan security_event: %v", err)
        }
        events = append(events, map[string]any{
            "event_type":  evType,
            "severity":    severity,
            "actor_ip":    actorIP,
            "actor_email": actorEmail,
            "user_id":     userID,
            "org_id":      orgID,
            "details":     details,
        })
    }
    return events
}
```

**Important:** `ew.Stop()` can only be called once (it stops the rate limiter). If a test needs multiple flushes, use a different approach: query the DB and retry with a short sleep. But for most tests, a single Stop() + query at the end of the test is sufficient.

**Alternative if Stop-once is a problem:** Instead of calling `Stop()`, access the `wg` field. But since it's unexported, the cleaner approach is to just `time.Sleep(100*time.Millisecond)` and query. However, this is flaky. The recommended approach is: call `Stop()` once at end of test, query events. Most tests only need one event check at the end.

**NOTE:** The implementer should verify that `ew.Stop()` is safe to call in `t.Cleanup` after `srv.Close()` (which also calls `ew.Stop()`). If double-Stop panics, remove the `t.Cleanup(srv.Close)` and handle cleanup manually, or guard with a `sync.Once`. Read `EventWriter.Stop()` carefully.

3. **Add one smoke test** to verify the infrastructure works:

```
TestEventWriterInfrastructure_SmokeTest:
- Create server with newMFAServerWithEvents
- Register user, enroll TOTP, login (get pending token)
- Submit correct TOTP code via POST /auth/mfa/verify
- Call flushAndQueryEvents with EventMFAVerifySuccess
- Assert at least 1 event found with correct event_type
- Assert event has a non-nil user_id
```

This validates the entire pipeline: handler → EventWriter → DB → query.

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/api/... -run TestEventWriter -count=1` and confirm green
```

---

## Task 2: JWT Enrollment Token Security Tests (SC10)

**Findings closed:** SC10

**Files to modify:** `internal/auth/jwt_test.go`

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

Access, refresh, and pending tokens all have comprehensive security test suites: round-trip, expiry rejection, wrong secret, alg:none, RS256 confusion. `ParseEnrollmentToken` at 76.9% coverage only has the dual-key rotation test (`TestParseEnrollmentToken_DualKey` at line 867). The enrollment token carries the encrypted TOTP secret — algorithm confusion attacks could allow forging enrollment tokens.

### Implementation

Copy the pattern from the pending token security tests (lines 660-817 in `jwt_test.go`). Add these tests in the enrollment token section after the existing `TestParseEnrollmentToken_DualKey`:

1. **`TestEnrollmentTokenRoundTrip`:**
   - Issue enrollment token with `auth.IssueEnrollmentToken(secret, userID, secretEnc, 5*time.Minute)`
   - Parse with `auth.ParseEnrollmentToken(tokenStr, secret, nil)`
   - Assert `claims.UserID == userID`
   - Assert `claims.SecretEnc` matches the input `secretEnc` bytes

2. **`TestEnrollmentTokenRejectsExpired`:**
   - Issue with TTL `-1*time.Second`
   - Parse → expect non-nil error

3. **`TestEnrollmentTokenRejectsWrongSecret`:**
   - Issue with `secret`, parse with `wrongSecret`
   - Expect non-nil error

4. **`TestEnrollmentTokenRejectsAlgNone`:**
   - Issue valid token, split on `.`, replace header with `{"alg":"none","typ":"JWT"}` base64-encoded
   - Reconstruct as `fakeHeader + "." + parts[1] + "."`
   - Parse → expect non-nil error

5. **`TestEnrollmentTokenRejectsWrongAlgorithm`:**
   - Issue valid token, split on `.`, replace header with `{"alg":"RS256","typ":"JWT"}` base64-encoded
   - Reconstruct as `fakeHeader + "." + parts[1] + "." + parts[2]`
   - Parse → expect non-nil error

### Test Data

Use the same test fixtures as the pending token tests:
- `secret := []byte("test-secret-32-bytes-minimum-aaaa")`
- `wrongSecret := []byte("wrong-secret-32-bytes-minimum-bb")`
- `userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")`
- `secretEnc := []byte("encrypted-totp-secret-placeholder")`

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/auth/... -count=1` and confirm green
```

---

## Task 3: Store Direct Tests (C1 + SC8 + SC11 + N8 + N9 + N10)

**Findings closed:** C1 (VerifyAndUpdateTOTPStep, UserMFARequiredOrgNames, UserMFARequirementOrgNames, AllUserOrgsAllowRememberDevice, MinRememberDeviceDays), SC8 (multi-org most-restrictive), SC11 (RequiredOrgOwners layer), N8 (already-used recovery code), N9 (generate-then-verify), N10 (UpdateOrgMFASettings org-not-found)

**Files to modify:** `internal/store/mfa_test.go`

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

These store methods have 0% direct store test coverage but are exercised indirectly by API tests. Per testing-pitfalls §7: "Every public method on `*Store` needs at least one test that calls it directly."

The `UserMFARequired` function (store/mfa.go:620-652) has a 4-layer enforcement model:
- Layer 1: `cfg.RequiredSiteAdmins && isSiteAdmin` → return true
- Layer 2a: `cfg.RequiredOrgOwners` → check `IsOrgOwner(ctx, userID)` → return true if owner
- Layer 2b: `UserInMFARequiredOrg(ctx, userID)` → return true
- Layer 3: `UserHasMFARequirement(ctx, userID)` → return true

The `MFAConfig` struct (store/mfa.go:611-614) has fields:
- `RequiredSiteAdmins bool`
- `RequiredOrgOwners  bool`

### Implementation

Add these tests to `internal/store/mfa_test.go`:

#### C1: Direct store tests for 5 methods

1. **`TestStore_VerifyAndUpdateTOTPStep_Direct`:**
   - Create user, create TOTP credential with `[]byte("encrypted-secret")`
   - Call `s.VerifyAndUpdateTOTPStep(ctx, userID, 100)` — expect `(true, nil)` (fresh step)
   - Call `s.VerifyAndUpdateTOTPStep(ctx, userID, 100)` again — expect `(false, nil)` (replay: same step)
   - Call `s.VerifyAndUpdateTOTPStep(ctx, userID, 50)` — expect `(false, nil)` (replay: lower step)
   - Call `s.VerifyAndUpdateTOTPStep(ctx, userID, 101)` — expect `(true, nil)` (new step)
   - **Why this matters:** The FOR UPDATE lock prevents concurrent replay. This direct test verifies the step comparison logic without HTTP roundtrip overhead.

2. **`TestStore_UserMFARequiredOrgNames_Direct`:**
   - Create user, create org with name "TestOrg", add user as member
   - Set org `mfa_required_all = true` via `s.UpdateOrgMFASettings(ctx, orgID, true, true, 30)`
   - Call `s.UserMFARequiredOrgNames(ctx, userID)` — expect `["TestOrg"]`
   - Create second org "OtherOrg" with `mfa_required_all = false`, add user
   - Call again — expect `["TestOrg"]` (only the required org)

3. **`TestStore_UserMFARequirementOrgNames_Direct`:**
   - Create user, create org with name "ReqOrg", add user as member
   - Call `s.CreateMFARequirement(ctx, orgID, userID, ownerID)` (need an owner user too)
   - Call `s.UserMFARequirementOrgNames(ctx, userID)` — expect `["ReqOrg"]`
   - Create second org without requirement, add user — expect still just `["ReqOrg"]`

4. **`TestStore_AllUserOrgsAllowRememberDevice_Direct`:**
   - Create user, create org A (default: remember_device_allowed=true), add user
   - Call `s.AllUserOrgsAllowRememberDevice(ctx, userID)` — expect `true`
   - Create org B, set `remember_device_allowed = false` via `s.UpdateOrgMFASettings(ctx, orgBID, false, false, 30)`, add user
   - Call again — expect `false` (most-restrictive wins: `bool_and()` across orgs)

5. **`TestStore_MinRememberDeviceDays_Direct`:**
   - Create user, create org A with `remember_device_days = 30`, add user
   - Call `s.MinRememberDeviceDays(ctx, userID)` — expect `30`
   - Create org B with `remember_device_days = 14`, add user
   - Call again — expect `14` (MIN across orgs)

#### SC8: Multi-org most-restrictive policy (combined test)

6. **`TestStore_RememberDevice_MultiOrg_MostRestrictive`:**
   - Create user in Org A (allowed=true, days=30) + Org B (allowed=true, days=14)
   - Assert `AllUserOrgsAllowRememberDevice == true`
   - Assert `MinRememberDeviceDays == 14`
   - Update Org B to `allowed=false`
   - Assert `AllUserOrgsAllowRememberDevice == false`
   - Assert `MinRememberDeviceDays == 14` (still 14 from Org B)

#### SC11: RequiredOrgOwners negative case in UserMFARequired

**NOTE:** The positive case (`RequiredOrgOwners=true` + user is owner → required=true) already exists: `TestUserMFARequired_OrgOwnerRequired` (mfa_test.go line ~1649). Only the **negative case** is missing — non-owner with `RequiredOrgOwners=true` should NOT trigger MFA requirement.

7. **`TestStore_UserMFARequired_RequiredOrgOwners_NonOwner`:**
   - Create user, create org, add user as **member** (role="member") — NOT owner
   - Call `s.UserMFARequired(ctx, userID, false, store.MFAConfig{RequiredOrgOwners: true})` — expect `false` (user is not an owner, no other layers active)
   - This ensures the `IsOrgOwner` check actually discriminates between owners and members, per testing-pitfalls §11 "Multi-layer authorization negative cases"

#### N8: Already-used recovery code

9. **`TestStore_VerifyRecoveryCode_AlreadyUsed`:**
   - Create user, generate recovery codes
   - Verify one code successfully — expect `(true, 9, nil)`
   - Verify the **same code** again — expect `(false, 9, nil)` (the `WHERE used_at IS NULL` clause rejects it)

#### N9: Generate-then-verify round trip

10. **`TestStore_RecoveryCode_GenerateAndVerify_RoundTrip`:**
    - Create user, generate codes (get plaintext list)
    - Pick the first code, verify it — expect `(true, 9, nil)`
    - Pick the second code, verify it — expect `(true, 8, nil)`
    - Verify an invalid code "xxxxx-xxxxx" — expect `(false, 8, nil)`

#### N10: UpdateOrgMFASettings with non-existent org

11. **`TestStore_UpdateOrgMFASettings_OrgNotFound`:**
    - Call `s.UpdateOrgMFASettings(ctx, uuid.New(), true, true, 30)` with a random UUID
    - Expect `(nil, nil)` — the method returns `(nil, nil)` for no-rows (see org.go line 59-60)

### Setup Notes

- Use `s.CreateUser(ctx, email, name, "$argon2id$stub", 2)` for user creation
- Use `s.CreateOrg(ctx, name, ownerID)` for org creation (this creates the org AND adds the owner)
- For adding users to additional orgs: `s.CreateOrgMember(ctx, orgID, userID, "member")`
- For setting MFA settings: `s.UpdateOrgMFASettings(ctx, orgID, requiredAll, rememberAllowed, rememberDays)`
- For making a user an owner in an additional org: `s.CreateOrgMember(ctx, orgID, userID, "owner")`

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/store/... -run "TestStore_Verify|TestStore_UserMFA|TestStore_AllUser|TestStore_MinRemember|TestStore_Remember|TestStore_Recovery|TestStore_UpdateOrgMFA" -count=1` and confirm green
```

### Review Loop

```
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Task 4: Admin MFA Test Gaps (SC2 + SC3 + SC6 + SC7 + C2)

**Findings closed:** SC2 (cross-org for reset-mfa as smoke test), SC3 (force-pw-reset negative cases), SC6 (site admin + viewer), SC7 (side-effect assertions), C2 (unrequire RBAC), plus SC1 event assertions for admin handlers

**Files to modify:** `internal/api/admin_mfa_test.go`

**Depends on:** Task 1 (event writer infrastructure)

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

The existing test file (`admin_mfa_test.go`) has:
- `setupAdminMFATest` — creates one org with owner/admin/member
- `TestAdminMFAReset` — owner→member success (checks MFA cleared only)
- `TestAdminMFAResetByAdmin` — admin→member success
- `TestAdminMFAResetOwnerByAdmin` — admin→owner denied (403)
- `TestAdminMFAResetByMember` — member→admin denied (403)
- `TestAdminForcePasswordReset` — owner→member success (checks flag only)
- `TestAdminForcePasswordResetByMember` — member→admin denied (403)
- `TestAdminRequireMFA` + RBAC variants (owner, self-target, admin→admin, member)
- `TestAdminUnrequireMFA` + self-target only
- `TestAdminUpdateOrgMFASettings` + member denied

Admin MFA endpoints use `newMFAServer` which has no event writer. New tests that need event assertions should use `newMFAServerWithEvents` from Task 1.

The route registration (server.go lines 306-309) shows all 5 admin MFA endpoints use `RequireOrgRole(RoleAdmin)` middleware.

### Implementation

#### SC2: Cross-org isolation tests (all 5 admin endpoints)

Sam chose D3 option 1: cross-org test for every admin MFA endpoint.

**Shared setup:** Create two orgs. Owner A in Org A, Owner B + Member B in Org B. Each test has Owner A attempt an admin action targeting Org B's member.

1a. **`TestAdminMFAReset_CrossOrg_Rejected`:**
   - Owner A attempts `POST /orgs/{orgB}/members/{memberB}/reset-mfa` — expect 403 or 404 (owner A not in orgB)
   - Assert no `EventMFAAdminReset` event emitted

1b. **`TestAdminForcePasswordReset_CrossOrg_Rejected`:**
   - Owner A attempts `POST /orgs/{orgB}/members/{memberB}/force-password-reset` — expect 403 or 404

1c. **`TestAdminRequireMFA_CrossOrg_Rejected`:**
   - Owner A attempts `POST /orgs/{orgB}/members/{memberB}/require-mfa` — expect 403 or 404

1d. **`TestAdminUnrequireMFA_CrossOrg_Rejected`:**
   - Owner A attempts `DELETE /orgs/{orgB}/members/{memberB}/require-mfa` — expect 403 or 404

1e. **`TestAdminUpdateOrgMFASettings_CrossOrg_Rejected`:**
   - Owner A attempts `PATCH /orgs/{orgB}/mfa-settings` with `{"mfa_required_all":true}` — expect 403 or 404

**Implementation tip:** These 5 can share a single test function with subtests (`t.Run`) to avoid duplicating the 2-org setup. The shared helper creates both orgs + users, then each subtest hits one endpoint.

#### SC3: adminForcePasswordReset negative cases

2. **`TestAdminForcePasswordReset_SelfTarget`:**
   - Setup admin MFA test actors
   - Owner attempts `POST .../force-password-reset` targeting themselves
   - Expect HTTP 400 with body containing "cannot force password reset on yourself"

3. **`TestAdminForcePasswordReset_NonExistentUser`:**
   - Setup admin MFA test actors
   - Owner attempts `POST /orgs/{orgID}/members/{randomUUID}/force-password-reset`
   - Expect HTTP 404

4. **`TestAdminForcePasswordReset_AdminTargetsAdmin`:**
   - Setup admin MFA test actors
   - Register a second admin, add to org
   - First admin attempts `POST .../force-password-reset` targeting second admin
   - Expect HTTP 403

4b. **`TestAdminForcePasswordReset_OAuthOnlyAccount`:**
   - Setup admin MFA test actors
   - Clear the member's password hash in DB: `UPDATE users SET password_hash = NULL WHERE id = $1`
   - Owner attempts `POST .../force-password-reset` targeting the OAuth-only member
   - Expect HTTP 400 with body containing "no native identity" or "OAuth-only"
   - This tests `admin_mfa.go:124`: `if !user.PasswordHash.Valid`

#### SC6: Site admin and viewer role paths

5. **`TestAdminMFAReset_SiteAdmin_CrossOrgBypass`:**
   - Create server with `newMFAServerWithEvents`
   - Register site admin user, mark as site admin via `UPDATE users SET is_site_admin = true WHERE id = $1`
   - Register owner + member in a separate org (site admin is NOT in this org)
   - Login as site admin, collect cookies
   - Enroll TOTP for the member
   - Site admin attempts `POST /orgs/{orgID}/members/{memberID}/reset-mfa`
   - **Important:** The site admin needs to be a member of the org for the `RequireOrgRole(RoleAdmin)` middleware to pass. Check how `checkAdminMFAPermission` works — it has a site admin bypass at line 419, but the *route middleware* `RequireOrgRole(RoleAdmin)` fires first. If the site admin is not an org member, the middleware blocks them before `checkAdminMFAPermission` runs.
   - **Resolution:** Read the `RequireOrgRole` middleware to check if site admins bypass it. If not, the site admin must be added to the org as any role. If site admins DO bypass the org middleware, the test works as described. The implementer must verify this before writing the test.
   - If site admins don't bypass org middleware: add site admin to org as member role, then test that they can still reset an admin's MFA (which a normal member cannot do) — this proves the `checkAdminMFAPermission` site admin path is exercised.
   - Assert `EventMFAAdminReset` event emitted with correct details

6. **`TestAdminMFAReset_ViewerRole_Rejected`:**
   - Register owner + viewer in same org (viewer added with role "viewer")
   - Login as viewer, collect cookies
   - Viewer attempts `POST /orgs/{orgID}/members/{memberID}/reset-mfa`
   - Expect HTTP 403 (the `RequireOrgRole(RoleAdmin)` middleware blocks viewers)

#### SC7: Admin action side-effect assertions

7. **Enhance `TestAdminMFAReset` — add missing side-effect checks:**
   - **Already tested:** `UserHasMFACredentials == false` (credential deletion)
   - **Add:** `CountUnusedRecoveryCodes(ctx, memberID) == 0` (recovery codes deleted)
   - **Add:** Read user's `token_version` before reset, read again after — assert it incremented
   - **Add (optional):** If the member had email OTP challenges, verify they're deleted

   Since the existing test uses `newMFAServer` (no events), create a NEW test that duplicates the scenario with `newMFAServerWithEvents` and adds all assertions:

8. **`TestAdminMFAReset_AllSideEffects`:**
   - Create server with `newMFAServerWithEvents`
   - Setup actors, enroll TOTP for member, generate recovery codes for member
   - Record member's `token_version` via `srv.store.GetUserByID`
   - Owner resets member's MFA → expect 200
   - Assert: `UserHasMFACredentials(ctx, memberID) == false`
   - Assert: `CountUnusedRecoveryCodes(ctx, memberID) == 0`
   - Assert: member's `token_version` incremented (read user again, compare)
   - Assert: `EventMFAAdminReset` event emitted with `severity == "critical"` and `details["target_user_id"] == memberID`

9. **`TestAdminForcePasswordReset_AllSideEffects`:**
   - Create server with `newMFAServerWithEvents`
   - Setup actors
   - Create a remember-device token for member: `srv.store.CreateRememberDeviceToken(ctx, memberID, hash, time.Now().Add(24*time.Hour))`
   - Record member's `token_version`
   - Owner forces password reset → expect 200
   - Assert: `ForcePasswordReset == true`
   - Assert: member's `token_version` incremented
   - Assert: `ValidateRememberDeviceToken` for the member returns nil/false (device tokens deleted)
   - Assert: `EventAuthPasswordResetForced` event emitted with `severity == "critical"`

#### C2: adminUnrequireMFA RBAC gaps

10. **`TestAdminUnrequireMFA_AdminTargetsMember_Success`:**
    - Setup actors, create MFA requirement for member
    - Admin removes member's MFA requirement → expect 204
    - Verify requirement gone

11. **`TestAdminUnrequireMFA_AdminTargetsAdmin_Rejected`:**
    - Setup actors, register second admin, create MFA requirement for second admin
    - First admin attempts to unrequire second admin's MFA → expect 403

12. **`TestAdminUnrequireMFA_MemberRejected`:**
    - Setup actors, create MFA requirement for admin
    - Member attempts to unrequire admin's MFA → expect 403

#### SC1: Event assertions for existing admin tests

For the tests added above that use `newMFAServerWithEvents`, event assertions are already included. Additionally:

13. **`TestAdminRequireMFA_EmitsEvent`:**
    - Create server with `newMFAServerWithEvents`
    - Owner adds per-member MFA requirement → expect 201
    - Assert: `EventMFAAdminRequireMember` event emitted

14. **`TestAdminUnrequireMFA_EmitsEvent`:**
    - Create server with `newMFAServerWithEvents`
    - Setup requirement, owner removes it → expect 204
    - Assert: `EventMFAAdminUnrequireMember` event emitted

15. **`TestAdminUpdateOrgMFASettings_EmitsEvent`:**
    - Create server with `newMFAServerWithEvents`
    - Owner updates `mfa_required_all: true` → expect 200
    - Assert: `EventMFAOrgRequireAllEnabled` event emitted with `severity == "info"`

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/api/... -run "TestAdmin" -count=1` and confirm green
```

---

## Task 5: Auth MFA Tests — Security-Critical (SC4 + SC5 + SC12 + A4 + A5)

**Findings closed:** SC4 (email OTP confirm handler error branches), SC5 (pending token as access token), SC12 (cross-user enrollment attack), A4 (wrong code token absence check), A5 (well-formed-but-wrong-key challenge), plus SC1 event assertions for MFA verify/challenge

**Files to modify:** `internal/api/auth_mfa_test.go`

**Depends on:** Task 1 (event writer infrastructure)

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

Key handler code in `auth_mfa.go`:
- `mfaEmailOTPConfirmHandler` (line 825): 48.4% coverage. Calls `resolveEnrollmentUserID`, `checkNotAlreadyEnrolled`, `VerifyEmailOTPChallenge`, `CreateMFACredential`, `generateFirstEnrollmentRecoveryCodes`, `clearEnrollmentPending`.
- `mfaTOTPConfirmHandler` (line ~637): Has a guard `enrollClaims.UserID != userID` for cross-user enrollment.
- The middleware `RequireAuthenticated` only accepts `access_token` cookies.

### Implementation

#### SC4: mfaEmailOTPConfirmHandler error branches

1. **`TestEmailOTPConfirm_WrongCode`:**
   - Register user, login (get access_token cookies)
   - Start email OTP setup (POST /auth/mfa/email-otp/setup) — this creates a challenge
   - Submit wrong code "000000" to POST /auth/mfa/email-otp/confirm
   - Expect HTTP 401 with body containing "invalid verification code"
   - Assert absence of `access_token` cookie in response

2. **`TestEmailOTPConfirm_AlreadyEnrolled`:**
   - Register user, login, directly create email_otp credential in DB via `enrollEmailOTP(t, ctx, srv, userID)`
   - Attempt POST /auth/mfa/email-otp/confirm with code "123456"
   - Expect HTTP 409 with body containing "email_otp already enrolled"

3. **`TestEmailOTPConfirm_NoAuth`:**
   - Send POST /auth/mfa/email-otp/confirm with no cookies at all
   - Expect HTTP 401

#### SC5: Pending token rejected as access token

4. **`TestPendingToken_RejectedAsAccessToken`:**
   - Register user, enroll TOTP (directly in DB)
   - Login → get pending token from `mfa_pending_token` cookie
   - Create a request to a protected endpoint (e.g., GET /auth/mfa/methods)
   - Set `access_token` cookie to the pending token value
   - Send the request
   - Expect HTTP 401 (the pending token has different claims, `ParseAccessToken` should reject it)
   - **Why this matters:** If `ParseAccessToken` doesn't check the `typ` claim or claim structure, a pending token could pass as an access token, bypassing MFA entirely.

#### SC12: Cross-user enrollment attack

5. **`TestTOTPConfirm_CrossUserEnrollment_Rejected`:**
   - Register User A, login as User A (get access_token cookies)
   - User A starts TOTP setup → gets `mfa_enroll_token` cookie and secret
   - Register User B, login as User B (get access_token cookies)
   - Generate valid TOTP code from User A's secret
   - User B attempts POST /auth/mfa/totp/confirm with:
     - User B's `access_token` cookie
     - User A's `mfa_enroll_token` cookie
     - The valid TOTP code
   - Expect HTTP 401 (the enrollment token's UserID doesn't match User B)

#### A4: Wrong code should not have auth cookies

6. **`TestMFAVerify_WrongCode_NoAuthCookies`:**
   - Register user, enroll TOTP, login (get pending token)
   - Submit wrong TOTP code via POST /auth/mfa/verify
   - Assert HTTP 401
   - Assert `cookieValue(resp, "access_token") == ""` (no access token issued)
   - Assert `cookieValue(resp, "refresh_token") == ""` (no refresh token issued)

#### A5: Well-formed JWT with wrong key as challenge input

7. **`TestMFAChallenge_WellFormedWrongKey`:**
   - Register user, enroll TOTP
   - Create a well-formed pending token signed with a different secret:
     ```go
     wrongSecret := []byte("wrong-secret-32-bytes-minimum-bb")
     fakeToken, _ := auth.IssuePendingToken(wrongSecret, userID, 1, []string{"mfa_challenge"}, []string{"totp"}, 5*time.Minute)
     ```
   - Send POST /auth/mfa/challenge with `mfa_pending_token` cookie set to `fakeToken`, body `{"method":"totp"}`
   - Expect HTTP 401 with body containing "invalid or expired pending token"

8. **`TestMFAChallenge_ExpiredPendingToken`:**
   - Create an expired pending token:
     ```go
     expiredToken, _ := auth.IssuePendingToken(secret, userID, 1, []string{"mfa_challenge"}, []string{"totp"}, -1*time.Second)
     ```
   - Send POST /auth/mfa/challenge with this token
   - Expect HTTP 401

#### SC1: Event assertions for MFA verify

9. **`TestMFAVerify_TOTP_EmitsSuccessEvent`:**
   - Use `newMFAServerWithEvents`
   - Register user, enroll TOTP, login (get pending token)
   - Submit correct TOTP code → expect 200
   - Flush events, query for `EventMFAVerifySuccess`
   - Assert event found with correct `user_id`

10. **`TestMFAVerify_TOTP_EmitsFailedEvent`:**
    - Use `newMFAServerWithEvents`
    - Register user, enroll TOTP, login (get pending token)
    - Submit wrong code "000000" → expect 401
    - Flush events, query for `EventMFAVerifyFailed`
    - Assert event found with correct `user_id`

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/api/... -run "TestEmailOTPConfirm|TestPendingToken_Rejected|TestTOTPConfirm_CrossUser|TestMFAVerify_WrongCode_No|TestMFAChallenge_WellFormed|TestMFAChallenge_Expired|TestMFAVerify_TOTP_Emits" -count=1` and confirm green
```

### Review Loop

```
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Task 6: Auth MFA Tests — Correctness + Nice-to-Have (C3 + C4 + N2-N7)

**Findings closed:** C3 (buildMFARequiredReasons multi-org), C4 (clearEnrollmentPending), N2 (reauthenticatePassword disabled), N3 (resolveAccessTokenUserID invalid), N4 (email OTP rate limit 429), N5 (remove non-existent method), N6 (second enrollment skip), N7 (email OTP setup rate limit), plus SC1 event assertions for enrollment/removal

**Files to modify:** `internal/api/auth_mfa_test.go`

**Depends on:** Task 1 (event writer infrastructure)

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

Key functions in `auth_mfa.go`:
- `buildMFARequiredReasons` (line 1306): queries 4 enforcement layers, returns structured `mfaRequiredReason` objects with `Source` and `OrgName` fields. At 50% coverage.
- `clearEnrollmentPending` (line 1272): removes `mfa_enrollment_required` from pending token. If no items remain, issues full auth tokens. At 50% coverage.
- `reauthenticatePassword` (line 1126): checks user exists, has password hash, verifies argon2. Returns error for OAuth-only accounts. At 66.7%.
- `resolveAccessTokenUserID` (line 1231): returns 401 for empty token, 401 for invalid/expired token. At 66.7%.
- `generateFirstEnrollmentRecoveryCodes` (line 1170): generates codes only if `credCount == 1`. At 53.8%.

### Implementation

#### C3: buildMFARequiredReasons multi-org

1. **`TestMFAMethods_RequiredReasons_MultiOrg`:**
   - Register user, login, get access_token
   - Create org A with `mfa_required_all = true` via `srv.store.UpdateOrgMFASettings`
   - Create org B, add user to org B, set per-member requirement on user in org B
   - GET /auth/mfa/methods
   - Parse response body, examine `required_reasons`
   - Assert: at least 2 reasons present
   - Assert: one reason has `source == "org_policy"` with org A's name
   - Assert: one reason has `source == "per_member"` with org B's name
   - Assert: `required == true`

2. **`TestMFAMethods_RequiredReasons_SiteAdmin`:**
   - Register user, mark as site admin, login
   - Set `cfg.MFARequiredSiteAdmins = true` on the server config
   - GET /auth/mfa/methods
   - Assert: reason with `source == "site_admin"` present
   - **Note:** This requires the server to have `MFARequiredSiteAdmins` set. Either create the server with this config field set, or modify the test server config. Read the `config.Config` struct to find the field name — likely `MFARequiredSiteAdmins`.

#### C4: clearEnrollmentPending — full auth token issuance

3. **`TestEnrollment_CompletionIssuesFullTokens`:**
   - Register user (no MFA yet)
   - Set org `mfa_required_all = true` to mandate enrollment
   - Login → get pending token with `["mfa_enrollment_required"]`
   - Start TOTP setup → get enrollment token and secret
   - Confirm TOTP enrollment with valid code
   - **Assert:** The response should include `access_token` and `refresh_token` cookies (full auth tokens issued by `clearEnrollmentPending`)
   - **Assert:** The `mfa_pending_token` cookie is cleared (MaxAge=-1 or empty value)
   - This tests the "all pending items cleared → issue full tokens" branch of `clearEnrollmentPending`

#### N2: reauthenticatePassword with OAuth-only account

4. **`TestMFARemoveMethod_OAuthOnlyAccount`:**
   - Register a user, clear their password hash in DB: `UPDATE users SET password_hash = NULL WHERE id = $1`
   - Login first (before clearing password), get access_token
   - Enroll TOTP and a second method (email_otp)
   - Attempt DELETE /auth/mfa/methods/totp with body `{"current_password": "anything"}`
   - Expect HTTP 400 with body containing "OAuth" or "password re-auth not available"

#### N3: resolveAccessTokenUserID with invalid token

5. **`TestMFAMethods_InvalidAccessToken`:**
   - Send GET /auth/mfa/methods with `access_token` cookie set to "garbage-not-a-jwt"
   - Expect HTTP 401

6. **`TestMFAMethods_ExpiredAccessToken`:**
   - Issue an expired access token: `auth.IssueAccessToken(secret, userID, 1, -1*time.Second)`
   - Send GET /auth/mfa/methods with this expired token as `access_token` cookie
   - Expect HTTP 401

#### N4: Email OTP rate limit 429 at API level

7. **`TestMFAChallenge_EmailOTP_RateLimit429`:**
   - Create server with `MFAEmailOTPMaxPerHour: 2` (low limit for testing)
   - Register user, enroll email_otp (directly in DB), enroll TOTP (so login gives pending token)
   - Login → get pending token
   - POST /auth/mfa/challenge with `{"method":"email_otp"}` — expect 200 (1st)
   - POST /auth/mfa/challenge with `{"method":"email_otp"}` — expect 200 (2nd)
   - POST /auth/mfa/challenge with `{"method":"email_otp"}` — expect 429
   - Assert response body contains "too many email OTP requests"

#### N5: Remove non-existent method

8. **`TestMFARemoveMethod_NotEnrolled`:**
   - Register user, login, enroll TOTP only
   - Attempt DELETE /auth/mfa/methods/email_otp with body `{"current_password": "correct-password"}`
   - Expect HTTP 404 or appropriate error (the method doesn't exist for this user)
   - **Note:** Read `mfaRemoveMethodHandler` to verify what status code it returns for a non-existent method. It calls `s.DeleteMFACredential` which returns rows affected. If 0 rows, it may return 404 or 200.

#### N6: Second enrollment skips recovery code generation

9. **`TestTOTPConfirm_SecondEnrollment_NoRecoveryCodes`:**
   - Register user, login
   - Enroll email_otp first (via setup + confirm, or directly in DB + setup TOTP)
   - Since email_otp is already enrolled (credCount > 1 after TOTP is added), TOTP confirm should NOT return recovery codes
   - **Setup flow:**
     1. Login, get cookies
     2. Create email_otp credential directly in DB (to simulate first enrollment already done)
     3. Also generate recovery codes for the user directly
     4. Start TOTP setup, confirm TOTP
     5. Assert: `recovery_codes` is empty/null in the confirm response (credCount == 2, not 1)

#### N7: Email OTP setup rate limit

10. **`TestEmailOTPSetup_RateLimit`:**
    - Create server with `MFAEmailOTPMaxPerHour: 2`
    - Register user, login, get access_token
    - POST /auth/mfa/email-otp/setup — expect 200
    - POST /auth/mfa/email-otp/setup — expect 200 (2nd sends another code)
    - Actually, email OTP setup also checks rate limits. Verify by reading `mfaEmailOTPSetupHandler` (line ~760). If it has the same `CountRecentEmailOTPChallenges` check, the 3rd call should return 429.
    - **Note:** The implementer should read the handler to verify the rate limit check exists in setup, not just challenge.

#### SC1: Event assertions for enrollment/removal

11. **`TestTOTPConfirm_EmitsEnrollmentEvent`:**
    - Use `newMFAServerWithEvents`
    - Register user, login, start TOTP setup, confirm TOTP
    - Flush events, query for `EventMFAMethodEnrolled`
    - Assert event has `details["method"] == "totp"`

12. **`TestMFARemoveMethod_EmitsRemovalEvent`:**
    - Use `newMFAServerWithEvents`
    - Register user, login, enroll TOTP + email_otp
    - Remove TOTP method (DELETE with correct password)
    - Flush events, query for `EventMFAMethodRemoved`
    - Assert event has `details["method"] == "totp"`

13. **`TestRecoveryCodeRegen_EmitsEvent`:**
    - Use `newMFAServerWithEvents`
    - Register user, login, enroll TOTP (gets first recovery codes)
    - POST /auth/mfa/recovery-codes/regenerate with `{"current_password": "..."}`
    - Flush events, query for `EventMFARecoveryCodesGenerated`
    - Assert event found

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/api/... -run "TestMFAMethods_Required|TestEnrollment_Completion|TestMFARemoveMethod|TestMFAChallenge_EmailOTP_Rate|TestTOTPConfirm_Second|TestEmailOTPSetup_Rate|TestTOTPConfirm_Emits|TestRecoveryCodeRegen_Emits" -count=1` and confirm green
```

---

## Task 7: Auth/Refresh Tests + Email Rendering + formatTTL (C5 + SC9 + N1)

**Findings closed:** C5 (refreshGrace/issueRefreshPair error paths), SC9 (MFA OTP email rendering test), N1 (formatTTL edge cases)

**Files to modify:** `internal/api/auth_test.go` (for C5), `internal/notify/render_test.go` (for SC9)

### Preamble

```
BEFORE starting work:
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Context

**refreshGrace** (auth.go line 606-628):
- Handles re-issue within the 60-second grace window after a refresh token is already used
- Branches: `!orig.ReplacedByJti.Valid` → 401; replacement token not found → 401; replacement already used → 401; version mismatch → 401; success → issueRefreshPair
- At 53.3% coverage

**issueRefreshPair** (auth.go line 631-652):
- Issues new access + refresh JWT pair, marks old JTI as used
- Error branches: IssueAccessToken fail, IssueRefreshToken fail, CreateRefreshToken fail, MarkRefreshTokenUsed fail → all 500
- At 50% coverage — the 500 error paths require DB/JWT failures that are hard to trigger naturally

**RenderMFAOTP** (notify/render.go line 133):
- Takes `MFAOTPData{Code string, ExpiresIn string}`, returns `(subject, htmlBody, textBody, error)`
- Currently at 0% coverage

### Implementation

#### C5: refreshGrace and refresh token reuse

1. **`TestRefresh_GraceWindow_TokenReuse`:**
   - Register user, login → get access + refresh tokens
   - Submit refresh (POST /auth/refresh) → get new tokens (token A → B rotation)
   - Immediately submit refresh with the OLD token (the one that was just consumed)
   - If within grace window (60 seconds), expect 200 with new tokens (grace path exercises `refreshGrace`)
   - Assert new access_token and refresh_token cookies are present

2. **`TestRefresh_TokenReuse_AfterGraceWindow`:**
   - This is harder to test without time manipulation. The grace window is typically 60 seconds.
   - **Alternative approach:** Submit refresh with old token, then submit it a SECOND time. The first reuse succeeds (grace), but the grace path's replacement token is now also marked used. A third attempt should fail.
   - Register user, login → tokens
   - First refresh (A→B) — success
   - Second refresh with A (grace: A→B→C) — success (if within window)
   - Third refresh with A — expect 401 "refresh token already used" (B is now consumed, no grace available)

3. **`TestRefresh_VersionMismatch_SessionInvalidated`:**
   - Register user, login → get tokens
   - Increment user's `token_version` via `srv.store.IncrementTokenVersion`
   - Submit refresh with the old refresh token
   - Expect 401 "session invalidated"

4. **`TestRefresh_TokenReuse_EmitsSecurityEvent`:**
   - Use a server with event writer
   - Register user, login → tokens
   - First refresh (A→B) — success
   - Second refresh with A — success (grace)
   - Third refresh with A — expect 401
   - **If** the "token reuse" path emits `EventAuthTokenReuseDetected`, assert the event exists
   - **Note:** Read auth.go lines 575-587 to confirm when the reuse detection event fires. It fires when a token is used but its `used_at` is set AND it's outside the grace window.

#### SC9: MFA OTP email rendering test

5. **`TestRenderMFAOTP_BasicOutput`** (in `internal/notify/render_test.go`):
   - Call `RenderMFAOTP(MFAOTPData{Code: "123456", ExpiresIn: "10 minutes"})`
   - Assert no error
   - Assert subject is non-empty and contains a relevant phrase (e.g., "verification" or "code")
   - Assert HTML body contains "123456" (the code)
   - Assert HTML body contains "10 minutes" (the expiry)
   - Assert text body contains "123456"
   - Assert text body contains "10 minutes"
   - Assert HTML body is non-empty
   - Assert text body is non-empty

6. **`TestRenderMFAOTP_SubjectSanitization`** (in `internal/notify/render_test.go`):
   - This is optional but valuable: verify the subject doesn't contain CRLF (header injection prevention)
   - Call `RenderMFAOTP(MFAOTPData{Code: "654321", ExpiresIn: "5 minutes"})`
   - Assert subject does not contain `\r` or `\n`

#### N1: formatTTL edge cases

7. **`TestFormatTTL`** (in `internal/api/auth_password_reset_test.go`):
   - `formatTTL` is at 76.9% — the untested branches are the hours-only and single-unit paths. The function is unexported, so call it from the same package.
   - Test cases:
     - `formatTTL(10 * time.Minute)` → `"10 minutes"`
     - `formatTTL(1 * time.Minute)` → `"1 minute"` (singular)
     - `formatTTL(2 * time.Hour)` → `"2 hours"`
     - `formatTTL(1 * time.Hour)` → `"1 hour"` (singular)
     - `formatTTL(24 * time.Hour)` → `"1 day"` (singular)
     - `formatTTL(48 * time.Hour)` → `"2 days"`
     - `formatTTL(90 * time.Minute)` → `"1 hour"` (rounds to hours when h > 0)
   - Use a table-driven test pattern:
     ```go
     func TestFormatTTL(t *testing.T) {
         tests := []struct{ d time.Duration; want string }{...}
         for _, tt := range tests {
             if got := formatTTL(tt.d); got != tt.want {
                 t.Errorf("formatTTL(%v) = %q, want %q", tt.d, got, tt.want)
             }
         }
     }
     ```

### Completion Check

```
BEFORE marking this task complete:
1. Review your tests against dev/testing-pitfalls.md
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./internal/api/... -run "TestRefresh" -count=1` and confirm green
5. Run `go test ./internal/notify/... -run "TestRenderMFAOTP" -count=1` and confirm green
```

### Review Loop (Final)

```
After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Finding-to-Task Mapping

| Finding | Severity | Task | Description |
|---------|----------|------|-------------|
| SC1 | Security-Critical | 1 + 4-7 | Event writer infrastructure + per-handler assertions |
| SC2 | Security-Critical | 4 | Cross-org admin endpoint isolation |
| SC3 | Security-Critical | 4 | adminForcePasswordReset negative cases |
| SC4 | Security-Critical | 5 | mfaEmailOTPConfirmHandler error branches |
| SC5 | Security-Critical | 5 | Pending token rejected as access token |
| SC6 | Security-Critical | 4 | Site admin + viewer role paths |
| SC7 | Security-Critical | 4 | Admin action side-effect assertions |
| SC8 | Security-Critical | 3 | Remember-device multi-org most-restrictive |
| SC9 | Security-Critical | 7 | MFA OTP email rendering |
| SC10 | Security-Critical | 2 | Enrollment token JWT security tests |
| SC11 | Security-Critical | 3 | UserMFARequired RequiredOrgOwners path |
| SC12 | Security-Critical | 5 | Cross-user enrollment attack |
| C1 | Correctness | 3 | Direct store tests for 5 methods |
| C2 | Correctness | 4 | adminUnrequireMFA RBAC |
| C3 | Correctness | 6 | buildMFARequiredReasons multi-org |
| C4 | Correctness | 6 | clearEnrollmentPending full token issuance |
| C5 | Correctness | 7 | refreshGrace/issueRefreshPair error paths |
| C6 | Correctness | 4 | checkAdminMFAPermission site admin (via SC6) |
| A1 | Assertion Quality | 4-7 | Security event payloads (via SC1) |
| A2 | Assertion Quality | 4 | TestAdminMFAReset side effects (via SC7) |
| A3 | Assertion Quality | 4 | TestAdminForcePasswordReset side effects (via SC7) |
| A4 | Assertion Quality | 5 | Wrong code token absence check |
| A5 | Assertion Quality | 5 | Well-formed-but-wrong-key challenge |
| N1 | Nice-to-Have | 7 | formatTTL edge cases |
| N2 | Nice-to-Have | 6 | reauthenticatePassword OAuth-only |
| N3 | Nice-to-Have | 6 | resolveAccessTokenUserID invalid token |
| N4 | Nice-to-Have | 6 | Email OTP rate limit 429 |
| N5 | Nice-to-Have | 6 | Remove non-existent method |
| N6 | Nice-to-Have | 6 | Second enrollment skip |
| N7 | Nice-to-Have | 6 | Email OTP setup rate limit |
| N8 | Nice-to-Have | 3 | Already-used recovery code |
| N9 | Nice-to-Have | 3 | Generate-then-verify round trip |
| N10 | Nice-to-Have | 3 | UpdateOrgMFASettings org-not-found |

## Deferred Items

None — all 36 findings from the consolidated report are covered in this plan.

## Execution Notes

- **Task dependency:** Tasks 2, 3 are independent and can run in parallel. Task 1 must complete before Tasks 4-7. Tasks 4-7 touch different files and can run in parallel after Task 1.
- **Parallel execution plan:** `[Task 1] → [Task 4 | Task 5 | Task 6 | Task 7]` with `[Task 2 | Task 3]` independent.
- **No production code changes** are expected. If the event writer infrastructure (Task 1) requires a minimal production change, document it clearly and get approval.
- **Test naming:** Follow the existing pattern in each file. Admin tests use `TestAdmin...`, auth MFA tests use `TestMFA...` or `TestEmailOTP...`, store tests use `TestStore_...` or `TestMFA_...`.
- **Config fields:** When a test needs non-default config (e.g., `MFARequiredSiteAdmins`, `MFARequiredOrgOwners`), the implementer must create a custom server with the appropriate config. Use the `newMFAServer` pattern but with the needed config field set.
