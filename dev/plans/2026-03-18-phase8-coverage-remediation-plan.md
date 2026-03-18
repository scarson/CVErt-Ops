# Phase 8 Test Coverage Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 1 production bug, 2 code gaps (audit logging), 3 design decisions (HMAC/SSRF/lockout), and close 28 security-critical + 35 correctness coverage gaps identified in the Phase 8 (A-E) test coverage review.

**Architecture:** Tests are integration tests using `testutil.NewTestDB(t)` for real Postgres via testcontainers. API tests use `newRegisterServer(t, db, "open")` for full HTTP stack. Audit tests use `newAuditServer(t, db)`. Cross-org tests create two users in separate orgs and verify org A can't access org B's data.

**Tech Stack:** Go, PostgreSQL, testcontainers-go, `net/http/httptest`

**References:**
- Consolidated findings: `dev/test-coverage-reports/2026-03-18-phase8-consolidated.md`
- Testing pitfalls: `dev/testing-pitfalls.md`
- Implementation pitfalls: `dev/implementation-pitfalls.md`
- Audit integration pattern: `internal/api/audit_integration_test.go` (use `newAuditServer`, `findAuditEntry`)
- Cross-org test pattern: `internal/api/groups_test.go:TestCrossOrg_GroupAccess`
- Contract helpers: `internal/api/contract.go` (`writeProblem`, `writeList`, `encodePageCursor`)

---

## Cross-Plan Sequencing

This plan is part of a coordinated three-plan remediation. See `dev\plans\2026-03-18-phase8-11-hr-remediation-sequencing.md` for the master execution order.

**This plan executes in two stages:**
- **Stage 2:** Batch 1 (Tasks 1–8) — production code fixes. Runs after HR Stage 1 code fixes.
- **Stage 4:** Batches 2–5 (Tasks 9–23+) — test coverage additions. Interleaved with HR test tasks.

**Ordering precedence:** For Stage 4 task ordering, the sequencing document takes precedence over the batch ordering in this plan. The batches below define logical grouping, but the actual execution order interleaves HR test tasks per the sequencing doc's Stage 4 table.

**Tasks merged with Health Review plan:**
- **Task 4** (webhook HMAC fix): Also apply HR F3 (TestBuildSafeClient assertions) in the same pass. Both modify `webhook_test.go`.
- **Task 6** (safeurl wrap): Also apply HR E5 (feed body size limit) in the same pass. Both modify the feed client in `main.go`. Compose transports: safeurl (inner) → body size limit (outer).

**Tasks combined in Stage 4:**
- **Tasks 12 + 17** (middleware_auth_test.go): Also apply HR D3 (pending token rejection test) in the same pass.

**Dependencies from Health Review (must be complete before this plan starts):**
- HR G5 (testChannelHandler returns 502) must be done before Task 16 (cross-org channel tests) — tests should assert against the corrected status code.
- HR C1 + E4 (main.go changes) must be done before Task 6 modifies main.go.

---

## Pre-Implementation Requirements (ALL agents)

**BEFORE writing ANY code, you MUST complete ALL of these steps in order:**

1. **Invoke `/test-driven-development`** (the skill at `.claude/skills/test-driven-development/`) — this loads the TDD methodology into your context. You MUST follow it for every task.
2. **Read `dev/testing-pitfalls.md` IN FULL** — not skimming, not referencing later, read the entire file NOW so every pitfall is in your working context while you write tests. This file has 16 sections and ~170 checklist items. Many apply directly to tasks in this plan. Each task calls out specific sections, but adjacent pitfalls also apply.
3. **Read `dev/implementation-pitfalls.md`** for Go/Postgres conventions (especially §2 transaction helpers, §4 RLS, §8 security)
4. **Read `CLAUDE.md`** for project rules (TDD, naming, comments, commit frequency, ABOUTME headers)

**MANDATORY QA CHECK — after EVERY task and before marking it complete:**

1. **Re-read the specific `dev/testing-pitfalls.md` sections** called out in the task's "Pitfall check" line
2. **Review every new test** against these questions — if the answer to any is "no", fix the test before proceeding:
   - Does this test assert **behavior** (return values, DB state, HTTP response body), not just **execution** (`err == nil`)?
   - Does this test include at least one **negative case** (rejection, error, forbidden)?
   - Are assertions **unconditional** (no `if status == 200 { assert... }` patterns)?
   - If testing a security property, is the test using **well-formed-but-wrong** input (not just `"invalid"`)?
3. Run `go test ./...` (or the relevant package tests) and confirm all pass
4. Run `golangci-lint run` on changed packages and fix any issues
5. Commit with a descriptive message

**IMPORTANT — Read before edit:** Every task lists files to modify. Read them FIRST before making changes. Line numbers in this plan are approximate — find the correct insertion point by reading the current file.

**DO NOT:** Add features, refactor code, or make "improvements" beyond what each task specifies. If you notice something that should be fixed but isn't in this plan, note it in your journal — don't fix it.

---

## Batch 1: Production Bug + Code Gaps (Priority 0)

These are code fixes, not just test additions. Each task includes both the fix AND the test.

### Task 1: Fix Generic Feed Cursor Pagination Infinite Fetch (B1)

**Finding:** B1 in consolidated report
**Files:**
- Modify: `internal/feed/generic/config.go` — `Validate()` function (~line 70-132)
- Modify: `internal/feed/generic/config_test.go`

**Context:** `Validate()` checks that `pagination.type` is a valid enum value but does NOT validate that dependent sub-fields are set. A config with `pagination.type: cursor` but empty `cursor_param` causes `buildURL` to return a malformed URL and fetch the same page infinitely.

**Step 1: Write failing tests for dependent field validation**

Add three test cases to the existing config validation tests:
1. `pagination.type: cursor` with empty `cursor_param` → expect validation error containing "cursor_param is required"
2. `pagination.type: cursor` with empty `cursor_path` → expect validation error containing "cursor_path is required"
3. `pagination.type: offset` with empty `page_param` → expect validation error containing "page_param is required"

Also add a positive test: `pagination.type: cursor` with both `cursor_param` and `cursor_path` set → expect no error from pagination validation.

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/feed/generic/ -v -run TestValidate -count=1`
Expected: FAIL — validation currently accepts these invalid configs.

**Step 3: Add dependent sub-field validation to Validate()**

After the `pagination.type` switch block (after line 126), add:

```go
// Dependent field validation for pagination types.
switch c.Pagination.Type {
case "cursor":
    if c.Pagination.CursorParam == "" {
        errs = append(errs, "pagination.cursor_param is required when type is cursor")
    }
    if c.Pagination.CursorPath == "" {
        errs = append(errs, "pagination.cursor_path is required when type is cursor")
    }
case "offset":
    if c.Pagination.PageParam == "" {
        errs = append(errs, "pagination.page_param is required when type is offset")
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/feed/generic/ -v -run TestValidate -count=1`
Expected: PASS

**Step 5: Run full generic package tests**

Run: `go test ./internal/feed/generic/... -count=1`
Expected: All pass — no existing test should break since all existing cursor configs have `cursor_param` set.

**Step 6: Commit**

**Pitfall check:** tp§5 "Dependent config sub-field validation" — this is the exact pitfall we're fixing.

---

### Task 2: Add Audit Logging to Groups Handler (D4/SC27)

**Finding:** SC27 in consolidated report — CODE gap, not just test gap
**Files:**
- Modify: `internal/api/groups.go` — add `audit.Entry` calls to 5 mutating operations
- Create or modify: `internal/api/audit_integration_test.go` — add `TestAuditIntegration_Groups`

**Context:** Every other mutating handler group (channels, alert_rules, watchlists, saved_searches, sso, orgs) has audit logging. Groups has zero. The pattern: call `srv.auditLog(r, audit.Entry{...})` after the successful mutation. See `channels.go` for the pattern — each mutation gets an `Action` string, `EntityType: "group"` or `"group_member"`, and `EntityID` set to the group's UUID.

**⚠️ Audit logging design:** `srv.auditLog` is fire-and-forget (async write via the event writer). It does NOT participate in the handler's database transaction — it runs after the mutation commits. If the audit write fails, the mutation still succeeds. This satisfies NIST SP 800-53 AU-5 (all baselines) and IEC 62443 CR 2.10 (continue operating + alert). It does NOT satisfy AU-10 Non-repudiation (HIGH baseline only) for security-critical mutations — that is a future design phase item. Do NOT wrap audit calls in the handler's transaction. Match the existing `channels.go` pattern exactly.

See `dev/research-findings/auditing-gaps.md` for the full standards analysis and remediation path.

**Step 0 (prerequisite): Add Prometheus counter for audit write failures**

Before adding new audit calls, add a failure counter to the audit writer so failures are observable (NIST AU-5 compliance — see `dev/research-findings/auditing-gaps.md`):

1. Create `internal/metrics/audit.go`:
```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var AuditWriteFailures = promauto.NewCounter(prometheus.CounterOpts{
    Name: "cvertops_audit_write_failures_total",
    Help: "Audit log entries that failed to write to the database.",
})
```

2. In `internal/audit/writer.go`, add `import "github.com/scarson/cvert-ops/internal/metrics"` and add `metrics.AuditWriteFailures.Inc()` at both error sites (marshal failure ~line 67, insert failure ~line 72).

This is a one-time prerequisite — Tasks 3, 7, 8 benefit automatically.

**Step 1: Read the existing audit integration test pattern**

Read `internal/api/audit_integration_test.go` (specifically `TestAuditIntegration_Channels`) and `internal/api/channels.go` audit calls to understand the exact pattern.

**Step 2: Write failing test `TestAuditIntegration_Groups`**

Follow the pattern from `TestAuditIntegration_Channels`:
1. Create server with `newAuditServer(t, db)`
2. Register a user, get token
3. Create a group → flush audit → assert `findAuditEntry(t, db, orgID, "group", "create")` is non-nil
4. Update the group → flush → assert `findAuditEntry(t, db, orgID, "group", "update")` is non-nil
5. Add a member → flush → assert `findAuditEntry(t, db, orgID, "group_member", "add")` is non-nil
6. Remove a member → flush → assert `findAuditEntry(t, db, orgID, "group_member", "remove")` is non-nil
7. Delete the group → flush → assert `findAuditEntry(t, db, orgID, "group", "delete")` is non-nil

**Step 3: Run test to verify it fails**

Expected: FAIL — no audit entries found (groups.go has no audit calls).

**Step 4: Add audit logging to groups.go**

Add `"github.com/scarson/cvert-ops/internal/audit"` to imports. Add `srv.auditLog(r, audit.Entry{...})` after each successful mutation:
- `createGroupHandler`: after `srv.store.CreateGroup` succeeds → `Action: "create", EntityType: "group", EntityID: groupID`
- `updateGroupHandler`: after `srv.store.UpdateGroup` succeeds → `Action: "update", EntityType: "group", EntityID: groupID`
- `deleteGroupHandler`: after `srv.store.SoftDeleteGroup` succeeds → `Action: "delete", EntityType: "group", EntityID: groupID`
- `addGroupMemberHandler`: after `srv.store.AddGroupMember` succeeds → `Action: "add", EntityType: "group_member", EntityID: groupID`
- `removeGroupMemberHandler`: after `srv.store.RemoveGroupMember` succeeds → `Action: "remove", EntityType: "group_member", EntityID: groupID`

Include `NewState` with the group name/description for create/update, and `OldState` for delete. Follow the channels.go pattern for state capture.

**Step 5: Run test to verify it passes**

Run: `go test ./internal/api/ -v -run TestAuditIntegration_Groups -count=1 -timeout=300s`
Expected: PASS

**Step 6: Run full API tests**

Run: `go test ./internal/api/... -count=1 -timeout=300s`

**Step 7: Commit**

**Pitfall check:** tp§7 "Audit trail completeness" — this fixes the exact pitfall.

---

### Task 3: Add Audit Logging to Ingest Handler (D5/SC28)

**Finding:** SC28 in consolidated report — CODE gap
**Files:**
- Modify: `internal/api/ingest.go` — add audit logging after successful ingestion
- Modify: `internal/api/audit_integration_test.go` — add `TestAuditIntegration_Ingest`

**Context:** The ingest handler accepts external CVE data via webhook. There's no audit trail for what data was ingested, by whom, or from which source. Add an audit entry after the successful processing loop.

**Step 1: Write failing test**

Add `TestAuditIntegration_Ingest`:
1. `newAuditServer(t, db)`, register user, get token
2. POST a valid ingest request with 2 patches
3. Flush audit writer
4. Assert `findAuditEntry(t, db, orgID, "ingest", "create")` is non-nil
5. Assert the entry's `NewState` contains the source_name and patch count

**Step 2: Run test — expect FAIL**

**Step 3: Add audit logging to ingestHandler**

After the processing loop completes (after the `results` slice is built), add:
```go
srv.auditLog(r, audit.Entry{
    Action:     "create",
    EntityType: "ingest",
    NewState:   map[string]any{"source_name": req.SourceName, "patch_count": len(req.Patches), "accepted": accepted, "rejected": rejected},
})
```

Add `"github.com/scarson/cvert-ops/internal/audit"` to imports.

**Step 4: Run test — expect PASS**

**Step 5: Run full API tests, commit**

---

### Task 4: Skip Webhook HMAC When Secret Is Empty (D3)

**Finding:** SC22 / D3 in consolidated report
**Files:**
- Modify: `internal/notify/webhook.go` — guard HMAC computation on non-empty secret
- Modify or create: `internal/notify/webhook_test.go` — add empty-secret test

**Context:** Currently `Send()` computes HMAC with an empty key when `SigningSecret` is empty, sending a misleading signature header. GitHub and other providers omit the header entirely when no secret is configured.

**Step 1: Write failing test**

```go
func TestWebhookSend_EmptySecret_NoSignatureHeader(t *testing.T) {
    // Create a test server that captures request headers
    var capturedHeaders http.Header
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        capturedHeaders = r.Header.Clone()
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()

    cfg := WebhookConfig{URL: ts.URL, SigningSecret: ""}
    err := Send(context.Background(), ts.Client(), cfg, []byte(`{"test":true}`))
    require.NoError(t, err)

    // Signature headers must NOT be present when secret is empty
    assert.Empty(t, capturedHeaders.Get("X-CVErtOps-Signature"), "signature header should be absent with empty secret")
    assert.Empty(t, capturedHeaders.Get("X-CVErt-Timestamp"), "timestamp header should be absent with empty secret")
}
```

Also add a positive test verifying that when `SigningSecret` is non-empty, the headers ARE present.

**Step 2: Run test — expect FAIL** (currently sends headers with empty-key HMAC)

**Step 3: Guard HMAC block on non-empty secret**

In `webhook.go`, wrap the HMAC computation block (lines 56-67) in:
```go
if cfg.SigningSecret != "" {
    // existing HMAC code...
}
```

**Step 4: Run tests — expect PASS**

**Step 5: Run full notify package tests, commit**

**Pitfall check:** tp§8 "Production client configuration exercised in tests"

---

### Task 5: Lockout Fail-Open Regression Test (D1)

**Finding:** D1 / SEM-1 in consolidated report
**Files:**
- Modify: `internal/api/lockout_test.go` or create test in appropriate file

**Context:** `lockoutManager.Check()` at `lockout.go:44` intentionally fails open on DB errors (returns `allowed=true`), with rate limiter as secondary defense. The comment at line 53-54 documents this. Add a regression test so this design decision can't be accidentally changed.

**Step 1: Write the regression test**

The test needs to simulate a DB error from `GetLoginLockoutState`. Since `lockoutManager` takes a `store` interface, you'll need to check what interface methods it uses and either use a mock or trigger a real DB error.

Read `lockout.go` to understand the store interface dependency. Determine what interface `lockoutManager` depends on (likely a subset of `*store.Store` methods). Then:

**How to simulate the DB error:** If `lockoutManager` accepts an interface (check the constructor), create a test-only struct that implements only `GetLoginLockoutState` and returns `fmt.Errorf("simulated DB failure")`. If it takes a concrete `*store.Store`, you'll need to use a testcontainer DB and force a failure (e.g., close the DB pool before calling Check). Read the constructor to determine which approach works.

The test should:
1. Create a lockout manager with a store/interface that returns an error from `GetLoginLockoutState`
2. Call `Check()` with any email
3. Assert `allowed == true` (fail-open behavior)
4. Add a comment: `// Regression: lockout must fail open on DB errors — rate limiter is secondary defense`

**Step 2: Run test — expect PASS** (this tests existing behavior)

**Step 3: Commit**

**Pitfall check:** tp§11 "Fail-open regression tests"

---

### Task 6: Wrap Generic Feed Client in SafeURL (D2)

**Finding:** D2 in consolidated report
**Files:**
- Modify: `cmd/cvert-ops/main.go` — wrap `feedClient` with safeurl for generic feeds
- Add test to verify safeurl is used

**Context:** `feedClient` in main.go (line 177) is `&http.Client{Timeout: 5 * time.Minute}` — no SSRF protection. Built-in feeds use hardcoded URLs (NVD, MITRE, etc.) so SSRF isn't a concern there. But generic feeds use admin-configured URLs, so they need safeurl protection.

**Step 1: Read main.go lines 176-184 to understand the current wiring**

The current code creates one `feedClient` for all feeds. For SSRF protection on generic feeds only, either:
- Create a separate safeurl-wrapped client for generic feeds, OR
- Wrap the existing feedClient with safeurl for all feeds (simpler, no downside)

The simpler approach: wrap `feedClient` with safeurl for all outbound feed fetches. This is safe because built-in feeds only contact known public endpoints.

**Step 2: Write a test verifying the adapter rejects internal URLs**

In `internal/feed/generic/adapter_test.go`, add:
```go
func TestAdapter_SSRFProtection(t *testing.T) {
    // This test verifies that the adapter's client (when constructed with safeurl)
    // rejects private IP targets. In production, main.go passes a safeurl-wrapped client.
    cfg := &Config{Name: "ssrf-test", URL: "http://127.0.0.1:9999/api", Format: "json", ...}
    safeClient := notify.BuildSafeClient() // reuse the existing safeurl builder
    adapter := NewAdapter(cfg, safeClient)
    _, err := adapter.Fetch(context.Background())
    assert.Error(t, err) // safeurl should block 127.0.0.1
}
```

NOTE: Check what `notify.BuildSafeClient()` returns and whether it's reusable. If not, construct a safeurl client inline. Read `internal/notify/webhook.go` for the `BuildSafeClient` function.

**Step 3: Modify main.go to use safeurl**

Replace `feedClient := &http.Client{Timeout: 5 * time.Minute}` with a safeurl-wrapped client. Check how `notify.BuildSafeClient()` works and reuse the pattern. Import `doyensec/safeurl` if needed.

**⚠️ Merged with HR E5:** Also implement `maxBodyTransport` (body size limit) as an outer wrapper. Transport composition order: `safeurl.Transport` (inner, handles SSRF) → `maxBodyTransport` (outer, adds `io.LimitReader` on response body). The body limit should be configurable (default: 512MB for bulk feed archives). See HR plan Task E5 for the `maxBodyTransport` implementation details.

**Scope boundary:** Do NOT modify any feed adapter code in `internal/feed/`. Only modify the client construction in `cmd/cvert-ops/main.go`. The adapters receive the client via dependency injection and don't need to change.

**Step 4: Run tests, commit**

**Pitfall check:** `testing-pitfalls.md` §8 — "Production client configuration exercised in tests." The SSRF test in Step 2 exercises the production safeurl client. Verify it uses the SAME client construction path as main.go — not a separately-constructed test client that might have different settings.

---

### Task 7: Add Audit Logging to Reports Handler (Pre-existing)

**Finding:** Pre-existing gap — reports.go has 0 audit logging
**Files:**
- Modify: `internal/api/reports.go` — add audit.Entry calls to create, patch, delete, bind/unbind channel
- Modify: `internal/api/audit_integration_test.go` — add `TestAuditIntegration_Reports`

**Context:** The reports handler has 5 mutating operations (create, patch, delete, bind channel, unbind channel) with zero audit logging. Every other handler group that mutates data (channels, alert_rules, watchlists, saved_searches, SSO, orgs, and now groups from Task 2) has audit logging.

**Step 1: Read the audit integration test pattern**

Read `internal/api/audit_integration_test.go` — specifically `TestAuditIntegration_Channels` (~line 196). Understand:
- `newAuditServer(t, db)` creates a server + httptest.Server + audit.Writer
- `aw.Flush()` forces async audit writes to complete
- `findAuditEntry(t, db, orgID, entityType, action)` queries for matching audit entries

Also read `internal/api/channels.go` audit calls to see the exact `audit.Entry{}` field pattern.

**Step 2: Read reports.go fully**

Find the 5 mutation handlers: `createReportHandler`, `patchReportHandler`, `deleteReportHandler`, `bindChannelToReportHandler`, `unbindChannelFromReportHandler`. Note where each mutation succeeds (the store call returns without error) — that's where the audit call goes.

**Step 3: Write failing test `TestAuditIntegration_Reports`**

```go
func TestAuditIntegration_Reports(t *testing.T) {
    t.Parallel()
    db := testutil.NewTestDB(t)
    ctx := context.Background()
    _, ts, aw := newAuditServer(t, db)

    reg := doRegister(t, ctx, ts, "reports-audit@example.com", "test-password-1234")
    loginResp := doLogin(t, ctx, ts, "reports-audit@example.com", "test-password-1234")
    defer loginResp.Body.Close()
    token := cookieValue(loginResp, "access_token")
    orgID := mustParseUUID(t, reg.OrgID)

    // Create report
    // ... (POST /orgs/{orgID}/reports with name, schedule, etc.)
    aw.Flush()
    entry := findAuditEntry(t, db, orgID, "report", "create")
    if entry == nil { t.Error("expected audit entry for report create") }

    // Patch report
    // ... (PATCH /orgs/{orgID}/reports/{id})
    aw.Flush()
    entry = findAuditEntry(t, db, orgID, "report", "update")
    if entry == nil { t.Error("expected audit entry for report update") }

    // Delete report
    // ... (DELETE /orgs/{orgID}/reports/{id})
    aw.Flush()
    entry = findAuditEntry(t, db, orgID, "report", "delete")
    if entry == nil { t.Error("expected audit entry for report delete") }
}
```

Use helper functions from the test file (e.g., `doCreateReport` if it exists, or construct requests manually following the pattern in existing report tests at `internal/api/reports_test.go`).

**Step 4: Run test — expect FAIL** (no audit entries because reports.go has no audit calls)

**Step 5: Add audit logging to reports.go**

Add `"github.com/scarson/cvert-ops/internal/audit"` to imports. For each mutation handler, add `srv.auditLog(r, audit.Entry{...})` after the successful store call:

- `createReportHandler`: `Action: "create", EntityType: "report", EntityID: reportID.String()`
- `patchReportHandler`: `Action: "update", EntityType: "report", EntityID: reportID`
- `deleteReportHandler`: `Action: "delete", EntityType: "report", EntityID: reportID`
- `bindChannelToReportHandler`: `Action: "bind", EntityType: "report_channel_binding", EntityID: reportID`
- `unbindChannelFromReportHandler`: `Action: "unbind", EntityType: "report_channel_binding", EntityID: reportID`

Include `NewState` map with report name for create/update. Follow the channels.go pattern exactly for state capture structure.

**Step 6: Run test — expect PASS**

**Step 7: Run full API tests** (`go test ./internal/api/... -count=1 -timeout=300s`), then commit.

**Pitfall check:** tp§7 "Audit trail completeness"

---

### Task 8: Add Audit Logging to API Keys Handler (Pre-existing)

**Finding:** Pre-existing gap — apikeys.go has 0 audit logging
**Files:**
- Modify: `internal/api/apikeys.go` — add audit.Entry calls to create and revoke
- Modify: `internal/api/audit_integration_test.go` — add `TestAuditIntegration_APIKeys`

**Context:** API key creation and revocation have no audit trail. Two mutating operations: createAPIKeyHandler and revokeAPIKeyHandler.

**Step 1: Read the audit integration test pattern**

Same as Task 7 Step 1 — read `audit_integration_test.go` and the channels.go audit pattern.

**Step 2: Read apikeys.go fully**

Find the 2 mutation handlers: `createAPIKeyHandler`, `revokeAPIKeyHandler`. Note where each succeeds.

**Step 3: Write failing test `TestAuditIntegration_APIKeys`**

1. `newAuditServer(t, db)`, register user, get token
2. Create an API key (POST /orgs/{orgID}/api-keys)
3. `aw.Flush()` → assert `findAuditEntry(t, db, orgID, "api_key", "create")` is non-nil
4. Revoke the API key (DELETE /orgs/{orgID}/api-keys/{id})
5. `aw.Flush()` → assert `findAuditEntry(t, db, orgID, "api_key", "revoke")` is non-nil

**Step 4: Run test — expect FAIL**

**Step 5: Add audit logging to apikeys.go**

Add `"github.com/scarson/cvert-ops/internal/audit"` to imports.

- `createAPIKeyHandler`: `Action: "create", EntityType: "api_key", EntityID: keyID.String()`, `NewState: map[string]any{"name": req.Name, "permissions": req.Permissions, "expires_at": req.ExpiresAt}`
- `revokeAPIKeyHandler`: `Action: "revoke", EntityType: "api_key", EntityID: keyID`

**SECURITY CRITICAL:** The `NewState` for create must NOT include the raw API key value or hash. Include only: key ID, name, permissions, expiry.

**Step 6: Run test — expect PASS**

**Step 7: Run full API tests, commit**

**Pitfall check:** tp§7 "Audit trail completeness"

---

**After completing Batch 1:**
```
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.
```

---

## Batch 2: Admin Endpoint Tests (Security-Critical)

### Task 9: adminConfigHandler Secret Redaction Test (SC1)

**Finding:** SC1 — 0% coverage, secrets leak risk
**Files:**
- Create or modify: `internal/api/admin_system_test.go`

**Context:** `adminConfigHandler` at `admin_system.go:34` returns runtime config with secrets redacted via `redactSecret()`. Zero tests verify the redaction works. Also test `redactSecret` directly.

**Step 1: Write tests**

```go
func TestAdminConfigHandler_SecretsRedacted(t *testing.T) {
    t.Parallel()
    db := testutil.NewTestDB(t)
    ctx := context.Background()
    srv, ts := newRegisterServer(t, db, "open")
    // Make user site admin
    reg := doRegister(t, ctx, ts, "admin@example.com", "test-password-1234")
    makeSiteAdmin(t, db, reg.UserID)
    loginResp := doLogin(t, ctx, ts, "admin@example.com", "test-password-1234")
    defer loginResp.Body.Close()
    token := cookieValue(loginResp, "access_token")

    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/config", nil)
    req.Header.Set("Cookie", "access_token="+token)
    resp, err := ts.Client().Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, 200, resp.StatusCode)

    var body map[string]any
    json.NewDecoder(resp.Body).Decode(&body)

    // Verify ALL secrets are redacted, not exposed.
    // This list must match every field that redactSecret() is called on in adminConfigHandler.
    // Read admin_system.go to verify completeness — if any new secret field was added, add it here.
    secretFields := []string{"jwt_secret", "jwt_secret_previous", "database_url", "database_url_migrate", "smtp_password", "sso_encryption_key", "gemini_api_key", "encryption_key", "encryption_key_previous"}
    for _, field := range secretFields {
        val, ok := body[field].(string)
        if ok && val != "" {
            assert.Equal(t, "***", val, "secret field %s should be redacted", field)
            assert.NotEqual(t, srv.cfg.JWTSecret, val, "field %s must not contain actual secret", field)
        }
    }
}

func TestRedactSecret(t *testing.T) {
    assert.Equal(t, "***", redactSecret("my-secret"))
    assert.Equal(t, "", redactSecret(""))
}
```

NOTE: Check how `makeSiteAdmin` works — look for existing test helpers. If none exists, read the test pattern from `admin_reload_test.go` or `admin_security_events_test.go` which also need site admin.

**Step 2: Run tests — expect PASS** (testing existing behavior)

**Step 3: Commit**

**Pitfall check:** tp§5 "Config endpoint secret redaction"

---

### Task 10: Admin User Management Tests (SC2)

**Finding:** SC2 — 5 handlers at 0%
**Files:**
- Create: `internal/api/admin_users_test.go`

**Context:** 5 handlers: adminListUsersHandler, adminDisableUserHandler, adminEnableUserHandler, adminUnlockUserHandler, adminResetPasswordHandler. All at 0%. Read `admin_users.go` completely before writing tests.

**Step 1: Read admin_users.go fully**

Understand: self-disable prevention, security event emission, disabled-user idempotency, password reset flow.

**Step 2: Write tests for each handler**

At minimum test:
1. `TestAdminListUsers_BasicPagination` — list returns users with proper envelope
2. `TestAdminDisableUser_Success` — disable a non-admin user, verify `disabled_at` is set
3. `TestAdminDisableUser_SelfDisablePrevented` — admin tries to disable themselves, expect 400/409
4. `TestAdminEnableUser_Success` — disable then enable, verify `disabled_at` cleared
5. `TestAdminUnlockUser_Success` — lock a user (via failed logins), admin unlocks
6. `TestAdminResetPassword_Success` — reset triggers `force_password_reset` flag
7. `TestAdminUsers_RequiresSiteAdmin` — non-admin gets 403 (verify middleware wiring)

**Step 3: Run tests — expect PASS** (testing existing behavior, no code changes needed)

**Step 4: Commit**

**Pitfall check:** tp§13 "Admin flag enforcement at all entry points"

---

### Task 11: Admin Audit Log and Deliveries Tests (SC16, C1)

**Finding:** SC16 (admin audit log at 0%) + C1 (admin deliveries at 0%)
**Files:**
- Create or modify: `internal/api/admin_system_test.go` — admin audit log tests
- Create: `internal/api/admin_deliveries_test.go` — admin deliveries tests

**Step 1: Write admin audit log handler tests**

1. `TestAdminAuditLog_BasicList` — returns entries across orgs
2. `TestAdminAuditLog_FilterByEntityType` — filter parameter works
3. `TestAdminAuditLog_Pagination` — cursor pagination works
4. `TestAdminAuditLog_RequiresSiteAdmin` — non-admin gets 403

**Step 2: Write admin deliveries handler tests**

1. `TestAdminDeliveries_BasicList` — returns deliveries
2. `TestAdminRetryDelivery_Success` — retry re-enqueues
3. `TestAdminDeliveries_RequiresSiteAdmin` — non-admin gets 403

**Step 3: Run tests, commit**

---

**After completing Batch 2:**
```
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (minimum 3 rounds).
```

---

## Batch 3: Auth/MFA Security Tests

### Task 12: tryAPIKeyAuth Revoked/Disabled Key Tests (SC3)

**Finding:** SC3 — 62.1% coverage, revoked-key and disabled-user paths untested
**Files:**
- Modify: `internal/api/middleware_auth_test.go`

**Step 1: Read middleware_auth.go:105 (tryAPIKeyAuth) fully**

Understand: revoked-key security event emission, disabled-user rejection, org membership check.

**Step 2: Write tests**

1. `TestTryAPIKeyAuth_RevokedKey_401` — create API key, revoke it, make request, assert 401
2. `TestTryAPIKeyAuth_DisabledUser_401` — create API key, disable the user, make request with API key, assert 401
3. Verify security events are emitted for revoked-key usage (if the handler emits them)

**Step 3: Run tests, commit**

**Pitfall check:** tp§11 "Security check enforcement across similar endpoints"

---

### Task 13: loginHandler Critical Paths (SC4)

**Finding:** SC4 — 71.5%, disabled-user, MFA enrollment, remember-device paths uncovered
**Files:**
- Modify: `internal/api/auth_test.go`

**Step 1: Read auth.go loginHandler (~line 265) fully**

**Step 2: Write tests for uncovered paths**

1. `TestLogin_DisabledUser_Rejected` — disable user (`disabled_at IS NOT NULL`), attempt login, assert appropriate error (not 500). **`testing-pitfalls.md` §13:** Verify the disabled check fires in the login handler itself, not just middleware — the login handler runs before auth middleware.
2. `TestLogin_MFAEnrollmentRequired_PendingToken` — if org requires MFA and user has none, login returns pending token with MFA enrollment step (read the handler to understand the exact response shape)
3. `TestLogin_RememberDeviceCookie` — if remember-device cookie is present and valid, MFA step is skipped

NOTE: These tests require understanding the MFA flow. Read the handler fully before writing tests. If MFA enrollment requires complex setup, focus on the disabled-user path first (simplest and most security-critical).

**Pitfall check:** `testing-pitfalls.md` §13 — Admin flag enforcement at all entry points. Verify `disabled_at` is checked in the login handler, not only in middleware (middleware runs on authenticated requests; login is unauthenticated).

**Step 3: Run tests, commit**

---

### Task 14: refreshHandler Theft Detection (SC5)

**Finding:** SC5 — refreshHandler 72.4%, refreshGrace 53.3%, issueRefreshPair 50%
**Files:**
- Modify: `internal/api/auth_test.go`

**Step 1: Read auth.go refreshHandler and refreshGrace fully**

Understand the token theft detection mechanism: when a refresh token is reused after rotation, it indicates theft.

**Step 2: Write tests**

1. `TestRefresh_TokenTheftDetection` — use a refresh token, then use the OLD (pre-rotation) token again. Assert that the second use is rejected AND triggers a security response (session invalidation or security event).
2. `TestRefresh_GraceWindow` — if a grace window exists, verify that a slightly-old token within the grace period is accepted, but beyond the window is rejected.

**Pitfall check:** `testing-pitfalls.md` §11 — "Multi-step restricted session state consistency." If the refresh handler mutates DB state (e.g., incrementing `token_version`), verify the newly issued token reflects the post-mutation state.

**Step 3: Run tests, commit**

---

### Task 15: MFA Handler Coverage (SC6-SC10)

**Finding:** SC6 (mfaEmailOTPConfirmHandler 48.4%), SC7 (sendMFAOTPEmail 37.5%), SC8 (mfaRemoveMethodHandler 54.8%), SC9 (buildMFARequiredReasons 50%), SC10 (clearEnrollmentPending 50%)
**Files:**
- Modify: `internal/api/auth_mfa_test.go` or `internal/api/auth_mfa_integration_test.go`

**Context:** These are Phase 11 MFA handlers with low coverage. The most critical are:
- SC9: `buildMFARequiredReasons` — fail-closed logic (DB error → require MFA)
- SC10: `clearEnrollmentPending` — token issuance on final enrollment step

**Step 1: Read each handler fully before writing tests**

**Step 2: Write tests — prioritize SC9 and SC10**

For `buildMFARequiredReasons` (SC9):
- Test with org policy requiring MFA → returns reason
- Test with per-user requirement → returns reason
- Test with admin-set flag → returns reason
- Test with NO requirements → returns empty

For `clearEnrollmentPending` (SC10):
- Test that when last pending step clears, full auth tokens are issued (not just cookie cleared)

For `mfaEmailOTPConfirmHandler` (SC6):
- Test successful confirmation flow (if SMTP is configured in test env, or mock)

For `sendMFAOTPEmail` (SC7):
- Test with SMTP not configured → appropriate error
- Test with SMTP configured → email sent (requires Mailpit or mock)

For `mfaRemoveMethodHandler` (SC8):
- Test removal of last MFA method when org requires MFA → should be blocked
- Test removal when other methods exist → should succeed

**Step 3: Run tests, commit**

**Pitfall check:** tp§11 "Multi-layer authorization negative cases", tp§11 "Full auth token issuance on restricted session completion"

---

### Task 16: Cross-Org Isolation Tests (SC24-SC26)

**Finding:** SC24 (MFA admin), SC25 (channels), SC26 (ingest) — no dedicated cross-org tests
**Files:**
- Modify: `internal/api/admin_mfa_test.go` — add MFA cross-org test
- Modify: `internal/api/channels_test.go` — add channels cross-org test
- Modify: `internal/api/ingest_test.go` — add ingest cross-org test

**Context:** Follow the pattern from `TestCrossOrg_GroupAccess` in `groups_test.go`:
1. Alice owns org A, Bob owns org B
2. Bob tries to access org A's resources → expect 403

**Step 1: Write `TestCrossOrg_MFAAdminActions`**

Bob (admin of org B) tries to:
- POST /orgs/{orgA}/members/{aliceUID}/reset-mfa → 403
- POST /orgs/{orgA}/members/{aliceUID}/force-password-reset → 403
- POST /orgs/{orgA}/members/{aliceUID}/require-mfa → 403
- PATCH /orgs/{orgA}/mfa-settings → 403

**Step 2: Write `TestCrossOrg_ChannelAccess`**

Alice creates a channel in org A. Bob tries:
- GET /orgs/{orgA}/channels → 403
- POST /orgs/{orgA}/channels → 403
- PATCH /orgs/{orgA}/channels/{id} → 403
- DELETE /orgs/{orgA}/channels/{id} → 403
- POST /orgs/{orgA}/channels/{id}/rotate-secret → 403

**Step 3: Write `TestCrossOrg_IngestAccess`**

Bob tries: POST /orgs/{orgA}/ingest → 403

**Step 4: Run tests — expect PASS** (middleware already blocks cross-org)

**Step 5: Commit**

**Pitfall check:** tp§10 "Cross-tenant visibility assertion"

---

### Task 17: RequireAuthenticated Disabled-User + checkAdminMFAPermission (SC14-SC15)

**Finding:** SC14 (checkAdminMFAPermission 59.1%), SC15 (RequireAuthenticated disabled-user 85.3%)
**Files:**
- Modify: `internal/api/middleware_auth_test.go` — dedicated disabled-user test
- Modify: `internal/api/admin_mfa_test.go` — additional RBAC boundary tests

**Step 1: Write dedicated disabled-user middleware test**

```go
func TestRequireAuthenticated_DisabledUser_401(t *testing.T) {
    // Create user, get valid token, then disable user, then make request with token
    // Assert 401 (not 200, not 500)
}
```

**Step 2: Write checkAdminMFAPermission boundary tests**

Test the three-tier hierarchy exhaustively:
- Admin targets member → allowed
- Admin targets admin → blocked (same level)
- Admin targets owner → blocked (higher level)
- Member targets anyone → blocked (middleware catches first, but handler also checks)

**Step 3: Run tests, commit**

---

**After completing Batch 3:**
```
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (minimum 3 rounds).
```

---

## Batch 4: SSO + Doctor + Store Security Tests

### Task 18: SSO Handler Encryption Tests (SC11-SC13)

**Finding:** SC11 (patchSSO 45.3%), SC12 (createSSO 55.3%), SC13 (ssoEncryptionKeyPrevious 72.7%)
**Files:**
- Modify: `internal/api/sso_test.go`

**Step 1: Read SSO handlers to understand encryption flow**

The SSO handlers encrypt/decrypt OIDC client secrets using AES-GCM. Dual-key rotation means: try current key, fall back to previous key.

**Step 2: Write tests for encryption paths**

1. `TestCreateSSO_EncryptsClientSecret` — create SSO connection, verify client_secret is encrypted in DB (not plaintext)
2. `TestPatchSSO_ReEncryptsOnKeyRotation` — create with key A, patch with key B, verify re-encrypted
3. `TestSSO_PreviousKeyFallback` — encrypt with key A, rotate to key B, verify reading still works (DecryptWithFallback)

**Step 3: Run tests, commit**

---

### Task 19: Doctor Security Checks (SC19-SC21)

**Finding:** SC19 (RLSCheck 62.5%), SC20 (EncryptionSentinelCheck 50%), SC21 (SecurityHeadersCheck 48%)
**Files:**
- Modify: `internal/doctor/checks_test.go`

**Step 1: Read the check implementations to understand failure paths**

**Step 2: Write failure-detection tests**

For RLSCheck:
- Test with a table that has RLS disabled → should return StatusFail with the table name

For EncryptionSentinelCheck:
- Test with wrong key → should return StatusFail
- Test with previous key (dual-key) → should return StatusPass (or warn)

For SecurityHeadersCheck:
- Test against a server that's missing required headers → should report which are missing

**Step 3: Run tests, commit**

---

### Task 20: Store Security Method Tests (SC17-SC18, C4-C12)

**Finding:** SC17 (admin org store at 0%), SC18 (LookupAPIKeyByHash at 0%), various correctness gaps
**Files:**
- Modify: `internal/store/admin_org_test.go` (create if needed)
- Modify: `internal/store/apikey_test.go`
- Modify: `internal/store/security_events_test.go`
- Modify: `internal/store/mfa_test.go`

**Step 1: Write store-level tests**

Priority order:
1. `TestAdminSuspendOrg` / `TestAdminUnsuspendOrg` — verify org access is affected
2. `TestLookupAPIKeyByHash` — insert key, revoke it, verify hash lookup still returns it
3. `TestListSecurityEvents_FilterBySeverity` — exercise the missing filter paths
4. `TestVerifyRecoveryCode_WrongCode` — wrong code returns appropriate error
5. `TestVerifyEmailOTPChallenge_ExhaustedAttempts` — max attempts reached
6. `TestGetCVEMaterialHash` — verify after an ingest

**Step 2: Run tests, commit**

**Pitfall check:** tp§7 "Direct tests for every public store method"

---

**After completing Batch 4:**
```
Review loop — minimum 3 rounds.
```

---

## Batch 5: Correctness Gaps (Grouped by Package)

### Task 21: Worker Periodic Job Framework (C3)

**Finding:** C3 — RegisterPeriodic + runPeriodic at 0%
**Files:**
- Modify: `internal/worker/pool_test.go`

**Step 1: Write test for periodic job registration and execution**

1. `TestRegisterPeriodic_ExecutesAtInterval` — register a periodic task with a short interval (100ms), verify it fires at least twice within 500ms
2. `TestRegisterPeriodic_StopsOnShutdown` — register periodic task, call Stop(), verify task stops firing

**Step 2: Run tests, commit**

**Pitfall check:** tp§14 "Goroutine shutdown path"

---

### Task 22: Generic Feed Error Paths (C22-C26)

**Finding:** C22 (fetchJSONStream 72.5%), C23 (nextPage 37.5%), C24 (applyAuth 73.7%), C25 (fetchCSAF 72.2%), C26 (csafToPatches CVSSv4 83.7%)
**Files:**
- Modify: `internal/feed/generic/adapter_test.go`
- Modify: `internal/feed/generic/config_test.go` (if auth validation tests needed)

**Step 1: Add error path tests**

1. `TestFetchJSONStream_NonObjectOpeningToken` — response starts with `[` instead of `{`
2. `TestApplyAuth_HeaderAuthEmptyEnv` — header auth type with empty HeaderValueEnv
3. `TestCSAFToPatches_CVSSv4` — test fixture with a cvss_v4 block
4. `TestFetchCSAF_HTTPErrorStatus` — mock server returns 500

**Step 2: Run tests, commit**

**Pitfall check:** tp§9 "Behavioral parity between alternate code paths"

---

### Task 23: Notify Package Error Paths (C27-C29)

**Finding:** C27 (runDigest 57.1%), C28 (advanceReport timezone 55.6%), C29 (EmailSend TLS 72%)
**Files:**
- Modify: `internal/notify/digest_test.go`
- Modify: `internal/notify/email_test.go`

**Step 1: Add tests**

1. `TestAdvanceReport_InvalidTimezone` — report with invalid timezone string
2. `TestEmailSend_TLSMandatory` — test with TLS mandatory config

**Step 2: Run tests, commit**

---

### Task 24: CLI Command Tests (C30-C32)

**Finding:** C30 (rotateEncryptionKeys error paths 73.7%), C31 (doctor CLI 0%), C32 (quota commands 0%)
**Files:**
- Modify: `cmd/cvert-ops/rotate_test.go`
- Modify: `cmd/cvert-ops/validate_test.go` or create appropriate test file

**Step 1: Write tests**

1. `TestRotateEncryptionKeys_DecryptFailure` — corrupted ciphertext in DB
2. `TestRotateEncryptionKeys_EmptyPreviousKey` — no previous key configured
3. Basic quota command wiring tests (verify flag parsing)

**Step 2: Run tests, commit**

---

### Task 25: Auth/Token Correctness (C33-C35)

**Finding:** C33 (ParseEnrollmentToken unknown-key rejection), C34 (VerifyPassword invalid base64), C35 (invitation/member handler coverage)
**Files:**
- Modify: `internal/auth/jwt_test.go`
- Modify: `internal/auth/password_test.go`

**Step 1: Write tests**

1. `TestParseEnrollmentToken_UnknownKeyRejects` — JWT signed with wrong key → error (matches other token type tests)
2. `TestVerifyPassword_InvalidBase64Salt` — corrupted stored hash
3. `TestVerifyPassword_InvalidBase64Key` — corrupted stored hash

**Step 2: Run tests, commit**

**Pitfall check:** tp§11 "Token type enforcement across session types"

---

### Task 26: Alert DSL Missing Operators (C15-C17)

**Finding:** C15 (conditionToSQL unknown field 80%), C16 (textSQL ends_with 77.8%), C17 (affectedPackageSQL starts_with/ends_with 81.8%)
**Files:**
- Modify: `internal/alert/dsl/compiler_test.go`

**Step 1: Write tests for missing operator branches**

1. `TestTextSQL_EndsWith` — test ends_with operator
2. `TestAffectedPackageSQL_StartsWith` — test starts_with for package names
3. `TestAffectedPackageSQL_EndsWith` — test ends_with for package names
4. `TestConditionToSQL_UnknownField` — unknown field category returns error

**Step 2: Run tests, commit**

---

**After completing Batch 5:**
```
Review loop — minimum 3 rounds.
```

---

## Batch 6: Assertion Quality Fixes

### Task 27a: RLS Test Breadth (AQ1)

**Finding:** AQ1 — RLS test only covers watchlists table
**Files:**
- Modify: `internal/store/rls_test.go`

**Step 1: Read `internal/store/rls_test.go` to understand the existing pattern**

The current test creates data in two orgs and verifies org A can't see org B's data — but only for the watchlists table.

**Step 2: Add cross-tenant assertions for 2+ more org-scoped tables**

Add test cases for at least `alert_rules` and `notification_channels`. These tables have RLS policies (all org-scoped tables do). Follow the exact same pattern: insert data in org A and org B via bypass tx, query via org-scoped tx for org A, assert org B's data is not visible.

**Step 3: Run tests, commit**

**Pitfall check:** tp§10 "Cross-tenant visibility assertion", "Child table isolation"

---

### Task 27b: Generic Feed Assertion Strengthening (AQ7-AQ8)

**Finding:** AQ7 (weak error message assertion), AQ8 (weak error type assertion)
**Files:**
- Modify: `internal/feed/generic/adapter_test.go`

**Step 1: Read the existing tests**

Find `TestAdapter_URLUnreachable` and `TestAdapter_NonJSONResponse`. Currently both use `assert.Error(t, err)` without verifying the error message or type.

**Step 2: Strengthen assertions**

- `TestAdapter_URLUnreachable`: Replace `assert.Error` with `assert.ErrorContains(t, err, "connection refused")` or similar (read the actual error message from the implementation first)
- `TestAdapter_NonJSONResponse`: Assert error message contains an indication that the response wasn't valid JSON (e.g., "invalid character" or "unexpected token")

**Step 3: Run tests, commit**

---

### Task 27c: BuildSafeClient + RenderMFAOTP (AQ10-AQ11)

**Finding:** AQ10 (MaxConnsPerHost not asserted), AQ11 (RenderMFAOTP untested)
**Files:**
- Modify: `internal/notify/webhook_test.go` (AQ10)
- Modify: `internal/notify/render_test.go` or create if needed (AQ11)

**Step 1: Fix BuildSafeClient assertion**

Find the `TestBuildSafeClient_*` test. Add assertion that the returned client's transport has `MaxConnsPerHost: 50`. Type-assert the transport to access the field:
```go
transport, ok := client.Transport.(*http.Transport)
// or it may be a safeurl wrapper — read BuildSafeClient to understand the actual type
```

**Step 2: Add RenderMFAOTP test**

Read existing `Render*` tests (e.g., for alert notifications, digest reports) to understand the template rendering test pattern. Write a basic test that calls `RenderMFAOTP` with valid inputs and asserts the output contains the OTP code.

**Step 3: Run tests, commit**

---

**After completing Batch 6:**
```
Final review loop — minimum 3 rounds.
```

---

## BEFORE starting any task:
1. Read `dev/testing-pitfalls.md`
2. Read the TDD skill at `.claude/skills/test-driven-development/` (or invoke `/test-driven-development`)
For pure test additions: write the test, verify it fails for the right reason (or passes if testing already-correct behavior), then move on.
For code changes (Tasks 1-8): write failing test → fix code → verify green.

## BEFORE marking any task complete:
1. Review your tests against `dev/testing-pitfalls.md`
2. Verify: are assertions checking behavior, not just execution?
3. Verify: are negative cases tested, not just positive?
4. Run `go test ./...` (or relevant subset) and confirm green

---

## Appendix: Nice-to-Have Gaps (Not Addressed in This Plan)

These 30 gaps were classified as nice-to-have in the coverage review. They are documented here for future reference but are not included as tasks because they are either:
- Error paths that are practically unreachable (crypto errors with valid keys)
- Thin wrappers around sqlc-generated code
- Internal error handling that doesn't affect security or correctness

| ID | Description | Location | Reason Deferred |
|----|-------------|----------|----------------|
| N1 | ListCVEs at 0% | store/cve.go:78 | Possibly dead code, thin wrapper |
| N2 | PauseFeed/ResumeFeed at 0% | store/feed.go:201-234 | Thin sqlc wrappers |
| N3 | GetActiveEmailOTPChallenge at 0% | store/generated | Non-ForUpdate may be dead code |
| N4 | ListSecurityEvents (generated) at 0% | store/generated | Dead code — raw SQL used instead |
| N5 | withBypassRawTx error paths at 50% | store/store.go:73 | Infrastructure BeginTx/panic |
| N6 | withOrgRawTx error paths at 64.3% | store/store.go:101 | Same as N5 |
| N7 | OrgTx/WorkerTx infrastructure paths at 77.8% | store/store.go | Same as N5 |
| N8 | runStatus at 50% | alert/evaluator.go | Trivial 3-way switch |
| N9 | Adapter.New nil-client at 66.7% | feed/*/adapter.go | Defensive path |
| N10 | DownloadToTemp at 66.7% | feed/util.go | OS-level errors |
| N11 | WrapClientWithUA at 90.0% | feed/util.go | nil-client path |
| N12-N23 | Notify error paths (50-95%) | notify/*.go | Internal error wrapping |
| N24 | autoMigrate advisory lock at 46.2% | cmd/main.go | Requires full env |
| N25 | Crypto Encrypt/Decrypt unreachable paths | crypto/aes.go | Valid keys can't fail |
| N26 | isGCMAuthError string matching | crypto/aes.go | Low risk |
| N27 | IssueToken SignedString error | auth/jwt.go | HMAC never fails |
| N28 | jwtPreviousSecretBytes at 66.7% | api/server.go | Startup config |
| N29 | parseQueryDate unit tests | api/helpers.go | Helper function |
| N30 | pauseFeedHandler/resumeFeedHandler | api/admin_feeds.go | Admin wiring |
