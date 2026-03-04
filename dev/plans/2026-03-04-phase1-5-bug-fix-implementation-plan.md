# Bug Fix Implementation Plan — All Phases

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 44 deduplicated bugs found across the 7-phase bug hunter A/B test (Phases 1, 2a, 2b, 3a, 3b, 4, 5).

**Architecture:** TDD for each fix — write a failing test, implement the minimal fix, verify. Bugs grouped by file/subsystem to minimize context switching. Priority-ordered: P0 critical bugs first, P1 security bugs second, P2 significant correctness third, P3 minor last.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, squirrel, huma + chi

**Source:** `dev/plans/2026-03-03-code-bug-hunter-skill-design.md` — full bug evidence with file:line references, severity, and impact analysis.

---

## Open Questions (Deferred — Resolve Before Implementing Affected Tasks)

1. **PK migration collision fix strategy (Task 2):** merge-and-delete vs delete-then-update. **DEFERRED.**
2. **Batch cursor advancement on failure (Task 6):** leave as-is vs smart retry. **DEFERRED.**
3. **PostFilter field reference (Task 6):** minimal AND/OR fix vs add field ref. **DEFERRED.**
4. **Digest store method (Task 9):** verify in code during implementation.
5. **Worker semaphore HOL blocking:** defer to separate PR. **DEFERRED.**
6. **Admin-can-remove-owner RBAC intent (Task 4):** bug or design choice. **DEFERRED.**

---

## Task 1: Fix DSL compiler float parse (P0 — Critical)

**Bugs:** Float parse `return v, json.Unmarshal(raw, &v)` — unspecified eval order (Phase 4 #1, Phase 2b re-find)

**Files:**
- Modify: `internal/alert/dsl/compiler.go:141-145`
- Test: `internal/alert/dsl/compiler_test.go`

**Step 1: Write failing test**

Add a test that compiles a float condition and verifies the parsed value is the user-specified threshold, not 0:

```go
func TestConditionToSQL_FloatParsesCorrectValue(t *testing.T) {
    cond := Condition{
        Field: "epss_score",
        Op:    "gte",
        Value: json.RawMessage(`0.75`),
    }
    sqlizer, err := conditionToSQL(cond, fieldRegistry["epss_score"])
    require.NoError(t, err)

    query, args, err := sqlizer.ToSql()
    require.NoError(t, err)
    // The compiled SQL should use 0.75, not 0
    require.Contains(t, args, 0.75, "float value should be 0.75, not zero")
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/alert/dsl/ -run TestConditionToSQL_FloatParsesCorrectValue -v`
Expected: FAIL — args contains 0.0 instead of 0.75 (or pass if gc compiler happens to evaluate left-to-right in the favorable order, but the code is still wrong per spec)

**Step 3: Implement fix**

Change `compiler.go:141-145` to match the `kindTime` pattern (lines 147-153):

```go
case kindFloat:
    return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
        var v float64
        if err := json.Unmarshal(raw, &v); err != nil {
            return nil, err
        }
        return v, nil
    })
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/alert/dsl/ -run TestConditionToSQL_FloatParsesCorrectValue -v`
Expected: PASS

**Step 5: Run full DSL test suite**

Run: `go test ./internal/alert/dsl/... -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add internal/alert/dsl/compiler.go internal/alert/dsl/compiler_test.go
git commit -m "fix: DSL compiler float parse uses unspecified evaluation order

The closure \`return v, json.Unmarshal(raw, &v)\` has undefined
evaluation order per Go spec — v may be read before Unmarshal writes
to it, producing 0.0 for all float conditions. Split into separate
unmarshal and return statements, matching the kindTime pattern."
```

---

## Task 2: Fix PK migration collision + advisory lock gap (P0 — Critical)

**Bugs:**
- PK migration collision — `UPDATE cves SET cve_id = $2 WHERE cve_id = $1` hits unique constraint when target exists (Phase 1 #1)
- Advisory lock gap — lock both old and new CVE IDs during migration (Phase 1 #2)

**Files:**
- Modify: `internal/merge/pipeline.go:352-378`
- Test: `internal/merge/pipeline_test.go`

**Step 1: Write failing test**

Test that `migrateCVEPK` handles the case where the target CVE ID already exists:

```go
func TestMigrateCVEPK_TargetExists(t *testing.T) {
    // Setup: create two CVEs — one with alias ID, one with canonical ID
    // Call migrateCVEPK to rename alias → canonical
    // Verify: merge succeeds, source rows consolidated, no unique constraint violation
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/merge/ -run TestMigrateCVEPK_TargetExists -v`
Expected: FAIL with unique constraint violation

**Step 3: Implement fix**

Replace the simple UPDATE with a merge strategy:
1. Lock both old and new CVE IDs (ordered to prevent deadlocks)
2. If target CVE exists: move `cve_sources` rows from old to new, delete old CVE row
3. If target CVE doesn't exist: UPDATE as before
4. Re-run merge pipeline on the canonical ID to recompute fields

**NOTE:** The exact merge semantics depend on the deferred Question 1.

**Step 4: Run tests, commit**

---

## Task 3: Wire activation pipeline + fix handler response codes (P0 — Critical)

**Bugs:**
- Activation pipeline not wired — rules stuck in "activating" forever (Phase 3a #1)
- 201 vs 202 status code for activating rules (Phase 3a #3, Phase 2b re-find)
- Cache eviction missing for error/disabled→activating transitions (Phase 2b #5)

**Files:**
- Modify: `internal/api/alert_rules.go:240-262` (create), `internal/api/alert_rules.go:459-505` (update)
- Modify: `cmd/cvert-ops/main.go` (register activation handler in worker)
- Modify: `internal/store/alert_rule.go` (add EnqueueActivation if needed)
- Test: `internal/api/alert_rules_test.go`

**Step 1: Write failing tests**

```go
func TestCreateAlertRule_ActivatingEnqueuesJob(t *testing.T) {
    // Create rule with enabled=true
    // Verify: job_queue has an entry with queue="alert_activation" for this rule
}

func TestCreateAlertRule_ActivatingReturns202(t *testing.T) {
    // Create rule with enabled=true
    // Verify: response status is 202 Accepted, not 201 Created
}

func TestUpdateAlertRule_ReEnableCachesEvict(t *testing.T) {
    // Create active rule, disable it, re-enable with new DSL
    // Verify: cache evicted (old compiled rule not served)
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

In `createAlertRuleHandler` (after line 262):
```go
if status == "activating" {
    if err := srv.store.EnqueueActivationJob(r.Context(), orgID, row.ID); err != nil {
        slog.ErrorContext(r.Context(), "enqueue activation", "error", err)
    }
    writeJSON(w, http.StatusAccepted, entry)
} else {
    writeJSON(w, http.StatusCreated, entry)
}
```

In `updateAlertRuleHandler` state machine (line 477-481):
```go
case "error", "draft", "disabled":
    if req.Enabled != nil && *req.Enabled {
        newStatus = "activating"
        needsCacheEvict = true  // ADD THIS
    }
```

After the update, enqueue activation job if status transitioned to "activating".

In `main.go`: register the `alert_activation` queue handler that calls `EvaluateActivation`.

**Step 4: Run tests, full suite, commit**

---

## Task 4: Fix auth security — OAuth + RBAC (P1 — Security)

**Bugs:**
- OAuth bypass RegistrationMode — GitHub/Google auto-create without checking (Phase 2a #2)
- Admin can remove org owner — missing role hierarchy check (Phase 2a #1)
- OAuth email collision 500 — no pgErrCode "23505" handling (Phase 2a #3)
- Nonce non-constant-time comparison (Phase 2a #6)
- OAuth no last_login_at update (Phase 2a #8)

**Files:**
- Modify: `internal/api/oauth_github.go:135-153`
- Modify: `internal/api/oauth_google.go:110, 123-141`
- Modify: `internal/api/oauth_oidc.go:191`
- Modify: `internal/api/orgs.go:283-338`
- Test: `internal/api/oauth_test.go`, `internal/api/orgs_test.go`

**Step 1: Write failing tests for each bug**

```go
func TestOAuthGitHub_RejectsNewUserWhenInviteOnly(t *testing.T) {
    // Set RegistrationMode = "invite-only"
    // Attempt OAuth login with unknown email
    // Verify: 403 Forbidden, NOT auto-created
}

func TestRemoveMember_AdminCannotRemoveOwner(t *testing.T) {
    // Auth as admin, attempt to remove owner
    // Verify: 403 Forbidden
}

func TestOAuthGitHub_EmailCollisionReturns409(t *testing.T) {
    // Create user with email X via native register
    // Attempt OAuth login with same email X
    // Verify: 409 Conflict, NOT 500
}

func TestOAuthGoogle_NonceUsesConstantTimeCompare(t *testing.T) {
    // This is a code audit test — verify subtle.ConstantTimeCompare is used
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

In `oauth_github.go` and `oauth_google.go` — add RegistrationMode check before auto-creating user:
```go
if srv.cfg.RegistrationMode == "invite-only" {
    http.Error(w, "registration is invite-only", http.StatusForbidden)
    return
}
```

In `orgs.go` `removeMemberHandler` — add role hierarchy check matching `updateMemberRoleHandler`:
```go
if *targetRole == "owner" {
    http.Error(w, "cannot remove an owner", http.StatusForbidden)
    return
}
```

In `oauth_github.go` and `oauth_google.go` — handle email collision:
```go
if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
    http.Error(w, "email already registered", http.StatusConflict)
    return
}
```

In `oauth_google.go:110` and `oauth_oidc.go:191` — change `!=` to constant-time compare:
```go
if subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
```

In all OAuth callbacks — add `UpdateLastLogin`:
```go
_ = srv.store.UpdateLastLogin(ctx, user.ID)
```

**Step 4: Run tests, full auth suite, commit**

---

## Task 5: Fix auth security — API key scoping (P1 — Security)

**Bugs:**
- API key not scoped to its org during auth (Phase 2a #5)
- tryAPIKeyAuth swallows database errors as 401 (Phase 2a #7)

**Files:**
- Modify: `internal/api/middleware_auth.go:48-67`
- Test: `internal/api/middleware_auth_test.go`

**Step 1: Write failing tests**

```go
func TestTryAPIKeyAuth_RejectsKeyFromDifferentOrg(t *testing.T) {
    // Create API key for org A
    // Make request to /api/v1/orgs/{orgB}/...
    // Verify: 403 Forbidden (key's org doesn't match URL org)
}

func TestTryAPIKeyAuth_Returns500OnDBError(t *testing.T) {
    // Simulate DB error during key lookup
    // Verify: 500, not 401
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

In `tryAPIKeyAuth` — validate key.OrgID against the URL org:
```go
urlOrgID := chi.URLParam(r, "org_id")
if urlOrgID != "" && key.OrgID.String() != urlOrgID {
    return nil, fmt.Errorf("api key org mismatch")
}
```

Distinguish "not found" from DB errors:
```go
key, err := srv.store.GetAPIKeyByHash(ctx, hash)
if errors.Is(err, store.ErrNotFound) {
    return nil, nil  // not authenticated, try next method
}
if err != nil {
    return nil, fmt.Errorf("api key lookup: %w", err)  // DB error → 500
}
```

**Step 4: Run tests, commit**

---

## Task 6: Fix evaluator core bugs (P2 — Significant)

**Bugs:**
- DryRun readTx missing RLS context (Phase 2b #2) — `evaluator.go:313`
- EvaluateActivation overwrites concurrent user disables (Phase 2b #3) — `evaluator.go:242`
- SweepZombieActivations TOCTOU (Phase 2b #4) — `evaluator.go:282-289`
- PostFilter AND semantics breaks OR rules (Phase 4 #2) — `evaluator.go:520-542`

**Files:**
- Modify: `internal/alert/evaluator.go`
- Modify: `internal/alert/dsl/types.go` (add Logic field to CompiledRule if needed)
- Modify: `internal/store/alert_rule.go` (conditional status update)
- Test: `internal/alert/evaluator_test.go`

**Step 1: Write failing tests**

```go
func TestDryRun_WatchlistConditionReturnsMatches(t *testing.T) {
    // Create watchlist with items, create rule with watchlist condition
    // DryRun should return matches > 0, not 0
}

func TestEvaluateActivation_DoesNotOverrideDisabledStatus(t *testing.T) {
    // Start activation scan
    // Disable rule during scan
    // Activation completes — status should remain "disabled", not "active"
}

func TestSweepZombieActivations_SkipsCompletedJobs(t *testing.T) {
    // Create activation job that just completed (status = "complete")
    // Run sweep — should NOT overwrite to "error"/"failed"
}

func TestApplyPostFilters_UsesORLogicForORRules(t *testing.T) {
    // Compiled rule with logic="or" and 2 PostFilters
    // Candidate matching filter A but not filter B should be included
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

**DryRun RLS:** Change `readTx` to `bypassTx` at line 313:
```go
if err := e.bypassTx(ctx, func(tx *sql.Tx) error {
    var err error
    candidates, partial, err = e.queryCandidatesAll(ctx, tx, compiled)
    return err
}); err != nil {
```

**EvaluateActivation:** Add `WHERE status = 'activating'` guard. This requires modifying `SetAlertRuleStatus` or adding a new conditional method:
```go
func (s *Store) SetAlertRuleStatusIf(ctx context.Context, orgID, ruleID uuid.UUID, newStatus, requiredCurrentStatus string) (bool, error) {
    // UPDATE alert_rules SET status = $3 WHERE id = $1 AND org_id = $2 AND status = $4
}
```
At `evaluator.go:242`:
```go
updated, err := e.rules.SetAlertRuleStatusIf(ctx, orgID, ruleID, "active", "activating")
if err != nil { return err }
if !updated {
    e.log.Info("activation complete but rule status changed concurrently", "rule_id", ruleID)
}
return nil
```

**SweepZombie TOCTOU:** Same pattern — add status preconditions:
```go
// Only mark rule as error if it's still "activating"
e.rules.SetAlertRuleStatusIf(ctx, z.OrgID, z.RuleID, "error", "activating")

// Only fail job if it's still "running"
e.db.ExecContext(ctx,
    `UPDATE job_queue SET status = 'failed', finished_at = now() WHERE id = $1 AND status = 'running'`,
    z.JobID)
```

**PostFilter AND/OR:** Add logic awareness to `applyPostFilters`:
```go
func applyPostFilters(candidates []cveSummary, filters []dsl.PostFilter, logic string) []cveSummary {
    if len(filters) == 0 {
        return candidates
    }
    var matched []cveSummary
    for _, c := range candidates {
        if logic == "or" {
            // ANY filter match includes the candidate
            pass := false
            for _, f := range filters {
                ok := f.Pattern.MatchString(c.Description)
                if f.Negate { ok = !ok }
                if ok { pass = true; break }
            }
            if pass { matched = append(matched, c) }
        } else {
            // ALL filters must match (existing AND behavior)
            pass := true
            for _, f := range filters {
                ok := f.Pattern.MatchString(c.Description)
                if f.Negate { ok = !ok }
                if !ok { pass = false; break }
            }
            if pass { matched = append(matched, c) }
        }
    }
    return matched
}
```

Update all callers to pass `compiled.Logic` (or the rule's logic field).

**Step 4: Run tests, full evaluator suite, commit**

---

## Task 7: Fix DSL executor bugs (P2 — Significant)

**Bugs:**
- ExecuteDSLQuery RLS bypass for watchlist conditions (Phase 2b #1) — `dsl_executor.go:160`
- ExecuteDSLQuery silently drops PostFilters (Phase 4 #3) — `dsl_executor.go:118-194`

**Files:**
- Modify: `internal/store/dsl_executor.go:118-194`
- Test: `internal/store/dsl_executor_test.go`

**Step 1: Write failing tests**

```go
func TestExecuteDSLQuery_WatchlistConditionReturnsResults(t *testing.T) {
    // Create watchlist with items, compile rule with watchlist condition
    // Execute DSL query — should return matches, not empty
}

func TestExecuteDSLQuery_AppliesPostFilters(t *testing.T) {
    // Compile rule with regex condition (produces PostFilter)
    // Execute DSL query — results should be filtered by regex
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

**RLS bypass:** The comment at line 116 says "cves table is global, no RLS" but when compiled rules include watchlist subqueries, they reference `watchlist_items` which has RLS. Wrap the query in a bypass transaction when the compiled rule has watchlist conditions:

```go
if len(compiled.WatchlistIDs) > 0 {
    // Watchlist subquery needs RLS bypass
    err = s.withBypassTx(ctx, func(tx *sql.Tx) error {
        rows, queryErr := tx.QueryContext(ctx, query, args...)
        // ... scan results ...
        return nil
    })
} else {
    rows, err = s.db.QueryContext(ctx, query, args...)
    // ... existing code ...
}
```

**PostFilter application:** After the SQL query, apply PostFilters to the results:

```go
// After scanning all results, apply PostFilters
if len(compiled.PostFilters) > 0 {
    var filtered []generated.Cfe
    for _, c := range results {
        pass := true
        for _, f := range compiled.PostFilters {
            ok := f.Pattern.MatchString(c.DescriptionPrimary.String)
            if f.Negate { ok = !ok }
            if !ok { pass = false; break }
        }
        if pass { filtered = append(filtered, c) }
    }
    results = filtered
}
```

**Note:** PostFilter application after SQL means the page might have fewer than `limit` results. This is acceptable for MVP but may need follow-up for pagination consistency.

**Step 4: Run tests, commit**

---

## Task 8: Fix notification delivery bugs (P2 — Significant)

**Bugs:**
- Claim/mark TOCTOU — SELECT + UPDATE not atomic (Phase 3a #2)
- Cancelled context in delivery goroutines (Phase 3a #4)
- Deterministic email errors retried (Phase 3a #5)

**Files:**
- Modify: `internal/store/notification_delivery.go` (claim/mark CTE)
- Modify: `internal/notify/worker.go:144-154` (context + email errors)
- Test: `internal/store/notification_delivery_test.go`, `internal/notify/worker_test.go`

**Step 1: Write failing tests**

```go
func TestClaimAndMark_Atomic(t *testing.T) {
    // Two concurrent workers claim the same delivery
    // Only one should succeed
}

func TestDeliveryWorker_UsesDetachedContext(t *testing.T) {
    // Cancel the parent context after dispatching
    // Delivery goroutine should still complete
}

func TestDeliveryWorker_PermanentEmailErrorExhausts(t *testing.T) {
    // Trigger a permanent email error (invalid address, etc.)
    // Verify: delivery marked as exhausted, not retried
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

**Claim/mark TOCTOU:** Replace separate SELECT + UPDATE with a single CTE:
```sql
WITH claimed AS (
    UPDATE notification_deliveries
    SET status = 'sending', claimed_at = now()
    WHERE id IN (
        SELECT id FROM notification_deliveries
        WHERE status = 'pending' AND scheduled_at <= now()
        ORDER BY scheduled_at
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING *
)
SELECT * FROM claimed
```

**Cancelled context:** Use `context.WithoutCancel` for delivery goroutines:
```go
detached := context.WithoutCancel(ctx)
go func() {
    defer wg.Done()
    // Use detached context for the HTTP call
    err := channel.Send(detached, payload)
    // ...
}()
```

**Deterministic email errors:** Classify permanent vs transient errors:
```go
func isPermanentEmailError(err error) bool {
    // 4xx SMTP errors, invalid address, etc.
    var smtpErr *smtp.Error
    if errors.As(err, &smtpErr) {
        return smtpErr.Code >= 400 && smtpErr.Code < 500
    }
    return false
}
```

**Step 4: Run tests, commit**

---

## Task 9: Fix email/digest/reports bugs (P2 — Significant)

**Bugs:**
- Digest runner calls wrong store method (Phase 3b #1)
- PATCH /reports can't clear severity_threshold to NULL (Phase 3b #2)
- RuleID zero UUID for digest deliveries (Phase 3b #3)

**Files:**
- Modify: `internal/notify/digest.go`
- Modify: `internal/api/reports.go`
- Modify: `internal/store/notification_delivery.go` (RuleID field)
- Test: `internal/notify/digest_test.go`, `internal/api/reports_test.go`

**Step 1: Write failing tests for each bug**

**Step 2: Implement fixes**

**Digest store method:** Change to `ListActiveChannelsForDigest` (or equivalent worker-path method).

**PATCH severity_threshold:** Use a three-state approach — `*float64` pointer with explicit null sentinel, or add a `ClearSeverityThreshold *bool` field.

**RuleID zero UUID:** Change `RuleID string` to `*string` with `.Valid` check, matching the `ReportID` pattern.

**Step 3: Run tests, commit**

---

## Task 10: Fix feed pipeline bugs (P2 — Significant + P3 — Minor)

**Bugs:**
- NextCursor contract violation — adapters don't return nil when done (Phase 1 #3)
- OSV multi-event range data loss — only last event pair kept (Phase 1 #4)
- Worker panic recovery — no recover() in queue goroutines (Phase 1 #5)
- ParseTime/RFC1123 — missing time.RFC1123 layout (Phase 1 #6)
- CVSS 0.0 rejection — `> 0` should be `>= 0` (Phase 1 #7)
- Staged EPSS after tombstone — applied to withdrawn CVEs (Phase 1 #8)
- ResolveCanonicalID non-deterministic — unsorted aliases (Phase 1 #9)

**Files:**
- Modify: `internal/feed/util.go` (ParseTime)
- Modify: `internal/merge/pipeline.go` (ResolveCanonicalID)
- Modify: `internal/feed/osv/adapter.go` (multi-event)
- Modify: `internal/feed/mitre/adapter.go`, `internal/feed/ghsa/adapter.go` (CVSS 0.0)
- Modify: `internal/worker/queue.go` (panic recovery)
- Modify: Various adapters (NextCursor)
- Modify: Staged EPSS application code
- Test: Corresponding test files

**Step 1: Write failing tests for each bug**

These are mostly straightforward unit tests — e.g., `TestParseTime_RFC1123`, `TestResolveCanonicalID_Deterministic`, `TestOSVAdapter_MultiEventRange`.

**Step 2: Implement fixes**

**ParseTime:** Add `time.RFC1123` to `timeLayouts` slice in `util.go`.

**ResolveCanonicalID:** Sort aliases before selecting canonical ID:
```go
sort.Strings(aliases)
```

**OSV multi-event:** Collect all event pairs, not just the last:
```go
var ranges []VersionRange
for _, event := range events {
    ranges = append(ranges, VersionRange{...})
}
```

**CVSS 0.0:** Change `if score > 0` to `if score >= 0` in MITRE/GHSA adapters.

**Worker panic recovery:** Add `recover()` wrapper:
```go
go func() {
    defer func() {
        if r := recover(); r != nil {
            log.Error("worker panic", "error", r, "stack", string(debug.Stack()))
            // Mark job as failed
        }
    }()
    // ... process job ...
}()
```

**NextCursor:** Return `nil` when there are no more pages (check each adapter).

**Staged EPSS:** Skip staged EPSS application when CVE status is "rejected" or "withdrawn".

**Step 3: Run tests for each fix, commit per logical group**

---

## Task 11: Fix pagination & cursor bugs (P3 — Minor)

**Bugs:**
- base64.StdEncoding cursor corrupted by URL `+` decoding (Phase 2b #6)
- Pagination phantom page (Phase 3a #7)

**Files:**
- Modify: `internal/api/watchlists.go:90-93` (encodeTimeCursor + decodeTimeCursor)
- Modify: `internal/api/alert_rules.go`, `internal/api/alert_events.go`, `internal/api/audit_log.go` (same cursor functions)
- Modify: `internal/api/deliveries.go` (phantom page)
- Test: `internal/api/watchlists_test.go`, `internal/api/deliveries_test.go`

**Step 1: Write failing tests**

```go
func TestTimeCursor_RoundTripsWithPlusCharacter(t *testing.T) {
    // Create a timestamp/UUID that produces base64 with '+' character
    // Encode, pass through url.ParseQuery, decode
    // Verify: round-trip succeeds
}
```

**Step 2: Implement fix**

Change `base64.StdEncoding` to `base64.URLEncoding` (matching `dsl_executor.go`):
```go
func encodeTimeCursor(t time.Time, id uuid.UUID) string {
    raw := t.UTC().Format(time.RFC3339Nano) + "|" + id.String()
    return base64.URLEncoding.EncodeToString([]byte(raw))
}

func decodeTimeCursor(s string) (time.Time, uuid.UUID, error) {
    b, err := base64.URLEncoding.DecodeString(s)
    // ...
}
```

**Phantom page:** Use `limit+1` pattern (fetch one extra row, check if next page exists).

**Step 3: Run tests, commit**

---

## Task 12: Fix API handler consistency bugs (P3 — Minor)

**Bugs:**
- deleteWatchlistItemHandler 204 on non-existent items (Phase 2b #9)
- Duplicate watchlist IDs rejected with misleading error (Phase 2b #7)
- deleteReportHandler 204 for non-existent reports (Phase 3b #7)
- rotateSecretHandler TOCTOU — empty secret with 200 (Phase 3b #5)
- Replay no-op + rate limit waste (Phase 3a #6)

**Files:**
- Modify: `internal/api/watchlists.go:589-614`
- Modify: `internal/api/alert_rules.go:146-156` (parseWatchlistUUIDs)
- Modify: `internal/api/reports.go`
- Modify: `internal/api/channels.go`
- Modify: `internal/api/deliveries.go`
- Test: Corresponding test files

**Step 1: Write failing tests for each**

**Step 2: Implement fixes**

**deleteWatchlistItemHandler:** Add existence check before delete (matching deleteWatchlistHandler pattern).

**Duplicate watchlist IDs:** Deduplicate UUIDs in `parseWatchlistUUIDs`:
```go
func parseWatchlistUUIDs(raw []string) ([]uuid.UUID, error) {
    seen := make(map[uuid.UUID]bool)
    var result []uuid.UUID
    for _, s := range raw {
        id, err := uuid.Parse(s)
        if err != nil { return nil, err }
        if !seen[id] {
            seen[id] = true
            result = append(result, id)
        }
    }
    return result, nil
}
```

**deleteReportHandler:** Add existence check before delete.

**rotateSecretHandler:** Check `if secret == ""` and return 404.

**Replay no-op:** Check delivery exists and is replayable before consuming rate limit token.

**Step 3: Run tests, commit**

---

## Task 13: Fix store/worker misc bugs (P3 — Minor)

**Bugs:**
- Worker event methods use withOrgTx instead of withBypassTx (Phase 2b #10) — `alert_rule.go:257, 283, 296`
- AcceptInvitation RLS bypass / dead method (Phase 2a #5) — `org.go:302-307`

**Files:**
- Modify: `internal/store/alert_rule.go:257, 283, 296`
- Modify: `internal/store/org.go:302-307`
- Test: `internal/store/alert_rule_test.go`

**Step 1: Verify AcceptInvitation is dead code — if so, remove it**

**Step 2: Change worker event methods to use withBypassTx**

Switch `InsertAlertEvent`, `GetUnresolvedAlertEventCVEs`, and `ResolveAlertEvent` from `withOrgTx` to `withBypassTx`, matching the pattern used by `InsertAlertRuleRun` and `UpdateAlertRuleRun`.

**Step 3: Run tests, commit**

---

## Task 14: Fix SSO handler bugs + retention Runner.Run (P2 — Significant + P3 — Minor)

**Bugs:**
- PATCH SSO allows empty required fields — no non-empty validation after trimming (Phase 5 #1)
- Missing audit trail for SSO domain changes — `putSSODomainsHandler` has no `auditLog` call (Phase 5 #2)
- Runner.Run always returns nil — violates documented contract "Returns nil unless context cancelled" (Phase 5 #3)
- SSO domain conflict returns 500 instead of 409 — missing `isUniqueViolation` check (Phase 5 #4)
- deleteSSOHandler returns 204 for non-existent connection — missing nil check (Phase 5 #5)

**Files:**
- Modify: `internal/api/sso.go:280-315` (PATCH validation), `internal/api/sso.go:426-471` (audit log + domain conflict), `internal/api/sso.go:386-423` (delete nil check)
- Modify: `internal/retention/runner.go:49-98` (return ctx.Err / propagate errors)
- Test: `internal/api/sso_test.go`, `internal/retention/runner_test.go`

**Step 1: Write failing tests**

```go
func TestPatchSSO_RejectsEmptyRequiredFields(t *testing.T) {
    // Create SSO connection
    // PATCH with {"display_name": ""}
    // Verify: 422 Unprocessable Entity, not 200
    // Repeat for issuer_url, client_id, client_secret
}

func TestPutSSODomains_AuditLogEntry(t *testing.T) {
    // Create SSO connection
    // PUT domains
    // Verify: audit log entry exists with action "update" for SSO entity
}

func TestRunnerRun_ReturnsCancelledContextError(t *testing.T) {
    // Create runner, cancel context mid-run
    // Verify: Run returns ctx.Err(), not nil
}

func TestRunnerRun_ReturnsErrorOnCleanupFailure(t *testing.T) {
    // Create runner with failing store (ListAllOrgs returns error)
    // Verify: Run returns error, not nil
}

func TestPutSSODomains_ConflictReturns409(t *testing.T) {
    // Create SSO connection for org A, claim domain "example.com"
    // Create SSO connection for org B, try to claim "example.com"
    // Verify: 409 Conflict, not 500
}

func TestDeleteSSO_NotFoundReturns404(t *testing.T) {
    // Attempt DELETE on org with no SSO connection
    // Verify: 404, not 204
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement fixes**

**PATCH SSO validation:** Add non-empty checks after trimming, matching `createSSOHandler`:
```go
if req.DisplayName != nil {
    displayName = strings.TrimSpace(*req.DisplayName)
    if displayName == "" {
        http.Error(w, "display_name cannot be empty", http.StatusUnprocessableEntity)
        return
    }
}
// Same for issuer_url, client_id, client_secret
```

**Audit log for SSO domains:** Add `srv.auditLog(...)` call after successful domain update:
```go
srv.auditLog(r.Context(), w, orgID, "sso_connection", conn.ID.String(), "update_domains", userID)
```

**Runner.Run error propagation:** Check context and propagate cleanup errors:
```go
if err := ctx.Err(); err != nil {
    return err
}
// After cleanupTierGated:
if cleanupErr != nil {
    return fmt.Errorf("tier-gated cleanup: %w", cleanupErr)
}
```

**SSO domain conflict 409:** Add unique violation check:
```go
if err := srv.store.SetSSOEmailDomains(r.Context(), conn.ID, orgID, req.Domains); err != nil {
    if isUniqueViolation(err) {
        http.Error(w, "one or more domains already claimed by another org", http.StatusConflict)
        return
    }
    slog.ErrorContext(r.Context(), "sso put domains: store", "error", err)
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
}
```

**deleteSSOHandler nil check:** Add existence check matching sibling handlers:
```go
if current == nil {
    http.Error(w, "sso connection not found", http.StatusNotFound)
    return
}
```

**Step 4: Run tests, full SSO + retention suite, commit**

---

## Deferred (Needs Discussion)

### Batch cursor advancement on failure
See Question 2 — depends on Sam's trade-off preference.

### Worker semaphore head-of-line blocking
See Question 5 — architectural change, may warrant separate PR.

---

## Verification

After all tasks complete:

1. **Full test suite:** `go test ./... -count=1`
2. **Lint:** `golangci-lint run`
3. **Manual smoke test:** Start server, create alert rule with float condition, verify it compiles correctly
4. **Security review:** Run `/security-review` on Tasks 4 and 5 (auth changes)
5. **Pitfall check:** Run `/pitfall-check` on evaluator and store changes

## Parallelization

Tasks 1-3 (P0) are independent — can be worked in parallel by separate agents.

Tasks 4-5 (P1) are independent of each other and of Tasks 1-3.

Tasks 6-10 (P2) have some dependencies:
- Task 6 (evaluator) should precede Task 7 (executor) — both touch PostFilter logic
- Tasks 8 and 9 are independent
- Task 10 is independent

Tasks 11-13 (P3) are all independent and can be parallelized.

Task 14 (Phase 5 SSO + retention) is independent of all other tasks and can run in parallel with any wave.
