# Bug Hunt Report: Phase 8 (Operational Maturity) — Multi-Pass

**Date:** 2026-03-16
**Scope:** Phase 8 PR #15 (commit a437c02d) — 8B Observe, 8C Operate, 8D Extend
**Methodology:** Five focused passes: Contract Violations, Pattern Deviations, Failure Modes, Concurrency Issues, Error Propagation. Source files only (no test files read).

---

## Pass 1: Contract Violations

### Bug 1: Feed Scheduler Does Not Respect `paused_at` — Paused Feeds Continue Running

**Location:** `internal/ingest/scheduler.go:126-163`
**Severity:** significant

**Evidence:** The `maybeEnqueue` method checks for backoff (`BackoffUntil`) and not-due (`LastSuccessAt`), but never checks the `PausedAt` field from `FeedSyncState`:

```go
func (s *Scheduler) maybeEnqueue(ctx context.Context, entry FeedScheduleEntry) {
    state, err := s.store.GetFeedSyncState(ctx, entry.FeedName)
    // ...
    if state != nil {
        // Checks backoff — yes
        if state.BackoffUntil != nil && state.BackoffUntil.After(time.Now()) {
            // skip
        }
        // Checks not-due — yes
        if state.LastSuccessAt != nil && state.LastSuccessAt.Add(entry.Interval).After(time.Now()) {
            // skip
        }
        // Checks paused — NO! Missing check.
    }
    // Proceeds to enqueue the job...
}
```

Meanwhile, `PauseFeed`/`ResumeFeed` exist in the store (`internal/store/feed.go:201-212`), the SQL sets `paused_at` (`internal/store/queries/feed.sql:36-39`), and the admin UI shows pause/resume buttons (`web/src/views/admin/AdminFeedsView.vue`). The `FeedSyncState` struct includes `PausedAt *time.Time` and `syncStateFromRow` correctly reads it from the DB.

**Impact:** An admin pauses a feed via the UI. The `paused_at` timestamp is set in the database and shown in the UI. But the scheduler ignores it, so the feed continues to be scheduled and executed on its normal interval. The pause feature is completely non-functional.

### Bug 2: `readyz` and `MigrationCheck` Do Not Check `dirty` Flag on Schema Migrations

**Location:** `internal/api/readyz.go:46-58`, `internal/doctor/checks.go:58-73`
**Severity:** minor

**Evidence:** Both endpoints query:
```sql
SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1
```

golang-migrate's `schema_migrations` table has two columns: `version` (bigint) and `dirty` (boolean). When a migration fails mid-execution, `dirty = true` and `version` is set to the failed migration's version. The current check would compare this version against `expectedSchemaVersion` and could report either "current" (if the dirty version happens to match) or "behind" — neither of which accurately represents "broken: migration failed mid-apply."

**Impact:** A partially-applied migration would not be detected by readyz or doctor. The readyz endpoint could return 200 OK (if the dirty version matches `expectedSchemaVersion`), allowing traffic to flow to a pod with a corrupted schema. In the doctor case, it would report "pass" when it should report "fail."

### Bug 3: `adminPatchOrgHandler` Tier and Suspend Changes Are Not Atomic

**Location:** `internal/api/admin_orgs.go:89-168`
**Severity:** minor

**Evidence:** The handler performs tier update and suspend/unsuspend as separate database operations:
```go
if body.Tier != nil {
    if _, err := srv.store.AdminUpdateOrgTier(r.Context(), orgID, *body.Tier); err != nil {
        // returns error
    }
}

if body.Suspend != nil {
    if *body.Suspend {
        if _, err := srv.store.AdminSuspendOrg(r.Context(), orgID); err != nil {
            // returns error
        }
    }
    // ...
}
```

Each store method runs in its own `withBypassTx` transaction. If the tier update succeeds but the suspend fails (or vice versa), the org is left in a partially-updated state, and the client receives an error response despite the tier having been changed.

**Impact:** A PATCH request with both `tier` and `suspend` fields could result in a partial update with an error response. The re-fetch at line 160-167 would return the partially-updated org. Low severity since admin operations are infrequent and can be retried.

---

## Pass 2: Cross-Sibling Pattern Violations

### Bug 4: `adminListOrgsHandler` Returns Raw Store Type, Siblings Use Handler-Level Mapping

**Location:** `internal/api/admin_orgs.go:85` vs `internal/api/admin_orgs.go:167`
**Severity:** minor

**Evidence:** The `adminListOrgsHandler` returns the raw `AdminOrgRow` from the store:
```go
writeList(w, orgs, nextCursor)
```

But `adminPatchOrgHandler` maps the result through `toAdminOrgResponse`:
```go
writeJSON(w, http.StatusOK, toAdminOrgResponse(updated))
```

The `AdminOrgRow` includes `member_count`, `last_activity_at` fields. The `adminOrgResponse` struct omits them. This means the list endpoint returns more fields than the single-org PATCH response, creating an inconsistent API contract across the same resource type.

**Impact:** API clients see different shapes for the same org resource depending on which endpoint they call. The list response includes `member_count` and `last_activity_at`; the PATCH response does not.

### Bug 5: `triggerFeedHandler` Allows Triggering Paused Feeds

**Location:** `internal/api/feeds.go:84-108`
**Severity:** minor

**Evidence:** The `triggerFeedHandler` checks `ingest.IsKnownFeed(feedName)` but does not check whether the feed is currently paused. Compare with the pause/resume handlers which do check known-feed status. A paused feed should not be manually triggerable — if the admin paused it, they likely don't want it running at all.

Meanwhile `pauseFeedHandler` and `resumeFeedHandler` (same file) follow the same pattern of checking `IsKnownFeed` but not the pause state for triggering. The inconsistency is between the *semantic* expectation (paused = don't run) and the actual behavior (paused = don't auto-schedule, but manual trigger works fine).

**Impact:** An admin could pause a feed and then accidentally trigger it via the "Run" button in the UI. This is arguably a feature, but given Bug 1 (scheduler ignores pause), the combination means pause has zero effect.

---

## Pass 3: Failure Mode Reasoning

### Bug 6: Generic Feed Adapter `fetchJSON` Reads Entire Response Body Into Memory

**Location:** `internal/feed/generic/adapter.go:126`
**Severity:** minor

**Evidence:**
```go
body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
```

`maxResponseSize` is 50 MB. The architecture docs mandate streaming parse for large responses: "Streaming parse required for all large responses: `json.Decoder` with `Token()`/`More()` loop; `Decode(&slice)` is forbidden for large feeds."

The generic adapter reads the entire response (up to 50 MB) into a `[]byte`, then uses `gjson.GetBytes` and `gjson.ForEach` to iterate. While `gjson` doesn't decode into Go structs (so it's lighter than `json.Decode(&slice)`), it still requires the full body in memory.

**Impact:** A 50 MB response would allocate 50 MB of heap memory for the body, plus whatever gjson needs internally. For the generic adapter this may be acceptable since admins control the feed URLs, but it deviates from the project's stated architectural requirement. Not a correctness bug per se, but a deviation from the stated constraint.

### Bug 7: `adminBulkRetryDeliveriesHandler` Accepts Limit From Both Query Param and JSON Body

**Location:** `internal/api/admin_deliveries.go:113-148`
**Severity:** minor

**Evidence:**
```go
limit, ok := parseLimitParam(w, r, 100, 1000)
if !ok {
    return
}

if r.ContentLength > 0 {
    var body struct {
        Limit *int `json:"limit"`
    }
    if errDetail := decodeJSON(r, &body); errDetail != nil {
        writeProblem(w, http.StatusBadRequest, "invalid JSON body")
        return
    }
    if body.Limit != nil {
        // Silently overrides query param limit
        limit = *body.Limit
    }
}
```

If both a query param `?limit=50` and a JSON body `{"limit": 500}` are provided, the JSON body silently wins. This is confusing behavior for a POST endpoint. More importantly, the JSON body limit validation (`1-1000`) differs from the query param validation (`1-200` via `parseLimitParam`), so the JSON body can set a limit higher than the query param allows.

**Impact:** Ambiguous API contract. A client could set a limit of 1000 via JSON body but only 200 via query param. The dual-input pattern makes the actual limit non-obvious.

---

## Pass 4: Concurrency Issues

### Bug 8: `adminPatchOrgHandler` TOCTOU Between Existence Check and Updates

**Location:** `internal/api/admin_orgs.go:106-157`
**Severity:** minor

**Evidence:** The handler does:
1. `AdminGetOrgByID` — check org exists and not deleted
2. `AdminUpdateOrgTier` — update tier
3. `AdminSuspendOrg`/`AdminUnsuspendOrg` — update suspend state
4. `AdminGetOrgByID` — re-fetch to return

Each is a separate transaction. Between step 1 and steps 2/3, another admin could delete the org. The `AdminUpdateOrgTier` SQL has `WHERE deleted_at IS NULL`, so it would return `sql.ErrNoRows`, causing the handler to return a 500 error instead of a 404.

**Impact:** Low severity due to admin-only access and the narrow race window. The worst case is a confusing 500 error instead of a clean 404.

No goroutine leaks, lock ordering issues, or shared-state races were found in the Phase 8 code. The worker pool's `context.WithoutCancel` usage is correct; the `orgRateLimiter` properly protects its map with a mutex; the delivery worker's semaphore eviction is safe.

---

## Pass 5: Error Propagation

### Bug 9: `validate-feeds --dry-run` Silently No-Ops

**Location:** `cmd/cvert-ops/validate.go:49-51`
**Severity:** minor

**Evidence:**
```go
if dryRun {
    slog.Info("dry-run: connectivity checks not yet implemented")
}
```

The `--dry-run` flag is documented as "fetch first page from each feed URL to verify connectivity" but does nothing. The user gets a log message at INFO level but the command still exits 0 and prints "OK: N feed config(s) valid." The flag silently does not do what it says.

**Impact:** An operator running `validate-feeds --dry-run` would believe their feed URLs are reachable when they have not been tested at all. The exit code and output message are misleading.

### Bug 10: `adminDisableUserHandler` Swallows Information on the "Already Disabled" Path

**Location:** `internal/api/admin_users.go:90-109`
**Severity:** minor

**Evidence:** When `AdminDisableUser` returns `sql.ErrNoRows` (already disabled), the handler re-fetches the user and returns 200 with `{"status": "disabled"}`. This is correct idempotent behavior. However, the response doesn't indicate that the user was *already* disabled — it looks identical to a fresh disable. Compare with `adminEnableUserHandler` which does the same pattern. This is internally consistent but loses information.

**Impact:** Very minor — idempotent responses are a valid design choice. Noted for completeness.

---

## Design Concerns

### Feed Pause Architecture Gap

The `paused_at` feature has all the plumbing (migration, store methods, SQL, admin API, admin UI) but the scheduler — the one component that needs to respect it — does not check it. This is the most significant finding: a feature that appears to work in the UI but has no backend effect.

### Non-Atomic Multi-Field Admin PATCH

The `adminPatchOrgHandler` performs multiple independent transactions for a single PATCH request. While each individual store call is correct, the combination violates the principle of atomic API operations. If the project grows to include audit logging per-field, this pattern would produce partial audit trails for failed requests.

### `readyz` Schema Check Incomplete

The readyz endpoint's migration check queries only `version`, not `dirty`. This is a common pitfall with golang-migrate. In production Kubernetes, this means a pod with a dirty (partially-applied) migration could pass readiness probes.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| Significant | 1 |
| Minor | 9 |

| Pass | Bugs Found |
|------|-----------|
| Pass 1 — Contract Violations | 3 |
| Pass 2 — Pattern Deviations | 2 |
| Pass 3 — Failure Modes | 2 |
| Pass 4 — Concurrency | 1 |
| Pass 5 — Error Propagation | 3 |

The Phase 8 code is generally well-structured and follows project conventions. The most significant finding is Bug 1 (scheduler ignores `paused_at`), which makes the feed pause feature completely non-functional. The remaining bugs are minor contract inconsistencies, missing edge case handling, and an unimplemented flag.
