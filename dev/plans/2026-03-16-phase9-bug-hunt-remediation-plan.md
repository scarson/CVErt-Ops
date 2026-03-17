# Phase 9 Bug Hunt Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all confirmed correctness bugs found by the Phase 9 bug hunt trio (6 agents, 11 findings).

**Architecture:** Nine independent fix tasks across Go backend and Vue frontend. Each task is self-contained — no ordering dependencies between tasks (except Task 0 prerequisite for all).

**Tech Stack:** Go 1.26, PostgreSQL, Vue 3 + TypeScript, httptest, vitest

---

## Global Agent Instructions

**BEFORE starting ANY task**, every agent MUST:

1. Read `dev/testing-pitfalls.md` in full — this is mandatory context for test design
2. Invoke the `superpowers:test-driven-development` skill
3. Follow TDD strictly: write failing test → verify failure → implement fix → verify pass

**AFTER completing each task (or logical batch)**, every agent MUST:

1. Run `go test ./internal/api/... -count=1 -race` (for Go tasks) or `cd web && npm run test:unit` (for frontend tasks) to verify no regressions
2. Run `golangci-lint run ./internal/...` (for Go tasks) or `cd web && npm run lint && npm run type-check` (for frontend tasks)
3. Review their tests against `dev/testing-pitfalls.md` — specifically check:
   - §3 "Error Path Differentiation" — are error paths tested, not just happy paths?
   - §12 "Frontend State & Error Handling" — does every fetch failure render an error state, not a blank page?
   - For each test: "Am I testing real logic or mocked behavior?" (CLAUDE.md rule: never write tests that test mocked behavior)
4. Commit the task with a descriptive message

---

## Task 0: Prerequisite Reading (ALL agents)

**This is not a coding task.** Every agent must read these files before starting work:

- `dev/testing-pitfalls.md` (full file)
- `internal/api/contract.go` (shared helpers: `writeJSON`, `writeProblem`, `writeList`, cursor helpers)
- `internal/api/contract_test.go` (test patterns for contract helpers)

---

## Task 1: Fix PostFilter + Pagination Interaction

**Bug:** When regex PostFilters remove rows from a `limit+1` fetch, the next-page cursor check runs on the post-filtered set and silently truncates results. Users get incomplete saved search results with no next-page indicator.

**Severity:** HIGH

**Files:**
- Modify: `internal/store/dsl_executor.go` (lines 188-214)
- Test: `internal/store/dsl_executor_test.go`

**Root cause:** Lines 188-199 apply PostFilters to `results`, then line 204 checks `len(results) > limit` on the filtered set. If filtering removes enough rows, the check is false even though more matching rows exist in the database.

**Step 1: Write the failing test**

Add a test to `dsl_executor_test.go` that proves the bug. The test needs:
- A compiled DSL query with a regex PostFilter that matches ~40% of rows
- A limit small enough that the PostFilter will remove enough rows to hide the next-page indicator
- Assertion: `nextCursor` must be non-empty when there are more unfiltered rows in the database, even if filtered results are fewer than `limit`

The test must use a real database (not mocks). Read the existing `dsl_executor_test.go` to understand the test setup pattern — it uses `testutil.TestDB` and inserts CVEs with known descriptions.

**IMPORTANT test design constraint:** The test must insert enough CVEs that the SQL query returns `limit+1` pre-filter rows, but the PostFilter removes enough to drop below `limit`. For example:
- Insert 30 CVEs, 10 with description matching regex `buffer overflow`, 20 without
- Set limit=15
- SQL fetches 16 rows (limit+1)
- PostFilter keeps only the matching ones (say 5 of 16)
- BUG: `len(filtered) > 15` → false → no cursor
- FIX: pre-filter count was 16 > 15 → cursor should exist

**Step 2: Run test to verify it fails**

Run: `go test ./internal/store/... -run TestExecuteDSLQuery_PostFilterPagination -count=1 -v`
Expected: FAIL — nextCursor is empty when it should be non-empty

**Step 3: Implement the fix**

Replace `dsl_executor.go` lines 188-214 with this EXACT implementation. Do NOT deviate — the ordering matters for correctness:

```go
// Save pre-filter state for pagination. The pagination decision must use the
// pre-filter row count because PostFilters can remove rows after SQL fetch.
preFetchCount := len(results)

// Save the last pre-filter row's cursor position BEFORE filtering overwrites results.
// Needed when PostFilters remove all visible rows but more pages exist.
var preFetchCursorRow generated.CVE
if preFetchCount > limit {
    preFetchCursorRow = results[limit-1]
}

// Apply in-process PostFilters (regex conditions) to SQL results.
if len(compiled.PostFilters) > 0 {
    wrapped := make([]cvePostFilterTarget, len(results))
    for i := range results {
        wrapped[i] = cvePostFilterTarget{&results[i]}
    }
    filtered := dsl.ApplyPostFilters(wrapped, compiled.PostFilters, compiled.Logic)
    results = make([]generated.CVE, len(filtered))
    for i := range filtered {
        results[i] = *filtered[i].cve
    }
}

// If the pre-filter fetch returned limit+1 rows, there is a next page.
var nextCursor string
if preFetchCount > limit {
    // Trim post-filtered results to at most limit entries.
    if len(results) > limit {
        results = results[:limit]
    }
    // Use the last visible row for cursor when we have post-filter results,
    // otherwise fall back to the pre-filter cursor position so the client
    // can advance past this empty page.
    cursorSource := preFetchCursorRow
    if len(results) > 0 {
        cursorSource = results[len(results)-1]
    }
    nextCursor, err = encodeDSLCursor(dslCursor{
        SortDate: cursorSource.DateModifiedCanonical,
        CVEID:    cursorSource.CveID,
    })
    if err != nil {
        return nil, "", err
    }
}
```

**Edge cases this handles:**
1. **PostFilter removes some rows, rest < limit:** `preFetchCount > limit` → true → cursor emitted. Client gets fewer than limit results but knows to fetch next page.
2. **PostFilter removes ALL rows:** `len(results) == 0` → cursor falls back to `preFetchCursorRow` → client can advance.
3. **No PostFilters:** `preFetchCount == len(results)` → original behavior preserved.
4. **Last page (no more data):** `preFetchCount <= limit` → no cursor → correct.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/store/... -run TestExecuteDSLQuery_PostFilterPagination -count=1 -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test ./internal/store/... -count=1 -race`
Expected: All tests pass

**Step 6: Add final-page edge case test (testing-pitfalls.md §9)**

Add a second test: PostFilter on the LAST page (no more rows in DB). Verify `nextCursor` is empty — the fix must not produce a spurious cursor when all data has been consumed.

**Step 7: Review tests against testing-pitfalls.md**

Check §9 "Cursor Lifecycle" — verify cursor behavior on final page and mid-pagination. Check §3 — verify error paths (invalid cursor, DB error) are tested.

**Step 8: Commit**

```
fix(store): preserve pre-filter row count for PostFilter pagination decision
```

---

## Task 2: Fix PostFilter Case-Sensitivity Mismatch

**Bug:** Alert evaluator pre-lowercases descriptions in SQL (`lower(cves.description_primary)`), but `cvePostFilterTarget.PostFilterField` returns raw case. Same regex rule produces different results depending on evaluation path.

**Severity:** MEDIUM

**Files:**
- Modify: `internal/store/dsl_executor.go` (line 253)
- Test: `internal/store/dsl_executor_test.go`

**Root cause:** `cvePostFilterTarget.PostFilterField` returns `c.cve.DescriptionPrimary.String` without lowering. The alert evaluator's `queryCandidates` selects `COALESCE(lower(cves.description_primary), '')`, so regex matching is effectively case-insensitive in alert evaluation but case-sensitive in DSL execution.

**Step 1: Write the failing test**

Add TWO tests:

**Test A:** Insert a CVE with mixed-case description (e.g., `"Critical Buffer Overflow in Chrome"`). Run a DSL query with a regex PostFilter for `buffer overflow` (lowercase). Assert the CVE matches — currently it won't because the description contains uppercase letters.

**Test B (verify lowercase applies to target, not regex):** Insert a CVE with mixed-case description `"Critical Buffer Overflow"`. Run a DSL query with regex PostFilter `critical buffer` (lowercase). Assert the CVE matches — the target text is lowered before matching, so a lowercase regex matches mixed-case text. This confirms parity with the alert evaluator path which uses `lower()` in SQL.

**Test C (negative — uppercase regex should NOT match lowered text):** Same CVE. Run with regex PostFilter `Critical Buffer` (mixed case). Assert the CVE does NOT match — because the target is lowered to `"critical buffer overflow"` but the regex `Critical` has an uppercase C. This proves the fix lowercases the target, not the regex, which is the correct behavior matching the evaluator's `lower()` semantics.

Use a real database. Read existing tests in `dsl_executor_test.go` for the setup pattern.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/store/... -run TestExecuteDSLQuery_PostFilterCaseInsensitive -count=1 -v`
Expected: FAIL — CVE not matched

**Step 3: Implement the fix**

Change line 253 of `dsl_executor.go`:

```go
// Before:
return c.cve.DescriptionPrimary.String

// After:
return strings.ToLower(c.cve.DescriptionPrimary.String)
```

Add `"strings"` to the import block if not already present.

**IMPORTANT:** Check if the `cve_id` field (line 251) should also be lowered. In the evaluator's `queryCandidates`, `cves.cve_id` is selected without `lower()` — so the `cve_id` field should NOT be lowered. Only the description field.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/store/... -run TestExecuteDSLQuery_PostFilterCaseInsensitive -count=1 -v`
Expected: PASS

**Step 5: Run full test suite and lint**

Run: `go test ./internal/store/... -count=1 -race && golangci-lint run ./internal/store/...`

**Step 6: Commit**

```
fix(store): lowercase description in PostFilter to match alert evaluator behavior
```

---

## Task 3: Convert Watchlist Items Cursor to Opaque Format

**Bug:** `listWatchlistItemsHandler` uses a raw UUID string as its cursor, while every other paginated endpoint uses `encodePageCursor`/`decodePageCursor`. Breaks contract uniformity.

**Severity:** MEDIUM

**Files:**
- Modify: `internal/api/watchlists.go` (lines 545-579)
- Test: `internal/api/watchlists_test.go`

**Reference pattern:** Read how other handlers use cursors. For example, look at `listAlertRulesHandler` in `alert_rules.go` or `listDeliveriesHandler` in `deliveries.go` for the standard pattern:
1. Define a cursor struct (e.g., `watchlistItemCursor`)
2. Decode with `decodePageCursor(cursorStr, &cursor)`
3. Encode with `encodePageCursor(cursorStruct)`

**Step 1: Write the failing test**

Add a test to `watchlists_test.go` that verifies the cursor is opaque (base64url-encoded JSON), not a raw UUID. The test should:
1. Create a watchlist with enough items to trigger pagination (>50 items, since `const limit = 50`)
2. Fetch the first page
3. Assert `next_cursor` is NOT a valid UUID (it should be base64-encoded)
4. Fetch the second page using the cursor
5. Assert items don't overlap between pages

Read existing tests in `watchlists_test.go` for the test helper patterns (test server setup, auth, org creation).

**IMPORTANT:** The cursor param name is `cursor` (line 553: `r.URL.Query().Get("cursor")`). This is already correct and consistent with other endpoints.

**Step 2: Run test to verify it fails**

Expected: FAIL — the cursor IS a raw UUID

**Step 3: Implement the fix**

Define a cursor struct and convert the handler:

```go
// watchlistItemCursor is the opaque cursor for watchlist item pagination.
type watchlistItemCursor struct {
	ID string `json:"id"`
}
```

Update the cursor decode block (lines 553-560):

```go
// Before:
if a := r.URL.Query().Get("cursor"); a != "" {
    id, err := uuid.Parse(a)
    if err != nil {
        writeProblem(w, http.StatusBadRequest, "invalid cursor")
        return
    }
    afterID = &id
}

// After:
if a := r.URL.Query().Get("cursor"); a != "" {
    var cur watchlistItemCursor
    if err := decodePageCursor(a, &cur); err != nil {
        writeProblem(w, http.StatusBadRequest, "invalid cursor")
        return
    }
    id, err := uuid.Parse(cur.ID)
    if err != nil {
        writeProblem(w, http.StatusBadRequest, "invalid cursor")
        return
    }
    afterID = &id
}
```

Update the cursor encode block (lines 569-573):

```go
// Before:
if len(items) > limit {
    items = items[:limit]
    nextCursor = items[len(items)-1].ID.String()
}

// After:
if len(items) > limit {
    items = items[:limit]
    nextCursor = encodePageCursor(watchlistItemCursor{
        ID: items[len(items)-1].ID.String(),
    })
}
```

**Step 4: Run test to verify it passes**

**Step 5: Run full test suite**

Run: `go test ./internal/api/... -run TestWatchlist -count=1 -race -v`

**IMPORTANT backward-compatibility note:** This changes the cursor format for existing clients. Since this is a pre-release product with no external consumers, this is acceptable. Do NOT add backward-compatibility code to decode raw UUIDs — clean break.

**Step 6: Commit**

```
fix(api): convert watchlist items cursor to opaque base64url format
```

---

## Task 4: Fix AdminSystemView Doctor 503 Handling

**Bug:** `/admin/doctor` returns 503 with valid JSON when unhealthy. Both `fetchAll()` and `runDoctor()` only parse when `resp.ok` (200-299). Health card shows nothing when system is unhealthy.

**Severity:** MEDIUM

**Files:**
- Modify: `web/src/views/admin/AdminSystemView.vue` (lines 54 and 76)
- Test: `web/src/views/admin/__tests__/AdminSystemView.test.ts`

**Step 1: Write the failing test**

Add tests to `AdminSystemView.test.ts` that verify doctor results are displayed when the endpoint returns 503. Read the existing test file to understand the mock pattern (it uses `vi.mock` with `mockGET` for the typed client, and the doctor endpoint uses raw `fetch`).

**Test 1: fetchAll with 503 doctor response**
- Mock `fetch` to return a Response with `status: 503`, `ok: false`, and a valid JSON body containing doctor results (e.g., `{ checks: [{ name: "db", healthy: false, message: "connection timeout" }] }`)
- Assert that `doctor.value` is populated (the Health Checks section renders)

**Test 2: runDoctor with 503 response**
- Same mock pattern
- Trigger the "Run Doctor" button click
- Assert doctor results are updated

**IMPORTANT mock note:** The doctor endpoint uses raw `fetch()`, not the typed client. You need to mock `global.fetch` (or `window.fetch`), NOT the typed client's GET method. Read the existing tests carefully to see if there's already a fetch mock pattern. If the test file uses `vi.fn()` for `mockGET`, the fetch mock needs a separate setup.

**How to mock fetch for this test:**

```typescript
const doctorBody = { checks: [{ name: 'db', healthy: false, message: 'timeout' }] }
const mockFetch = vi.fn().mockResolvedValue({
  ok: false,
  status: 503,
  json: () => Promise.resolve(doctorBody),
})
vi.stubGlobal('fetch', mockFetch)
```

**Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run src/views/admin/__tests__/AdminSystemView.test.ts`
Expected: FAIL — doctor value is not populated on 503

**Step 3: Implement the fix**

In `AdminSystemView.vue`, change both locations:

**Line 54 (in fetchAll):**
```typescript
// Before:
if (doctorResp.ok) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}

// After:
if (doctorResp.status === 200 || doctorResp.status === 503) {
  doctor.value = (await doctorResp.json()) as DoctorResult
}
```

**Line 76 (in runDoctor):**
```typescript
// Before:
if (resp.ok) {
  doctor.value = (await resp.json()) as DoctorResult
}

// After:
if (resp.status === 200 || resp.status === 503) {
  doctor.value = (await resp.json()) as DoctorResult
}
```

**Also update the all-failed check on line 61:**
```typescript
// Before:
if (versionResult.error && !doctorResp.ok && configResult.error) {

// After:
if (versionResult.error && !(doctorResp.status === 200 || doctorResp.status === 503) && configResult.error) {
```

**Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run src/views/admin/__tests__/AdminSystemView.test.ts`
Expected: PASS

**Step 5: Run full frontend test suite**

Run: `cd web && npm run test:unit && npm run lint && npm run type-check`

**Step 6: Add all-failed edge case test (testing-pitfalls.md §12)**

Add a test where ALL three calls fail: version returns error, doctor returns 500 (not 200 or 503), config returns error. Assert the global error message is displayed. This verifies the "all failed" check still works after the 503 fix.

**Step 7: Review against testing-pitfalls.md §12**

Verify: does the test check that doctor results render on 503? Does the error state still trigger when ALL calls fail? Does the test verify that a 500 doctor response does NOT populate doctor data?

**Step 8: Commit**

```
fix(web): parse doctor response on 503 — unhealthy is valid data, not an error
```

---

## Task 5: Convert Middleware Errors to RFC 9457

**Bug:** Middleware files use `http.Error()` (text/plain) while all handlers use `writeProblem()` (application/problem+json). Frontend clients parsing `Content-Type` will fail on middleware errors.

**Severity:** MEDIUM

**Files:**
- Modify: `internal/api/middleware_auth.go` (7 `http.Error` calls)
- Modify: `internal/api/middleware_rbac.go` (5 `http.Error` calls)
- Modify: `internal/api/middleware_csrf.go` (1 `http.Error` call)
- Modify: `internal/api/middleware_site_admin.go` (3 `http.Error` calls)
- Modify: `internal/api/ratelimit.go` (1 `http.Error` call — the `authRateLimit` one at line 90)
- Test: `internal/api/middleware_auth_test.go`
- Test: `internal/api/middleware_rbac_test.go`
- Test: `internal/api/middleware_cors_test.go` (may have CSRF tests)
- Existing tests in the above files

**⛔ SCOPE EXCLUSION — DO NOT MODIFY THESE FILES UNDER ANY CIRCUMSTANCES:**
- `internal/api/oauth_github.go` — DO NOT TOUCH
- `internal/api/oauth_google.go` — DO NOT TOUCH
- `internal/api/oauth_oidc.go` — DO NOT TOUCH

These are OAuth callback handlers (browser-redirect flows). The browser makes the request directly, not the SPA. Converting to `writeProblem` would show raw JSON in the browser tab. These need a redirect-based error pattern which is a separate design task. If you touch these files, you are doing the wrong thing — STOP.

**Step 1: Write failing tests for Content-Type**

For each middleware file, add or update a test that asserts the error response has `Content-Type: application/problem+json` and the body is valid RFC 9457 JSON. Focus on one representative error case per middleware:

- `middleware_auth_test.go`: Test that a request with no cookie and no Bearer token returns 401 with `application/problem+json` Content-Type and a JSON body with `status`, `title`, `detail` fields
- `middleware_rbac_test.go`: Test that a request from a viewer to an admin-required endpoint returns 403 with RFC 9457 format
- Add a test for CSRF rejection (may need a new test file `middleware_csrf_test.go` or add to an existing file)
- Add a test for site admin rejection in `middleware_site_admin_test.go` or similar

Read existing tests to understand the test server setup. Middleware tests typically create a chi router, add the middleware, add a dummy handler, and use `httptest`.

**Step 2: Run tests to verify they fail**

Expected: FAIL — Content-Type is `text/plain; charset=utf-8`, not `application/problem+json`

**Step 3: Implement the conversions**

**Pattern:** Replace every `http.Error(w, msg, status)` with `writeProblem(w, status, msg)` followed by `return`.

**IMPORTANT:** `http.Error` already calls `w.WriteHeader` and writes the body. `writeProblem` does the same. The conversion is a direct 1:1 replacement. However, check that every `http.Error` call is followed by a `return` — `writeProblem` does NOT return, so if there's no `return` after `http.Error`, you must add one.

**middleware_auth.go** — 7 replacements:
```go
// Before:
http.Error(w, "unauthorized", http.StatusUnauthorized)
// After:
writeProblem(w, http.StatusUnauthorized, "unauthorized")
```

Same pattern for "internal error" calls:
```go
// Before:
http.Error(w, "internal error", http.StatusInternalServerError)
// After:
writeProblem(w, http.StatusInternalServerError, "internal error")
```

**middleware_rbac.go** — 5 replacements. Same pattern. Note the specific messages:
- `"unauthorized"` → keep as detail
- `"invalid org_id"` → keep as detail
- `"api key not valid for this organization"` → keep as detail
- `"forbidden"` → keep as detail (two occurrences)

**middleware_csrf.go** — 1 replacement:
```go
// Before:
http.Error(w, "CSRF check failed: X-Requested-By header required", http.StatusForbidden)
// After:
writeProblem(w, http.StatusForbidden, "CSRF check failed: X-Requested-By header required")
```

**middleware_site_admin.go** — 3 replacements:
- `"unauthorized"` (401)
- `"internal error"` (500)
- `"forbidden: site admin required"` (403)

**ratelimit.go** — 1 replacement (line 90 only, the `authRateLimit` function):
```go
// Before:
w.Header().Set("Retry-After", "60")
http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
// After:
w.Header().Set("Retry-After", "60")
writeProblem(w, http.StatusTooManyRequests, "rate limit exceeded")
```

**IMPORTANT:** The `Retry-After` header must remain. `writeProblem` sets `Content-Type` and calls `WriteHeader`, but `Retry-After` is set before that, so it's fine — Go's `http.ResponseWriter` allows setting headers before `WriteHeader`.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/... -run "TestMiddleware|TestAuth|TestCSRF|TestRBAC|TestSiteAdmin|TestRateLimit" -count=1 -v`

**Step 5: Run full test suite**

Run: `go test ./internal/api/... -count=1 -race && golangci-lint run ./internal/api/...`

**Step 6: Commit**

```
fix(api): convert middleware errors from text/plain to RFC 9457 problem+json
```

---

## Task 6: Add Nil-Guard to savedSearchExecuteResponse and nlSearchResponse

**Bug:** Both response structs bypass `writeList`'s nil→empty-slice coercion. Safe today but fragile.

**Severity:** LOW

**Files:**
- Modify: `internal/api/saved_searches.go` (lines 460-468)
- Modify: `internal/api/ai.go` (lines 210-226)
- Test: `internal/api/saved_searches_test.go`
- Test: `internal/api/ai_test.go`

**Context:** `nlSearchResponse` has extra fields (`InterpretedQuery`, `Model`, `Cached`) so it can't use `writeList` directly. But we can add the nil-guard inline. `savedSearchExecuteResponse` IS a pure list envelope and could use `writeList`, but it's also used by `nlSearchResponse`'s code path, so keep them consistent — add nil-guards to both.

**Step 1: Write failing tests**

Add tests that verify `items` is `[]` (empty array) not `null` when there are zero results. The test must check the raw JSON, not just the Go struct.

For `saved_searches_test.go`:
- Execute a saved search that matches zero CVEs
- Parse the raw response body
- Assert `body["items"]` is an empty JSON array (`[]`), not null

For `ai_test.go`:
- Similar, but test may need to mock the LLM client to return a valid DSL query that matches nothing

Read existing test files for the setup patterns.

**Step 2: Run tests — they may or may not fail**

These tests might pass today because `make([]CVEItem, 0)` is non-nil. That's OK — the tests serve as regression guards. The code change is defensive.

**Step 3: Implement the fixes**

**saved_searches.go** — Convert to use `writeList` since `savedSearchExecuteResponse` is a pure `{items, next_cursor}` envelope identical to `listResponse[T]`:

```go
// Replace lines 465-468:
// Before:
writeJSON(w, http.StatusOK, savedSearchExecuteResponse{
    Items:      items,
    NextCursor: nextCursor,
})

// After:
writeList(w, items, nextCursor)
```

Then delete the `savedSearchExecuteResponse` struct definition (lines 46-49). Verify no other code references it with: `grep -rn "savedSearchExecuteResponse" internal/`

**ai.go** — Cannot use `writeList` because `nlSearchResponse` has extra fields (`InterpretedQuery`, `Model`, `Cached`). Add an explicit nil-guard before the `writeJSON` call:

```go
// Add before the writeJSON call at line 220:
if items == nil {
    items = []CVEItem{}
}
```

**Step 4: Run tests**

Run: `go test ./internal/api/... -run "TestSavedSearch|TestNLSearch|TestAI" -count=1 -v`

**Step 5: Verify no other code references `savedSearchExecuteResponse`**

Run: `grep -r "savedSearchExecuteResponse" internal/` — should only be the struct definition and one usage (both of which you're removing/replacing).

**Step 6: Run full test suite**

Run: `go test ./internal/api/... -count=1 -race && golangci-lint run ./internal/api/...`

**Step 7: Commit**

```
fix(api): use writeList for saved search execute; add nil-guard to NL search response
```

---

## Task 7: Fix deleteGroupHandler — Return 404 for Non-Existent Groups

**Bug:** `deleteGroupHandler` calls `SoftDeleteGroup` directly without checking existence. Returns 204 for non-existent groups instead of 404.

**Severity:** LOW

**Files:**
- Modify: `internal/api/groups.go` (lines 225-244)
- Test: `internal/api/groups_test.go`

**Reference pattern:** Read `deleteWatchlistHandler` in `watchlists.go` (lines 411-450) — it does a fetch-before-delete and returns 404 if not found. Follow the same pattern.

**Step 1: Write the failing test**

Add a test that sends `DELETE /api/v1/orgs/{org_id}/groups/{random_uuid}` and asserts 404 is returned, not 204.

Read existing `groups_test.go` for the test setup pattern.

**IMPORTANT per testing-pitfalls.md §3:** "Silent success on missing resources: When a DELETE or cancel operation targets a non-existent resource, test that it returns 404 — not 204."

**Step 2: Run test to verify it fails**

Expected: FAIL — returns 204

**Step 3: Implement the fix**

Add a fetch-before-delete pattern matching `deleteWatchlistHandler`:

```go
func (srv *Server) deleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid group_id")
		return
	}

	// Verify group exists before deleting.
	current, err := srv.store.GetGroup(r.Context(), orgID, groupID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get group for delete", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	if err := srv.store.SoftDeleteGroup(r.Context(), orgID, groupID); err != nil {
		slog.ErrorContext(r.Context(), "delete group", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

**Step 4: Run test to verify it passes**

**Step 5: Run full test suite**

Run: `go test ./internal/api/... -run TestGroup -count=1 -race -v`

**Step 6: Commit**

```
fix(api): return 404 when deleting non-existent group instead of silent 204
```

---

## Task 8: Fix Group Member Handlers — Validate Group Existence

**Bug:** `addGroupMemberHandler` and `removeGroupMemberHandler` don't validate that the group exists. Add produces FK violation as 500; remove succeeds silently.

**Severity:** LOW

**Files:**
- Modify: `internal/api/groups.go` (lines 280-342)
- Test: `internal/api/groups_test.go`

**Step 1: Write failing tests**

Two tests:

**Test 1: Add member to non-existent group returns 404**
- POST to `/api/v1/orgs/{org_id}/groups/{random_uuid}/members` with a valid user_id
- Assert 404 (currently returns 500 from FK violation)

**Test 2: Remove member from non-existent group returns 404**
- DELETE to `/api/v1/orgs/{org_id}/groups/{random_uuid}/members/{user_id}`
- Assert 404 (currently returns 204)

**Step 2: Run tests to verify they fail**

Expected: Test 1 fails with 500, Test 2 fails with 204

**Step 3: Implement the fix**

Add a group existence check at the start of both handlers, after parsing `groupID`:

```go
// Verify group exists.
group, err := srv.store.GetGroup(r.Context(), orgID, groupID)
if err != nil {
    slog.ErrorContext(r.Context(), "get group", "error", err)
    writeProblem(w, http.StatusInternalServerError, "internal error")
    return
}
if group == nil {
    writeProblem(w, http.StatusNotFound, "group not found")
    return
}
```

Add this block to both `addGroupMemberHandler` and `removeGroupMemberHandler`, right after the `groupID` parse.

**Step 4: Run tests**

**Step 5: Run full test suite**

Run: `go test ./internal/api/... -run TestGroup -count=1 -race -v`

**Step 6: Commit**

```
fix(api): validate group existence in add/remove member handlers
```

---

## Task 9: Fix Stale Comment in jobs.go

**Bug:** File-level comment says "All methods use s.q" but `HasPendingOrRunningJob` uses `s.withBypassTx`.

**Severity:** LOW (documentation only)

**Files:**
- Modify: `internal/store/jobs.go` (lines 3-7)

**No test needed** — this is a comment-only fix.

**Step 1: Update the comment**

```go
// Before (lines 3-7):
//
// All methods use s.q (bound to the raw pool) rather than a transaction helper.
// The jobs table is not org-scoped and has no RLS policies, so withOrgTx provides
// no safety benefit. Each method executes a single atomic SQL statement, so
// withBypassTx would add transaction overhead with no correctness gain.

// After:
//
// Most methods use s.q (bound to the raw pool) rather than a transaction helper.
// The jobs table is not org-scoped and has no RLS policies, so withOrgTx provides
// no safety benefit. HasPendingOrRunningJob uses withBypassTx because it runs
// within an existing handler flow that needs transaction isolation.
```

**Step 2: Verify lint passes**

Run: `golangci-lint run ./internal/store/...`

**Step 3: Commit**

```
fix(docs): correct stale comment in jobs.go about transaction helper usage
```

---

## Verification Gate

After all tasks are complete:

1. Run full Go test suite: `go test ./... -count=1 -race`
2. Run full frontend test suite: `cd web && npm run test:unit`
3. Run full linters: `golangci-lint run && cd web && npm run lint && npm run type-check`
4. Review each commit's test against `dev/testing-pitfalls.md` checklist
5. Verify no `http.Error` calls remain in middleware files (excluding OAuth):
   ```
   grep -rn "http.Error" internal/api/middleware_auth.go internal/api/middleware_rbac.go internal/api/middleware_csrf.go internal/api/middleware_site_admin.go internal/api/ratelimit.go
   ```
   Expected: zero results (OAuth files intentionally still use `http.Error` — see Task 5 scope exclusion)
