# Vendor Feed Adapter Bug Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 8 confirmed bugs from the triple bug hunt plus the `append(globalVar, ...)` fragility in resolve.go.

**Architecture:** Targeted fixes across 5 files. No new files. No schema changes. All fixes are isolated — no cross-task dependencies except Task 1 and Task 2 share `redhat/adapter.go`.

**Tech Stack:** Go 1.26, `net/http`, `encoding/json`, `io`, `strings`

**Worktree:** `.worktrees/vendor-feed-adapters/` on branch `feature/vendor-feed-adapters`

**Important:** All paths below are relative to `.worktrees/vendor-feed-adapters/`. Run all `go test` commands from the worktree root using `go -C .worktrees/vendor-feed-adapters test ./...` or `cd` into the worktree first.

---

### Task 1: Fix Red Hat cursor — always return non-nil NextCursor with advanced AfterDate

**Bug:** Red Hat adapter returns `NextCursor = nil` on last page, so `AfterDate` never advances and every sync re-fetches the full catalog.

**Files:**
- Modify: `internal/feed/redhat/adapter.go:469-485`
- Modify: `internal/feed/redhat/adapter_test.go` (TestFetch_Pagination, TestFetch_Success)

**Step 1: Write the failing test**

Add a test that asserts `NextCursor` is non-nil with an advanced `AfterDate` when the last page is returned. Add to `adapter_test.go`:

```go
func TestFetch_LastPageAdvancesCursor(t *testing.T) {
	t.Parallel()

	// A partial page (< 100 items) signals end of pagination.
	// The adapter must still return a non-nil NextCursor with today's date
	// so the next sync starts from where we left off.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cve.json"):
			_, _ = w.Write([]byte(`[{"CVE":"CVE-2025-0001"}]`))
		case strings.Contains(r.URL.Path, "/cve/CVE-"):
			_, _ = w.Write([]byte(`{"name":"CVE-2025-0001","details":["test"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: ts.URL, inner: http.DefaultTransport},
	}
	adapter := newTestAdapter(client)

	cursorJSON, _ := json.Marshal(Cursor{AfterDate: "2025-01-01"})
	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor must not be nil on last page — AfterDate must advance")
	}
	var cur Cursor
	if err := json.Unmarshal(result.NextCursor, &cur); err != nil {
		t.Fatalf("unmarshal cursor: %v", err)
	}
	if cur.AfterDate == "2025-01-01" {
		t.Error("AfterDate was not advanced from the original cursor value")
	}
	if cur.AfterDate == "" {
		t.Error("AfterDate is empty — should be today's date")
	}
	if cur.Page != 0 {
		t.Errorf("Page should be 0 (reset) on last page, got %d", cur.Page)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/redhat/ -run TestFetch_LastPageAdvancesCursor -v`
Expected: FAIL — `NextCursor must not be nil on last page`

**Step 3: Implement the fix**

In `adapter.go`, replace the cursor logic at lines 469-485. When `!fullPage` (last page), return a cursor with today's date and Page reset to 0:

```go
	// Determine next cursor for pagination.
	// When fullPage: advance to the next page with same AfterDate.
	// When !fullPage (last page): advance AfterDate to today, reset Page.
	// Always return non-nil NextCursor so the caller persists the new position.
	var next Cursor
	if fullPage {
		page := cur.Page
		if page == 0 {
			page = 1
		}
		next = Cursor{
			AfterDate: cur.AfterDate,
			Page:      page + 1,
		}
	} else {
		next = Cursor{
			AfterDate: fetchedAt.Format("2006-01-02"),
		}
	}
	nextCursor, err := json.Marshal(next)
	if err != nil {
		return nil, fmt.Errorf("redhat: marshal cursor: %w", err)
	}
```

And update the return to use `nextCursor` (which is now always non-nil).

**Step 4: Update existing test expectations**

Two existing tests assert `NextCursor == nil` for partial pages. Both must be updated:

(a) `TestFetch_Success` (line ~648-651) — replace:
```go
	// NextCursor should be nil (no more pages when list < 100)
	if result.NextCursor != nil {
		t.Errorf("NextCursor should be nil when list page is not full, got %s", result.NextCursor)
	}
```
with:
```go
	// NextCursor should advance AfterDate even on partial page
	if result.NextCursor == nil {
		t.Fatal("NextCursor should not be nil — AfterDate must advance on last page")
	}
```

(b) `TestFetch_Pagination` (line ~793-796) — replace:
```go
	// Page 2 has fewer than 100, so NextCursor should be nil
	if result2.NextCursor != nil {
		t.Errorf("NextCursor should be nil for partial page, got %s", result2.NextCursor)
	}
```
with:
```go
	// Page 2 has fewer than 100, so NextCursor should advance AfterDate
	if result2.NextCursor == nil {
		t.Fatal("NextCursor should not be nil — AfterDate must advance on last page")
	}
	var lastCur Cursor
	if err := json.Unmarshal(result2.NextCursor, &lastCur); err != nil {
		t.Fatalf("unmarshal last-page cursor: %v", err)
	}
	if lastCur.Page != 0 {
		t.Errorf("Page should be 0 (reset) on last page, got %d", lastCur.Page)
	}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/feed/redhat/ -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add internal/feed/redhat/adapter.go internal/feed/redhat/adapter_test.go
git commit -m "fix(redhat): always advance AfterDate cursor on last page

Previously returned nil NextCursor on the last page, causing every sync
to re-fetch the entire catalog from the original AfterDate."
```

---

### Task 2: Fix Red Hat detail body drain and error double-prefix

**Bugs:** (a) Detail success path doesn't drain body before Close (kills connection reuse). (b) Error message "redhat: parse detail" is double-prefixed.

**Files:**
- Modify: `internal/feed/redhat/adapter.go:460-463, 170-175`
- Modify: `internal/feed/redhat/adapter_test.go`

**Step 1: Write the failing test for body drain**

Connection reuse is hard to test directly, but we can verify the body is fully read. Add a test that counts connections or verifies body consumption. The simplest approach: test that error messages aren't double-prefixed (bug 7):

```go
func TestParseDetailResponse_ErrorPrefix(t *testing.T) {
	t.Parallel()

	_, err := parseDetailResponse(strings.NewReader(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	msg := err.Error()
	// Should NOT contain "redhat:" prefix — caller adds the prefix with CVE context
	if strings.HasPrefix(msg, "redhat:") {
		t.Errorf("parseDetailResponse should not prefix errors with 'redhat:', got: %s", msg)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/redhat/ -run TestParseDetailResponse_ErrorPrefix -v`
Expected: FAIL — error starts with "redhat: parse detail:"

**Step 3: Implement both fixes**

(a) Fix `parseDetailResponse` to not prefix (line 173-174):
```go
func parseDetailResponse(r io.Reader) (*detailRecord, error) {
	var detail detailRecord
	if err := json.NewDecoder(r).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}
```

(b) Add body drain on detail success path (lines 460-461):
```go
		detail, err := parseDetailResponse(io.LimitReader(resp.Body, maxDetailSize))
		io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec // drain remainder for connection reuse
		resp.Body.Close()              //nolint:errcheck,gosec
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/feed/redhat/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/feed/redhat/adapter.go internal/feed/redhat/adapter_test.go
git commit -m "fix(redhat): drain detail body for connection reuse, deduplicate error prefix

Detail success path now drains remaining response bytes before Close,
enabling HTTP connection pool reuse across 100+ detail fetches per sync.
Removed redundant 'redhat: parse detail:' prefix from parseDetailResponse."
```

---

### Task 3: Fix KEV enrichment null-byte sanitization

**Bug:** KEV `recordToPatch` doesn't call `StripNullBytes` on enrichment fields.

**Files:**
- Modify: `internal/feed/kev/adapter.go:281-288`
- Modify: `internal/feed/kev/adapter_test.go`

**Step 1: Write the failing test**

```go
func TestRecordToPatch_NullByteInEnrichment(t *testing.T) {
	t.Parallel()

	rec := kevRecord{
		CVEID:          "CVE-2024-9999",
		RequiredAction: "Apply\x00update",
		VendorProject:  "Test\x00Vendor",
		Product:        "Widget\x00Pro",
		Notes:          "See\x00advisory",
		DueDate:        "2024-12-01",
	}

	patch := recordToPatch(rec)
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}
	if patch.VendorEnrichment == nil {
		t.Fatal("expected non-nil VendorEnrichment")
	}

	data := string(patch.VendorEnrichment.Data)
	if strings.Contains(data, "\x00") {
		t.Errorf("enrichment data contains null bytes: %q", data)
	}
	if !strings.Contains(data, "Applyupdate") {
		t.Errorf("expected stripped required_action 'Applyupdate' in enrichment, got: %s", data)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/kev/ -run TestRecordToPatch_NullByteInEnrichment -v`
Expected: FAIL — `enrichment data contains null bytes`

**Step 3: Implement the fix**

In `adapter.go`, strip null bytes on all enrichment string fields:

```go
	enrichmentData, err := json.Marshal(map[string]any{
		"required_action": feed.StripNullBytes(rec.RequiredAction),
		"due_date":        feed.StripNullBytes(rec.DueDate),
		"ransomware_use":  rec.KnownRansomwareCampaignUse == "Known",
		"vendor_project":  feed.StripNullBytes(rec.VendorProject),
		"product":         feed.StripNullBytes(rec.Product),
		"notes":           feed.StripNullBytes(rec.Notes),
	})
```

Note: `strings.Clone` is not needed here because the result of `StripNullBytes` on a string containing `\x00` is already a new allocation, and `json.Marshal` copies values anyway. For clean strings, `StripNullBytes` returns the original — but that's fine inside a `map[string]any` that gets marshaled to a fresh `[]byte`.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/feed/kev/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/feed/kev/adapter.go internal/feed/kev/adapter_test.go
git commit -m "fix(kev): strip null bytes from enrichment data fields

MSRC and Red Hat adapters already sanitize enrichment strings. KEV was
only sanitizing CanonicalPatch fields (CVEID, ShortDescription, CWEs)
but not the enrichment map values. A null byte in upstream KEV data
would cause the JSONB insert to fail."
```

---

### Task 4: Fix MSRC CVSS 0.0 handling

**Bug:** `bestV3Score > 0` treats CVSS 0.0 as "no score."

**Files:**
- Modify: `internal/feed/msrc/adapter.go:109-134`
- Modify: `internal/feed/msrc/adapter_test.go`

**Step 1: Write the failing test**

```go
func TestCsafToPatches_CVSSZeroScore(t *testing.T) {
	t.Parallel()

	doc := &csaf.Document{
		DocumentMeta: csaf.DocumentMeta{
			Tracking: csaf.Tracking{
				InitialReleaseDate: "2026-01-01T00:00:00Z",
				CurrentReleaseDate: "2026-01-01T00:00:00Z",
			},
		},
		ProductTree: csaf.ProductTree{},
		Vulnerabilities: []csaf.Vulnerability{
			{
				CVE: "CVE-2026-0001",
				Scores: []csaf.Score{
					{
						CVSSv3: &csaf.CVSSv3{
							BaseScore:    0.0,
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
						},
					},
				},
			},
		},
	}

	patches := csafToPatches(doc)
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}
	if patches[0].CVSSv3Score == nil {
		t.Fatal("CVSSv3Score should not be nil for a valid 0.0 score")
	}
	if *patches[0].CVSSv3Score != 0.0 {
		t.Errorf("CVSSv3Score = %f, want 0.0", *patches[0].CVSSv3Score)
	}
	if patches[0].CVSSv3Vector == nil || *patches[0].CVSSv3Vector == "" {
		t.Error("CVSSv3Vector should be set alongside the 0.0 score")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/feed/msrc/ -run TestCsafToPatches_CVSSZeroScore -v`
Expected: FAIL — `CVSSv3Score should not be nil for a valid 0.0 score`

**Step 3: Implement the fix**

Replace the CVSS extraction block in `csafToPatches` (lines 109-134):

```go
		// CVSS: take the highest v3 score across all product score entries.
		// Track presence separately since 0.0 is a valid CVSS score ("NONE" severity).
		var bestV3Score float64
		var bestV3Vector string
		var foundV3 bool
		var bestV4Score float64
		var bestV4Vector string
		var foundV4 bool

		for _, score := range vuln.Scores {
			if score.CVSSv3 != nil && (!foundV3 || score.CVSSv3.BaseScore > bestV3Score) {
				bestV3Score = score.CVSSv3.BaseScore
				bestV3Vector = score.CVSSv3.VectorString
				foundV3 = true
			}
			if score.CVSSv4 != nil && (!foundV4 || score.CVSSv4.BaseScore > bestV4Score) {
				bestV4Score = score.CVSSv4.BaseScore
				bestV4Vector = score.CVSSv4.VectorString
				foundV4 = true
			}
		}
		if foundV3 {
			p.CVSSv3Score = &bestV3Score
			vec := strings.Clone(feed.StripNullBytes(bestV3Vector))
			p.CVSSv3Vector = &vec
		}
		if foundV4 {
			p.CVSSv4Score = &bestV4Score
			vec := strings.Clone(feed.StripNullBytes(bestV4Vector))
			p.CVSSv4Vector = &vec
		}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/feed/msrc/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/feed/msrc/adapter.go internal/feed/msrc/adapter_test.go
git commit -m "fix(msrc): handle CVSS 0.0 score correctly

Previously used > 0 guard which treated valid 0.0 scores as 'no score'.
Now tracks presence with a bool flag, consistent with how NVD handles it."
```

---

### Task 5: Fix MSRC /updates body drain and cursor marshal error

**Bugs:** (a) `/updates` non-200 path doesn't drain body. (b) No-updates path swallows cursor marshal error.

**Files:**
- Modify: `internal/feed/msrc/adapter.go:310-312, 341`
- Modify: `internal/feed/msrc/adapter_test.go`

**Step 1: Write the failing test for cursor marshal consistency**

The marshal error is nearly impossible to trigger with current types, so test the drain behavior instead. We can write a test that verifies error wrapping consistency:

```go
func TestFetch_UpdatesNon200(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"maintenance"}`))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: ts.URL, inner: http.DefaultTransport},
	}
	adapter := New(client)

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}
```

**Step 2: Implement both fixes**

(a) Add body drain on `/updates` non-200 (line 310-311):
```go
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec // drain for connection reuse
		return nil, fmt.Errorf("msrc: updates HTTP %d", resp.StatusCode)
	}
```

(b) Handle cursor marshal error on no-updates path (line 341):
```go
		nextCursorJSON, err := json.Marshal(nextCursor)
		if err != nil {
			return nil, fmt.Errorf("msrc: marshal cursor: %w", err)
		}
```

**Step 3: Run tests to verify they pass**

Run: `go test ./internal/feed/msrc/ -v`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add internal/feed/msrc/adapter.go internal/feed/msrc/adapter_test.go
git commit -m "fix(msrc): drain /updates body on error, handle cursor marshal error

Added body drain on non-200 /updates response for connection reuse.
Fixed swallowed cursor marshal error on the no-updates short-circuit path."
```

---

### Task 6: Fix advisory lock ordering comment

**Bug:** Comment says "lower key first" but code always acquires newKey first.

**Files:**
- Modify: `internal/merge/pipeline.go:84-90`

**Step 1: Fix the comment**

Replace the misleading comment. The code's actual behavior (always newKey first from step 1, then oldKey) is correct in practice because PK migrations are always advisory-ID → CVE-ID. The comment should describe reality:

```go
		if err == nil && oldCVEID != patch.CVEID {
			// Lock the old CVE ID too — prevents concurrent writers for the old
			// ID from racing with the migration. newKey is already held from
			// step 1 above; acquire oldKey here. Deadlock between two concurrent
			// PK migrations is theoretically possible but practically unreachable:
			// migrations always go advisory-ID → CVE-ID, never the reverse.
			// PostgreSQL's deadlock detector resolves it if it ever occurs.
```

**Step 2: Run merge tests to verify nothing broke**

Run: `go test ./internal/merge/ -v`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add internal/merge/pipeline.go
git commit -m "fix(merge): correct misleading advisory lock ordering comment

Comment claimed 'lower key first' ordering but code acquires newKey first.
Updated comment to accurately describe actual behavior and explain why
the theoretical deadlock is unreachable in practice."
```

---

### Task 7: Harden resolve.go global slice append pattern

**Bug:** `append(globalVar, ...)` is safe today (len==cap) but fragile if global slices grow.

**Files:**
- Modify: `internal/merge/resolve.go:139, 153, ~236`
- Modify: `internal/merge/resolve_test.go`

**Step 1: Write the failing test**

This is a fragility fix — demonstrate the pattern is safe by testing that priority vars are never mutated:

```go
func TestPrioritySlicesNotMutatedByResolve(t *testing.T) {
	t.Parallel()

	// Capture lengths before resolve
	statusLen := len(statusPriority)
	cvssLen := len(cvssPriority)
	pkgLen := len(pkgPriority)

	// Run a resolve with an unknown source to trigger the append path
	patches := map[string]feed.CanonicalPatch{
		"unknown_source": {CVEID: "CVE-2026-0001"},
		SourceNVD:        {CVEID: "CVE-2026-0001"},
	}
	_ = Resolve(patches)

	// Verify global slices were not mutated
	if len(statusPriority) != statusLen {
		t.Errorf("statusPriority was mutated: len changed from %d to %d", statusLen, len(statusPriority))
	}
	if len(cvssPriority) != cvssLen {
		t.Errorf("cvssPriority was mutated: len changed from %d to %d", cvssLen, len(cvssPriority))
	}
	if len(pkgPriority) != pkgLen {
		t.Errorf("pkgPriority was mutated: len changed from %d to %d", pkgLen, len(pkgPriority))
	}
}
```

**Step 2: Run test — should pass (currently safe)**

Run: `go test ./internal/merge/ -run TestPrioritySlicesNotMutatedByResolve -v`
Expected: PASS (proves current behavior is correct)

**Step 3: Implement the hardening**

Replace the `append(globalVar, ...)` calls with `slices.Concat` (Go 1.22+). In `resolve.go`, add `"slices"` to imports and replace:

All 3 occurrences (confirmed by grep):

Line 139 (CVSS v3): `append(cvssPriority, otherSources(...)...)` → `slices.Concat(cvssPriority, otherSources(...))`

Line 153 (CVSS v4): same pattern, same replacement.

Line 236 (packages — uses `pkgPriority`): `append(pkgPriority, otherSources(...)...)` → `slices.Concat(pkgPriority, otherSources(...))`

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/merge/ -v`
Expected: ALL PASS

**Step 5: Run lint**

Run: `golangci-lint run ./internal/merge/...`
Expected: Clean

**Step 6: Commit**

```bash
git add internal/merge/resolve.go internal/merge/resolve_test.go
git commit -m "fix(merge): use slices.Concat instead of append on global priority vars

append(globalVar, ...) is safe when len==cap but fragile if the global
slice's capacity ever changes. slices.Concat always allocates a new
backing array, making the pattern mutation-proof."
```

---

### Task 8: Final verification and lint

**Step 1: Run all tests in the worktree**

Run: `go test ./...`
Expected: ALL PASS

**Step 2: Run linter**

Run: `golangci-lint run`
Expected: Clean (or only pre-existing warnings)

**Step 3: Verify test output is pristine**

Check that no unexpected log output or warnings appear in test output.

**Step 4: Commit any remaining cleanup**

If lint or tests reveal issues from the fixes, fix and commit.

---

## Design Concerns — NOT addressed in this plan

These were reviewed and intentionally deferred:

| Concern | Reason to defer |
|---------|----------------|
| MSRC "Exploitation Detected" → `ExploitAvailable` | Requires design decision on mapping multi-valued exploitability to boolean. Separate feature. |
| CSAF 3/8 product status types | YAGNI — only `known_affected` is used by MSRC today. |
| Neither adapter sets Severity/Status | By design — vendor adapters provide severity via enrichment. |
| MSRC backfill pagination | Operational concern — worth addressing but separate from correctness. |
| MSRC string date comparison | Low risk with ISO 8601. Monitor. |
| Single CSAF failure aborts fetch | Consistent with NVD pattern. Blast radius concern is valid but separate. |
| MSRC document-level dates | CSAF format limitation, not a code defect. Merge resolution mitigates for multi-source CVEs. |
