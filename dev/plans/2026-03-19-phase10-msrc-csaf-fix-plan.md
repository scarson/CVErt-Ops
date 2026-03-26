# MSRC Adapter CSAF Fix + Phase 10 Completion Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the broken MSRC adapter (switch from non-existent `/csaf/{id}` API endpoint to Microsoft's real CSAF 2.0 static file distribution), capture proper CSAF golden fixtures, write remaining golden tests (EPSS + MSRC), add MSRC to SeedCorpus, and complete Phase 10 test fixture corpus verification.

**Architecture:** The MSRC adapter's `Fetch()` method is rewritten to use Microsoft's CSAF static file distribution (`msrc.microsoft.com/csaf/advisories/`). Discovery uses `changes.csv` (a standard CSAF directory mechanism) for incremental sync. Individual per-CVE CSAF 2.0 JSON files are downloaded and parsed by the existing `csaf.Parse()` function. The `csafToPatches()` and `buildVendorEnrichment()` functions are unchanged — they already handle CSAF 2.0 correctly.

**Tech Stack:** Go 1.26, `net/http`, `encoding/csv`, `encoding/json`, `internal/feed/csaf` (existing parser), `httptest` (golden file tests), testcontainers (EPSS test)

**Worktree:** All work happens in `.claude/worktrees/phase10-fixture-corpus` on branch `phase10/test-fixture-corpus`.

---

## Context

**The Bug:** The MSRC adapter constructs URLs as `api.msrc.microsoft.com/cvrf/v3.0/csaf/{releaseID}`, but this endpoint does not exist. It returns HTTP 400 "Invalid ID format" for every release ID. The adapter was tested against hand-crafted CSAF fixtures and passed all tests, but never worked against real Microsoft data.

**The Fix:** Microsoft publishes real CSAF 2.0 files at `msrc.microsoft.com/csaf/advisories/`. Discovery mechanism:
- `changes.csv` — CSV of `"path","timestamp"` pairs, sorted newest-first, no header row
- `index.txt` — plain text list of all file paths
- Individual files at `https://msrc.microsoft.com/csaf/advisories/{year}/msrc_cve-{id}.json`

Each file is ~6KB of proper CSAF 2.0 JSON (keys: `document`, `product_tree`, `vulnerabilities`) that the existing `csaf.Parse()` handles correctly. Files are per-CVE (one vulnerability per document), not per-release-month.

**What stays unchanged:**
- `csafToPatches()` — converts `csaf.Document` to `[]feed.CanonicalPatch` (all field mappings preserved)
- `buildVendorEnrichment()` — extracts vendor-specific metadata (severity, fix state, KB articles, exploitability)
- `parseCSAFDocument()` — delegates to `csaf.Parse()`
- All `TestCSAFToPatches_*` unit tests (6 tests) — they test CSAF parsing, not Fetch
- The `csaf` parser package — untouched

**What changes:**
- `Fetch()` method — new two-phase: download `changes.csv` → download per-CVE CSAF files
- `Cursor` struct — `last_release_date` → `last_updated` (cursor semantics changed)
- Constants — `baseURL` → new CSAF base URL; size limits adjusted
- Removed: `updateEntry`, `updatesResponse`, `parseUpdates()`, `dateTimeRe`, OData filter logic
- Fetch tests — rewritten for new flow (5 tests)

**Testing-pitfalls warnings applicable to this plan:**
- §9.4 (Falsy-value preservation): CVSS 0.0 must be preserved. Existing `TestCSAFToPatches_CVSSZeroIsValid` covers this and stays unchanged.
- §9.1 (Wire format assumptions): We've verified the real CSAF file format with `curl` — proper CSAF 2.0 JSON.
- §7 (Test data must flow through production code paths): SeedCorpus feeds through `merge.Ingest`, not raw SQL.
- §16 (Test setup must not discard errors): All `os.ReadFile`, `json.Unmarshal` etc. must check errors with `require.NoError` or `t.Fatalf`.

**Implementation-pitfalls warnings:**
- FEED-1 (Wire format): Verified — per-CVE CSAF files use `{"document":..., "product_tree":..., "vulnerabilities":[...]}`. Not streaming (files are ~6KB).
- FEED-5 (defer in loops): When downloading multiple CSAF files in a loop, use explicit `resp.Body.Close()` per iteration, NOT `defer`.
- FEED-10 (String cloning): `csafToPatches()` already clones strings. No changes needed there.
- FEED-16 (Body drain): Drain response body before close on non-200 responses.

---

## Subagent Execution Protocol

All tasks that write tests MUST follow this protocol.

### Before starting any task:
```
1. Read dev/testing-pitfalls.md
2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
For pure test additions: write the test, verify it fails for the right reason
(or passes if it's testing already-correct behavior), then move on.
For code bugs: write failing test → fix code → verify green.
```

### Before marking any task complete:
```
1. Review your tests against dev/testing-pitfalls.md
2. Verify test coverage of the fix (are error paths tested? edge cases?)
3. Run tests for the relevant packages only (e.g., `go test ./internal/feed/msrc/... -count=1`).
   Do NOT run `go test ./...` — Docker container overload is a known issue.
```

### After completing each phase:
```
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next phase.
```

---

## Phase A: Capture Real CSAF Fixtures

### Task 1: Download real CSAF files for golden test data

**Files:**
- Replace: `internal/feed/msrc/testdata/golden/csaf/*.json` (currently CVRF-format files, must be replaced with real CSAF 2.0)
- Create: `internal/feed/msrc/testdata/golden/changes.csv`
- Remove: `internal/feed/msrc/testdata/golden/updates.json` (OData response, no longer needed)

**Step 1: Download CSAF files for manifest CVEs**

The test fixture manifest (`dev/plans/test-fixture-manifest.json`) includes 3 MSRC CVEs: CVE-2026-3909, CVE-2026-21510, CVE-2025-14174. Download their CSAF files. Note that the CSAF filename format is `msrc_cve-{id}.json` with lowercase `cve`.

```bash
# From worktree root
mkdir -p internal/feed/msrc/testdata/golden/csaf

# Try each CVE — some may not have CSAF files yet
curl -sL "https://msrc.microsoft.com/csaf/advisories/2026/msrc_cve-2026-3909.json" -o /tmp/msrc_cve-2026-3909.json
curl -sL "https://msrc.microsoft.com/csaf/advisories/2026/msrc_cve-2026-21510.json" -o /tmp/msrc_cve-2026-21510.json
curl -sL "https://msrc.microsoft.com/csaf/advisories/2025/msrc_cve-2025-14174.json" -o /tmp/msrc_cve-2025-14174.json
```

Check each file: a valid CSAF file starts with `{"document":`. If any returns a 404 or HTML, it doesn't exist. In that case, pick replacement CVEs from the CSAF index:

```bash
curl -sL "https://msrc.microsoft.com/csaf/advisories/index.txt" | grep "2026/" | head -10
```

Download 3-5 valid CSAF files. Place them in `internal/feed/msrc/testdata/golden/csaf/` with their original filenames (e.g., `msrc_cve-2026-3909.json`).

Verify each file is valid CSAF 2.0:
- Contains `"document"` key with `"tracking"` sub-key
- Contains `"vulnerabilities"` array with at least one entry having a `"cve"` field
- Contains `"product_tree"` key

**Step 2: Create a changes.csv fixture**

Build a `changes.csv` listing only the downloaded CSAF files. Format: `"path","timestamp"` with no header row. Use the `document.tracking.current_release_date` from each file as the timestamp. Example:

```csv
"2026/msrc_cve-2026-3909.json","2026-03-18T01:00:00Z"
"2026/msrc_cve-2026-21510.json","2026-03-17T07:00:00Z"
"2025/msrc_cve-2025-14174.json","2026-03-12T07:00:00Z"
```

Save to `internal/feed/msrc/testdata/golden/changes.csv`.

**Step 3: Remove old CVRF fixtures**

Delete:
- `internal/feed/msrc/testdata/golden/updates.json` (OData response, no longer used)
- All files in `internal/feed/msrc/testdata/golden/csaf/` that are CVRF format (check: CVRF files have `"DocumentTitle"` key; CSAF files have `"document"` key)

**Step 4: Commit**

```bash
git add internal/feed/msrc/testdata/golden/
git commit -m "test: replace CVRF fixtures with real CSAF 2.0 files from msrc.microsoft.com"
```

---

## Phase B: Fix MSRC Adapter

### Task 2: Rewrite MSRC adapter Fetch method for CSAF static files

**Files:**
- Modify: `internal/feed/msrc/adapter.go`

**Current behavior:** Fetches from `api.msrc.microsoft.com/cvrf/v3.0/updates` (OData) then `api.msrc.microsoft.com/cvrf/v3.0/csaf/{releaseID}` (broken endpoint). Returns patches grouped by monthly release.

**Desired behavior:** Fetches `changes.csv` from `msrc.microsoft.com/csaf/advisories/changes.csv`, filters by cursor timestamp, downloads individual per-CVE CSAF files, parses them with the existing CSAF parser. Returns patches — one per CVE file.

**Step 1: Update constants and imports**

Replace the constants section:

```go
const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "msrc"

	// baseURL is the MSRC CSAF advisory distribution base.
	baseURL = "https://msrc.microsoft.com/csaf/advisories/"

	// maxChangesSize caps the changes.csv response to prevent OOM.
	maxChangesSize = 10 << 20 // 10 MB

	// maxCSAFDocSize caps individual CSAF file response to prevent OOM.
	// Per-CVE files are typically ~6KB; 1MB is generous.
	maxCSAFDocSize = 1 << 20 // 1 MB
)
```

Remove these imports (no longer needed): `"net/url"`, `"regexp"`.
Add this import: `"encoding/csv"`.

**Step 2: Update Cursor struct**

```go
// Cursor is the JSON-serializable sync state for the MSRC adapter.
type Cursor struct {
	LastUpdated string `json:"last_updated"`
}
```

**Step 3: Remove dead code**

Delete these types and functions entirely:
- `dateTimeRe` (regexp for OData injection prevention — no longer needed)
- `updateEntry` struct
- `updatesResponse` struct
- `parseUpdates()` function

Keep these functions unchanged:
- `parseCSAFDocument()` — still used
- `csafToPatches()` — still used
- `buildVendorEnrichment()` — still used

**Step 4: Add changes.csv parser**

```go
// changeEntry represents a single row from the CSAF changes.csv file.
type changeEntry struct {
	Path      string // e.g., "2026/msrc_cve-2026-3909.json"
	Timestamp string // e.g., "2026-03-18T01:00:00Z"
}

// parseChangesCSV parses the CSAF changes.csv file. The CSV has no header row;
// each row is "path","timestamp". Returns entries sorted by the CSV's natural
// order (newest first).
func parseChangesCSV(r io.Reader) ([]changeEntry, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 2
	cr.ReuseRecord = true

	var entries []changeEntry
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("msrc: parse changes.csv: %w", err)
		}
		entries = append(entries, changeEntry{
			Path:      strings.Clone(record[0]),
			Timestamp: strings.Clone(record[1]),
		})
	}
	return entries, nil
}
```

**Step 5: Rewrite Fetch method**

Replace the entire `Fetch` method with:

```go
// Fetch implements feed.Adapter. Two-phase:
// 1. Download changes.csv to discover updated CSAF advisory files
// 2. Download and parse each changed per-CVE CSAF file
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("msrc: parse cursor: %w", err)
		}
	}

	// Phase 1: download changes.csv
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("msrc: rate limit: %w", err)
	}

	changesURL := baseURL + "changes.csv"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, changesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("msrc: build changes request: %w", err)
	}

	resp, err := a.client.Do(req) //nolint:gosec // URL constructed from constant base
	if err != nil {
		return nil, fmt.Errorf("msrc: fetch changes.csv: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec // drain for connection reuse
		return nil, fmt.Errorf("msrc: changes.csv HTTP %d", resp.StatusCode)
	}

	entries, err := parseChangesCSV(io.LimitReader(resp.Body, maxChangesSize))
	if err != nil {
		return nil, err
	}

	// Filter to entries newer than cursor
	var pending []changeEntry
	var latestTimestamp string
	for _, e := range entries {
		if e.Timestamp > latestTimestamp {
			latestTimestamp = e.Timestamp
		}
		if cur.LastUpdated != "" && e.Timestamp <= cur.LastUpdated {
			continue
		}
		pending = append(pending, e)
	}

	// Short-circuit: no new changes
	if len(pending) == 0 {
		effectiveTS := cur.LastUpdated
		if latestTimestamp > effectiveTS {
			effectiveTS = latestTimestamp
		}
		nextCursor := Cursor{LastUpdated: effectiveTS}
		nextCursorJSON, marshalErr := json.Marshal(nextCursor)
		if marshalErr != nil {
			return nil, fmt.Errorf("msrc: marshal cursor: %w", marshalErr)
		}
		return &feed.FetchResult{
			SourceMeta: feed.SourceMeta{
				SourceName: SourceName,
				FetchedAt:  time.Now().UTC(),
			},
			NextCursor: nextCursorJSON,
			LastPage:   true,
		}, nil
	}

	// Phase 2: download and parse each changed CSAF file
	fetchedAt := time.Now().UTC()
	var allPatches []feed.CanonicalPatch

	for _, entry := range pending {
		if err := a.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("msrc: rate limit: %w", err)
		}

		fileURL := baseURL + entry.Path
		fileReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("msrc: build request for %s: %w", entry.Path, reqErr)
		}
		fileReq.Header.Set("Accept", "application/json")

		fileResp, doErr := a.client.Do(fileReq) //nolint:gosec // URL constructed from constant base + CSV path
		if doErr != nil {
			return nil, fmt.Errorf("msrc: fetch %s: %w", entry.Path, doErr)
		}

		if fileResp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, fileResp.Body) //nolint:errcheck,gosec // drain for connection reuse
			fileResp.Body.Close()              //nolint:errcheck,gosec
			return nil, fmt.Errorf("msrc: %s HTTP %d", entry.Path, fileResp.StatusCode)
		}

		body, readErr := io.ReadAll(io.LimitReader(fileResp.Body, maxCSAFDocSize))
		fileResp.Body.Close() //nolint:errcheck,gosec
		if readErr != nil {
			return nil, fmt.Errorf("msrc: read %s: %w", entry.Path, readErr)
		}

		doc, parseErr := parseCSAFDocument(body)
		if parseErr != nil {
			return nil, fmt.Errorf("msrc: parse %s: %w", entry.Path, parseErr)
		}

		patches := csafToPatches(doc)
		allPatches = append(allPatches, patches...)
	}

	// Update cursor to latest timestamp seen
	effectiveTS := cur.LastUpdated
	if latestTimestamp > effectiveTS {
		effectiveTS = latestTimestamp
	}
	nextCursor := Cursor{LastUpdated: effectiveTS}
	nextCursorJSON, err := json.Marshal(nextCursor)
	if err != nil {
		return nil, fmt.Errorf("msrc: marshal cursor: %w", err)
	}

	return &feed.FetchResult{
		Patches: allPatches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  fetchedAt,
		},
		NextCursor: nextCursorJSON,
		LastPage:   true,
	}, nil
}
```

**Step 6: Run existing CSAF parsing tests**

```bash
cd <worktree> && go test ./internal/feed/msrc/... -run TestCSAFToPatches -v -count=1
```

Expected: All 6 `TestCSAFToPatches_*` tests PASS (these test `csafToPatches()` which is unchanged).

The `TestFetch_*` and `TestParseUpdates` tests will fail — that's expected and fixed in Task 3.

**Step 7: Commit**

```bash
git add internal/feed/msrc/adapter.go
git commit -m "fix(msrc): switch to real CSAF 2.0 static file distribution

The previous /cvrf/v3.0/csaf/{id} endpoint never existed on Microsoft's
API — it returned HTTP 400 for all release IDs. The adapter now uses
Microsoft's CSAF static file distribution at msrc.microsoft.com/csaf/
advisories/, which serves proper CSAF 2.0 JSON per-CVE files.

Discovery uses changes.csv (standard CSAF directory mechanism) for
incremental sync. The csafToPatches() and buildVendorEnrichment()
functions are unchanged."
```

---

### Task 3: Update MSRC adapter unit tests for new Fetch flow

**Files:**
- Modify: `internal/feed/msrc/adapter_test.go`

**Depends on:** Task 2 (adapter rewrite)

The test file has two sections:
1. **CSAF parsing tests** (lines 66-776) — `TestCSAFToPatches_*` and `csafToPatchesFromJSON` helper. These are UNCHANGED.
2. **Fetch tests** (lines 433-651) — `TestFetch_*`, `TestParseUpdates`, and `redirectTransport`. These must be REWRITTEN.

**Step 1: Remove dead test code**

Delete:
- `TestParseUpdates` function (tests removed `parseUpdates()`)
- `redirectTransport` struct and its `RoundTrip` method (replace with `testutil.NewURLRewriteTransport`)

**Step 2: Add `parseChangesCSV` unit test**

```go
func TestParseChangesCSV(t *testing.T) {
	t.Parallel()

	body := `"2026/msrc_cve-2026-3909.json","2026-03-18T01:00:00Z"
"2026/msrc_cve-2026-21510.json","2026-03-17T07:00:00Z"
"2025/msrc_cve-2025-14174.json","2026-03-12T07:00:00Z"
`

	entries, err := parseChangesCSV(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if entries[0].Path != "2026/msrc_cve-2026-3909.json" {
		t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, "2026/msrc_cve-2026-3909.json")
	}
	if entries[0].Timestamp != "2026-03-18T01:00:00Z" {
		t.Errorf("entries[0].Timestamp = %q, want %q", entries[0].Timestamp, "2026-03-18T01:00:00Z")
	}
}
```

**Step 3: Rewrite Fetch tests**

Replace `TestFetch_Success` with a test that:
1. Creates an httptest server with two route handlers:
   - `/csaf/advisories/changes.csv` → serves a 1-entry CSV fixture
   - `/csaf/advisories/2026/msrc_cve-2026-21001.json` → serves `minimalCSAFDoc` (the existing test constant)
2. Uses `testutil.NewURLRewriteTransport("https://msrc.microsoft.com", srv.URL, http.DefaultTransport)` — import `"github.com/scarson/cvert-ops/internal/testutil"`
3. Calls `adapter.Fetch(ctx, nil)` with nil cursor
4. Asserts: 1 patch returned, CVEID = "CVE-2026-21001", SourceName = "msrc", cursor.LastUpdated is set, LastPage = true

Replace `TestFetch_ShortCircuit` with a test that:
1. Creates server serving a 1-entry changes.csv with timestamp `"2026-03-12T08:00:00Z"`
2. Provides a cursor with `LastUpdated: "2026-03-12T08:00:00Z"` (same as CSV)
3. Asserts: 0 patches, only 1 HTTP request (changes.csv only, no CSAF file requests)

Replace `TestFetch_HTTPError` with a test that:
1. Creates server returning 500 on `/changes.csv`
2. Asserts: error contains "HTTP 500"

Replace `TestFetch_CSAFHTTPError` with a test that:
1. Creates server returning valid changes.csv but 500 on the CSAF file request
2. Asserts: error contains "HTTP 500"

Remove `TestFetch_InvalidCursorDate` entirely — the OData injection test is no longer relevant (no OData filter is constructed). The cursor is just a timestamp string compared locally.

**Step 4: Run all MSRC tests**

```bash
cd <worktree> && go test ./internal/feed/msrc/... -v -count=1
```

Expected: ALL tests PASS — both the unchanged CSAF parsing tests and the new Fetch tests.

**Step 5: Commit**

```bash
git add internal/feed/msrc/adapter_test.go
git commit -m "test(msrc): update Fetch tests for CSAF static file distribution"
```

**Phase B review loop:** After completing Tasks 2-3, run the review loop described in the Subagent Execution Protocol. Specifically verify: (1) all 6 `TestCSAFToPatches_*` tests still pass unchanged; (2) new Fetch tests cover success, short-circuit, and both error paths; (3) no existing test was deleted without replacement; (4) `parseChangesCSV` has its own unit test; (5) no `url` or `regexp` imports remain (removed dead code); (6) ABOUTME comments are updated if needed.

---

## Phase C: Golden File Tests

### Task 4: Write MSRC golden file test

**Files:**
- Create: `internal/feed/msrc/golden_test.go`

**Depends on:** Tasks 1 (fixtures) and 2 (adapter fix)

This test is in the `msrc_test` package (external test package). It serves the golden fixtures via httptest, runs the adapter's `Fetch()`, and verifies the real CSAF data parses correctly.

**Step 1: Write the test**

```go
// ABOUTME: Golden file test for the MSRC adapter using real CSAF 2.0 files.
// ABOUTME: Verifies vendor enrichment, CVSS extraction, and CSAF parsing from real Microsoft data.
package msrc_test
```

The test must:
1. Read `testdata/golden/changes.csv` fixture
2. Read all `testdata/golden/csaf/*.json` fixture files into a map keyed by path
3. Create an httptest server that routes:
   - Requests ending in `/changes.csv` → serve the CSV fixture
   - Requests containing path segments matching CSAF filenames → serve the corresponding fixture
4. Use `testutil.NewURLRewriteTransport("https://msrc.microsoft.com", srv.URL, http.DefaultTransport)`
5. Create adapter with `msrc.New(client)`, call `Fetch(ctx, nil)`
6. Loop until `LastPage == true`, collecting all patches

**Required assertions (from Phase 10 plan Task 10F):**
1. `len(allPatches) > 0` — non-zero patches
2. Every patch: `p.CVEID != ""` — all entries map to CVE IDs
3. At least one patch: `p.VendorEnrichment != nil` with `len(p.VendorEnrichment.Data) > 0`
4. At least one patch: `p.CVSSv3Score != nil` — CVSS data extracted
5. Every patch: `p.CVEID` starts with `"CVE-"` — proper CVE format
6. **Falsy-value check (testing-pitfalls §9.4):** If any patch has `CVSSv3Score == 0.0`, log it as correctly preserved

**Step 2: Run and verify**

```bash
cd <worktree> && go test ./internal/feed/msrc/... -run TestFetch_GoldenFiles -v -count=1
```

Expected: PASS

**Step 3: Commit**

```bash
git add internal/feed/msrc/golden_test.go
git commit -m "test: add MSRC golden file test against real CSAF 2.0 advisories"
```

---

### Task 5: Run EPSS golden file test

**Files:** `internal/feed/epss/golden_test.go` (already created in worktree)

**Depends on:** Docker Desktop must be running (testcontainers)

The EPSS golden test was written in a previous session but never executed (computer shut down). Run it now.

**Step 1: Verify Docker is available**

```bash
docker info >/dev/null 2>&1 && echo "Docker available" || echo "Docker NOT available"
```

If Docker is NOT available, this is a **HARD BLOCKER**. Stop and report.

**Step 2: Run the test**

```bash
cd <worktree> && go test ./internal/feed/epss/... -run TestApply_GoldenFiles -v -count=1 -timeout=300s
```

Expected: PASS — seeds NVD CVEs via merge pipeline, applies EPSS scores, verifies DB values.

If the test FAILS, debug and fix. Common issues:
- NVD fixture path resolution (`../nvd/testdata/golden/` relative to EPSS package)
- EPSS rate limiter blocking (24h limiter — should succeed on first call)
- Testcontainer startup timeout

**Step 3: If test passes, no commit needed** (test file was already committed by previous session)

If test required fixes, commit the fixes:
```bash
git add internal/feed/epss/golden_test.go
git commit -m "fix: correct EPSS golden test [describe what was fixed]"
```

---

## Phase D: SeedCorpus Integration

### Task 6: Add MSRC to SeedCorpus helper

**Files:**
- Modify: `internal/testutil/seedcorpus.go`

**Depends on:** Tasks 1-2 (fixtures + adapter fix)

The `SeedCorpus` function currently seeds 6 feeds: NVD, MITRE, GHSA, OSV, KEV, Red Hat. MSRC is missing. Add it between KEV and Red Hat (matching source precedence order from PLAN.md §5.1).

**Step 1: Add MSRC import**

Add to the import block:
```go
"github.com/scarson/cvert-ops/internal/feed/msrc"
```

**Step 2: Add MSRC to feeds list**

In the `feeds` slice (around line 58-65), add MSRC between KEV and Red Hat:

```go
feeds := []feedDef{
    {"nvd", "nvd", fetchNVDGolden},
    {"mitre", "mitre", fetchMITREGolden},
    {"ghsa", "ghsa", fetchGHSAGolden},
    {"osv", "osv", fetchOSVGolden},
    {"kev", "kev", fetchKEVGolden},
    {"msrc", "msrc", fetchMSRCGolden},  // ADD THIS LINE
    {"redhat", "redhat", fetchRedHatGolden},
}
```

**Step 3: Add `fetchMSRCGolden` function**

Add this function after `fetchKEVGolden` and before `fetchRedHatGolden`:

```go
func fetchMSRCGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "msrc", "testdata", "golden")

	// Read changes.csv fixture
	changesData, err := os.ReadFile(filepath.Join(goldenDir, "changes.csv"))
	if err != nil {
		t.Fatalf("MSRC changes.csv fixture missing: %v", err)
	}

	// Read all CSAF fixture files into a map
	csafDir := filepath.Join(goldenDir, "csaf")
	csafEntries, err := os.ReadDir(csafDir)
	if err != nil {
		t.Fatalf("MSRC CSAF fixtures missing: %v", err)
	}

	csafByName := make(map[string][]byte)
	for _, e := range csafEntries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(csafDir, e.Name()))
		if readErr != nil {
			t.Fatalf("read MSRC CSAF fixture %s: %v", e.Name(), readErr)
		}
		csafByName[e.Name()] = data
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if strings.HasSuffix(path, "/changes.csv") {
			w.Header().Set("Content-Type", "text/csv")
			w.Write(changesData) //nolint:errcheck
			return
		}

		// Serve CSAF files by filename
		for name, data := range csafByName {
			if strings.HasSuffix(path, "/"+name) {
				w.Write(data) //nolint:errcheck
				return
			}
		}

		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://msrc.microsoft.com", srv.URL, http.DefaultTransport),
	}

	return fetchAllPatches(t, msrc.New(client), nil)
}
```

**Step 4: Run SeedCorpus test**

```bash
cd <worktree> && go test ./internal/testutil/... -run TestSeedCorpus -v -count=1 -timeout=600s
```

Expected: PASS — now seeds 8 feeds (was 7 before, added MSRC). The test asserts `FeedsSeeded == len(requiredFeeds)` where `requiredFeeds` includes "msrc".

Wait — check the existing test's `requiredFeeds` list. If it doesn't already include "msrc", this will fail correctly. If it does include "msrc", the test was already expecting MSRC and was previously failing (or the test counted differently). Read `internal/testutil/seedcorpus_test.go` to verify, and update `requiredFeeds` if needed.

**Step 5: Commit**

```bash
git add internal/testutil/seedcorpus.go
git commit -m "test: add MSRC to SeedCorpus golden fixture helper"
```

**Phase D review loop:** After completing Task 6, run the review loop. Verify: (1) MSRC is positioned correctly in source precedence order; (2) the test server handles both changes.csv and per-CVE CSAF file routes; (3) `fetchMSRCGolden` uses `NewURLRewriteTransport` consistently with other adapters; (4) `SeedCorpus` now reports 8 feeds seeded (not 7).

---

## Phase E: Verification & Documentation

### Task 7: Verify full feed test suite (Task 10H from Phase 10 plan)

**Step 1: Run all feed adapter tests**

```bash
cd <worktree> && go test ./internal/feed/... -v -count=1 -timeout=300s
```

Verify:
1. All golden file tests RUN (not SKIP) for: NVD, KEV, GHSA, MITRE, OSV, Red Hat, MSRC
2. EPSS golden test may skip if Docker is not available (it uses testcontainers) — this is acceptable for feed-only verification
3. All existing inline-JSON tests still pass
4. No compilation errors or import cycles

**Step 2: Verify full-project compilation**

```bash
cd <worktree> && go build ./...
```

Expected: clean build, no errors.

**Step 3: No commit** — this is a verification step.

---

### Task 8: Final verification of changed packages (Task 12 from Phase 10 plan)

```bash
cd <worktree> && go test ./internal/feed/... ./internal/testutil/... -count=1 -timeout=600s
```

Also verify compilation:
```bash
cd <worktree> && go build ./...
```

If EPSS test needs Docker and it's available, also run:
```bash
cd <worktree> && go test ./internal/feed/epss/... -run TestApply_GoldenFiles -v -count=1 -timeout=300s
```

All tests must pass. If any golden file tests skip, go back and fix the missing fixtures.

---

### Task 9: Document the refresh process (Task 13 from Phase 10 plan)

**Files:**
- Modify: `dev/plans/2026-03-15-phase10-test-fixture-corpus-plan.md`

Add a `## Refresh Process` section at the end of the document (before the dependency graph if one exists):

```markdown
## Refresh Process

1. Re-run the capture: `go run ./dev/cmd/capture-feeds/... all`
2. Re-run the selection agent (Task 6 instructions) against new captures
3. Review and commit the updated canonical manifest at `dev/plans/test-fixture-manifest.json`
4. Re-run extraction: `go run ./dev/cmd/extract-fixtures/...`
5. For MSRC: download updated CSAF files from `https://msrc.microsoft.com/csaf/advisories/` and rebuild `changes.csv`
6. Run all adapter tests: `go test ./internal/feed/...`
7. If tests pass, commit the updated manifest and fixtures together
8. If tests fail, investigate — the upstream schema may have changed

**When to refresh:**
- When an adapter test breaks in a way suggesting upstream schema change
- When adding a new edge case category to the matrix
- When adding a new feed adapter

**Adding a new feed adapter:**
1. Add a capture case to `dev/cmd/capture-feeds/main.go`
2. Add extraction logic to `dev/cmd/extract-fixtures/main.go`
3. Add a `golden_test.go` to the new adapter package
4. Re-run capture and extraction to populate fixtures
```

**Commit:**

```bash
git add dev/plans/2026-03-15-phase10-test-fixture-corpus-plan.md
git commit -m "docs: add fixture corpus refresh process documentation"
```

---

## Dependency Graph

```
Task 1 (capture fixtures)  ──┐
                              ├──→ Task 2 (fix adapter) ──→ Task 3 (fix tests) ──→ Task 4 (MSRC golden test)
                              │                                                         │
                              └──────────────────────────────────────────────────→ Task 6 (SeedCorpus)
                                                                                        │
Task 5 (EPSS golden test) ─────────────────────────────────────────────────────────────→ │
                                                                                        ↓
                                                                              Task 7 (verify feed suite)
                                                                                        ↓
                                                                              Task 8 (final verification)
                                                                                        ↓
                                                                              Task 9 (documentation)
```

Tasks 1-4 and Task 5 are independent and can run in parallel. Tasks 7-9 are sequential and depend on all prior tasks.

---

## Execution Notes

- **All work in the worktree** at `.claude/worktrees/phase10-fixture-corpus`
- **Do NOT run `go test ./...`** — Docker container overload. Only run relevant package subsets.
- **MSRC rate limiter:** The adapter uses 1 req/sec. For golden tests with 3-5 fixture files, this adds ~3-5 seconds of delay. Acceptable.
- **EPSS test requires Docker Desktop** — if unavailable, this is a hard blocker for Task 5 only. Other tasks can proceed.
- **Worktree already has dev merged** — SCIM code is present. No further merges needed.

---

## Appendix: Autonomous Decisions

Decisions made without Sam's explicit input during overnight execution. Flagged for review.

### D1: CVE-2026-3909 replacement with CVE-2026-32194

**Context:** The manifest specified 3 MSRC CVEs (CVE-2026-3909, CVE-2026-21510, CVE-2025-14174). CVE-2026-3909 has no CSAF file in Microsoft's CSAF distribution (`index.txt` search returned no match).
**Decision:** Replaced with CVE-2026-32194, a recent (2026-03-19) advisory with full CSAF data including product tree, CVSS scores, and vendor enrichment fields.
**Risk:** Low — the replacement CVE provides equivalent test coverage. The manifest's category coverage (X3: NVD+MSRC overlap) is maintained since CVE-2026-32194 is also a Microsoft CVE.
