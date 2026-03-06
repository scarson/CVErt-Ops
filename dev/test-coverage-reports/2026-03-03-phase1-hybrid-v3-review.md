# Phase 1 Hybrid v3 Test Coverage Review

**Date:** 2026-03-03
**Scope:** `internal/feed/...`, `internal/merge/...`, `internal/worker/...`
**Method:** Hybrid — Go coverage tools (Pass 1) + semantic analysis (Pass 2)
**Overall coverage:** 83.4% (statements)

## §1 Coverage Baseline

| Package | Functions | 100% | 80–99% | 1–79% | 0% |
|---------|-----------|------|--------|-------|----|
| feed/epss | 4 | 2 | 0 | 1 | 1 |
| feed/ghsa | 5 | 3 | 2 | 0 | 0 |
| feed/kev | 5 | 3 | 1 | 1 | 0 |
| feed/mitre | 8 | 4 | 1 | 3 | 0 |
| feed/nvd | 11 | 5 | 4 | 1 | 1 |
| feed/osv | 7 | 4 | 1 | 2 | 0 |
| feed/util | 5 | 5 | 0 | 0 | 0 |
| merge | 22 | 16 | 3 | 2 | 0 |
| worker | 6 | 4 | 1 | 1 | 0 |
| **Total** | **73** | **46** | **13** | **11** | **2** |

### Per-function coverage

```
feed/epss:
  New                 100.0%    Apply               14.3%
  applyRow              0.0%    parseLine1          100.0%

feed/ghsa:
  New                 100.0%    Fetch                85.2%
  fetchPage            86.8%    parseLinkHeader     100.0%
  parseAdvisory       100.0%

feed/kev:
  New                 100.0%    Fetch                80.0%
  parseKEV             72.7%    recordToPatch       100.0%
  extractCWEs         100.0%

feed/mitre:
  New                  66.7%    Fetch                84.8%
  isCVEEntry          100.0%    downloadToTemp       57.1%
  parseEntry           83.3%    parseCVE5           100.0%
  applyCVSS           100.0%    cloneStrings        100.0%

feed/nvd:
  New                   0.0%    Fetch                85.2%
  doRequest            90.0%    parseCursor         100.0%
  zeroValueCursor      83.3%    computeNextCursor   100.0%
  parseNVDResponse     70.6%    cveToCanonical       97.3%
  applyNVDCVSS         96.7%    pickPreferred       100.0%
  cloneStrings        100.0%

feed/osv:
  New                 100.0%    Fetch                81.8%
  isAdvisoryEntry     100.0%    downloadToTemp       57.1%
  parseEntry           83.3%    parseAdvisory       100.0%
  extractPackageRange 100.0%

feed/util:
  ParseTime           100.0%    ParseTimePtr        100.0%
  StripNullBytes      100.0%    StripNullBytesJSON  100.0%
  ResolveCanonicalID  100.0%

merge:
  advisoryKey         100.0%    CVEAdvisoryKey      100.0%
  JoinForFTS          100.0%    ComputeMaterialHash  88.0%
  normalizeCVSSVector 100.0%    Ingest               67.6%
  toNullString        100.0%    toNullStringPtr     100.0%
  toNullFloat64       100.0%    toNullTimePtr       100.0%
  toNullRawMessage    100.0%    derefString         100.0%
  buildAffectedPkgKeys100.0%    buildCPEStrings     100.0%
  collectPackageNames 100.0%    migrateCVEPK         71.4%
  resolve              92.5%    firstStr            100.0%
  firstStrPtr         100.0%    otherSources        100.0%
  computeScoreDiverges100.0%    canonicalizeURL      92.3%

worker:
  New                 100.0%    Register            100.0%
  Start               100.0%    runQueue             87.5%
  processOne          100.0%    runStaleRecovery     53.8%
```

## §2 Triage by Coverage

### Uncovered (0%) — 2 functions

**epss/applyRow** (adapter.go:237, 38 lines) — **Security-critical.** Implements the two-statement EPSS pattern with advisory lock coordination. Security-relevant paths:
1. Advisory lock acquisition (`pg_advisory_xact_lock`) preventing TOCTOU races with merge pipeline
2. Statement 1: `UPDATE cves SET epss_score ... WHERE epss_score IS DISTINCT FROM` — must not update `date_modified_canonical`
3. Statement 2: `INSERT INTO epss_staging` for CVEs not yet in the `cves` table
4. Null-byte stripping on CVE IDs before DB write
5. Error propagation from each DB statement

The entire `apply_integration_test.go` file contains only `t.Skip` TODO stubs — no real integration tests exist.

**nvd/New** (adapter.go:72, 24 lines) — **Nice-to-have.** Constructor reads `NVD_API_KEY` env var to select rate limit (5 req/30s with key, 5 req/30s without). All NVD tests bypass `New()` and construct adapters directly with struct literals.

### Partially covered (1–79%) — 11 functions

**epss/Apply** (14.3%, adapter.go:106, 131 lines) — **Security-critical.** Only the same-day cursor short-circuit (lines 121-128) is tested. Untested paths:
- HTTP download of CSV feed
- Line-by-line CSV parsing loop
- Per-row `applyRow` calls within transaction
- Cursor update on completion
- Error handling for HTTP, parse, and DB failures
- Rate limiter `Wait()` integration

**worker/runStaleRecovery** (53.8%, pool.go:154, 24 lines) — **Correctness.** Tests cover cancellation and error-continues, but not the actual recovery tick execution path. The `n > 0` log branch (successful recovery of stale jobs) is never hit.

**mitre/downloadToTemp** (57.1%, adapter.go:154, 38 lines) — **Correctness.** Untested error cleanup paths:
- `io.Copy` failure → temp file should still be cleaned up
- `f.Seek(0, io.SeekStart)` failure after successful copy
- Only the happy path (successful download + seek) is exercised

**osv/downloadToTemp** (57.1%, adapter.go:143, 38 lines) — **Correctness.** Same pattern and same gaps as `mitre/downloadToTemp`.

**mitre/New** (66.7%, adapter.go:50, 21 lines) — **Nice-to-have.** The `client != nil` branch is untested — tests always pass `nil` and get `http.DefaultClient`.

**merge/Ingest** (67.6%, pipeline.go:35, 231 lines) — **Correctness.** Despite 67.6% line coverage, this function has thorough integration tests (14 test scenarios). Untested paths are mostly individual error-return branches within the 10-step pipeline:
- Advisory lock acquisition failure
- Individual child-table upsert failures (affected_packages, cpes, references, weaknesses)
- FTS index update failure
- Some early-return error paths after partial pipeline completion

**nvd/parseNVDResponse** (70.6%, adapter.go:344, 73 lines) — **Correctness.** Streaming JSON parser. Untested branches:
- Non-string key discard (lines ~360-365) — `json.Decoder.Token()` returns non-string key type
- Some navigation error paths in the `Token()`/`More()` loop

**merge/migrateCVEPK** (71.4%, pipeline.go:352, 29 lines) — **Correctness.** Migrates child tables (sources, affected_packages, cpes, references, weaknesses, epss_staging, search_index) when PK changes. Individual table migration error paths untested — only the happy path and first-table-failure are exercised.

**kev/parseKEV** (72.7%, adapter.go:144, 107 lines) — **Correctness.** Streaming JSON parser. Untested branches:
- Non-string key discard branch (lines 178-184)
- Some `Token()` error paths in the streaming navigation

**mitre/parseEntry** (83.3%, adapter.go:192, 88 lines) — **Correctness.** Untested: error path from `entry.Open()` failure on a ZIP entry.

**osv/parseEntry** (83.3%, adapter.go:181, 63 lines) — **Correctness.** Untested: error path from `entry.Open()` failure on a tar.gz entry.

### Well-covered (80–99%) — 13 functions

**ghsa/Fetch** (85.2%), **ghsa/fetchPage** (86.8%) — Untested: some pagination edge cases and HTTP error paths in multi-page fetches.

**kev/Fetch** (80.0%) — Untested: HTTP error paths, short-circuit when no new entries.

**mitre/Fetch** (84.8%) — Untested: some error paths in ZIP download/extraction flow.

**nvd/Fetch** (85.2%) — Untested: some retry/error paths in paginated API calls.

**nvd/doRequest** (90.0%) — Untested: likely a specific HTTP error or retry path.

**nvd/zeroValueCursor** (83.3%) — Untested: one branch in cursor zero-value detection.

**osv/Fetch** (81.8%) — Untested: some error paths in tar.gz download/extraction.

**merge/ComputeMaterialHash** (88.0%) — Untested: likely a nil-input or empty-fields edge case.

**merge/resolve** (92.5%) — Untested: ~2-3 branches in the multi-source field resolution logic. Likely edge cases in per-field priority selection.

**merge/canonicalizeURL** (92.3%) — Untested: URL parse error fallback (returns raw URL string when `url.Parse` fails).

**nvd/cveToCanonical** (97.3%) — Untested: one or two very specific edge cases in NVD-to-canonical CVE conversion.

**nvd/applyNVDCVSS** (96.7%) — Untested: likely a nil-metric or missing-version edge case in CVSS extraction.

**worker/runQueue** (87.5%) — Untested: likely the `processOne` call during an actual ticker tick (as opposed to the channel-select path).

### Fully covered (100%) — 46 functions

All 46 functions at 100% coverage. Security-relevant functions audited for assertion quality in §5.

## §3 Data Pipeline Security Matrix

This scope has no org-scoped API endpoints. The security checklist matrix is adapted for data pipeline safety properties that are security-relevant in a vulnerability intelligence system.

**Pipeline operations enumerated:**
1. EPSS Apply — download + parse + two-statement write
2. NVD Fetch — paginated API + streaming parse + merge ingest
3. KEV Fetch — streaming JSON parse + merge ingest
4. MITRE Fetch — ZIP download + temp file + parse + merge ingest
5. OSV Fetch — tar.gz download + temp file + parse + merge ingest
6. GHSA Fetch — paginated GraphQL + parse + merge ingest
7. Merge Ingest — advisory lock + resolve + upsert + child tables + FTS
8. Worker processOne — job claiming + handler dispatch

**Columns:**
1. **Advisory lock** — CVE-level advisory lock prevents TOCTOU races between concurrent writers
2. **Null-byte strip** — `\x00` stripped from all string values before DB write (Postgres rejects)
3. **Streaming parse** — Large responses use `json.Decoder` Token/More loop (not `Decode(&slice)`)
4. **Temp file cleanup** — Temp files cleaned up on both success and error paths
5. **Cursor safety** — Cursor only advances after successful processing (not before)
6. **Error propagation** — Errors propagated correctly (not swallowed), partial work rolled back
7. **Rate limiting** — Upstream rate limits respected via per-adapter limiter

| Pipeline Op | Advisory lock | Null-byte strip | Streaming parse | Temp file cleanup | Cursor safety | Error propagation | Rate limiting |
|-------------|---------------|-----------------|-----------------|-------------------|---------------|-------------------|---------------|
| EPSS Apply | GAP (applyRow 0%, lock code untested) | Tested (TestNullByteStripping) | N/A (CSV line-by-line) | N/A (no temp files) | GAP (Apply 14.3%, cursor update path untested) | GAP (Apply 14.3%, error paths untested) | Tested (TestAdapterRateLimiterNonNil) |
| NVD Fetch | Tested (TestIngest_AdvisoryLockAcquired, via merge) | Tested (TestCveToCanonical_NullByteStripping) | Tested (TestParseNVDResponse) | N/A (no temp files) | Tested (TestFetch_* integration tests) | Tested (TestFetch_* integration tests) | Tested (adapter constructor) |
| KEV Fetch | Tested (via merge) | Tested (TestRecordToPatch_NullByteStripping) | Tested (TestParseKEV_*) | N/A (no temp files) | Tested (TestFetch_* integration tests) | Tested (TestFetch_* integration tests) | Tested (adapter constructor) |
| MITRE Fetch | Tested (via merge) | Tested (TestParseCVE5_NullByteStripping) | N/A (ZIP, not streaming JSON) | GAP (downloadToTemp error cleanup 57.1%) | Tested (TestFetch_* integration tests) | GAP (downloadToTemp error paths 57.1%) | Tested (adapter constructor) |
| OSV Fetch | Tested (via merge) | Tested (TestParseAdvisory null bytes stripped) | N/A (tar.gz, not streaming JSON) | GAP (downloadToTemp error cleanup 57.1%) | Tested (TestFetch_* integration tests) | GAP (downloadToTemp error paths 57.1%) | Tested (adapter constructor) |
| GHSA Fetch | Tested (via merge) | Tested (TestParseAdvisory_NullByteStripping) | Tested (fetchPage uses json.Decoder) | N/A (no temp files) | Tested (TestFetch_* pagination tests) | Tested (TestFetch_* integration tests) | Tested (adapter constructor) |
| Merge Ingest | Tested (TestIngest_AdvisoryLockAcquired) | Tested (pipeline.go:48 null-byte strip) | N/A (receives parsed patches) | N/A (no temp files) | N/A (not cursor-based) | Tested (TestIngest_* 14 integration tests) | N/A (internal pipeline) |
| Worker processOne | N/A (no CVE-level lock) | N/A (delegates to handlers) | N/A (job queue) | N/A (no temp files) | Tested (TestProcessOne_* claim-before-dispatch) | Tested (TestProcessOne_* 7 scenarios) | N/A (internal scheduler) |

**Summary:** 4 GAP cells, all security-critical:
1. EPSS advisory lock coordination — untested (applyRow at 0%)
2. EPSS cursor safety — untested (Apply at 14.3%)
3. MITRE/OSV temp file error cleanup — untested (downloadToTemp at 57.1%)
4. EPSS error propagation — untested (Apply at 14.3%)

**Spot-check verification:** Verified 3 "Tested" cells:
1. NVD Null-byte strip → `TestCveToCanonical_NullByteStripping` (adapter_test.go:670) — confirms null bytes in CVE ID, status, description, CWE, references, CPEs are all stripped. Verified.
2. Merge Advisory lock → `TestIngest_AdvisoryLockAcquired` (pipeline_integration_test.go:545) — verifies pg_locks contains the advisory lock during Ingest execution. Verified.
3. KEV Streaming parse → `TestParseKEV_*` (adapter_test.go) — tests exercise the json.Decoder Token/More loop with various catalog shapes. Verified.

## §4 Semantic Code Analysis

### A. Cross-Handler Consistency

**Pattern: Fetch → parse → return patches + cursor**

All 6 feed adapters follow the same Fetch pattern:
1. Unmarshal cursor
2. Rate limiter Wait
3. HTTP request (or temp file download)
4. Parse response into `[]feed.CanonicalPatch`
5. Marshal new cursor
6. Return `FetchResult{Patches, SourceMeta, NextCursor}`

**Consistency check across all 6 adapters:**

| Adapter | Rate limiter | User-Agent header | Null-byte strip | Cursor on success only | Error wrapping |
|---------|-------------|-------------------|-----------------|----------------------|----------------|
| EPSS | Yes (Wait) | Yes | Yes (cve ID) | GAP (untested) | Yes |
| NVD | Yes (Wait) | Yes | Yes (all fields) | Yes | Yes |
| KEV | Yes (Wait) | Yes | Yes (all fields) | Yes | Yes |
| MITRE | Yes (Wait) | Yes (via downloadToTemp) | Yes (all fields) | Yes | Yes |
| OSV | Yes (Wait) | N/A (downloadToTemp) | Yes (all fields) | Yes | Yes |
| GHSA | Yes (Wait per page) | Yes | Yes (all fields) | Yes | Yes |

**Finding:** OSV's `downloadToTemp` does NOT set a User-Agent header. All other adapters do. This is a cross-handler consistency gap — OSV requests arrive without identification.

Let me verify: Reading `osv/adapter.go` downloadToTemp (line 143-177) — the HTTP request at line 144-147 uses `http.NewRequestWithContext` but sets no `User-Agent` header. Contrast with KEV (line 80), NVD (line 176-177), GHSA (line 165-166) which all set `"CVErt-Ops/1.0 vulnerability intelligence platform"`. MITRE's downloadToTemp (line 154-158) also does NOT set User-Agent.

**Revised finding:** Both OSV and MITRE `downloadToTemp` functions lack User-Agent headers. This is a consistency gap across 2 of 6 adapters.

**Pattern: Null-byte stripping on all string fields**

All 6 adapter parse functions call `feed.StripNullBytes()` on every string field extracted from upstream data. Verified by grep — every adapter has comprehensive null-byte stripping. Additionally, `merge/pipeline.go` strips null bytes from both `normalizedJSON` and `rawPayload` before DB insertion (lines 48-51). No consistency gaps here.

**Pattern: Advisory lock coordination (EPSS + merge)**

Both `epss/applyRow` and `merge/Ingest` use `merge.CVEAdvisoryKey(cveID)` for their advisory lock key. Same function, same domain prefix ("cve"). No right-function-called bug. However, the EPSS side is untested (applyRow at 0%).

### B. Right-Function-Called

**merge/Ingest Step 9 — EPSS staging drain:**
- Line 230: calls `q.GetEPSSStaging(ctx, patch.CVEID)` — correct function for reading staging
- Line 237: calls `q.UpdateCVEEPSS(ctx, ...)` — correct function for applying score to cves table
- Line 245: calls `q.DeleteEPSSStaging(ctx, patch.CVEID)` — correct function for draining staging
- All three are the right functions. No bug.

**epss/applyRow — two-statement pattern:**
- Line 247: `merge.CVEAdvisoryKey(cveID)` — correct lock key function
- Line 255: `q.UpdateCVEEPSS(ctx, ...)` — correct function (same sqlc query as Ingest Step 9)
- Line 265: `q.UpsertEPSSStaging(ctx, ...)` — correct function for staging insertion
- No right-function-called bug.

**merge/resolve — field precedence:**
- `statusPriority` used for Status and Description — correct (MITRE > NVD > OSV > GHSA)
- `cvssPriority` used for CVSSv3 and CVSSv4 — correct (NVD > OSV > GHSA > MITRE)
- Severity falls back from `cvssPriority` to `statusPriority` — correct behavior per PLAN.md
- No right-function-called bug.

### C. TOCTOU Windows

**EPSS Apply → applyRow TOCTOU (CRITICAL — untested):**
The entire purpose of the advisory lock in `applyRow` is to prevent a TOCTOU race: merge/Ingest could insert a new CVE between Statement 1 (UPDATE cves) and Statement 2 (INSERT epss_staging). The advisory lock serializes these — but this coordination is at 0% coverage. If the lock key diverged (different function or domain), the protection would silently fail. **The code is correct but the test gap means regressions would be undetected.**

**merge/Ingest PK migration TOCTOU:**
Between `FindCVEBySourceID` (line 73) and `migrateCVEPK` (line 81), the advisory lock is already held (acquired at line 61), so no concurrent writer can interfere. No TOCTOU window.

**MITRE/OSV incremental cursor:**
Cursor is set to `fetchedAt := time.Now().UTC()` (mitre:101, osv:100) *before* processing entries. If processing takes long, entries modified between fetchedAt and actual completion could be missed on the next run. However, the `entry.Modified.After(cur.LastModified)` filter uses the ZIP's embedded timestamps, not the server clock, so this is a bounded window. Acceptable design — not a bug.

### D. Defense-in-Depth

**EPSS applyRow — no caller pre-check:**
`Apply` does not pre-check whether a CVE exists before calling `applyRow`. Instead, `applyRow` relies on the DB-side guards: `IS DISTINCT FROM` for existing CVEs, `WHERE NOT EXISTS` for staging. Both statements are unconditional. This is correct defense-in-depth — the DB layer is safe regardless of caller behavior.

**merge/Ingest — no pre-check on CVE existence:**
Ingest uses `ON CONFLICT (cve_id) DO UPDATE` for the cves upsert (Step 6). The advisory lock (Step 1) prevents concurrent inserts from creating a race. No pre-check needed — the SQL is safe independently. Correct.

**Worker processOne — handler lookup guard:**
`processOne` checks `h == nil` after acquiring the read lock (line 127). If a queue has no registered handler, it logs an error and returns. The job remains claimed but not completed — it will eventually hit stale recovery. This is a reasonable fail-open-to-stale rather than fail-to-crash design.

### E. Store-Layer Independence

**merge/Ingest's child table delete+re-insert:**
Steps 8 (delete + re-insert references, packages, CPEs) always runs within the advisory-locked transaction. The DELETE is not guarded by "if len(resolved.References) > 0" — it always runs, even if the resolved result has zero references. This is correct: a CVE that had references in a previous source but lost them in an update should have its references removed. The store layer is safe independently of caller pre-checks.

**EPSS UpdateCVEEPSS — IS DISTINCT FROM guard:**
The sqlc query uses `WHERE epss_score IS DISTINCT FROM $1`. This is DB-side safety — even if called redundantly, it won't create dead tuples. Correct store-layer independence.

## §5 Assertion Quality Audit

### Security-relevant 100% functions

**merge/advisoryKey + CVEAdvisoryKey (100%)** — advisory_test.go
- Tests verify: determinism, uniqueness across different IDs, domain prefix isolation, CVEAdvisoryKey delegates correctly to advisoryKey
- Assertions check actual key values and equality/inequality — not execution-only
- **Quality: GOOD.** Tests verify behavioral correctness, not just "runs without error."

**merge/ComputeMaterialHash (88%) + normalizeCVSSVector (100%)** — hash_test.go
- 15 tests covering: determinism, field sensitivity (status, severity, CVSS scores, exploit_available, in_cisa_kev), CWE order independence, CPE order independence, affected package order independence, CVSS vector normalization, nil-vs-zero score differentiation, affected package content sensitivity, sort tiebreak correctness
- Assertions verify hash equality/inequality, idempotence, prefix preservation
- **Quality: EXCELLENT.** Comprehensive property-based testing. No anti-patterns.

**feed/util (all 5 functions at 100%)** — util_test.go
- ParseTime: tests canonical RFC3339, date-only, Unix epoch, empty string, "n/a"
- ParseTimePtr: tests nil and valid input
- StripNullBytes: tests removal, no-op on clean string
- StripNullBytesJSON: tests null byte removal
- ResolveCanonicalID: tests CVE-prefixed IDs, non-CVE IDs, alias arrays
- **Quality: GOOD.** All functions have behavior-verifying assertions.

**merge/resolve (92.5%)** — resolve_test.go
- Extensive unit tests for per-field source precedence (MITRE > NVD for status, NVD > MITRE for CVSS)
- Tests verify correct winner selection, fallback behavior, union merging, CVSS score divergence detection
- **Quality: GOOD.** Tests verify the right source wins — not just that a value is non-empty.

**worker/processOne (100%)** — pool_test.go
- 7 test scenarios: nil job (no handler call), claim error (logs but no panic), handler success (CompleteJob called with correct ID), handler failure (FailJob called with correct error message), nil handler (logs error for orphan queue), FailJob error (both errors logged), CompleteJob error (logs but no panic)
- **Quality: GOOD.** Tests verify side effects (which store method called, with what arguments), not just "err == nil." No conditional assertions.

### Adapter parse function assertion quality

**All 6 adapter parseAdvisory/parseCVE5/recordToPatch functions (100%):**
- Each has a dedicated null-byte stripping test that verifies every output field is clean
- Tests check: CVE ID extraction, description text, CWE IDs, references, affected packages, severity, CVSS vectors
- **Quality: GOOD across all adapters.** Assertions check specific field values, not just struct non-nil.

### Assertion quality issues found

**worker/TestProcessOne_NilHandler** — pool_test.go:376-388
- This test claims a job from a queue with no registered handler. It verifies "does not panic" but does NOT verify that the job remains in a claimable state (it's stuck as "running" until stale recovery). The test doesn't assert that CompleteJob is NOT called — it relies on the absence of a `completeFn` in the fakeJobStore. This is a weak negative assertion, but acceptable for a pool unit test.

**worker/TestRunStaleRecovery_CallsRecoverAndStops** — pool_test.go:435+
- Tests cancellation path only. Does not verify that `RecoverStaleJobs` is actually called on a tick. The `n > 0` log branch is never hit in tests. This is more of a coverage gap (§2) than an assertion quality issue.

**merge/TestIngest_* integration tests** — pipeline_integration_test.go
- All 14 integration tests use `testutil.NewTestDB(t)` with real Postgres and verify DB state after Ingest. No conditional assertions. No execution-only tests. Each test checks specific DB rows and field values.
- **Quality: EXCELLENT.** Real database, real assertions, no mocks.

**EPSS tests** — adapter_test.go
- `TestApply_SameDayCursorSkips` (line 142-169): Tests the short-circuit path by passing `nil` as the store. Verifies cursor is returned unchanged. This is correct for testing the short-circuit, but means the nil-store path artificially limits what can be tested without integration infrastructure.
- **Quality: ACCEPTABLE for unit tests.** The real gap is the missing integration tests (apply_integration_test.go is all stubs).

## §6 Gap Context

| Category | Files | Gaps | Action |
|----------|-------|------|--------|
| Uncovered (0%) | 2 | 7 | Create test cases (1 security-critical, 1 nice-to-have) |
| Partial coverage (1–79%) | 9 | 17 | Add specific test cases for uncovered branches |
| Well covered (80–99%) | 13 | 13 | Add edge case tests for specific uncovered branches |
| Security matrix GAPs | 3 | 4 | Add advisory lock, cursor safety, temp file cleanup tests |
| Assertion quality | 1 | 1 | Strengthen weak negative assertion |
| Semantic analysis | 2 | 2 | Add User-Agent headers to OSV/MITRE downloadToTemp |
| **Total** | | **44** | |

## What's Well-Covered

- **Merge pipeline (22 functions):** 16 at 100%, strongest coverage in scope. 14 integration tests with real Postgres verify complete pipeline behavior including material hash determinism, multi-source resolution, PK migration, advisory locking, concurrent writes, and FTS indexing.
- **Adapter parse functions:** All 6 adapters have comprehensive null-byte stripping tests, field extraction tests, and integration-level Fetch tests. Streaming JSON parsing (KEV, NVD, GHSA) is well-tested with synthetic HTTP responses.
- **Hash and advisory key infrastructure:** ComputeMaterialHash has 15 property-based tests; advisoryKey has determinism, uniqueness, and domain isolation tests. These are foundational security primitives and they're solid.

## Production Bugs Discovered

- **Cross-handler consistency: Missing User-Agent header in OSV and MITRE `downloadToTemp`.** All other adapters set `"CVErt-Ops/1.0 vulnerability intelligence platform"`. OSV and MITRE download large bulk archives without identifying themselves. Not a security bug, but a data pipeline hygiene issue — upstream operators can't distinguish CVErt from scrapers. Source: semantic analysis §4A.

## Security-Critical Gaps (8)

1. EPSS `applyRow` advisory lock acquisition untested — adapter.go:247 — source: coverage + matrix
2. EPSS `applyRow` Statement 1 (UPDATE cves SET epss_score) untested — adapter.go:255 — source: coverage
3. EPSS `applyRow` Statement 2 (INSERT epss_staging) untested — adapter.go:265 — source: coverage
4. EPSS `applyRow` IS DISTINCT FROM guard untested — adapter.go:255 — source: coverage
5. EPSS `Apply` HTTP download + parse pipeline untested — adapter.go:125-220 — source: coverage
6. EPSS `Apply` cursor update on success untested — adapter.go:222-227 — source: matrix
7. EPSS `Apply` error propagation from HTTP/parse/DB untested — adapter.go:125-220 — source: matrix
8. EPSS advisory lock coordination with merge pipeline untested end-to-end — adapter.go:247, pipeline.go:61 — source: semantic

## Correctness Gaps (19)

1. mitre/downloadToTemp io.Copy failure cleanup — adapter.go:175-178 — source: coverage
2. mitre/downloadToTemp Seek failure cleanup — adapter.go:182-185 — source: coverage
3. osv/downloadToTemp io.Copy failure cleanup — adapter.go:166-168 — source: coverage
4. osv/downloadToTemp Seek failure cleanup — adapter.go:173-175 — source: coverage
5. kev/parseKEV non-string key discard branch — adapter.go:178-184 — source: coverage
6. nvd/parseNVDResponse non-string key discard branch — adapter.go:~360-365 — source: coverage
7. mitre/parseEntry entry.Open() failure — adapter.go:193 — source: coverage
8. osv/parseEntry entry.Open() failure — adapter.go:183 — source: coverage
9. merge/Ingest advisory lock acquisition failure — pipeline.go:61 — source: coverage
10. merge/Ingest delete references failure — pipeline.go:176 — source: coverage
11. merge/Ingest insert reference failure — pipeline.go:184 — source: coverage
12. merge/Ingest delete affected packages failure — pipeline.go:195 — source: coverage
13. merge/Ingest insert affected package failure — pipeline.go:199 — source: coverage
14. merge/Ingest delete affected CPEs failure — pipeline.go:215 — source: coverage
15. merge/Ingest insert affected CPE failure — pipeline.go:219 — source: coverage
16. merge/Ingest FTS index update failure — pipeline.go:252 — source: coverage
17. merge/migrateCVEPK individual table migration error paths — pipeline.go:352-380 — source: coverage
18. worker/runStaleRecovery actual tick execution path — pool.go:166-174 — source: coverage
19. OSV/MITRE downloadToTemp missing User-Agent header — osv/adapter.go:144, mitre/adapter.go:154 — source: semantic

## Nice-to-Have (17 total, top 5 shown)

1. nvd/New constructor at 0% (24 lines) — adapter.go:72 — source: coverage
2. mitre/New nil client fallback branch — adapter.go:50 — source: coverage
3. ghsa/Fetch pagination edge cases — adapter.go:92 — source: coverage
4. kev/Fetch HTTP error paths — adapter.go:64 — source: coverage
5. nvd/doRequest specific error/retry path — adapter.go:160 — source: coverage

(Plus 12 more: remaining Fetch error paths across ghsa, mitre, nvd, osv adapters; nvd/zeroValueCursor one branch; merge/ComputeMaterialHash nil-input edge; merge/canonicalizeURL parse-error fallback; worker/runQueue tick execution path)

## Assertion Quality Issues (1)

1. worker/TestProcessOne_NilHandler — pool_test.go:376-388 — weak negative assertion: does not verify CompleteFn is NOT called, relies on absence of completeFn in fakeJobStore. Should explicitly set completeFn to `t.Fatal("should not complete")`.

## §7 Key Observations

### Cross-Cutting Patterns

**EPSS Apply is a coverage desert.** The entire EPSS write path — `Apply` (14.3%) and `applyRow` (0%) — accounts for 8 of the 8 security-critical gaps. The `apply_integration_test.go` file contains only `t.Skip` TODO stubs. This is the single most impactful area for test investment. The EPSS two-statement pattern with advisory locking is a correctness-critical mechanism that prevents data corruption from concurrent EPSS + merge writes — and it's completely unverified.

**downloadToTemp error cleanup is a systematic gap.** Both mitre and osv share identical `downloadToTemp` implementations with identical untested error paths (io.Copy failure, Seek failure). The pattern is duplicated — fixing one adapter's tests could be extracted into a shared test helper.

**Streaming JSON non-string key discard is a systematic gap.** Both KEV and NVD streaming parsers have untested branches for discarding non-string JSON keys. These are defensive paths that handle malformed upstream data — low severity but consistent across parsers.

**Merge pipeline error paths are numerous but low-individual-risk.** The 8 merge/Ingest correctness gaps are all individual error-return branches within the 10-step pipeline. Each is a single `if err != nil { return }` after a child-table operation. Testing each individually would improve coverage but the integration tests already verify the happy path thoroughly. Priority: below EPSS gaps.

**Assertion quality is strong across the scope.** No conditional assertions found. No execution-only tests. No garbage-input anti-patterns. The merge integration tests are particularly strong — real Postgres, real assertions, no mocks. The only quality issue is a weak negative assertion in worker/processOne.

### Coverage ≠ Confidence Mismatches

The merge package has 67.6% Ingest coverage but HIGH confidence due to 14 thorough integration tests. The EPSS package has higher average coverage (parseLine1 at 100%, New at 100%) but VERY LOW confidence because the core business logic (Apply + applyRow) is essentially untested.

### TOCTOU Windows

One TOCTOU window exists (EPSS Apply ↔ merge Ingest) and the code handles it correctly via advisory lock coordination. However, the advisory lock coordination is at 0% coverage — a regression in the lock key function or domain prefix would silently break the TOCTOU protection.
