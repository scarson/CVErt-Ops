# Phase 1 Test Coverage Review — Hybrid v4 (Run N1)

**Date:** 2026-03-03
**Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`
**Method:** Hybrid v4 — coverage-guided triage + semantic analysis
**Overall coverage:** 83.4%

## §1 Coverage Baseline

| Package | Functions | Uncovered (0%) | Partial (1-79%) | Well-covered (80-99%) | Full (100%) |
|---------|-----------|----------------|------------------|-----------------------|-------------|
| feed/epss | 4 | 1 | 1 | 0 | 2 |
| feed/ghsa | 5 | 0 | 0 | 2 | 3 |
| feed/kev | 5 | 0 | 1 | 1 | 3 |
| feed/mitre | 8 | 0 | 2 | 2 | 4 |
| feed/nvd | 11 | 1 | 1 | 5 | 4 |
| feed/osv | 7 | 0 | 1 | 2 | 4 |
| feed (util) | 5 | 0 | 0 | 0 | 5 |
| merge | 22 | 0 | 2 | 3 | 17 |
| worker | 6 | 0 | 1 | 1 | 4 |
| **Total** | **73** | **2** | **9** | **16** | **46** |

### Per-function coverage

| # | Function | Coverage | Category |
|---|----------|----------|----------|
| 1 | epss.New | 100.0% | full |
| 2 | epss.Apply | 14.3% | partial |
| 3 | epss.applyRow | 0.0% | uncovered |
| 4 | epss.parseLine1 | 100.0% | full |
| 5 | ghsa.New | 100.0% | full |
| 6 | ghsa.Fetch | 85.2% | well-covered |
| 7 | ghsa.fetchPage | 86.8% | well-covered |
| 8 | ghsa.parseLinkHeader | 100.0% | full |
| 9 | ghsa.parseAdvisory | 100.0% | full |
| 10 | kev.New | 100.0% | full |
| 11 | kev.Fetch | 80.0% | well-covered |
| 12 | kev.parseKEV | 72.7% | partial |
| 13 | kev.recordToPatch | 100.0% | full |
| 14 | kev.extractCWEs | 100.0% | full |
| 15 | mitre.New | 66.7% | partial |
| 16 | mitre.Fetch | 84.8% | well-covered |
| 17 | mitre.isCVEEntry | 100.0% | full |
| 18 | mitre.downloadToTemp | 57.1% | partial |
| 19 | mitre.parseEntry | 83.3% | well-covered |
| 20 | mitre.parseCVE5 | 100.0% | full |
| 21 | mitre.applyCVSS | 100.0% | full |
| 22 | mitre.cloneStrings | 100.0% | full |
| 23 | nvd.New | 0.0% | uncovered |
| 24 | nvd.Fetch | 85.2% | well-covered |
| 25 | nvd.doRequest | 90.0% | well-covered |
| 26 | nvd.parseCursor | 100.0% | full |
| 27 | nvd.zeroValueCursor | 83.3% | well-covered |
| 28 | nvd.computeNextCursor | 100.0% | full |
| 29 | nvd.parseNVDResponse | 70.6% | partial |
| 30 | nvd.cveToCanonical | 97.3% | well-covered |
| 31 | nvd.applyNVDCVSS | 96.7% | well-covered |
| 32 | nvd.pickPreferred | 100.0% | full |
| 33 | nvd.cloneStrings | 100.0% | full |
| 34 | osv.New | 100.0% | full |
| 35 | osv.Fetch | 81.8% | well-covered |
| 36 | osv.isAdvisoryEntry | 100.0% | full |
| 37 | osv.downloadToTemp | 57.1% | partial |
| 38 | osv.parseEntry | 83.3% | well-covered |
| 39 | osv.parseAdvisory | 100.0% | full |
| 40 | osv.extractPackageRange | 100.0% | full |
| 41 | feed.ParseTime | 100.0% | full |
| 42 | feed.ParseTimePtr | 100.0% | full |
| 43 | feed.StripNullBytes | 100.0% | full |
| 44 | feed.StripNullBytesJSON | 100.0% | full |
| 45 | feed.ResolveCanonicalID | 100.0% | full |
| 46 | merge.advisoryKey | 100.0% | full |
| 47 | merge.CVEAdvisoryKey | 100.0% | full |
| 48 | merge.JoinForFTS | 100.0% | full |
| 49 | merge.ComputeMaterialHash | 88.0% | well-covered |
| 50 | merge.normalizeCVSSVector | 100.0% | full |
| 51 | merge.Ingest | 67.6% | partial |
| 52 | merge.toNullString | 100.0% | full |
| 53 | merge.toNullStringPtr | 100.0% | full |
| 54 | merge.toNullFloat64 | 100.0% | full |
| 55 | merge.toNullTimePtr | 100.0% | full |
| 56 | merge.toNullRawMessage | 100.0% | full |
| 57 | merge.derefString | 100.0% | full |
| 58 | merge.buildAffectedPkgKeys | 100.0% | full |
| 59 | merge.buildCPEStrings | 100.0% | full |
| 60 | merge.collectPackageNames | 100.0% | full |
| 61 | merge.migrateCVEPK | 71.4% | partial |
| 62 | merge.resolve | 92.5% | well-covered |
| 63 | merge.firstStr | 100.0% | full |
| 64 | merge.firstStrPtr | 100.0% | full |
| 65 | merge.otherSources | 100.0% | full |
| 66 | merge.computeScoreDiverges | 100.0% | full |
| 67 | merge.canonicalizeURL | 92.3% | well-covered |
| 68 | worker.New | 100.0% | full |
| 69 | worker.Register | 100.0% | full |
| 70 | worker.Start | 100.0% | full |
| 71 | worker.runQueue | 87.5% | well-covered |
| 72 | worker.processOne | 100.0% | full |
| 73 | worker.runStaleRecovery | 53.8% | partial |

## §2 Coverage-Guided Triage

### Uncovered (0%) — 2 functions

**epss.applyRow** (37 lines) — **security-critical.** Core per-CVE EPSS write logic: acquires advisory lock via `CVEAdvisoryKey`, executes two-statement pattern (UPDATE `cves` if exists + INSERT `epss_staging` if not). Security-relevant paths:
- Advisory lock acquisition (coordinates with merge pipeline — must use same FNV hash)
- UPDATE with `IS DISTINCT FROM` guard (prevents dead tuples on unchanged scores)
- INSERT into `epss_staging` for CVEs not yet in `cves` table
- Null-byte stripping on CVE ID before DB write
- Error propagation from each DB statement

The only test file is `apply_integration_test.go` — **all 3 test functions are `t.Skip("TODO")` stubs.** Zero actual test coverage exists for the EPSS write path.

**nvd.New** (18 lines) — **correctness.** Constructor reads `NVD_API_KEY` env var, sets conditional rate limiter (50/30s with key, 5/30s without). Tests construct the adapter directly (`&Adapter{...}`) bypassing `New()`, so the env-var path and default-client path are untested.

### Partial coverage (1–79%) — 9 functions

**epss.Apply (14.3%)** — Only the same-day cursor skip path is tested (lines 106–120). The entire download/parse/apply flow is untested: HTTP request, CSV parsing, line-by-line iteration calling `applyRow`, cursor advancement, rate limiter wait. ~120 lines of untested code. **Security-critical** (drives applyRow).

**mitre.New (66.7%)** — Uncovered: nil-client fallback to `http.DefaultClient`. Nice-to-have.

**mitre.downloadToTemp (57.1%)** — Uncovered error paths: HTTP non-200 response, `io.Copy` failure, `f.Seek(0, 0)` failure. Tests use `buildMITREZip` helper which serves valid ZIP data — no tests exercise the error returns. Correctness level — temp file cleanup on error is the main concern.

**osv.downloadToTemp (57.1%)** — Structurally identical to mitre.downloadToTemp. Same uncovered error paths. Correctness level.

**kev.parseKEV (72.7%)** — Streaming JSON parser. Uncovered: the error branch when `json.Decoder.Token()` fails on opening `{` or a malformed top-level key. Tests cover full catalog parse, short-circuit, empty, and unknown keys, but not a structurally broken JSON stream mid-parse. Correctness level.

**nvd.parseNVDResponse (70.6%)** — Streaming JSON parser. Uncovered: error from `json.Decoder.Token()` for top-level structure, and the `skipUnknownValue` path for nested unknown objects. Tests cover valid responses, empty arrays, missing vulnerabilities key, empty body, unknown keys, and malformed records. The remaining uncovered paths are structural JSON errors. Correctness level.

**merge.Ingest (67.6%)** — Integration tests are comprehensive (14 test functions covering tombstone, PK migration, EPSS staging, concurrent writes, child tables, FTS, raw payload, multi-source resolution). Uncovered paths:
- `json.Marshal(patch)` error (line 44) — extremely unlikely
- `q.GetAllCVESources` error (line 113) — DB error propagation
- Some individual child-table insert errors within loops (references, packages, CPEs)
Correctness level for the uncovered error-wrapping paths.

**merge.migrateCVEPK (71.4%)** — Integration test covers the happy path (old ID → new ID migration across all tables). Uncovered: individual UPDATE error paths within the loop (7 update statements). Correctness level.

**worker.runStaleRecovery (53.8%)** — Tests cover context cancellation and error-continues. Uncovered: the successful recovery path where `RecoverStaleJobs` returns a count > 0 and the `slog.Info` log line fires. Nice-to-have.

### Well-covered (80–99%) — 16 functions

| Function | Coverage | Uncovered branch | Severity |
|----------|----------|-----------------|----------|
| ghsa.Fetch | 85.2% | Rate limiter wait error, context cancel mid-page | correctness |
| ghsa.fetchPage | 86.8% | Response body read error after successful HTTP | nice-to-have |
| kev.Fetch | 80.0% | Rate limiter wait error, empty-response short-circuit | correctness |
| mitre.Fetch | 84.8% | Error from `zip.NewReader`, context cancel mid-entry | correctness |
| mitre.parseEntry | 83.3% | `parseCVE5` returns nil (empty CVE ID) from a file that passed `isCVEEntry` | nice-to-have |
| nvd.Fetch | 85.2% | Rate limiter wait error, `doRequest` date-header parse failure | correctness |
| nvd.doRequest | 90.0% | Rate limiter wait error | nice-to-have |
| nvd.zeroValueCursor | 83.3% | Edge case in window calculation | nice-to-have |
| nvd.cveToCanonical | 97.3% | Description with only non-"en" `lang` where no English is present (test exists but coverage tool may not count the nil-return path) | nice-to-have |
| nvd.applyNVDCVSS | 96.7% | v4.0 severity-only path when v3 is absent | nice-to-have |
| osv.Fetch | 81.8% | Rate limiter wait error, context cancel mid-entry | correctness |
| osv.parseEntry | 83.3% | `parseAdvisory` returns nil (empty ID) from a file that passed `isAdvisoryEntry` | nice-to-have |
| merge.ComputeMaterialHash | 88.0% | CVSSv3Vector non-empty with nil CVSSv3Score (unlikely but possible) | nice-to-have |
| merge.resolve | 92.5% | All sources have malformed JSON (every unmarshal fails) | correctness |
| merge.canonicalizeURL | 92.3% | `url.Parse` error (malformed URL string) | nice-to-have |
| worker.runQueue | 87.5% | `processOne` returns error path after successful claim | correctness |

## §3 Data Pipeline Security Matrix

This scope has no org-scoped API endpoints. The matrix is adapted for data pipeline security concerns: advisory lock coordination, null-byte sanitization, streaming parse safety, temp file cleanup, rate limiter initialization, and error handling strategy.

### Pipeline components enumeration

1. EPSS adapter (Apply + applyRow)
2. GHSA adapter (Fetch + fetchPage)
3. KEV adapter (Fetch + parseKEV)
4. MITRE adapter (Fetch + downloadToTemp)
5. NVD adapter (Fetch + doRequest)
6. OSV adapter (Fetch + downloadToTemp)
7. Merge pipeline (Ingest)
8. PK migration (migrateCVEPK)
9. Worker pool (processOne + runStaleRecovery)

### Matrix

| Component | Advisory lock | Null-byte strip | Streaming parse | Temp file cleanup | Rate limiter init | Error strategy |
|-----------|--------------|-----------------|-----------------|-------------------|-------------------|----------------|
| EPSS Apply+applyRow | GAP (applyRow acquires lock but 0% tested) | Tested (TestNullByteStripping) | N/A (CSV line-by-line) | N/A | Tested (TestAdapterRateLimiterNonNil) | GAP (no test for apply error propagation) |
| GHSA Fetch | N/A | Tested (TestParseAdvisory_NullByteStripping) | Tested (TestFetch_Success — streaming JSON array) | N/A | Tested (TestAdapterRateLimiterNonNil) | Tested (malformed records skipped: TestFetch_MalformedEntrySkipped) |
| KEV Fetch | N/A | Tested (TestRecordToPatch_NullBytesStripped) | Tested (TestParseKEV — Token/More loop) | N/A | N/A (KEV has no explicit limiter test) | Tested (record decode errors fatal: TestParseKEV) |
| MITRE Fetch | N/A | Tested (TestParseCVE5_NullByteStripping) | N/A (ZIP archive, not streaming JSON) | GAP (downloadToTemp error paths untested — 57.1%) | N/A | Tested (malformed entries skipped: TestFetch_MalformedEntrySkipped) |
| NVD Fetch | N/A | Tested (TestCveToCanonical_NullByteStripping) | Tested (TestParseNVDResponse — Token/More loop) | N/A | Tested (adapter constructed with rate.NewLimiter) | Tested (malformed records skipped: TestParseNVDResponse_malformed) |
| OSV Fetch | N/A | Tested (TestParseAdvisory null bytes stripped) | N/A (ZIP archive, not streaming JSON) | GAP (downloadToTemp error paths untested — 57.1%) | Tested (TestAdapterRateLimiterNonNil) | Tested (malformed entries skipped via parseEntry) |
| Merge Ingest | Tested (TestIngestAdvisoryLockAcquired) | Tested (pipeline.go:48 — bytes.ReplaceAll null bytes) | N/A | N/A | N/A | Tested (14 integration test functions) |
| PK migration | Tested (TestIngestMigrateCVEPK — within advisory lock) | N/A | N/A | N/A | N/A | GAP (individual UPDATE error paths untested — 71.4%) |
| Worker pool | N/A | N/A | N/A | N/A | N/A | Tested (TestProcessOne error paths) |

### Spot-check verification

1. **"Tested" — EPSS null-byte strip (TestNullByteStripping in epss/adapter_test.go:173):** Verified — test injects `\x00` into CVE ID, asserts `feed.StripNullBytes` removes it. Correct.
2. **"Tested" — Merge advisory lock (TestIngestAdvisoryLockAcquired in pipeline_integration_test.go):** Verified — test inserts a CVE, then verifies `pg_advisory_xact_lock` was called by checking concurrent writes serialize correctly. Correct.
3. **"Tested" — NVD streaming parse (TestParseNVDResponse):** Verified — 6 test cases including malformed records, empty body, unknown keys. Uses `strings.NewReader` which exercises the streaming `json.Decoder` path. Correct.

### Security matrix GAPs (4)

1. **EPSS advisory lock untested** — `applyRow` acquires `CVEAdvisoryKey` lock (same as merge pipeline) but has zero test coverage
2. **EPSS apply error propagation untested** — no test verifies that DB errors from the two-statement pattern propagate correctly
3. **MITRE/OSV downloadToTemp cleanup untested** — error paths (HTTP error, io.Copy fail) don't verify temp file cleanup
4. **migrateCVEPK error paths untested** — individual UPDATE failures not tested

## §4 Semantic Code Analysis

### A. Cross-adapter consistency

**Pattern: malformed record handling**

| Adapter | On decode error | Strategy |
|---------|----------------|----------|
| NVD | `slog.Error` + `continue` | skip |
| GHSA | `parseAdvisory` returns nil → skip | skip |
| MITRE | `parseCVE5` returns err → `slog.Warn` + `continue` | skip |
| OSV | `parseAdvisory` returns err → `slog.Warn` + `continue` | skip |
| KEV | `return nil, ..., fmt.Errorf("decode record: %w", err)` | **fatal** |
| EPSS | untested (Apply at 14.3%) | unknown |

KEV is the only adapter that treats a single malformed record as fatal. This appears intentional — KEV is a curated CISA catalog (~1,100 records) where a malformed record signals data corruption rather than normal variance. However, this means a single corrupt record in the CISA JSON could block all KEV updates until the upstream is fixed. **Observation, not necessarily a bug** — the design choice should be documented.

**Pattern: rate limiter initialization**

All adapters with `New()` constructors initialize a rate limiter. Tested for EPSS, GHSA, OSV (explicit `TestAdapterRateLimiterNonNil`). NVD and MITRE construct adapters directly in tests, bypassing `New()` — rate limiter init is untested for these two.

**Pattern: null-byte stripping**

All 6 feed adapters + merge pipeline strip null bytes from string fields before DB writes. Consistent and well-tested across all adapters. ✓

**Pattern: downloadToTemp cleanup**

MITRE and OSV use identical downloadToTemp implementations. Both correctly close and remove the temp file on `io.Copy` or `Seek` error. Code is correct — the gap is that these cleanup paths are untested.

### B. Right-function-called

- **`CVEAdvisoryKey` in EPSS applyRow:** Uses the same FNV-64a hash function as the merge pipeline's Ingest. Correct — both paths acquire the same advisory lock for a given CVE ID. ✓
- **`ComputeMaterialHash` in Ingest:** Correctly populates `MaterialFields` struct from resolved values, including sorted CWE IDs and normalized CPE strings. ✓
- **`feed.ResolveCanonicalID` in GHSA/OSV:** Both use the shared utility to promote native advisory IDs to CVE IDs via alias arrays. ✓
- **`canonicalizeURL` in resolve:** Used for reference deduplication — lowercases host, sorts query params, strips fragment. Correct function for the purpose. ✓

No wrong-function-called bugs found.

### C. TOCTOU windows

- **EPSS + merge coordination:** Both EPSS `applyRow` and merge `Ingest` acquire `CVEAdvisoryKey` advisory lock. This serializes writes and prevents TOCTOU between EPSS score updates and merge pipeline CVE upserts. ✓
- **Merge Ingest steps 2–10:** All within a single advisory-locked transaction. No state checked in one step and used in another without lock protection. ✓
- **PK migration:** `migrateCVEPK` runs within the same advisory-locked transaction as Ingest. ✓
- **Worker processOne:** Job claimed → processed → marked complete/failed. If crash between claim and completion, `runStaleRecovery` re-queues. ✓

No TOCTOU windows found.

### D. Defense-in-depth

Not applicable for this scope — no HTTP middleware protecting these components (they're background workers and data pipeline functions, not API handlers).

### E. Store-layer independence

Not applicable — this scope's store interactions are all within the merge pipeline integration tests, which test the full pipeline path including advisory locks and DB writes.

## §5 Assertion Quality Audit

### EPSS adapter tests

- **TestApply_SameDayCursorSkips:** Checks `err == nil` and cursor unchanged. Assertions are appropriate for the tested path (short-circuit). ✓
- **TestAdapterRateLimiterNonNil:** Checks three fields are non-nil. Appropriate. ✓
- **TestNullByteStripping:** Verifies cleaned string value. Appropriate. ✓

### GHSA adapter tests

- **TestParseAdvisory:** 20+ subcases with specific field assertions (CVEID, SourceID, Description, CVSS, CWE, references, withdrawn, null bytes). Strong assertion quality. ✓
- **TestFetch_Success/Pagination/HTTPError:** End-to-end tests with httptest server. Verify patch count, CVE IDs, source metadata, and cursor. ✓

### KEV adapter tests

- **TestParseKEV:** Verifies patch count, CVE IDs, ordering, catalog version. ✓
- **TestRecordToPatch:** 7 subcases including field-level assertions, null-byte stripping, and tag mapping. ✓
- **TestExtractCWEs:** 11 subcases including edge cases (NVD-CWE-Other, NVD-CWE-noinfo, empty). ✓

### NVD adapter tests

- **TestCveToCanonical:** Field-by-field assertions on all output fields (CVEID, Status, IsWithdrawn, Description, CWE dedup, CPE dedup/normalization, References, CVSS). Strong. ✓
- **TestApplyNVDCVSS:** 7 subcases covering v3.1 preference, v3.0 fallback, v4.0 independence, severity precedence, empty severity, NVD source preference. ✓
- **TestFetch tests:** 8 test functions covering success, cursor, HTTP error, invalid cursor, zero window, no Date header, API key header, Date response header. ✓

### MITRE adapter tests

- **TestParseCVE5:** Comprehensive — minimal valid, empty CVE ID, rejected state (case-insensitive), descriptions (3 subcases), CWE dedup, CWE type filter, references, CPEs, full entry, null-byte stripping, date fields, invalid JSON, ADP fallback. ✓
- **TestApplyCVSS:** 8 subcases covering precedence, fallback, independence, no-overwrite, zero-score skip, severity precedence. ✓
- **TestFetch:** Success, incremental skip, HTTP error, non-CVE entries skipped, malformed entry skipped. ✓

### OSV adapter tests

- **TestParseAdvisory:** Comprehensive — CVE alias resolution, no aliases, aliases without CVE, withdrawn, description preference, affected packages with ranges, CVSS vectors, duplicate CVSS, references, empty URL skip, empty ID, null bytes, active status, no description, package skip on empty ecosystem/name, empty CVSS vector, case-insensitive CVSS type, multiple ranges. ✓
- **TestExtractPackageRange:** 7 subcases including malformed events. ✓

### Merge pipeline integration tests

- **14 test functions** covering material hash determinism, field sensitivity, EPSS exclusion, PK migration, EPSS staging, tombstone, multi-source, child tables, FTS, advisory lock, raw payload, concurrent writes, non-material updates. Strong. ✓

### Merge resolve tests

- **26 test functions** covering status priority, description precedence, date selection, CVSS precedence, score divergence, CWE union, KEV/exploit OR logic, reference dedup, package priority, date modified max, malformed source skip, CVSSv4, severity fallback, canonicalizeURL (7 subcases), firstStr/firstStrPtr (6 subcases), otherSources (3 subcases), computeScoreDiverges boundary (4 subcases). Strong. ✓

### Merge hash tests

- **15 test functions** covering determinism, field sensitivity, CWE order, nil vs empty slices, package order, CPE order, CVSS vector normalization (v3 + v4), status sensitivity, score nil vs zero, exploit available, package content, sort tiebreak. Strong. ✓

### Worker pool tests

- **processOne tests:** Cover nil job, claim error, success, failure, nil handler, fail-job error, complete-job error. Uses fakeJobStore.
- **Assertion quality concern:** fakeJobStore is a mock — but it's testing the worker's orchestration logic (what to call in which order), not the store's behavior. This is appropriate for unit-testing the worker's control flow. The store itself would be tested via integration tests. ✓

### Overall assertion quality

No anti-patterns detected: no execution-only tests, no conditional assertions, no garbage-input-only tests. Test coverage across all packages uses specific field-level assertions that verify behavior, not just execution. The weakest area is EPSS — `Apply` and `applyRow` have essentially zero meaningful test coverage.

## Gap Context

| Category | Functions | Gaps | Action |
|----------|-----------|------|--------|
| Uncovered (0%) | 2 | 6 | Write tests for applyRow (integration) and nvd.New (unit) |
| Partial coverage (1-79%) | 9 | 12 | Add specific test cases for uncovered branches |
| Well-covered (80-99%) | 16 | 16 | Add edge case tests (most are nice-to-have) |
| Security matrix GAPs | 4 | 4 | Add pipeline security tests |
| Semantic analysis | 1 | 1 | Document KEV error strategy |
| Assertion quality | 0 | 0 | N/A |
| **Total** | | **39** | |

## What's Well-Covered

- **Merge pipeline:** 14 integration tests covering all 10 Ingest steps including tombstone, PK migration, EPSS staging, concurrent writes, child tables, FTS, advisory lock, raw payload. Material hash tests cover determinism, field sensitivity, ordering invariants, and nil-vs-empty semantics.
- **Feed adapter parse functions:** All 6 adapters have comprehensive unit tests for their core parse/convert functions (parseCVE5, parseAdvisory, cveToCanonical, recordToPatch, etc.) with null-byte stripping, edge cases, and field-level assertions.
- **Merge resolve:** 26 tests cover per-field precedence logic, CVSS score divergence detection, CWE union/dedup, reference deduplication by canonical URL, affected package priority, and unknown-source fallback.

## Production Bugs Discovered

None. Semantic analysis (§4) found no wrong-function-called bugs, no TOCTOU windows, and no cross-handler pattern violations. The advisory lock coordination between EPSS and merge pipeline uses the correct shared `CVEAdvisoryKey` function. The downloadToTemp cleanup code is correctly implemented (close + remove on error).

## Security-Critical Gaps (6)

1. **epss.applyRow — zero test coverage** — `adapter.go:237` — 37 lines of advisory-locked DB write logic completely untested. Only `t.Skip("TODO")` stubs exist. [source: coverage]
2. **epss.Apply — near-zero coverage (14.3%)** — `adapter.go:106` — entire download/parse/apply flow untested (~120 lines). Drives applyRow. [source: coverage]
3. **EPSS advisory lock coordination untested** — `applyRow` acquires `CVEAdvisoryKey` lock (same as merge pipeline) but no test verifies correct lock acquisition. [source: matrix]
4. **EPSS two-statement pattern untested** — UPDATE cves + INSERT epss_staging pattern has no test for correct execution, error propagation, or `IS DISTINCT FROM` guard behavior. [source: matrix]
5. **EPSS error propagation untested** — no test verifies that DB errors from applyRow propagate correctly through Apply to the caller. [source: matrix]
6. **nvd.New rate limiter conditional untested** — `adapter.go:72` — API key env var conditional rate limiter (50/30s vs 5/30s) untested. A nil or misconfigured limiter could panic or violate NVD rate limits. [source: coverage]

## Correctness Gaps (14)

1. **mitre.downloadToTemp error paths (57.1%)** — `adapter.go:154` — HTTP error, io.Copy fail, Seek fail cleanup paths untested (code is correct but untested)
2. **osv.downloadToTemp error paths (57.1%)** — `adapter.go:143` — same as mitre
3. **kev.parseKEV Token() error (72.7%)** — `adapter.go:161` — opening `{` Token error untested
4. **kev.parseKEV read-key error (72.7%)** — `adapter.go:173` — key Token error untested
5. **nvd.parseNVDResponse Token() errors (70.6%)** — `adapter.go:344` — top-level structure Token errors untested
6. **merge.Ingest — GetAllCVESources error (67.6%)** — `pipeline.go:113` — DB error propagation untested
7. **merge.Ingest — child table insert loop errors (67.6%)** — `pipeline.go:184,199,219` — individual insert errors in reference/package/CPE loops untested
8. **merge.migrateCVEPK — individual UPDATE errors (71.4%)** — `pipeline.go:373` — each of 7 UPDATE statements' error paths untested
9. **merge.resolve — all-malformed-sources edge (92.5%)** — `resolve.go:79` — what happens when every source has invalid JSON
10. **nvd.New — constructor correctness (0%)** — `adapter.go:72` — env var handling, default client, rate limiter setup
11. **mitre.New — nil-client fallback (66.7%)** — `adapter.go:50` — untested path
12. **ghsa.Fetch — rate limiter wait error (85.2%)** — `adapter.go:92` — context cancel during rate wait
13. **kev.Fetch — rate limiter wait error (80.0%)** — `adapter.go:64` — context cancel during rate wait
14. **worker.runQueue — processOne error propagation (87.5%)** — `pool.go:94` — error path after successful claim

## Nice-to-Have (19 total, top 5 shown)

Total: 19 gaps across well-covered functions (rate limiter wait errors, edge-case error returns, unlikely runtime failures).

1. **ghsa.fetchPage response body read error (86.8%)** — `adapter.go:148`
2. **nvd.doRequest rate limiter wait error (90.0%)** — `adapter.go:160`
3. **merge.ComputeMaterialHash CVSSv3Vector with nil score (88.0%)** — `hash.go:49`
4. **merge.canonicalizeURL url.Parse error (92.3%)** — `resolve.go:357`
5. **worker.runStaleRecovery successful recovery log path (53.8%)** — `pool.go:154`

## Assertion Quality Issues (0)

No assertion quality anti-patterns detected across any test files. All tests use field-level behavioral assertions.

## Key Observations

1. **EPSS is a coverage desert.** `applyRow` (0%) and `Apply` (14.3%) together represent the entire EPSS write path — ~160 lines of advisory-locked DB interaction with zero meaningful coverage. The `apply_integration_test.go` file contains only `t.Skip("TODO")` stubs. This is the single highest-priority coverage gap in Phase 1.

2. **Cross-adapter error handling inconsistency:** KEV treats malformed records as fatal (returns error) while all other adapters skip and continue. This appears to be an intentional design choice (KEV is a curated catalog), but it means a single corrupt JSON record in the CISA KEV feed blocks all KEV updates. Consider documenting this as a deliberate policy or adding a skip-and-warn path.

3. **downloadToTemp code is correct despite low coverage.** Both MITRE and OSV implementations properly close and remove temp files on error paths. The 57.1% coverage reflects untested error branches, not incorrect code. Tests would provide regression protection.

4. **Merge pipeline is impressively well-tested.** 14 integration tests + 26 resolve tests + 15 hash tests thoroughly exercise the 10-step Ingest pipeline, field precedence logic, and material hash computation. The remaining uncovered paths are error-wrapping branches that provide fault propagation rather than business logic.

5. **No production bugs found by semantic analysis.** All function calls are to the correct functions, advisory lock coordination is sound, TOCTOU windows are properly guarded by advisory locks, and downloadToTemp cleanup is correctly implemented. The absence of semantic bugs reflects good code quality in the Phase 1 implementation.

6. **Constructor coverage gap pattern:** `nvd.New` (0%) and `mitre.New` (66.7%) are untested because Fetch-level integration tests construct adapters directly. While the constructors are simple, the NVD constructor has conditional rate limiter logic based on env vars that should be tested.

