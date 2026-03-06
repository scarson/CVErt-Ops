# Phase 1 Test Coverage Review — Enhanced Coverage-Tool v3

**Scope:** `internal/feed/...`, `internal/merge/...`, `internal/worker/...`
**Skill:** `/test-coverage-review-go` (enhanced v3)
**Date:** 2026-03-03
**Overall Statement Coverage:** 83.4%

---

## Coverage Baseline

| Package | Functions | 100% | 80–99% | 1–79% | 0% | Key Concern |
|---------|-----------|------|--------|-------|----|-------------|
| feed/epss | 4 | 2 | 0 | 1 | 1 | Apply 14.3%, applyRow 0% |
| feed/ghsa | 5 | 3 | 2 | 0 | 0 | Fetch/fetchPage error branches |
| feed/kev | 5 | 3 | 1 | 1 | 0 | parseKEV 72.7% streaming errors |
| feed/mitre | 8 | 5 | 2 | 1 | 0 | downloadToTemp 57.1% |
| feed/nvd | 11 | 5 | 4 | 1 | 1 | New 0%, parseNVDResponse 70.6% |
| feed/osv | 7 | 4 | 2 | 1 | 0 | downloadToTemp 57.1% |
| feed (util) | 5 | 5 | 0 | 0 | 0 | All fully covered |
| merge | 22 | 18 | 2 | 2 | 0 | Ingest 67.6%, migrateCVEPK 71.4% |
| worker | 6 | 3 | 1 | 1 | 1 | runStaleRecovery 53.8% |
| **Total** | **73** | **48** | **14** | **7** | **2** | |

## Security Checklist Matrix

**N/A** — This scope contains no org-scoped API endpoints. All functions are internal feed adapters, merge pipeline, and worker pool. There are no HTTP handlers, no authentication checks, no RBAC enforcement, and no tenant isolation boundaries in this scope.

Security-relevant concerns (advisory lock coordination, data integrity, input validation) are captured in the gap analysis below.

## Gap Context

| Category | Files | Gaps | Action |
|----------|-------|------|--------|
| Uncovered (0%) | 2 | 2 | Create test files / integration tests |
| Partial coverage | 14 | 42 | Add specific test cases for uncovered branches |
| Assertion quality | 7 | 10 | Strengthen existing tests |
| Semantic spot-checks | 2 | 2 | Fix code or add targeted tests |
| TOCTOU windows | 1 | 1 | Add concurrency test |
| Cross-adapter consistency | 3 | 3 | Backfill systematic gaps |
| **Total** | | **60** | |

(Nice-to-have gaps excluded from this count. Including nice-to-have: 97 total gaps.)

## What's Well-Covered

- **Parse/convert layer at 100% across all adapters.** `parseAdvisory` (GHSA, OSV), `parseCVE5` (MITRE), `recordToPatch` (KEV), `extractCWEs` (KEV), `applyCVSS` (MITRE), `extractPackageRange` (OSV), `cveToCanonical` (NVD 97.3%) all have thorough assertion-rich tests. Null byte stripping is validated at the parse level in every adapter with dedicated tests.

- **Material hash computation thoroughly tested.** 18 unit tests covering determinism, field sensitivity for every material field, order independence (CWEs, CPEs, packages), nil-vs-empty slice equivalence, CVSS vector normalization. Excellent assertion quality.

- **Source precedence resolution well-covered.** 28+ tests covering status (MITRE > NVD), CVSS (NVD > OSV > GHSA), packages (OSV > GHSA), CWE union/dedup/sort, KEV/exploit OR-logic, reference dedup by canonical URL, severity two-tier fallback.

- **Shared utilities at 100%.** `ParseTime`, `ParseTimePtr`, `StripNullBytes`, `ResolveCanonicalID` have comprehensive edge-case coverage.

- **Worker pool `processOne` well-tested** with handler success/failure/nil-job scenarios.

## Production Bugs Discovered

### BUG-1: `feed.ParseTime` does not parse RFC1123 — NVD Date header safety layer is dead code

- **Location:** [adapter.go:194-195](internal/feed/nvd/adapter.go#L194-L195) calls `feed.ParseTime(dateStr)` on the HTTP `Date` response header. [util.go:13-18](internal/feed/util.go#L13-L18) only supports RFC3339Nano, RFC3339, `2006-01-02T15:04:05`, and `2006-01-02`.
- **Root cause:** HTTP `Date` headers use RFC1123 format (`Sun, 01 Jun 2025 12:00:00 GMT`). `ParseTime` returns zero time, so `nvdTime` is always zero.
- **Impact:** The three-tier fallback for `effectiveNow` (response timestamp → Date header → `time.Now()`) effectively becomes two-tier. If the NVD response JSON omits its `timestamp` field, the adapter falls back directly to `time.Now()` instead of using the server's clock, defeating the clock-skew safety. Cursor upper bounds may be computed from local clock, potentially missing or re-fetching records.
- **Source:** semantic

### BUG-2: PK migration collision causes data loss when new CVE ID already exists

- **Location:** [pipeline.go:352](internal/merge/pipeline.go#L352) `migrateCVEPK` — when the new CVE ID already exists in `cves` (e.g., NVD created CVE-2024-1234 first, then GHSA publishes GHSA-xxxx with alias CVE-2024-1234), `UPDATE cves SET cve_id = $2 WHERE cve_id = $1` fails with a unique constraint violation.
- **Impact:** The entire Ingest transaction rolls back, the source patch is lost, and the old CVE row remains orphaned under its advisory ID — never migrated, never merged. This is fail-closed (no data corruption), but causes silent data loss.
- **Fix:** Should merge the old row's child data into the existing new row rather than renaming the PK, or handle the conflict explicitly.
- **Source:** semantic

## Security-Critical Gaps (2)

1. **EPSS `applyRow` at 0% — advisory lock coordination untested** — [adapter.go:237-274](internal/feed/epss/adapter.go#L237-L274) — The advisory lock key, Statement 1 IS DISTINCT FROM guard, and Statement 2 WHERE NOT EXISTS + ON CONFLICT pattern are all untested. This is the sole guard against TOCTOU races between concurrent EPSS and merge operations. No test verifies the lock key matches `merge.CVEAdvisoryKey`. — source: coverage

2. **PK migration collision not tested** — [pipeline.go:352](internal/merge/pipeline.go#L352) — When newID already exists in `cves`, `migrateCVEPK` hits a PK uniqueness violation. No test covers this scenario. The advisory lock serializes same-ID writers, but can't prevent the collision when the target ID was created by a different source. — source: semantic

## Correctness Gaps (42)

### EPSS Adapter (10)

3. EPSS `Apply` — entire HTTP download + gzip decode + CSV parse + DB write path untested (14.3% coverage, only cursor short-circuit is tested) — [adapter.go:125-227](internal/feed/epss/adapter.go#L125-L227) — source: coverage
4. EPSS `Apply` — HTTP error response (non-200) path untested — [adapter.go:141-143](internal/feed/epss/adapter.go#L141-L143) — source: coverage
5. EPSS `Apply` — invalid gzip stream error path untested — [adapter.go:145-148](internal/feed/epss/adapter.go#L145-L148) — source: coverage
6. EPSS `Apply` — `parseLine1` failure within Apply untested — [adapter.go:162-165](internal/feed/epss/adapter.go#L162-L165) — source: coverage
7. EPSS `Apply` — unparseable `score_date` error path untested — [adapter.go:177-179](internal/feed/epss/adapter.go#L177-L179) — source: coverage
8. EPSS `Apply` — CSV data row parse loop (empty CVE skip, unparseable score skip, applyRow call) untested — [adapter.go:192-220](internal/feed/epss/adapter.go#L192-L220) — source: coverage
9. EPSS `Apply` — end-to-end cursor round-trip untested — [adapter.go:222-227](internal/feed/epss/adapter.go#L222-L227) — source: coverage
10. EPSS `applyRow` — `UpdateCVEEPSS` IS DISTINCT FROM guard not verified — [adapter.go:255-260](internal/feed/epss/adapter.go#L255-L260) — source: coverage
11. EPSS `applyRow` — `UpsertEPSSStaging` WHERE NOT EXISTS + ON CONFLICT not verified — [adapter.go:265-271](internal/feed/epss/adapter.go#L265-L271) — source: coverage
12. EPSS `applyRow` — transaction commit/rollback lifecycle untested — [adapter.go:237-274](internal/feed/epss/adapter.go#L237-L274) — source: coverage

### NVD Adapter (3)

13. NVD `New` — constructor untested: rate limiter interval differs with/without `NVD_API_KEY` (0.6s vs 6s), client nil-fallback — [adapter.go:72-90](internal/feed/nvd/adapter.go#L72-L90) — source: coverage
14. NVD `doRequest` — `feed.ParseTime` does not support RFC1123 → Date header clock-skew safety layer dead code (BUG-1) — [adapter.go:194-195](internal/feed/nvd/adapter.go#L194-L195) — source: semantic
15. NVD `applyNVDCVSS` — v4.0-only scenario (no v3.1 or v3.0) untested — [adapter.go:499](internal/feed/nvd/adapter.go#L499) — source: coverage

### GHSA Adapter (6)

16. GHSA `Fetch` — invalid cursor JSON error branch untested — [adapter.go:95-97](internal/feed/ghsa/adapter.go#L95-L97) — source: coverage
17. GHSA `Fetch` — invalid cursor `Since` timestamp parse error untested — [adapter.go:104-106](internal/feed/ghsa/adapter.go#L104-L106) — source: coverage
18. GHSA `Fetch` — context cancellation during `rateLimiter.Wait` untested — [adapter.go:115-117](internal/feed/ghsa/adapter.go#L115-L117) — source: coverage
19. GHSA `fetchPage` — `dec.Token()` read error on response body untested — [adapter.go:191-193](internal/feed/ghsa/adapter.go#L191-L193) — source: coverage
20. GHSA `fetchPage` — non-array response body untested — [adapter.go:194-196](internal/feed/ghsa/adapter.go#L194-L196) — source: coverage
21. GHSA `fetchPage` — malformed individual record `dec.Decode` error (skip-and-continue) not explicitly tested — [adapter.go:201-203](internal/feed/ghsa/adapter.go#L201-L203) — source: coverage

### KEV Adapter (7)

22. KEV `Fetch` — context cancellation during `rateLimiter.Wait` untested — [adapter.go:72-74](internal/feed/kev/adapter.go#L72-L74) — source: coverage
23. KEV `parseKEV` — opening brace `dec.Token()` error untested — [adapter.go:161](internal/feed/kev/adapter.go#L161) — source: coverage
24. KEV `parseKEV` — non-string key token branch untested — [adapter.go:177-185](internal/feed/kev/adapter.go#L177-L185) — source: coverage
25. KEV `parseKEV` — `dec.Token()` key read error untested — [adapter.go:172-175](internal/feed/kev/adapter.go#L172-L175) — source: coverage
26. KEV `parseKEV` — drain of skipped array on version match error untested — [adapter.go:213-214](internal/feed/kev/adapter.go#L213-L214) — source: coverage
27. KEV `parseKEV` — `dec.Decode(&catalogVersion)` error untested — [adapter.go:189-191](internal/feed/kev/adapter.go#L189-L191) — source: coverage
28. KEV `parseKEV` — `dec.Decode(&dateReleased)` error untested — [adapter.go:195-197](internal/feed/kev/adapter.go#L195-L197) — source: coverage

### MITRE Adapter (3)

29. MITRE `Fetch` — context cancellation during `rateLimiter.Wait` untested — [adapter.go:79-81](internal/feed/mitre/adapter.go#L79-L81) — source: coverage
30. MITRE `Fetch` — `zip.NewReader()` error on corrupted ZIP untested — [adapter.go:96-99](internal/feed/mitre/adapter.go#L96-L99) — source: coverage
31. MITRE `downloadToTemp` — `io.Copy` failure branch untested — [adapter.go:175-179](internal/feed/mitre/adapter.go#L175-L179) — source: coverage

### OSV Adapter (3)

32. OSV `Fetch` — context cancellation during `rateLimiter.Wait` untested — [adapter.go:79-81](internal/feed/osv/adapter.go#L79-L81) — source: coverage
33. OSV `Fetch` — `zip.NewReader()` error on corrupted ZIP untested — [adapter.go:95-98](internal/feed/osv/adapter.go#L95-L98) — source: coverage
34. OSV `downloadToTemp` — `io.Copy` failure branch untested — [adapter.go:164-167](internal/feed/osv/adapter.go#L164-L167) — source: coverage

### Merge Pipeline (7)

35. `Ingest` — null-byte stripping of `rawPayload` not tested with actual NUL bytes — [pipeline.go:49-51](internal/merge/pipeline.go#L49-L51) — source: coverage
36. `Ingest` — null-byte stripping of `normalizedJSON` not tested with NUL bytes — [pipeline.go:48](internal/merge/pipeline.go#L48) — source: coverage
37. `Ingest` — PK migration skip when `SourceID` empty not tested — [pipeline.go:72](internal/merge/pipeline.go#L72) — source: coverage
38. `migrateCVEPK` — migration when `epss_staging` rows exist under old ID untested — [pipeline.go:369](internal/merge/pipeline.go#L369) — source: coverage
39. `resolve` — CPE normalization fallback when `CPENormalized == ""` untested — [resolve.go:256-257](internal/merge/resolve.go#L256-L257) — source: coverage
40. `canonicalizeURL` — empty path normalization uses log-only assertion, doesn't assert specific value — [resolve.go:367-369](internal/merge/resolve.go#L367-L369) — source: assertion
41. EPSS-merge concurrent race: no test verifies EPSS adapter and Ingest don't race on the same CVE ID via the shared advisory lock — source: coverage

### Worker (3)

42. `runQueue` — the `<-ticker.C` branch calling `processOne` never directly exercised — [pool.go:106](internal/worker/pool.go#L106) — source: coverage
43. `runStaleRecovery` — `TestRunStaleRecovery_CallsRecoverAndStops` counter declared but never asserted — execution-only test — [pool.go:154](internal/worker/pool.go#L154) — source: assertion
44. `processOne` — `TestProcessOne_NilHandler` no assertion that job was NOT marked as completed — [pool.go:113](internal/worker/pool.go#L113) — source: assertion

## Nice-to-Have (53)

<details>
<summary>Click to expand nice-to-have gaps</summary>

### EPSS (6)
45. `Apply` — invalid cursor JSON error path — [adapter.go:109-111](internal/feed/epss/adapter.go#L109-L111)
46. `Apply` — rate limiter wait with cancelled context — [adapter.go:125-127](internal/feed/epss/adapter.go#L125-L127)
47. `Apply` — line 1 read error path — [adapter.go:157-160](internal/feed/epss/adapter.go#L157-L160)
48. `Apply` — model version change warning log path — [adapter.go:169-174](internal/feed/epss/adapter.go#L169-L174)
49. `Apply` — CSV header read failure — [adapter.go:187-189](internal/feed/epss/adapter.go#L187-L189)
50. `applyRow` — `BeginTx` failure + advisory lock failure error paths — [adapter.go:238-249](internal/feed/epss/adapter.go#L238-L249)

### NVD (9)
51. `Fetch` — context cancellation during rate limiter wait
52. `Fetch` — `NextCursor` JSON marshal error
53. `doRequest` — `http.NewRequestWithContext` failure (unreachable)
54. `zeroValueCursor` — `windowEnd.After(now)` branch (unreachable before May 2002)
55. `parseNVDResponse` — non-string JSON key path
56. `parseNVDResponse` — read key error path
57. `parseNVDResponse` — decode `totalResults` error path
58. `parseNVDResponse` — decode timestamp error path
59. `parseNVDResponse` — vulnerabilities `[`/`]` token error paths

### GHSA (1)
60. `fetchPage` — `http.NewRequestWithContext` error branch

### KEV (3)
61. `Fetch` — `http.NewRequestWithContext` error
62. `Fetch` — `json.Marshal` cursor failure
63. `parseKEV` — discard of unknown key value error

### MITRE (5)
64. `New` — `client == nil` branch (always called with non-nil client in tests)
65. `Fetch` — `tmpFile.Stat()` error
66. `Fetch` — `json.Marshal` cursor failure
67. `downloadToTemp` — `f.Seek` failure
68. `downloadToTemp` — `os.CreateTemp` failure

### OSV (4)
69. `Fetch` — `tmpFile.Stat()` error
70. `Fetch` — `json.Marshal` cursor failure
71. `downloadToTemp` — `f.Seek` failure
72. `downloadToTemp` — `os.CreateTemp` failure

### NVD (2)
73. `cveToCanonical` — empty CPE criteria skip path
74. `parseEntry` (MITRE) — `entry.Open()` error

### OSV (1)
75. `parseEntry` — `entry.Open()` error

### Merge (20)
76–95. `Ingest` — 18 individual DB error branches (`json.Marshal`, `BeginTx`, advisory lock, `UpsertCVESource`, `InsertCVERawPayload`, `GetAllCVESources`, `resolve()`, `UpsertCVE`, `DeleteCVEReferences`, `InsertCVEReference`, `DeleteCVEAffectedPackages`, `InsertAffectedPackage`, `DeleteCVEAffectedCPEs`, `InsertAffectedCPE`, `GetEPSSStaging` non-ErrNoRows, `UpdateCVEEPSS`, `DeleteEPSSStaging`, `UpsertCVESearchIndex`, `tx.Commit()`); plus `migrateCVEPK` child-table UPDATE errors (8 branches)

### Worker (2)
96. `runStaleRecovery` — `n > 0` log branch
97. `canonicalizeURL` — `url.Parse` error fallback

</details>

## Assertion Quality Issues (10)

1. **`TestFetch_DateResponseHeader` (NVD)** — Execution-only test. Explicitly admits in comments it cannot distinguish success from failure. Creates false confidence about a feature that is actually broken (BUG-1). — [adapter_test.go](internal/feed/nvd/adapter_test.go)

2. **`TestFetch_Success` (NVD)** — Does not assert `NextCursor` content. Since `totalResults=2` and `resultsPerPage=2000`, window is exhausted and cursor should advance — not verified. — [adapter_test.go](internal/feed/nvd/adapter_test.go)

3. **`TestFetch_WithCursor` (NVD)** — Verifies query parameters forwarded but does not assert `NextCursor` content or that `StartIndex` was correctly advanced. — [adapter_test.go](internal/feed/nvd/adapter_test.go)

4. **`TestIngest_AdvisoryLockAcquired`** — Execution-only: does not verify the lock is held during the transaction. Only checks `CVEAdvisoryKey` determinism and CVE was written post-commit. — [pipeline_integration_test.go](internal/merge/pipeline_integration_test.go)

5. **`TestIngest_TombstoneRejectedCVE`** — Only checks `CvssV3Score` and `EpssScore` are NULL. Does not verify `severity` is preserved, `in_cisa_kev` is set to `false`, or the other 5 tombstoned fields. — [pipeline_integration_test.go](internal/merge/pipeline_integration_test.go)

6. **`TestIngest_TombstoneRejectedCVE`** — Does not verify `in_cisa_kev` is set to `false` (tombstone SQL explicitly sets it to false, distinct from NULL). — [pipeline_integration_test.go](internal/merge/pipeline_integration_test.go)

7. **`TestIngest_MultiSourceResolution`** — Only verifies description from NVD. Does not assert severity from MITRE was resolved. Test name claims "multi source resolution" but only verifies one field. — [pipeline_integration_test.go](internal/merge/pipeline_integration_test.go)

8. **`TestRunStaleRecovery_CallsRecoverAndStops`** — Declares `recoverCalls` counter but never asserts it. Test name claims recovery is called but only verifies the goroutine stops cleanly. — [pool_test.go](internal/worker/pool_test.go)

9. **`TestProcessOne_NilHandler`** — Verifies no panic but does not assert the job was NOT marked as completed or failed. — [pool_test.go](internal/worker/pool_test.go)

10. **`TestRunStaleRecovery_ErrorContinues`** — Does not verify the goroutine continues polling after error; only verifies context cancellation stops it. — [pool_test.go](internal/worker/pool_test.go)

## TOCTOU Analysis

### Enumerated Multi-Step Flows

| Flow | Steps | Guard | Tested? | Gap? |
|------|-------|-------|---------|------|
| Advisory lock → merge ops → release | Lock → upsert sources → resolve → upsert CVE → commit | `pg_advisory_xact_lock(CVEAdvisoryKey)` | Yes (`TestIngest_ConcurrentWriteSerializesCorrectly`, 5 iterations) | No |
| Read all cve_sources → resolve → upsert cves | All within advisory-locked txn | Same advisory lock | Yes (end-to-end in integration tests) | No |
| Check CVE exists → insert/update | `INSERT ... ON CONFLICT DO UPDATE` — atomic SQL | SQL engine | Yes | No |
| EPSS staging read → apply → drain | All within advisory-locked txn | Advisory lock (same key) | Architecturally safe; no concurrent test | **Yes** (gap #41) |
| PK migration: check alias → rename → re-merge | All within advisory-locked txn (on NEW ID) | Advisory lock on new ID | Partially; no collision test | **Yes** (gap #2) |
| PK migration: old-ID vs new-ID lock conflict | Writer A locks GHSA-xxxx, Writer B locks CVE-2024-1234. Both modify `cve_sources WHERE cve_id = 'GHSA-xxxx'` | Row-level locks prevent corruption, but merge resolution could see inconsistent snapshot | Not tested | **Yes** (narrow window, correctness gap #41) |
| GHSA cursor → overlap → query | Single goroutine, in-memory | N/A | N/A | No |
| KEV version check → short-circuit | Within same JSON decoder stream | Tested (`TestParseKEV_VulnerabilitiesBeforeVersion`) | Yes | No |
| MITRE/OSV download → parse | Same `*os.File` handle | `os.CreateTemp` uniqueness | N/A | No |
| fetchedAt → cursor persistence | `time.Now()` → cursor marshal | Overlap window (GHSA), full re-download (KEV/MITRE/OSV) | Partially | No |

## Key Observations

### Cross-Cutting Patterns

1. **EPSS adapter is a coverage desert.** `Apply` at 14.3% and `applyRow` at 0% mean the entire EPSS enrichment pipeline — from HTTP download through CSV parsing to database writes — has no real test coverage. The integration test file (`apply_integration_test.go`) exists but contains only `t.Skip()` stubs.

2. **Systematic gap: No context cancellation tests across ALL adapters.** Every adapter's `Fetch`/`Apply` calls `rateLimiter.Wait(ctx)` as its first operation. None of the 6 adapters test what happens when the context is cancelled during this wait. This is 6 uncovered branches across the codebase.

3. **Systematic gap: No invalid cursor JSON tests (except KEV).** KEV is the only adapter with `TestFetch_InvalidCursor`. GHSA, MITRE, OSV, and EPSS all have the same `json.Unmarshal` error branch untested. NVD has a separate `parseCursor` tested at 100%.

4. **`downloadToTemp` code duplication at 57.1% (MITRE, OSV).** Identical functions with identical untested branches. The `io.Copy` failure branch is the most important — it tests cleanup (close file + remove temp) on mid-download failure.

5. **User-Agent header inconsistency.** Only KEV and EPSS set `User-Agent: CVErt-Ops/1.0 vulnerability intelligence platform`. NVD, GHSA, MITRE, OSV do not set any User-Agent. Not a bug, but inconsistent courtesy practice.

6. **Assertion quality pattern in merge integration tests.** `TestIngest_TombstoneRejectedCVE` only verifies 2 of 7 tombstoned fields. `TestIngest_MultiSourceResolution` only verifies 1 field despite testing multi-source resolution. These tests cover the happy path but would not catch regressions that break individual field handling.

7. **NVD Fetch tests verify patches but not cursor advancement.** Both `TestFetch_Success` and `TestFetch_WithCursor` assert correct patches but skip `NextCursor` verification. Cursor advancement drives the entire pagination and window-chunking logic.

8. **Worker assertion quality is systematically weak.** `TestRunStaleRecovery_CallsRecoverAndStops` declares a counter but never checks it. `TestProcessOne_NilHandler` verifies no-panic but not job state. `TestRunStaleRecovery_ErrorContinues` doesn't verify continuation. These tests create false confidence about behaviors they claim to verify.

### Cross-Adapter Consistency Analysis (§4.5A)

All 6 adapters share consistent patterns for:
- Rate limiter setup in `New()` with `nil` client fallback
- Cursor parsing via `json.Unmarshal` with `len(cursorJSON) > 0` guard
- Error wrapping via `fmt.Errorf("<source>: <context>: %w", err)`
- Null byte stripping via `feed.StripNullBytes` on all string fields
- `ResolveCanonicalID` used correctly by GHSA and OSV (the two adapters needing alias resolution)

No cross-adapter pattern violations (wrong-function-called, missing side effects) were found. The adapters are internally consistent in their architecture. The gaps are systematic (all adapters missing the same error branches) rather than individual (one adapter doing something differently from the others).