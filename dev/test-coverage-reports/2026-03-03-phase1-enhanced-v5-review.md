# Phase 1 Test Coverage Review — Enhanced v5

**Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`
**Date:** 2026-03-03
**Skill version:** test-coverage-review-go v5
**Overall coverage:** 83.4% (statements)

## §1 Coverage Baseline

| Package | Functions | 0% | 1–79% | 80–99% | 100% |
|---------|-----------|-----|-------|--------|------|
| internal/feed/epss | 4 | 1 (applyRow) | 1 (Apply 14.3%) | 0 | 2 |
| internal/feed/ghsa | 5 | 0 | 0 | 2 (Fetch 85.2%, fetchPage 86.8%) | 3 |
| internal/feed/kev | 5 | 0 | 1 (parseKEV 72.7%) | 1 (Fetch 80.0%) | 3 |
| internal/feed/mitre | 8 | 0 | 2 (New 66.7%, downloadToTemp 57.1%) | 2 (Fetch 84.8%, parseEntry 83.3%) | 4 |
| internal/feed/nvd | 11 | 1 (New) | 1 (parseNVDResponse 70.6%) | 5 | 4 |
| internal/feed/osv | 7 | 0 | 1 (downloadToTemp 57.1%) | 2 (Fetch 81.8%, parseEntry 83.3%) | 4 |
| internal/feed (util) | 5 | 0 | 0 | 0 | 5 |
| internal/merge | 22 | 0 | 2 (Ingest 67.6%, migrateCVEPK 71.4%) | 3 (ComputeMaterialHash 88%, resolve 92.5%, canonicalizeURL 92.3%) | 17 |
| internal/worker | 6 | 0 | 1 (runStaleRecovery 53.8%) | 1 (runQueue 87.5%) | 4 |
| **Total** | **73** | **2** | **9** | **16** | **46** |

### Functions at 0% Coverage

| Function | File | Lines | Risk Classification |
|----------|------|-------|---------------------|
| `applyRow` | internal/feed/epss/adapter.go:237 | 38 | **Correctness** — DB write logic (advisory lock + two-statement EPSS pattern), but no auth/tenant context |
| `New` | internal/feed/nvd/adapter.go:72 | 19 | **Nice-to-have** — constructor; rate limiter setup based on env var presence |

### Functions at 1–79% Coverage

| Function | File | Coverage | Category |
|----------|------|----------|----------|
| `Apply` | epss/adapter.go:106 | 14.3% | Correctness — main EPSS orchestration |
| `New` | mitre/adapter.go:50 | 66.7% | Nice-to-have — constructor nil-client branch |
| `downloadToTemp` | mitre/adapter.go:154 | 57.1% | Correctness — error cleanup paths |
| `downloadToTemp` | osv/adapter.go:143 | 57.1% | Correctness — error cleanup paths |
| `parseKEV` | kev/adapter.go:144 | 72.7% | Correctness — streaming JSON short-circuit + error paths |
| `parseNVDResponse` | nvd/adapter.go:344 | 70.6% | Correctness — streaming JSON error paths |
| `Ingest` | merge/pipeline.go:35 | 67.6% | **Security-relevant** — core merge pipeline; potential data integrity concern |
| `migrateCVEPK` | merge/pipeline.go:352 | 71.4% | Correctness — PK rename across tables |
| `runStaleRecovery` | worker/pool.go:154 | 53.8% | Correctness — stuck job recovery |

## §3 Security Checklist Matrix

**N/A** — Phase 1 scope contains no org-scoped API endpoints. All packages (feed adapters, merge pipeline, worker pool) operate on global/shared CVE data without org context. No endpoints to enumerate.

## §4 Assertion Quality Audit

### Strong Assertions (exemplary patterns)

- **worker/pool_test.go — processOne tests**: Excellent assertion depth. Tests verify exact `uuid.UUID` values passed to `CompleteJob`/`FailJob`, exact error message strings, handler invocation counts, and correct behavior under compounding failures (handler fail + FailJob fail). This is the gold standard in this codebase.
- **merge/hash_test.go — ComputeMaterialHash**: Tests determinism, field sensitivity, order-independence for CWEs/packages/CPEs, and nil-vs-empty slice equivalence. Verifies properties, not just execution.
- **ghsa/adapter_test.go — parseAdvisory**: ~20 test cases covering alias resolution, withdrawn advisories, CVSS source prioritization, CWE extraction, package details, reference mapping, and null byte stripping. Each case has targeted assertions on the specific fields under test.
- **kev/adapter_test.go — extractCWEs**: 11 test cases including empty input, multi-item, duplicates, whitespace, unprefixed. Good boundary testing.

### Assertion Quality Issues

| # | Test | File | Anti-pattern | What Should Change |
|---|------|------|--------------|--------------------|
| AQ-1 | `TestApply_SameDayCursorSkips` | epss/adapter_test.go:142 | **Execution-only + side-effect reliance** — verifies cursor bytes are unchanged, but doesn't assert that zero HTTP requests were made or that no DB interaction occurred. The test passes even if the adapter silently makes a request and returns the same cursor. | Inject a counting HTTP client (httptest) that fails if called. Assert zero interactions. |
| AQ-2 | `TestAdapterRateLimiterNonNil` | epss/adapter_test.go:124 | **Execution-only** — checks `rateLimiter != nil` and `client != nil` but never verifies the rate limiter is properly configured (e.g., limit value, burst). | At minimum, verify `rateLimiter.Wait(ctx)` completes without error to confirm it's functional. |
| AQ-3 | `TestRunStaleRecovery_CallsRecoverAndStops` | worker/pool_test.go:435 | **Missing assertion on call count** — `recoverCalls` is incremented but never asserted. The test only checks that the goroutine stops on cancel. | Assert `recoverCalls >= 1` after cancel to verify the recovery function was actually invoked. |
| AQ-4 | EPSS integration stubs | epss/apply_integration_test.go:28-38 | **All `t.Skip("TODO")`** — three "test" functions that skip immediately. This is worse than no tests because it creates the appearance of test coverage in test listings. | Implement the tests or remove the stubs. As-is they provide false confidence. |
| AQ-5 | `TestRunStaleRecovery_ErrorContinues` | worker/pool_test.go:467 | **Missing assertion on error logging** — test verifies goroutine doesn't crash on error, but never checks that the error was actually logged. | Either capture slog output and verify the error message, or verify `calls >= 1`. |

## §4.5 Semantic Spot-Checks

### A. Cross-Adapter Consistency

**Pattern: Streaming JSON error handling on malformed records**

| Adapter | Record decode error behavior | Line |
|---------|------------------------------|------|
| NVD | `continue` — skips malformed record, continues array | nvd/adapter.go:391-393 |
| GHSA | `continue` — skips malformed record, continues array | ghsa/adapter.go:201-203 |
| KEV | `return error` — fatal, aborts entire parse | kev/adapter.go:220-222 |
| MITRE | N/A — reads ZIP entries, not streaming JSON array | — |
| OSV | N/A — reads ZIP entries, not streaming JSON array | — |

**Assessment:** This is likely **intentional**. KEV is an authoritative catalog (small, well-structured); a malformed record indicates data corruption and should halt. NVD/GHSA are large feeds where individual record issues shouldn't abort an entire sync. However, neither NVD nor GHSA logs a warning when skipping — a malformed record is silently discarded. This is a correctness concern: operators have no visibility into data loss from malformed upstream records.

**Pattern: `downloadToTemp` implementations**

MITRE (adapter.go:154) and OSV (adapter.go:143) have near-identical `downloadToTemp` functions with identical coverage gaps (57.1%). Both have the same untested error cleanup paths:
- HTTP response body read error → temp file left on disk
- `os.CreateTemp` failure path
- `io.Copy` failure → temp file not removed

This is duplicated code. A shared utility in `internal/feed/util.go` would eliminate the duplication and the coverage gap would need to be fixed only once.

**Pattern: Null byte stripping**

All adapters consistently use `feed.StripNullBytes()` for CVE IDs and `bytes.ReplaceAll(json, []byte{0}, []byte{})` for JSON payloads. Consistent across EPSS, GHSA, KEV, NVD, MITRE, OSV, and the merge pipeline. No issues.

**Pattern: Constructor nil-client fallback**

All adapters that accept `*http.Client` fall back to `http.DefaultClient` when nil. Consistent across all six adapters. No issues.

### B. Right-Function-Called

No wrong-function-called issues found in Phase 1 scope. Key verifications:
- `merge.CVEAdvisoryKey(cveID)` used identically in both `merge.Ingest` (pipeline.go:61) and `epss.applyRow` (adapter.go:247) — correct coordination.
- `feed.ParseTime` used consistently for timestamp parsing across all adapters (not `time.Parse` with a single layout).
- `ComputeMaterialHash` receives properly constructed `MaterialFields` from resolved data (pipeline.go:122-134) — all fields mapped correctly.

### C. Defense-in-Depth

**Worker pool `processOne`** (pool.go:113-149): If `ClaimJob` returns a job for a queue with no registered handler, the function logs an error and returns without calling `FailJob`. This means the job stays in `running` state until stale recovery picks it up. This is correct behavior (no handler = can't process = must retry), but the stale recovery path that would handle this is only at 53.8% coverage.

## §4.6 TOCTOU Analysis

### Multi-step flows in scope

| # | Flow | Steps | Temporal Window? |
|---|------|-------|-----------------|
| TOCTOU-1 | EPSS applyRow | (A) Advisory lock → (B) UPDATE cves → (C) INSERT epss_staging → (D) Commit | **No** — all within single advisory-locked transaction. Lock acquired at step A, held through commit at D. |
| TOCTOU-2 | EPSS ↔ merge coordination | (A) EPSS adapter calls `applyRow` with advisory lock on CVE X → (B) Merge pipeline calls `Ingest` with advisory lock on same CVE X | **No window** — `pg_advisory_xact_lock` serializes. Both use identical key via `merge.CVEAdvisoryKey()`. Correct by design. **However: completely untested.** The advisory lock coordination is the critical safety mechanism, and there are zero tests verifying that concurrent EPSS + merge writes serialize correctly. |
| TOCTOU-3 | merge.Ingest 10-step pipeline | (A) Advisory lock → (B) Upsert source → ... → (J) FTS index → (K) Commit | **No** — entire pipeline runs within single advisory-locked transaction. |
| TOCTOU-4 | merge.Ingest PK migration | (A) FindCVEBySourceID → (B) migrateCVEPK → (C) Continue with new PK | **No** — within same advisory-locked transaction. The check (A) and act (B) are atomic. |
| TOCTOU-5 | Worker claim → process → complete | (A) ClaimJob (SELECT FOR UPDATE SKIP LOCKED) → (B) Handler executes → (C) CompleteJob/FailJob | **Potential window** — if handler (B) takes long and worker crashes between B and C, the job is stuck in `running`. **Guarded by** stale recovery (`runStaleRecovery` with `staleThreshold`). Not a data integrity risk, but stale recovery coverage is only 53.8%. |
| TOCTOU-6 | EPSS Apply same-day short-circuit | (A) Check `cur.ScoreDate` matches today → (B) Skip download | **Minor** — if the process runs across midnight UTC, the cursor date could match "today" at step A but be stale by the time the next run occurs. Not a data loss risk (next run will catch it), but worth documenting. No test covers the midnight-boundary edge case. |

**Summary:** The advisory lock coordination between EPSS and merge is correctly implemented (same key derivation function, same lock type). The design prevents TOCTOU. The gap is **testing**: there are zero tests verifying that concurrent writes actually serialize. This is a correctness gap because the lock coordination is the linchpin of data integrity for the EPSS two-statement pattern.

## §5 Severity Classification & §6 Cross-Cutting Analysis

### Gap Context

| Category | Files | Gaps | Action |
|----------|-------|------|--------|
| Uncovered (0%) | 2 | 2 | Write tests for applyRow; nvd/New is nice-to-have |
| Partial coverage | 7 | 12 | Add specific test cases for identified branches |
| Assertion quality | 5 | 5 | Strengthen existing tests |
| Semantic spot-checks | 2 | 2 | Silent-discard logging, downloadToTemp dedup |
| TOCTOU | 1 | 1 | Concurrent EPSS+merge lock serialization test |
| **Total** | | **22** | |

### What's Well-Covered

- **Feed utility functions** (`internal/feed/util.go`): `ParseTime`, `StripNullBytes`, `StripNullBytesJSON`, `ResolveCanonicalID` — all at 100% with strong assertions. This shared foundation is solid.
- **Worker pool processOne** (100%): Six test cases covering every combination of claim/handler/complete/fail success and failure. Assertion quality is exemplary (exact UUID and error message verification).
- **Merge resolution** (92.5%) and **hash computation** (88%): Core data integrity logic is well-tested, including order-independence, nil-vs-empty equivalence, and field sensitivity. Integration tests verify determinism against a real database.
- **GHSA adapter** (all functions ≥85%): Best coverage of any adapter, with comprehensive `parseAdvisory` test matrix covering alias resolution, CVSS prioritization, withdrawn status, and null byte handling.

### Production Bugs Discovered

None. No wrong-function-called or missing-side-effect bugs found in Phase 1 scope. The code is consistent and correct where tested. The risk is entirely in **untested code paths**.

### Security-Critical Gaps (2)

| # | Gap | Location | Source |
|---|-----|----------|--------|
| SC-1 | `applyRow` at 0% — the advisory-locked two-statement EPSS write pattern is completely untested. This is the critical serialization mechanism preventing TOCTOU between EPSS enrichment and CVE ingest. If the advisory lock key derivation, statement ordering, or commit logic is wrong, scores could be lost or misassigned. | epss/adapter.go:237-274 | coverage |
| SC-2 | EPSS ↔ merge advisory lock coordination untested — both `applyRow` and `Ingest` acquire `pg_advisory_xact_lock(CVEAdvisoryKey(cveID))`, but no test verifies they actually serialize concurrent writes. A subtle bug in key derivation (e.g., using different hash functions) would silently break the TOCTOU guard. | epss/adapter.go:247 + merge/pipeline.go:61 | TOCTOU |

### Correctness Gaps (12)

| # | Gap | Location | Source |
|---|-----|----------|--------|
| C-1 | `Apply` at 14.3% — main EPSS orchestration path (download, gzip decompress, CSV parse, per-row apply) completely untested. Only same-day-skip short-circuit tested. | epss/adapter.go:106-230 | coverage |
| C-2 | `downloadToTemp` (MITRE) at 57.1% — HTTP error cleanup path untested (temp file not removed on `io.Copy` failure). | mitre/adapter.go:154 | coverage |
| C-3 | `downloadToTemp` (OSV) at 57.1% — identical to C-2. Both should be deduplicated into shared utility. | osv/adapter.go:143 | coverage |
| C-4 | `parseKEV` at 72.7% — non-string key branch (line 178) and some error paths in streaming navigation untested. | kev/adapter.go:144 | coverage |
| C-5 | `parseNVDResponse` at 70.6% — streaming error paths (non-string key discard, closing brace errors) untested. | nvd/adapter.go:344 | coverage |
| C-6 | `Ingest` at 67.6% — several error branches untested: `json.Marshal(patch)` failure, `GetAllCVESources` error, `TombstoneCVE` error path, multiple child table insert error paths. | merge/pipeline.go:35 | coverage |
| C-7 | `migrateCVEPK` at 71.4% — UPDATE branches for some child tables (references, affected_packages) untested. | merge/pipeline.go:352 | coverage |
| C-8 | `runStaleRecovery` at 53.8% — error path logging and `n > 0` log path both untested. | worker/pool.go:154 | coverage |
| C-9 | NVD/GHSA silent discard on malformed records — both adapters `continue` on decode error without logging. Operators have zero visibility into upstream data corruption. | nvd/adapter.go:391-393, ghsa/adapter.go:201-203 | semantic |
| C-10 | `Fetch` (MITRE) at 84.8% — some error branches in ZIP entry processing untested. | mitre/adapter.go:68 | coverage |
| C-11 | `Fetch` (OSV) at 81.8% — same pattern as C-10. | osv/adapter.go:57 | coverage |
| C-12 | `Fetch` (KEV) at 80.0% — untested branch: HTTP error path returns correct error format. | kev/adapter.go:86 | coverage |

### Nice-to-Have (5 of 8 total)

8 nice-to-have gaps identified. Top 5 by impact:

| # | Gap | Location |
|---|-----|----------|
| N-1 | `New` (NVD) at 0% — constructor with env-var-based rate limiter selection. 19 lines. | nvd/adapter.go:72 |
| N-2 | `New` (MITRE) at 66.7% — nil-client fallback branch. | mitre/adapter.go:50 |
| N-3 | `ComputeMaterialHash` at 88% — unreachable `jcs.Transform` error panic branch. | merge/hash.go |
| N-4 | `canonicalizeURL` at 92.3% — edge case URL parse failure branch. | merge/resolve.go |
| N-5 | `runQueue` at 87.5% — context cancellation timing edge case. | worker/pool.go |

3 additional: `fetchPage` (GHSA, 86.8%), `parseEntry` (MITRE, 83.3%), `parseEntry` (OSV, 83.3%).

### Assertion Quality Issues (5)

See §4 above for full details: AQ-1 through AQ-5.

### Key Observations

1. **Coverage desert: EPSS.** The EPSS adapter has the weakest coverage in Phase 1 (applyRow 0%, Apply 14.3%, integration test stubs all `t.Skip`). This is the most architecturally complex adapter — advisory locks, two-statement DB pattern, gzip streaming, CSV parsing — and it has effectively zero testing of its main execution path. This is the single highest-priority area for test investment.

2. **Duplicated `downloadToTemp`.** MITRE and OSV have near-identical implementations (same coverage percentage, same gaps). Extracting to `feed.DownloadToTemp()` in `util.go` would eliminate the duplication and halve the testing surface.

3. **Silent malformed-record discard.** NVD and GHSA silently `continue` past decode errors. This is likely intentional (resilience over strictness for large feeds), but without logging, operators cannot detect upstream data quality regressions. Adding a `slog.Warn` on the `continue` path would be low-effort, high-value.

4. **Worker stale recovery coverage gap.** `runStaleRecovery` is the safety net for jobs that crash mid-processing. At 53.8% coverage, neither the error-handling path nor the "recovered N jobs" logging path is verified. The test checks "stops on cancel" but not "actually recovers jobs."

5. **TOCTOU guard untested.** The advisory lock coordination between EPSS and merge is the linchpin of data integrity. Both sides correctly use `merge.CVEAdvisoryKey()`, but no integration test verifies that concurrent writes actually serialize. This is the most important functional test missing from the test suite.
