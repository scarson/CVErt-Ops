# Phase 1 Test Coverage Review — Run K1 (Enhanced v4)

**Date:** 2026-03-03
**Scope:** `internal/feed/...`, `internal/merge/...`, `internal/worker/...`
**Skill variant:** test-coverage-review-go (Enhanced v4)
**Overall coverage:** 83.4% (statements)
**Functions in scope:** 73

## §1 Coverage Baseline

Raw `go tool cover -func` output (coverage-phase1-func.txt):

```
internal/feed/epss/adapter.go:81:    New                   100.0%
internal/feed/epss/adapter.go:106:   Apply                  14.3%
internal/feed/epss/adapter.go:237:   applyRow                0.0%
internal/feed/epss/adapter.go:282:   parseLine1            100.0%

internal/feed/ghsa/adapter.go:74:    New                   100.0%
internal/feed/ghsa/adapter.go:92:    Fetch                  85.2%
internal/feed/ghsa/adapter.go:148:   fetchPage              86.8%
internal/feed/ghsa/adapter.go:220:   parseLinkHeader       100.0%
internal/feed/ghsa/adapter.go:307:   parseAdvisory         100.0%

internal/feed/kev/adapter.go:47:     New                   100.0%
internal/feed/kev/adapter.go:64:     Fetch                  80.0%
internal/feed/kev/adapter.go:144:    parseKEV               72.7%
internal/feed/kev/adapter.go:251:    recordToPatch         100.0%
internal/feed/kev/adapter.go:285:    extractCWEs           100.0%

internal/feed/mitre/adapter.go:50:   New                    66.7%
internal/feed/mitre/adapter.go:71:   Fetch                  84.8%
internal/feed/mitre/adapter.go:146:  isCVEEntry            100.0%
internal/feed/mitre/adapter.go:154:  downloadToTemp         57.1%
internal/feed/mitre/adapter.go:192:  parseEntry             83.3%
internal/feed/mitre/adapter.go:280:  parseCVE5             100.0%
internal/feed/mitre/adapter.go:372:  applyCVSS             100.0%
internal/feed/mitre/adapter.go:410:  cloneStrings          100.0%

internal/feed/nvd/adapter.go:72:     New                     0.0%
internal/feed/nvd/adapter.go:96:     Fetch                  85.2%
internal/feed/nvd/adapter.go:160:    doRequest              90.0%
internal/feed/nvd/adapter.go:203:    parseCursor           100.0%
internal/feed/nvd/adapter.go:218:    zeroValueCursor        83.3%
internal/feed/nvd/adapter.go:234:    computeNextCursor     100.0%
internal/feed/nvd/adapter.go:344:    parseNVDResponse       70.6%
internal/feed/nvd/adapter.go:417:    cveToCanonical         97.3%
internal/feed/nvd/adapter.go:499:    applyNVDCVSS           96.7%
internal/feed/nvd/adapter.go:546:    pickPreferred         100.0%
internal/feed/nvd/adapter.go:559:    cloneStrings          100.0%

internal/feed/osv/adapter.go:53:     New                   100.0%
internal/feed/osv/adapter.go:71:     Fetch                  81.8%
internal/feed/osv/adapter.go:137:    isAdvisoryEntry       100.0%
internal/feed/osv/adapter.go:143:    downloadToTemp         57.1%
internal/feed/osv/adapter.go:181:    parseEntry             83.3%
internal/feed/osv/adapter.go:244:    parseAdvisory         100.0%
internal/feed/osv/adapter.go:346:    extractPackageRange   100.0%

internal/feed/util.go:23:            ParseTime             100.0%
internal/feed/util.go:34:            ParseTimePtr          100.0%
internal/feed/util.go:47:            StripNullBytes        100.0%
internal/feed/util.go:52:            StripNullBytesJSON    100.0%
internal/feed/util.go:67:            ResolveCanonicalID    100.0%

internal/merge/advisory.go:20:       advisoryKey           100.0%
internal/merge/advisory.go:33:       CVEAdvisoryKey        100.0%
internal/merge/fts.go:7:             JoinForFTS            100.0%
internal/merge/hash.go:49:           ComputeMaterialHash    88.0%
internal/merge/hash.go:104:          normalizeCVSSVector   100.0%
internal/merge/pipeline.go:35:       Ingest                 67.6%
internal/merge/pipeline.go:266:      toNullString          100.0%
internal/merge/pipeline.go:270:      toNullStringPtr       100.0%
internal/merge/pipeline.go:277:      toNullFloat64         100.0%
internal/merge/pipeline.go:284:      toNullTimePtr         100.0%
internal/merge/pipeline.go:291:      toNullRawMessage      100.0%
internal/merge/pipeline.go:298:      derefString           100.0%
internal/merge/pipeline.go:309:      buildAffectedPkgKeys  100.0%
internal/merge/pipeline.go:323:      buildCPEStrings       100.0%
internal/merge/pipeline.go:332:      collectPackageNames   100.0%
internal/merge/pipeline.go:352:      migrateCVEPK           71.4%
internal/merge/resolve.go:79:        resolve                92.5%
internal/merge/resolve.go:275:       firstStr              100.0%
internal/merge/resolve.go:295:       firstStrPtr           100.0%
internal/merge/resolve.go:315:       otherSources          100.0%
internal/merge/resolve.go:332:       computeScoreDiverges  100.0%
internal/merge/resolve.go:357:       canonicalizeURL        92.3%

internal/worker/pool.go:45:          New                   100.0%
internal/worker/pool.go:54:          Register              100.0%
internal/worker/pool.go:64:          Start                 100.0%
internal/worker/pool.go:94:          runQueue               87.5%
internal/worker/pool.go:113:         processOne            100.0%
internal/worker/pool.go:154:         runStaleRecovery       53.8%

total:                               (statements)           83.4%
```

### Package Summary

| Package | Functions | 0% | 1–79% | 80–99% | 100% |
|---------|-----------|-----|-------|--------|------|
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

## §2 Coverage Triage

### 0% Functions (2)

| Function | Lines | Risk | Notes |
|----------|-------|------|-------|
| epss/applyRow | 237–274 (37 lines) | **Security-critical** | Two-statement EPSS write pattern with advisory lock (PLAN.md §5.3). Integration test stubs exist but all `t.Skip("TODO")`. Paths: advisory lock acquisition, UpdateCVEEPSS (IS DISTINCT FROM), UpsertEPSSStaging (WHERE NOT EXISTS), tx commit/rollback. |
| nvd/New | 72–90 (19 lines) | Nice-to-have | Trivial constructor. Tests bypass by constructing `&Adapter{}` directly — reasonable approach. Env-var rate limiter config (6s vs 0.6s) untested but values are constants. |

### 1–79% Functions (9)

| Function | Coverage | Risk | Uncovered branches |
|----------|----------|------|--------------------|
| epss/Apply | 14.3% | **Correctness** | Only same-day cursor short-circuit tested. Entire HTTP download, gzip decompression, CSV parsing, row-by-row DB apply loop, model version change warning, all error paths — all untested. Integration test stubs all `t.Skip("TODO")`. |
| kev/parseKEV | 72.7% | Correctness | Non-string key branch (defensive, unreachable in practice), some error paths in streaming parser. Short-circuit path (catalogVersion match) IS tested. |
| mitre/New | 66.7% | Nice-to-have | Non-nil client branch. Tests always pass `nil`. |
| mitre/downloadToTemp | 57.1% | Correctness | Error cleanup paths: `io.Copy` failure (close+remove), `f.Seek` failure (close+remove). HTTP status error path exercised by TestFetch_HTTPError. |
| osv/downloadToTemp | 57.1% | Correctness | Identical gaps to mitre/downloadToTemp (code is duplicated). |
| nvd/parseNVDResponse | 70.6% | Correctness | Non-string JSON key branch (defensive, practically unreachable), some error branches in streaming navigation. Core parsing is well-tested. |
| merge/Ingest | 67.6% | **Correctness** | Core merge pipeline. Integration tests cover: material hash, PK migration, staged EPSS, tombstone, multi-source resolution, child table rewrite, FTS, advisory lock, raw payload, concurrent write. Uncovered branches likely in error paths (e.g., resolve error, marshal error, various DB operation errors). |
| merge/migrateCVEPK | 71.4% | Correctness | 7 sequential UPDATE statements; ~2 not reached in test fixture (likely tables with no rows for the test CVE). |
| worker/runStaleRecovery | 53.8% | **Correctness** | Actual recovery logic (ticker.C branch) never execised. staleCheckInterval = 1 minute, tests cancel after 50ms. Only ctx.Done() path covered. See §4 assertion quality. |

### 80–99% Functions — Key Gaps (16 functions)

Most gaps in this range are error paths that are difficult or impractical to trigger in tests (e.g., `http.NewRequestWithContext` failure with a constant URL, `json.Marshal` failure on a basic struct). Notable exceptions:

| Function | Coverage | Gap |
|----------|----------|-----|
| ghsa/Fetch | 85.2% | Cursor parse error, rate limiter error, cursor marshal error |
| ghsa/fetchPage | 86.8% | Request build error (unreachable), non-`[` response format, individual record decode skip |
| kev/Fetch | 80.0% | Rate limiter error, cursor marshal error |
| mitre/Fetch | 84.8% | Cursor parse error, tmpFile stat error, zip open error |
| osv/Fetch | 81.8% | Same gaps as mitre/Fetch |
| nvd/Fetch | 85.2% | Rate limiter error, cursor marshal error, both-timestamps-zero fallback to time.Now() |
| nvd/doRequest | 90.0% | NewRequestWithContext error (unreachable with constant URL) |
| nvd/zeroValueCursor | 83.3% | windowEnd.After(now) cap (epoch+120 days is always before now) |
| nvd/cveToCanonical | 97.3% | ~2 lines, likely minor edge cases |
| nvd/applyNVDCVSS | 96.7% | ~1 line, likely a guard condition already covered by another path |
| merge/ComputeMaterialHash | 88.0% | Nil-to-empty-slice conversions and/or panic paths (unreachable) |
| merge/resolve | 92.5% | Some source precedence edge cases, CPE with empty normalized |
| merge/canonicalizeURL | 92.3% | URL parse error fallback |
| worker/runQueue | 87.5% | ticker.C → processOne path (tests cancel before tick fires) |

### 100% Functions (46)

All utility functions, pure parsers, and helpers at 100%. Security-relevant 100% functions audited in §4.

## §3 Security Checklist Matrix

**N/A** — this scope contains no org-scoped API endpoints. The packages under review (feed adapters, merge pipeline, worker pool) are backend infrastructure that does not handle HTTP requests directly.

## §4 Assertion Quality Audit

### Issues Found

| # | Test | Anti-pattern | Description |
|---|------|-------------|-------------|
| 1 | worker/TestRunStaleRecovery_ErrorContinues | **Execution-only** | Claims to test error-continues behavior, but `staleCheckInterval = 1 minute` means the ticker never fires during the 50ms test window. `recoverFn` is **never called**. Test only verifies goroutine starts and stops — identical behavior to TestRunStaleRecovery_CallsRecoverAndStops. |
| 2 | worker/TestRunStaleRecovery_CallsRecoverAndStops | **Execution-only** | Same issue. `recoverCalls` counter is never incremented because ticker never fires. The variable name implies verification but the assertion is absent. |
| 3 | worker/TestRunQueue_ContextCancellationStops | **Side-effect coverage** | Cancels after 50ms, before the 2-second poll interval. `processOne` is never called via `runQueue` in this test. The `runQueue` → `processOne` path is only covered by direct `processOne()` calls elsewhere. |
| 4 | epss/TestApply_SameDayCursorSkips | **Missing negative** | Correctly tests the short-circuit path, but there is no corresponding test for the non-short-circuit path (yesterday's cursor → should proceed to download). The integration test stubs for this exist but are all `t.Skip`. |

### Verified Good Patterns

- **merge/hash_test.go**: Excellent assertion quality — tests determinism, field sensitivity, ordering independence, nil-vs-empty, and idempotency. 18+ focused test functions.
- **merge/resolve_test.go**: Comprehensive per-field source precedence tests. Each priority rule has a dedicated test (MITRE wins status, NVD wins CVSS, etc.). 30+ test functions.
- **nvd/adapter_test.go**: Strong behavioral assertions — checks correct CVE ID extraction, deduplication, null-byte stripping, CVSS source preference, pagination cursor computation.
- **kev/adapter_test.go**: Tests KEV-specific behaviors: short-circuit on catalog version match, date parsing, CWE extraction from JSONB, record decode error fatality.

## §4.5 Semantic Spot-Checks

### A. Cross-Adapter Consistency

**Pattern: Malformed record handling**
| Adapter | Behavior | Tested |
|---------|----------|--------|
| NVD | Silent skip (`continue`) | Yes (TestParseNVDResponse/malformed) |
| GHSA | Silent skip (`continue`) | Covered via side-effect |
| KEV | **Fatal error** (`return fmt.Errorf`) | Yes (TestParseKEV_RecordDecodeErrorIsFatal) |
| MITRE | Silent skip (via `parseEntry` error → `continue`) | Yes (TestFetch_MalformedEntrySkipped) |
| OSV | Silent skip (via `parseEntry` error → `continue`) | Not explicitly tested |

KEV is intentionally fatal (curated catalog — errors indicate real problems). The other adapters tolerate malformed records. OSV's malformed entry skip behavior lacks a dedicated test (the Fetch tests exercise parseEntry success, but no test sends a malformed JSON entry within the ZIP). **Correctness gap.**

**Pattern: Null-byte stripping**
All adapters call `feed.StripNullBytes` on string fields extracted from JSON. Verified in: NVD (TestCveToCanonical_NullByteStripping), GHSA (TestParseAdvisory_NullByteStripping), KEV (TestRecordToPatch_NullByteStripping), OSV (TestNullByteStripping), MITRE (TestParseCVE5_NullByteStripping). **Consistent and well-tested.**

**Pattern: `strings.Clone` on extracted data**
All adapters use `strings.Clone` for data extracted from large JSON responses (prevents retaining the full response buffer). Consistent across NVD, GHSA, KEV, MITRE, OSV. **Correct.**

**Pattern: User-Agent header**
| Adapter | Sets User-Agent |
|---------|----------------|
| EPSS | Yes (`CVErt-Ops/1.0 vulnerability intelligence platform`) |
| KEV | Yes (same) |
| NVD | No |
| GHSA | No (but sets `Accept` and `X-GitHub-Api-Version`) |
| MITRE | No |
| OSV | No |
Nice-to-have consistency issue. Not a correctness bug.

### B. Right-Function-Called

- **EPSS applyRow** calls `merge.CVEAdvisoryKey(cveID)` — **correct**, matches the same FNV hash key used by `merge.Ingest` (line 61). Verified by reading both call sites.
- **merge/Ingest** calls `CVEAdvisoryKey(patch.CVEID)` — **correct**.
- All adapters returning `feed.FetchResult` correctly set `SourceMeta.SourceName` to their package's `SourceName` constant. **Verified** across all 5 adapters + EPSS.

### C. Defense-in-Depth

Not directly applicable for this scope (no middleware/handler pattern). Feed adapters are backend workers, not HTTP handlers.

### Code Duplication Finding

**mitre/downloadToTemp and osv/downloadToTemp are identical functions** (same signature, same implementation, same 57.1% coverage). Both are package-private. This is a refactoring opportunity — a shared `feed.DownloadToTemp` function would consolidate the 34 lines and their test coverage. Not a bug but worth noting.

## §4.6 TOCTOU Analysis

### Multi-Step Flows Enumerated

| # | Flow | Steps | Guard | Window? | Tested? |
|---|------|-------|-------|---------|---------|
| 1 | EPSS applyRow | begin tx → advisory lock → Statement 1 → Statement 2 → commit | pg_advisory_xact_lock(CVEAdvisoryKey) | No (lock held throughout) | **NO (0% coverage)** |
| 2 | merge/Ingest PK migration | advisory lock on NEW ID → find old CVE by source ID → migrate old→new | Advisory lock on NEW ID + Postgres row-level locks | **Yes** (see below) | Partial (happy path only) |
| 3 | merge/Ingest read→resolve→upsert | read cve_sources → resolve → upsert cves | Advisory lock held throughout tx | No | Yes (integration tests) |
| 4 | merge/Ingest EPSS staging drain | GetEPSSStaging → UpdateCVEEPSS → DeleteEPSSStaging | Advisory lock + same tx | No | Yes (TestIngest_StagedEPSSApplied) |
| 5 | Worker job processing | ClaimJob → execute handler → CompleteJob/FailJob | Atomic UPDATE for claim | Worker crash window (5 min) | Claim: yes. Recovery: **assertion-only** |
| 6 | EPSS Apply same-day skip | read cursor → compare date → skip | N/A (scheduling boundary) | Midnight edge case | Yes (TestApply_SameDayCursorSkips) |
| 7 | KEV short-circuit | read catalogVersion → compare → skip | Single call, no concurrency | No | Yes (TestParseKEV_ShortCircuit) |
| 8 | NVD cursor advancement | Fetch → computeNextCursor → return | Single call | No | Yes |

### Temporal Window Details

**Window 2 — PK migration concurrent ingest:**
- `Ingest` acquires advisory lock on `CVEAdvisoryKey(patch.CVEID)` (the NEW CVE ID)
- `FindCVEBySourceID` finds the OLD CVE ID (e.g., GHSA-xxxx)
- `migrateCVEPK` updates all child tables from OLD → NEW ID
- **Gap**: A concurrent ingest for the OLD CVE ID acquires a *different* advisory lock (`CVEAdvisoryKey(oldCVEID)`). Both transactions can proceed simultaneously.
- **Mitigation**: Postgres row-level locks on the `cves` table serialize the conflicting UPDATEs. The PK migration's `UPDATE cves SET cve_id = $2 WHERE cve_id = $1` will block if another transaction holds a row lock.
- **Risk**: Low in practice (requires simultaneous ingest of the same advisory from different feed adapters during alias resolution). But the advisory lock design doesn't explicitly cover this case.
- **Test gap**: `TestIngest_MigrateCVEPK` tests single-writer PK migration. No concurrent PK migration test exists.

**Window 5 — Worker crash:**
- Between ClaimJob and CompleteJob/FailJob, a worker crash leaves the job in `running` state with a stale `locked_at`.
- `runStaleRecovery` resets these after 5 minutes — but the actual recovery logic is never exercised in tests (see §4 assertion quality issue #1–2).

## §5–7 Gap Summary and Final Report

### Gap Context

| Category | Files | Gaps | Action |
|----------|-------|------|--------|
| Uncovered (0%) | 1 | 2 | Create integration tests |
| Partial coverage | 7 | 9 | Add specific test cases |
| Security matrix GAPs | 0 | 0 | N/A (no endpoints) |
| Assertion quality | 2 | 4 | Fix test timing / add assertions |
| Semantic spot-checks | 3 | 3 | Add consistency tests |
| TOCTOU | 1 | 2 | Add concurrent tests |
| **Total** | | **20** | |

### What's Well-Covered

- **merge/resolve.go** (92.5%) — 30+ dedicated tests for per-field source precedence rules. Excellent coverage of priority logic, deduplication, and edge cases.
- **merge/hash.go** (88–100%) — Material hash determinism, field sensitivity, ordering independence, nil-vs-empty equivalence, and CVSS vector normalization. Exemplary test quality.
- **nvd/adapter.go cveToCanonical and applyNVDCVSS** (96–97%) — Thorough parsing tests with null-byte stripping, CWE/CPE deduplication, CVSS source preference, and edge case handling.
- **feed/util.go** (100%) — All utility functions fully covered with table-driven tests.
- **worker/processOne** (100%) — All execution paths tested: nil job, claim error, handler success, handler failure, FailJob error, CompleteJob error, nil handler.

### Production Bugs Discovered

None. No wrong-function-called or missing-side-effect bugs found in the semantic spot-checks. The code is well-structured and consistent.

### Security-Critical Gaps (3)

| # | Description | Location | Source |
|---|-------------|----------|--------|
| 1 | EPSS `applyRow` — advisory lock + two-statement write pattern completely untested. This is the core TOCTOU guard for EPSS/merge coordination (PLAN.md §5.3). | epss/adapter.go:237–274 | coverage |
| 2 | EPSS `Apply` — entire HTTP+gzip+CSV+DB pipeline untested (14.3% = only same-day skip path). Advisory lock coordination, IS DISTINCT FROM guard, and error handling all untested. | epss/adapter.go:106–228 | coverage |
| 3 | EPSS advisory lock coordination — the TOCTOU guard between EPSS and merge pipeline is untested. No test verifies that concurrent EPSS and merge writes are serialized. | epss/adapter.go:247 | TOCTOU |

### Correctness Gaps (12)

| # | Description | Location | Source |
|---|-------------|----------|--------|
| 1 | `worker/runStaleRecovery` actual recovery logic never exercised — ticker never fires during 50ms test window. Stale job reset (n > 0 logging, error handling) untested. | worker/pool.go:154–177 | assertion |
| 2 | `worker/runStaleRecovery` ErrorContinues test — `recoverFn` never called, test is functionally identical to CallsRecoverAndStops. | worker/pool_test.go:467–496 | assertion |
| 3 | `worker/runQueue` ticker.C → processOne path — only tested via direct `processOne()` calls, not through `runQueue`'s polling loop. | worker/pool.go:94–109 | assertion |
| 4 | `mitre/downloadToTemp` error cleanup paths — io.Copy failure and f.Seek failure cleanup (close + remove) untested. | mitre/adapter.go:175–186 | coverage |
| 5 | `osv/downloadToTemp` error cleanup paths — identical gaps to mitre (duplicated code). | osv/adapter.go:164–175 | coverage |
| 6 | `merge/migrateCVEPK` — some child table UPDATEs not reached in test fixture (~2 of 7). | merge/pipeline.go:352–378 | coverage |
| 7 | PK migration concurrent ingest — advisory lock on NEW ID doesn't explicitly serialize concurrent writers for the OLD ID. No concurrent test. | merge/pipeline.go:61–84 | TOCTOU |
| 8 | `kev/parseKEV` — non-string key branch, some error paths in streaming parser. | kev/adapter.go:144–248 | coverage |
| 9 | `nvd/parseNVDResponse` — defensive branches (non-string key), some error paths. | nvd/adapter.go:344–413 | coverage |
| 10 | `merge/Ingest` — error paths in DB operations (resolve error, various upsert/delete errors). | merge/pipeline.go:35–262 | coverage |
| 11 | OSV malformed ZIP entry skip behavior — no dedicated test sends a malformed JSON entry within the ZIP. | osv/adapter.go:112–116 | semantic |
| 12 | `epss/Apply` non-short-circuit path — no test for yesterday's cursor proceeding to download. | epss/adapter_test.go | assertion |

### Nice-to-Have (13 total, top 5 shown)

| # | Description | Location |
|---|-------------|----------|
| 1 | `nvd/New` (0%) — trivial constructor with env-var rate limiter. Tests bypass by constructing `&Adapter{}` directly. | nvd/adapter.go:72–90 |
| 2 | `mitre/New` (66.7%) — non-nil client branch untested. | mitre/adapter.go:50–59 |
| 3 | User-Agent header inconsistency — KEV and EPSS set it, NVD/GHSA/MITRE/OSV do not. | All adapter New/Fetch |
| 4 | `mitre/osv downloadToTemp` code duplication — identical 34-line functions in two packages. | mitre/adapter.go:154, osv/adapter.go:143 |
| 5 | Error paths unreachable with constant URLs — `http.NewRequestWithContext` failure in adapters with hardcoded URL constants. | Multiple adapters |

*(8 additional nice-to-have gaps: remaining adapter error paths for rate limiter errors, cursor marshal errors, and other defensive branches that cannot be triggered under normal operation.)*

### Assertion Quality Issues (4)

| # | Test | Issue | Fix |
|---|------|-------|-----|
| 1 | worker/TestRunStaleRecovery_CallsRecoverAndStops | Execution-only: `recoverCalls` counter never incremented because ticker (1 min) never fires in 50ms test window. | Replace `staleCheckInterval` with an injectable parameter or use a test-specific shorter interval. Assert `recoverCalls > 0`. |
| 2 | worker/TestRunStaleRecovery_ErrorContinues | Execution-only: `recoverFn` never called. Test claims to verify error-continues but is identical in behavior to test #1. | Same fix as #1. Additionally, verify that the goroutine survives at least one error cycle before being cancelled. |
| 3 | worker/TestRunQueue_ContextCancellationStops | Side-effect coverage: `processOne` never called via `runQueue`'s ticker. Only ctx.Done() path exercised. | Use injectable `pollInterval` or a shorter test interval to exercise at least one tick cycle. |
| 4 | epss/TestApply_SameDayCursorSkips | Missing negative: tests short-circuit but no test for the non-short-circuit path (stale cursor → proceed to download). | Add an httptest-based test with a yesterday's-date cursor that exercises the full download+parse path (requires DB or mock). |

## §6 Cross-Cutting Analysis

### Coverage Deserts

**EPSS adapter is a coverage desert.** Of 4 functions, 1 is at 0% (applyRow), 1 is at 14.3% (Apply), and only parseLine1 (100%) and New (100%) are covered. The entire database interaction path — advisory locking, two-statement write, transaction management — has zero test coverage. The integration test stubs exist but are all `t.Skip("TODO")`. This is the most significant systematic gap in Phase 1.

### Assertion Quality Pattern

**Worker pool timing-dependent tests are systematically shallow.** All three goroutine lifecycle tests (runStaleRecovery ×2, runQueue ×1) share the same flaw: they cancel context before any ticker fires, so the actual work loops are never exercised. The pattern `sleep(50ms) → cancel()` tests goroutine startup/shutdown but not the core loop behavior. The `processOne` function is well-tested via direct calls, but the integration between ticker → processOne is only verified by side-effect.

### Coverage ≠ Confidence Mismatch

**merge/Ingest at 67.6% understates confidence.** The function has 14 integration tests covering the core pipeline: material hash, PK migration, staged EPSS, tombstone, multi-source resolution, child tables, FTS, advisory lock, raw payload, concurrent writes. The ~32% uncovered code is almost entirely error paths (`fmt.Errorf` returns after DB operation failures). These error paths are important but secondary to the correctly-tested happy path and concurrent safety.

### TOCTOU Windows

Two temporal windows identified:
1. **EPSS advisory lock** (Window 1): The guard exists and is architecturally correct, but has zero test coverage. The TOCTOU race it prevents (concurrent EPSS + merge writes) is exactly the scenario described in PLAN.md §5.3.
2. **PK migration** (Window 2): The advisory lock on the NEW CVE ID doesn't explicitly serialize concurrent writers for the OLD CVE ID. Postgres row-level locks provide implicit protection, but this is defense-in-depth by accident rather than by design.

### Cross-Adapter Observations

- **downloadToTemp duplication**: mitre and osv have identical implementations. Consolidating into `feed.DownloadToTemp` would halve the test surface and eliminate the duplicated coverage gap.
- **All adapters share a consistent pattern** for: streaming JSON parse, null-byte stripping, strings.Clone, cursor-based pagination. This consistency is a project strength.
- **Malformed record handling divergence** (KEV=fatal, others=skip) is intentional and tested. Not a bug.

## Key Observations

1. **EPSS is the critical blind spot.** The two-statement write pattern with advisory locking is the most architecturally significant untested code in Phase 1. It implements the PLAN.md §5.3 TOCTOU guard — the absence of tests here means the core coordination between EPSS and merge pipeline is unverified.

2. **Worker ticker tests need timing control.** The pattern of testing goroutine loops by cancelling before the first tick produces execution-only coverage. An injectable interval (or a channel-based test clock) would allow tests to exercise the actual work path.

3. **The merge pipeline is the strongest area.** Despite 67.6% line coverage on `Ingest`, the 14 integration tests demonstrate thorough behavioral coverage of the pipeline's correctness invariants. The resolve.go and hash.go test suites are exemplary.

4. **No production bugs found.** Semantic spot-checks found no wrong-function-called or missing-side-effect issues. Cross-adapter consistency is strong. The codebase is well-structured.
