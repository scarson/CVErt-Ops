# Phase 1 Hybrid v2 Test Coverage Review

**Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`
**Date:** 2026-03-03
**Skill:** `/test-coverage-review-hybrid-go` (Run H — A/B test)
**Overall coverage:** 83.4% (statements)

---

## Coverage Baseline

| Package | Functions | 100% | 80–99% | 1–79% | 0% |
|---------|-----------|------|--------|-------|----|
| feed/epss | 4 | 2 | 0 | 1 | 1 |
| feed/ghsa | 5 | 3 | 2 | 0 | 0 |
| feed/kev | 5 | 3 | 1 | 1 | 0 |
| feed/mitre | 8 | 5 | 2 | 1 | 0 |
| feed/nvd | 11 | 5 | 4 | 1 | 1 |
| feed/osv | 7 | 4 | 2 | 1 | 0 |
| feed (util) | 5 | 5 | 0 | 0 | 0 |
| merge | 22 | 16 | 3 | 2 | 0 |
| worker | 6 | 4 | 1 | 1 | 0 |
| **Total** | **73** | **47** | **15** | **8** | **2** |

### Raw `go tool cover -func` output (§1 baseline)

```
internal/feed/epss/adapter.go:81    New                100.0%
internal/feed/epss/adapter.go:106   Apply               14.3%
internal/feed/epss/adapter.go:237   applyRow              0.0%
internal/feed/epss/adapter.go:282   parseLine1          100.0%
internal/feed/ghsa/adapter.go:74    New                 100.0%
internal/feed/ghsa/adapter.go:92    Fetch                85.2%
internal/feed/ghsa/adapter.go:148   fetchPage            86.8%
internal/feed/ghsa/adapter.go:220   parseLinkHeader     100.0%
internal/feed/ghsa/adapter.go:307   parseAdvisory       100.0%
internal/feed/kev/adapter.go:47     New                 100.0%
internal/feed/kev/adapter.go:64     Fetch                80.0%
internal/feed/kev/adapter.go:144    parseKEV             72.7%
internal/feed/kev/adapter.go:251    recordToPatch       100.0%
internal/feed/kev/adapter.go:285    extractCWEs         100.0%
internal/feed/mitre/adapter.go:50   New                  66.7%
internal/feed/mitre/adapter.go:71   Fetch                84.8%
internal/feed/mitre/adapter.go:146  isCVEEntry          100.0%
internal/feed/mitre/adapter.go:154  downloadToTemp       57.1%
internal/feed/mitre/adapter.go:192  parseEntry           83.3%
internal/feed/mitre/adapter.go:280  parseCVE5           100.0%
internal/feed/mitre/adapter.go:372  applyCVSS           100.0%
internal/feed/mitre/adapter.go:410  cloneStrings        100.0%
internal/feed/nvd/adapter.go:72     New                   0.0%
internal/feed/nvd/adapter.go:96     Fetch                85.2%
internal/feed/nvd/adapter.go:160    doRequest            90.0%
internal/feed/nvd/adapter.go:203    parseCursor         100.0%
internal/feed/nvd/adapter.go:218    zeroValueCursor      83.3%
internal/feed/nvd/adapter.go:234    computeNextCursor   100.0%
internal/feed/nvd/adapter.go:344    parseNVDResponse     70.6%
internal/feed/nvd/adapter.go:417    cveToCanonical       97.3%
internal/feed/nvd/adapter.go:499    applyNVDCVSS         96.7%
internal/feed/nvd/adapter.go:546    pickPreferred       100.0%
internal/feed/nvd/adapter.go:559    cloneStrings        100.0%
internal/feed/osv/adapter.go:53     New                 100.0%
internal/feed/osv/adapter.go:71     Fetch                81.8%
internal/feed/osv/adapter.go:137    isAdvisoryEntry     100.0%
internal/feed/osv/adapter.go:143    downloadToTemp       57.1%
internal/feed/osv/adapter.go:181    parseEntry           83.3%
internal/feed/osv/adapter.go:244    parseAdvisory       100.0%
internal/feed/osv/adapter.go:346    extractPackageRange 100.0%
internal/feed/util.go:23            ParseTime           100.0%
internal/feed/util.go:34            ParseTimePtr        100.0%
internal/feed/util.go:47            StripNullBytes      100.0%
internal/feed/util.go:52            StripNullBytesJSON  100.0%
internal/feed/util.go:67            ResolveCanonicalID  100.0%
internal/merge/advisory.go:20       advisoryKey         100.0%
internal/merge/advisory.go:33       CVEAdvisoryKey      100.0%
internal/merge/fts.go:7             JoinForFTS          100.0%
internal/merge/hash.go:49           ComputeMaterialHash  88.0%
internal/merge/hash.go:104          normalizeCVSSVector 100.0%
internal/merge/pipeline.go:35       Ingest               67.6%
internal/merge/pipeline.go:266      toNullString        100.0%
internal/merge/pipeline.go:270      toNullStringPtr     100.0%
internal/merge/pipeline.go:277      toNullFloat64       100.0%
internal/merge/pipeline.go:284      toNullTimePtr       100.0%
internal/merge/pipeline.go:291      toNullRawMessage    100.0%
internal/merge/pipeline.go:298      derefString         100.0%
internal/merge/pipeline.go:309      buildAffectedPkgKeys 100.0%
internal/merge/pipeline.go:323      buildCPEStrings     100.0%
internal/merge/pipeline.go:332      collectPackageNames 100.0%
internal/merge/pipeline.go:352      migrateCVEPK         71.4%
internal/merge/resolve.go:79        resolve              92.5%
internal/merge/resolve.go:275       firstStr            100.0%
internal/merge/resolve.go:295       firstStrPtr         100.0%
internal/merge/resolve.go:315       otherSources        100.0%
internal/merge/resolve.go:332       computeScoreDiverges 100.0%
internal/merge/resolve.go:357       canonicalizeURL      92.3%
internal/worker/pool.go:45          New                 100.0%
internal/worker/pool.go:54          Register            100.0%
internal/worker/pool.go:64          Start               100.0%
internal/worker/pool.go:94          runQueue             87.5%
internal/worker/pool.go:113         processOne          100.0%
internal/worker/pool.go:154         runStaleRecovery     53.8%
total:                              (statements)         83.4%
```

---

## Security Checklist Matrix

Phase 1 scope contains no org-scoped API endpoints — the standard per-endpoint security matrix (Cross-org, Unauth→401, orgID fail-closed, RBAC, Audit log) is **N/A**.

The adapted matrix below covers Phase 1's security-equivalent properties: data integrity coordination, input sanitization, streaming parse safety, and TOCTOU prevention.

| Component | Advisory Lock | Null-Byte Stripping | Streaming Parse Safety | Rate Limiting | TOCTOU Protection | Temp File Cleanup |
|-----------|--------------|---------------------|------------------------|--------------|-------------------|-------------------|
| EPSS adapter | **GAP** (applyRow 0% — lock acquisition untested) | Tested (TestParseLine1, Apply CSV path) | N/A (CSV, not JSON) | Tested (TestAdapterRateLimiterNonNil) | **GAP** (no integration test proves EPSS vs merge serialization) | N/A |
| GHSA adapter | N/A | Tested (TestParseAdvisory_NullByteStripping) | **GAP** (decode error silently skipped, no logging — line 201) | Tested (TestFetch_Success) | N/A | N/A |
| KEV adapter | N/A | Tested (TestRecordToPatch_NullByteStripping) | **GAP** (decode error aborts entire feed — inconsistent with other adapters) | Tested (TestFetch_Success) | N/A | N/A |
| MITRE adapter | N/A | Tested (TestParseCVE5_NullByteStripping) | Tested (parseEntry explicit close) | Tested (TestFetch_Success) | N/A | **GAP** (io.Copy failure cleanup path untested — downloadToTemp 57.1%) |
| NVD adapter | N/A | Tested (TestCVEToCanonical_NullByteStripping) | **GAP** (decode error silently skipped, no logging — line 391) | Tested (TestFetch_APIKeyHeader) | N/A | N/A |
| OSV adapter | N/A | **GAP** (ref.URL checked before StripNullBytes — line 326) | Tested (parseEntry explicit close) | Tested (TestFetch_Success) | N/A | **GAP** (io.Copy failure cleanup path untested — downloadToTemp 57.1%) |
| Merge pipeline | Tested (TestIngest_ConcurrentWriteSerializesCorrectly) | Tested (Ingest strips raw payload + normalized JSON) | N/A | N/A | Tested (advisory lock serializes concurrent CVE writes) | N/A |
| Worker pool | N/A | N/A | N/A | N/A | N/A | N/A |

**Matrix GAPs: 7** — all security-relevant data integrity concerns without test verification.

---

## Gap Context

| Category | Functions | Gaps | Action |
|----------|-----------|------|--------|
| Uncovered (0%) | 2 | 11 | Write integration tests (EPSS applyRow, NVD New) |
| Partial coverage (1–79%) | 8 | 36 | Add specific test cases for uncovered branches |
| Well-covered gaps (80–99%) | 15 | 18 | Add targeted edge case tests |
| Security matrix GAPs | 7 | 7 | Add security-specific data integrity tests |
| Assertion quality | 8 | 8 | Strengthen existing test assertions |
| Semantic analysis (bugs) | 4 | 4 | Fix code bugs |
| Cross-handler violations | 3 | 3 | Fix pattern inconsistencies |
| **Total** | | **87** | |

---

## What's Well-