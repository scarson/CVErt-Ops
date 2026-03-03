# Phase 1 Coverage Review — Diff Analysis

**Date:** 2026-03-03
**Purpose:** Compare the original Phase 1 test coverage review (v1, skill without security checklist / depth threshold / operator variant rules) against the post-remediation re-review (v2, updated skill) to measure what the updated skill catches that v1 missed.

## Missing Test Files: Root Cause

**All Phase 1 remediation test files exist on `dev` but not `phase-5`.**

The three remediation commits were made on `dev`:
- `1800995` — Boolean coercion bug fix + ABOUTME
- `e881673` — 9 new test files, ~4,200 lines (pure function tests)
- `4e03a5d` — 28 Fetch-level integration tests, ~1,300 lines

`phase-5` was branched from a merge base (`838a065`) that predates these commits. The remediation work was never merged or cherry-picked into `phase-5`.

**Impact:** 9 test files with 92 test functions and 132 subtests exist on `dev` but are invisible on `phase-5`. This includes ALL feed adapter test files (ghsa, kev, mitre, nvd, osv), merge pipeline helper tests (advisory_test.go, fts_test.go, pipeline_helpers_test.go), and worker/pool_test.go. The `strings.EqualFold` boolean fix also only exists on `dev`.

**Action needed:** Merge `dev` into `phase-5` (or cherry-pick the three commits) to unify the test code.

---

## Headline Numbers

| Metric | Original (v1) | Re-review (v2) | Delta |
|--------|---------------|----------------|-------|
| Total gaps | 501 | 791 | +290 (+58%) |
| Security-critical | 34 | 66 | +32 (+94%) |
| Correctness | 401 | 640 | +239 (+60%) |
| Nice-to-have | 66 | 85 | +19 (+29%) |
| Files at 100% gap rate | 8 of 18 | 8 of 18 | same |
| Paths mapped | ~580 (est.) | 915 | +335 (+58%) |

The v2 review found **58% more total gaps** and **nearly doubled** the security-critical count.

---

## What the Updated Skill Caught That v1 Missed

### 1. Security Checklist (new in v2) — +32 security-critical gaps

The v1 skill had no mandatory per-endpoint security checklist. The v2 skill requires checking every API endpoint against 6 criteria. This caught:

| Category | v1 count | v2 count | New gaps found |
|----------|----------|----------|----------------|
| SQL parameterization per value type | 1 (FTS Q param) | 11 | +10 |
| Security header assertions | 5 | 8 | +3 |
| Unauthenticated access documentation | 0 | 3 | +3 |
| Boolean fail-open variants | 5 | 6 | +1 (`exploit_available="1"`) |
| cve_id input validation vectors | 2 (format) | 6 (format + null bytes + path traversal + SQL injection per endpoint) | +4 |
| Argon2 semaphore DoS | 2 (sizing + capacity) | 3 (sizing + available + full/non-blocking) | +1 |
| OAuth config (scopes, redirect) | 2 | 5 (GitHub redirect + scopes, Google redirect + scopes + OIDC retry) | +3 |
| GHSA auth header absent test | 1 | 1 | 0 |
| Advisory lock / TOCTOU | 2 | 7 | +5 |
| Material hash EPSS exclusion | 0 | 2 | +2 |

**Key finding:** The v1 review treated "SQL injection via Q parameter" as a single gap. The v2 review, with its per-value-type parameterization checklist, found that every filter parameter (Q, severity array, CWEID, ecosystem, package_name, cursor CVEID, cve_id path param × 2 endpoints, EPSSMin/Max, CVSSMin/Max) is a separate code path through squirrel that needs individual verification. This turned 1 gap into 11.

### 2. Operator Variant Rules (new in v2) — +~100 correctness gaps

v1 had no explicit rule about testing each variant separately. It often rolled similar items into categories:

| v1 approach | v2 approach | Example |
|-------------|-------------|---------|
| "Null bytes stripped from all fields" (1 gap per adapter) | Each field is a separate gap row | NVD: 6 fields × 1 gap = 6 gaps vs v1's 1 |
| "CVSS v3.1/v3.0/v4.0 precedence" (1 category) | Each score version, each guard condition, each severity path = separate rows | NVD applyNVDCVSS: 14 paths vs v1's ~4 |
| "Streaming JSON parsing" (1 category) | Each key case, each error path, each nested structure = separate rows | NVD parseNVDResponse: 18 paths vs v1's ~5 |
| "SearchCVEs filter branches" (1 summary) | Each filter (CVSSMin, CVSSMax, DateFrom, DateTo, CWEID, Ecosystem, EPSSMin, EPSSMax, InCISAKEV, ExploitAvail, cursor) = separate rows + combinations | 19 filter paths vs v1's "23 gaps" (but v1 undercounted because it rolled up) |

**Impact:** The v1 report said "~200 gaps for feed adapter parsing." The v2 report itemized 448 correctness gaps for the same adapters. The per-adapter detail went from ~40 gaps/adapter to ~70-90 gaps/adapter because each field extraction, dedup, and error path got its own row.

### 3. Depth Threshold (new in v2) — caught pipeline.go thoroughness

The v2 skill adds: "if a file has 500+ lines and you mapped fewer than 1 path per 25 lines, re-review."

| File | Lines | v1 paths mapped | v2 paths mapped | Ratio improvement |
|------|-------|-----------------|-----------------|-------------------|
| nvd/adapter.go | 568 | 62 | 106 | 1:9.2 → 1:5.4 |
| api/cves.go | 520 | 47 | 65 | 1:11.1 → 1:8.0 |
| merge/pipeline.go | 372 | 68 | 91 | 1:5.5 → 1:4.1 |
| api/server.go | 422 | 43 | 75 | 1:9.8 → 1:5.6 |

The depth threshold forced more thorough path mapping on all large files. server.go saw the biggest improvement (+32 paths, 74% increase).

### 4. "Covered (indirectly)" Prohibition (same in both, but v2 enforced more strictly)

Both versions of the skill prohibit marking paths as "Covered (indirectly)". However, v2 subagents were more rigorous about this:

- v1 counted `resolve.firstStr` as covered because resolve tests exercised it. v2 correctly flagged it as a GAP (8 paths).
- v1 counted `computeScoreDiverges` as covered via `TestResolveScoreDiverges*`. v2 flagged 7 dedicated-test-needed paths.
- v1 counted `canonicalizeURL` as partially covered. v2 flagged all 10 paths as GAPs (no dedicated test function exists).

**Impact:** ~25 paths that v1 considered "covered" were correctly re-categorized as GAPs.

---

## What v1 Caught That v2 Missed or Handled Differently

### v1 found the actual bug

v1 identified the boolean coercion bug (`in_cisa_kev == "true"` vs `strings.EqualFold`) as a real code defect. The remediation fixed it in commit `1800995`. v2 re-found the same gap because the fix only exists on `dev`, not `phase-5`. If `phase-5` had the fix, v2 would have missed it (the gap would have been "Covered").

### v1's "potential SQL bug" observation

v1 observation #2 identified that `cveColumns` uses `cves.cve_id` (table-qualified) but `SearchCVEs` uses `FROM "cves" c` (aliased). This was later confirmed as a real bug and fixed in commit `05b3a4c`. v2 did not independently discover this because it's a cross-file inconsistency that requires comparing column definitions to query construction — not a per-function path mapping issue.

### v1's `cloneStrings` duplication observation

v1 noted the duplicate `cloneStrings` implementations in MITRE and NVD. v2 noted it in passing but didn't flag it as prominently because the v2 skill focuses on test coverage, not code quality.

---

## Structural Differences Between Reports

| Aspect | v1 | v2 |
|--------|----|----|
| Subagent count | 1 (monolithic) | 5 (parallel) |
| Gap granularity | Rolled up by category | Each gap = 1 row |
| Null byte gaps | 5 (1 per adapter) | 20 (1 per field per adapter) |
| SQL injection gaps | 1 | 11 |
| CVSS paths per adapter | ~4-6 | ~14-20 |
| Security checklist | None | 6-point per endpoint |
| Depth verification | None | 1 path per 25 lines minimum |

---

## Adjusted Comparison (Normalizing for Branch Difference)

Since `phase-5` is missing all remediation test files, the v2 review reviewed against a pre-remediation codebase. To fairly compare the skill versions, we can estimate what v2 would have found if `dev` were the review target:

**Tests on `dev` that would close gaps:**
- Feed adapter test files (5 files, ~150 test functions): would close ~220 correctness + ~3 security-critical gaps
- merge/advisory_test.go: would close ~4 security-critical gaps (advisory key tests)
- merge/fts_test.go: would close 3 correctness gaps
- merge/pipeline_helpers_test.go: would close ~25 correctness gaps
- worker/pool_test.go: would close ~8 correctness gaps
- Boolean fix (1800995): would close 2 security-critical gaps
- NVD API key header test (4e03a5d): would close 1 security-critical gap

**Estimated v2 against `dev` branch:**

| Severity | v2 on phase-5 | Estimated v2 on dev | v1 original |
|----------|---------------|---------------------|-------------|
| Security-critical | 66 | ~56 | 34 |
| Correctness | 640 | ~381 | 401 |
| Nice-to-have | 85 | ~72 | 66 |
| **Total** | **791** | **~509** | **501** |

Even after normalizing for the missing tests, **v2 would still find ~22 more security-critical gaps** than v1 did. The security checklist, operator variant rules, and depth threshold each contribute unique findings that v1's approach structurally could not catch.

---

## Key Takeaways

1. **The security checklist is the highest-value addition.** It found 32 new security-critical gaps. The per-endpoint systematic check (SQL parameterization per value type, unauthenticated access documentation, security header assertions) catches gaps that per-function analysis structurally misses.

2. **Operator variant rules prevent gap undercounting.** v1's "~200 feed adapter gaps" became v2's 448 because each field, each error path, and each variant got its own row. This prevents the illusion that "5 gaps" is manageable when it's actually 40 distinct test cases.

3. **The depth threshold forces thoroughness on large files.** server.go went from 43 to 75 mapped paths (+74%). Without the threshold, reviewers naturally skim large files.

4. **Branch divergence is the biggest remediation gap.** 9 test files with 92 test functions exist on `dev` but not `phase-5`. This isn't a test coverage issue — it's a git workflow issue. The remediation work was done but never integrated.

5. **Both versions found the same 8 files at 100% gap rate.** The structural problem (no test files for NVD/MITRE/KEV/GHSA/OSV/pipeline/fts/advisory/worker) is unchanged. The v1 remediation added tests for all of these, but only on `dev`.
