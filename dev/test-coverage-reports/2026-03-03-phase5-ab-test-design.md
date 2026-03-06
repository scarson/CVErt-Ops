# Phase 5 Coverage Review — A/B Test Design

**Date:** 2026-03-03
**Purpose:** Compare the enhanced `test-coverage-review-go` (v2) against `test-coverage-review-hybrid-go` on the same Phase 5 codebase that the original two skills already ran against.

---

## The Four Runs

| Run | Skill | Version | Status | Report file |
|-----|-------|---------|--------|-------------|
| A (baseline) | `test-coverage-review` | Original | Done | `2026-03-03-phase5-test-coverage-review.md` |
| B (baseline) | `test-coverage-review-go` | Original (pre-enhancement) | Done | `2026-03-03-phase5-coverage-tool-review.md` |
| C (test) | `test-coverage-review-go` | Enhanced (v2 — matrix + semantic spot-checks) | **To run** | `2026-03-03-phase5-enhanced-coverage-tool-review.md` |
| D (test) | `test-coverage-review-hybrid-go` | New | **To run** | `2026-03-03-phase5-hybrid-review.md` |

Runs A and B provide baselines. Runs C and D test whether the enhancements close the gaps identified in the diff analysis (`2026-03-03-phase5-diff-analysis.md`).

---

## What We're Measuring

### Primary question
Does the two-pass structural separation (hybrid, Run D) produce meaningfully different semantic analysis than bolting the same checks onto a single-pass skill (enhanced coverage-tool, Run C)?

### Secondary questions
1. Do both enhanced skills produce the security matrix? (Both should — this is the structural enforcement test)
2. Do both enhanced skills find the 2 production bugs that path-mapping found and the original coverage-tool missed?
   - BUG-1: Invitation handler missing audit log on tier block (`orgs.go:404-407`)
   - BUG-2: `org_tier.go:61` uses `CountMembersByOrg` instead of `CountMemberSlotsUsedByOrg`
3. How many cross-org isolation gaps does each find? (Path-mapping found 6, original coverage-tool found 1)
4. Do both catch the assertion quality issues? (Original coverage-tool found 3, path-mapping found 0)
5. Do the source tags on security-critical gaps differ in distribution?

### Scoring rubric

| Metric | Weight | How to score |
|--------|--------|--------------|
| Security matrix completeness | 25% | Did it produce the matrix? Are all cells filled? Count GAP cells found. |
| Production bugs found | 25% | Did it find BUG-1? BUG-2? Any new bugs? |
| Cross-org isolation gaps | 15% | Count. Compare to path-mapping's 6. |
| Assertion quality findings | 10% | Count. Compare to original coverage-tool's 3. |
| TOCTOU windows identified | 10% | Count. Compare to path-mapping's 2. |
| False positives | 10% | Any phantom files? Mischaracterized packages? Wrong severity? |
| Cross-handler consistency | 5% | Did it identify the audit-log-on-tier-block pattern and the violation? |

---

## Controlled Variables

Both runs MUST use identical:
- **Codebase state:** `dev` branch at current HEAD (commit after Phase 5 remediation)
- **Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
- **Coverage data:** Same `go test -coverprofile` + `go tool cover -func` output (run once, share with both)
- **Model:** Whatever the session defaults to (both in separate Claude Code sessions)

---

## Test Prompts

### Pre-step: Generate shared coverage data

Run this once before either test session. Save output to files that can be referenced.

```
Run coverage for Phase 5 scope and save the output:

go test -coverprofile=coverage-ab.out -coverpkg=./internal/api/...,./internal/store/...,./internal/tier/... -count=1 -timeout=300s ./internal/api/... ./internal/store/... ./internal/tier/...

go tool cover -func=coverage-ab.out > coverage-ab-func.txt

Save both files. These will be used as input for both A/B test runs.
```

### Run C: Enhanced coverage-tool

Start a new Claude Code session. Prompt:

```
Run /test-coverage-review-go on Phase 5 scope.

Scope: ./internal/api/..., ./internal/store/..., ./internal/tier/...

Coverage data has already been generated — use the files:
- coverage-ab.out (coverage profile)
- coverage-ab-func.txt (per-function coverage)

Read coverage-ab-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase5-enhanced-coverage-tool-review.md

This is a test of the skill's effectiveness. Follow the skill instructions exactly as written — do not skip any steps, especially the Security Checklist Matrix (§3) and Semantic Spot-Checks (§4.5). Every step matters for this evaluation.
```

### Run D: Hybrid

Start a new Claude Code session. Prompt:

```
Run /test-coverage-review-hybrid-go on Phase 5 scope.

Scope: ./internal/api/..., ./internal/store/..., ./internal/tier/...

Coverage data has already been generated — use the files:
- coverage-ab.out (coverage profile)
- coverage-ab-func.txt (per-function coverage)

Read coverage-ab-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase5-hybrid-review.md

This is a test of the skill's effectiveness. Follow the skill instructions exactly as written — do not skip any steps, especially the Security Checklist Matrix (§3) and Semantic Code Analysis (§4). Every step matters for this evaluation.
```

---

## Post-Test Analysis

After both runs complete, compare using the scoring rubric above. Create a comparison report at:
`dev/test-coverage-reports/2026-03-03-phase5-ab-test-results.md`

Structure:

```
## Scoring Summary

| Metric | Weight | Run A (path-mapping) | Run B (orig coverage) | Run C (enhanced coverage) | Run D (hybrid) |
|--------|--------|---------------------|----------------------|--------------------------|----------------|
| Security matrix | 25% | N/A | N/A | ... | ... |
| Production bugs | 25% | 2 | 0 | ... | ... |
| Cross-org gaps | 15% | 6 | 1 | ... | ... |
| Assertion quality | 10% | 0 | 3 | ... | ... |
| TOCTOU windows | 10% | 2 | 0 | ... | ... |
| False positives | 10% | 23+ | 0 | ... | ... |
| Cross-handler | 5% | Yes (BUG-1) | No | ... | ... |

## Key Findings
- Did the matrix prevent the false-sense-of-security problem?
- Did the semantic spot-checks/analysis find the production bugs?
- Does structural separation (hybrid) produce different results than bolt-on (enhanced)?
- Any new findings neither baseline caught?

## Recommendation
- Which skill to use going forward
- Whether to retire any of the three Go coverage skills
```

---

## Execution Notes

- Run C and D in **separate Claude Code sessions** so they don't share context
- Do NOT mention the other skill or the A/B test within either session — each should run the skill cold
- The "follow the skill instructions exactly" sentence is intentional — it counters the tendency to shortcut under time pressure without revealing that this is a test of compliance
- Both sessions should use the same model (check with `/model` at start)
- If either session hits context limits and compresses, note this — it may affect cross-handler analysis quality

---

## Runs E and F: Post-Improvement Validation

**Date added:** 2026-03-03
**Purpose:** Validate that the 8 targeted improvements (derived from C/D analysis) close the specific gaps each skill exhibited.

### The Six Runs (Updated)

| Run | Skill | Version | Status | Report file |
|-----|-------|---------|--------|-------------|
| A (baseline) | `test-coverage-review` | Original | Done | `phase5-test-coverage-review.md` |
| B (baseline) | `test-coverage-review-go` | Original (pre-enhancement) | Done | `phase5-coverage-tool-review.md` |
| C (test) | `test-coverage-review-go` | Enhanced v2 (matrix + semantic) | Done | `phase5-enhanced-coverage-tool-review.md` |
| D (test) | `test-coverage-review-hybrid-go` | Hybrid v1 | Done | `phase5-hybrid-review.md` |
| E (validation) | `test-coverage-review-go` | Enhanced v3 (8 improvements) | **To run** | `phase5-enhanced-v3-review.md` |
| F (validation) | `test-coverage-review-hybrid-go` | Hybrid v2 (8 improvements) | **To run** | `phase5-hybrid-v2-review.md` |

Runs A-D established baselines and identified failure modes. Runs E-F test whether targeted improvements close those failure modes.

---

### What Changed Between C→E and D→F

**Both skills (5 improvements):**
1. **Audit log column** — 7th matrix column for audit trail completeness (success AND denial paths)
2. **Cite-test-name** — "Tested" cells must cite exact `TestFunctionName`; if you can't name it → GAP
3. **Route enumeration** — read router setup, list all endpoints, build matrix from that list, verify count
4. **Spot-check verification** — pick 3 random "Tested" cells, read the cited test, verify it tests the claimed property
5. **Conditional assertion emphasis** — flagged as "most dangerous anti-pattern" with Phase 5 example

**Enhanced skill only (1 improvement):**
6. **TOCTOU promoted to §4.6** — dedicated section with scarcity gate requiring enumeration of all multi-step flows before concluding "no TOCTOU"

**Hybrid skill only (2 improvements):**
7. **Matrix completeness gate** — explicit row-count vs endpoint-count verification before starting Pass 2
8. **Subagent matrix delegation** — for 15+ endpoint scopes, subagents may construct matrix rows with main-agent merge/verification/spot-check

---

### Primary Question

**Do the targeted improvements close the specific gaps identified in the C/D comparison?**

This is a regression test for skill design, not a general capability comparison. Each improvement has a testable prediction (see hypotheses table below). The question is answered by checking each prediction against the E/F outputs.

### Testable Hypotheses

| # | Improvement | Run E prediction | Run F prediction | How to verify |
|---|------------|-----------------|-----------------|---------------|
| H1 | Audit log column | Catches BUG-1 (invitation tier-block audit) via "Audit log" GAP cell. Run C missed this. | Maintains BUG-1 detection AND adds audit-specific GAP cells. | Check audit log column for invitation endpoint. |
| H2 | Cite-test-name | Fewer false "Tested" marks. Resolves ≥4 of the 7 C/D disputed endpoints (either by citing a real test or marking GAP). | Same. | Compare E/F matrix against C/D disputed endpoints table. For each "Tested" cell, verify the cited test function exists and tests the claimed property. |
| H3 | Route enumeration | All org-scoped endpoints present. Endpoint count stated explicitly. | GET /sso/link now present (Run D omitted it entirely). Endpoint count stated explicitly. Row count vs endpoint count verified. | Count matrix rows. Compare against `server.go` route registration. |
| H4 | Spot-check | Spot-check performed (3 cells verified). At least 1 cell corrected from "Tested" to GAP if the cited test doesn't match. | Same. | Check report for spot-check section. |
| H5 | Conditional assertion | Tier middleware conditional assertion identified. | Tier middleware conditional assertion identified. | Search findings for conditional assertion. |
| H6 | TOCTOU §4.6 | Finds ≥1 TOCTOU window (Run C found 0, wrote "No TOCTOU windows detected"). Multi-step flow enumeration present in output. | N/A — Run D already found 3. Maintains or improves. | Count TOCTOU findings. Check for multi-step flow enumeration. |
| H7 | Matrix completeness gate | N/A | Explicit "X endpoints enumerated, X matrix rows" verification in report between Pass 1 and Pass 2. | Search report for count verification. |
| H8 | Subagent matrix delegation | N/A | If scope triggers subagent dispatch, matrix quality is maintained (no regression vs Run D). | Compare matrix completeness/accuracy vs Run D. |

**Success criteria:** ≥6 of 8 hypotheses confirmed. If ≤4 confirmed, the improvements need redesign.

---

### Scoring Rubric v2

The original v1 rubric (used for Runs A-D) is preserved in the results document for historical comparison. Runs E-F will be scored on BOTH rubrics — v1 for direct comparison against C/D, and v2 for measuring the specific improvements.

**v1 rubric** (same as Runs A-D — 7 metrics, see original design above)

**v2 rubric** (9 metrics — splits matrix into completeness + accuracy, adds audit log column):

| Metric | Weight | How to score | What it measures |
|--------|--------|--------------|------------------|
| Production bugs found | 20% | BUG-1? BUG-2? New bugs? | Core detection ability. Audit log column should help catch BUG-1. |
| Matrix completeness | 10% | Route enumeration performed? All endpoints present? Row count verified? Explicit count in output? | Route enumeration + completeness gate. |
| Matrix accuracy | 15% | "Tested" cells cite exact test function names? Spot-check performed? Score against the 7 disputed endpoints from C/D. | Cite-test-name + spot-check improvements. |
| Cross-org isolation gaps | 10% | Count. Compare to C's 21 and D's 14. | Matrix thoroughness. |
| Assertion quality findings | 10% | Count. Conditional assertion specifically found? | Conditional assertion emphasis. |
| TOCTOU windows identified | 10% | Count. Multi-step flow enumeration present? "No TOCTOU" without enumeration = 0. | TOCTOU promotion (enhanced v3). |
| False positives | 10% | Phantom files? Mischaracterized packages? False GAPs? False "Tested" marks? | Overall accuracy. Cite-test-name should reduce false "Tested". |
| Cross-handler consistency | 5% | Audit-log-on-tier-block pattern identified? All sibling handlers compared? | Semantic analysis depth. |
| Audit log gap detection | 10% | Count of audit-specific findings from the 7th column. Did it surface gaps beyond what cross-handler analysis found? | New column value-add over existing checks. |

---

### Controlled Variables

Runs E and F MUST use identical conditions to Runs C and D:
- **Codebase state:** `dev` branch. No source code changes to `internal/api/...`, `internal/store/...`, or `internal/tier/...` since C/D (last source change: `4c8062a`). Verify with `git log --oneline --diff-filter=M -- "internal/api/*.go" "internal/store/*.go" "internal/tier/*.go"` before running.
- **Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`
- **Coverage data:** Same `coverage-ab.out` and `coverage-ab-func.txt` files used for C/D (73.5% overall, 560 functions). Do NOT re-generate.
- **Model:** Same as C/D (check with `/model` at start of each session)
- **Sessions:** Separate Claude Code sessions, no cross-contamination

**If source code HAS changed** since C/D (e.g., remediation commits), STOP. Either (a) re-generate coverage data at current HEAD and note the deviation, or (b) check out the C/D commit (`4c8062a` or later doc-only commit) and run from there. Option (b) is preferred for clean comparison.

---

### Test Prompts

#### Pre-step: Verify controlled variables

Before either run, in a shell (NOT in the test session):

```
# Verify no source changes since C/D
git log --oneline --diff-filter=M -- "internal/api/*.go" "internal/store/*.go" "internal/tier/*.go" | head -3
# Should show 4c8062a as most recent

# Verify coverage data files exist
ls -la coverage-ab.out coverage-ab-func.txt
```

#### Run E: Enhanced coverage-tool v3

Start a new Claude Code session. Prompt:

```
Run /test-coverage-review-go on Phase 5 scope.

Scope: ./internal/api/..., ./internal/store/..., ./internal/tier/...

Coverage data has already been generated — use the files:
- coverage-ab.out (coverage profile)
- coverage-ab-func.txt (per-function coverage)

Read coverage-ab-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase5-enhanced-v3-review.md

This is a test of the skill's effectiveness. Follow the skill instructions exactly as written — do not skip any steps, especially the Security Checklist Matrix (§3), TOCTOU Analysis (§4.6), and Semantic Spot-Checks (§4.5). Every step matters for this evaluation.
```

**Note:** The prompt now mentions §4.6 (TOCTOU) — this is the key new section. The "follow exactly" instruction counters shortcutting without revealing this is a comparative test.

#### Run F: Hybrid v2

Start a new Claude Code session. Prompt:

```
Run /test-coverage-review-hybrid-go on Phase 5 scope.

Scope: ./internal/api/..., ./internal/store/..., ./internal/tier/...

Coverage data has already been generated — use the files:
- coverage-ab.out (coverage profile)
- coverage-ab-func.txt (per-function coverage)

Read coverage-ab-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase5-hybrid-v2-review.md

This is a test of the skill's effectiveness. Follow the skill instructions exactly as written — do not skip any steps, especially the Security Checklist Matrix (§3) and Semantic Code Analysis (§4). Every step matters for this evaluation.
```

---

### Post-Test Analysis

After both runs complete:

1. **Score on v1 rubric** — direct comparison against C/D. Fill in the E/F columns in the historical scoring table.
2. **Score on v2 rubric** — measures improvement-specific capabilities.
3. **Check each hypothesis** — mark confirmed/refuted with evidence.
4. **Resolve the 7 disputed endpoints** — E/F should produce cited test names for each. Compare E vs F, then verify against actual test files.
5. **Update recommendation** — does the hybrid still win? Did the enhanced skill close its TOCTOU gap?

Structure for the updated results document:

```
## Scoring Summary v1 (Historical — Runs A-F)
[Original rubric with E/F columns added]

## Scoring Summary v2 (Runs E-F Only)
[New rubric scores]

## Hypothesis Results
| # | Prediction | Run E result | Run F result | Confirmed? |

## Disputed Endpoint Resolution
[The 7 endpoints, with E/F citations, ground-truth verification]

## Updated Recommendation
[Based on all 6 runs]
```

---

### Execution Notes

- Same isolation rules as C/D: separate sessions, no mention of A/B test or other runs
- The prompt intentionally calls out §4.6 for Run E — this is the section most likely to be skipped (it was nonexistent in Run C's skill version)
- Both sessions should use the same model (check with `/model` at start)
- If either session hits context limits, note this — compare compaction timing vs C/D
- The subagent matrix delegation (improvement #8) will only activate if scope is 15+ endpoints. Phase 5 scope has ~25-30 org-scoped endpoints, so it SHOULD trigger for Run F if subagents are dispatched. If Run F runs without subagents (main-agent only), H8 is untestable and should be marked N/A

---

## Runs G and H: Phase 1 Generalization Test

**Date added:** 2026-03-03
**Purpose:** Test whether improvements generalize beyond the Phase 5 codebase they were designed against. Phase 1 code (feed adapters, merge pipeline, worker pool) has fundamentally different patterns — data ingestion, shared interfaces, advisory locking — with zero overlap to the Phase 5 RBAC/SSO/audit handlers used in Runs A-F.

### Why Phase 1?

Runs E-F test regression: do improvements work on the code they were designed for? But skills tuned on Phase 5 might only work on Phase 5 patterns. Phase 1 provides:

- **Different code patterns:** Feed adapters share an interface (not HTTP handlers). Merge pipeline uses advisory locks and multi-step transactions (not middleware + RBAC). Worker pool manages goroutine lifecycles (not request/response).
- **No org-scoped API endpoints:** CVE endpoints are global (`/api/v1/cves/...`). The security matrix section is N/A — this tests whether skills handle non-API scope gracefully.
- **Real TOCTOU surface:** The merge pipeline's advisory locking, EPSS two-statement pattern, and FNV hash locks are genuine temporal risks — not hypothetical timing windows.
- **Cross-handler consistency via interfaces:** All 6 feed adapters implement `FeedAdapter`. Pattern violations (e.g., one adapter doesn't handle rate limiting, one doesn't stream) are cross-handler bugs in a different domain.

### The Eight Runs (Updated)

| Run | Skill | Version | Scope | Status | Report file |
|-----|-------|---------|-------|--------|-------------|
| A-D | (see above) | — | Phase 5 | Done | (see above) |
| E | `test-coverage-review-go` | Enhanced v3 | Phase 5 | **To run** | `phase5-enhanced-v3-review.md` |
| F | `test-coverage-review-hybrid-go` | Hybrid v2 | Phase 5 | **To run** | `phase5-hybrid-v2-review.md` |
| G | `test-coverage-review-go` | Enhanced v3 | **Phase 1** | **To run** | `phase1-enhanced-v3-review.md` |
| H | `test-coverage-review-hybrid-go` | Hybrid v2 | **Phase 1** | **To run** | `phase1-hybrid-v2-review.md` |

### Phase 1 Scope

```
internal/feed/...    — 6 feed adapters + shared interface + util
internal/merge/...   — merge pipeline, resolve, hash, FTS, advisory locking
internal/worker/...  — worker pool lifecycle, job queue
```

These packages are Phase 1-only with zero overlap to Phase 5's `internal/api/...`, `internal/store/...`, `internal/tier/...`. The CVE API handlers (`api/cves.go`) are excluded to keep the scope cleanly distinct.

**What's different from Phase 5:**

| Dimension | Phase 5 | Phase 1 |
|-----------|---------|---------|
| Primary code pattern | HTTP handlers + middleware | Interface implementations + pipelines |
| Org-scoped endpoints | ~25-30 | 0 |
| Security matrix applicable? | Yes (core test) | No (N/A — no org-scoped endpoints) |
| TOCTOU surface | SSO redirect/callback, tier races | Advisory locks, EPSS staging, pipeline steps |
| Cross-handler dimension | Sibling HTTP handlers (audit, tier) | Sibling interface implementations (6 adapters) |
| Assertion quality risk | Conditional assertions in middleware tests | Shallow assertions in adapter/pipeline tests |

---

### Primary Question (G/H)

**Do the semantic analysis improvements generalize to non-API code with different patterns?**

The matrix improvements (audit log column, cite-test-name, route enumeration, spot-check) are untestable on Phase 1 — there are no org-scoped endpoints. This is by design: G/H isolate the semantic improvements for a clean generalization test.

### Testable Hypotheses (G/H)

| # | Improvement | Run G prediction (enhanced v3) | Run H prediction (hybrid v2) | How to verify |
|---|------------|-------------------------------|------------------------------|---------------|
| G1 | TOCTOU §4.6 | Finds ≥1 temporal window in merge pipeline (advisory lock, EPSS two-statement, pipeline step ordering). Multi-step flow enumeration present. | Same — Run D's TOCTOU section found 3 in Phase 5; Phase 1 has comparable surface area. | Count TOCTOU findings. Check for pipeline multi-step flow analysis. |
| G2 | Cross-handler consistency | Identifies shared patterns across 6 feed adapters (error handling, rate limiting, streaming parse, alias resolution). Flags violations where one adapter doesn't follow the pattern. | Same. | Check whether all 6 adapters are compared. Count pattern violations found. |
| G3 | Assertion quality | Identifies shallow assertions in feed/merge tests. Conditional assertion anti-pattern check applied. | Same. | Count assertion quality findings. |
| G4 | Wrong-function-called | Identifies incorrect function usage in merge/store interactions (analogous to Phase 5's CountMembersByOrg vs CountMemberSlotsUsedByOrg). | Same. | Count wrong-function-called findings. |
| G5 | Non-API scope handling | Matrix section correctly marked N/A or adapted (not fabricated with fake endpoints). No forced application of org-scoped patterns to global code. | Same. | Check whether skill over-applies matrix to non-API code. |
| G6 | Structural separation (hybrid only) | N/A | Hybrid's two-pass structure produces more semantic findings than enhanced's single-pass, even on non-API code. | Compare G vs H finding counts by category. |

**Success criteria:** ≥4 of 6 hypotheses confirmed (G5 and G6 are meta-hypotheses about skill behavior, not bug-finding).

---

### Controlled Variables (G/H)

- **Codebase state:** Same `dev` branch HEAD as Runs E-F
- **Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`
- **Coverage data:** New files — `coverage-phase1.out` and `coverage-phase1-func.txt` — generated once, shared with both runs. Do NOT reuse Phase 5 coverage data.
- **Model:** Same as E/F (check with `/model`)
- **Sessions:** Separate Claude Code sessions, no cross-contamination, no mention of Phase 5 runs

---

### Pre-step: Generate Phase 1 Coverage Data

Run once before G/H sessions:

```bash
go test -coverprofile=coverage-phase1.out \
  -coverpkg=./internal/feed/...,./internal/merge/...,./internal/worker/... \
  -count=1 -timeout=300s \
  ./internal/feed/... ./internal/merge/... ./internal/worker/...

go tool cover -func=coverage-phase1.out > coverage-phase1-func.txt
```

Save both files. Note the overall coverage percentage and function count for the results document.

---

### Test Prompts (G/H)

#### Run G: Enhanced coverage-tool v3 on Phase 1

Start a new Claude Code session. Prompt:

```
Run /test-coverage-review-go on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Coverage data has already been generated — use the files:
- coverage-phase1.out (coverage profile)
- coverage-phase1-func.txt (per-function coverage)

Read coverage-phase1-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-enhanced-v3-review.md

This is a test of the skill's effectiveness. Follow the skill instructions exactly as written — do not skip any steps, especially the TOCTOU Analysis (§4.6) and Semantic Spot-Checks (§4.5). Note: this scope has no org-scoped API endpoints, so the Security Checklist Matrix (§3) should be adapted or marked N/A. Every step matters for this evaluation.
```

**Note:** The prompt explicitly mentions the lack of org-scoped endpoints. This prevents the skill from wasting analysis time fabricating a matrix and focuses it on semantic analysis — which is what we're testing.

#### Run H: Hybrid v2 on Phase 1

Start a new Claude Code session. Prompt:

```
Run /test-coverage-review-hybrid-go on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Coverage data has already been generated — use the files:
- coverage-phase1.out (coverage profile)
- coverage-phase1-func.txt (per-function coverage)

Read coverage-phase1-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-hybrid-v2-review.md

This is a test of the skill's effectiveness. Follow the skill instructions exactly as written — do not skip any steps, especially the Security Checklist Matrix (§3) and Semantic Code Analysis (§4). Note: this scope has no org-scoped API endpoints, so the Security Checklist Matrix should be adapted or marked N/A. Every step matters for this evaluation.
```

---

### Post-Test Analysis (G/H)

After G and H complete:

1. **Check each G-hypothesis** — mark confirmed/refuted with evidence
2. **Compare G vs H** — does structural separation still matter on non-API code? (G6)
3. **Compare Phase 5 vs Phase 1 findings** — do the skills find comparable density of issues? Different types?
4. **Identify Phase 1-specific bugs** — any genuine production bugs discovered? (No benchmark bugs planted — everything is a genuine discovery)
5. **Skill adaptation assessment** — how did each skill handle the missing matrix? Gracefully or awkwardly?

### Scoring Rubric (G/H)

Phase 1 uses a reduced rubric — matrix-specific metrics are N/A:

| Metric | Weight | How to score |
|--------|--------|--------------|
| Production bugs / design violations | 25% | Wrong function called, missing side effects, pattern violations. No benchmark bugs — everything is genuine discovery. |
| TOCTOU windows | 20% | Count. Multi-step flow enumeration performed? Advisory lock analysis? |
| Cross-handler consistency | 20% | Feed adapter pattern comparison (all 6 compared?). Merge step consistency. Pattern violations found. |
| Assertion quality | 15% | Count. Conditional assertion check applied? Shallow assertion identification? |
| False positives | 10% | Fabricated endpoints, mischaracterized packages, wrong coverage data interpretation. |
| Non-API adaptation | 10% | Matrix correctly N/A? No forced org-scoped analysis on global code? |

---

### Execution Notes (G/H)

- Same isolation rules: separate sessions, no mention of other runs
- G/H MUST run AFTER E/F — if E/F reveal skill bugs, fix them before running G/H
- The prompt tells the skill that org-scoped endpoints don't exist — watch whether the skill reads and respects this or ignores it
- Phase 1 has many functions at 0% coverage (all 6 feed adapters). This tests whether the skills handle 0% functions efficiently (one row per function with risk classification, not exhaustive branch enumeration)
- If either session hits context limits, note this — Phase 1 has fewer functions than Phase 5 (560), so compaction is less likely

---

## Runs I5, J5, K1, L1: Retry with Context-Efficient Prompts

**Date added:** 2026-03-03
**Purpose:** Re-run all four test conditions (enhanced v3 + hybrid v2 × Phase 5 + Phase 1) with updated skill prompts designed to avoid the context exhaustion that truncated Run H and may have degraded Run E's semantic analysis. Also validates any skill changes made after scoring Runs E/G/H.

### Why Retry?

Runs E-H produced useful data but had execution problems:

| Prior run | Problem | Impact on scoring |
|-----------|---------|-------------------|
| E (enhanced v3, Phase 5) | 3/7 false "Tested" marks; missed BUG-2 | v1 score 7.35 — below D's 8.85. BUG-2 miss may be random variance or skill defect. |
| F (hybrid v2, Phase 5) | Never executed | H7, H8 untestable. No Phase 5 hybrid v2 data at all. |
| G (enhanced v3, Phase 1) | Clean execution, highest score (9.05) | Baseline for comparison. Re-run validates consistency. |
| H (hybrid v2, Phase 1) | Truncated at 141 lines | Estimated score 6.55†. Missing: bugs, assertions, TOCTOU, observations. |

The retry addresses two classes of issue:
1. **Context exhaustion** (H truncated, possibly affected E quality) — mitigated by prompt changes
2. **Skill defects** (cite-test-name false positives, audit column not triggering cross-handler analysis) — mitigated by skill updates

### The Twelve Runs (Updated)

| Run | Skill | Version | Scope | Status | Report file |
|-----|-------|---------|-------|--------|-------------|
| A–D | (see above) | — | Phase 5 | Done | (see above) |
| E–H | (see above) | v3 / hybrid v2 | Phase 5 + Phase 1 | Done (E,G) / Missing (F) / Truncated (H) | (see above) |
| I5 | `test-coverage-review-go` | Enhanced v4 | Phase 5 | Done | `phase5-enhanced-v4-review.md` |
| J5 | `test-coverage-review-hybrid-go` | Hybrid v3 | Phase 5 | Done | `phase5-hybrid-v3-review.md` |
| K1 | `test-coverage-review-go` | Enhanced v4 | **Phase 1** | Done (retry) | `phase1-enhanced-v4-review.md` |
| L1 | `test-coverage-review-hybrid-go` | Hybrid v3 | **Phase 1** | Done | `phase1-hybrid-v3-review.md` |

### What Changed Between E→I5/K1 and H→J5/L1

**Skill changes** (list specific changes made to skill files after E/G/H scoring):

| # | Change | Skill | Addresses which E/G/H failure? |
|---|--------|-------|-------------------------------|
| S1 | Added Context Management section with scope-size heuristics table (small <100 functions: no subagents; medium 100–300: 2 max; large 300–600: 3 max, incremental report; XL 600+: split into sub-scopes) | Both | H truncation (73 functions = small scope, subagents may have added unnecessary overhead). E quality degradation (559 functions = large scope, needed incremental writing). |
| S2 | File-based subagent output: subagents write full analysis to temp file (`subagent-{scope}-findings.md`), return only file path + severity counts + top 3 findings (~200 tokens vs ~30,000 per subagent) | Both | Subagent results flooding main agent context. With 3 subagents, this reduces context intake from ~90K tokens to ~600 tokens. |
| S3 | Incremental report writing: write report skeleton at start, append matrix section immediately after completion, append each analysis section as completed, write summary last | Both | H truncated at "What's Well-Covered" — lost production bugs, assertion quality, TOCTOU, and key observations sections. With incremental writing, completed sections are persisted regardless of context exhaustion. |
| S4 | Targeted reads: use line-range reads (`Read lines 86-115`) instead of full files; use Grep with `head_limit` to cap search result size | Both | General context pressure across all large-scope runs. Every tool result enters context — minimizing input size is the only lever the agent controls. |
| S5 | Expanded subagent prompt template with structured output format (per-function table, not prose) and explicit file-based output location | Both | Standardizes subagent behavior. Prevents ad-hoc subagent responses that vary in verbosity and format. |
| S6 | Incremental reading: process one package at a time (read source+test → analyze → write findings → next package). Do NOT read all source/test files upfront. Cross-adapter notes accumulate in the report, not in context. | Both | K1 died reading 17 files simultaneously before writing any output. Even small scopes (<100 functions) can exhaust context by reading all files at once. |

**Prompt changes** (context exhaustion mitigations — see test prompts below):

| # | Change | Rationale |
|---|--------|-----------|
| P1 | "Write each major section to the report file as you complete it" | Prevents losing analysis if context runs out during report generation |
| P2 | "For the matrix, use compact format: T(TestName) for tested cells, GAP(reason) for gaps" | Reduces token count in the largest section |
| P3 | "Limit nice-to-have gaps to a count + top 5 examples" | Run G listed 53 nice-to-haves — massive token sink with low value |
| P4 | "If you hit context pressure, prioritize completing the report over adding more detail" | Explicit priority: finished report > thorough report |

---

### Primary Question (I5/J5/K1/L1)

**Do the retried runs produce more accurate and complete results than E/G/H?**

This is a regression test AND improvement test:
- I5 vs E: Does the enhanced skill find BUG-2? Are the 3 false "Tested" marks fixed?
- J5 vs D: Does hybrid v2 on Phase 5 extend D's 8.85 lead? (First Phase 5 hybrid v2 data)
- K1 vs G: Consistency check — does enhanced v4 match G's 9.05 on the same code?
- L1 vs H: Does the hybrid complete without truncation? Does it match or beat G/K1?

### Testable Hypotheses

| # | Prediction | Run | How to verify |
|---|-----------|-----|---------------|
| I1 | I5 finds BUG-2 (wrong count function) — E missed it | I5 | Search report for CountMembersByOrg / CountMemberSlotsUsedByOrg |
| I2 | I5 resolves ≥5/7 disputed endpoints correctly (E got 4/7) | I5 | Compare against ground truth table from results doc |
| I3 | I5 TOCTOU maintained: ≥3 windows (E found 3) | I5 | Count TOCTOU findings. Regression if < 3 |
| J1 | J5 finds both BUG-1 AND BUG-2 (D found both) | J5 | Search report for both benchmark bugs |
| J2 | J5 completes without truncation (Run F never ran) | J5 | Report file exists and has ≥200 lines |
| J3 | J5 scores ≥8.5 on v1 rubric (matching D's 8.85) | J5 | Score on v1 rubric |
| K1h | K1 finds ≥1 of G's 2 production bugs (ParseTime, PK migration) | K1 | Search for RFC1123 / migrateCVEPK |
| K2 | K1 assertion quality count ≥8 (G found 10) | K1 | Count. Regression if < 8 |
| L1h | L1 completes without truncation (H truncated at 141 lines) | L1 | Report file exists and ends with a complete section |
| L2 | L1 TOCTOU: ≥2 windows (H's truncation hid this section) | L1 | Count TOCTOU findings |
| L3 | L1 adapted matrix present (H's adapted matrix was excellent) | L1 | Check for domain-specific matrix columns |

**Success criteria:** ≥8 of 11 hypotheses confirmed.

---

### Controlled Variables

**Phase 5 (I5, J5):**
- **Codebase state:** `dev` branch at current HEAD. Verify no source changes to `internal/api/...`, `internal/store/...`, `internal/tier/...` since E/F/G/H
- **Coverage data:** Same `coverage-ab.out` and `coverage-ab-func.txt` (73.5% overall, 559 functions). Do NOT re-generate
- **Scope:** `./internal/api/...`, `./internal/store/...`, `./internal/tier/...`

**Phase 1 (K1, L1):**
- **Codebase state:** Same `dev` branch HEAD as I5/J5
- **Coverage data:** Same `coverage-phase1.out` and `coverage-phase1-func.txt` (83.4% overall, 73 functions). Do NOT re-generate
- **Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`

**Both:**
- **Model:** Same as E/G/H (check with `/model` at start)
- **Sessions:** Separate Claude Code sessions, no cross-contamination, no mention of A/B test or prior runs

### Pre-step: Verify Controlled Variables

Before any run:

```bash
# Verify no source changes since E/G/H
git log --oneline --diff-filter=M -- "internal/api/*.go" "internal/store/*.go" "internal/tier/*.go" "internal/feed/**/*.go" "internal/merge/*.go" "internal/worker/*.go" | head -5

# Verify coverage data files exist
ls -la coverage-ab.out coverage-ab-func.txt coverage-phase1.out coverage-phase1-func.txt
```

If source code HAS changed, re-generate coverage data and note the deviation.

---

### Test Prompts

#### Run I5: Enhanced v4 on Phase 5

```
Run /test-coverage-review-go on Phase 5 scope.

Scope: ./internal/api/..., ./internal/store/..., ./internal/tier/...

Coverage data has already been generated — use the files:
- coverage-ab.out (coverage profile)
- coverage-ab-func.txt (per-function coverage)

Read coverage-ab-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase5-enhanced-v4-review.md

IMPORTANT — write each major section (Coverage Baseline, Security Matrix, Gap Analysis, TOCTOU, Assertion Quality, Key Observations) to the report file as you complete it. Do not wait until the end to write the full report. This prevents losing work if the session runs long.

For the matrix, use compact format: T(TestName) for tested cells, GAP(reason) for gaps. Do not write prose descriptions of tested cells.

Limit nice-to-have gaps to a count and top 5 examples.

Follow the skill instructions exactly — do not skip any steps, especially the Security Checklist Matrix (§3), TOCTOU Analysis (§4.6), and Semantic Spot-Checks (§4.5). Every step matters.
```

#### Run J5: Hybrid v3 on Phase 5

```
Run /test-coverage-review-hybrid-go on Phase 5 scope.

Scope: ./internal/api/..., ./internal/store/..., ./internal/tier/...

Coverage data has already been generated — use the files:
- coverage-ab.out (coverage profile)
- coverage-ab-func.txt (per-function coverage)

Read coverage-ab-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase5-hybrid-v3-review.md

IMPORTANT — write each major section to the report file as you complete it, using the Edit tool to append. Do not accumulate the entire report in memory. This is critical for avoiding context exhaustion on large scopes.

For the security matrix, use compact format: T(TestName) for tested cells, GAP(reason) for gaps. Do not write prose descriptions of tested cells.

Limit nice-to-have gaps to a count and top 5 examples. If you feel context pressure, prioritize completing all sections over adding exhaustive detail to any one section.

Follow the skill instructions exactly — do not skip any steps, especially the Security Checklist Matrix (§3) and Semantic Code Analysis (§4). Every step matters.
```

#### Run K1: Enhanced v4 on Phase 1

```
Run /test-coverage-review-go on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Coverage data has already been generated — use the files:
- coverage-phase1.out (coverage profile)
- coverage-phase1-func.txt (per-function coverage)

Read coverage-phase1-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-enhanced-v4-review.md

IMPORTANT — write each major section to the report file as you complete it. Do not wait until the end.

This scope has no org-scoped API endpoints, so the Security Checklist Matrix (§3) should be marked N/A. Focus analysis on TOCTOU (§4.6), cross-adapter consistency, and assertion quality.

Limit nice-to-have gaps to a count and top 5 examples.

Follow the skill instructions exactly — do not skip any steps. Every step matters.
```

#### Run L1: Hybrid v3 on Phase 1

```
Run /test-coverage-review-hybrid-go on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Coverage data has already been generated — use the files:
- coverage-phase1.out (coverage profile)
- coverage-phase1-func.txt (per-function coverage)

Read coverage-phase1-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-hybrid-v3-review.md

IMPORTANT — write each major section to the report file as you complete it, using the Edit tool to append. Do not accumulate the entire report in memory. This is the #1 priority — a complete shorter report is far more valuable than a detailed truncated one.

This scope has no org-scoped API endpoints. The Security Checklist Matrix (§3) should be adapted for data pipeline concerns (advisory locks, streaming parse safety, null-byte stripping, temp file cleanup) OR marked N/A — do not fabricate org-scoped endpoints.

Limit nice-to-have gaps to a count and top 5 examples.

Follow the skill instructions exactly — do not skip any steps. Every step matters.
```

---

### Scoring Rubrics

**Phase 5 (I5, J5):** Score on both v1 and v2 rubrics (same as E/F). Add columns to the existing scoring tables.

**Phase 1 (K1, L1):** Score on the Phase 1 reduced rubric (same as G/H). Add columns to the existing scoring table.

**All runs:** Also score against the hypothesis table above.

---

### Post-Test Analysis

After all four runs complete:

1. **Score on rubrics** — fill in I5/J5/K1/L1 columns in the results document
2. **Check hypotheses** — mark each confirmed/refuted with evidence
3. **Disputed endpoints** — verify I5/J5 against the ground truth table (all 7 are GAPs)
4. **Context exhaustion** — did J5 and L1 complete? Note line counts vs H's 141
5. **Consistency** — K1 vs G: does the same skill on the same code produce similar results?
6. **Delta analysis** — for each run, compute deltas against the prior version (I5 vs E, J5 vs D, K1 vs G, L1 vs H)

Structure for results:

```
## Runs I5/J5/K1/L1: Retry Results

### Execution Status
| Run | Lines | Truncated? | Context compaction? |

### Scoring (Phase 5 — v1 rubric, adding I5/J5 columns)
[Existing table with new columns]

### Scoring (Phase 5 — v2 rubric, adding I5/J5 columns)
[Existing table with new columns]

### Scoring (Phase 1 — reduced rubric, adding K1/L1 columns)
[Existing table with new columns]

### Hypothesis Results
| # | Prediction | Result | Evidence | Confirmed? |

### Consistency Analysis (K1 vs G)
[Side-by-side comparison of findings]

### Delta Analysis
| Metric | E→I5 | D→J5 | G→K1 | H→L1 |

### Updated Recommendation
[Based on all 12 runs]
```

---

### Execution Notes

- Same isolation rules: separate sessions, no mention of A/B test or prior runs
- Run order: I5 and K1 first (enhanced), then J5 and L1 (hybrid). If enhanced runs reveal new skill bugs, fix before hybrid runs
- The "write incrementally" instruction is the key context exhaustion mitigation. Watch whether each skill actually writes to the file incrementally or accumulates in memory
- If any run still truncates despite the prompt changes, note the line count and which section was being written — this identifies whether the bottleneck is analysis or report generation
- The compact matrix format ("T(TestName)" vs prose) should significantly reduce Phase 5 token usage — Phase 5 has 72 endpoints × 7 columns = 504 cells. At ~20 tokens per prose cell vs ~5 tokens for compact, this saves ~7,500 tokens in the matrix alone

---

## Runs M1, N1: Phase 1 Small-Scope Fix

**Date added:** 2026-03-03
**Purpose:** Re-test Phase 1 with a targeted fix for the small-scope regression identified in K1/L1 scoring. S7 adds a scope-size exception to the incremental reading rule: scopes with <100 functions may read all source files before analysis, restoring the cross-package pattern recognition that made Run G the highest-scoring run (9.05).

### Why Retry?

K1 and L1 regressed sharply compared to G, despite using skills with more improvements (S1-S6). Root cause analysis identified S6 (incremental reading for ALL scopes) as the culprit:

| Prior run | Score | Problem | Root cause |
|-----------|-------|---------|------------|
| G (enhanced v3, Phase 1) | 9.05 | Best run overall — found 2 production bugs, 10 assertion quality issues | Read all 73 functions into context simultaneously → cross-package pattern recognition enabled |
| K1 (enhanced v4, Phase 1) | 5.85 | 0 production bugs, 4 assertion quality issues | S6 forced per-package reading → couldn't compare adapters side-by-side → missed ParseTime RFC1123 bug |
| L1 (hybrid v3, Phase 1) | 5.50 | 0 genuine production bugs, 1 assertion quality issue | Same S6 constraint → lost cross-adapter visibility |

The fix is surgical: S7 changes "Incremental reading (ALL scopes)" to "Incremental reading (medium+ scopes, ≥100 functions)" and adds an explicit small-scope rule allowing holistic file reading for <100-function scopes.

### The Fourteen Runs (Updated)

| Run | Skill | Version | Scope | Status | Report file |
|-----|-------|---------|-------|--------|-------------|
| A–D | (see above) | — | Phase 5 | Done | (see above) |
| E–H | (see above) | v3 / hybrid v2 | Phase 5 + Phase 1 | Done (E,G) / Missing (F) / Truncated (H) | (see above) |
| I5 | `test-coverage-review-go` | Enhanced v4 | Phase 5 | Done | `phase5-enhanced-v4-review.md` |
| J5 | `test-coverage-review-hybrid-go` | Hybrid v3 | Phase 5 | Done | `phase5-hybrid-v3-review.md` |
| K1 | `test-coverage-review-go` | Enhanced v4 | Phase 1 | Done | `phase1-enhanced-v4-review.md` |
| L1 | `test-coverage-review-hybrid-go` | Hybrid v3 | Phase 1 | Done | `phase1-hybrid-v3-review.md` |
| M1 | `test-coverage-review-go` | Enhanced v5 | **Phase 1** | Done | `phase1-enhanced-v5-review.md` |
| N1 | `test-coverage-review-hybrid-go` | Hybrid v4 | **Phase 1** | Done | `phase1-hybrid-v4-review.md` |

### What Changed Between K1→M1 and L1→N1

| # | Change | Skill | Addresses which K1/L1 failure? |
|---|--------|-------|-------------------------------|
| S7 | Scope-size exception for incremental reading: changed "ALL scopes" to "medium+ scopes (≥100 functions)". For small scopes (<100 functions), read all SOURCE files before analysis (for cross-package pattern recognition), but read TEST files one package at a time during triage. Explicit 4-step workflow: (1) coverage data → (2) all source files → (3) per-package test reading + triage + write findings → (4) cross-cutting analysis. | Both | K1 and L1 found 0 production bugs because per-package reading prevented comparing adapters side-by-side. G found 2 bugs by holding all 73 functions in context. S7 restores G's holistic source reading for small scopes while preventing the context exhaustion that killed M1's first attempt (which loaded all source AND test files simultaneously). |

**Note:** M1's first attempt died from context exhaustion despite the original S7 wording ("read all source files before analysis"). The skill interpreted this as "read everything" and loaded 13 source files + 10 test files, exhausting context. S7 was refined to explicitly distinguish source files (load all upfront for pattern recognition) from test files (load per-package during triage — they don't contribute to cross-package visibility).

This is a single-variable test: only S7 changed. All other S1-S6 improvements and P1-P4 prompt mitigations remain identical to K1/L1.

---

### Primary Question (M1/N1)

**Does restoring holistic file reading for small scopes recover the production-bug-finding capability lost in K1/L1?**

This is a controlled regression test. G (enhanced v3, no S1-S6) scored 9.05 with holistic reading. K1 (enhanced v4, with S1-S6 including restrictive S6) scored 5.85 with per-package reading. M1 (enhanced v5, S1-S6 plus S7 exception) should recover toward G's level if S6 was the root cause.

Secondary question: Does the hybrid skill also benefit from holistic reading on small scopes, or does its two-pass structure provide enough cross-package visibility regardless?

### Testable Hypotheses

| # | Prediction | Run | How to verify |
|---|-----------|-----|---------------|
| M1h | M1 finds ≥1 of G's 2 production bugs (ParseTime RFC1123, PK migration) | M1 | Search report for RFC1123 / migrateCVEPK. K1 found 0; G found 2. |
| M2 | M1 assertion quality count ≥8 (G found 10, K1 found 4) | M1 | Count assertion quality findings. |
| M3 | M1 TOCTOU count ≥4 (G found 8, K1 found 8 — TOCTOU was unaffected by S6) | M1 | Count. TOCTOU should remain stable since it's per-flow analysis. |
| M4 | M1 cross-adapter consistency identifies patterns across all 6 adapters | M1 | Check whether all 6 adapters are compared in cross-handler analysis. K1 compared them but missed pattern violations. |
| M5 | M1 v1-equivalent score ≥7.5 (recovering from K1's 5.85 toward G's 9.05) | M1 | Score on Phase 1 reduced rubric. |
| N1h | N1 finds ≥1 production bug (L1 found 0) | N1 | Search report for production bugs. |
| N2 | N1 cross-adapter consistency improves over L1 | N1 | Compare pattern violation counts: L1 had limited cross-adapter findings. |
| N3 | N1 completes without truncation (L1 completed at 450 lines — this should be stable) | N1 | Report file ends with a complete section. |
| N4 | N1 v1-equivalent score ≥6.5 (recovering from L1's 5.50) | N1 | Score on Phase 1 reduced rubric. |

**Success criteria:** ≥6 of 9 hypotheses confirmed. The critical ones are M1h and M5 — if the small-scope exception doesn't restore production bug detection, the root cause analysis was wrong.

---

### Controlled Variables

- **Codebase state:** Same `dev` branch HEAD as K1/L1. Verify no source changes to `internal/feed/...`, `internal/merge/...`, `internal/worker/...`
- **Coverage data:** Same `coverage-phase1.out` and `coverage-phase1-func.txt` (83.4% overall, 73 functions). Do NOT re-generate
- **Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`
- **Model:** Same as K1/L1 (check with `/model` at start)
- **Sessions:** Separate Claude Code sessions, no cross-contamination, no mention of A/B test or prior runs

### Pre-step: Verify Controlled Variables

Before either run:

```bash
# Verify no source changes since K1/L1
git log --oneline --diff-filter=M -- "internal/feed/**/*.go" "internal/merge/*.go" "internal/worker/*.go" | head -5

# Verify coverage data files exist
ls -la coverage-phase1.out coverage-phase1-func.txt
```

---

### Test Prompts

#### Run M1: Enhanced v5 on Phase 1

```
Run /test-coverage-review-go on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Coverage data has already been generated — use the files:
- coverage-phase1.out (coverage profile)
- coverage-phase1-func.txt (per-function coverage)

Read coverage-phase1-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-enhanced-v5-review.md

IMPORTANT — write each major section to the report file as you complete it. Do not wait until the end.

This scope has no org-scoped API endpoints, so the Security Checklist Matrix (§3) should be marked N/A. Focus analysis on TOCTOU (§4.6), cross-adapter consistency, and assertion quality.

Limit nice-to-have gaps to a count and top 5 examples.

Follow the skill instructions exactly — do not skip any steps. Every step matters.
```

#### Run N1: Hybrid v4 on Phase 1

```
Run /test-coverage-review-hybrid-go on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Coverage data has already been generated — use the files:
- coverage-phase1.out (coverage profile)
- coverage-phase1-func.txt (per-function coverage)

Read coverage-phase1-func.txt and use it as your §1 output. Do NOT re-run go test.

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-hybrid-v4-review.md

IMPORTANT — write each major section to the report file as you complete it, using the Edit tool to append. Do not accumulate the entire report in memory. This is the #1 priority — a complete shorter report is far more valuable than a detailed truncated one.

This scope has no org-scoped API endpoints. The Security Checklist Matrix (§3) should be adapted for data pipeline concerns (advisory locks, streaming parse safety, null-byte stripping, temp file cleanup) OR marked N/A — do not fabricate org-scoped endpoints.

Limit nice-to-have gaps to a count and top 5 examples.

Follow the skill instructions exactly — do not skip any steps. Every step matters.
```

---

### Scoring Rubric

Score on the Phase 1 reduced rubric (same as G/H/K1/L1):

| Metric | Weight | How to score |
|--------|--------|--------------|
| Production bugs / design violations | 25% | Wrong function called, missing side effects, pattern violations. No benchmark bugs — everything is genuine discovery. |
| TOCTOU windows | 20% | Count. Multi-step flow enumeration performed? Advisory lock analysis? |
| Cross-handler consistency | 20% | Feed adapter pattern comparison (all 6 compared?). Merge step consistency. Pattern violations found. |
| Assertion quality | 15% | Count. Conditional assertion check applied? Shallow assertion identification? |
| False positives | 10% | Fabricated endpoints, mischaracterized packages, wrong coverage data interpretation. |
| Non-API adaptation | 10% | Matrix correctly N/A? No forced org-scoped analysis on global code? |

---

### Post-Test Analysis

After both runs complete:

1. **Score on Phase 1 reduced rubric** — add M1/N1 columns to the existing G/H/K1/L1 table
2. **Check hypotheses** — mark each confirmed/refuted with evidence
3. **Delta analysis** — M1 vs K1 vs G, N1 vs L1 vs H. Three-way comparison isolates S7's effect
4. **Production bug detection** — did holistic reading restore the ability to find ParseTime RFC1123? This is the key diagnostic
5. **Cross-adapter pattern analysis** — did having all adapters in context improve pattern violation detection?
6. **Root cause validation** — if M1 recovers to G-level scores, S6 was confirmed as the K1/L1 regression root cause. If M1 still regresses, other factors (S1-S5, prompt changes P1-P4) are also contributing

Structure for results:

```
## Runs M1/N1: Small-Scope Fix Results

### Execution Status
| Run | Lines | Truncated? | Context compaction? |

### Scoring (Phase 1 — reduced rubric, adding M1/N1 columns)
[Existing table with new columns — now G, H, K1, L1, M1, N1]

### Hypothesis Results
| # | Prediction | Result | Evidence | Confirmed? |

### Root Cause Validation
[Did S7 fix the K1/L1 regression? Three-way comparison: G vs K1 vs M1]

### Delta Analysis
| Metric | K1→M1 | L1→N1 | G→M1 (target: ~0) |

### Updated Recommendation
[Based on all 14 runs — does scope-size-aware context management resolve the trade-off?]
```

---

### Execution Notes

- Same isolation rules: separate sessions, no mention of A/B test or prior runs
- Run M1 first (enhanced). If it reveals new skill bugs, fix before N1
- The test prompts are identical to K1/L1 — the only difference is the skill version (S7). This makes it a clean single-variable test
- Watch specifically for: does the skill actually read all source files upfront (as S7 allows for small scopes), or does it still process incrementally? If it still processes incrementally despite S7, the exception wording may need strengthening
- G scored 9.05 with no S1-S6 at all. M1 has S1-S5 plus S7. If M1 matches G, S7 was sufficient. If M1 exceeds G, S1-S5 add value on top of holistic reading. If M1 is between K1 and G, S7 partially helps but other S1-S5 changes still interfere
