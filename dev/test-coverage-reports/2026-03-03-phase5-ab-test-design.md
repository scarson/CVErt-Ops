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
