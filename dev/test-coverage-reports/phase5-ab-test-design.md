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
