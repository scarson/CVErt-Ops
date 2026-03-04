# Code Bug Hunter Skill — Design & Test Plan

**Date:** 2026-03-03
**Status:** Design complete, awaiting implementation

## Motivation

The coverage review skills (test-coverage-review-go, test-coverage-review-hybrid-go) excel at systematic gap enumeration on large scopes (Phase 5: I5 scored 9.45, J5 scored 9.25) but consistently fail to find production bugs on small scopes (Phase 1: K1 scored 5.85, M1 scored 6.20 — both found 0 bugs). The one run that found bugs on Phase 1 was G (enhanced v3, score 9.05, 2 production bugs) — which used an earlier skill version with no structural guardrails.

The coverage review skills optimize for **test completeness**: what code paths lack tests? The bug hunter optimizes for **code correctness**: what code does the wrong thing?

These are complementary tools, not replacements. The coverage skill tells you where to write tests. The bug hunter tells you where the code is broken.

## Shared Foundation

### Input

A scope (package paths or file list). Source code only — no coverage data, no test files.

### Core Instruction

Read the code in scope and find bugs. A "bug" is code that does the wrong thing — not code that lacks tests.

### What Counts as a Finding

- A function whose implementation contradicts its contract or documented behavior
- A pattern followed by N siblings but violated by one
- A multi-step flow where failure at step K causes silent data loss or corruption
- A concurrency assumption that doesn't hold (races, TOCTOU, lock ordering gaps)
- An error that's swallowed, loses context, or propagates to the wrong layer

### What is NOT a Finding

This is the critical boundary — the skill must not drift into coverage review:

- Code that is correct but untested
- Low coverage percentages or missing test cases
- Weak assertions in existing tests
- Style, naming, or refactoring opportunities
- Hypothetical issues in code that's provably unreachable

**The distinction:** this skill judges **the code's correctness**, not **the tests' completeness**. If a function does the right thing but has no tests, that's not a bug. If a function has 100% test coverage but silently drops errors, that IS a bug.

### Output Format

```
# Bug Hunt Report

## Scope
[Packages/files analyzed. Brief note on analysis approach taken.]

## Bugs
### [Title — what's wrong]
**Location:** file:line
**Severity:** critical / significant / minor
**Evidence:** [What the code does vs what it should do]
**Impact:** [What goes wrong in practice]

(Repeat for each bug. If zero bugs found, say so.)

## Design Concerns
[Patterns that increase bug risk — fragile assumptions, missing
coordination, dangerous defaults. NOT coverage gaps, NOT style
suggestions, NOT refactoring ideas.]
```

Each finding requires specific file/line evidence. No findings without proof. Zero bugs is a valid result — don't pad.

### Skill Brevity Principle

Each variant's skill text should be SHORT (2-3 pages max). Every additional instruction reduces analytical freedom. The coverage review skills degraded from v3→v5 precisely because accumulating structural instructions constrained the LLM's analytical style. The bug hunter avoids this by design.

---

## Three Variants

### Variant A: Holistic (`code-bug-hunter-holistic`)

**Reading strategy:** Read ALL source files in scope before any analysis. No incremental processing. Get everything in context first.

**Analysis approach:** After reading, examine the codebase as a whole. Look across files for contract mismatches, pattern violations, and failure modes. No prescribed order — follow whatever threads seem most productive.

**Key instruction:** "You have the entire codebase in context. Your job is to find things that are wrong. Read every source file, then think about what could break. Don't enumerate — investigate."

**Strengths:** Directly mirrors G's approach. Maximum cross-file visibility. Minimal structural overhead.

**Risks:** No guidance means the LLM might produce a superficial scan rather than deep analysis. G had the coverage skill's section structure pushing it toward TOCTOU/cross-handler analysis; the holistic variant has nothing pushing it anywhere.

### Variant B: Multi-pass (`code-bug-hunter-multipass`)

**Reading strategy:** Read files relevant to each strategy pass. May re-read files across passes.

**Analysis approach:** Five focused passes, one per bug type:

1. Read all files → identify function contracts → check implementations against contracts
2. Read sibling implementations (adapters, handlers) → compare patterns → find violations
3. Read multi-step flows (pipelines, transactions) → reason about failure at each step
4. Read concurrent code (locks, goroutines, shared state) → check assumptions
5. Read error handling paths → trace propagation from origin to caller

**Key instruction:** "Make five passes through the code, each looking for one type of bug. Each pass should read the files relevant to that strategy. Report findings as you go."

**Strengths:** Most systematic. Each strategy gets dedicated attention. Easy to see which strategy found what.

**Risks:** Five passes on 13 files means significant re-reading, eating context. Rigid separation may prevent cross-pollination — G's BUG-2 was found while analyzing a multi-step flow, which crosses strategy boundaries. Most structural overhead of the three.

### Variant C: Exploratory (`code-bug-hunter-exploratory`)

**Reading strategy:** Start with high-coupling "hub" files — the ones imported by many others or that coordinate between packages. Read outward from there, following risky-looking code paths.

**Analysis approach:** Prioritize by risk signals: complex control flow, cross-package coordination, error-handling density, mutable shared state. When something looks suspicious, dig deeper into that thread. Don't try to read everything — spend time on the riskiest code.

**Key instruction:** "Start with the most complex or interconnected files. When you see something risky, follow that thread — read the callers, the callees, the sibling implementations. Investigate deeply rather than broadly. You don't need to read every file."

**Strengths:** Depth over breadth. Could find bugs the other variants miss by spending more time on fewer files. Most likely to produce novel findings.

**Risks:** Might miss BUG-1 entirely if it doesn't read nvd/adapter.go (not obviously a "hub" file). "Risky-looking" is subjective — the LLM might fixate on obvious complexity (merge pipeline) and miss subtle bugs in simpler code.

---

## Test Framework

### Ground Truth (from Run G)

Two known production bugs in Phase 1 scope:

- **BUG-1: ParseTime/RFC1123** — `feed.ParseTime` (util.go:13-18) only supports RFC3339 variants and `2006-01-02`. NVD adapter (adapter.go:194-195) calls `ParseTime` on the HTTP `Date` header, which uses RFC1123. ParseTime returns zero time, making the Date header fallback dead code. Clock-skew safety layer silently broken.

- **BUG-2: PK migration collision** — `migrateCVEPK` (pipeline.go:352) does `UPDATE cves SET cve_id = $2 WHERE cve_id = $1`. If the target CVE ID already exists (e.g., NVD created it first, GHSA has it as an alias), this hits a unique constraint violation. The advisory lock serializes same-ID writes but can't prevent this cross-ID collision. Entire Ingest transaction rolls back — silent data loss.

### Scoring Rubrics (3)

#### Rubric 1: Bugs-Only

Purpose-built for the bug hunter's core mission.

| Metric | Weight | How to score |
|--------|--------|---|
| Ground-truth bugs found | 40% | BUG-1 and/or BUG-2. 10 = both, 6 = one, 2 = zero. |
| Novel bugs found | 20% | Genuine bugs NOT in the G benchmark. Must be real correctness issues, not coverage gaps. 10 = significant find, 5 = minor/debatable, 2 = none. |
| Evidence quality | 20% | Are findings well-located (file:line), clearly explained, with concrete impact? |
| False positive rate | 20% | Findings that aren't actually bugs — coverage gaps dressed as bugs, misunderstood code, fabricated issues. 10 = zero false positives. |

#### Rubric 2: Bugs + Analysis Quality

Rewards thorough reasoning even when bugs aren't found.

| Metric | Weight | How to score |
|--------|--------|---|
| Ground-truth bugs found | 25% | Same as Rubric 1. |
| Novel bugs found | 15% | Same as Rubric 1. |
| Cross-file reasoning demonstrated | 20% | Did the analysis connect code across packages? Compare sibling implementations? Trace flows across boundaries? |
| Failure mode depth | 15% | Did the analysis reason about "what happens when X fails?" beyond surface-level error returns? |
| Evidence quality | 15% | Same as Rubric 1. |
| False positive rate | 10% | Same as Rubric 1. |

#### Rubric 3: Phase 1 Reduced (cross-comparison)

Same rubric used for G/K1/M1/N1. Allows direct score comparison with coverage review skills. The bug hunter will naturally score low on assertion quality and non-API adaptation — that's the point.

| Metric | Weight |
|--------|--------|
| Production bugs / design violations | 25% |
| TOCTOU windows | 20% |
| Cross-handler consistency | 20% |
| Assertion quality | 15% |
| False positives | 10% |
| Non-API adaptation | 10% |

### Hypotheses

| # | Prediction | How to verify |
|---|-----------|---|
| H1 | At least one variant finds BUG-1 (ParseTime/RFC1123) | Search report for RFC1123, ParseTime, Date header |
| H2 | At least one variant finds BUG-2 (PK migration collision) | Search report for migrateCVEPK, unique constraint, collision |
| H3 | Variant A (holistic) scores highest on Rubric 1 (bugs-only) | It mirrors G's approach most closely |
| H4 | Variant B (multipass) scores highest on Rubric 2 (analysis quality) | Systematic passes produce more comprehensive cross-file reasoning |
| H5 | Variant C (exploratory) finds at least one novel bug not in the G benchmark | Depth-first exploration may uncover bugs that breadth-first misses |
| H6 | All three variants score ≤4/10 on Rubric 3 assertion quality | Bug hunter doesn't analyze test quality — confirms tool differentiation |
| H7 | The highest Rubric 1 score across all variants exceeds M1's equivalent (6.20) | A purpose-built bug hunter should beat a coverage skill at finding bugs |

**Success criteria:** H1 or H2 confirmed (at least one variant finds at least one ground-truth bug). If neither is confirmed, the bug hunter concept needs fundamental rethinking — or the ground-truth bugs require domain knowledge the LLM can't reliably apply.

### Controlled Variables

- **Codebase state:** Same `dev` branch HEAD as all Phase 1 runs
- **Scope:** `./internal/feed/...`, `./internal/merge/...`, `./internal/worker/...`
- **No coverage data provided** — source code only
- **Model:** Same as prior runs (check with `/model` at start of each session)
- **Sessions:** Separate Claude Code sessions per variant, no cross-contamination, no mention of A/B test or other variants

### Test Prompts

#### Run BH-A: Holistic

```
Run /code-bug-hunter-holistic on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-bughunt-holistic.md

Follow the skill instructions exactly.
```

#### Run BH-B: Multi-pass

```
Run /code-bug-hunter-multipass on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-bughunt-multipass.md

Follow the skill instructions exactly.
```

#### Run BH-C: Exploratory

```
Run /code-bug-hunter-exploratory on Phase 1 scope.

Scope: ./internal/feed/..., ./internal/merge/..., ./internal/worker/...

Save the report to: dev/test-coverage-reports/2026-03-03-phase1-bughunt-exploratory.md

Follow the skill instructions exactly.
```

Prompts are deliberately minimal — the skill itself provides all the guidance. No hints about what to look for, what bugs exist, or how many to find.

### Post-Test Analysis

After all three runs complete:

1. **Score each variant on all three rubrics** — produces a 3×3 scoring matrix
2. **Check hypotheses** — mark each confirmed/refuted with evidence
3. **Compare rubric scores** — does the bugs-only rubric rank variants differently than the Phase 1 reduced rubric? This validates the "different tools for different jobs" thesis
4. **Analyze false positives** — did any variant report coverage gaps as bugs? This tests whether the anti-guidance worked
5. **Novel findings** — did any variant find bugs G missed? These would be genuinely new contributions
6. **Pick winner** — if one variant clearly dominates, adopt it. If none finds ground-truth bugs, reconsider the approach

### Scoring Matrix Template

|  | Rubric 1 (bugs-only) | Rubric 2 (bugs+analysis) | Rubric 3 (Phase 1 reduced) |
|--|:-:|:-:|:-:|
| BH-A (holistic) | | | |
| BH-B (multipass) | | | |
| BH-C (exploratory) | | | |
| M1 (coverage, for comparison) | — | — | 6.20 |
| G (coverage v3, for comparison) | — | — | 9.05 |
