# Code Bug Hunter Skill — Design & Test Plan

**Date:** 2026-03-03
**Status:** Complete — all three variants tested, scored, and analyzed

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

---

## Results

### Execution Status

| Run | Skill | Bugs found | Design concerns | Report file |
|-----|-------|:----------:|:---------------:|-------------|
| BH-A | code-bug-hunter-holistic | 6 | 2 | `2026-03-03-phase1-bughunt-holistic.md` |
| BH-B | code-bug-hunter-multipass | 5 | 5 | `2026-03-03-phase1-bughunt-multipass.md` |
| BH-C | code-bug-hunter-exploratory | 5 | 2 | `2026-03-03-phase1-bughunt-exploratory.md` |

All three variants completed without truncation or context exhaustion.

### Ground-Truth Bug Detection

Both ground-truth bugs found by ALL three variants on first attempt:

| Bug | BH-A | BH-B | BH-C |
|-----|------|------|------|
| BUG-1 (ParseTime/RFC1123 — dead code) | Bug #4 (minor) | Bug #1 (minor) | Bug #5 (minor) |
| BUG-2 (PK migration collision — data loss) | Bug #1 (significant) | Bug #4 (critical) | Bug #1 (critical) |

For comparison: the coverage review skills found 0 ground-truth bugs in 4 Phase 1 attempts (K1, L1, M1, N1).

### Novel Findings (beyond G benchmark)

| Finding | Severity | BH-A | BH-B | BH-C |
|---------|----------|:----:|:----:|:----:|
| Advisory lock not acquired on old CVE ID during PK migration | significant | #2 | — | — |
| NextCursor contract violation — 4/5 adapters return non-nil when done | significant | #3 | #2 | — |
| OSV multi-event range data loss in structured fields | significant | #5 | #3 | #2 |
| Worker pool no panic recovery — unrecovered panic crashes process | significant | #6 | — | — |
| MITRE/GHSA reject valid CVSS 0.0 scores (NVD accepts them) | minor | — | #5 | — |
| Staged EPSS applied after tombstone on withdrawn CVEs | minor | — | — | #3 |
| ResolveCanonicalID non-deterministic with multiple CVE aliases | minor | — | — | #4 |

8 unique novel findings total. All genuine correctness issues, zero coverage-gap false positives.

**Note on BH-A Bug #6 (worker panic):** The core finding (no `recover()` in queue goroutines) is correct, but the impact description is wrong — BH-A says "the process keeps running with a dead queue." In Go, an unrecovered goroutine panic terminates the entire process, not just the goroutine. The finding is real; the described consequence is incorrect.

### Scoring

#### Rubric 1: Bugs-Only

| Metric | Weight | BH-A | BH-B | BH-C |
|--------|--------|:----:|:----:|:----:|
| Ground-truth bugs found | 40% | 10 (both) | 10 (both) | 10 (both) |
| Novel bugs found | 20% | 10 (4 novel, 3 significant) | 8 (3 novel, 2 significant) | 7 (3 novel, 1 significant) |
| Evidence quality | 20% | 9 (worker panic impact wrong) | 10 (all accurate, schema refs) | 9 (good depth, less detailed on PK) |
| False positive rate | 20% | 10 (all genuine) | 10 (all genuine) | 10 (all genuine) |
| **Weighted total** | | **9.80** | **9.60** | **9.20** |

#### Rubric 2: Bugs + Analysis Quality

| Metric | Weight | BH-A | BH-B | BH-C |
|--------|--------|:----:|:----:|:----:|
| Ground-truth bugs found | 25% | 10 | 10 | 10 |
| Novel bugs found | 15% | 10 | 8 | 7 |
| Cross-file reasoning | 20% | 10 (pipeline→migrations→queries, interface→5 adapters, advisory lock analysis) | 9 (systematic passes, Pass 2 cross-sibling excellent) | 9 (pipeline step ordering, util→adapters, merge→hash) |
| Failure mode depth | 15% | 9 (5-step PK scenario, concurrent writer race; worker impact wrong) | 9 (PK with schema evidence, decode→empty patches, EPSS retry→24hr gap) | 9 (staged EPSS ordering, alias flipping, PK cascade, FailJob chain) |
| Evidence quality | 15% | 9 | 10 | 9 |
| False positive rate | 10% | 10 | 10 | 10 |
| **Weighted total** | | **9.70** | **9.35** | **9.05** |

#### Rubric 3: Phase 1 Reduced (cross-comparison with coverage review skills)

| Metric | Weight | BH-A | BH-B | BH-C | M1 | G |
|--------|--------|:----:|:----:|:----:|:--:|:-:|
| Production bugs / design violations | 25% | 10 | 10 | 10 | 2 | 10 |
| TOCTOU windows | 20% | 4 | 3 | 4 | 7 | 8 |
| Cross-handler consistency | 20% | 6 | 7 | 5 | 7 | 8 |
| Assertion quality | 15% | 1 | 1 | 1 | 6 | 9 |
| False positives | 10% | 9 | 10 | 10 | 10 | 10 |
| Non-API adaptation | 10% | 10 | 10 | 10 | 10 | 10 |
| **Weighted total** | | **6.55** | **6.65** | **6.45** | **6.20** | **9.05** |

#### Scoring Matrix (filled)

|  | Rubric 1 (bugs-only) | Rubric 2 (bugs+analysis) | Rubric 3 (Phase 1 reduced) |
|--|:-:|:-:|:-:|
| **BH-A (holistic)** | **9.80** | **9.70** | 6.55 |
| **BH-B (multipass)** | 9.60 | 9.35 | **6.65** |
| **BH-C (exploratory)** | 9.20 | 9.05 | 6.45 |
| M1 (coverage, for comparison) | — | — | 6.20 |
| G (coverage v3, for comparison) | — | — | 9.05 |

### Hypothesis Results

| # | Prediction | Result | Evidence | Confirmed? |
|---|-----------|--------|----------|:----------:|
| H1 | At least one variant finds BUG-1 (ParseTime/RFC1123) | All three found it | BH-A #4, BH-B #1, BH-C #5 | **Confirmed** |
| H2 | At least one variant finds BUG-2 (PK migration collision) | All three found it | BH-A #1, BH-B #4, BH-C #1 | **Confirmed** |
| H3 | BH-A scores highest on Rubric 1 | BH-A: 9.80 > BH-B: 9.60 > BH-C: 9.20 | Most novel bugs of highest significance | **Confirmed** |
| H4 | BH-B scores highest on Rubric 2 | BH-A: 9.70 > BH-B: 9.35 | Holistic cross-file reasoning beat structured passes | **Refuted** |
| H5 | BH-C finds ≥1 novel bug | Staged EPSS ordering + ResolveCanonicalID non-determinism | Both unique to BH-C | **Confirmed** |
| H6 | All three score ≤4/10 on R3 assertion quality | All scored 1/10 | Bug hunter doesn't analyze tests — confirms tool differentiation | **Confirmed** |
| H7 | Highest R1 score exceeds M1's equivalent | BH-A R1: 9.80; all R3 scores (6.45–6.65) > M1 (6.20) | Bug hunter outperforms on both purpose-built and shared rubrics | **Confirmed** |

**6/7 confirmed.** Success criteria (H1 or H2): **STRONG PASS** — both confirmed by all three variants.

### Analysis

#### Why Rubric 3 undervalues the bug hunter

All three variants scored 6.45–6.65 on Rubric 3 despite finding both ground-truth bugs that M1 missed entirely. This is because Rubric 3 weights TOCTOU enumeration (20%) and assertion quality (15%) — coverage-review behaviors the bug hunter deliberately ignores. The bug hunter scores 1/10 on assertion quality by design (it doesn't analyze tests). This isn't a flaw — it validates the "different tools for different jobs" thesis.

The coverage review skill (M1) scores 6.20 on Rubric 3 but would score ≤4 on Rubric 1 (0 ground-truth bugs, 0 novel bugs). Each tool excels on its purpose-built rubric.

#### Why H4 was refuted

H4 predicted multipass would score highest on analysis quality because structured passes produce more comprehensive cross-file reasoning. The opposite happened: BH-A's unconstrained exploration generated deeper cross-package connections than BH-B's five separate passes. This mirrors the G vs K1/M1 pattern — analytical freedom outperforms structural discipline for deep semantic analysis.

The multipass structure may actually inhibit cross-pollination. G's BUG-2 was found while analyzing a multi-step flow, which crosses strategy boundaries — holistic analysis naturally follows these threads while multipass compartmentalizes them.

#### Novel finding distribution

Each variant found unique bugs the others missed:
- **BH-A uniquely found:** advisory lock gap (significant concurrency issue), worker panic recovery (significant reliability issue)
- **BH-B uniquely found:** CVSS 0.0 rejection (minor cross-sibling pattern)
- **BH-C uniquely found:** staged EPSS ordering (minor timing issue), ResolveCanonicalID non-determinism (minor data consistency)

Running multiple variants increases total bug coverage. BH-A found the most unique bugs and the most significant ones.

#### False positive analysis

Zero coverage-gap false positives across all three variants. The anti-guidance ("what is NOT a bug" section) worked perfectly — none of the reports mentioned test coverage, missing test cases, or assertion quality. Every finding is a genuine correctness issue with specific code evidence. This is the strongest validation that the coverage-review / bug-hunter separation is well-designed.

BH-A's only accuracy issue is the worker panic impact description (says process keeps running; actually crashes). This is an evidence quality error, not a false positive — the core finding is real.

### Recommendation

**Adopt BH-A (holistic) as the primary bug hunter skill.** It scored highest on both Rubric 1 (9.80) and Rubric 2 (9.70), found the most bugs (6), and produced the most significant novel findings (4). Its minimal structural overhead maximizes analytical freedom — the same quality that made Run G the highest-scoring coverage review run.

**Keep BH-C (exploratory) as a complement for large scopes.** Its depth-first approach found unique bugs the others missed (staged EPSS, ResolveCanonicalID). On codebases too large for holistic reading, BH-C's selective depth may be more effective than BH-A's attempt to read everything.

**BH-B (multipass) can be retired or kept as a secondary option.** It didn't outperform BH-A on any rubric, and its structured passes added overhead without proportional benefit. However, it did find a unique cross-sibling pattern bug (CVSS 0.0) that BH-A missed, so there's some value in its systematic Pass 2 comparison.

### Actionable bugs to fix

Prioritized by severity and impact:

1. **PK migration collision** (critical) — all three found this. Needs a merge-and-delete strategy instead of simple UPDATE renames.
2. **Advisory lock gap** (significant) — BH-A found this. Lock both old and new CVE IDs during migration, with consistent ordering to prevent deadlocks.
3. **NextCursor contract violation** (significant) — BH-A/B found this. Either fix 4 adapters to return nil when done, or split NextCursor into `NextPageCursor` + `SyncState`.
4. **OSV multi-event range data loss** (significant) — all three found this. Collect all event pairs, not just the last one.
5. **Worker panic recovery** (significant) — BH-A found this. Add `recover()` in queue goroutines with error logging and job failure recording.
6. **ParseTime/RFC1123** (minor) — all three found this. Add `time.RFC1123` to `timeLayouts` in util.go.
7. **CVSS 0.0 rejection** (minor) — BH-B found this. Change `> 0` to `>= 0` in MITRE/GHSA adapters.
8. **Staged EPSS after tombstone** (minor) — BH-C found this. Skip staged EPSS application for withdrawn CVEs.
9. **ResolveCanonicalID non-deterministic** (minor) — BH-C found this. Sort CVE aliases before selecting canonical ID.

---

## Phase 3a Runs (Notification Delivery)

### Scope

Different domain from Phase 1 (data pipeline → notification delivery). Tests whether holistic dominance generalizes.

**Files:** `internal/notify/` (dispatcher.go, client.go, webhook.go, email.go, template.go, render.go, digest.go, worker.go), `internal/alert/evaluator.go`, `internal/store/notification_channel.go`, `internal/store/alert_rule_channel.go`, `internal/store/notification_delivery.go`, `internal/api/channels.go`, `internal/api/deliveries.go`, `internal/api/alert_rules.go`

15 source files, ~104 functions. Cross-cutting concerns: SSRF protection, HMAC signing, per-org concurrency semaphore, delivery retry/DLQ, alert rule activation lifecycle.

### Test Prompts

#### Run BH-D: Holistic
```
Run /code-bug-hunter-holistic on Phase 3a scope.

Scope: internal/notify/dispatcher.go, internal/notify/client.go, internal/notify/webhook.go,
internal/notify/email.go, internal/notify/template.go, internal/notify/render.go,
internal/notify/digest.go, internal/notify/worker.go, internal/alert/evaluator.go,
internal/store/notification_channel.go, internal/store/alert_rule_channel.go,
internal/store/notification_delivery.go, internal/api/channels.go, internal/api/deliveries.go,
internal/api/alert_rules.go

Save the report to: dev/test-coverage-reports/2026-03-03-phase3a-bughunt-holistic.md
```

#### Run BH-E: Multi-pass
```
Run /code-bug-hunter-multipass on Phase 3a scope.

Scope: internal/notify/dispatcher.go, internal/notify/client.go, internal/notify/webhook.go,
internal/notify/email.go, internal/notify/template.go, internal/notify/render.go,
internal/notify/digest.go, internal/notify/worker.go, internal/alert/evaluator.go,
internal/store/notification_channel.go, internal/store/alert_rule_channel.go,
internal/store/notification_delivery.go, internal/api/channels.go, internal/api/deliveries.go,
internal/api/alert_rules.go

Save the report to: dev/test-coverage-reports/2026-03-03-phase3a-bughunt-multipass.md
```

#### Run BH-F: Exploratory
```
Run /code-bug-hunter-exploratory on Phase 3a scope.

Scope: internal/notify/dispatcher.go, internal/notify/client.go, internal/notify/webhook.go,
internal/notify/email.go, internal/notify/template.go, internal/notify/render.go,
internal/notify/digest.go, internal/notify/worker.go, internal/alert/evaluator.go,
internal/store/notification_channel.go, internal/store/alert_rule_channel.go,
internal/store/notification_delivery.go, internal/api/channels.go, internal/api/deliveries.go,
internal/api/alert_rules.go

Save the report to: dev/test-coverage-reports/2026-03-03-phase3a-bughunt-exploratory.md
```

### Phase 3a Execution Status

| Run | Skill | Bugs found | Design concerns | Report file |
|-----|-------|:----------:|:---------------:|-------------|
| BH-D | code-bug-hunter-holistic | 5 | 3 | `2026-03-03-phase3a-bughunt-holistic.md` |
| BH-E | code-bug-hunter-multipass | 7 | 3 | `2026-03-03-phase3a-bughunt-multipass.md` |
| BH-F | code-bug-hunter-exploratory | 4 | 3 | `2026-03-03-phase3a-bughunt-exploratory.md` |

All three variants completed without truncation or context exhaustion.

### Phase 3a Bug Detection

9 unique bugs across all variants:

| # | Bug | Severity | BH-D | BH-E | BH-F |
|---|-----|----------|:----:|:----:|:----:|
| 1 | Activation pipeline not wired — rules stuck in "activating" forever | critical | #1 (critical) | **MISSED** | #2 (significant) |
| 2 | Claim/mark TOCTOU — duplicate deliveries under multi-worker | significant | #5 (minor) | #5 (significant) | #1 (significant) |
| 3 | 201 vs 202 status code for activating rules | significant | #2 (significant) | #1 (significant) | #4 (minor) |
| 4 | Worker delivery goroutines use cancelled parent context | significant | #3 (significant) | — | — |
| 5 | Deterministic email errors retried instead of immediately exhausted | significant | — | #4 (significant) | — |
| 6 | Replay handler 204 on no-op + wastes rate limit tokens | minor | #4 (minor) | #2 (minor) | #3 (minor) |
| 7 | Delivery list pagination phantom last page | minor | — | #3 (minor) | — |
| 8 | Per-org semaphore head-of-line blocking across orgs | minor | — | #6 (minor) | — |
| 9 | Batch evaluator advances cursor on partial evaluation failure | minor | — | #7 (minor) | — |

**Unique contributions:**
- **BH-D:** 1 unique significant (cancelled context → duplicates on shutdown)
- **BH-E:** 4 unique (1 significant: email retry waste; 3 minor: pagination, semaphore, cursor)
- **BH-F:** 0 unique — all 4 findings are a subset of BH-D's

**Critical miss:** BH-E (multipass) missed the activation pipeline bug — the most critical finding in the scope. Its Pass 1 (Contract Violations) found the 201/202 symptom but assumed the activation scan IS queued, never checking `main.go` for handler registration or `alert_rules.go` for `EnqueueJob` calls.

### Phase 3a Scoring

#### Rubric 1: Bugs-Only (adapted — no pre-planted ground truth)

Since Phase 3a has no pre-planted ground-truth bugs, the 40% weight becomes "critical bug detection" — ability to find the most impactful bugs. The activation pipeline bug is the clear standout: it breaks the entire alert rule lifecycle.

| Metric | Weight | BH-D | BH-E | BH-F |
|--------|--------|:----:|:----:|:----:|
| Critical bug detection | 40% | 10 (found + correctly rated critical) | 4 (found symptom only, missed root cause) | 8 (found it, underrated as significant) |
| Novel/unique bugs found | 20% | 8 (1 unique significant, 5 total) | 10 (4 unique, 7 total — most of any variant) | 3 (0 unique, 4 total — complete subset of BH-D) |
| Evidence quality | 20% | 9 (thorough lifecycle tracing, main.go wiring check; slightly underrated claim/mark) | 9 (systematic SQL evidence, 4 email error types with line numbers; missed deeper activation issue) | 8 (solid evidence with CTE fix suggestion; underrated activation severity) |
| False positive rate | 20% | 10 (all genuine) | 10 (all genuine) | 10 (all genuine) |
| **Weighted total** | | **9.40** | **7.40** | **7.40** |

#### Rubric 2: Bugs + Analysis Quality

| Metric | Weight | BH-D | BH-E | BH-F |
|--------|--------|:----:|:----:|:----:|
| Critical bug detection | 25% | 10 | 4 | 8 |
| Novel bugs found | 15% | 8 | 10 | 3 |
| Cross-file reasoning | 20% | 10 (API→evaluator→main.go wiring, SIGTERM→ctx→DB→stuck→restart chain) | 7 (systematic per-pass but missed cross-file activation thread; sibling comparison excellent) | 9 (claim→mark→SQL thread, activation→main.go; good depth-first following) |
| Failure mode depth | 15% | 9 (SIGTERM shutdown scenario, 5-step activation lifecycle, rate limit exhaustion) | 9 (4 permanent email error types, transaction flow for TOCTOU, cursor edge case) | 7 (stated problems clearly, proposed CTE fix, but shorter failure chains) |
| Evidence quality | 15% | 9 | 9 | 8 |
| False positive rate | 10% | 10 | 10 | 10 |
| **Weighted total** | | **9.40** | **7.60** | **7.50** |

#### Phase 1 vs Phase 3a Comparison

| Variant | Phase 1 R1 | Phase 3a R1 | Phase 1 R2 | Phase 3a R2 |
|---------|:----------:|:-----------:|:----------:|:-----------:|
| **Holistic** | 9.80 (BH-A) | 9.40 (BH-D) | 9.70 (BH-A) | 9.40 (BH-D) |
| **Multipass** | 9.60 (BH-B) | 7.40 (BH-E) | 9.35 (BH-B) | 7.60 (BH-E) |
| **Exploratory** | 9.20 (BH-C) | 7.40 (BH-F) | 9.05 (BH-C) | 7.50 (BH-F) |

Holistic is remarkably consistent (±0.40 across domains). The other two dropped significantly (2+ points on R1).

### Phase 3a Analysis

#### Why BH-E missed the critical bug

BH-E's multipass structure found the 201/202 status code mismatch in Pass 1 (Contract Violations) but assumed the activation scan was actually queued. It never followed the thread from the API handler to `main.go` to discover no handler is registered. The pass structure created a boundary: "is the status code wrong?" is a contract question, but "is the activation pipeline wired end-to-end?" requires cross-file tracing that spans passes.

This is the same failure mode as Phase 1 (H4 refuted): structured passes inhibit cross-pollination. BH-D naturally followed the thread from "status is set to activating" → "where is the job enqueued?" → "where is the handler registered?" → "it's not registered anywhere." Multipass compartmentalized this reasoning.

#### Why BH-F found nothing unique

In Phase 1, BH-C (exploratory) found 2 unique bugs (staged EPSS, ResolveCanonicalID). In Phase 3a, BH-F found nothing unique — every one of its 4 bugs was also found by BH-D. The depth-first approach's advantage is selective deep analysis when the scope is too large to read everything. Phase 3a (15 files) is well within the holistic variant's reading capacity, neutralizing the exploratory variant's differentiation.

#### BH-E's unique contributions are still valuable

Despite missing the critical bug, BH-E found 4 bugs nobody else found, including the deterministic email retry waste (significant). Its Pass 3 (Failure Mode Reasoning) identified that template rendering, payload unmarshal, empty recipients, and config parse errors are all permanent but get retried. Its Pass 4 (Concurrency) found both the TOCTOU and the head-of-line blocking. These passes work well individually — the weakness is in cross-pass thread following.

#### Severity calibration varies across variants

- **Claim/mark TOCTOU:** BH-D says minor, BH-E/F say significant. Significant is more accurate — duplicate deliveries is a real-world impact.
- **201 vs 202:** BH-D/E say significant, BH-F says minor. BH-F's reasoning ("since activation isn't wired, 201 is arguably correct") is defensible but the API contract violation stands regardless.
- **Activation pipeline:** BH-D says critical, BH-F says significant. Critical is correct — the entire feature is broken.

### Updated Recommendation

Phase 3a strongly reinforces the Phase 1 conclusion:

**BH-A/D (holistic) is the clear primary bug hunter.** Consistent 9.40–9.80 across domains and rubrics. The only variant that reliably finds critical bugs through cross-file reasoning.

**BH-B/E (multipass) produces the most raw findings but has a critical blind spot.** The compartmentalized pass structure finds many smaller bugs but can miss the most important one. In Phase 1 this wasn't punished because all variants found both ground-truth bugs. In Phase 3a, the blind spot cost multipass ~2 points. For maximum coverage, run multipass as a complement to holistic — never as a replacement.

**BH-C/F (exploratory) adds no value when scope fits holistic reading capacity.** All of its findings were a subset of holistic's. The exploratory approach's depth-first selection is only valuable when the scope is too large for holistic to read everything — which wasn't the case for either Phase 1 (8 files) or Phase 3a (15 files).

### Phase 3a Actionable bugs to fix

Prioritized by severity and impact:

1. **Activation pipeline not wired** (critical) — enqueue `alert_activation` job in create/update handlers, register handler in main.go
2. **Claim/mark TOCTOU** (significant) — combine SELECT and UPDATE into a single CTE
3. **201 vs 202 status code** (significant) — conditional response code based on `status`
4. **Cancelled context in delivery goroutines** (significant) — `context.WithoutCancel()` wrapper
5. **Deterministic email errors retried** (significant) — classify permanent errors, exhaust immediately
6. **Replay no-op + rate limit waste** (minor) — check delivery exists/replayable before consuming token
7. **Pagination phantom page** (minor) — use `limit+1` pattern like alert rules handler
8. **Semaphore head-of-line blocking** (minor) — group claimed rows by org, dispatch org batches in parallel
9. **Batch cursor advancement on failure** (minor) — don't advance cursor past failed rules

---

## Phase 3b Runs (Email/Templates/Digests)

### Scope

Overlapping domain with Phase 3a (shared: worker.go, notification_delivery.go, deliveries.go, channels.go). Tests whether multipass's cross-sibling strength generalizes when bugs are localized pattern violations rather than deep cross-file issues.

**Files:** `internal/store/scheduled_report.go`, `internal/store/report_channel.go`, `internal/store/notification_channel.go`, `internal/store/notification_delivery.go`, `internal/notify/email.go`, `internal/notify/render.go`, `internal/notify/template.go`, `internal/notify/digest.go`, `internal/notify/worker.go`, `internal/api/channels.go`, `internal/api/reports.go`, `internal/api/deliveries.go`, `internal/api/server.go`

13 source files. Cross-cutting concerns: digest execution lifecycle, PATCH semantics for nullable fields, delivery serialization, secret rotation, worker transaction patterns.

### Phase 3b Execution Status

| Run | Skill | Bugs found | Design concerns | Report file |
|-----|-------|:----------:|:---------------:|-------------|
| BH-G | code-bug-hunter-holistic | 4 | 2 | `2026-03-03-phase3b-bughunt-holistic.md` |
| BH-H | code-bug-hunter-multipass | 5 | 3 | `2026-03-03-phase3b-bughunt-multipass.md` |
| BH-I | code-bug-hunter-exploratory | 3 | 2 | `2026-03-03-phase3b-bughunt-exploratory.md` |

All three variants completed without truncation or context exhaustion.

### Phase 3b Bug Detection

7 unique bugs across all variants:

| # | Bug | Severity | BH-G | BH-H | BH-I |
|---|-----|----------|:----:|:----:|:----:|
| 1 | Digest runner calls wrong store method (API path instead of worker path) | significant | #1 (significant) | #1 (significant) | Design concern only |
| 2 | PATCH /reports can't clear severity_threshold to NULL | significant | #2 (significant) | #3 (significant) | #3 (minor) |
| 3 | RuleID zero UUID for digest deliveries | significant | **MISSED** | #2 (significant) | #2 (minor) |
| 4 | rotateSecretHandler TOCTOU — empty secret with 200 | minor | #3 (minor) | — | — |
| 5 | Replay rate limit consumed on no-op | minor | #4 (minor) | Design concern | — |
| 6 | deleteReportHandler 204 for non-existent reports | minor | — | #4 (minor) | — |
| 7 | Claim/mark TOCTOU (re-found from Phase 3a overlap) | significant | — | #5 (significant) | #1 (significant) |

**Unique contributions:**
- **BH-G:** 2 unique (rotateSecret TOCTOU, replay rate limit as bug)
- **BH-H:** 1 unique (deleteReport 204)
- **BH-I:** 0 unique — complete subset of other variants

**Key miss:** BH-G (holistic) missed the RuleID zero UUID bug — a textbook cross-sibling pattern violation where `ReportID` uses `*string` with `.Valid` check but `RuleID` uses `string` with unconditional `.UUID.String()`. This is exactly the class of bug multipass's Pass 2 (Cross-Sibling) is designed to catch.

### Phase 3b Scoring

#### Rubric 1: Bugs-Only (adapted)

Phase 3b has no single critical bug. The most important findings are PATCH clearing (direct user impact), RuleID zero UUID (incorrect API for all digest deliveries), and digest wrong store method (convention violation + dead code).

| Metric | Weight | BH-G | BH-H | BH-I |
|--------|--------|:----:|:----:|:----:|
| Critical/important bug detection | 40% | 7 (found PATCH clear + digest method; missed RuleID zero UUID) | 10 (found all three important bugs at correct severity) | 6 (found PATCH + RuleID but both rated minor; digest only design concern) |
| Novel/unique bugs found | 20% | 7 (4 total, 2 unique: rotateSecret TOCTOU, replay rate limit) | 8 (5 total, most bugs; 1 truly unique: deleteReport 204) | 3 (3 total, 0 unique — complete subset) |
| Evidence quality | 20% | 9 (design doc cross-refs, TOCTOU scenario, code from both sides) | 9 (cross-sibling RuleID/ReportID comparison, SQL evidence) | 8 (good CTE fix suggestion on claim/mark; shorter analysis on others) |
| False positive rate | 20% | 10 | 10 | 10 |
| **Weighted total** | | **8.00** | **9.40** | **6.60** |

#### Rubric 2: Bugs + Analysis Quality

| Metric | Weight | BH-G | BH-H | BH-I |
|--------|--------|:----:|:----:|:----:|
| Critical bug detection | 25% | 7 | 10 | 6 |
| Novel bugs found | 15% | 7 | 8 | 3 |
| Cross-file reasoning | 20% | 8 (digest flow tracing good; missed RuleID sibling pattern) | 9 (Pass 2 cross-sibling excellent; SQL↔handler contract checking) | 7 (good claim/mark depth; digest method only a concern) |
| Failure mode depth | 15% | 8 (TOCTOU scenario, severity_threshold dead-end analysis) | 8 (RuleID consumer confusion, deleteReport audit gap) | 7 (CTE fix solid, but shorter chains overall) |
| Evidence quality | 15% | 9 | 9 | 8 |
| False positive rate | 10% | 10 | 10 | 10 |
| **Weighted total** | | **7.95** | **9.05** | **6.60** |

### Phase 3b Analysis

#### Why multipass wins Phase 3b

Phase 3b's bugs are localized contract/pattern violations, not deep cross-file reasoning problems. The RuleID zero UUID bug is a textbook cross-sibling pattern violation — `ReportID` uses `*string` with `.Valid` check while `RuleID` uses `string` with unconditional `.UUID.String()`. Multipass's Pass 2 is specifically designed to catch exactly this class of bug. Holistic read all the same code but never forced itself into a systematic sibling comparison.

This is the **first reversal** — multipass wins on both rubrics. The pattern is clear: when bugs require deep cross-file reasoning (Phase 1, Phase 3a), holistic wins. When bugs are localized contract/pattern violations (Phase 3b), multipass wins.

#### Why holistic dropped

Holistic's strength is following threads across package boundaries (API→evaluator→main.go in Phase 3a). Phase 3b's bugs don't require that — they're within-file or adjacent-file pattern issues. Holistic's unconstrained exploration doesn't penalize but also doesn't force the systematic comparison that catches serialization asymmetries.

#### Exploratory continues to underperform

Zero unique contributions again (3rd time in 4 phases). Its depth-first selection focused on worker.go and digest.go — re-finding the claim/mark TOCTOU from Phase 3a scope overlap — while giving insufficient attention to the API serialization patterns where the novel bugs were.

### Phase 3b Actionable bugs to fix

Prioritized by severity and impact:

1. **Digest runner wrong store method** (significant) — call `ListActiveChannelsForDigest` instead of `ListChannelsForReport`
2. **PATCH can't clear severity_threshold** (significant) — add sentinel value or use three-state type to distinguish null from absent
3. **RuleID zero UUID** (significant) — change `RuleID` to `*string` with `.Valid` check, matching `ReportID` pattern
4. **Claim/mark TOCTOU** (significant) — already listed in Phase 3a; combine into single CTE
5. **rotateSecretHandler TOCTOU** (minor) — check `if secret == ""` and return 404
6. **Replay rate limit on no-op** (minor) — already listed in Phase 3a
7. **deleteReportHandler 204** (minor) — add existence check before delete, matching channel handler pattern

---

## Phase 4 Runs (AI/DSL/Saved Searches)

### Scope

Largest scope tested (21 files). Different domain (DSL compilation, alert evaluation, AI features). Tests whether holistic hits reading capacity limits and exploratory differentiates at larger scale.

**Files:** `internal/ai/ai.go`, `internal/ai/gemini.go`, `internal/ai/mock.go`, `internal/ai/quota.go`, `internal/ai/sanitize.go`, `internal/ai/schema.go`, `internal/alert/dsl/field.go`, `internal/alert/dsl/types.go`, `internal/alert/dsl/compiler.go`, `internal/alert/dsl/validator.go`, `internal/alert/evaluator.go`, `internal/store/dsl_executor.go`, `internal/api/ai.go`, `internal/api/saved_searches.go`, `internal/api/server.go`, `internal/store/ai.go`, `internal/store/saved_search.go`, `cmd/cvert-ops/quota.go`, `cmd/cvert-ops/main.go`, `internal/config/config.go`, `internal/metrics/ai.go`

21 source files. Cross-cutting concerns: DSL compilation + evaluation, PostFilter regex handling, float value parsing, quota management, NL search pipeline.

### Phase 4 Execution Status

| Run | Skill | Bugs found | Design concerns | Report file |
|-----|-------|:----------:|:---------------:|-------------|
| BH-J | code-bug-hunter-holistic | 2 | 2 | `2026-03-03-phase4-bughunt-holistic.md` |
| BH-K | code-bug-hunter-multipass | 1 | 2 | `2026-03-03-phase4-bughunt-multipass.md` |
| BH-L | code-bug-hunter-exploratory | 1 | 2 | `2026-03-03-phase4-bughunt-exploratory.md` |

All three variants completed without truncation or context exhaustion.

### Phase 4 Bug Detection

3 unique bugs across all variants:

| # | Bug | Severity | BH-J | BH-K | BH-L |
|---|-----|----------|:----:|:----:|:----:|
| 1 | Float parse `return v, json.Unmarshal(raw, &v)` — unspecified eval order | critical (disputed) | #1 (critical) | #1 (critical) | Design concern ("tests pass") |
| 2 | PostFilter AND semantics breaks OR rules in evaluator | significant | #2 | — | — |
| 3 | ExecuteDSLQuery silently drops PostFilters (NL search + saved search) | significant | — | — | #1 |

**Unique contributions:**
- **BH-J:** 1 unique significant (PostFilter AND semantics in evaluator)
- **BH-K:** 0 unique — its only finding was also found by BH-J
- **BH-L:** 1 unique significant (ExecuteDSLQuery drops PostFilters)

**The float bug dispute:** BH-J/K both claim `return v, json.Unmarshal(raw, &v)` always returns 0.0 (left-to-right evaluation). BH-L claims "Tests confirm this works correctly with the current gc compiler." The Go spec says the order of variable reads relative to function calls is **not specified** — both positions are partially right. BH-J/K correctly identify code that should be fixed (unspecified behavior); BH-L correctly notes the uncertainty but incorrectly dismisses it. Verification requires running the tests. Regardless, the code should be fixed — `kindTime` right below does it correctly.

**Complementary PostFilter findings:** BH-J traced compiler→evaluator and found `applyPostFilters` always uses AND (wrong for OR rules). BH-L traced compiler→evaluator→dsl_executor and found `ExecuteDSLQuery` never applies PostFilters at all. Neither found both — different analytical threads, both genuine.

### Phase 4 Scoring

#### Rubric 1: Bugs-Only (adapted)

| Metric | Weight | BH-J | BH-K | BH-L |
|--------|--------|:----:|:----:|:----:|
| Critical/important bug detection | 40% | 10 (found float bug + PostFilter AND — deepest analysis) | 7 (found float bug only; missed both PostFilter issues) | 4 (incorrectly dismissed float bug; found ExecuteDSLQuery drop) |
| Novel/unique bugs found | 20% | 8 (2 total, 1 unique: PostFilter AND) | 3 (1 total, 0 unique) | 5 (1 bug + 1 correct concern, 1 unique: ExecuteDSLQuery) |
| Evidence quality | 20% | 10 (Go spec citation, kindTime comparison, concrete OR example) | 8 (same float analysis, fix included; thin — only 1 finding) | 6 (good ExecuteDSLQuery tracing; wrong on float bug assessment) |
| False positive rate | 20% | 10 | 10 | 10 |
| **Weighted total** | | **9.60** | **7.00** | **5.80** |

#### Rubric 2: Bugs + Analysis Quality

| Metric | Weight | BH-J | BH-K | BH-L |
|--------|--------|:----:|:----:|:----:|
| Critical bug detection | 25% | 10 | 7 | 4 |
| Novel bugs found | 15% | 8 | 3 | 5 |
| Cross-file reasoning | 20% | 10 (compiler→evaluator PostFilter AND + compiler→validator float) | 6 (float bug is single-file; no cross-file findings) | 8 (compiler→evaluator→dsl_executor three-package tracing) |
| Failure mode depth | 15% | 9 (OR rule example, all-consumer enumeration) | 7 (consumer list but no failure scenarios beyond float) | 8 (LLM-generated regex scenario, caller tracing) |
| Evidence quality | 15% | 10 | 8 | 6 |
| False positive rate | 10% | 10 | 10 | 10 |
| **Weighted total** | | **9.55** | **6.65** | **6.45** |

### Phase 4 Analysis

#### The 21-file scope didn't differentiate exploratory

Phase 4 was the largest scope tested — 21 files, which was expected to test whether holistic hits reading capacity limits. It didn't. Holistic read everything and found the most bugs (2), including both the critical float bug and the unique PostFilter AND bug. The exploratory variant's selective depth-first approach found a unique bug (ExecuteDSLQuery) but incorrectly dismissed the critical one. Multipass had its weakest showing across all phases (1 bug in 21 files).

#### Why multipass was weakest in Phase 4

Multipass's five passes missed both PostFilter issues despite having Pass 2 (Cross-Sibling Pattern Violations) and Pass 5 (Error Propagation) which should have caught them. The PostFilter AND semantics bug is a cross-sibling issue (evaluator applies PostFilters differently than the rule's logic field suggests), and the ExecuteDSLQuery drop is an error propagation issue (compiler output is consumed differently by two callers). The structured passes may lose depth at larger scopes — more files per pass means less attention per file.

#### Complementary analysis between BH-J and BH-L

The most interesting Phase 4 result: holistic and exploratory each found a unique PostFilter bug the other missed. BH-J focused on the evaluator's AND semantics; BH-L assumed the evaluator was correct and traced to dsl_executor. Running both would have caught all three bugs. This is the first phase where exploratory found something holistic missed.

### Phase 4 Actionable bugs to fix

Prioritized by severity and impact:

1. **Float parse unspecified behavior** (critical/significant) — split Unmarshal and return into separate statements, matching `kindTime` pattern
2. **PostFilter AND semantics in evaluator** (significant) — propagate rule logic to `applyPostFilters`, use OR when rule logic is OR
3. **ExecuteDSLQuery drops PostFilters** (significant) — apply PostFilters after SQL query in the executor, or have callers apply them

---

## Full Cross-Phase Comparison

| Variant | Ph1 R1 | Ph3a R1 | Ph3b R1 | Ph4 R1 | **Avg R1** | Ph1 R2 | Ph3a R2 | Ph3b R2 | Ph4 R2 | **Avg R2** |
|---------|:------:|:-------:|:-------:|:------:|:----------:|:------:|:-------:|:-------:|:------:|:----------:|
| **Holistic** | **9.80** | **9.40** | 8.00 | **9.60** | **9.20** | **9.70** | **9.40** | 7.95 | **9.55** | **9.15** |
| **Multipass** | 9.60 | 7.40 | **9.40** | 7.00 | 8.35 | 9.35 | 7.60 | **9.05** | 6.65 | 8.16 |
| **Exploratory** | 9.20 | 7.40 | 6.60 | 5.80 | 7.25 | 9.05 | 7.50 | 6.60 | 6.45 | 7.40 |

### Wins by phase

| Phase | Winner (R1) | Winner (R2) | Bug type that dominated |
|-------|-------------|-------------|------------------------|
| Phase 1 (data pipeline) | Holistic (9.80) | Holistic (9.70) | Cross-file (PK migration cascade) |
| Phase 3a (notification delivery) | Holistic (9.40) | Holistic (9.40) | Cross-file (activation pipeline wiring) |
| Phase 3b (email/templates/digests) | **Multipass (9.40)** | **Multipass (9.05)** | Localized pattern violations (RuleID serialization) |
| Phase 4 (AI/DSL/saved searches) | Holistic (9.60) | Holistic (9.55) | Cross-file (PostFilter flow across packages) |

Holistic wins 3 of 4 phases. Multipass wins when bugs are localized contract/pattern violations.

### Final Recommendation

**Adopt holistic as the primary bug hunter skill.** Average R1 9.20, R2 9.15. Wins 3 of 4 phases. Remarkably consistent (8.00–9.80 on R1, σ=0.70). The only variant that reliably finds critical bugs through cross-file reasoning.

**Keep multipass as a complement for focused contract/pattern audits.** Average R1 8.35, R2 8.16. Wins Phase 3b decisively (9.40 vs 8.00) when bugs are localized. High variance (7.00–9.60 on R1, σ=1.12) — excels at pattern violations, fails at cross-file reasoning. Run it alongside holistic when the scope is dominated by API handlers, serialization, or cross-sibling patterns. Never as a replacement.

**Retire exploratory or reserve for very large scopes (30+ files).** Average R1 7.25, R2 7.40. Zero unique contributions in 3 of 4 phases. The 21-file scope of Phase 4 still didn't differentiate it from holistic. Its one bright spot (Phase 4: ExecuteDSLQuery) shows it CAN find things holistic misses when following different threads, but this is inconsistent. If future scopes exceed holistic's reading capacity, re-evaluate.

**For maximum bug yield: run holistic + multipass on the same scope.** The union of their findings captures nearly all bugs. Holistic provides the critical cross-file finds; multipass fills in the localized pattern violations holistic sometimes misses.
