---
name: performance-audit-cycle
description: Full performance audit cycle — dispatch the sibling performance-audit skill (parallel perf lanes + execution-cost map), cross-validate findings against real code and hot-path reachability, present decisions, and write a fix plan via writing-plans-enhanced with a measurement/verification gate. Use before scaling work, when chasing latency/throughput/resource regressions, or for an audit-and-fix loop rather than just a snapshot.
argument-hint: "<scope, e.g. 'the request pipeline', 'PR 45', 'src/render/'>"
---

# Performance Audit Cycle

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## Overview

Running a full performance audit cycle for: **$ARGUMENTS**

This is a multi-phase workflow. The runner MUST follow each phase in order and MUST NOT skip phases.

This skill orchestrates sibling workhorses in this plugin: [`performance-audit`](../performance-audit/SKILL.md) for the parallel lane dispatch + synthesis, [`writing-plans-enhanced`](../writing-plans-enhanced/SKILL.md) for the fix plan, and [`plan-review-cycle`](../plan-review-cycle/SKILL.md) for the adversarial plan review. The cycle owns scope research, cross-validation, optional dynamic confirmation, the user-decision loop, and performance-specific plan instructions. It MUST NOT duplicate the subagent-proofing, TDD, Living Document Contract, or plan-review discipline encoded in the delegated skills.

### Scope validation

If `$ARGUMENTS` is empty or unclear, the runner MUST ask the user for a scope before Phase 1. Useful shapes: a request/render path, a feature, a directory/package, a PR number, a commit range. The runner MUST NOT guess a scope or default to "everything" — performance lanes perform best on a precise, bounded surface.

**Whole-repo / oversized scope.** If the user DOES want "everything" — a whole repository, a top-level directory/package set, "all of `<X>`", or any surface materially larger than one run is optimized for (roughly >4k production LOC, or spanning more than one language/package) — do NOT cram it into one run and do NOT silently audit only part of it. Instead follow [`whole-repo-scoping.md`](whole-repo-scoping.md), **starting at its size-router (its first routing step)**, which sub-routes between a lightweight pass (small / ≤2 slices: survey, eyeball, run, 3-line ledger, no formal review round) and the full survey-through-execute + review-gate method (a repo / multi-package / larger surface / >2 languages). The method does the rest: survey + measure production LOC, build a cheap hot-path/reachability map, cut the code into bounded language-homogeneous slices by perf-relevance, calibrate cross-slice call frequency, assign depth tiers (full / reduced / cold sweep(s) / overlay), **adversarially review the partition before executing**, then run this cycle once per slice with a persistent progress ledger. That method turns "audit the whole repo" into a reviewed plan of bounded runs that collectively cover all the code.

---

## Phase 1 — Research scope

Determine what code falls within **$ARGUMENTS** and give the audit a precise, actionable scope.

- **Phase/feature:** check `docs/plans/` for a matching plan; `git log --oneline` for the commits; `git diff --stat` for the file list.
- **PR:** the changed files + commit range.
- **Directory/package:** list the files directly.

Produce a **scope summary** — files/packages, a one-paragraph description of what the code does, the realistic load it sees (request rates, data sizes, concurrency), and any known performance context. Identify **adjacent code** (shared utilities, hot callers) the lanes should be aware of. Realistic load matters: it's how the lanes calibrate Impact (reachability × frequency × per-occurrence cost).

---

## Phase 2 — Dispatch performance-audit

The runner MUST invoke the sibling [`performance-audit`](../performance-audit/SKILL.md) skill (or, if the framework cannot invoke skills by name, read its `SKILL.md` from the plugin install location), passing the scope summary + adjacent context. Follow it through Phase 0 (detection), Phase 1 (currency brief), Phase 2 (lane dispatch), and Phase 3 (synthesis). This produces raw per-lane reports + a consolidated report (and, if suspected bugs were found, a bug-hunt kickoff prompt) under `docs/perf-audits/`.

**The runner MUST NOT proceed until all dispatched lanes complete and the consolidated report is written.**

---

## Phase 3 — Cross-validate every finding

Audit lanes are adversarial and produce false positives, mischaracterize impact, and sometimes flag intentional tradeoffs. Every finding needs verification.

**COMPLETENESS REQUIREMENT:** The runner MUST account for every single finding from every lane report (not just the synthesis — lanes may carry findings the synthesis merged or missed). Before validating, enumerate all findings. Every finding MUST appear in the validated report as one of: confirmed / design decision / false positive / out-of-scope. **The runner MUST NOT decide what's "too minor" to include — that's the user's decision in Phase 5.** Silently dropping findings defeats the audit.

For each finding:
1. **Read the actual code** at the cited location. Verify the evidence yourself.
2. **Confirm hot-path reachability** — is the code actually reached under the realistic load from Phase 1? An impressive-looking quadratic over input that's always tiny is not a real finding. Re-rank Impact if the lane over- or under-stated reachability.
3. **Check plan/design/pitfalls docs** — is this an intentional, documented tradeoff?
4. **Verify the impact claim** — is the cost real and on the aggregate-cost path? Cross-reference the Execution Cost Map.
5. **Cross-lane validation** — agreement across lanes strengthens; single-lane findings get extra scrutiny.

Classify each: **Confirmed** · **Design decision needing user input** · **False positive** (explain why) · **Out of scope / pre-existing** (still document).

**Blast-radius analysis** for confirmed findings: what else calls this code; would the fix change an API/signature affecting consumers; ordering dependencies; could the optimization alter observable behavior (a correctness risk)?

Write `docs/perf-audits/<date>-<slug>-validated.md` (Confirmed / Design decisions / False positives / Out-of-scope sections, each finding carrying the finding-model fields + blast radius). **COMPLETENESS CHECK:** re-read every lane report; confirmed + design + false-positive + out-of-scope MUST be ≥ the total unique findings. Add any missing.

---

## Phase 4 — Optional dynamic validation

If the environment can build and run the project AND a real workload exists (or can be defensibly constructed — never invent load), the runner SHOULD measure the worst confirmed findings to confirm or refute them before presenting. Measurement upgrades a finding's Confidence to `Measured`. If the project isn't runnable or no honest workload exists, skip this phase and state why in the validated report. The runner MUST NOT fabricate benchmark numbers.

---

## Phase 5 — Present to user

Present the validated findings. Structure:

1. **Executive summary** — X confirmed (N critical / N major / N minor), Y design decisions, Z false positives, W out-of-scope. Include the **regression delta** from the run metadata (vs the prior same-scope run: N new / N persisting / N resolved) and name the new and resolved findings — that's the trend signal the user most wants.
2. **Confirmed findings** — table (title, impact rank, location, on-cost-map, effort as work magnitude). **The runner MUST NOT omit minors.** The user prioritizes, not the runner.
3. **Execution Cost Map highlights** — the likely time-concentration regions, for architectural awareness.
4. **Design decisions** — each with enough context for an informed call; recommend where you have a well-reasoned opinion.
5. **Out-of-scope findings with larger blast radius** — include in fix plan, or document for later?
6. **Suspected bugs** — note the appendix exists and that a `bug-hunt-cycle` kickoff prompt is ready (suggest running it; do not auto-invoke).
7. **Scope question for the fix plan** — the default is **ALL confirmed findings** (see Phase 6 disposition discipline). Ask the user only which, if any, they want to *opt out*, and surface any agent-recommended substantive deferrals for their decision.

**The runner MUST wait for the user's input on design decisions and opt-outs before Phase 6.**

---

## Phase 6 — Write fix plan

After user input, the runner MUST invoke [`writing-plans-enhanced`](../writing-plans-enhanced/SKILL.md) to create the implementation plan. That skill owns subagent-proofing, TDD, pitfall review, cross-task conflict minimization, and the Living Document Contract — the cycle MUST NOT duplicate them. The runner MUST pass these **performance-specific instructions** to layer on top:

- **Plan file path:** `docs/plans/<date>-<slug>-perf-audit-remediation-plan.md`. The `-perf-audit-remediation-plan.md` suffix distinguishes these from bug-hunt / health-review plans.
- **Source:** the validated findings report at `docs/perf-audits/<date>-<slug>-validated.md`.
- **Traceability + self-contained task titles:** each task MUST cite its originating finding ID (`P1`, `P2`, …) **as a suffix for traceability**, but the task title and description MUST stand on their own — describe what / where / why (e.g. "Batch line-item catalog lookups in `enrich_line_items` — one DB round-trip instead of one per item [perf finding P3]"), never just "Fix P3" or "address the `data-access` lane". This discipline carries into the resulting commit messages, PR text, and code comments. See `finding-model.md` "Referring to findings".
- **Verification gate — every task MUST include:**
  - a **baseline** captured *before* the change — a measurement OR an explicit complexity/allocation argument;
  - a **post-change demonstration** that it improved — a measurement OR argument; **if it does not improve, revert the change**;
  - a **correctness guard** — existing tests pass + a test pinning the behavior the optimization must preserve (per TDD; consult `testing-anti-patterns` so the guard tests real behavior, not mocks).
- **No severity-based deferral (disposition discipline, per `finding-model.md`):** every finding's default disposition is **FIX**. The plan MUST schedule **all** findings by default. A finding may be dropped only when the **user explicitly opted it out** (Phase 5) or the agent gives a **substantive reason naming a specific concrete mechanism** (the exact refactor it collides with; the exact out-of-scope dependency bump; the specific correctness regression + why it outweighs the gain). "Minor / low-priority / might be risky / could be complex" is **forbidden** as a deferral rationale. Deferred items go in the Deferred appendix (below) with their named mechanism or the user's opt-out.
- **Counter over-optimization:** specify the minimum change per task; state what NOT to touch. Performance tasks tempt wholesale rewrites.
- **Advisory:** after remediation, run the auto-generated bug-hunt kickoff over the diff — performance changes are a classic bug source.

When `writing-plans-enhanced` presents execution options, the runner MUST recommend one with reasoning (context consumed, self-containment, parallelizable vs sequential tasks, risk).

### Deferred items appendix

If any findings are deferred, the plan MUST include:

```markdown
## Appendix: Findings Identified But Not Fixed in This Cycle
### <Title>  (finding <Pn>)
**Impact:** <rank>   **Location:** <file:line>
**Why deferred:** <user opt-out OR the specific named mechanism — refactor/dependency/regression>
**Recommended approach:** <brief fix for when this is addressed>
```

This appendix is the persistent record — written to the plan file, never left in conversation memory.

---

## Phase 7 — Plan review cycle

Before committing, the runner MUST review the fix plan for subagent-readiness by invoking [`plan-review-cycle`](../plan-review-cycle/SKILL.md). That skill owns the multi-round adversarial review; the cycle MUST NOT duplicate it. After it completes, the runner SHOULD log plan-quality observations to the project's pattern store (key `plan-review-<slug>`).

---

## Phase 8 — Commit reports

The runner MUST stage and commit all performance audit cycle artifacts:

```bash
git add docs/perf-audits/<date>-<slug>-*
git add docs/perf-audits/runs.jsonl    # the run ledger (historical/regression substrate)
git add docs/perf-audits/cache/        # if a currency brief was refreshed
git add docs/plans/<plan-file>         # if the plan was written
git commit -m "docs(perf): <slug> — validated findings and fix plan"
```

---

## Phase 9 — Whole-repo / multi-slice roll-up (conditional)

When this cycle was run **once per slice** as part of a whole-repo plan (per [`whole-repo-scoping.md`](whole-repo-scoping.md)), add **one cross-slice roll-up after the last slice**. It is the single highest-value artifact of a whole-repo run: it turns N per-slice reports into systemic themes a per-unit view can't see — e.g. a transport-write-buffering theme spread across four protocol slices is invisible in any one report but obvious across them.

- **Inputs:** `docs/perf-audits/runs.jsonl` (the run ledger) + every slice's consolidated report.
- **Output:** `docs/perf-audits/<date>-WHOLE-REPO-ROLLUP.md` — shared root causes / repo-wide themes grouped *across* slices, a prioritized cross-slice fix list, and a heat map (slice × tier × severity). **Surface any `frequency-unresolved — assume-hot` findings** (from the method's cross-slice calibration) for the operator to confirm reachability, rather than letting an unverified assume-hot finding ship top-ranked.
- **When:** conditionally REQUIRED when the request was a *posture* question ("how's the repo's performance?"); optional when it was "find and queue fixes". For a **service monorepo** it is **two-level** — a per-service synthesis, then a cross-service meta-roll-up.

This does not re-audit; it synthesizes already-committed slice reports. Commit it like the slice reports.
