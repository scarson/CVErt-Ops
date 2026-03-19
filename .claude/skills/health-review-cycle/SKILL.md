---
name: health-review-cycle
description: Full health review cycle — dispatch 5 adversarial dimension agents, cross-validate findings, present design decisions, and write a fix plan. Use periodically as a health check or before major milestones.
argument-hint: "[optional: specific area to focus on, or 'full' for all dimensions]"
---

# Health Review Cycle

Running a full health review cycle for: **$ARGUMENTS** (default: full review across all dimensions)

This is a multi-phase workflow. Follow each phase in order. Do not skip phases.

---

## Phase 1: Dispatch Health Review

Read the skill at `.claude/skills/project-health-review/SKILL.md` and execute it. This launches **5 parallel adversarial agents** (Code Quality, Architecture, Test Quality, Ops Readiness, API Design), each writing to `dev/health-reviews/`.

Follow the skill exactly through its Execution and Synthesis sections. This produces:
- 5 individual agent reports in `dev/health-reviews/`
- 1 consolidated synthesis report in `dev/health-reviews/`

**Do not proceed to Phase 2 until all 5 agents have completed and the consolidated report is written.**

---

## Phase 2: Cross-Validate Every Finding

The health review agents are adversarial by design — they look for problems. But adversarial agents also produce false positives, mischaracterize severity, and sometimes flag intentional design decisions as bugs. Every finding needs verification.

**COMPLETENESS REQUIREMENT:** You MUST account for every single finding from every agent report. Before starting cross-validation, enumerate all findings from all 5 agent reports and the synthesis. Every finding must appear in the validated report as one of: confirmed issue, design decision, false positive, or known/already-tracked. **You do NOT get to decide what's "too minor" to include — that's Sam's decision in Phase 3.** Silently dropping findings defeats the entire purpose of the adversarial review.

### 2a. Verify each finding against actual code

For each finding in the consolidated report AND in individual agent reports (agents may have findings the synthesis missed):

1. **Read the actual code** at the cited location. Do not trust the agent's description alone — verify the evidence yourself.
2. **Check PLAN.md and `dev/research.md`** — is this an intentional design decision? Some "problems" are documented tradeoffs.
3. **Check `dev/implementation-pitfalls.md`** — is this a known pattern with documented rationale?
4. **Check git history if needed** — was there a deliberate choice here? (`git log --oneline -5 <file>` or `git blame`)
5. **Verify severity** — is the claimed risk actually reachable? Under what conditions? An agent may flag a theoretical risk that's architecturally impossible.

### 2b. Cross-agent validation

When multiple agents flag the same area:
- **Agreement strengthens the finding** — if Architecture and Ops Readiness both flag it, it's likely real
- **Contradiction resolves it** — if Code Quality says "this abstraction is unnecessary" but Architecture says "this abstraction enables X," investigate who's right

When only one agent flags something:
- **Increased scrutiny** — single-agent findings have a higher false-positive rate
- **Check if other agents examined the same code** — an agent that read the code and didn't flag it is a weak counter-signal (they might have missed it), but it's worth noting

### 2c. Classify each finding

- **Confirmed issue** — verified problem with evidence
- **Design decision needing user input** — legitimate concern but the correct response depends on product priorities, architectural tradeoffs, or scope decisions that require Sam's judgment
- **False positive** — explain why the finding is incorrect or not applicable
- **Known / already tracked** — issue is real but already documented in an existing plan, bug hunt report, or implementation-pitfalls.md

### 2d. Blast radius analysis

For confirmed issues, assess fix complexity and blast radius:
- Is this a localized fix (one file, one function) or cross-cutting (touches many packages)?
- Would fixing this require API changes that affect the frontend?
- Would fixing this require migration changes?
- Are there ordering dependencies (must fix X before Y)?

### 2e. Write validated report

Write to `dev/health-reviews/<date>-<slug>-validated.md`:

```markdown
# <Scope> Health Review — Validated Findings

**Date:** <YYYY-MM-DD>
**Scope:** <description>
**Source:** Project health review (5-dimension adversarial)

---

## Confirmed Issues

### I1. <Title>
**Severity:** CRITICAL | MAJOR | MINOR
**Dimensions:** <which agents flagged it>
**Location:** <file:line or architectural description>
**Evidence:** <verified problem description>
**Blast radius:** <what would need to change>
**Fix approach:** <brief description>

(Repeat for each confirmed issue, ordered by severity)

---

## Design Decisions Requiring User Input

### D1. <Title>
**Flagged by:** <which agent(s)>
**The concern:** <what was flagged>
**Why this needs a decision:** <what tradeoffs are involved>
**Options:** <enumerate choices with pros/cons>
**Recommendation:** <if applicable>

---

## False Positives

### FP1. <Title>
**Flagged by:** <which agent>
**Why invalid:** <brief explanation>

---

## Known / Already Tracked

### K1. <Title>
**Flagged by:** <which agent>
**Where tracked:** <plan file, bug hunt report, or pitfalls doc>
```

**COMPLETENESS CHECK:** Before moving on, re-read every agent report and verify that every finding is accounted for in the validated report. Count the findings: the total of confirmed + design decisions + false positives + known/already-tracked MUST equal or exceed the total unique findings across all agent reports. If any are missing, add them now.

After writing the validated report, update your private journal with key observations: what patterns emerged across dimensions, which findings surprised you, what the false-positive rate looked like, and any insights about the project's overall health.

---

## Phase 3: Present to User

Present the validated findings to Sam. Structure the presentation as:

1. **Executive summary** — X confirmed issues (N critical, N major, N minor), Y design decisions needing input, Z false positives, W already-tracked
2. **Critical issues** — table (title, dimensions, location, fix complexity)
3. **Major issues** — same format
4. **Minor issues** — same format. **Do NOT omit minors.** Sam decides what to prioritize, not you.
5. **Design decisions** — present each with enough context for an informed decision. Think through each in the context of PLAN.md, project roadmap, and current phase. Make recommendations where you have a well-reasoned opinion.
6. **Already-tracked items** — briefly note these so Sam knows the health review didn't miss them, but no action needed
7. **Scope question** — ask which issues Sam wants in the fix plan:
   - All confirmed issues?
   - Critical + major only?
   - Critical only?
   - Specific subset?

**Wait for Sam's input on all design decisions and scope questions before proceeding to Phase 4.**

---

## Phase 4: Write Fix Plan

After Sam has provided input, invoke `/writing-plans` to create an implementation plan for the selected issues. The plan file MUST be saved to `dev/plans/<date>-<slug>-remediation-plan.md` (e.g., `dev/plans/2026-03-18-health-review-remediation-plan.md`).

When `/writing-plans` presents execution options, **include a recommendation** for which approach would be most effective. The three options are: (1) subagent-driven in this session, (2) parallel session with `/executing-plans` in a worktree, or (3) Agent Teams for multi-agent parallel execution. Base the recommendation on: how much context this session has consumed, whether the plan is self-contained enough for a fresh session, how many tasks are parallelizable vs sequential, and whether any tasks are risky enough to warrant focused attention rather than parallel dispatch. Explain the reasoning concisely.

### Critical requirements for the plan

Health review findings span multiple dimensions and often have complex dependencies. The plan MUST account for this:

1. **Eliminate ambiguity.** For each task, specify:
   - The exact files to modify
   - The exact behavior change (current behavior → desired behavior)
   - The exact test to write or update
   - Whether the fix requires coordination with other tasks (ordering dependencies)
   - Which health review dimension(s) the task addresses (for traceability)

2. **Prevent context gaps.** Each task must be self-contained:
   - Include the finding evidence from the validated report
   - Include the fix approach — don't just say "fix the issue"
   - Include relevant PLAN.md context if the fix must align with a design specification
   - For cross-cutting fixes: explicitly list all files and packages affected

3. **Prevent interpretation drift.** Health review fixes are especially prone to over-engineering — an agent asked to "fix an architectural issue" will often redesign the architecture. For each task:
   - Specify the minimum fix that addresses the finding
   - Explicitly state what NOT to change ("do not refactor X, only fix Y")
   - Where there's only one correct fix, state it

4. **Mandate TDD and testing discipline.** Every task MUST include this preamble:
   ```
   BEFORE starting work:
   1. Read dev/testing-pitfalls.md
   2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
   Follow TDD: write failing test → implement fix → verify green.
   ```
   Every task MUST include this completion check:
   ```
   BEFORE marking this task complete:
   1. Review your tests against dev/testing-pitfalls.md
   2. Verify test coverage of the fix (are error paths tested? edge cases?)
   3. Run `go test ./...` (or relevant subset) and confirm green
   ```
   Every logical group of tasks MUST include this review loop:
   ```
   After every logical group of tasks:
   You MUST carefully review the batch of work from multiple perspectives
   and revise/refine as appropriate. Repeat this review loop (you must do
   a minimum of three review rounds; if you still find substantive issues
   in the third review, keep going with additional rounds until there are
   no findings) until you're confident there aren't any more issues. Then
   update your private journal and continue onto the next tasks.
   ```

5. **Review against `dev/testing-pitfalls.md` and `dev/implementation-pitfalls.md`.** Check whether any planned fixes could fall into documented pitfalls. Add explicit warnings to relevant task descriptions.

6. **Order tasks by dependency, not severity.** Health review fixes often have implicit ordering:
   - Infrastructure fixes before feature fixes (e.g., fix RLS bypass before adding new endpoints)
   - Schema changes before code changes
   - Shared utility fixes before fixes in code that uses those utilities
   - Group tasks that touch the same file to avoid merge conflicts

7. **Separate quick wins from larger efforts.** If some findings are one-line fixes (e.g., `defer apiSrv.Close()`) and others are multi-day refactors (e.g., migrate all chi handlers to huma), group them separately. Quick wins can go in one task; larger efforts need their own tasks with clear scope boundaries.

### Deferred items appendix

If Sam chose not to fix some confirmed issues, add an appendix:

```markdown
## Appendix: Issues Identified But Not Fixed in This Cycle

### <Title>
**Severity:** <CRITICAL | MAJOR | MINOR>
**Dimensions:** <which agents flagged it>
**Evidence:** <what's wrong>
**Why deferred:** <Sam's reasoning or scope decision>
**Recommended approach:** <brief fix description for when this is addressed>
```

This appendix is the persistent record. It MUST be written to the plan file — not left in conversation memory.

---

## Phase 5: Plan Review Cycle

Before committing, rigorously review the fix plan for subagent-readiness.

Carefully review the plan from multiple perspectives and revise/refine as appropriate. Repeat this review loop (you must do a minimum of three review rounds; if you still find substantive issues in the third review, keep going with additional rounds until there are no findings) until you're confident there aren't any more issues. Specifically consider:

- **Ambiguity:** Are there task descriptions where a subagent could reasonably interpret the instructions two different ways? Eliminate every instance.
- **Context gaps:** Would a subagent starting fresh (no conversation history) have everything it needs to complete each task correctly? Check for implicit assumptions.
- **Unclear instructions:** Are there vague directives like "fix the issue" or "handle this correctly" instead of specific behavioral descriptions?
- **Undesirable interpretation latitude:** Are there areas where a subagent might "improve" or "enhance" beyond scope? Add explicit "do NOT" boundaries where needed.
- **Cross-task dependencies:** Are ordering constraints clearly stated? Would a subagent working on Task 3 know it depends on Task 1 completing first?
- **Testing pitfalls:** Review the plan against `dev/testing-pitfalls.md` — could any planned test additions fall into documented pitfalls? Add warnings to relevant tasks.
- **Implementation pitfalls:** Review the plan against `dev/implementation-pitfalls.md` — could any planned fixes fall into documented pitfalls?

After completing the review cycle, update your private journal with observations about the plan quality and any patterns in the issues you found.

---

## Phase 6: Commit Reports

Stage and commit all health review cycle artifacts:

```bash
git add dev/health-reviews/<date>-*
git add dev/plans/<plan-file>  # if the plan was written
git commit -m "docs(health): <slug> — validated findings and fix plan"
```
