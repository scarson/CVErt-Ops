---
name: bug-hunt-cycle
description: Full bug hunt cycle — dispatch 3 bug hunters in parallel, cross-validate findings, present design decisions, and write a fix plan. Use when finishing a phase or auditing a body of work.
argument-hint: "<scope, e.g. 'Phase 9', 'PR 45', 'internal/feed/'>"
---

# Bug Hunt Cycle

Running a full bug hunt cycle for: **$ARGUMENTS**

This is a multi-phase workflow. Follow each phase in order. Do not skip phases.

---

## Phase 1: Research Scope

Determine what code falls within **$ARGUMENTS**. The goal is to give each bug hunter a precise, actionable scope — not a vague "look at everything."

**For a phase reference:**
- Check `dev/plans/` for a matching plan file — it lists the files and packages involved
- Check `git log --oneline` for commits belonging to the phase
- Run `git diff --stat <first-commit>^..<last-commit>` to get the file list

**For a PR reference:**
- Use `gh pr view <number> --json files` to get changed files
- Use `gh pr view <number> --json commits` for the commit range

**For a directory/package reference:**
- List the files directly

Produce a **scope summary**: a list of packages/files, a one-paragraph description of what this code does, and any known architectural context (e.g., "this is the alert evaluation pipeline — it coordinates between the store, the DSL compiler, and the notification fan-out"). This context helps the bug hunters understand *intent*, not just *syntax*.

Also identify **adjacent code** the hunters should be aware of but that isn't the primary target — shared utilities called by the scoped code, interfaces implemented, etc. Mention these so the hunters can follow threads across package boundaries.

---

## Phase 2: Dispatch Bug Hunters

Launch **three parallel subagents** using the Agent tool. All three MUST run concurrently.

Determine today's date and the scope slug (e.g., `phase9`, `pr-45`, `feed-adapters`) for file naming. Each agent writes its report to `dev/bug-hunts/`.

### Agent prompts

Each agent gets:
1. The scope summary and file list from Phase 1
2. The adjacent code context
3. Its specific methodology (below)
4. The output file path
5. This instruction: **"Write your full report to the specified file AND return your findings in your response. The file is the persistent record; the response is for consolidation."**

**Exploratory agent:**
```
You are a bug hunter using depth-first exploration. Read the skill at
.claude/skills/code-bug-hunter-exploratory/SKILL.md and follow it exactly.

Scope: [paste scope summary + file list]
Adjacent code to be aware of: [paste adjacent context]
Output file: dev/bug-hunts/<date>-<slug>-exploratory.md

Write your report to the output file. Also return your full findings in
your response so they can be consolidated with the other hunters' results.
```

**Holistic agent:**
```
You are a bug hunter using holistic read-everything-then-reason analysis.
Read the skill at .claude/skills/code-bug-hunter-holistic/SKILL.md and
follow it exactly.

Scope: [paste scope summary + file list]
Adjacent code to be aware of: [paste adjacent context]
Output file: dev/bug-hunts/<date>-<slug>-holistic.md

Write your report to the output file. Also return your full findings in
your response so they can be consolidated with the other hunters' results.
```

**Multipass agent:**
```
You are a bug hunter using five focused analysis passes (contract violations,
cross-sibling patterns, failure modes, concurrency, error propagation).
Read the skill at .claude/skills/code-bug-hunter-multipass/SKILL.md and
follow it exactly.

Scope: [paste scope summary + file list]
Adjacent code to be aware of: [paste adjacent context]
Output file: dev/bug-hunts/<date>-<slug>-multipass.md

Write your report to the output file. Also return your full findings in
your response so they can be consolidated with the other hunters' results.
```

Wait for all three to complete before proceeding.

---

## Phase 3: Cross-Validate and Consolidate

Read all three reports (both from agent responses and the files in `dev/bug-hunts/`). Build a unified findings list.

**COMPLETENESS REQUIREMENT:** You MUST account for every single finding from every hunter report. Before starting cross-validation, enumerate all findings across all 3 reports. Every finding must appear in the consolidated report as one of: confirmed bug, design decision, false positive, or out-of-scope. **You do NOT get to decide what's "too minor" to include — that's Sam's decision in Phase 5.** Silently dropping findings defeats the entire purpose of the bug hunt.

### 3a. Deduplicate

Many findings will overlap. Group findings that describe the same underlying issue. Note consensus — "all three found this" is a strong signal; "only one found this" needs extra scrutiny.

### 3b. Cross-validate EVERY finding

For each unique finding, determine its validity:

1. **Read the actual code** at the cited location. Do not trust the hunter's description alone — verify the evidence yourself.
2. **Check if another hunter examined the same code and found it correct** (or intentional). If the holistic hunter flags X as a bug but the exploratory hunter followed that thread and noted it was intentional, that's a resolution — document it.
3. **Check if the "bug" is actually a documented design decision** in PLAN.md, `dev/research.md`, or `dev/implementation-pitfalls.md`.
4. **Verify the impact claim.** Is the failure mode actually reachable? Under what conditions?

Classify each finding as:
- **Confirmed bug** — verified incorrect behavior with evidence
- **Design decision needing user input** — legitimate concern but the correct fix depends on product intent, architectural tradeoffs, or scope decisions that require Sam's judgment
- **False positive** — incorrect finding, explain why
- **Out of scope / pre-existing** — valid bug but clearly unrelated to the specified scope (still document it)

### 3c. Blast radius analysis

For confirmed bugs and out-of-scope bugs, assess blast radius:
- What other code calls/uses the buggy code?
- Would the fix require changes outside the scoped packages?
- Could the fix break existing behavior that callers depend on (even if that behavior is technically wrong)?

If a fix has **larger scope** than the scoped work (e.g., modifying shared utility code that other packages use), flag it explicitly. These will be surfaced to the user in Phase 4.

### 3d. Write consolidated report

Write the consolidated report to `dev/bug-hunts/<date>-<slug>-consolidated.md` using this structure:

```markdown
# <Scope> Bug Hunt — Consolidated Findings

**Date:** <YYYY-MM-DD>
**Scope:** <description of what was analyzed>
**Hunters:** Exploratory, Holistic, Multipass

---

## Confirmed Bugs

### B1. <Title>
**Consensus:** <which hunters found it, or "verified by consolidation">
**Location:** <file:line>
**Evidence:** <what the code does vs what it should do>
**Impact:** <what goes wrong in practice>
**Blast radius:** <what else would need to change>
**Fix approach:** <brief description>

(Repeat for each confirmed bug)

---

## Design Decisions Requiring User Input

### D1. <Title>
**Location:** <file:line>
**The concern:** <what the hunters flagged>
**Why this needs a decision:** <what tradeoffs are involved>
**Options:** <enumerate the choices with pros/cons>
**Recommendation:** <if you have one, state it with reasoning>

---

## False Positives

### FP1. <Title>
**Flagged by:** <which hunter>
**Why invalid:** <brief explanation>

---

## Bugs Outside Primary Scope

### O1. <Title>
**Location:** <file:line>
**Blast radius:** <what would need to change>
**Recommendation:** <fix in this cycle or document for later>
```

**COMPLETENESS CHECK:** Before moving on, re-read every hunter report and verify that every finding is accounted for in the consolidated report. Count the findings: the total of confirmed + design decisions + false positives + out-of-scope MUST equal or exceed the total unique findings across all hunter reports. If any are missing, add them now.

After writing the consolidated report, update your private journal with key observations: what patterns emerged across hunters, which findings surprised you, what the false-positive rate looked like, and any insights about the codebase's risk profile.

---

## Phase 4: Test Gap Analysis

For each **confirmed bug**, reflect on why existing tests didn't catch it. This phase improves the project's testing safety net — not just the code.

### 4a. Why didn't tests catch this?

For each confirmed bug, answer:

1. **Do tests exist** for the code path where the bug lives? If not, why not — was it an oversight, or was the code path considered untestable?
2. **If tests exist**, why didn't they catch it? Common reasons:
   - Tests only cover the happy path
   - Tests mock the component where the bug actually lives
   - Tests assert on the wrong thing (e.g., "no error returned" instead of "correct value produced")
   - Test inputs don't exercise the edge case
   - Integration between components isn't tested (unit tests pass individually but the composition is broken)
3. **What test would have caught this?** Briefly describe the test — input, expected behavior, why it would fail against the buggy code. (This feeds into the fix plan in Phase 6.)

### 4b. Review against `dev/testing-pitfalls.md`

Read `dev/testing-pitfalls.md` and check each confirmed bug's test gap against the documented pitfalls:

- **Pitfall already covers this scenario** — the test gap exists because the pitfall guidance wasn't followed. Note which pitfall applies. No doc update needed, but flag it in the fix plan so the subagent knows to follow that specific pitfall.
- **Pitfall doesn't cover this scenario** — the bug reveals a testing blind spot not yet documented. Draft a candidate addition to `dev/testing-pitfalls.md`.

### 4c. Update `dev/testing-pitfalls.md` if warranted

For each candidate addition from 4b, assess whether it's **generalizable** — would this pitfall apply to future code in this project, or is it a one-off specific to this bug?

- **Generalizable:** Write the addition to `dev/testing-pitfalls.md`. Follow the existing format and conventions in the file. Keep it concise — a pitfall entry should be actionable, not a narrative.
- **One-off:** Don't update the file. Instead, include a specific testing note in the fix plan task for this bug.

### 4d. Add test gap summary to consolidated report

Append a section to `dev/bug-hunts/<date>-<slug>-consolidated.md`:

```markdown
---

## Test Gap Analysis

### B1. <Bug title>
**Why missed:** <reason tests didn't catch it>
**Pitfall coverage:** <"covered by pitfall X — not followed" or "new pitfall added" or "one-off — noted in fix plan">
**Catch test:** <brief description of the test that would have caught it>

(Repeat for each confirmed bug)

### Testing Pitfalls Updates
- <List any additions made to dev/testing-pitfalls.md, or "None">
```

---

## Phase 5: Present to User

Present the findings to Sam. Structure the presentation as:

1. **Executive summary** — X confirmed bugs, Y design decisions needing input, Z false positives, W out-of-scope findings
2. **Confirmed bugs** — brief table (title, severity, location, fix complexity)
3. **Design decisions** — present each one with enough context for an informed decision. Think through each decision point in the context of the overall project architecture (PLAN.md, research.md). Make recommendations where you have a well-reasoned opinion, but be clear about what's a recommendation vs what's a clear correct answer.
4. **Out-of-scope bugs with larger blast radius** — for each, ask: include in fix plan, or document for later?

**Wait for Sam's input on all design decisions and scope questions before proceeding to Phase 6.**

---

## Phase 6: Write Fix Plan

After Sam has provided input on all decisions, invoke `/writing-plans` to create an implementation plan for all confirmed bugs + any out-of-scope bugs Sam chose to include. The plan file MUST be saved to `dev/plans/<date>-<slug>-remediation-plan.md` (e.g., `dev/plans/2026-03-18-phase11-mfa-bug-hunt-remediation-plan.md`).

When `/writing-plans` presents execution options, **include a recommendation** for which approach would be most effective. The three options are: (1) subagent-driven in this session, (2) parallel session with `/executing-plans` in a worktree, or (3) Agent Teams for multi-agent parallel execution. Base the recommendation on: how much context this session has consumed, whether the plan is self-contained enough for a fresh session, how many tasks are parallelizable vs sequential, and whether any tasks are risky enough to warrant focused attention rather than parallel dispatch. Explain the reasoning concisely.

### Critical requirements for the plan

The plan will be executed via `/subagent-driven-development` or `/executing-plans`. Subagents are powerful but fail in predictable ways. The plan MUST be written to prevent these failures:

1. **Eliminate ambiguity.** For each task, specify:
   - The exact files to modify
   - The exact behavior change (current behavior → desired behavior)
   - The exact test to write (input, expected output, edge cases)
   - Whether the fix requires coordination with other tasks (ordering dependencies)

2. **Prevent context gaps.** Subagents start fresh with no conversation history. Each task description must be self-contained:
   - Include the bug evidence (file:line, what's wrong)
   - Include the fix approach (don't just say "fix the bug")
   - Include relevant architectural context from PLAN.md if the fix depends on understanding a design choice
   - If the fix touches shared code, explicitly list other callers that must still work

3. **Prevent interpretation drift.** Where there's only one correct fix, state it explicitly. Don't leave room for a subagent to "improve" or "enhance" the fix beyond what's needed. Where there are multiple valid approaches, pick one and specify it — don't let the subagent choose.

4. **Mandate TDD and testing discipline.** Every task MUST include this preamble:
   ```
   BEFORE starting work:
   1. Read the skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
   2. Read dev/testing-pitfalls.md
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

5. **Review against `dev/testing-pitfalls.md`.** Read it yourself and check whether any of the planned fixes could fall into documented testing pitfalls. If so, add explicit warnings to the relevant task descriptions.

6. **Review against `dev/implementation-pitfalls.md`.** Same — check if any fixes could fall into documented implementation pitfalls.

7. **Group tasks to minimize cross-task conflicts.** If two bugs touch the same file, they should be in the same task or explicitly sequenced. Parallel subagents editing the same file will create merge conflicts.

### Deferred bugs appendix

If Sam chose to defer any out-of-scope bugs, add an appendix to the plan:

```markdown
## Appendix: Bugs Identified But Not Fixed in This Cycle

### <Title>
**Location:** <file:line>
**Evidence:** <what's wrong>
**Why deferred:** <Sam's reasoning or scope decision>
**Recommended fix:** <brief approach for when this is addressed>
```

This appendix is the persistent record. It MUST be written to the plan file — not left in conversation memory.

---

## Phase 7: Plan Review Cycle

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

## Phase 8: Commit Reports

Stage and commit all bug hunt artifacts:

```bash
git add dev/bug-hunts/<date>-<slug>-*.md
git add dev/plans/<plan-file>            # if the plan was written
git add dev/testing-pitfalls.md          # if updated in Phase 4
git commit -m "docs(bug-hunt): <slug> — consolidated findings and fix plan"
```
