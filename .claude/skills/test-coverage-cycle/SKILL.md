---
name: test-coverage-cycle
description: Full test coverage cycle — run hybrid coverage review, cross-validate findings, present design decisions, and write a fix plan. Use when finishing a phase or auditing test coverage for a body of work.
argument-hint: "<scope, e.g. 'Phase 9', 'PR 45', 'internal/feed/'>"
---

# Test Coverage Cycle

Running a full test coverage cycle for: **$ARGUMENTS**

This is a multi-phase workflow. Follow each phase in order. Do not skip phases.

---

## Phase 1: Research Scope

Determine what code falls within **$ARGUMENTS**. The goal is to identify the packages to cover and any architectural context that informs what "correct" test coverage means.

**For a phase reference:**
- Check `dev/plans/` for a matching plan file — it lists the files and packages involved
- Check `git log --oneline` for commits belonging to the phase
- Run `git diff --stat <first-commit>^..<last-commit>` to get the file list

**For a PR reference:**
- Use `gh pr view <number> --json files` to get changed files
- Use `gh pr view <number> --json commits` for the commit range

**For a directory/package reference:**
- List the files directly

Produce a **scope summary**:
- List of packages/files in scope
- A one-paragraph description of what this code does
- Which packages contain security-critical code (auth, tenant isolation, crypto, input validation) — these get extra scrutiny
- Which packages contain API handlers — these need the security checklist matrix
- Adjacent packages that callers/callees of scoped code live in (needed for `-coverpkg`)

---

## Phase 2: Run Coverage Baseline

Run coverage in the main session. This data is the shared baseline for all subsequent analysis.

**Use a scope-specific filename in `dev/coverage/`** to avoid clobbering other concurrent coverage runs and keep the project root clean. The directory is already gitignored via the `*.out` glob.

```bash
mkdir -p dev/coverage
# Use the scope slug from Phase 1 + timestamp (supports before/after comparisons)
COVER_FILE="dev/coverage/coverage-<slug>-$(date +%Y%m%d-%H%M%S).out"

# Adjust -coverpkg to include adjacent packages that scoped code calls
# Timeout: 600s minimum — each DB test spins its own testcontainer, and
# concurrent agents competing for container resources make this worse.
# A full-suite run that times out forces re-runs in segments, taking longer overall.
go test -coverprofile="$COVER_FILE" \
  -coverpkg=./internal/... \
  -count=1 -timeout=600s \
  ./internal/...
```

Then extract per-function coverage:

```bash
go tool cover -func="$COVER_FILE"
```

Save both outputs. Note any test failures — failed packages still generate partial coverage. Do NOT exclude failing packages.

Determine the scope size from the function count:

| Scope | Functions | Strategy |
|-------|-----------|----------|
| Small | <100 | Single agent runs the full hybrid review |
| Medium | 100–300 | 2 subagents for triage + semantic, main agent owns security matrix |
| Large | 300–600 | 3 subagents, file-based output, incremental report |
| XL | 600+ | Split into sub-scopes and run this skill multiple times |

---

## Phase 3: Dispatch Coverage Review

Launch the hybrid coverage review. The methodology is in `.claude/skills/test-coverage-review-hybrid-go/SKILL.md` — this is the most thorough coverage skill, combining Go coverage tools with semantic code analysis.

### Small scopes (<100 functions)

Launch **one subagent** that runs the full hybrid review:

```
You are a test coverage reviewer using the hybrid (coverage tools + semantic analysis) methodology.

Read the skill at .claude/skills/test-coverage-review-hybrid-go/SKILL.md and follow it exactly.

Scope: [paste scope summary + package list]
Coverage data (`go tool cover -func` output):
[paste func output]

Output file: dev/test-coverage-reports/<date>-<slug>-hybrid-coverage-review.md

Write your full report to the output file. Also return your findings in
your response so they can be consolidated.

IMPORTANT: This is research only. DO NOT write any code or fix any tests.
```

### Medium+ scopes (100+ functions)

Launch **two parallel subagents** plus do the security matrix yourself:

**Subagent 1 — Coverage-guided triage:**
```
Perform coverage-guided triage (§2 of the hybrid skill) for [packages].

Coverage data:
[paste relevant func output lines]

Analyze every function: 0% → classify risk; 1-99% → identify uncovered branches;
100% security functions → audit assertion quality.

Output file: dev/test-coverage-reports/subagent-<slug>-triage.md
Return ONLY: file path, counts by severity, top 3 findings, any production bugs.
DO NOT write code.
```

**Subagent 2 — Semantic analysis:**
```
Perform semantic analysis (§4B-E of the hybrid skill) for [packages].

For every API handler and security-critical function:
- Right-function-called (§4B)
- TOCTOU windows (§4C)
- Defense-in-depth (§4D)
- Store-layer independence (§4E)
Also: assertion quality audit (§5) for covered security code.

Output file: dev/test-coverage-reports/subagent-<slug>-semantic.md
Return ONLY: file path, counts by severity, top 3 findings, any production bugs.
DO NOT write code.
```

**Main agent — Security checklist matrix (§3):**

While subagents run, build the security checklist matrix yourself. This requires cross-handler visibility that subagents lack. Follow §3 of the hybrid skill exactly — enumerate all endpoints first, fill every cell, spot-check 3 "Tested" cells.

After all subagents complete, perform **cross-handler consistency analysis (§4A)** yourself.

Wait for all agents to complete before proceeding.

---

## Phase 4: Cross-Validate and Consolidate

Read all reports (subagent files + your own matrix/cross-handler analysis). Build a unified findings list.

### 4a. Verify every finding

For each gap or bug reported:

1. **Read the actual code** at the cited location. Verify the evidence — don't trust descriptions alone.
2. **Check for false positives.** Is the "gap" actually covered by a test the reviewer missed? Is the "bug" intentional behavior documented in PLAN.md or `dev/research.md`?
3. **Check assertion quality claims.** If a test is flagged as "execution-only," read the test and confirm. Sometimes assertions are in helper functions the reviewer didn't follow.
4. **Verify TOCTOU claims.** Is the temporal window actually exploitable, or is there a transaction/lock the reviewer didn't see?

Classify each finding as:
- **Confirmed gap/bug** — verified with evidence
- **Design decision needing user input** — the "correct" test behavior depends on product intent or architectural tradeoffs
- **False positive** — explain why
- **Out of scope / pre-existing** — valid gap but unrelated to the specified scope

### 4b. Blast radius analysis

For confirmed bugs (not just coverage gaps — actual code bugs found by semantic analysis):
- What other code calls/uses the buggy code?
- Would the fix require changes outside the scoped packages?
- Flag larger-scope fixes explicitly for user decision in Phase 6.

### 4c. Write consolidated report

Write to `dev/test-coverage-reports/<date>-<slug>-consolidated.md`:

```markdown
# <Scope> Test Coverage — Consolidated Findings

**Date:** <YYYY-MM-DD>
**Scope:** <description>
**Methodology:** Hybrid (Go coverage tools + semantic analysis)

---

## Coverage Baseline

| Package | Coverage | Functions | Uncovered |
|---------|----------|-----------|-----------|
| ... | ... | ... | ... |
| **Overall** | **X%** | **N** | **N** |

## Security Checklist Matrix

[Full matrix from Phase 3]

## Confirmed Security-Critical Gaps (N)

### SC1. <Title>
**Location:** <file:line>
**Source:** coverage | matrix | semantic | assertion
**Evidence:** <what's missing or wrong>
**Fix approach:** <brief description>

## Confirmed Correctness Gaps (N)

### C1. <Title>
...

## Production Bugs Discovered (N)

### B1. <Title>
**Location:** <file:line>
**Blast radius:** <what else would need to change>
...

## Design Decisions Requiring User Input (N)

### D1. <Title>
**The concern:** <what was flagged>
**Why this needs a decision:** <tradeoffs>
**Options:** <choices with pros/cons>
**Recommendation:** <if applicable>

## False Positives (N)

### FP1. <Title>
**Why invalid:** <explanation>

## Nice-to-Have (N)
- [One-line items]

## Key Observations
- [Cross-cutting patterns, systematic gaps, assertion quality patterns]
```

After writing the consolidated report, update your private journal with key observations: what coverage patterns emerged, which gaps were most surprising, what the false-positive rate looked like, and any insights about the codebase's testing health.

---

## Phase 5: Test Gap Analysis

For each **confirmed production bug** and each **confirmed security-critical gap**, reflect on why existing tests didn't catch it. Coverage gaps with 0% coverage are self-explanatory (no tests exist) — focus this analysis on the more interesting cases: bugs in covered code, security gaps where tests exist but verify the wrong property, and partial coverage where the uncovered branch is the dangerous one.

### 5a. Why didn't tests catch this?

For each confirmed production bug and security-critical gap, answer:

1. **Do tests exist** for this code path? If coverage is >0%, tests exist — so why didn't they catch the problem?
2. **If tests exist**, what went wrong? Common reasons:
   - Tests assert on the wrong property (e.g., "no error" instead of "correct tenant isolation")
   - Tests use mocked dependencies that hide the real behavior
   - Tests only exercise the positive case — the negative security case is untested
   - Assertion quality is weak (execution-only tests that don't verify outcomes)
   - Tests cover the function but not the specific branch where the bug lives
3. **What test would have caught this?** Briefly describe — this feeds directly into the fix plan in Phase 7.

### 5b. Review against `dev/testing-pitfalls.md`

Read `dev/testing-pitfalls.md` and check each gap against the documented pitfalls:

- **Pitfall already covers this scenario** — the gap exists because the pitfall guidance wasn't followed. Note which pitfall applies. No doc update needed, but flag it in the fix plan so the subagent knows to follow that specific pitfall.
- **Pitfall doesn't cover this scenario** — the gap reveals a testing blind spot not yet documented. Draft a candidate addition to `dev/testing-pitfalls.md`.

### 5c. Update `dev/testing-pitfalls.md` if warranted

For each candidate addition from 5b, assess whether it's **generalizable** — would this pitfall apply to future code in this project, or is it a one-off specific to this finding?

- **Generalizable:** Write the addition to `dev/testing-pitfalls.md`. Follow the existing format and conventions in the file. Keep it concise — a pitfall entry should be actionable, not a narrative.
- **One-off:** Don't update the file. Instead, include a specific testing note in the fix plan task for this finding.

### 5d. Add test gap summary to consolidated report

Append a section to `dev/test-coverage-reports/<date>-<slug>-consolidated.md`:

```markdown
---

## Test Gap Analysis

### <Finding ID>. <Title>
**Why missed:** <reason tests didn't catch it>
**Pitfall coverage:** <"covered by pitfall X — not followed" or "new pitfall added" or "one-off — noted in fix plan">
**Catch test:** <brief description of the test that would have caught it>

(Repeat for each analyzed finding — skip 0%-coverage gaps where the answer is simply "no tests")

### Testing Pitfalls Updates
- <List any additions made to dev/testing-pitfalls.md, or "None">
```

---

## Phase 6: Present to User

Present the findings to Sam. Structure the presentation as:

1. **Executive summary** — coverage baseline, X security-critical gaps, Y correctness gaps, Z production bugs, W design decisions
2. **Security-critical gaps** — table (title, location, source, fix complexity)
3. **Production bugs** — these are code bugs, not just missing tests. Highlight blast radius.
4. **Design decisions** — present each with enough context for an informed decision. Think through each in the context of PLAN.md and project architecture. Make recommendations where you have a well-reasoned opinion.
5. **Out-of-scope / larger-blast-radius items** — for each, ask: include in fix plan, or document for later?

**Wait for Sam's input on all design decisions and scope questions before proceeding to Phase 7.**

---

## Phase 7: Write Fix Plan

After Sam has provided input on all decisions, invoke `/writing-plans` to create an implementation plan for all confirmed gaps + production bugs + any out-of-scope items Sam chose to include.

### Critical requirements for the plan

The plan will be executed via `/subagent-driven-development` or `/executing-plans`. The plan MUST be written to prevent subagent failures:

1. **Eliminate ambiguity.** For each task, specify:
   - The exact test file to create or modify
   - The exact gap being addressed (cite the consolidated report finding ID, e.g., "SC1")
   - The exact test to write — describe the scenario, input, expected output, and edge cases
   - For production bugs: the code fix AND the test, with current→desired behavior
   - Whether the task requires coordination with other tasks (ordering dependencies)

2. **Prevent context gaps.** Each task must be self-contained:
   - Include the finding evidence (file:line, what's wrong/missing)
   - For security matrix gaps: include the specific property to test (e.g., "cross-org isolation for GET /orgs/:id/rules")
   - Include relevant architectural context if the test depends on understanding a design choice
   - For assertion quality fixes: include what the current test does wrong and what the fixed assertion should verify

3. **Prevent interpretation drift.** Test coverage fixes are especially prone to "good enough" tests that don't actually verify the property. For each task:
   - Specify the exact assertion (not just "test that it works")
   - For security tests: specify both the positive case AND the negative case (e.g., "user in org A gets 403 for org B's resource" — not just "auth works")
   - For TOCTOU tests: specify the interleaving to simulate

4. **Mandate TDD and testing discipline.** Every task MUST include this preamble:
   ```
   BEFORE starting work:
   1. Read dev/testing-pitfalls.md
   2. Read the TDD skill at .claude/skills/test-driven-development/ (or invoke /test-driven-development)
   For pure test additions: write the test, verify it fails for the right reason
   (or passes if it's testing already-correct behavior), then move on.
   For code bugs: write failing test → fix code → verify green.
   ```
   Every task MUST include this completion check:
   ```
   BEFORE marking this task complete:
   1. Review your tests against dev/testing-pitfalls.md
   2. Verify: are assertions checking behavior, not just execution?
   3. Verify: are negative cases tested, not just positive?
   4. Run `go test ./...` (or relevant subset) and confirm green
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

5. **Review against `dev/testing-pitfalls.md`.** Read it yourself and check whether any of the planned test additions could fall into documented pitfalls. Add explicit warnings to relevant task descriptions. Common pitfalls for coverage work:
   - Tests that check `err == nil` without verifying the returned value
   - Tests that use `"invalid"` input instead of well-formed-but-wrong-key tokens
   - Conditional assertions (`if status == 200 { assert... }`) that silently pass on failure
   - Tests that only cover the happy path of a security check

6. **Review against `dev/implementation-pitfalls.md`.** For tasks that fix production bugs (not just add tests), check if the fix could fall into documented pitfalls.

7. **Group tasks to minimize cross-task conflicts.** Tests for the same package should be in the same task or explicitly sequenced. Group by test file, not by finding severity.

### Deferred items appendix

If Sam chose to defer any items, add an appendix to the plan:

```markdown
## Appendix: Gaps Identified But Not Addressed in This Cycle

### <Title>
**Finding ID:** <SC1, C3, etc.>
**Location:** <file:line>
**Evidence:** <what's missing>
**Why deferred:** <Sam's reasoning or scope decision>
**Recommended approach:** <brief description for when this is addressed>
```

This appendix is the persistent record. It MUST be written to the plan file — not left in conversation memory.

---

## Phase 8: Plan Review Cycle

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

## Phase 9: Commit Reports

Stage and commit all coverage cycle artifacts:

```bash
git add dev/test-coverage-reports/<date>-<slug>-*.md
git add dev/plans/<plan-file>            # if the plan was written
git add dev/testing-pitfalls.md          # if updated in Phase 5
git commit -m "docs(coverage): <slug> — consolidated findings and fix plan"
```
