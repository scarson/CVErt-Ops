---
name: writing-plans-enhanced
description: Use when writing implementation plans for this project. Wraps superpowers:writing-plans with project-specific conventions — plan location, execution strategy recommendation, subagent-proofing requirements, TDD mandates, and pitfall review.
---

# Writing Plans (Enhanced)

Wraps `/superpowers:writing-plans` with project-specific requirements
that prevent subagent failures during execution.

## Step 1: Invoke the base skill

Invoke `/superpowers:writing-plans`. Follow it completely.

Save the plan to `docs/plans/<date>-<slug>-plan.md`
(e.g., `docs/plans/2026-04-08-mcp-tools-plan.md`).

## Step 2: Execution strategy recommendation

When `/writing-plans` presents execution options, recommend one with
reasoning. The three options:

1. **Subagent-driven** (`/superpowers:subagent-driven-development`) —
   fresh subagent per task, review between tasks. Best for independent
   tasks needing quality gates.
2. **Parallel session** (`/superpowers:executing-plans` in a worktree) —
   batch execution with checkpoints. Best for tightly coupled sequential
   tasks.
3. **Parallel agents** (`/superpowers:dispatching-parallel-agents`) —
   concurrent agents on independent workstreams. Best for 3+ independent
   tracks with different files.

Base the recommendation on:
- How much context this session has consumed
- Whether the plan is self-contained enough for a fresh session
- How many tasks are parallelizable vs sequential
- Whether any tasks are risky enough to warrant focused attention

## Step 3: Subagent-proof the plan

Subagents start fresh with zero context. The plan MUST prevent their
predictable failure modes:

### Eliminate ambiguity
For each task, specify:
- Exact files to create or modify
- Exact behavior change (current → desired)
- Exact test to write (input, expected output, edge cases)
- Ordering dependencies with other tasks

### Prevent context gaps
Each task description must be self-contained:
- Include evidence (file:line, what's wrong or what's needed)
- Include the approach (not just "fix the bug" or "add the feature")
- Include architectural context if the task depends on a design choice
- If the task touches shared code, list other callers that must still work

### Prevent interpretation drift
- Where there's one correct approach, state it explicitly
- Where there are multiple valid approaches, pick one and specify it
- Add "do NOT" boundaries where a subagent might over-engineer

### Mandate TDD
Every task MUST include:
```
BEFORE starting work:
1. Invoke /superpowers:test-driven-development
2. Read docs/pitfalls/testing-pitfalls.md
Follow TDD: write failing test → implement → verify green.
```

Every task MUST include:
```
BEFORE marking this task complete:
1. Review tests against docs/pitfalls/testing-pitfalls.md
2. Verify test coverage (error paths? edge cases?)
3. Run tests and confirm green
```

Every logical group of tasks MUST include:
```
After completing this group:
Review the batch from multiple perspectives. Minimum 3 review rounds.
If round 3 still finds issues, keep going until clean.
```

### Review against pitfalls
Read both pitfalls docs and check if any planned work could fall into
documented traps. Add explicit warnings to relevant task descriptions:
- `docs/pitfalls/implementation-pitfalls.md`
- `docs/pitfalls/testing-pitfalls.md`

### Minimize cross-task conflicts
If two tasks touch the same file, put them in the same task or
explicitly sequence them. Parallel subagents editing the same file
create merge conflicts.

## Step 4: Run /plan-review-cycle

After writing the plan, invoke `/plan-review-cycle` before committing.
