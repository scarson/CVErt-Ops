---
name: plan-review-cycle
description: Use after writing an implementation plan, before committing. Adversarial review for subagent-readiness — checks ambiguity, context gaps, interpretation drift, cross-task conflicts, and pitfall coverage across minimum 4 rounds.
---

# Plan Review Cycle

Rigorously review an implementation plan for subagent-readiness before
committing. Minimum 3 rounds. If round 3 finds substantive issues,
keep going until clean.

## How to run

### Round structure

Each round reviews the plan against ALL of these dimensions:

**Ambiguity** — Can a subagent reasonably interpret any task description
two different ways? Eliminate every instance. Look for "handle this
correctly," "fix the issue," "update as needed" — replace with specific
behavioral descriptions.

**Context gaps** — Would a subagent starting fresh (no conversation
history) have everything it needs? Check for:
- References to "the bug we discussed" (subagent wasn't in that discussion)
- Implicit knowledge of the codebase structure
- Assumptions about what packages are installed or what patterns exist
- Missing file paths or line numbers

**Interpretation latitude** — Could a subagent "improve" or "enhance"
beyond scope? Look for:
- Tasks that describe a goal without constraining the approach
- Missing "do NOT" boundaries on adjacent code
- Opportunities for a subagent to refactor, rename, or reorganize

**Cross-task dependencies** — Are ordering constraints explicit? Would
a subagent working on Task 3 know it depends on Task 1? Look for:
- Shared files modified by multiple tasks
- Tasks that create types/interfaces consumed by later tasks
- Test fixtures needed across tasks

**Testing pitfalls** — Read `docs/pitfalls/testing-pitfalls.md`. Could
any planned test additions fall into documented pitfalls? Add warnings
to relevant tasks. Common traps:
- Testing mock behavior instead of real behavior
- Missing AOT verification
- Substring assertions instead of structural JSON checks

**Implementation pitfalls** — Read `docs/pitfalls/implementation-pitfalls.md`.
Could any planned implementation fall into documented traps? Common:
- AOT-unsafe types in serialization contexts
- Pre-signed URL auth header leaks
- Hand-built JSON without escaping

### Round execution

For each round:
1. Read the plan end-to-end
2. Check every dimension above
3. Note each finding with location (Task N, specific text)
4. Fix all findings in the plan
5. Record the round number and finding count

### Completion criteria

- Round 1: expect 5+ findings (plans always have gaps on first review)
- Round 2: expect 2-3 findings (residual from fixes in round 1)
- Round 3: expect 1-2 (second-order effects of prior fixes)
- Round 4: if 0 findings, you're done. If any, keep going.
- Round 5+: continue until a round produces 0 findings

If round 1 produces 0 findings, you're not looking hard enough.
Re-read the dimensions and try again.

### After completion

Log observations about plan quality and recurring patterns:

```
/gstack-learn add
```

Type: pattern
Key: plan-review-[slug]
Insight: what patterns emerged, what was most commonly wrong

Commit the reviewed plan.
