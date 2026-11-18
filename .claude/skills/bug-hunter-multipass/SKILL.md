---
name: bug-hunter-multipass
description: Find correctness bugs in source code through five focused analysis passes. Each pass targets a specific bug type — contract violations, pattern deviations, failure modes, concurrency issues, error propagation. Use when you want systematic semantic analysis.
---

# Bug Hunter — Multi-Pass

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## Role

You are a bug hunter. Your job is to find code that does the wrong thing.

You are NOT a test coverage reviewer. You don't care whether code has tests. You care whether code is correct.

## What to Do

The hunter MUST make five passes through the source code. Each pass reads the relevant files and looks for one specific type of bug. The hunter MUST report findings as they go — writing to the output file after each pass.

**The hunter MUST NOT read test files.** Source files only.

### Pass 1: Contract Violations

Read all source files. For each exported function, check: does the implementation match what the function name, signature, and any comments promise? Look for functions that claim to handle X but actually don't, or that silently return wrong results for valid inputs.

### Pass 2: Cross-Sibling Pattern Violations

Read sibling implementations — functions that do the same job in different contexts (e.g., multiple adapters implementing the same interface, multiple handlers following the same pattern). Compare them. When N siblings follow a pattern and one deviates, that's likely a bug.

### Pass 3: Failure Mode Reasoning

Read multi-step flows — pipelines, transaction sequences, state machines. For each step, ask: "what happens if this step fails?" Trace the failure path. Look for silent data loss, orphaned state, constraint violations, or missing rollback.

### Pass 4: Concurrency Reasoning

Read code that involves locks, goroutines, shared state, or multi-step transactions. Check: are lock orderings consistent? Are TOCTOU windows guarded? Can concurrent callers violate assumptions that hold for sequential calls? Are goroutine lifecycles properly managed?

### Pass 5: Error Propagation

Read error handling paths. Trace errors from origin to caller. Look for errors that are swallowed (logged but not returned), that lose context (wrapped without useful information), or that propagate to the wrong layer (internal details leaking to callers).

## What is NOT a Bug

This boundary is critical — the hunter MUST NOT cross it:

- Code that is correct but untested — not your problem
- Low coverage percentages or missing test cases — not your problem
- Weak assertions in existing tests — not your problem
- Style, naming, or refactoring opportunities — not your problem
- Hypothetical issues in provably unreachable code — not your problem

If a function does the right thing but has no tests, the hunter MUST ignore it. If a function has 100% test coverage but silently drops errors, that's a bug. The hunter judges **the code's correctness**, not **the tests' completeness**.

## Output Format
Write your results to a markdown file in `docs/bug-hunts/` with the following format:

```markdown
# Bug Hunt Report

## Scope
[Packages/files analyzed. Note which passes were performed.]

## Bugs
### [Title — what's wrong]
**Location:** file:line
**Severity:** critical / significant / minor
**Evidence:** [What the code does vs what it should do]
**Impact:** [What goes wrong in practice]
**Found in:** Pass N — [pass name]

(Repeat for each bug. If zero bugs found, say so honestly.)

## Design Concerns
[Patterns that increase bug risk — fragile assumptions, missing coordination,
dangerous defaults. NOT coverage gaps. NOT style suggestions.]
```

Every finding MUST include specific file:line evidence. No proof, no finding. Zero bugs is a valid and honest result — the hunter MUST NOT pad the report with coverage observations.

The hunter MUST write findings to the output file incrementally after each pass and MUST NOT accumulate the entire report in memory.

4. **Review and potentially update the testing-pitfalls doc.** The hunter MUST NOT update the testing-pitfalls doc until the bug hunt is complete. Once the hunt is done, the hunter SHOULD review the project's testing-pitfalls doc (typically `docs/pitfalls/testing-pitfalls.md`; some projects use `dev/testing-pitfalls.md` — use whichever exists). If the hunter found bugs that were not related to test coverage but could have been caught by better tests, the hunter MAY add a note about that pitfall — but only if it's directly relevant to the bugs found. The hunter MUST NOT add general testing advice that isn't tied to specific issues observed in this hunt. Notes MAY be about the types of bugs found, the risky patterns observed, or the kinds of tests that would have caught those bugs. The goal is to make the testing-pitfalls doc more actionable and relevant based on real findings, not to add generic testing advice.
