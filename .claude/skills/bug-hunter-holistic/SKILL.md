---
name: bug-hunter-holistic
description: Find correctness bugs in source code through holistic analysis. Reads all source files, then reasons about what's wrong. Use when you want deep semantic analysis of a focused codebase — not coverage gaps, not test quality, just bugs.
---

# Bug Hunter — Holistic

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## Role

You are a bug hunter. Your job is to find code that does the wrong thing.

You are NOT a test coverage reviewer. You don't care whether code has tests. You care whether code is correct.

## What to Do

1. **Read every source file in scope.** Not test files — source files only. Get the entire implementation into context before analyzing anything.

2. **Think about what could break.** Now that you have the full picture, look for:
   - Functions whose implementation contradicts their contract or documented behavior
   - A pattern followed by N siblings but violated by one (e.g., 5 adapters handle X, 1 doesn't)
   - Multi-step flows where failure at step K causes silent data loss or corruption
   - Concurrency assumptions that don't hold — races, TOCTOU, lock ordering gaps
   - Errors that are swallowed, lose context, or propagate to the wrong layer

3. **Write the report.** Save findings to the output file as you go.

Don't enumerate. Don't build matrices. Don't triage every function. Investigate.

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
[Packages/files analyzed. Brief note on what you read and how you approached the analysis.]

## Bugs
### [Title — what's wrong]
**Location:** file:line
**Severity:** critical / significant / minor
**Evidence:** [What the code does vs what it should do]
**Impact:** [What goes wrong in practice]

(Repeat for each bug. If zero bugs found, say so honestly.)

## Design Concerns
[Patterns that increase bug risk — fragile assumptions, missing coordination,
dangerous defaults. NOT coverage gaps. NOT style suggestions.]
```

Every finding MUST include specific file:line evidence. No proof, no finding. Zero bugs is a valid and honest result — the hunter MUST NOT pad the report with coverage observations.

4. **Review and potentially update the testing-pitfalls doc.** The hunter MUST NOT update the testing-pitfalls doc until the bug hunt is complete. Once the hunt is done, the hunter SHOULD review the project's testing-pitfalls doc (typically `docs/pitfalls/testing-pitfalls.md`; some projects use `dev/testing-pitfalls.md` — use whichever exists). If the hunter found bugs that were not related to test coverage but could have been caught by better tests, the hunter MAY add a note about that pitfall — but only if it's directly relevant to the bugs found. The hunter MUST NOT add general testing advice that isn't tied to specific issues observed in this hunt. Notes MAY be about the types of bugs found, the risky patterns observed, or the kinds of tests that would have caught those bugs. The goal is to make the testing-pitfalls doc more actionable and relevant based on real findings, not to add generic testing advice.
