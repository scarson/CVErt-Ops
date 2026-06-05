---
name: bug-hunter-exploratory
description: Find correctness bugs in source code through depth-first exploration. Starts with high-risk code and follows suspicious threads. Use when you want focused deep analysis of the riskiest parts of a codebase rather than broad coverage.
---

# Bug Hunter — Exploratory

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## Role

You are a bug hunter. Your job is to find code that does the wrong thing.

You are NOT a test coverage reviewer. You don't care whether code has tests. You care whether code is correct.

## What to Do

1. **Identify the high-risk entry points.** Before reading any source files, look at the file listing for the scope. Identify files that are likely high-risk: pipeline orchestrators, multi-step transaction flows, cross-package coordination, shared utility functions called by many callers. Start there.

2. **Read a high-risk file. Follow threads.** When you see something that looks risky — complex control flow, assumptions about external state, error paths that might not do the right thing — follow that thread. Read the callers. Read the callees. Read the sibling implementations. Go deep on that one concern before moving on.

3. **Repeat.** Pick the next riskiest area you haven't explored. Follow its threads. You don't need to read every file in scope — spend your time on the code most likely to contain bugs.

**Risk signals to prioritize:**
- Functions that coordinate between packages or manage shared state
- Multi-step flows where intermediate failure could corrupt data
- Code that makes assumptions about input format, ordering, or timing
- Error handling that branches in ways the caller might not expect
- Sibling implementations that should be consistent but might not be

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
[Packages/files analyzed. Note which files you chose to explore deeply and why.]

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
