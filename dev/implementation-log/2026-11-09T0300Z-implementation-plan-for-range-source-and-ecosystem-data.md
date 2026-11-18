# Implementation plan for range, source and ecosystem data

## What was done

Revised `dev/plans/2026-11-08-cve-range-data-batch-design.md` after Sam's decision that there are no existing installs: the work ships as an ordinary migration, development databases are wiped, and old ecosystem names are rejected. Wrote `dev/plans/2026-11-08-cve-range-data-batch-plan.md`, three phases and 13 tasks. No implementation code or migration was written; implementation waits for Sam's approval.

## Findings not in PLAN.md

- Codex (`gpt-6-astra`) reviewed the design once and the plan five times. The design review changed the GHSA mapping so a declared range is never shortened, added listed OSV versions beside ranges, made late-binding independent of processing order, and moved open alerts when a CVE is renamed.
- A semicolon inside a SQL comment breaks a migration, because the runner splits files on semicolons (`dev/implementation-pitfalls.md` DB-16).
- Packages that reach `web/embed.go`, including `./internal/api`, do not compile in a fresh worktree until the frontend is built.

## Open

The plan's review ended under its convergence rule with two verify-first flags in Task 2.6, both about a CVE rename racing the alert evaluator. See `dev/plans/reviews/2026-11-08-cve-range-data-batch-plan.plan-review.md`.

## Quality checks

No test suite was run: these commits change only documents. The plan's code was compiled and partly executed by the reviewer in a temporary copy.
