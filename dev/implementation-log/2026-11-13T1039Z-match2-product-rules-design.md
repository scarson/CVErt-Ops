# MATCH-2 design: product conditions and correlated package conditions in alert rules

## What was built

- `dev/plans/2026-11-13-product-match-rules-design.md`: the `affected.cpe_product` rule field, correlation of `affected.ecosystem` with `affected.package`, `eq`/`in` on `affected.package`, and a re-check signal for match inputs outside `material_hash`. No code or migration.
- Review files in `dev/plans/reviews/`:
  - a ledger with two runs;
  - three independent Opus reports;
  - one independent Claude Fable report.
- New pitfall DB-27 (query shape of DSL predicates over child tables) and a squirrel note under DB-12 in `dev/implementation-pitfalls.md`.
- Section 12 of `dev/deferred-features.md`: five deferred items.

## Decisions and gotchas

- Sam ruled on two questions (2026-11-13):
  - the restated requirements are right, including that "exact" means equal after the ecosystem's own name folding;
  - CNA product names and NVD's `vulnerable` flag get a separate re-check signal (`cves.match_inputs_hash`, `cves.date_match_inputs_changed`), not a `material_hash` change, so rules do not fire again on informational churn.
- The design decided ten more, each with its alternatives in its section 15.2.
- The requirement's acceptance example, CVE-2026-111497 (Brotli), cannot match Node from CNA data: its CNA record names only `Google` / `Brotli`. The acceptance case uses a Node-named CVE instead, such as CVE-2026-123866.
- Squirrel's `sq.Eq{col: slice}` expands to one placeholder per element, so the DSL's existing `in` lists can pass PostgreSQL's 65,535-parameter limit. The design binds every list with `= ANY(?)`.
- Query shape decides speed (DB-27):
  - `OR`-ed correlated `EXISTS` is slow over the whole corpus;
  - a join to `unnest()` range arrays loses the index;
  - `NOT IN` over a large set times out.

  The chosen form is an uncorrelated CVE-ID set with the candidate IDs inside each branch.
- `internal/check`'s other-product boundary test changes from Unicode letter/digit to ASCII, so the Go and SQL forms agree. No stored row is affected on the kept ingest.

## Quality checks

- Measured read-only on the kept full ingest (about 2.6 million CVEs, PostgreSQL 18):
  - realtime 0.28 ms for the largest product;
  - batch 93 to 447 ms for 5,000 candidate IDs;
  - dry-run 2.6 ms to 1.3 s;
  - exact package match with no ecosystem 217 ms cold, by index skip scan.
- PostgreSQL 15 to 17 are not measured; the design's section 13 requires it.
- Review: run 1 stopped after 6 rounds by its plateau trigger (15, 14, 11 substantive findings). Run 2 (Fable) raised 11 findings, settled the contested ones in discussion, and checked the fixes twice (10 problems, then 1). The final rewrite of sections 7 and 15 for Sam's rulings had no independent check.
- No tests ran, because no code changed.
