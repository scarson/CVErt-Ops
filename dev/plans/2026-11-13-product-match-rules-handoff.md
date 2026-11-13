# Handoff: MATCH-2 design (product conditions in alert rules)

Date: 2026-11-13. From the session that wrote and reviewed the design. Read this first, then the design.

## Headline state

- **Design:** `dev/plans/2026-11-13-product-match-rules-design.md`, approved for planning. Sam answered its two questions on 2026-11-13 (design section 15.1). No implementation code, migration or implementation plan exists.
- **Branch:** `claude/match2-design-e1e345`, pull request [scarson/CVErt-Ops#236](https://github.com/scarson/CVErt-Ops/pull/236) to `dev`. Sam asked for it to be merged once this handoff is pushed. The PR holds only documents:
  - the design;
  - its review files in `dev/plans/reviews/`;
  - this handoff;
  - a pitfalls entry (DB-27, and a note under DB-12);
  - five deferred items (`dev/deferred-features.md` section 12);
  - an implementation-log entry.
- **Base:** the design was written against `dev` at `5598af6`. `dev` has since gained PRs 231 to 234. None changes the alert DSL compiler's conditions, but 233 and 234 touch nearby files (see Seams).
- **Next action:** write the implementation plan from the design.

## Glossary

- **MATCH-2:** a requirement in Sam's private homelab integration requirements document. That document is outside this repository and must not be quoted, committed or named by host. The design's section 1 restates the requirement, and Sam confirmed the restatement.
- **CNA:** the CVE Numbering Authority, the organisation that publishes a CVE record. Its record's `affected[]` entries name vendor, product and versions, and arrive on the day of publication, before NVD's analysis.
- **Kept ingest:** a full ingest of every feed (about 2.6 million CVEs, PostgreSQL 18) in the Docker container `cvert-check-ingest-postgres`, kept from the version check plan's Phase 2. It is kept data, never scratch. Use it read-only: start each session with `SET default_transaction_read_only = on`, and never stop, restart or write to it.
- **Name table:** `internal/check/names.go`, mapping a CPE product (such as `nodejs:node.js`) to the CNA spellings of it, plus "other products" a name would wrongly find. It is shared by the version check endpoint and, after this work, by rules.
- **Re-check signal:** design section 7. `cves.match_inputs_hash` and `cves.date_match_inputs_changed` make realtime and batch evaluation re-check a CVE whose CNA product names or NVD vulnerable flags changed, without changing `material_hash`.

## What this session produced

| Artifact | What it holds |
|---|---|
| `dev/plans/2026-11-13-product-match-rules-design.md` | The design. Section 15 records Sam's two rulings and ten decisions taken without him, each with context and rejected alternatives. Appendix A holds the measured SQL. |
| `dev/plans/reviews/2026-11-13-product-match-rules-design.ledger.md` | Review ledger, run 1 (rows L1 to L53) and run 2 (rows M1 to M22). |
| `dev/plans/reviews/...round-2-independent.md`, `round-4-`, `round-6-`, `run-2-round-1-fable.md` | Raw reports of the independent reviews. |
| `dev/implementation-pitfalls.md` DB-27, and a note under DB-12 | Query-shape traps measured here; squirrel's `IN` placeholder expansion. |
| `dev/deferred-features.md` section 12 | Five deferred items, each with its unblock condition. |
| `dev/implementation-log/2026-11-13T1039Z-match2-product-rules-design.md` | Log entry. |

Outside the repository, in the shared side-session notes folder of the session that started this one: `match2-design.md` and `match2-measurements/` (read-only SQL files `m1` to `m12`, with outputs). Appendix A of the design holds the statements, so the repository does not depend on that folder.

## Decisions a planner must not reopen without Sam

Sam's rulings (design section 15.1):

1. The requirements as restated in design section 1 are right. That includes "exact match" meaning equal after the ecosystem's own name folding, and the acceptance case being a Node CVE named by its CNA, not the Brotli CVE.
2. Match inputs outside `material_hash` (CNA product names, NVD's vulnerable flag) are caught by a separate re-check signal, not by changing `material_hash`. Sam's reason: "The excess rule firing on info churn is what we're trying to avoid."

The ten decisions in design section 15.2 were taken by the design and can be overturned by Sam. Each states what would change it.

## Ready to start

1. **Implementation plan.** Use `superpowers-plus:writing-plans-enhanced`, which runs its own plan review. Read design sections 3 to 8, 12, 13 and 16 in full. Commit order is design section 16. The plan must schedule:
   - `schema-review`, then `migration`, for the two `cves` columns and their partial index (design section 7.2);
   - the measurements and thresholds of design section 13, on the kept ingest and on PostgreSQL 15;
   - `/pitfall-check` before the evaluator commit, and `/plan-check` against PLAN.md §10 before merge.
2. **PLAN.md updates** listed in design section 11, in the implementation pull request, not before.

## In flight

Nothing. No agent, worktree or background process from this session is running. The kept-ingest worker belongs to another session; leave it alone.

## Deferred

`dev/deferred-features.md` section 12 holds five items, each with the condition that makes it worth picking up:

- the re-check after a name-table edit (forced by a CI digest test when it becomes needed);
- a watchlist "product" item type;
- `neq` and `not_in` on the product field;
- CNA package keys in package rules;
- CNA-supplied CPEs.

## Seams

- **The version check endpoint (MATCH-1) shares the name table and changes with this work.**
  - Two Node spellings are added (`node.js` / `node.js`, `the node.js project` / `node.js`).
  - The other-product boundary test changes from Unicode letter/digit to ASCII.

  Neither changes a stored answer on the kept ingest (design sections 3.4 and 5.1). The version check design's section 4.5 table (`dev/plans/2026-11-08-version-check-endpoint-design.md`) should get an amendment line in the implementation pull request.
- **`internal/check` gains exports and two helpers from `internal/store/check.go`** (design section 3.4). The `internal/store` check code changes to call them; its tests must still pass.
- **PR 233** moved the watchlist match SQL into `dsl.WatchlistPackageMatchSQL` and `WatchlistCPEMatchSQL`, which `internal/store/alert_rule.go` also uses for the alert-event listing. This design leaves those helpers alone. Watchlist package matching keeps `lower()` on ecosystems, while rule conditions compare ecosystems exactly (design section 15.2, "Ecosystems compared exactly"). That is a deliberate difference, not drift.
- **PR 234** added an ascending alert-event feed with a cursor. The re-check signal adds no `alert_events` columns and does not change event dedupe, so the feed is unaffected. A re-check that creates a new event appears in the feed like any other event.
- **The CLI and MCP design (PR 235)** may describe DSL fields, validation or the validate endpoint. The new field, operators, limits and the never-matching-ecosystems error should reach it when either is built.
- **The private requirements document's progress section** is maintained by the session that started this one, outside the repository. That session has this session's report: MATCH-2 design done, PR 236, acceptance case substituted, re-check signal chosen.
- **`setSQL` changes existing behaviour:** every `in` and `not_in` list in the DSL, not only the new fields, moves to `= ANY(?)` (design section 3.2, pitfall DB-12). Existing tests of set fields must still pass.

## Operational guardrails from this session

- The Bash tool fails on long heredocs with misleading quote errors; write scripts with the Write tool and run the file (already a rule in the global CLAUDE.md; this session hit it once more and logged it in papercuts).
- Query timings on the kept ingest are warm-cache unless stated; report cold and warm separately when a threshold is close.
- When `origin/dev` moves under a worktree, `git diff origin/dev --stat` shows other branches' work as deletions. Check `git diff origin/dev...HEAD --stat` (three dots) before concluding anything.
- Never commit the private requirements text, its host names, or local user paths to this public repository.

## Review rounds on this handoff

These rounds were run by the session that wrote this handoff, not by an independent reviewer. The first four lenses were applied while drafting, so they shaped the text rather than producing separate fixes.

1. **Naive fresh agent:** required the glossary and the named plan-writing skill.
2. **Recency bias:** required the two mid-session items a status report would skip: the `setSQL` change to existing `in` lists, and the ASCII boundary change to the version check.
3. **Seam auditor:** required PRs 233 and 234 to be checked against the re-check signal and the watchlist helpers.
4. **Operational guardrails:** required the three-dot diff check after `dev` moved under the worktree.
5. **Loss-averse auditor:** confirmed that the measurement SQL kept outside the repository is also in the design's Appendix A.
6. **Session-specific, public-repository privacy (1 finding, fixed):** this session handled a private requirements document and a kept database. A search of every committed file found the reviewers' local snapshot paths, which include the Windows user name, at the top of two raw review reports (`round-4-` and `round-6-independent.md`). They are replaced with commit references. Earlier commits on this branch still contain the paths; the user name already appears in the repository's checked-in CLAUDE.md. No host names or quotations of the private document were found.
7. **Planner-readiness of the decisions (no findings):** every decision in design section 15.2 names the section that implements it and what would change it.

A second pass through rounds 1 to 7 after the round 6 fix found nothing further.

## Continuation prompt

> You are continuing CVErt-Ops requirement MATCH-2, product conditions in alert rules. Read `dev/plans/2026-11-13-product-match-rules-handoff.md`, then `dev/plans/2026-11-13-product-match-rules-design.md` in full. The design is approved: Sam's two rulings are in its section 15.1, and its section 15.2 records the other decisions. Do not reopen them without asking Sam.
>
> Write the implementation plan with the `superpowers-plus:writing-plans-enhanced` skill, following the design's section 16 commit order. Include `schema-review` and `migration` for the re-check columns, every measurement and threshold in section 13 (on the kept full ingest, read-only, and on PostgreSQL 15), `/pitfall-check` before the evaluator commit and `/plan-check` against PLAN.md §10 before merge. Pitfall DB-27 in `dev/implementation-pitfalls.md` governs the query shapes. Branch from local `dev` in a new worktree. Do not quote or commit the private requirements document.
