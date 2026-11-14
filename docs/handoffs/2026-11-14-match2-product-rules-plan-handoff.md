# Handoff: MATCH-2 implementation plan (product conditions in alert rules)

Date: 2026-11-14. From the session that wrote and reviewed the implementation plan. Read this first, then the plan.

## Headline state (observed 2026-11-14 02:04 UTC, branch tip `d909e40`)

- **Plan:** `dev/plans/2026-11-13-product-match-rules-plan.md`. Plan review line: ⚠️ TERMINATED-FOR-EXECUTION, 8 rounds, 2 verify-first flags annotated in place. Every phase was ⬜ NOT STARTED. No implementation code, migration or worktree for implementation existed.
- **Branch:** `claude/match2-plan-9ad7a3`, pushed, tip `d909e40` (this handoff adds one commit on top).
- **PR:** [scarson/CVErt-Ops#241](https://github.com/scarson/CVErt-Ops/pull/241) to `dev` was open, mergeable, with no CI checks (docs only). Sam asked for it to be landed after this handoff is pushed, so it was expected to be merged minutes after this reading.
- **`origin/dev`:** was at `66385c6` (PR #239, PostgreSQL 18 minimum), which the branch contains.
- **Worktrees:** this session's `.claude/worktrees/match2-plan-9ad7a3`; the design session's `.claude/worktrees/match2-design-e1e345` also still existed (not this session's to remove).

## Glossary

- **MATCH-2:** a requirement in Sam's private homelab integration requirements document, which must never be quoted, named by host, or committed. Design section 1 restates it.
- **Design:** `dev/plans/2026-11-13-product-match-rules-design.md`, approved. Sam's rulings are its section 15.1; its other decisions are section 15.2.
- **Kept ingest:** the Docker container `cvert-check-ingest-postgres`, a complete ingest of every feed (about 2.6 million CVEs, PostgreSQL 18). Kept data, never scratch: read-only connections only; never stop, restart, or write to it. A feed worker owned by another session may still be writing to it.
- **Verify-first flag:** a span in the plan, marked with a blockquote starting "Verify-first", whose repair was not re-reviewed; the executor confirms it before building on it.
- **Plateau circuit breaker:** the plan review's rule that ends a cycle whose finding counts stop falling fast enough (here 9, 4, 3, 2); it ended this review as TERMINATED-FOR-EXECUTION rather than clean.

## What this session produced

| Artifact | What it holds |
|---|---|
| `dev/plans/2026-11-13-product-match-rules-plan.md` | Six phases in design section 16's order: check exports and value parser; CVE-set predicates, `CompiledRule.Where`, package correlation; `affected.cpe_product`; measurement gate; re-check signal; PLAN.md, reviews, PR. Execution Status table, Living Document Contract, Discoveries (two design wording gaps). |
| `dev/plans/reviews/2026-11-13-product-match-rules-plan.plan-review.md` | Review checkpoint: round table, breaker evidence, terminal, completion summary. |
| `dev/plans/reviews/2026-11-13-product-match-rules-plan.round-{2,4,6,8}-codex.md` | Raw Codex cold-read findings, one file per independent round. |
| `dev/implementation-log/2026-11-14T0040Z-match2-product-rules-plan.md` | Log entry: decisions and the review outcome. |
| This handoff | `docs/handoffs/2026-11-14-match2-product-rules-plan-handoff.md`. |

## Decisions made this session

- **Sam's ruling (2026-11-14):** the 50-product limit de-duplicates within a condition and sums across conditions (plan Task 3.1). Rule-wide de-duplication would let a rule compile to about 125,000 bind parameters, past PostgreSQL's 65,535.
- **Full activation scan on a disposable restored copy** (plan Task 4.2, M8). The kept ingest is read-only, so the design's section 13 activation scan runs on a copy restored from the kept backup into a new container. The executor must ask Sam for the backup's location (recorded outside the repository) and check disk first. The copy is kept until Task 5.5's batch-scan measurement, then removed.
- **Other choices the review forced**, each written into its task: `not_in: null` keeps matching everything (nil lists normalised to empty before `pq.Array`); the never-matching-ecosystems check is linear (map lookups of colon-prefixes); the batch `UNION` limits each branch to the page size; `match_inputs_hash` lower-cases ASCII only; the harness passes the kept ingest's password as a separate variable, never in a URL, and uses `store.DefaultQueryExecMode`.

## In flight

Nothing. No background job, agent or worktree of this session's was doing work at the time of the reading above.

## Ready to start

1. **Implement the plan**, from Setup through Phase 6, in a new worktree branched from local `dev` after PR #241 merges. Recommended execution: subagent-driven, one task at a time, one writer. Every phase edits files the next depends on, and Phase 4 is a gate that can change the limits Phase 5's tests use.
   - If PR #241 merged, branch from `dev` as the plan's Setup says.
   - If PR #241 is still open, ask Sam whether to merge it first; do not implement from an unmerged plan.
   - If PR #241 is closed unmerged, check whether `dev` contains `dev/plans/2026-11-13-product-match-rules-plan.md` before re-creating anything, then ask Sam.

## Deferred

Nothing new was deferred by this session. The design's five deferred items stay in `dev/deferred-features.md` section 12, each with its unblock condition there. The one most likely to come up during implementation is the re-check after a name-table edit: plan Task 1.3's digest test fails on any table edit and its message names what must be built first.

## Seams

- **Verify-first spans** (plan Tasks 2.1 and 5.3): the last review wave's repairs. Confirm them before building on them; defects found come back to the plan as findings.
- **Phase 4 gate needs Sam twice at most:** for the backup location (M8), and for any failing threshold. The plan says to stop at each; neither is decided in advance.
- **Version check endpoint (MATCH-1):** Phase 1 changes the shared name table (two Node.js spellings, ASCII boundary). Task 6.1 adds an amendment line to `dev/plans/2026-11-08-version-check-endpoint-design.md` section 4.5.
- **Migration number:** the plan assumes `000063`; Setup step 4 says to take the next free number on `origin/dev`.
- **CLI/MCP design (PR #235):** Task 6.1 checks whether CLI or MCP code exists and either documents the new field there or records that it must be carried when built.
- **Design wording gaps:** two, recorded in the plan's Discoveries (section 12 vs 3.1 on `*`/`?`; section 8 missing a printable-ASCII message). The design text was not edited.

## Operational guardrails from this session

- The Write and Edit tools decode `\u` escapes: writing `K` into plan text produced a raw KELVIN SIGN, which had to be replaced. In documents, describe such characters in words ("KELVIN SIGN (U+212A)"); in Go tests, build them with `string(rune(0x212A))`. (Already a rule in the user's global instructions; it recurred.)
- A `cd` in a Bash call to a directory outside the worktree moved the session's working directory; use absolute paths instead.
- Codex reviews ran as `codex exec -s read-only -c model_reasoning_effort=high -C <worktree> - < brief.md > log 2>&1` in the background. The log is large (over 600 KB); extract the findings that follow the last `tokens used` line. No `%TEMP%` scratch is left by a read-only run.

## Review rounds on this handoff

The session that wrote this handoff ran these rounds, not an independent reviewer. Lenses 1 to 5 were applied while drafting, so they shaped the text (the glossary, the decisions section, the Phase 4 stops in Seams, the guardrails) rather than producing separate fixes. Findings after the draft:

1. **Naive fresh agent:** no findings after drafting.
2. **Recency bias:** no findings after drafting.
3. **Seam auditor:** no findings after drafting.
4. **Operational guardrails:** no findings after drafting.
5. **Loss-averse auditor (2 findings, applied):** the two design wording gaps lived only in the PR description and the log, so they were routed into the plan's Discoveries; and the handoff had no Deferred section, so it now points at `dev/deferred-features.md` section 12.
6. **Public-repository privacy and credentials (session-specific; 1 finding, applied):** this session handled a kept database's connection plan and a private requirements document. A scan of every file this session commits found no local user paths, no `C:` paths, no password strings and no quotation of the private document. Separately, the continuation prompt's manifest called the container "not checked" without the `UNVERIFIED` marker; fixed.

A full pass through rounds 1 to 6 after these fixes found nothing further.

## Continuation prompt

```
# MATCH-2: implement product conditions in alert rules

0. Ground yourself before doing anything else. The state described below was
   observed at 2026-11-14 02:04 UTC. The world may have moved since — finding
   that it did is the normal case, not an anomaly.

   Answer these before acting on anything below, using whatever commands your
   environment provides. An error or an empty result is information, not a
   malfunction: a missing remote branch usually means it merged and was deleted.
   - Repository CVErt-Ops (clone https://github.com/scarson/CVErt-Ops): what is
     checked out, is the working tree clean, what is the tip of origin/dev, does
     dev contain dev/plans/2026-11-13-product-match-rules-plan.md?
   - PR 241 in scarson/CVErt-Ops: open, merged, or closed-unmerged; merged as
     what commit?
   - The Docker container cvert-check-ingest-postgres: is it running? (Check
     only; never start, stop or write to it.)

   Two things those answers do NOT settle, both failing toward redoing shipped
   work:
   - A squash or rebase merge rewrites the commit, so the handed-off tip is not
     an ancestor of the target branch even when the work shipped. Absence from
     the target branch is not absence of the work.
   - A PR's state is authoritative only for whether THAT PR merged. Work whose
     commits were cherry-picked, applied by hand, or superseded lands while its
     PR reads closed-unmerged. When PR state and the target branch's contents
     disagree, the contents win — confirm a change is really absent before
     re-creating anything.

   Then reconcile: where this document and live state disagree about anything
   volatile, live state is right and this document is stale. Everything else
   here — decisions, rationale, seams, deferral conditions — still stands.
   State having moved usually means work described as pending has already
   landed; that is not a reason to redo it. If it moved in a way this document
   does not account for — unfamiliar commits, a force-push, someone else's work
   in flight — stop and ask rather than improvising a reconciliation.

   What to check, and what it looked like when observed:
   repo   CVErt-Ops (clone https://github.com/scarson/CVErt-Ops)  branch claude/match2-plan-9ad7a3  tip d909e40 (plus one handoff commit)  — clean, pushed
   repo   CVErt-Ops origin/dev                                    — at 66385c6
   PR     241 in scarson/CVErt-Ops                                — open, mergeable, no checks; about to be merged by the writing session
   worktree .claude/worktrees/match2-plan-9ad7a3                  — live (planning only; do not implement in it)
   worktree for implementation                                    — none existed
   container cvert-check-ingest-postgres                          — UNVERIFIED (not checked this session; the planning session never connected to it); kept data, read-only use only
   phase status in the plan                                       — every phase NOT STARTED; plan review TERMINATED-FOR-EXECUTION with 2 verify-first flags

1. Read docs/handoffs/2026-11-14-match2-product-rules-plan-handoff.md, then
   dev/plans/2026-11-13-product-match-rules-plan.md in full, then the design
   sections it names (dev/plans/2026-11-13-product-match-rules-design.md).
   Design sections 15.1 and 15.2 are closed decisions; Sam also ruled on
   2026-11-14 that the 50-product limit counts per condition (plan Task 3.1).
   Do not reopen any of them without asking Sam.

2. If PR 241 merged, follow the plan's Setup: a new worktree branched from
   local dev. If it is still open, ask Sam whether to merge it first. If it was
   closed unmerged, confirm dev lacks the plan before doing anything, then ask
   Sam.

3. Execute the plan task by task, keeping its Execution Status and banners
   current (Living Document Contract). Treat the two verify-first spans (Tasks
   2.1 and 5.3) as verify-before-build. Stop at the Phase 4 gate for the
   backup location and for any failing threshold. Project rules: CLAUDE.md
   (TDD, ABOUTME headers, one dev/implementation-log entry per commit, scoped
   test runs, Docker required for integration tests).

4. Never quote or commit the private homelab requirements document, its host
   names, or local user paths; the repository is public.
```
