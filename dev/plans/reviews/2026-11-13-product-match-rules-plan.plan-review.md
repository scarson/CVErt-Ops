# Plan review checkpoint: product conditions in alert rules (MATCH-2)

Controller checkpoint for `plan-review-cycle` on `dev/plans/2026-11-13-product-match-rules-plan.md`. Compact state only; raw independent reports are kept beside this file as `2026-11-13-product-match-rules-plan.round-N-*.md`.

- **Run start:** 2026-11-13
- **Status:** finalized 2026-11-14 — TERMINATED-FOR-EXECUTION after 8 rounds, 2 verify-first flags annotated in place
- **Review baseline (after round 1 fixes):** 792 lines, 6 phases, 25 tasks (`grep -c "^### Task"`), each with a Tests or Run contract.
- **Named surfaces:** data integrity (merge hash, re-check signal, batch cursor) and security (rule values reaching SQL). A cross-model round is REQUIRED; Codex CLI is available.

## Round table

| Round | Reviewer | Raised | Fixed | Rejected (state) | Notes |
|---|---|---|---|---|---|
| 1 | self-review (Claude Opus 5.5) | 11 | 11 | 0 | Insert-cost test moved under the build tag; partial-index claim corrected; re-check test drive made exact; legacy SQL-text tests addressed; KELVIN SIGN built without escapes; pgx stdlib driver; password kept out of output via scratch script; pre-change `contains` form cited from code; product-limit create/PATCH symmetry; acceptance patch built from the NVD golden; import-cycle check recorded. |

| 2 | independent, cross-model (Codex gpt-6.1-sol, high, cold) | 9 | 9 | 0 | Parameter bound broken by cross-condition de-duplication (per-condition count adopted, open question to Sam); quadratic never-matching check made linear; password kept out of the URL; parity test placeholder collision; `not_in: null` meaning preserved; pre-flight psql made read-only from connection start; batch re-check test isolated with a falsification probe; `ageCorpus` brought into scope; M8 now a full activation on a disposable restored copy. Raw report: `2026-11-13-product-match-rules-plan.round-2-codex.md`. |
| 3 | self-review of the round-2 wave (Claude Opus 5.5) | 0 | 0 | 0 | Claim sweep: activation wording in the M8 row and the log entry, the `null` test wording, `ageCorpus` sentence. Sweep edits were part of the round-2 wave, not new findings. |

| 4 | independent, cross-model (Codex gpt-6.1-sol, high, cold) | 4 | 4 | 0 | Falsification-probe restore could discard uncommitted work (save and copy back instead); full-name recheck test rebuilt with colliding 256-character keys below the parser; harness uses production's `QueryExecModeCacheDescribe`; threshold comparison defined (planning plus execution, warm median, first run flagged). Raw report: `2026-11-13-product-match-rules-plan.round-4-codex.md`. |
| 5 | self-review of the round-4 wave (Claude Opus 5.5) | 0 | 0 | 0 | Checked the M7 "first run" row against the new comparison rule and the exec-mode line against both harness connections. |
| 6 | independent, cross-model (Codex gpt-6.1-sol, high, cold) | 3 | 3 | 0 | Batch `UNION` given per-branch limits, a pagination test and a measurement on the disposable copy (the copy is kept until then); rule status setup (`activateRule`, `activating`) made explicit for the integration tests; re-check timestamp test no longer assumes ordered clock readings. Raw report: `2026-11-13-product-match-rules-plan.round-6-codex.md`. |
| 7 | self-review of the round-6 wave (Claude Opus 5.5) | 0 | 0 | 0 | Swept the superseded "bounded range scan" claim (removed from the Phase 4 note); rewrote the Task 5.5 measurement paragraph as plain steps. |
| 8 | independent, cross-model (Codex gpt-6.1-sol, high, cold) | 2 | 2 | 0 | `match_inputs_hash` lower-cases ASCII only (Go's Unicode lower-casing could hide a change PostgreSQL's `lower()` sees); Task 2.1's database-backed tests moved to `internal/store/dsl_executor_test.go` (the DSL package has no `TestMain`). Both repairs are un-re-reviewed and annotated verify-first. Raw report: `2026-11-13-product-match-rules-plan.round-8-codex.md`. |

**Notes:** pitfalls docs live at `dev/implementation-pitfalls.md` and `dev/testing-pitfalls.md` (not `docs/pitfalls/`). The REQUIRED cross-model round (data integrity, security) was met in round 2.

## Independent rounds (breaker evidence)

| Ordinal | Round | Repairs reviewed / judged defective | Findings on review records / total | Concentration | Breaker |
|---|---|---|---|---|---|
| 1 | 2 | 11 / 0 (first independent round; round-1 repairs not separately judged) | 0 / 9 | Phase 4 (3), Phase 2 (2), Phase 3 (2), Phase 5 (2) | exempt (first independent round) |
| 2 | 4 | 9 / 1 (the round-2 falsification-probe restore) | 0 / 4 | Phase 4 (2), Phase 3 (1), Phase 5 (1) | no trigger: 4 < half of 9; 1/9 repairs defective; no findings in review records |
| 3 | 6 | 4 / 0 | 0 / 3 | Phase 5 (2), Phase 2 (1) | no trigger: 3 ≥ half of 4 is the first of two plateau rounds needed; 0/4 repairs defective; no findings in review records. A fourth independent round with 2 or more findings fires the plateau trigger. |
| 4 | 8 | 3 / 0 | 0 / 2 | Phase 5 (1), Phase 2 (1) | **plateau fired**: round 6 raised 3 ≥ half of 4, round 8 raised 2 ≥ half of 3. No user turn in hand (session started by another session), so the breaker fired and was disclosed. |

## Terminal

TERMINATED-FOR-EXECUTION after 8 rounds — 2 verify-first flags annotated in place (Task 2.1 test placement; Task 5.3 ASCII-only lower-casing in `match_inputs_hash`). Not certified clean.

Firing diagnostic: the plan grew from 792 lines (baseline) to 808 while the task count stayed at 25 and every task kept one Tests/Run contract; the last two independent rounds' findings sit in Phase 5 and Phase 2 (round 6: Phase 5 two, Phase 2 one; round 8: Phase 5 one, Phase 2 one). The growth is in test and measurement detail, not in decisions, and findings are spread, not pooled in one section, so this is not specification drift. The remaining verification belongs to execution: each annotated span is verify-before-build, and defects found while building come back to the plan as findings.

## Completion summary

Rounds: 1 self (11 found, fixed), 2 Codex cold (9, fixed), 3 self (0), 4 Codex cold (4, fixed), 5 self (0), 6 Codex cold (3, fixed), 7 self (0), 8 Codex cold (2, fixed and annotated). No rejections; nothing awaited concurrence. The REQUIRED cross-model round for the data-integrity and security surfaces was met in round 2 and every independent round after it. Open question for Sam recorded at Task 3.1 (whether the 50-product limit de-duplicates across conditions). Editorial pass skipped: it does not run on a terminated-for-execution terminal.

Observations: every independent round found real defects by reading source the plan named (squirrel placeholder numbering, pgx config parsing, fixture helpers, `TestMain` placement), which a plan-only read would miss. Repairs that introduced new mechanics (falsification probes, fixture constructions) were the ones later rounds faulted.
