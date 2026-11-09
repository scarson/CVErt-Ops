# Plan review controller checkpoint

- **Plan:** `dev/plans/2026-11-09-version-check-endpoint-plan.md`
- **Run started:** 2026-11-09. **Status:** finalized, TERMINATED-FOR-EXECUTION after 8 rounds with 5 verify-first flags annotated in place.
- **Baseline at opening:** 1,171 lines, 15 tasks, 15 task-level verification contracts (Phases 2 and 4 are operational steps).
- **Named surfaces:** data integrity (merge and ingest changes, verdict logic). A cross-model round is required.

## Round table

| Round | Reviewer | Raised | Fixed | Rejected | Notes |
|---|---|---:|---:|---:|---|
| 1 | Self-review (Claude Opus 5.5) | 12 | 12 | 0 | Unknown `versionType` treated as no version information; undefined `unlimited` readability; fix-order rule at odds with design section 7; `Evaluate` lacked a context; `Keys` and `Candidates` undefined; enrichment omitted severity and CVSS; test seam ambiguous; limit cross-reference wrong; migration test location, web schema path and regeneration command unspecified; CVE-2024-7347 label |

| 2 | Independent, Codex `gpt-6.1-sol` `xhigh`, cold | 13 | 13 | 0 | 2 blockers: inclusive end in `possiblyContains`; semicolon in a migration comment (DB-16). 8 major: nullable sentinel, long-name interval, `store` test import cycle, unbounded `package_key`, Phase 2 connection setup, compose container names, default-branch gate, sentinel with `changes[]`. 3 minor: cancellation plumbing, both upper bounds, PowerShell syntax |
| 3 | Self-review (Claude Opus 5.5), wave re-read | 1 | 1 | 0 | Named the real OpenAPI generation test |
| 4 | Independent, Codex `gpt-6.1-sol` `high`, cold | 7 | 6 | 1 (concurred) | Rejected and concurred in round 6: first `unaffected` segment with an unreadable bound, because no reading of it can condemn the version; the design row now says so. Fixed: NUL from percent-decoding, meter inside `readEntry` with the range limit before reading, Postgres TLS certificates in Phase 2, full-vendor recheck in the nearby-name SQL, an executable break test, metrics port in Phase 4 |
| 5 | Self-review (Claude Opus 5.5), wave re-read | 0 | 0 | 0 | Re-read this wave's edits together, no interaction found |
| 6 | Independent, Codex `gpt-6.1-sol` `high`, cold | 3 | 3 | 0 | Open-ended free-text range read as one version; wildcard end treated as inclusive; Alpine purl naming another distribution |
| 7 | Independent, Codex `gpt-6.1-sol` `high`, cold | 3 | 3 | 0 | Early returns preceded the wholly-`unaffected` rule; `CNARangeCount` wording ambiguous; NUL cleaned before purl parsing |
| 8 | Independent, Codex `gpt-6.1-sol` `high`, cold | 5 | 5 | 0 | Nearby-name filter at CVE level; oversized body gave 400 not 413; cancellation unseen between tick multiples; two measurements unassigned; conflicting authority sentence. All five repairs are annotated verify-first |

**Notes:** Project pitfalls docs are at `dev/implementation-pitfalls.md` and `dev/testing-pitfalls.md`. Awaiting-concurrence file: none open. Round 2 ran at `xhigh`, stepped up deliberately because it executed the verdict code. The wave above ten findings was re-read by the fix author, and the next cold round is the independent check on it.

## Independent rounds

| Ordinal | Round | Repairs reviewed / defective | Review-record findings / total | Concentration | Breaker |
|---|---|---|---|---|---|
| 1 | 2 | Not applicable (first independent round) | 0 / 13 | Task 3.5 (3), Task 1.2 (2), Tasks 3.8-3.9 (3), Phase 2 (2), other (3) | Not evaluated: first independent round |
| 2 | 4 | 14 / 2 defective (meter placement, Phase 4 process setup) | 0 / 7 | Task 3.5 (2), Tasks 1.1-1.2 (1), Task 3.9 (1), Task 3.11 (1), Phases 2 and 4 (2) | Plateau needs two consecutive rounds, 7 of 13 is the first. Repair recursion 2 of 14, under one third. Self-reference 0. Backstop no. No trigger, so the next round is allowed |
| 3 | 6 | 7 / 0 defective | 0 / 3 | Task 3.5 (2), Task 1.1 (1) | Plateau no: 3 is under half of 7. Repair recursion 0 of 7. Self-reference 0. Backstop no. No trigger, so the next round is allowed |
| 4 | 7 | 3 / 0 defective | 0 / 3 | Task 3.5 (2), Task 1.2 (1) | Plateau no: round 6 was under half, so two consecutive rounds have not met it. Repair recursion 0 of 3. Self-reference 0. Backstop no. No trigger, so the next round is allowed. If the next round raises 2 or more, plateau fires |
| 5 | 8 | 3 / 0 defective | 0 / 5 | Tasks 3.8, 3.10, 3.3 and 3.5, Phases 2 and 4, plan header: spread across six places | **Plateau fired:** rounds 7 and 8 raised 3 of 3 and 5 of 3. No user turn in hand, so fired and disclosed |

## Terminal summary

`TERMINATED-FOR-EXECUTION after 8 rounds — 5 verify-first flags annotated in place`. All 44 findings raised (31 of them by independent rounds) were fixed or, for one, rejected with the reviewer's concurrence. Independent rounds raised 13, 7, 3, 3, 5.

**Firing diagnostic.** Plan size grew from 1,171 lines to about 1,300, while the 15 tasks and their verification contracts stayed the same. The last two rounds' findings are spread across six places, so this is not specification drift and no relocation applies. The findings have moved from verdict logic to small mechanics. Execution is the cheaper reviewer from here.

**Executor's contract.** Annotated spans are verify-before-build. Defects that execution surfaces return to the plan as findings.

**Notes:** the required cross-model rounds were met by Codex `gpt-6.1-sol`. Each cold round compiled and ran the plan's code, and ran its SQL on PostgreSQL 18. None ran a live ingest.
