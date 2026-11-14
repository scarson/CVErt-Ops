# MATCH-2 implementation plan: product conditions in alert rules

## What was done

Wrote `dev/plans/2026-11-13-product-match-rules-plan.md`, the implementation plan for the approved MATCH-2 design (`dev/plans/2026-11-13-product-match-rules-design.md`). No code changed. The plan follows the design's section 16 commit order in six phases:

1. `internal/check` exports the name lookups and the two index-expression helpers, gains the rule's `vendor:product` value parser, two Node.js CNA spellings, an ASCII word boundary for other products, and a pinned digest of the name table.
2. The DSL compiles child-table conditions as CVE-ID sets that carry the caller's candidate IDs (`CompiledRule.Where(candidateIDs)`), correlates package conditions with `eq`/`in` ecosystem conditions on one row, adds `affected.package` `eq`/`in`, binds every list as one array parameter, and adds the 100-condition limit and the never-matching-ecosystems error.
3. The `affected.cpe_product` field (NVD vulnerable CPE rows and CNA names), its limits and messages, integration tests including the acceptance case and a same-answer-on-every-path check, and the AI prompt notes.
4. A measurement gate on the kept full ingest, read-only, against every threshold in design section 13.
5. The re-check signal: `schema-review`, then the `migration` skill for `cves.match_inputs_hash`, `cves.date_match_inputs_changed` and their partial index, merge computing the hash, the ingest handler and the batch scan acting on it.
6. PLAN.md and version check design updates, `/plan-check` against PLAN.md §10, code and security review, full suite, PR.

## Decisions and gotchas

- **The full activation scan runs on a disposable restored copy.** Design section 13 asks for a full activation scan, which writes `alert_events`; the kept ingest is read-only. The harness first times the read-only part of every activation page on the kept ingest, then the scan itself runs on a copy restored from the kept backup into a new container, which is removed afterwards.
- **Product limit counted per condition.** The design counts the 50 product values "after normalisation and de-duplication". De-duplicating across conditions would let 100 conditions each list the same 50 products and compile to about 125,000 bind parameters, past PostgreSQL's 65,535, so the plan de-duplicates within a condition and sums across conditions. This is put to Sam as an open question.
- **Validation stays linear.** The never-matching-ecosystems check looks up each value's colon-prefixes in per-condition maps instead of comparing values pairwise; a 1 MiB request can hold tens of thousands of ecosystem values.
- **`null` lists keep their meaning.** Moving `in`/`not_in` to `= ANY`/`<> ALL` binds a nil slice as SQL NULL; the plan normalises nil lists to empty so `not_in: null` still matches everything.
- **One message added.** Design section 3.1 refuses non-printable-ASCII product values but section 8 gives no message for it; the plan adds `value must be printable ASCII with no spaces, as a CPE 2.3 name is`.
- **Design wording defect found.** Section 12 says each refusal the rule adds is also refused by the check; section 3.1 says the check accepts unescaped `*` and `?`. The plan tests section 3.1's invariant (every value a rule accepts, the check accepts).
- **Measurements reuse the production statement.** Task 2.2 extracts `candidateQuery` from the evaluator so the build-tagged harness explains exactly what production runs.
- **The kept ingest's password stays out of output**: a scratchpad script reads it from the container and passes it to the harness as a separate variable, never inside a connection URL that a parse error would echo.

## Quality checks

Plan review by `plan-review-cycle`: 8 rounds, four of them cold reads by Codex (a different model provider), raising 9, 4, 3 and 2 findings, all fixed. The falling-but-not-zero counts tripped the review's plateau circuit breaker, so the review ended as TERMINATED-FOR-EXECUTION with the last two repairs marked verify-first in the plan (Task 2.1's test placement; Task 5.3's ASCII-only lower-casing in `match_inputs_hash`). It is not certified clean. Round table and raw reports: `dev/plans/reviews/2026-11-13-product-match-rules-plan.*`. Docs only; no tests run.

- **`match_inputs_hash` lower-cases ASCII only.** Go's `strings.ToLower` folds KELVIN SIGN to `k` where PostgreSQL's `lower()` may not, so a Unicode-folded hash could miss a CNA name change that changes a SQL match.
- **Batch candidate scan limits each branch.** The `UNION` of the two timestamp scans limits each branch to the page size, so a page never de-duplicates the whole eligible set; it is measured on the disposable copy.
