# MATCH-2 implementation summary: product conditions, package correlation and the re-check signal

> **Date:** 2026-11-14
> **Commits:** `cc883cd`..this commit on `claude/lucid-moser-fef966` (PR to `dev` not yet opened)
> **Plan:** `dev/plans/2026-11-13-product-match-rules-plan.md`
> **Design:** `dev/plans/2026-11-13-product-match-rules-design.md`; the query shape actually built is its section 17 (amendment after the implementation measurements)
> **Measurements:** `dev/plans/2026-11-13-product-match-rules-measurements.md` (every statement on the kept full ingest, before and after each remedy)

## What was built

| Feature | Files | Description |
|---|---|---|
| Shared product names | `internal/check` | The version check's name table, value parser, key builders and index expressions exported for rule matching; two Node CNA spellings added; the other-product boundary is an ASCII letter or digit; a digest test pins the table. |
| Array binding and `CompiledRule.Where` | `internal/alert/dsl`, `internal/store/dsl_executor.go`, `internal/alert/evaluator.go` | Every `in`/`not_in` list is one array parameter. The rule's SQL depends on the caller's candidate IDs. |
| Package correlation and exact match | `internal/alert/dsl` | `affected.package` `eq`/`in` after ecosystem folding; under `and`, matched on one row with the `eq`/`in` ecosystem conditions; ecosystems compared exactly; never-matching ecosystem combinations refused; 100-condition limit. |
| `affected.cpe_product` | `internal/alert/dsl`, `internal/ai/schema.go` | NVD vulnerable CPE rows and CNA names through the name table; 50-value limit; AI search prompt notes. |
| Measurement harness | `internal/alert/kept_ingest_measure_test.go`, `internal/alert/kept_ingest_activation_test.go` | Build tag `keptingest`; read-only against the kept ingest, writes only to a disposable copy. |
| Re-check signal | `migrations/000063_match_inputs_recheck.*`, `internal/merge/match_inputs.go`, `internal/ingest/handler.go`, `internal/alert/evaluator.go` | `match_inputs_hash` and `date_match_inputs_changed` on `cves`; realtime runs when either hash changes; the batch scan is a `UNION` of two keyset scans. |
| PLAN.md | `PLAN.md` §5.3, §10.1, §10.2, §10.3, §10.5, Appendix A | The field, correlation, limits, array binding, exact ecosystems, the built query shape, the re-check signal, and no `dsl_version` bump. Version check design section 4.5 gained an amendment line for the name table changes. |

## Measurement gate (plan Phase 4)

- **First run failed** for the limit rule (50 one-value product conditions and 50 one-value package conditions, no ecosystem, under `or`): realtime 23.3 ms against 5 ms; dry-run and batch out of shared memory (27.6 s and 17.7 s serially, against 5 s and 3 s); 50 products under `or` 16.2 s as a dry-run; full activation out of shared memory on its first page. Single-product, package-with-ecosystem and saved-search rows passed.
- **Sam's remedy, in three steps** (the limits stayed at 50 products and 100 conditions):
  1. Under `or`, all set conditions form one CVE set; the evaluator's candidate statement runs with JIT off.
  2. With candidate IDs, product sets match CPE prefixes and CNA names against bound arrays, so planning does not grow with the number of products; with none, the OR-ed range form stays.
  3. Evaluator rule statements also run with parallel query off, and under `or` all package `eq`/`in` conditions form one branch.
- **Final results:** every statement threshold passes (limit rule realtime 4.7 ms, dry-run 4.3 s, batch 0.45 s; 50 products under `or` 1.4 s).

## Decisions Sam accepted

- **Full activation of the limit rule (M8):** 12 min 5 s against 7 minutes, accepted as a cost of one insert transaction per event (200,252 events), not of the rule shape. The follow-up, PR 243 (activation writes each page's events in one transaction), merged into this branch; M8 then took 2 min 4 s.
- **Sparse batch page:** the re-check batch scan's first page takes 3.7 s against 3 s when more than a page of changes sits at the end of `cve_id` order (the existing arm alone takes 1.27 s there). Accepted; paging by `(date, cve_id)` would remove it if backlogs matter.

## Review outcomes

- The after-Phase-3 adversarial review found one defect in this branch (quadratic `Validate` cost), fixed in `d69081d`.
- Two older defects found by reviews are recorded under the plan's Discoveries for Sam, not fixed here: `Compile` builds wrong SQL for a stored rule holding an operator `Validate` refuses, and a renamed CVE ID can miss batch evaluation for a watchlist-bound rule if realtime fails on the promoting merge.
- No CLI or MCP code lists DSL fields or calls the validate endpoint yet, so nothing outside `internal/alert`, `internal/api` and `internal/ai` describes the new field.

## Quality checks

- Documentation only in this commit; no tests run for it. Per-task test runs are in each commit's own entry.
- Full suite: not run since `2339364` (Task 6.4 runs it before the PR).
