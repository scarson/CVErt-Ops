# Page the batch and EPSS candidate scans by (date, cve_id)

## What was built

| Feature | Files | Description |
|---|---|---|
| Candidate scans | `internal/alert/evaluator.go` | `changeScan` runs one keyset scan per change date: `(date_col, cve_id) > ($date, $id) AND date_col <= $until ORDER BY date_col, cve_id LIMIT n`. `changedCVEs` sorts and de-duplicates the IDs of all scans. The batch path scans `date_modified_canonical` and `date_match_inputs_changed`; the EPSS path scans `date_epss_updated`, and retracted CVEs by `date_modified_canonical`. The zero-cursor full scans still page by `cve_id` (`idPage`). `collectChanges` is the page loop; `evaluateBatchPath` no longer pages itself. |
| Upper bound | `internal/alert/evaluator.go` (`evaluateBatchPath`) | Each run reads changes stamped up to `batchTime + cursorRescanWindow`. The bound ends the scan even while merges keep re-stamping rows, and a stamping clock that runs ahead of the evaluator's by less than the window delays nothing. |
| Migration 000065 | `migrations/000065_change_date_keyset_indexes.{up,down}.sql` | Replaces `cves_date_modified_canonical_idx`, `cves_date_epss_updated_idx` and the partial `cves_date_match_inputs_changed_idx` with `(date, cve_id)` indexes (the match-inputs one stays partial), built concurrently before the old ones are dropped. |
| Tests | `internal/alert/batch_candidates_test.go`, `internal/alert/evaluator_test.go`, `migrations/change_date_keyset_indexes_test.go` | Page size 2 over date ties, a CVE found by both scans, the exclusive `since` and inclusive `until`, rows moved between pages (`TestBatchCandidates_RowsMovedDuringScan`), the EPSS split, the zero-cursor scans; `TestEvaluatorBatch_ChangeStampedAheadOfEvaluatorClock`; the migration down, up, up again, down. |
| Measurements | `dev/plans/2026-11-13-product-match-rules-measurements.md` ("Task 5.5 re-run"), `dev/plans/2026-11-13-product-match-rules-plan.md` | Every batch-path page is an index-only scan of 0.13 to 0.21 ms, sparse first page included (was 3.7 s, accepted by Sam earlier the same day). |
| PLAN.md | Appendix A, `cves` indexes | Names the three `(date, cve_id)` indexes. |

## Key decisions

- **Replace the single-column indexes rather than add composites.** Each `(date, cve_id)` index serves every query the single-column one served (the date is its leading column), and a backward scan of `(date_modified_canonical, cve_id)` gives search's `date_modified_canonical DESC, cve_id DESC` order exactly. Adding instead would put three more indexes on `cves`, whose rows the merge updates constantly.
- **Composite indexes, though single-column ones with an incremental sort were fast on the copy.** A later page's row comparison is exact on `(date, cve_id)`; on a date-only index it becomes `date >= $date` and re-reads every row that shares the page's last date. An EPSS batch stamps all its rows with one `now()`, so such ties are normal on `date_epss_updated`.
- **Rows that move during a scan** (reasoned in the `changeScan` comment): a row moved forward to a time at or before `until` is read at its new place, possibly twice (de-duplicated); a row moved past `until` is read by the next run, whose `since` is before this run's `until`; a row moved backward behind the scan position was stamped by a writer that committed during the run, the case `cursorRescanWindow` already covers.

## Gotchas discovered

- Bounding the scan at `batchTime` itself failed `TestEvaluatorBatch_CursorAdvancement`: the test database's `now()` runs ahead of the Go clock on Docker Desktop, so a CVE stamped just before the second run was deferred to the third. On the EPSS path that would be a day late. The bound is `batchTime + cursorRescanWindow`.
- The later-page statement on `date_match_inputs_changed` uses the partial index (measured: an index-only scan), whose predicate `IS NOT NULL` the statement's `date_col <= $until` implies. Whether a row comparison alone would let the planner prove it was not checked; keep the scalar bound in that statement.
- The Task 5.5 copy was gone. The new copy (one table, piped from a read-only `pg_dump -t cves` of the kept ingest) ran the old `UNION` sparse first page in 443 ms with the same `cves_pkey` plan, not 3.7 s: the earlier copy's layout differed.
- gosec G202 flags the column-name concatenation in `changePage`; suppressed inline, since the names come only from the four `changeScan` values.

## Quality checks

- Mutation checks on the scan tests: removing the de-duplication, removing the upper bound, and splitting the row comparison into two scalar comparisons each fail the tests.
- `go test ./internal/alert/... ./migrations/ -count=1`: pass. `golangci-lint run --allow-parallel-runners`: 0 issues.
