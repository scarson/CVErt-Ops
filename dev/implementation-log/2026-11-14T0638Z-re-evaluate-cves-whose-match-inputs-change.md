# Re-evaluate CVEs whose match inputs change

## What was built

| Feature | Files | Description |
|---|---|---|
| Change hashes | `internal/store/cve.go` | `GetCVEChangeHashes(ctx, cveID)` returns `CVEChangeHashes{Material, MatchInputs}`, empty strings for a missing row or a NULL value. It replaces `GetCVEMaterialHash`, whose only caller was the ingest handler. |
| Realtime trigger | `internal/ingest/handler.go` | The handler reads both hashes before and after each merge and runs `EvaluateRealtime` when the two structs differ and both reads succeeded. A change to `match_inputs_hash` alone (a CNA product name, an NVD vulnerable flag) now runs realtime evaluation. |
| Batch candidate scan | `internal/alert/evaluator.go` | `getCVEsModifiedSince`, in its two `since` cases, is a `UNION` of two keyset scans, one on `date_modified_canonical` and one on `date_match_inputs_changed`, each `ORDER BY cve_id LIMIT $n`, with an outer `ORDER BY cve_id ASC LIMIT $n`. The zero-`since` (full scan) cases and the EPSS path are unchanged. |
| Test fixture | `internal/alert/watchlist_cve_test.go` | `ageCorpus` also moves `date_match_inputs_changed` an hour back, so a CVE it ages is outside batch selection by both change dates. Its callers pass unchanged. |

This is the re-check signal of MATCH-2 design section 7 (`dev/plans/2026-11-13-product-match-rules-design.md`; Sam's ruling in section 15.1: a separate signal, never a `material_hash` change), read by the realtime and batch paths. The batch statement:

```sql
(SELECT cve_id FROM cves WHERE date_modified_canonical > $1 [AND cve_id > $2] ORDER BY cve_id LIMIT $n)
UNION
(SELECT cve_id FROM cves WHERE date_match_inputs_changed > $1 [AND cve_id > $2] ORDER BY cve_id LIMIT $n)
ORDER BY cve_id ASC LIMIT $n
```

## Key decisions

- The inner limits do not change a page: the first `$n` IDs of the union are among the first `$n` of each branch. `TestBatchCandidates_UnionPagesThroughBothChangeDates` pins it with 3 CVEs eligible only by `date_modified_canonical`, 3 only by `date_match_inputs_changed`, 2 by both and 3 by neither (one with a NULL `date_match_inputs_changed`), interleaved by ID: pages of 2 return the 8 eligible IDs once, in order. The test is in a new internal-package file, `internal/alert/batch_candidates_test.go`, because a page size of 2 needs the unexported `getCVEsModifiedSince`; the plan named `evaluator_test.go` or `match_inputs_recheck_test.go`, which are both `package alert_test`.
- `cursorRescanWindow` covers the new column: `date_match_inputs_changed` is stamped from the same merge clock value (`$5`) as `date_modified_canonical`, read after the per-CVE advisory lock and before the upsert.
- `TestGetCVEChangeHashes` (store) covers the method's contract: empty strings for a missing CVE, the stored values after a merge, and an empty `MatchInputs` for a NULL column.
- Falsification probe for the batch `UNION` arm: with `internal/alert/evaluator.go` saved to the session scratchpad and the second arm deleted, `TestRecheck_BatchEvaluatesSkippedRealtime` failed (0 events and 0 notifications after the batch run, want 1) and so did the pagination test. Deleting the arm alone left `(SELECT ...) ORDER BY ... LIMIT`, which PostgreSQL refuses (`multiple ORDER BY clauses not allowed`), so the probe also dropped the outer `ORDER BY`/`LIMIT` to fail on behaviour rather than syntax. The saved file was copied back with `cp`, `git diff` showed the change intact, and the tests passed again.

## Pitfall check

`/pitfall-check` on `internal/alert/evaluator.go`, `internal/merge/pipeline.go`, `internal/merge/match_inputs.go` and `internal/ingest/handler.go`: no issues. No `defer` in a loop, no `time.After` loop, no positional `IN` list, no streaming decode in scope, the `UpsertCVE` hash columns are text with an `IS DISTINCT FROM` CASE, the advisory keys are FNV in Go (DB-3), alert event inserts keep their dedupe guard, candidate queries keep the `COALESCE(lower(status), '')` retraction filter, the keyset scans page on the unique `cve_id` and only filter on the nullable date (a NULL date is never selected by that branch, which is correct: such a CVE has not been merged since the column was added), and the batch cursor keeps its rescan window (NOTIFY-20).

## Review: concurrency and clocks

One round; no material findings in this change.

- Two merges of one CVE serialize on the per-CVE advisory lock, and each stamps from a clock read after taking it. The handler's before and after reads are outside the lock, so an interleaving of two workers can make both see equal hashes and skip realtime; both merges still stamp `date_match_inputs_changed` (or `date_modified_canonical`), so the next batch run evaluates the CVE. This was already true for `material_hash`.
- When a late-binding move takes one of several sources away from a CVE (`bindAdvisoryToCVE`), that CVE is recanonicalized under its own lock, and any change to its match inputs is stamped, so batch evaluates it; realtime runs only for the patch's CVE ID, as before.
- Realtime failure followed by a batch run: covered by `TestRecheck_BatchEvaluatesSkippedRealtime`. A held batch cursor keeps `Since`, so the CVE stays in the window.
- Pre-existing, outside this change: a CVE renamed by `migrateCVEPKRename` keeps its old `date_modified_canonical` and `date_match_inputs_changed`, and moves `date_modified_canonical` only when an alert moved with it. If realtime evaluation of the promoting merge fails, a rule bound to a watchlist that lists the new CVE ID, whose item predates the rename and which had no event on the native ID, is never evaluated against it by the batch path.

## Quality checks

- `go test ./internal/ingest/... ./internal/store/... -count=1 -run 'Handler|CVE'`: pass (91 tests). The handler tests `CalledWhenOnlyMatchInputsChange`, `SkippedWhenPreMergeReadFails` and the store test `TestGetCVEChangeHashes` failed first on the undefined type and method.
- `TestBatchCandidates_UnionPagesThroughBothChangeDates` failed first (the 3 CVEs eligible only by `date_match_inputs_changed` missing), then passed.
- `go test ./internal/alert/... -count=1 -run 'Recheck|LateBinding|Batch'`: pass. `TestRecheck_*` (`internal/alert/match_inputs_recheck_test.go`) covers a CNA product change alone, a vulnerable flag flip, batch after skipped realtime, a case-only NVD copy, a stored NULL hash and the late-binding move; each reads `GetCVEChangeHashes` before and after the merge and runs realtime only when they differ, asserting on that comparison.
- `go test ./internal/alert/... -count=1`: pass (whole package once, since `ageCorpus` callers span several files).
- `go test ./internal/merge/... -count=1`: pass, and no golden file changed.
- `go build ./...`, `go vet -tags keptingest ./internal/alert/`: clean. golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
