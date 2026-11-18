# Watchlist items that name a CVE

## What was built

- Migration `000052_watchlist_cve_items`: `cve` value on `watchlist_item_type`, `watchlist_items.cve_id`, the `wi_cve_fields` type guard, the `watchlist_items_cve_uq` partial unique index, and `watchlist_items_cve_changed_idx` for the evaluators.
- `store.ReplaceWatchlistItems`: makes a watchlist's live items equal to a given list in one transaction, soft-deleting what was dropped and leaving unchanged rows untouched.
- The watchlist filter in `internal/alert/dsl/compiler.go` matches `cve` items.
- The batch and EPSS evaluation paths also evaluate CVEs added to or removed from the watchlists a rule is bound to.

## Key decisions

- **A CVE listed when it already matches alerts on the next run.** Evaluation is driven by `date_modified_canonical` and `date_epss_updated`, so a test against the plain cursor showed a CVE already in KEV never alerted (`0 events for CVE-2017-5638`). `getWatchlistCVEChangesSince` reads items whose `GREATEST(created_at, deleted_at)` is past the cursor and adds those CVEs to the candidates of the rules bound to that watchlist only. No rule changes status and no activation job runs. `alert_events` uniqueness keeps a repeat run or a repeat push from alerting twice.
- **A removed CVE is a candidate too**, so the rule resolves its event (`last_match_state = false`) without waiting for the CVE to change.
- **One EXISTS per item type in the filter**, instead of one EXISTS with an OR across types, so the planner can use each type's partial index. Timed with a throwaway test on 20,000 CVEs and a 10,000-item list: batch run with 10,000 candidates 337 ms, full-corpus dry run 591 ms, first push 202 ms, repeat push 18 ms.
- **No foreign key to `cves`.** A scanner can report a CVE no feed has delivered. The item starts matching when the CVE arrives.
- **`FOR UPDATE` on the watchlist row** serializes replaces. It also blocks the foreign-key check of a concurrent item insert, so a `POST` cannot land between the diff's read and write.
- **Multi-row insert through `ROWS FROM (unnest(...), ...)`.** A `VALUES` list at the cap would exceed the 65535 parameter limit. sqlc does not know the multi-argument `unnest`, and it accepts `ROWS FROM`.

## Gotchas

- `ALTER TYPE ... ADD VALUE` cannot be followed by a use of the value in the same transaction. The migration runner autocommits each statement (`MultiStatementEnabled`), so one file works. Comments in such a file must not contain a semicolon, because the runner splits on every one.
- Postgres cannot drop an enum value. The down migration removes the rows and the column and leaves `cve` in the type.
- `description_primary` is not a material field, so a description-only re-ingest does not bump `date_modified_canonical`. Tests that need a material change have to change a field in `MaterialFields`, such as severity.
- `testutil.SeedCorpus` calls `t.Setenv`, so a test that uses it cannot call `t.Parallel`.

## Quality checks

- `go test ./internal/alert/...` passes, including `TestWatchlistCVE_*`, which run the evaluator as `cvert_ops_app` so the list-change query passes through RLS.
- Targeted `go test ./internal/store/` for watchlist tests passes.
- `golangci-lint run` on the changed packages reports 0 issues.
