# EPSS database outage fails the run

## What was built

- `epss.Adapter.applyRows` now fails the run when a row fails for any reason other than Postgres refusing that row's data. Before this, every row error with a live job context was logged and skipped, so during a database outage `Apply` returned the new cursor with no rows applied. The handler recorded a success, and when the file was dated today the same-day cursor check skipped it until the next file.
- `isRowRejected` identifies a refusal: a `*pgconn.PgError` with SQLSTATE class 22 (data exception) or 23 (integrity constraint violation).

## Key decisions

- Classify the error rather than count failures. A consecutive-failure or per-batch threshold needs a chosen number and misses an outage that starts in the last rows of a file, or wrongly fails on a final short batch holding one bad row. Classification decides per row and has neither problem.
- Anything unrecognised fails the run. A wrongly failed run is visible in `feed_sync_state` and can be retried; a wrongly skipped row is silent. This also covers failures that hit every row without being an outage, such as `permission denied` (42501) or a read-only standby (25006).
- A failed batch still falls back to applying its rows one at a time for every error. A batch can be aborted by a deadlock with the merge pipeline, and only a row-level error shows whether the data or the database is at fault.
- The run stops at the first such row. During an outage each further row would wait on the same failure, and the apply is idempotent, so a later attempt can start again from the top of the file.

## Gotchas

- `TestApply_SkipsPoisonRows` returned a plain `fmt.Errorf` for its bad row, which is not what a refused row looks like. Its row hook now returns a `*pgconn.PgError`; the assertions are unchanged.
- A CVE ID that is not valid UTF-8 does not reach Postgres unchanged on the batch path. `pq.Array` sends `text[]` as a string, pgx's text-array parser (`pgtype/array.go`) reads it rune by rune, and the invalid byte is written back as U+FFFD, so Postgres accepts the row and stores the replaced ID. A direct single-row insert of the same value fails with 22021. The integration test for a refused row therefore uses a `CHECK` constraint it adds itself.

## Known limits

- If every row is refused as bad data, the row-by-row fallback runs until the 10-minute job limit, and the run then fails as interrupted. No threshold was added for this: it would take a whole file of rows the current schema has no constraint against.

## Quality checks

- `TestApply_DatabaseOutage_FailsRunAndLaterAttemptSucceeds` and `TestApply_UnreachableDatabase_FailsRun` (real driver, connection refused) failed before the change because `Apply` returned a cursor, and pass after it. The first also proves a later attempt the same day applies the file.
- `TestApply_RowRejectedByPostgres_CostsOnlyThatRow` (real Postgres, real 23514 through the driver) and `TestApply_SkipsPoisonRows` were break-tested with `isRowRejected` forced to false and failed with `epss: apply failed at ...`.
- `go test ./internal/feed/epss/ ./internal/ingest/ -count=1` passes with a real Postgres (`TESTCONTAINERS_RYUK_DISABLED=true`, because of the known reaper `removing` failure on this host).
- `golangci-lint run ./internal/feed/epss/... ./internal/ingest/...` reports 0 issues.
