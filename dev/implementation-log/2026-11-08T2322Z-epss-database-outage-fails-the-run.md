# EPSS database outage fails the run

## What was built

- `epss.Adapter.applyRows` now fails the run when a row fails for any reason other than Postgres refusing that row's data. Before this, every row error with a live job context was logged and skipped, so during a database outage `Apply` returned the new cursor with no rows applied. The handler recorded a success, and when the file was dated today the same-day cursor check skipped it until the next file.
- `isRowRejected` identifies a refusal: a `*pgconn.PgError` with SQLSTATE class 22 (data exception).
- `Apply` skips a row whose CVE ID does not match `feed.IsCVEID` or is longer than `maxCVEIDLength` (64 bytes), with a warning, before it reaches a batch. Failing the run on a row the database cannot store would otherwise stop every retry at that row: a 6,400-byte ID raises 54000 from the `epss_staging` primary key index.

## Key decisions

- Classify the error rather than count failures. A consecutive-failure or per-batch threshold needs a chosen number and misses an outage that starts in the last rows of a file, or wrongly fails on a final short batch holding one bad row. Classification decides per row and has neither problem.
- Anything unrecognised fails the run. A wrongly failed run is visible in `feed_sync_state` and can be retried; a wrongly skipped row is silent. This also covers failures that hit every row without being an outage, such as `permission denied` (42501) or a read-only standby (25006).
- Class 23 (constraint violations) fails the run. The two EPSS statements always supply every column they write and resolve key conflicts with `ON CONFLICT`, so a violation cannot come from one row's data; it means the schema has changed. An executing review confirmed the alternative: with the default dropped from `epss_staging.ingested_at`, every staging insert raised 23502, every row was skipped, and the run was recorded as a success.
- A failed batch still falls back to applying its rows one at a time for every error. A batch can be aborted by a deadlock with the merge pipeline, and only a row-level error shows whether the data or the database is at fault.
- The run stops at the first such row. During an outage each further row would wait on the same failure, and the apply is idempotent, so a later attempt can start again from the top of the file.

## Gotchas

- `TestApply_SkipsPoisonRows` returned a plain `fmt.Errorf` for its bad row, which is not what a refused row looks like. Its row hook now returns a `*pgconn.PgError`; the assertions are unchanged.
- A CVE ID that is not valid UTF-8 does not reach Postgres unchanged on the batch path. `pq.Array` sends `text[]` as a string, pgx's text-array parser (`pgtype/array.go`) reads it rune by rune, and the invalid byte is written back as U+FFFD, so Postgres accepts the row and stores the replaced ID. A direct single-row insert of the same value fails with 22021. The CVE ID check now drops such a row before it reaches the driver. The integration test for a refused row uses a `CHECK` expression it adds itself, which divides by zero for one CVE ID and raises 22012.

## Known limits

- If a schema change made every row raise a class 22 error, for example a column type change, the row-by-row fallback would run until the 10-minute job limit and the run would then fail as interrupted. A file too short to reach that limit would be recorded as a success. No threshold was added: no current column can raise a data exception for a well-formed row.

## Quality checks

- `TestApply_DatabaseOutage_FailsRunAndLaterAttemptSucceeds` and `TestApply_UnreachableDatabase_FailsRun` (real driver, connection refused) failed before the change because `Apply` returned a cursor, and pass after it. The first also proves a later attempt the same day applies the file.
- `TestApply_ConstraintViolation_FailsRun` (real 23502 after dropping the column default) and `TestApply_SkipsRowsWithMalformedCVEID` (the 6,400-byte ID, a non-CVE ID and invalid UTF-8) failed before the matching change and pass after it.
- `TestApply_RowRejectedByPostgres_CostsOnlyThatRow` (real Postgres, real SQLSTATE through the driver) and `TestApply_SkipsPoisonRows` were break-tested with `isRowRejected` forced to false and failed with `epss: apply failed at ...`.
- An executing review with live probes (read-only errors, statement timeouts, connections terminated during writes and commits, deferred constraint rejection) confirmed the outage paths and found the constraint and oversized-ID problems that this entry's decisions address.
- `go test ./internal/feed/ ./internal/feed/epss/ ./internal/ingest/ -count=1` passes with a real Postgres (`TESTCONTAINERS_RYUK_DISABLED=true`, because of the known reaper `removing` failure on this host).
- `golangci-lint run` reports 0 issues on `internal/feed/`, `internal/feed/epss/...` and `internal/ingest/...`.
