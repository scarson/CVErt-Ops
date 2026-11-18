# Alert event retention and the since filter use the most recent fire

## What was built

- `CleanupAlertEvents` now requires both `first_fired_at` and `last_fired_at` to be before the cutoff, so a reopened event ages from its most recent fire.
- `ListAlertEvents` compares `?since=` against `last_fired_at`.
- `PLAN.md` §21 (retention table) and Appendix B (alert-events filters) state this. The EPSS handling notes and §10.3 (execution model) no longer say that repeat fires are suppressed after a score re-crosses a threshold, which stopped being true when resolved events began to reopen.

## Key decisions

- No migration or new index for retention. `last_fired_at` is never earlier than `first_fired_at`, so `last_fired_at < cutoff` implies `first_fired_at < cutoff`. Keeping the redundant bound on `first_fired_at`, and the `ORDER BY` on it, leaves the batched delete on `alert_events_first_fired_at_idx`.
- List order and the keyset cursor stay on `first_fired_at`. A row's position in the list does not move when it reopens, so a client paging through the list cannot skip or repeat it. A reopened event therefore appears at its original position, not at the top.

## Gotchas

- The retention fixtures set only `first_fired_at`, and `last_fired_at` defaults to `now()`. Once the query read `last_fired_at`, a test that asserts survival, such as `TestRunner_UnlimitedRetentionSkipsOrg`, would have passed from the default alone, so every fixture now backdates both columns.

## Known limits

- `?since=` has no index on `last_fired_at`. A `since` query now filters within the org's events instead of bounding a range on `first_fired_at`. Results for events that never reopened are unchanged, but the query plan differs. This was not measured. The table is bounded by retention, and the web client does not send `since`.

## Quality checks

- `TestCleanupAlertEvents_AgesFromLastFire` failed before the fix with `deleted = 2, want 1`. `TestListAlertEvents_SinceCountsMostRecentFire` failed with `got 0 events, want 1`.
- `go test ./internal/retention/ -count=1` passes, as do the `TestCleanup` and `TestListAlertEvents` tests in `internal/store` and the `AlertEvent` tests in `internal/api`, with a real Postgres (`TESTCONTAINERS_RYUK_DISABLED=true`).
- The full suite was not run locally.
