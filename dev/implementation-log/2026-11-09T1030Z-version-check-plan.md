# Version check endpoint: implementation plan

## What was built

- `dev/plans/2026-11-09-version-check-endpoint-plan.md`: data changes, then a full ingest, then the endpoint, then measurement before merge. No code or migration.
- `dev/plans/reviews/2026-11-09-version-check-endpoint-plan.plan-review.md`: the review record.

## Decisions and gotchas

- The design's cursor reset is gone: there are no existing installs, so the first ingest is the walk.
- The data changes ship first because a walk under earlier code would have to be repeated.
- The golang-migrate driver splits on a semicolon inside a SQL comment (pitfall DB-16). The first draft of the migration had one.
- `testutil` imports `store`, so the snapshot tests live in `store_test` with an `export_test.go` bridge.
- `middleware.RequestSize` only wraps the body, and `decodeJSON` reports the overflow as 400, so the handler detects it and returns 413.
- A wholly `unaffected` CNA entry is No statement even with unreadable bounds, because no reading of it can condemn the version. The reviewer concurred after the rejection.

## Quality checks

- Plan review ended TERMINATED-FOR-EXECUTION after 8 rounds, on the plateau trigger, with 5 verify-first flags in the plan. Independent rounds raised 13, 7, 3, 3 and 5 findings.
- Each cold round compiled and ran the plan's purl and CNA segment code, and ran its SQL on PostgreSQL 18.
- No repository tests ran, because no code changed.
