# List newest deliveries when the database clock leads the app clock

## What was built

- `listDeliveriesHandler` (`GET /api/v1/orgs/{org_id}/deliveries`) bounds the first page with `firstPageCursorTime`, 9999-12-31T23:59:59Z, instead of `time.Now()`. The `ListDeliveries` query keeps only `created_at < $5 OR (created_at = $5 AND id < $6)`, and `created_at` comes from the database's `now()`. When the database host's clock led the app host's, deliveries created in that gap were missing from the first page, and from every later page, because the next cursor starts below the first page's last row.
- `TestListDeliveries_FirstPageIncludesRowsAheadOfAppClock` moves a delivery's `created_at` 5 seconds past the database's `now()` and asserts the first page lists it.

## Key decisions

- **A far-future sentinel rather than a nullable cursor bound.** The query, the store signature and the generated code stay as they are. A `$5 IS NULL OR ...` predicate gives the same result but changes `Store.ListDeliveries` and needs `sqlc generate`.
- `uuid.Max` stays as the first-page tiebreaker. No row has `created_at` equal to the sentinel, so the `id < $6` branch never applies on the first page.

## Gotchas

- `TestListDeliveries_Envelope` and `TestListDeliveries_FilterByRuleAndChannel` failed intermittently in full `internal/api` runs with "items count = 0, want 1" and passed alone. The test Postgres container's clock measured about 130–150 ms ahead of the host, so a delivery created just before the list request sometimes had a `created_at` later than the handler's `time.Now()`. This was the only handler in `internal/api` that seeded a cursor from the app clock.

## Quality checks

- New test failed before the fix (`items = []`) and passes after it.
- `go test ./internal/api/ -count=1` and `go test ./internal/store/ -count=1`: pass.
- `golangci-lint run ./internal/api/`: 0 issues.
