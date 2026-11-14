# Skip the never-matching check when an ecosystem value is invalid

## What was built

| Feature | Files | Description |
|---|---|---|
| Bounded never-matching check | `internal/alert/dsl/validator.go` | `validatePackageCorrelation` collects an `affected.ecosystem` `eq`/`in` condition's values for the never-matching check only when every value passes `ecosystem.Valid`. A condition with an invalid value leaves the check unrun, as an unparseable value already did. |
| Test | `internal/alert/dsl/dsl_test.go` | `TestValidate_InvalidEcosystemSkipsNeverMatchingCheck` |

The never-matching check (MATCH-2 design section 8, `dev/plans/2026-11-13-product-match-rules-design.md`) tries each value as the stored ecosystem, and for a value whose base takes a suffix, `hasColonPrefixIn` looks up the prefix before each of its colons. Each lookup hashes the prefix, so the cost is quadratic in the value's length. The check ran even when `validateValue` had already refused the ecosystem values, so one condition holding `"Debian"` followed by a mebibyte of colons, beside a correlated condition of more than eight values, cost seconds of CPU per request.

## Key decisions

- A valid ecosystem value is at most 64 characters (`ecosystem.Valid`, the `watchlist_items.ecosystem` CHECK), so the check's cost stays linear in the request. The skipped rule already carries an error for the invalid value, so it cannot be saved.
- The test's other ecosystem condition lists nine values on purpose: Go looks up a key in a map of eight or fewer entries by comparing keys, which rejects a prefix of the wrong length at once, so with a short list the quadratic cost does not show. With nine values the test took 17 s before the fix and 0.02 s after. It carries no timing assertion; it asserts one value error at the condition's index and no never-matching error, for an `eq` and an `in` condition, and that a valid never-matching rule is still refused.

## Quality checks

- `TestValidate_InvalidEcosystemSkipsNeverMatchingCheck` failed first (never-matching error present, two blocking errors), then passed.
- `go test ./internal/alert/dsl/... -count=1`: pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
