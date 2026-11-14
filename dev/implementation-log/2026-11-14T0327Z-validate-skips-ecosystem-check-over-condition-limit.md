# Validate skips the never-matching ecosystem check over the condition limit

## What was built

| Feature | Files | Description |
|---|---|---|
| Bounded validation cost | `internal/alert/dsl/validator.go` | `Validate` runs the never-matching ecosystem check (`validatePackageCorrelation`) only when the rule holds at most 100 conditions. A rule over the limit gets the limit error alone for that check. |
| Test | `internal/alert/dsl/dsl_test.go` | `TestValidate_OverConditionLimitSkipsEcosystemCheck`: a never-matching shape padded to 101 conditions returns the limit error and not the never-matching error; the same shape at 100 conditions returns the never-matching error. |

## Key decisions

- **Found by the after-Phase-3 adversarial review of the MATCH-2 plan** (`dev/plans/2026-11-13-product-match-rules-plan.md`). The check's cost is the number of ecosystem values times the number of conditions. Validate ran it before applying the 100-condition limit, so a 1 MiB `and` rule of 8,000 `affected.ecosystem` conditions and one 35,000-value list took about 5 s of CPU per create, PATCH, validate or saved-search request. Within the limit the cost is at most 100 times the values, which is linear in the request.
- The product limit check still runs over the limit: its cost is linear in the conditions, and the caller sees every error the rule has.

## Quality checks

- `go test ./internal/alert/dsl/... -count=1`: pass. The new test failed first, reporting the never-matching error on the 101-condition rule.
- `go test ./internal/api/... -count=1 -run AlertRule`: pass.
- golangci-lint v2.15.0 on `./internal/alert/...`: 0 issues.
