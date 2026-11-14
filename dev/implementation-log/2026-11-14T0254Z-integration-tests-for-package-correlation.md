# Integration tests for package correlation

## What was built

MATCH-2 plan Task 2.5 (design sections 4.2, 4.3 and 12). New `internal/alert/package_match_test.go` ingests a hand-built corpus through `merge.Ingest` (`feed.CanonicalPatch`, source `osv`; the rejected CVE gets an NVD record with status `Rejected`) and evaluates rules through the real evaluator.

- `TestPackageMatch_RuleConditions`: each case runs one rule through realtime (every corpus CVE as the candidate) and a second rule through an activation scan, asserts each rule's status before and after, and checks the events on every corpus CVE, so a negative case cannot pass by never evaluating. Cases: npm `foo` plus PyPI `lodash` does not match `{and: ecosystem eq npm, package eq lodash}` but matches the `or` form and `{and: ecosystem eq PyPI, package eq lodash}`; `package eq Foo_Bar` matches PyPI `foo-bar` and not npm `foo-bar`, with and without ecosystems named; `Debian` with `openssl` matches a `Debian:13` row; `ecosystem neq npm` with `package eq lodash` does not match a CVE with any npm row; two package conditions match only a CVE with both npm rows; `contains` correlates too; a rejected CVE with a matching row does not match.
- `TestPackageMatch_EventsResolveUnderCorrelation`: an event inserted with `store.InsertAlertEvent` at the CVE's current hash, standing for one opened under the uncorrelated reading, resolves on the next realtime evaluation; a control rule that still matches keeps its event open, and no new event is written at the same hash.

## Key decisions

- **Realtime and activation in each case.** The two paths pass candidate IDs differently (one ID, then pages), and the set form repeats them inside each set, so each case checks both give the same events.
- **The rejected CVE's precondition is asserted** (status `Rejected` and one npm `lodash` row), so its exclusion is the evaluator's status filter, not missing data.

## Gotchas

- Break-test: with correlation disabled in `correlationFor`, the correlated `npm`/`lodash` case, the `contains` case and the resolution test fail; restored, they pass. The single-ecosystem cases pass either way by construction, which is why the mixed-ecosystem CVE is in every case's assertions.

## Quality checks

- `go test ./internal/alert/... -count=1 -run 'Package|Ecosystem'`: pass; no error-level log lines.
- After Phase 2 review: every existing `affected.*` rule shape in `internal/alert/dsl/dsl_test.go` changes meaning only by correlation and by exact ecosystem comparison; `internal/store/dsl_executor_test.go` has no `affected.*` rule. No existing integration test changed.
- End of Phase 2 group: `go test ./internal/alert/... -count=1` pass (333 tests and subtests; the only error-level log lines are the two fan-out failures existing tests inject on purpose); `go test ./internal/store/... -count=1 -run DSL` pass (22).
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
