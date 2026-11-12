# Check endpoint phase-end review fixes, round 3

## What was built

Four commits from the third round of Phase 3 phase-end reviews of `POST /api/v1/orgs/{org_id}/check`, the version check endpoint of `dev/plans/2026-11-09-version-check-endpoint-plan.md`. Test first in each.

- `378ccbc` fix(check): `ownNames` in `internal/check/names.go` pairs each spelling of the CPE vendor (`_` read as a space, then kept) with each spelling of the product, listing each distinct name once (at most four). Before this it built only the all-spaced and all-kept names, so `cpe:2.3:a:acme_corp:foo_bar` never read a CNA row `Acme Corp` / `foo_bar` or `acme_corp` / `Foo Bar`, and a CVE known only through such a row answered `not_affected`. The nearby-name keys of a CPE with no table row come from `ownNames`, so they gain the same mixes.
- `c008d85` fix(check): `CNANearKey` carries `VendorRanges`, the `cve_cpe_matches` range of every CPE vendor whose NVD rows the item reads, with the item's part: each vendor of the name table row's CPEs, or the CPE's own vendor with no table row. `checkCNANearSQL` in `internal/store/check.go` takes every key's ranges flat (`unnest($4::bigint[], $5::text[], $6::text[])`, each range with its key's 1-based position) and excludes a CVE with a `cve_cpe_matches` row in any range of its key, keeping the `COLLATE "C"` range comparisons. Before this, an `nginx:nginx` item was held at `cna_name_uncertain` on every F5 CVE with an `NGINX Plus` CNA row while `f5:nginx` answered for the same CVE. Both nginx spellings now share one nearby-name key.
- `1644687` refactor(check): `parseCPE` checks vendor and product for a literal value after dropping redundant escapes, so `\-` alone is `invalid_cpe`. `NamesFor` returns `(names, cpes, mapped)`; the nearby-name vendor and fragment come only from `nearbyNames`. Stale comments on `CPEKey`, `cnaTable` and the `TestNamesFor` case for a `ProductRef` holding `microsoft:\.net` were corrected.
- `a72bd84` fix(api): the 503 detail of `writeCheckFailure` says the check took too long or the request was cancelled, and to retry or split the items, without naming a time limit. The statement timeout (14 s by default) and `checkTimeout` (30 s) give the same 503.

## Decisions and gotchas

- Fix B extends design section 4.5's "no `cve_cpe_matches` row for the CPE's own vendor" to every vendor the item reads NVD rows under. The design's table already puts `f5:nginx` and `nginx:nginx` in one row; this only lifts nearby-name blocks (cannot evaluate), never adds a `not_affected` beyond what an NVD row under a vendor the item already reads supports.
- Fix B, key identity: `CNANearKey` holds a slice, so it cannot be a map key. `keyBuilder` de-duplicates it by `nearKeyID`, its fields joined by `"\x00"`, through `addByID`, which `add` now calls with the key as its own ID.
- Fix B, TDD: the store test `TestReadCheckCandidates_CNANearEverySpelling` compiled against the old key and failed for the reason under repair (each spelling returned the CVE analysed under the other's vendor). The `internal/check` tests need the new field, so they failed to compile first; the reviewer's overlay probe showed the behaviour (`not_affected` vs `cannot_evaluate` for one CVE), and a break test (ranges cut back to the item's own vendor) made `TestEvaluateNearbyLiftEverySpelling` fail with that same split.
- Fix B, index use was not checked with `EXPLAIN`: on test-sized tables the planner scans whatever it likes. The range predicates are the same expressions as before.
- Fix A's end-to-end test and fix B's use two test helpers in `evaluate_test.go`, `cnaStored` and `nearStored`, which place a stored CNA row at every key the store would return it from. Placing rows by hand at a named key cannot show a row that no key reads.
- Fix C, the `TestNamesFor` cases lost their vendor and fragment expectations; `TestNearbyNames` now covers every table row instead, including `nginx:nginx` reading the table's vendor `f5`.
- Fix C's `\-` change was committed under `refactor(check)` with the other clean-ups, as instructed, though it changes behaviour for that one input.
- Break tests: the clone in `NamesFor` (removing it fails `TestNamesForDoesNotShareTheTable`); fix B's vendor ranges (above). Each was restored by hand before the commit.

## Quality checks

- `go test ./internal/check/ -count=1 -v`: pass, 83 tests (624 with subtests).
- `go test ./internal/store/ -run 'ReadCheck|Check|Snapshot' -count=1 -v`: pass, 22 tests.
- `go test ./internal/api/ -run 'Check|OpenAPI' -count=1 -v`: pass, 32 tests (151 with subtests); also passed after fixes A and B together. No expectation in `internal/api/check_integration_test.go` changed.
- `golangci-lint run ./internal/check/... ./internal/store/... ./internal/api/...`: 0 issues.
- Full suite not run.
