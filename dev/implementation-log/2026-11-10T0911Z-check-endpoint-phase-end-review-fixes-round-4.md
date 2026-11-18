# Check endpoint phase-end review fixes, round 4

## What was built

Two commits from the fourth round of Phase 3 phase-end reviews of `POST /api/v1/orgs/{org_id}/check`, the version check endpoint of `dev/plans/2026-11-09-version-check-endpoint-plan.md`. Both concern `checkCNANearSQL` in `internal/store/check.go`, the nearby-name lookup (design section 4.5: CNA rows near a product's name, on CVEs with no NVD row under a vendor the item reads).

- `238ba4b` test(store): `TestReadCheckCandidates_CNANearOwnRanges` in `internal/store/check_test.go` reads two nearby-name keys (nodejs, acme) in one request. CVE-2026-90047 has a CNA row `NodeJS` / `Node.js runtime` and an NVD row only under `a:acme:gizmo`; CVE-2026-90048 is the mirror (`Acme` / `Gizmo Pro`, NVD row under `a:nodejs:npm`). Each key must return its own CVE. No store test failed when the statement ignored which key a vendor range belongs to, which would let one item's ranges lift another item's nearby rows and give a wrong `not_affected`.
- `86d5578` fix(store): each nearby-name key carries its own vendor ranges in its own `unnest` row: `$4` and `$5` hold, per key, the range lows and the range highs joined by `rangeSeparator` (`"\x1f"`), and the `NOT EXISTS` probe reads `unnest(string_to_array(k.los, chr(31)), string_to_array(k.his, chr(31))) AS r(lo, hi)` joined to `cve_cpe_matches` on `cve_id` and the `COLLATE "C"` range. Before this, the ranges of every key were passed as one flat list with each key's position, and each candidate CNA row scanned the whole list.

## Decisions and gotchas

- The separator is safe because no range bound can hold it: `parseCPE` takes only printable ASCII (`internal/check/input.go`) and the name table's CPEs are lower-case text, the same argument `nearKeyID` makes for `"\x00"`. A key with no vendor ranges gets `""`, which `string_to_array` turns into an empty array, so nothing lifts its rows (the safe direction). The number of ranges per key is not capped.
- Mutation check for the test: an overlay `check.go` with `WHERE r.key_ord = k.ord` replaced by `WHERE true` (the reviewer's `check_nokeyord.go`) fails `TestReadCheckCandidates_CNANearOwnRanges` (both keys return no rows) and passes the other two `CNANear` tests; the committed code passes all three.
- Cost, measured with an overlay probe (not committed) on the reviewer's data: 200,000 unrelated CNA rows, 20,000 `Acme` / `Widget n` rows with three `cve_cpe_matches` rows each under other vendors, one busy key plus R-1 idle keys, `EXPLAIN ANALYZE` execution time.

  | R | one range per key, before `c008d85` | flat ranges (`c008d85`) | per-key ranges, without the `cves` join | per-key ranges, statement as committed |
  |---|---|---|---|---|
  | 1 | 41 ms (reviewer: 40) | 43 ms (reviewer: 45) | 58 ms | 80 ms |
  | 501 | 37 ms (reviewer: 39) | 441 ms (reviewer: 441) | 58 ms | 111 ms |
  | 2000 | 47 ms (reviewer: 46) | 1,516 ms (reviewer: 2,208) | 78 ms | 121 ms |

  The first two columns and the reviewer's figures leave out the `LEFT JOIN cves`, which adds one `cves_pkey` probe per row (20-50 ms here). The per-key plan runs one `cve_cpe_matches_cve_id_idx` scan per candidate row (loops=20000) whatever R is; the `cve_id` index scan sits under a `Materialize`, so a key with several ranges still probes the index once per row (with three ranges: 59,600 range rows, 20,000 index scans, 100 ms). The cost over one range per key, about 15-30 ms per 20,000 rows, is `string_to_array` and the function scan per row.

## Quality checks

- `go test ./internal/store/ -run 'ReadCheck|Check|Snapshot' -count=1 -v`: pass, 23 tests.
- `go test ./internal/api/ -run 'Check' -count=1 -v`: pass, 19 tests (82 with subtests).
- `golangci-lint run ./internal/store/...`: 0 issues.
- Full suite not run.
