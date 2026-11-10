# Check package: item status, feeds and the response

## What was built

- Task 3.8 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `a6a97ce`.
- `internal/check/keys.go`: `Keys`, `Candidates`, `KeyRows[T]`, `CNANearRow`, and `KeysFor(items)`. Keys are distinct across the request, in the order items first use them. The unexported `keysWithUses` also returns, per item, the index of each key it uses; `Evaluate` rebuilds it from the same items, so the store's `Candidates` and the evaluation agree on positions.
- `internal/check/feeds.go`: `FeedRow`, `FeedStatus` and `FeedStatuses(rows, now)`. A feed is complete when its cursor shows a finished walk (GHSA `since` non-empty, OSV `last_modified` a non-zero time, NVD `caught_up` true) and its last success is no more than 7 days before `now`. `ghsa`, `osv` and `nvd` are always in the map. `feedsFor(item)` gives the design section 5 dependencies.
- `internal/check/advisory.go`: `CVEEnrichment`, `CVEIDsFor`, the KEV and EPSS rule over `cve_ids`, and the listing order (Affected, KEV, CVSS v3, EPSS, `advisory_id`).
- `internal/check/results.go`: the response types with design section 11's JSON names, and the status and verdict values.
- `internal/check/evaluate.go`: `Evaluate`, `EvaluateWithLimits` and `DefaultLimits` (50,000 rows per item, 1,000 ranges per advisory). Per item: the row limit, grouping by CVE, retraction, the range limit before any reading, `Combine` of primary and CNA rows, the row-level nearby-name rule, `PickFix`, the 100-advisory and 20-range caps, and the item status by design section 4.7.
- `PackageRow`, `CPERow` and `CNARow` gained `Status` (the CVE's `cves.status`). `ItemError` gained JSON tags `code` and `message`.

## Decisions and gotchas

- `Evaluate` refuses `Candidates` whose slices do not have one entry per key of `KeysFor(items)`. Reading a missing key as no rows could answer "not affected".
- CNA name rows are de-duplicated by CVE, vendor, product and the JSON of `versions`, because one stored row comes back through an exact name and a prefix (`microsoft:.net_core` reads `.NET Core` through both `.net core` and `.net `). The item row limit counts rows before de-duplication, as the design counts every key.
- The nearby-name rule overrides any verdict except Affected, including `too_many_ranges`.
- Identical items (same parsed package or product and version) share one evaluation. A cached result's advisory slices are shared between the two results.
- An invalid item reports `data_complete: false`. It depends on no feed and is left out of the top-level `feeds` and `data_complete`.
- An advisory that cannot be evaluated with no reason would get a null `reason` rather than `""`. Every `version.Check` error wraps one of the three sentinels, so this does not happen today.
- `MatchedRange` omits `cpe`, `fixed` and `last_affected` when empty, which matches the design example.
- `nextPrefix` skips the UTF-16 surrogate range and carries past `U+10FFFF`. A test checks every prefix in the CNA name table gives an interval that holds it.

## Quality checks

- The tests were written first. With the types in place and empty function bodies, all 30 new top-level tests failed on their assertions. The existing tests still passed.
- Break test (from the plan's Verify-first note): `workMeter.Err` returning only `m.err` fails `TestEvaluateCancelledBeforeOneRow` (nil error, results returned). Restored with `git checkout`, then the test passes.
- Break test (from the plan's Verify-first note): dropping nearby rows by CVE alone fails `TestEvaluateCNANameUncertain` (`.NET 9.0` with `Microsoft .NET Runtime` answers `cna_cannot_clear`). Restored, then the test passes.
- `go test ./internal/check/ -count=1`: pass, 69 top-level tests (559 with subtests).
- `golangci-lint run ./internal/check/...`: 0 issues, after a tagged switch in `nextPrefix` and a De Morgan rewrite in a test.
