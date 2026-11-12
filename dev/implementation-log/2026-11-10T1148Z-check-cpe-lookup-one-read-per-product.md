# Check endpoint: one CPE read per product, floor = the lowest version asked

## What was built

Commit `2e5a57f`, a rework of `08b6595` (log `2026-11-10T1129Z-check-cpe-lookup-leaves-rows-below-the-version-unread.md`), which gave each item its own CPE key with a floor of two version components. The controller timed that form end to end: every distinct floor read the whole product and returned its own count rows, so 50 Firefox versions took 4.7 s, and 500 heavy items and 300 kernel versions answered HTTP 422 `candidate_limit_exceeded`, where the code before the rule answered 200.

- `internal/check/keys.go`: a request has one `CPEKey` per product again. `Floor` is the lowest version among the request's items of the product (`keyBuilder.addCPE`, by `version.NumericOrder`), or "" as soon as one of them is not dotted numbers. `versionFloor` is gone.
- `internal/store/check.go`: stored rows and CVE count rows share one `LIMIT` per key.
- Design sections 4.2 and 9 and the plan's Deviations and Phase 4 note are corrected.

## Decisions and gotchas

- **Why the lowest version, and not one key per major or a few keys per product.** Any floor at or below an item's version is sound, because a row below the floor answers Not affected for every version at or above it. With one key per product the read count is what it was before the rule, and with the shared `LIMIT` a key never returns more rows than before the rule, so no request can newly pass a limit. Keys per major, or up to N keys per product, read a product several times and return its count rows several times, so neither bound holds.
- **The price.** What a key returns depends on the request's other items of the product. An old version beside new ones (300 kernel versions from `2.0.0`), or one version that is not dotted numbers (`6.8.0-45-generic`), makes the read as large as before the rule; if it passes 50,000 rows, every item of that product answers `too_many_candidates`, which is what all of them answered before the rule. An item can be answered in one request and refused in another. The verdicts of an answered item never differ.
- **A version that is not dotted numbers cannot use a floored read.** Its advisories are all cannot evaluate, but the reason of each comes from its first row in stored order (`no_version_bounds`, `invalid_range` or `invalid_version`), which a count row does not keep.
- **The floor is the whole lowest version, not its first two components.** Cutting it bought shared reads between keys, which one key per product no longer needs. Kernel `2.6.32` asked alone now reads 34,782 rows and is answered.
- **Row order.** Neither form of the CPE statement has an `ORDER BY`, and the two forms need not return an advisory's rows in the same order. `Outcome.Reason` is the first row's that cannot be compared and `matched_ranges` follow row order, so `evaluateAdvisory` now sorts an advisory's CPE rows (`compareCPERows`: CPE, then the four bounds) before evaluating. This makes the order deterministic; it was the scan's order before. On the four measured requests no response changed.
- **From the independent review of `08b6595`** (0 mismatches between the SQL and Go rules over 228,276 real rows and 23 floors): the cost per floor and the doubled `LIMIT` are fixed by this rework; a 257-byte dotted bound (`1.` and 255 zeros) and a CPE with an escaped colon in its vendor are added to the store tests, and each was checked to fail under the mutant the review named (`<= 300` in `LeadingSQL`; splitting without escape handling); the JIT comment on `withOrgSnapshotTx` no longer repeats timings.
- **Not changed, found by the 300-kernel run:** `evaluateItem` groups all rows of an item's keys before it looks at their overflow flags (5.1 GiB allocated for 300 refused items, before and after). Recorded in the plan's Discoveries.

## Measured end to end (`serve` on `cvert_phase4`, ports 18081 and 19091; before is the `6ef031b` binary)

| Request | Before | After |
|---|---|---|
| 1 kernel item `6.12.0` | 200, 0.13 s, 57 MiB, `too_many_candidates` | 200, 0.25 to 0.34 s, 4 MiB, answered |
| 50 Firefox items `140.0.0` to `140.49.0` | 200, 4.5 s, 2.7 GiB | 200, 0.20 to 0.24 s, 29 MiB |
| 500 items, 10 large products | 200, 19.3 s, 11.4 GiB | 200, 1.7 to 2.0 s, 1.1 GiB |
| 300 kernel items `2.0.0` to `6.59.0` | 200, 2.0 s, 5.1 GiB, all `too_many_candidates` | 200, 2.0 to 2.2 s, 5.4 GiB, all `too_many_candidates` |
| 500 Opera items `100.0` to `599.0` (the review's case: about 21 s of database time with one key per floor) | not measured | 200, 0.11 s, 41 MiB |

The response bodies of the two binaries were compared item by item: all 851 items are equal in every field except the one kernel item that was over its limit before. The first form (`506f0c5`) answered the same for the Firefox and single-kernel requests.

## Quality checks

- `go test ./internal/version/ ./internal/check/ -count=1`: pass. `TestKeysForCPEFloor` (8 cases) failed on the previous key builder; `TestEvaluateLeavingOutRowsBelowChangesNoAnswer` now evaluates 19 requests (each version alone, four of several versions, one with a version that is not dotted numbers).
- `go test ./internal/store/ -run 'ReadCheck|Check|Snapshot' -count=1`: pass. `TestReadCheckCandidates_CPERowsBelowNeverReadMore` failed before the shared `LIMIT` (8 rows read against a request limit of 4). New: `TestReadCheckCandidates_CPERowsBelowEscapedColon`. In `internal/check`, `TestEvaluateCPERowsInOneOrder` failed before the sort.
- `go test ./internal/api/ -run Check -count=1`: pass.
- `golangci-lint run ./internal/check/... ./internal/store/... ./internal/version/...`: 0 issues.
- The full suite was not run; the controller runs it.
