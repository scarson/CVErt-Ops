# Check endpoint: a version that is not dotted numbers shares the product's floor

## What was built

`715df44` fix(check), on top of the CPE lookup floor (`2e5a57f`, log `2026-11-10T1148Z-check-cpe-lookup-one-read-per-product.md`). A request has one CPE key per product, whose floor is the lowest version asked of it, and the store leaves out rows whose ranges lie wholly below that floor (design sections 4.2 and 9 of `dev/plans/2026-11-08-version-check-endpoint-design.md`).

`2e5a57f` gave a key no floor as soon as one of its items had a version that was not dotted numbers, because such an advisory's reason came from its first row in sort order, which a count row cannot reproduce. The controller's end-to-end run on the `cvert_phase4` copy showed what that cost. A fleet of 10 LTS kernel versions was answered in 0.26 s. Adding one `6.8.0-45-generic`, the version `uname -r` prints, put all 11 items back at `too_many_candidates`.

- `internal/check/keys.go` `keyBuilder.addCPE`: the floor is the lowest dotted-number version among the key's items; other versions are passed over; no floor when there is none.
- `internal/check/cpe.go` `EvaluateCPERows`: for a version that is not dotted numbers, an advisory with rows, read or left out, answers CannotEvaluate with reason `invalid_version`, whatever row comes first. Count rows add NotAffected only for a dotted-number version.

## Decisions and gotchas

- This is the rule design section 4.2 already states ("An item version that is not dotted numbers is still cannot evaluate, reason `invalid_version`"). Before, the first row in sort order could give `no_version_bounds` or `invalid_range` instead. So the change alters only the reason for such items, and makes it independent of row order and of the floor.
- Equivalence: `TestEvaluateLeavingOutRowsBelowChangesNoAnswer` (`internal/check`) and the store equivalence test both compare filtered with unfiltered results. Their request that mixes dotted versions with a non-dotted one now carries a floor, and still matches.
- TDD order: the key and evaluation tests were changed first and failed (3 `TestKeysForCPEFloor` cases and the new `TestEvaluateRowsBelow` subtest). The `TestEvaluateCPERows` case "release candidate version is invalid_version whichever row comes first" was written after the code; it was shown to fail against the previous `cpe.go` through `go test -overlay`.

## Measured (`cvert_phase4` copy, serve at `715df44`, full suite running alongside)

- 10 LTS kernel versions: HTTP 200, 0.77 s. The same 10 plus `6.8.0-45-generic`: HTTP 200, 0.62 s, and the 10 answers are identical to those without it. `6.8.0-45-generic` itself answers cannot evaluate, `invalid_version`, on all 2,063 advisories.
- 500 items over the 10 largest products: HTTP 200, 3.94 s (1.9 s at `12bb16e` with nothing running alongside). 50 Firefox versions: 0.49 s.

## Quality checks

- `go test ./internal/check/ ./internal/version/ -count=1`: pass.
- `go test ./internal/store/ -run 'ReadCheck|Check|Snapshot' -count=1`: pass.
- `go test ./internal/api/ -run Check -count=1`: pass.
- `golangci-lint run ./internal/check/... ./internal/store/... ./internal/version/...`: 0 issues.
- Full suite: `go test ./... -count=1 -timeout=600s` passed at `715df44` (39 packages, 0 failures).
