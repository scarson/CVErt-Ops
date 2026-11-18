# Version check: the `unresolved` status, both Ubuntu streams, and the go/no-go fixes

## What was done

The Phase 4 go/no-go run (`2026-11-12T1030Z-version-check-go-no-go-run.md`) found every current release of Node, PHP, .NET, nginx, OpenSSL and PostgreSQL at `cannot_evaluate` with no advisory Affected. Sam asked for two independent reviews of the options (one Claude Fable 5.2 at high effort, one Codex at high effort), kept open for discussion, with the consensus to be built. Five discussion rounds and several measurements on the copy of the complete ingest reached consensus on every point. Design sections 4.3, 4.5, 4.7, 6, 9, 11, 12 and 15 of `dev/plans/2026-11-08-version-check-endpoint-design.md` record the result. This commit builds it:

- **Item status `unresolved`** for "no advisory was established as affected, and the data leaves one or more advisories unresolved". `cannot_evaluate` now means the check could not be completed: the item's version (`invalid_version`, `unknown_version_scheme`, the new `sdk_version_not_comparable`, or a row's `invalid_version` with a null item reason), `too_many_ranges`, the new `evaluation_failed`, `data_incomplete` (now also with no advisory), the new `distro_stream_incomplete`, and `cna_product_not_mapped` (when an advisory was found). The order only ever moves an item away from `not_affected`.
- **Failure flags per advisory** (`Outcome.VersionFailure`, `Outcome.EvaluationFailed`), kept apart from the reason the advisory shows. An advisory over the range limit keeps `too_many_ranges` over the nearby-name rule. An advisory that cannot be evaluated with no reason gets `evaluation_failed`, logged at error level.
- **`counts.cannot_evaluate_by_reason`**, over every advisory before the listing limit.
- **Ubuntu streams**: an item for a release's standard or plain Pro stream reads both (`ecosystem.ReleaseStreams`). Matched package ranges report their `ecosystem`, and advisories report `fix_ecosystem`. Pro sub-streams (`ecosystem.IsSubStream`) are never cleared.
- **.NET SDK numbers**: a `.NET` item whose third version component is 100 or more is not cleared by runtime-numbered ranges.
- **Name table**: `nodejs:nodejs` and `f5:nginx_open_source` added. The .NET Framework, OpenAPI.NET and Ruby's OpenSSL extension are other products (`otherProducts` in `names.go`) and neither name nor block the item.
- **CNA suffix bounds**: a `custom` entry with no changes and a bound such as `1.1.1t` says nothing about a version the leading-number rule places outside it (`outsideSuffixBounds`).
- **Check slots** from 4 to 1, until peak memory per check is measured.

## Decisions and gotchas

- **Measurements that changed the proposal.** Ubuntu almost never repeats a row in both streams (70 of 2,687,259 standard rows have a Pro counterpart), so the Pro stream alone is also a wrong "not affected"; the proposed "skip Pro when a standard row exists" was dropped. The FIPS and Realtime sub-streams miss standard USNs for their own packages (USN-8847-1 for `openssl` under `FIPS-updates:22.04`). 25 of the 27 nginx `cna_cannot_clear` advisories had NVD rows under `f5:nginx_open_source`, which the table lacked. Every NVD `.net` bound is runtime-numbered. The 48 `cna_name_uncertain` advisories came mostly from the .NET Framework and ASP.NET Core, not Visual Studio (which does not contain the fragment `.net`), and ASP.NET Core ships inside the SDK, so it was not excluded.
- **The earlier Pro-only total was too high.** 34,326 records counted the FIPS and Realtime sub-streams, which have no standard counterpart by construction. The plain-stream figure is 27,145 `UBUNTU-CVE-*` records. The plan's Discoveries entry is corrected in the next commit.
- **OpenSSL `1.1.1w`** answered `invalid_version` on 322 of its 328 advisories, not all of them (5 `cna_indeterminate`, 1 `cna_name_uncertain`); it now answers item-level `invalid_version`.
- **Not built**, with counterexamples in design section 15: clearing on unreadable CNA entries above every number they mention, loosening `cna_cannot_clear`, splitting `cna_cannot_clear`, and the rule that a nearby row does not block when the CVE has a name row.
- `Counts` now holds a map, so it is no longer comparable with `!=`; tests compare totals through a `countsOf` helper.
- The forced `evaluation_failed` test passes a logger to `withFailureReason` and asserts the line, so test output stays clean.

## Quality checks

- `go test ./internal/check/ ./internal/ecosystem/`: pass. Break tests: each of the four Ubuntu union tests fails with the union removed; each of eight status-rule mutations (nearby over range limit, counts by reason, the empty-reason fallback, the item-version slot, the sub-stream rule, the SDK rule, the unmapped rule at zero advisories, the row version-failure slot) is caught.
- `go test ./internal/store/ -run Check` and `go test ./internal/api/ -run 'Check|OpenAPI'`: pass.
- `golangci-lint run --allow-parallel-runners` (v2.15.0) on the changed packages: 0 issues.
- `openapi.json` and `web/src/lib/api/schema.d.ts` regenerated.
