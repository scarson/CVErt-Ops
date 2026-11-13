# Version check: distros whose feeds list fixes only are never cleared

## What was done

Sam decided that items in distributions whose feeds record issued fixes only should not answer `not_affected`. The rows of such a distribution cannot show a vulnerability it has not fixed, so a clean result there only means "no published fix is missing".

- `ecosystem.ListsFixesOnly` reports a distro not in `listsUnfixed`, the distros measured to store unfixed ranges.
- `setStatus` in `internal/check/evaluate.go` answers `unresolved` with the new item reason `distro_lists_fixes_only` where such an item would answer `not_affected`. The rule sits after every other `unresolved` and `cannot_evaluate` rule. A version below a published fix still answers `affected`, so a missing erratum is still reported.
- API: the reason enum and its description, and the status description. `openapi.json` and `web/src/lib/api/schema.d.ts` were regenerated.
- Docs: design sections 4.7 (status table), 6 (the measured list) and 11 (reason enumeration); `PLAN.md`'s endpoint summary; the Red Hat states proposal, whose option A this is.

## Decisions and gotchas

- **Measured over every distro, not six.** The earlier count covered nine distros. Over all 19 on the full ingest, eleven store no unfixed row: AlmaLinux, Alpine, Azure Linux, Mageia, Red Hat, Red Hat Lightwell, Rocky Linux, SUSE, TuxCare, openEuler and openSUSE. Alpaquita, BellSoft Hardened Containers, Chainguard, Debian, Echo, MinimOS, Ubuntu and Wolfi store some.
- **The list names the distros that record unfixed vulnerabilities, not the fix-only ones.** A distribution added to `distros` later is then fixes-only until its data is measured, which fails towards "not cleared". A test checks every entry of `listsUnfixed` is a distro name, since a misspelt entry would silently leave its distro fixes-only.
- An advisory that cannot be evaluated still gives `unresolved` with reason null, as before: its own reason explains it.

## Quality checks

- New unit cases in `TestEvaluateItemStatus`, covering Red Hat and Alpine items: clean answers unresolved, below a fix answers affected, a failing advisory keeps reason null, and `data_incomplete` wins. There is also `TestListsFixesOnly`. Both failed before the rule.
- New integration subtest `TestCheckIntegration_TargetedPatches/Distros_whose_feeds_list_fixes_only`, through the API on merged rows: Red Hat clean answers unresolved, below a fix answers affected, and Debian clean answers not_affected. A break test with the rule disabled failed it.
- `go test ./internal/ecosystem/ ./internal/check/` and `./internal/api/ -run 'Check|OpenAPI'`: pass.
