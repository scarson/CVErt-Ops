# Check endpoint: NVD bounds that are not dotted numbers

## What was built

Two commits: `6ef031b` (the rule) and `4300c7c` (fixes from an independent review).

`6ef031b` feat(check): `version.CheckProduct` (`internal/version/product.go`) replaces `version.CheckNumeric` for NVD `cve_cpe_matches` rows in `internal/check/cpe.go` (`EvaluateCPERows`). Design section 4.2 of `dev/plans/2026-11-08-version-check-endpoint-design.md` is amended with the rule ("Bounds that are not dotted numbers"), which Sam chose on 2026-11-10 after the Phase 4 provisional measurement in `dev/plans/2026-11-09-version-check-endpoint-plan.md`.

The measurement showed old NVD rows naming exact releases such as `php:2.0b10` or bounds such as OpenSSL `1.0.2zf` answering `invalid_range`, which held Node, PHP, OpenSSL and PostgreSQL items at `cannot_evaluate` at every version. `CheckProduct`:

- requires a dotted-number item version (`invalid_version` otherwise, as before);
- delegates to `CheckNumeric` when every bound is dotted numbers, so those rows answer exactly as before;
- otherwise compares a bound by its leading dotted numbers (`leadingOrder`), and the order counts only at the first component both leading parts have where they differ;
- never compares a bound with no leading digit, over 256 characters, or whose suffix starts with an epoch separator (`:` or `!`, plain or CPE-escaped);
- when the range's own two bounds have no decided order (`[1.0.2, 1.0.2zf)`, or an exact release), answers Not affected only when the version is decided below both or above both (`outsideBoth`), and never Affected.

## Decisions and gotchas

- The rule applies to NVD rows only. CNA free text such as `0.5.6 - 1.13.2` starts with digits too, and read by leading numbers would be taken as one version, so CNA versions keep design section 4.3's rules.
- A suffixed fixed bound gives no `fixed_version`: `PickFix` orders candidates with `NumericOrder`, which cannot read `1.0.2zf`, so no fix is reported. No change was needed in `internal/check/fix.go`.
- Undecided bound order: `validateRange` refuses inverted numeric ranges because an inverted range would read every version as not affected. With bounds that share their leading numbers the inversion cannot be detected, so such a row may only answer Not affected for a version outside both bounds, which is right whichever way the range runs.

## Independent review of `6ef031b`

A reviewer looked for wrong Not affected answers with probes and overlay mutants. `4300c7c` fixes what it found:

- CPE 2.3 wildcards in a bound answered Not affected: `10.0` against exact `1*`, `1.05` against `1.0*` or `1.0?`. An unescaped `*` or `?` now makes a bound not comparable (`hasWildcard`). Neither a wildcard nor `%` occurs in any version or bound of the partial ingest (1,215,035 CPE rows), so this is a guard, not a measured case.
- A URI-encoded epoch (`1%3a2.4`) escaped the epoch check; a bound holding `%` is no longer compared.
- An exclusive range on one suffixed value (`[1.0b1, 1.0b1)`) answered Not affected, where `CheckNumeric` refuses `[2.0, 2.0)`. Identical strings are now equal in `leadingOrder`, so the empty range is `invalid_range`.
- Test gaps: digit components of different lengths and with leading zeros (a plain string comparison passed every test and gave `9.0` in `[1.0, 10.0a)` Not affected), and a version decided between two bounds whose order is undecided (`1.0.1` in `[1.0, 1.0.2zf)`, cannot evaluate). The design said such a version could not occur; it is corrected.
- Not changed: a plain-field `1\\:2.4` epoch spelling (not plausible in NVD JSON), and a wrong Affected when the bound's scheme differs from the item's (`8u151`), which the numeric rule already had.

## Measured effect (copy of the partial ingest, uncapped measurement build)

| Item | Before (`6fdc2bb`) cannot evaluate / not affected | After (`6ef031b`) |
|---|---|---|
| Node `24.22.0` | 5 `invalid_range` / 46 | 0 / 51 (item `data_incomplete` until NVD finishes) |
| PHP `8.4.14` | 57 / 539 | 5 / 591 (1 `invalid_range`: CVE-2006-3017) |
| OpenSSL `3.5.4` | 167 / 20 | 10 / 177 (9 `cna_indeterminate`, 1 `cna_name_uncertain`) |
| PostgreSQL `18.1` | 5 / 97 | 4 / 98 (3 `cna_indeterminate`, 1 `no_version_bounds`) |

What still holds these items is CNA free text from 2011 to 2018 (`5.6.x before 5.6.1`, `through 1.6.2`, `Fixed in OpenSSL 1.1.0h (Affected 1.1.0-1.1.0g)`), which design section 15 keeps at cannot evaluate when NVD says Not affected.

## Quality checks

- `go test ./internal/version/ ./internal/check/ -count=1`: pass. New: `TestCheckProduct` (45 cases after `4300c7c`), `TestCheckProduct_NumericBoundsMatchCheckNumeric`, four `TestEvaluateCPERows` cases. The new behaviour cases failed before each change.
- `go test ./internal/api/ -run 'Check' -count=1`: pass at `6ef031b`.
- `golangci-lint run ./internal/check/... ./internal/version/...`: 0 issues at `4300c7c`.
