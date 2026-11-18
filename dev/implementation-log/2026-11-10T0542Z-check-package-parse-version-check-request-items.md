# Check package: parse version check request items

## What was built

- Task 3.2 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `a9f86cf`.
- New package `internal/check` (`doc.go`: pure verdict code for the endpoint, no database).
- `check.ParseItem(index, RawItem) Item` resolves one request item to a `PackageRef` (canonical ecosystem, name as given) or a `ProductRef` (lower-cased CPE part, vendor, product, escapes kept), and the version to compare. A refused item carries an `ItemError` with a code from design section 11's `error.code` enumeration and a fixed message that never repeats the caller's input.
- `splitCPE` splits a CPE 2.3 formatted string on unescaped colons, keeping escapes. Task 3.4 reuses it to read a stored CPE's version component.

## Decisions and gotchas

- Order of checks: every raw field's length (in characters, design section 3.4) and characters first, then the form, then the form's rules. `ecosystem` has no length limit of its own; `ecosystem.Valid` caps it.
- `invalid_characters` covers control characters (`unicode.IsControl`, including NUL, DEL and C1) and invalid UTF-8. JSON decoding replaces invalid UTF-8, so the UTF-8 check guards direct callers; PostgreSQL rejects both in a query parameter.
- `Item.ID` is echoed only when the id itself passes its checks, so a bad id is never echoed.
- Exactly one form: `purl` alone, `ecosystem` with `name` (and `version`), or `cpe` (with optional `version`). Anything else is `invalid_form`.
- A request purl with `download_url` or `vcs_url` is refused as `unsupported_repository` inside `ParseItem`, before `ecosystem.FromPurl`, which stays as it is for stored CNA package URLs. packageurl-go lower-cases qualifier keys, so `DOWNLOAD_URL` is caught too.
- CPE version: the CPE's own version counts as stated unless it is `*`, `-` or empty. Treating `-` (NA) as "no version stated" was a controller choice. One leading `v`/`V` before a digit is removed from both versions, in CPE form only. The two versions are compared case-insensitively, because the CPE string is lower-cased and the `version` field is not; the `version` field is used as given when both are stated.
- `PackageRef.Name` is not folded here; Task 3.8 folds it when it builds lookup keys.

## Quality checks

- The tests failed first against a stub `ParseItem` and `splitCPE` (103 failing tests and subtests).
- `go test ./internal/check/ -count=1 -v`: 6 top-level tests, 110 passing tests and subtests, 0 failures.
- `golangci-lint run ./internal/check/...`: 0 issues.
