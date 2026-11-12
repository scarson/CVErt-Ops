# Check package: combining sources and CNA names

## What was built

- Task 3.6 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `ac983d0`.
- `internal/check/combine.go`: `Combine(primary, hasPrimaryRows, cna)`, design section 4.4's five steps for one advisory: Affected if either source reports Affected; else the primary's CannotEvaluate reason when it has rows; else `cna_indeterminate` for an Indeterminate CNA reading; else NotAffected when the primary rows were compared and all report Not affected; else `cna_cannot_clear`. The primary is NVD CPE rows for a CPE item and package rows for a package item (design section 4.6).
- `internal/check/names.go`: `CNAName`, `cnaMapping`, the `cnaNames` table of design section 4.5, `NamesFor(ProductRef)` and `CNAName.Matches(vendor, product)`.

## Decisions and gotchas

- An Affected result lists the primary's `Matched` and `Candidates` first, then the CNA's, in fresh slices (`slices.Concat`), so the combined outcome never shares storage with the primary's. `Ranges` and `Comparable` are always the primary's; fix validation (Task 3.7) re-reads the CNA entries.
- Step 4 also requires `primary.Comparable`. `rowVerdicts` never returns NotAffected without a compared row, but a NotAffected outcome that compared nothing is not evidence, so it falls to `cna_cannot_clear` rather than clearing.
- The CPE's own name is plain text: each CPE escape becomes the character it quotes (`foo\:bar` becomes `foo:bar`), and an unescaped `_` becomes a space. An escaped `\_` stays an underscore. The table key is the CPE's spelling as `ProductRef` holds it, escapes kept, so `microsoft:\.net` finds its own name but no table row (mapped false), which leads to `cna_product_not_mapped` or `cna_name_uncertain`, never a clean answer.
- `f5:nginx` is the one product whose own name equals a table name; it is listed once.
- `NamesFor` returns a copy of the table row's `Names`, because `f5:nginx` and `nginx:nginx` (and the two .NET keys) share one mapping.
- `Matches` compares with `strings.ToLower` on both sides, not `strings.EqualFold`, to agree with the SQL `lower()` lookup; `EqualFold` folds some characters differently (U+0130). staticcheck SA6005 is suppressed inline with that reason.
- The design's `.net ` prefix also matches `.NET Framework 4.8`, so .NET Framework CNA rows are read as .NET rows. Their versions are 4.x, so they bear only on 4.x versions. A test documents this.
- revive's `unexported-return` is not enabled in `.golangci.yml`, so `NamesFor` returns the unexported `cnaMapping` as the plan writes it.

## Quality checks

- Combine tests failed first against a stub returning the zero `Outcome`; names tests against a stub returning nothing. Break tests: removing the `Comparable` guard, the `hasPrimaryRows` guard on step 4, prefix matching and case folding each fail a named test.
- `go test ./internal/check/ -count=1`: pass. The task's tests: 25 Combine and 25 names tests and subtests passing, 0 failures.
- `golangci-lint run ./internal/check/...`: 0 issues.
