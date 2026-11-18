# Version package: SemVer checks, orderings and a shared range grammar

## What was built

- Task 3.1 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `74b5011`.
- `version.CheckSemver(version, r)` checks a range typed `SEMVER` as SemVer in any ecosystem (design section 4.1). It uses the same gate as `Check` for npm: length limit, not a git commit hash, `semverSyntax`. It compares through npm's ordering, so it shares the range validation of `scheme.check`. `1.2.3-1ubuntu1` reads as a SemVer prerelease of `1.2.3`.
- `version.Order` is a comparison that returns an error when either side cannot be read under its syntax gate. `NumericOrder` (the order of `CheckNumeric`), `SemverOrder` (the order of `CheckSemver`) and `EcosystemOrder(ecosystem)` (a closure over `Compare`, nil for an ecosystem `lookupEcosystem` refuses, such as `Root:x` or `""`) give the CNA reader one ordering per `versionType` (design section 4.3).
- `version.ParseRangeExpression(ecosystem, raw, firstPatched)` holds the GHSA range grammar (`rangeConstraint`, `zeroVersion` and the parser body, with their explanatory comment). `ghsa.parseVulnerableRange` converts its result to `rangeBounds` in one line.

## Decisions and gotchas

- `scheme` gained an `order` method that validates both sides and compares. `Compare` now uses it through a helper, `ecosystemScheme`, which `Check` also uses, so the ecosystem gate is written once. `Compare`'s errors are unchanged (`ErrInvalidVersion: "<value>"`).
- The parsing cases moved from `internal/feed/ghsa/range_test.go` to `internal/version/constraint_test.go`. The GHSA test keeps five cases that show the conversion and that the ecosystem is passed through, and `TestBoundsEvents` stays as it was.
- With an empty ecosystem, `Compare` errors, so the first patched version never shortens a declared bound. Tests pin `>= 20.0.0, <= 20.10.27` with no ecosystem as `{Introduced: 20.0.0, LastAffected: 20.10.27}`, and the hyphen form `0.5.6 - 1.13.2` as unparsed.
- `gofmt -l` lists untouched files in this checkout because they are CRLF in the working copy. That is the checkout's line endings, not a formatting fault.

## Quality checks

- The new tests failed first on the missing functions (build failure: undefined `ParseRangeExpression`, `CheckSemver`, `SemverOrder` and the rest).
- `go test ./internal/version/ ./internal/feed/ghsa/ -count=1 -v`: both packages pass, 47 top-level tests, 0 failures.
- `golangci-lint run ./internal/version/... ./internal/feed/ghsa/...`: 0 issues.
