# internal/version checks versions against affected ranges

## What was built

- `version.Check(ecosystem, version, Range)` orders versions by the named OSV ecosystem's own rules, for npm, Go, crates.io, Hex, Pub, NuGet, PyPI, Maven, Packagist, RubyGems, Debian, Ubuntu, Alpine and Red Hat.
- `version.CheckNumeric(version, Range)` covers products with no ecosystem, such as CPE products: dotted numeric versions compare numerically and anything else cannot be evaluated.
- Both return `Affected`, `NotAffected` or `CannotEvaluate`. The error is non-nil exactly when the status is `CannotEvaluate` and wraps `ErrUnknownEcosystem`, `ErrInvalidVersion` or `ErrInvalidRange`.
- A depguard rule in `.golangci.yml` stops any other package importing `github.com/google/osv-scalibr`.

No caller exists yet. The version check endpoint is not built, and watchlists and the DSL have no version fields.

## Key decisions

- **`internal/version` holds its own syntax check for each ecosystem.** `semantic.Parse` accepts nearly any string and sorts it above or below every real version, so a parse result cannot show a string was a version. PyPI needed the full PEP 440 pattern, because anything else that starts with a digit, such as `1.0-foo`, becomes a "legacy" version below all others.
- **`CannotEvaluate` is the zero value of `Status`**, so an unset status never reads as "not affected".
- **`introduced: "0"` is not compared.** `0~rc1`, `0.0.0-alpha`, `0.dev1` and `0-alpha` all sort below a literal `0`, and the OSV schema defines it as "before every version".
- **A range with no upper bound reports `CannotEvaluate`.** OSV defines that shape as "affected from introduced onwards", but the GHSA adapter stores `Introduced: "0", Fixed: ""` whenever an advisory has no patched version, whatever its real upper limit is. A stored row cannot tell the two apart. Allowing open-ended ranges is worth revisiting once ranges are stored with their original events.
- **A range missing `introduced`, an inverted range, and `fixed` equal to `introduced` report `CannotEvaluate`.** An inverted range contains no version, so evaluating it would report everything as not affected.
- **Ecosystem names match exactly.** GHSA's `pip`, `go`, `maven` and `rust` report "cannot evaluate" until stored names are normalised, which is separate work. A release suffix is accepted only for distributions, so `Ubuntu:26.04:LTS` works and `npm:foo` does not.
- **Only the fourteen ecosystems with tested orderings are listed.** `semantic` also parses Rocky Linux, AlmaLinux, SUSE, Wolfi and others, which report "cannot evaluate" until each is added with its own tests.
- **Commit hashes are rejected explicitly.** OSV `GIT` ranges hold full hashes, and one that starts with a digit passes the looser patterns.

## Gotchas

- `NotAffected` applies to one range only. An advisory can have several, so a caller must check all of them.
- GHSA stores `Introduced: "0"` even when the real range starts later, such as `>= 1.0, < 1.2.3`. A version below 1.0 therefore reports `Affected`: a false positive, in the safe direction.
- `semver` compares a fourth component as a pre-release, so `1.2.3.4` sorts below `1.2.3`. The semver syntax check allows three numeric components; NuGet, which has its own comparator, allows four.

## Quality checks

- All 449 tests and subtests in `internal/version` pass: `go test ./internal/version/ -count=1`. Before the implementation, 406 of them failed against a stub. No database or Docker is needed.
- 30 mutations of the validation and comparison logic all made the tests fail, including removing each syntax gate, comparing `introduced: "0"` literally, swapping bound inclusivity and accepting inverted or open-ended ranges.
- `FuzzCheck` ran 4 million executions in 60 s with no failures. A 60 s fuzz of `semantic` itself ran 1.1 million executions with no panics.
- `golangci-lint run ./internal/version/...` reports 0 issues. A temporary import of `semantic` from `internal/tier` was refused by depguard.
- On the requirements this adoption raises, `go build ./...` and `go vet ./...` pass, and `go test ./internal/ai/... ./internal/metrics/... ./internal/feed/generic/... ./internal/testutil/...` passes. Those are the packages that reach a raised module. The list of raised modules is in the entry `2026-11-07T0140Z-version-checks-use-ecosystem-native-comparison.md`.
- The full suite did not run: Docker had 25 running containers from other sessions, and no first-party code changed outside `internal/version`. CI runs only on pull requests to `main`, so it will first run when `dev` next goes to `main`. No live Gemini call exercised the raised `otelhttp`.
