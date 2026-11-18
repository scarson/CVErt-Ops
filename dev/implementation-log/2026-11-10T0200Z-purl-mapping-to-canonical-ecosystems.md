# Purl mapping to canonical ecosystems

## What was built

- `internal/ecosystem/purl.go`: `FromPurl` maps a package URL to an OSV ecosystem, a package name and a version, with stable refusal codes (`invalid_purl`, `unsupported_purl_type`, `unsupported_purl_namespace`, `unsupported_repository`, `distro_required`, `distro_not_recognised`, `conflicting_distro`, `conflicting_version`). `PackageKey` gives a CNA `packageURL`'s stored identity, and `PackageKeyFor` the identity a package item looks up.
- `internal/ecosystem/ecosystem.go`: `IsDistro` and `NeedsRelease`, from a `distros` list of distribution base names.
- `github.com/package-url/packageurl-go` v0.1.7 is now a direct dependency. It was already in the module graph at v0.1.5 through `osv-scalibr`, which now resolves to v0.1.7 as well.
- Task 1.1 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 1 data changes).

## Decisions and gotchas

- `packageurl-go` percent-decodes the npm scope (`%40scope` becomes `@scope`), lower-cases names for `golang`, `deb`, `apk` and `composer`, and lower-cases PyPI names with `_` replaced by `-`. Every comparison goes through `FoldPackageName`, so the lower-casing does not change which rows match.
- `packageurl-go` drops a qualifier with an empty value, as the purl specification says, so `distro=` reads as no distro (`distro_required`) and `repository_url=` is not refused.
- A test checks that every `distros` entry is a canonical ecosystem name, so a misspelt entry cannot silently stop marking a distribution.

## Quality checks

- `go test ./internal/ecosystem/ -count=1`: failed first on undefined `FromPurl`, then passed.
- `go build ./...`, and `go test ./internal/version/ ./internal/feed/ghsa/ ./internal/feed/osv/ -count=1` pass after the dependency upgrade.
