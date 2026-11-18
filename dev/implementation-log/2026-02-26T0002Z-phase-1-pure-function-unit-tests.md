# Phase 1 — Pure-Function Unit Tests

> **Date:** 2026-02-25
> **Commit:** `4419e4a` on `dev`
> **Deliverables:** `internal/merge/hash_test.go`, `internal/merge/resolve_test.go`, `internal/feed/util_test.go`, additions to `internal/api/cves_test.go`

## Context

After Commit 9, a TDD gap was identified: the core pure functions in the
`merge/` and `feed/` packages had no tests despite containing complex,
bug-prone logic (source precedence, hash normalization, alias resolution).
These functions require no DB connection and are ideal candidates for fast,
isolated unit tests.

## Files created / modified

| File | Tests | What is exercised |
|---|---|---|
| `internal/merge/hash_test.go` | 10 | `ComputeMaterialHash`: determinism, field sensitivity (severity, in_cisa_kev, CVSS vector), CWE/CPE/pkg insertion-order independence, nil slice == empty slice, `normalizeCVSSVector`: empty, reordering, prefix preservation, idempotence |
| `internal/merge/resolve_test.go` | 20 | `resolve()`: MITRE wins status/description over NVD, NVD wins CVSS v3 over GHSA, IsWithdrawn primary-source path, IsWithdrawn OR logic (any-source fallback), DatePublished picks earliest, DatePublished nil when no source provides it, CWE union sorted+deduped, CISA KEV any-source, ExploitAvailable any-source, score-diverges threshold (≥2.0 → true, <2.0 → false, no-scores → false), reference dedup by canonical URL, distinct URLs preserved, pkg priority OSV wins over GHSA on collision, DateModifiedSourceMax picks latest source timestamp, malformed JSON source skipped gracefully |
| `internal/feed/util_test.go` | 15 | `ParseTime`: RFC3339Nano, RFC3339, no-timezone, date-only, invalid→zero, empty→zero, UTC output; `ParseTimePtr`: nil on empty, nil on invalid, non-nil on valid; `StripNullBytes`: removes nulls, no-op on clean; `StripNullBytesJSON`: removes nulls from bytes; `ResolveCanonicalID`: alias found, no alias, nil aliases, first CVE alias wins, native-is-CVE passthrough |
| `internal/api/cves_test.go` | +4 | `cfeToItem`: all-nil sql fields → nil pointers, nil CWEIDs → empty slice (not JSON null), all optional fields set correctly, timestamps formatted as RFC3339 (not Nano) |

**Total new tests in this commit:** 49 (+ the 18 from `9f5beec` = 67 test
functions across the `api`, `merge`, and `feed` packages, up from 2 in Phase 0).

## Implementation decisions / discoveries

**`package merge` for white-box resolve tests** — `resolve()` and
`computeScoreDiverges()` are unexported. Tests use `package merge` (same
package) to access them directly. This is the standard Go pattern for white-box
unit testing of unexported functions.

**`makeSource` helper in resolve_test.go** — Marshals a `feed.CanonicalPatch`
into `generated.CveSource.NormalizedJson`. The merge pipeline reads sources from
the DB as JSON and unmarshals them — this helper faithfully recreates that
path in tests without needing a real DB.

**`makeSourceWithDate` variant** — Adds `sql.NullTime` to `SourceDateModified`
for the `DateModifiedSourceMax` test. Otherwise that field always remains nil in
test data.

**`affectedPkgKey` is unexported** — `hash_test.go` uses `package merge` to
access the `affectedPkgKey` struct directly for the package-order test.

**Canonical URL dedup uses trailing-slash stripping** — `TestResolveRefDeduplicatedByCanonicalURL` uses `"https://example.com/advisory"` vs `"https://example.com/advisory/"` (trailing slash). `canonicalizeURL` strips trailing slashes via `strings.TrimRight(u.Path, "/")`, so both map to the same canonical form.

**`cfeToItem` tested for nil→empty CWEIDs** — The `NOT NULL DEFAULT '{}'`
database column can still return `nil` in Go when `pg.Array` produces an empty
Go slice from a `text[] = '{}'` value. `cfeToItem` guards this with `if
item.CWEIDs == nil { item.CWEIDs = []string{} }` to prevent `null` in JSON
responses. Test verifies this contract.

## Quality check results

**go test `./internal/merge/... ./internal/feed/... ./internal/api/...`:** All
tests pass. No failures.
**go test `./...` -short:** All packages pass (0 failures, 0 skips relevant to
new tests).
**golangci-lint:** 0 issues.
