# CNA package key and check lookup indexes

## What was built

- `migrations/000059_check_lookups`: adds the nullable `cve_cna_affected.package_key` column, and four indexes for the version check lookups. They cover the folded package name on `cve_affected_packages`, the CPE in C collation on `cve_cpe_matches`, CNA vendor and product cut to 256 characters, and a partial index on `package_key`.
- `feed.ParseCNAAffected` reads `packageURL` and sets `CNAAffected.PackageKey` to `ecosystem.PackageKey` of it. Merge writes the key through `InsertCNAAffected`.
- `TestCheckPackageIndexMatchesFoldedName` pins the migration to the expression `ecosystem.FoldedNameSQL("ecosystem", "package_name")` builds. The check query will be built from the same function, and the index is used only while the two match.
- Task 1.2 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 1 data changes).

## Decisions and gotchas

- The key is computed from the `packageURL` as the CNA sent it, not after `cleanCNAString`. Removing a NUL first could turn a refused URL into another package's identity, and `FromPurl` refuses control characters itself.
- `package_key` is not a `material_hash` input. A test merges the golden fastify record without and then with the key, and checks that neither the hash nor `date_modified_canonical` moves.
- `GetCVECNAAffected` is `SELECT *`, so the generated row type gains `PackageKey`. `internal/api/cves.go` maps fields one by one, so `GET /cves/{id}` is unchanged.
- The NVD and MITRE golden tests for CVE-2026-107832 pin the parsed CNA entry exactly. They now expect `PackageKey: "npm/fastify"`, which the record's `packageURL` carries.
- `sqlc generate` rewrote every generated file with LF line endings. Only `cves.sql.go` and `models.go` had real changes, and the others were restored.
- Schema review: no failures. One warning: the folded-name index has the same unbounded `package_name` key-size exposure as the existing `cve_affected_packages_eco_pkg_idx`.

## Quality checks

- The targeted tests failed first: missing field and missing migration. They then passed.
- `go test ./internal/feed/... ./internal/merge/ ./internal/store/ ./migrations/ ./internal/ecosystem/ -count=1`: everything passed except the two golden expectations above, which passed once updated.
- `go test ./internal/api/ -run TestGetCVE_` passes.
- Applying 000059's down file, then its up file, to a migrated test database removed the column and all four indexes, then restored them. This was checked with a temporary test, which was deleted afterwards because no test in the repository applies down migrations.
