# Version check Phase 1 review fixes

## What was built

Fixes from the end-of-phase review of Phase 1 (data changes) of `dev/plans/2026-11-09-version-check-endpoint-plan.md`. Four reviewers ran in two rounds. Round 1 split into purl mapping, data path, and test quality, with one reviewer each. Round 2 was one whole-batch reader.

- ac5ad2b: `ecosystem.FromPurl` refuses a name or version that is invalid UTF-8 or holds U+FFFD (`invalid_purl`). It refuses a major release number with leading zeros, any of Alpine's numbers with leading zeros, and an Ubuntu release without a two-digit month (`distro_not_recognised`).
- 7882fef: tests that kill mutations which earlier survived:
  - a non-LTS even Ubuntu year
  - `repository_url` on `deb` and `apk`
  - NUL and invalid UTF-8 in `apk` purls
  - an epoch with no version
  - an epoch with a leading zero
  - a merge test of 2,048-character incompressible CNA vendor and product values and a 2,600-byte package key
- 2899441:
  - `feed.ParseCNAAffected` keeps an entry whose only identity is its `packageURL`.
  - The `GET /cves/{id}` description of `cna_affected` says both the CVE record and NVD's copy contribute entries. `openapi.json` and `web/src/lib/api/schema.d.ts` are regenerated.
- The plan's Deviations and Discoveries record these fixes, and the review findings left for Sam or Phase 3.

## Decisions and gotchas

- `packageurl-go` lower-cases `deb`, `apk`, `golang` and `composer` names with `strings.ToLower`, which turns invalid bytes into U+FFFD before `FromPurl` sees them. A UTF-8 validity check alone missed `pkg:deb/debian/foo%FF`, so U+FFFD is refused as well. No registry name contains it.
- PostgreSQL compresses long index keys, so the long-value test uses pseudo-random two-byte characters. A repeated character would compress under the btree limit and prove nothing. Removing `left(..., 256)` from `cve_cna_affected_check_idx` made the test fail with "index row size 5544 exceeds btree version 4 maximum 2704". The migration was restored afterwards.
- A round-2 reviewer checked the worst case with four-byte characters, and confirmed that PostgreSQL stored the test's values uncompressed.
- Not changed, recorded under the plan's Discoveries:
  - whether `download_url` and `vcs_url` qualifiers should be refused, which is a design question for Sam
  - namespace shapes no registry holds, which answer `no_advisory_found` and never a wrong "not affected"
  - pitfall DB-19's claim that `IF NOT EXISTS` makes a failed concurrent index build safe to retry

## Quality checks

- The new refusal rows in ac5ad2b failed first: nine rows for invalid UTF-8 and the distro forms, then one more for the U+FFFD form. They passed after the fix.
- `TestParseCNAAffectedKeepsEntryWithOnlyAPackageKey` failed first ("got [], want one entry"), then passed.
- `go test ./internal/ecosystem/ ./internal/feed/ ./internal/feed/nvd/ -count=1` passes. So do the targeted `internal/merge` CNA tests and `internal/api -run 'TestGetCVE_|TestOpenAPI'`.
- `golangci-lint run`: 0 issues at 397a8c3. A full `go test ./...` passed at 397a8c3, before these fixes, and is rerun before the pull request.
