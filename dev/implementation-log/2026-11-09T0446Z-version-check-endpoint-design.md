# Version check endpoint design

## What was built

- `dev/plans/2026-11-08-version-check-endpoint-design.md`: the design for `POST /api/v1/orgs/{org_id}/check` (requirement MATCH-1), for Sam's review. No code or migration.

## Decisions and gotchas

- OSV names distro source packages. `php` on `Ubuntu:26.04:LTS` has no records and `php8.5` has four, so the acceptance example naming `php` cannot pass as written.
- CNA data must never clear a version. CVE-2026-56847 lists single versions with `defaultStatus: unaffected`, while NVD records a range, so a literal reading gives a wrong "not affected". CVE-2024-7347's `changes[]` does the same for nginx 1.27.0.
- Distro answers do not need the CVE join: the endpoint looks up by package, and those rows already exist under each distro advisory's own ID.
- No current index serves the lookups. Synthetic plans with 6 million package rows went from 10.9 s to under 0.5 s with one expression index.

## Quality checks

- Query plans measured on PostgreSQL 18 with synthetic data; version comparison cost measured with a throwaway benchmark, not committed.
- Real records read from the OSV, CVE and NVD APIs on 2026-11-08. Nothing has run against a full ingest of live feeds.
- `dependency-check` for `github.com/package-url/packageurl-go`: approved.
- No tests ran, because no code changed.
