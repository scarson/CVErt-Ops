# Version check design: case for each alternative

## What was built

- `dev/plans/2026-11-08-version-check-endpoint-design.md` revised after arguing the strongest case for each alternative. Section 15 now records that case and why each recommendation stands. No code or migration.

## Decisions and gotchas

- Distro records would have reported `in_cisa_kev: false` for exploited CVEs, including the acceptance example, because KEV and EPSS are written to the `CVE-*` row. They are now read from the derived CVE, and are `null` for a record with no CVE.
- A CPE product with no CNA name can no longer be cleared. A CVE NVD has not analysed is invisible for that product, and a warning would be missed by a script that reads only the status.
- `node --version` prints `v24.22.0`, which `version.CheckNumeric` refuses. A leading `v` is removed from CPE-form versions.
- Package items in distro ecosystems depend on OSV only, not GHSA.
- The previous claim that a per-item row limit needs a per-item read was false. `CROSS JOIN LATERAL` with `LIMIT` keeps one statement per data source.
- The rate limit counts a request once, so it does not bound the cost of one. A process-wide limit of 4 concurrent checks now does.

## Quality checks

- Golden data: of the 3 records with clean CNA bounds, one product on each side and NVD analysis, CVE-2026-56847 would be wrongly cleared by a looser CNA rule. The sample is too small to settle it, so the design lists it to measure on a full ingest.
- `LATERAL` per-key limit measured on PostgreSQL 18 with synthetic data: 300 keys, 110,951 rows, 0.7 to 1.6 s.
- No tests ran, because no code changed.
