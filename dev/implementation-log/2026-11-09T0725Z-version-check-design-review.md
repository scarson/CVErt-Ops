# Version check design: independent review findings

## What was built

- `dev/plans/2026-11-08-version-check-endpoint-design.md` revised from two independent reviews (Codex, `gpt-6.1-sol` and `gpt-6-astra`, `xhigh`). No code or migration.

## Decisions and gotchas

- The exception that let NVD's answer stand over a CNA wildcard is removed. Reviewers built clean answers from it, and its reason was wrong: maintained Node lines have concrete bounds, and the acceptance CVE's CNA names Brotli.
- `changes[]` is now read as segments, keeping every segment marked `affected`. An entry first marked `unaffected` can still report Affected.
- All reads share one `REPEATABLE READ`, read-only snapshot. Under `READ COMMITTED`, a merge between two statements can mix old NVD rows with new CNA rows and clear a version neither state cleared.
- A name table cannot prove coverage: CVE-2026-70007 names `.NET 9.0 runtime`, which the first table missed. Direct names are always used, the table allows prefixes, and a nearby CNA name on a CVE NVD has not analysed blocks that CVE.
- `resolveCNAAffected` changes to keep every source's copy. `cve_cna_affected` gains `package_key` so package items can use CNA package identity.
- `cve_ids` replaces a scalar `cve_id`, because a USN covers several CVEs. `fix_branch` qualifies a fix from a range with no lower bound.
- Limits are counted in Go across sources, because no single statement sees them all.

## Quality checks

- Wider CNA lookup measured on PostgreSQL 18 with synthetic data, on a database that is not C-collated: 100 exact and prefix keys, 101,029 rows, 0.44 to 0.55 s.
- Review claims about CVE-2026-70007, CVE-2024-27980, CVE-2017-7529, `withOrgRawTx` isolation and `resolveCNAAffected` were checked against upstream records and code.
- No tests ran, because no code changed.
