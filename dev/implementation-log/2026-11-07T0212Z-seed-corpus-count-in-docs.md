# Seed corpus count in docs

## What was built

- `AGENTS.md`, `CLAUDE.md`, `README.md` and `dev/testing-pitfalls.md` now say `testutil.SeedCorpus` seeds 68 real advisory records.

## Key decisions

- Changed "CVEs" to "advisory records": 27 of the 68 rows in `cves` have IDs that are not CVE IDs, such as `DEBIAN-CVE-2021-44228` and `GHSA-26hg-crh6-mjrw`.

## Quality checks

- `TestSeedCorpus` logs `seeded 68 CVEs from 8 feeds`.
- `internal/merge/testdata/golden_material_hashes.json` holds 68 entries, 41 of them with `CVE-` IDs.
