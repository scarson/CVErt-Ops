# Version check design: second review round

## What was built

- `dev/plans/2026-11-08-version-check-endpoint-design.md` revised from a second independent review of the rewritten verdict rules (Codex, `gpt-6.1-sol`, `xhigh`). No code or migration.

## Decisions and gotchas

- CNA segments are now fully specified: sorted by `at`, each judged on its own boundaries, with a first-match table. An `unknown` segment or an unreadable bound is Indeterminate. Only absent or sentinel values and `git` entries count as having no version information.
- The nearby-name block now asks whether NVD has analysed the CVE for this vendor. A CPE row for an unrelated product no longer suppresses it.
- A CVE that never changes is never merged again, so the migration resets the NVD and MITRE cursors once. `canonicalize` runs on every source write, so that walk rewrites every CVE, and fires no alerts because `material_hash` is unchanged.
- `package_key` uses the same purl mapping and `FoldPackageName` as a request, and a URL naming a private registry gets no key.
- `fix_branch` became `fix_major`. A range with a lower bound can still cross release lines, so the field claims only whether the leading number matches.

## Quality checks

- The review confirmed `REPEATABLE READ`, read-only, works with `SET LOCAL` through this repository's connection setup, on PostgreSQL 15 and 18.
- The changes from this round have had no further independent review.
- No tests ran, because no code changed.
