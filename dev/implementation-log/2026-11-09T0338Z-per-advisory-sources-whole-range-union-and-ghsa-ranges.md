# Per-advisory sources, whole-range union and GHSA ranges

## What was built

- `internal/ecosystem` holds OSV's ecosystem names, GHSA's mapping and package name folding.
- `cve_sources` is keyed `(cve_id, source_name, source_id)` (migration `000057`), so several advisories from one feed can describe one CVE. `resolve()` collapses rows of one source in `source_id` order.
- `cve_affected_packages` keeps every distinct range. The GHSA adapter parses `vulnerable_version_range` into real bounds, and the OSV adapter reads `versions` beside `ranges`.
- `material_hash` adds `last_affected` and range class under a sort that compares every hashed field.
- The web sources panel shows each advisory when one source has several for a CVE.

## Decisions and gotchas

- Golden pins moved once, by 20 entries: CVEs with GHSA rows or several OSV records, one with a GIT range and an uppercase name, two withdrawn Ubuntu records that now contribute no ranges, and five Root records with several fixes under one `introduced`.
- A CVE whose only source is the advisory renames whole, keeping `date_first_seen` and its alerts. Otherwise only the advisory's row leaves, so the result does not depend on processing order.
- Moved alerts: the check confirmed that an alert moved onto a CVE with an unchanged hash was never re-evaluated, so the target's `date_modified_canonical` is bumped when an alert moves.
- Accepted gap, Sam's decision: the evaluator re-checks that a CVE exists just before recording an event, but a rename that commits between that check and the insert still leaves one event under the old ID. Closing it would mean holding the merge lock on every event insert.
- A declared GHSA range is never shortened: an inclusive bound yields to `first_patched_version` only if that version provably sorts above it.
- `SeedCorpus` uses `t.Setenv`, so tests calling it cannot use `t.Parallel`.

## Quality checks

Targeted tests for `internal/merge`, `internal/alert`, `internal/ingest`, `internal/feed/...` and `internal/store` passed, `golangci-lint` is clean, and the web tests, lint and type check pass. Two tests were confirmed to fail without their mechanism: removing the row-level-security bypass and removing the per-advisory lock.

Not verified against live feeds: the OSV and GHSA adapters were tested on golden fixtures only.
