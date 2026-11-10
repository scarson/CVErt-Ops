# Keep every source's CNA affected entries

## What was built

- `resolveCNAAffected` in `internal/merge/resolve.go` stores the distinct CNA affected entries of every source, ordered by their JSON form. Before, it kept only the highest-priority source that had any, so NVD's relay was lost whenever MITRE held a copy.
- `cnaPriority` and its comment were removed, because no code reads them and the comment was false.
- Task 1.3 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 1 data changes). The approved design's section 4.3 ("All copies are read") gives the reason.

## Decisions and gotchas

- A stale copy costs only conservative answers. CNA data can report a version as affected or unresolved, never as not affected, so it can hold back a fix but cannot clear a version.
- Identical copies from MITRE and NVD still store one row: the JSON form is the deduplication key, and it includes `package_key`.
- `TestResolveCNAAffectedUsesOneSourceWithoutRepeats` pinned the rule being replaced. It was renamed `TestResolveCNAAffectedKeepsEverySourcesEntries`. Its first case now expects the union. One case was added: an entry both sources hold is kept once. The existing cases for NVD's copy alone and for no CNA data were kept.

## Quality checks

- `go test ./internal/merge/ -run TestResolveCNAAffected -count=1` failed on the union case before the change.
- `go test ./internal/merge/ -count=1` passes in full after it, including `TestIngest_RemovesRepeatedEntriesAndStaysStableOnRemerge` and the golden NVD and MITRE merge tests.
