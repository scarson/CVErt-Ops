# MATCH-2: batch re-check scan measured; activation passes after batched inserts

## What was built

| Feature | Files | Description |
|---|---|---|
| Measurements | `dev/plans/2026-11-13-product-match-rules-measurements.md` | Task 5.5: the batch candidate scan's `UNION` of two keyset scans on the disposable copy (dense and sparse windows); M8 re-run after merging PR 243. |
| Plan record | `dev/plans/2026-11-13-product-match-rules-plan.md` | Phase 5 commits, the Task 5.5 result, M8 passing, and a late-binding discovery. |

## Key decisions

- M8 passes after PR 243: 2 min 4 s for 200,252 events (12 min 5 s with one transaction per event).
- Task 5.5 fails its 3 s per-page threshold in one case: a window of about 26,000 eligible CVEs clustered at the end of `cve_id` order makes the planner walk `cves_pkey` in both arms (3.7 s for the first page; the existing arm alone 1.27 s). Dense windows and later pages are fast. Taken to Sam with the numbers.

## Quality checks

- Docs and measurements only; the merge was tested before commit (`go test ./internal/alert/... ./internal/store/...`: pass).
