# Phase 9 Health Review Remediation — Exploratory Bug Hunt

**Date:** 2026-03-16
**Scope:** PR #31 — merge pipeline, alert evaluator, ingest handler, worker pool, notification delivery, DSL executor, config, startup
**Strategy:** Depth-first from highest-risk business logic, following threads into data layer

## Confirmed Bugs

### Bug 1: PostFilter + pagination interaction silently drops results (HIGH)

**File:** `internal/store/dsl_executor.go`, lines 188-214

PostFilters (regex conditions) are applied **after** the SQL query fetches `limit+1` rows, but next-page detection (`len(results) > limit`) runs **after** filtering.

**Sequence:**
1. SQL returns `limit+1` rows (e.g., 26 for limit=25)
2. PostFilter removes non-matching rows (e.g., 10 match, leaving 16)
3. `len(results) > limit` → `16 > 25` → false
4. No next-cursor returned, even though more matching rows exist in the database

**Impact:** Users of saved searches or NL search with regex conditions get silently truncated results. Rows that match the regex on later pages are permanently inaccessible.

**Fix direction:** Run pagination check on the pre-filtered result set. Save pre-filter count, apply PostFilters, use the last pre-filter row's cursor position if pre-filter count exceeded limit.

### Bug 2: Case-sensitivity mismatch between alert evaluation and DSL query execution (MEDIUM)

**File:** `internal/store/dsl_executor.go`, line 253
vs `internal/alert/evaluator.go`, lines 39-43, 476

The alert evaluator fetches `COALESCE(lower(cves.description_primary), '')` (line 476), so regex matching via `cveSummary.PostFilterField` operates on pre-lowercased text.

But `ExecuteDSLQuery` uses `cvePostFilterTarget.PostFilterField` which returns `c.cve.DescriptionPrimary.String` — raw, unmodified case from the database.

**Impact:** Same regex rule produces different match results:
- Alert evaluation: effectively case-insensitive (pre-lowercased)
- Saved search / NL search: case-sensitive (raw case)

A rule with regex `chrome` (no `(?i)`) matches in alerts but misses "Chrome" via saved search.

**Fix:** `cvePostFilterTarget.PostFilterField` should return `strings.ToLower(c.cve.DescriptionPrimary.String)` to match the evaluator's behavior.

## Investigated and Cleared

1. **`evictStaleSemaphores` semaphore check** — Initially flagged, then confirmed correct: `len(sem) == 0` means "no goroutines hold slots," which is the right check for safe eviction
2. **`backoffDuration` overflow** — `max(failures, 0)` guard + `min(..., 10)` cap prevents overflow. `1<<10 * 30s ≈ 8.5 hours` is within safe range
