# NVD cursor records a finished walk

## What was built

- `nvd.Cursor` gains `CaughtUp` (`caught_up` in the cursor JSON, omitted while false). `computeNextCursor` sets it on the cursor it returns with `LastPage`. The more-pages and next-window cursors carry the input's value forward, so the flag stays set once the first walk reaches the present.
- Task 1.4 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 1 data changes). The version check endpoint will read the flag to report whether NVD data is complete (design section 5).

## Decisions and gotchas

- No other `Cursor` literal needed the field. `Fetch` walks past empty windows by assigning the whole cursor that `computeNextCursor` returns, and `zeroValueCursor` builds a cleared cursor, which must start false.
- `parseCursor` replaces a cursor that has a zero `window_start` with a fresh one, which drops `caught_up`. The adapter never writes that shape, and a cleared cursor should start false anyway.

## Quality checks

- The new tests failed first on the missing field: `TestComputeNextCursor_CaughtUp`, `TestCursorCaughtUpJSON`, `TestFetch_WalkPastEmptyWindowsKeepsCaughtUp` and `TestFetch_FirstWalkEndsCaughtUp`.
- `go test ./internal/feed/nvd/ -count=1` passes in full after the change.
