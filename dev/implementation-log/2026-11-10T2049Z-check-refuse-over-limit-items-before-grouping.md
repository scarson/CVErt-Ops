# Check endpoint: refuse an item over its row limit before grouping its rows

## What was built

`bfe4426` fix(check), at Sam's request, after the Phase 4 end-to-end run in `dev/plans/2026-11-09-version-check-endpoint-plan.md` (Discoveries). `evaluateItem` (`internal/check/evaluate.go`) called `rowsOf`, which grouped every row of an item's keys by advisory, and only then checked the item's row total and its keys' overflow flags. So an item that answered `too_many_candidates` still paid for every row: a request of 300 kernel versions, each over the 50,000-row per-key limit, allocated 5.35 GiB in 2.3 s.

`overItemLimit(use, data, limit)` reads only the sizes and overflow flags of the keys an item uses (package, CNA package key, CPE, CNA name, nearby-name), and `evaluateItem` calls it before `rowsOf`. `itemRows` no longer carries `total` and `overflow`, which only that check read. The rule is unchanged: an item is over its limit when one of its keys overflowed, or its keys' rows sum past `Limits.ItemRows` before de-duplication.

## Decisions and gotchas

- The test is `TestEvaluateItemOverLimitGroupsNoRows`. It uses `testing.AllocsPerRun`, which counts every allocation in the process, so it does not call `t.Parallel()` (with an inline `//nolint:paralleltest`). Go runs it before the package's parallel tests are released. It failed first at 40,149 allocations per refused item with 20,000 rows; it now needs fewer than 50. It covers both ways an item is over its limit: the item total, and a key's overflow flag.
- `internal/check/evaluate.go` was CRLF in the working copy after a merge, so the scripted edit normalised to LF to match, and wrote back the file's own endings. `git diff --stat` showed only the changed lines.

## Measured (`cvert_phase4` copy, serve from `bfe4426`'s tree)

| Request | Before (`12bb16e` / `715df44`) | After |
|---|---|---|
| 300 kernel versions, all over the limit | 2.3 s, 5.35 GiB | 0.29 s, 51 MiB |
| 10 LTS kernels plus `6.8.0-45-generic` | 0.28 s, 18 MiB | 0.28 s, 16 MiB |
| 500 items over the largest products | 2.0–3.9 s, 1.2 GiB | 2.1 s, 1.2 GiB |

The responses of all three are identical to the earlier runs.

## Quality checks

- `go test ./internal/check/ -count=1`: pass.
- `golangci-lint run ./internal/check/...`: 0 issues.
- Full suite: `go test ./... -count=1 -timeout=600s` passed at `bfe4426` (39 packages, 0 failures).
