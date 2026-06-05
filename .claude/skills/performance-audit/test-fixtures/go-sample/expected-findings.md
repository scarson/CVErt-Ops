# Expected Findings — Go fixture (core + net-http-servers + database-sql)

**Purpose:** exercise the Go core lanes + the `net-http-servers` and `database-sql` modules + the
Runtime & GC notes, with recall / precision / beyond-the-pack scoring. Illustrative Go (not built).

**Pack slice to provide:** `go.md` lane slices + the **Runtime & GC notes** section + (material to this
scope) `go/net-http-servers.md` and `go/database-sql.md`. Do NOT let the agent read this rubric.

## Planted issues (should be found)

| # | Location | Lane / module | Issue |
|---|----------|---------------|-------|
| 1 | `service.go` `HandleOrder` (per-item loop) | data-access / `database-sql` | **N+1**: one `QueryRow` per item; should be one `WHERE id = ANY($1)` batch |
| 2 | `service.go` `HandleOrder` (`&http.Client{}`) | data-access / `net-http-servers` | **http.Client built per request** (no keep-alive/pool reuse); `resp.Body` never drained+closed → connection not returned to the pool |
| 3 | `service.go` `Totals` | concurrency | three **independent** calls awaited **sequentially**; could run concurrently (errgroup / goroutines+WaitGroup). Independence holds → safe to parallelize (must state the guard) |
| 4 | `inventory.go` `FindDuplicateSKUs` | algorithmic | **O(n²)** `contains` (slice membership) inside the loop; use a `map[string]struct{}` set |
| 5 | `inventory.go` `BuildLabels` | memory | `labels` appended from a nil slice with no `make([]T, 0, n)` preallocation → repeated reallocations |

## Beyond-the-pack (floor-not-ceiling — bonus, not a recall requirement)

| Location | Issue | Why it's beyond the pack |
|----------|-------|--------------------------|
| `inventory.go` `BuildLabels` | `fmt.Sprintf("%d", it.Price)` for int→string on a hot path | `fmt` is reflection-based; `strconv.Itoa` is ~10× faster. No Go-pack bullet names fmt.Sprintf-for-int-conversion — the agent must reason it. Finding it rewards out-reasoning; missing it is not a recall miss, but consistent misses ⇒ checklist-drift signal. |

## Decoy (should NOT be flagged)

| Location | Why it must be ignored |
|----------|------------------------|
| `inventory.go` `IsSupportedRegion` | `contains` over `defaultRegions` mirrors the #4 O(n²) pattern, BUT it's a constant 3-element config slice and a single membership test (not a request-loop). O(3) is cold/bounded → not a finding. Recommending "use a map" here is a precision/checklist failure. |

## Scoring

- **Recall** = (# of {1..5} found) / 5. #3 must include the independence/correctness guard.
- **Precision** = `IsSupportedRegion` decoy not flagged (or explicitly considered + rejected on
  bounded-n grounds); zero fabricated findings.
- **Beyond-the-pack** = `fmt.Sprintf` flagged → bonus signal that the agent out-reasons the lens.

## How to run

Dispatch lane subagents (algorithmic, memory, data-access, concurrency) with the shared preamble +
that lane body from `../../lane-prompts.md`, the `go.md` lane slice + Runtime & GC notes + the two
modules, and this directory as scope. Score against the tables above.

## Last run

**2026-06-04, Sonnet — GREEN.** Recall 5/5; beyond-the-pack (`fmt.Sprintf` int→string) found and
explicitly flagged as not-in-the-pack; `IsSupportedRegion` decoy rejected on bounded-n grounds; the
2-operand string concat correctly rejected; zero fabrications. **Valid extra finding:** the agent also
flagged `QueryRow` without `r.Context()` (uncancellable DB work on client disconnect) — a real issue
not in the planted set; a legitimate beyond-the-rubric find, not a false positive.
