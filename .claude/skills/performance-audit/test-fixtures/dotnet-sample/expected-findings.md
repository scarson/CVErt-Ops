# Expected Findings — .NET fixture (core + aspnet-core + sql-server-data)

**Purpose:** exercise the .NET core lanes + the `aspnet-core` and `sql-server-data` modules + the
**Variant notes** (Modern vs Framework). Illustrative (not built).

**Pack slice to provide:** `dotnet.md` lane slices + the **Variant notes** section + `dotnet/aspnet-core.md`
+ `dotnet/sql-server-data.md`. Scope = `OrdersController.cs`. Do NOT let the agent read this rubric.

## Planted issues (should be found)

| # | Location | Lane / module | Issue |
|---|----------|---------------|-------|
| 1 | `Summary` loop (`o.Customer.Name`) | data-access / `sql-server-data` | **EF N+1**: lazy navigation accessed per row; use `Include`/projection |
| 2 | `Summary` loop (`line += …`) | memory / algorithmic | string `+=` in a loop → O(n²) allocation; `StringBuilder` |
| 3 | `Report` (`_db.Orders.ToList()` then `.Where`) | data-access / `sql-server-data` | **client-side evaluation** — materialize-then-filter instead of pushing `Where`/`Select` to SQL; also over-fetches columns |
| 4 | `Report` (`.CountAsync().Result`) | concurrency / Variant notes | **sync-over-async** blocks a thread-pool thread / deadlock risk; `await` it |

## Beyond-the-pack (floor-not-ceiling — bonus)

| Location | Issue | Why beyond the pack |
|----------|-------|---------------------|
| `SumValidQuantities` | `try/catch (FormatException)` per item in a loop — exceptions as control flow | Throwing/catching captures a stack and is expensive in .NET; on a hot path it dominates. `int.TryParse` avoids it. No .NET-pack bullet names exception-as-control-flow cost — requires reasoning. |

## Decoy (should NOT be flagged)

| Location | Why ignored |
|----------|-------------|
| `RegionAllowed` | LINQ `.Where(...).Any()` over a fixed 3-element static array — mirrors the materialize-then-filter shape but n=3, no DB, cold. "Push to SQL"/"avoid ToList" here is a precision/checklist failure. (A sharp agent may note `.Any(x => x == r)` is marginally cleaner, but that's a style note, not a perf finding.) |

## Scoring

- **Recall** = (# of {1..4} found) / 4.
- **Precision** = `RegionAllowed` decoy not flagged as a perf finding; no fabricated findings.
- **Beyond-the-pack** = the exception-as-control-flow loop flagged → out-reasons the lens.

## How to run

Dispatch lane subagents (data-access, memory, concurrency) with the shared preamble + lane body from
`../../lane-prompts.md`, the `dotnet.md` slices + Variant notes + the two modules, and
`OrdersController.cs` as scope. Score against the tables above.

## Last run

**2026-06-04, Sonnet — GREEN.** Recall 4/4 (also caught the missing `AsNoTracking()` + sync action
method within #3); beyond-the-pack (exception-as-control-flow) found and flagged as not-in-the-pack;
`RegionAllowed` decoy rejected as bounded/cold; `AsSplitQuery`/`IAsyncEnumerable` candidates correctly
ruled inapplicable; zero fabrications.
