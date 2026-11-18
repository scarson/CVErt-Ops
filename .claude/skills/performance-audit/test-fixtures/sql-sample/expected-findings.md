# Expected Findings — SQL fixture (companion pack + PostgreSQL + Routines)

**Purpose:** exercise the **SQL companion pack** (loads alongside a language pack) + the
**`sql/postgres.md`** dialect module + the **Routines discoverability** (the most expensive hand-SQL
lives inside a function body, invoked by name). PostgreSQL dialect; schema/DDL in scope.

**Pack slice to provide:** `sql.md` lane slices + the **Reading the plan & schema** notes + the
**Routines** section + `sql/postgres.md`. Provide all three files (`schema.sql`, `queries.sql`,
`procs.sql`) as scope. Do NOT let the agent read this rubric.

## Planted issues (should be found)

| # | Location | Lane / area | Issue |
|---|----------|-------------|-------|
| 1 | `queries.sql` Q1 | data-access / sargability | `WHERE date(created_at) = $1` is non-sargable AND `created_at` is unindexed; rewrite as a half-open range + add an index |
| 2 | `queries.sql` Q2 | data-access / missing index | filtered by `c.email` (indexed) then joins to orders on `orders.customer_id`, which has **no index** (schema confirms) → sequential scan of `orders`; add an index on `orders.customer_id`. `SELECT *` also over-fetches |
| 3 | `queries.sql` Q3 | memory / pagination | deep `OFFSET 100000` scans+discards; use keyset/seek pagination |
| 4 | `procs.sql` `enrich_recent_orders` | algorithmic / **Routines** | **RBAR inside a routine** — per-row query in a `LOOP`; replace with one set-based `UPDATE … FROM`. **Found only by following the `SELECT enrich_recent_orders()` call from queries.sql into the body** |
| 5 | `procs.sql` `trg_bump_order_count` | `sql/postgres.md` (triggers) | `FOR EACH ROW` trigger writes per inserted row → bulk insert becomes N writes; statement-level trigger / transition table |

## Beyond-the-pack / the discoverability signal

**#4 is the headline test of the Routines feature**: a top-level-only audit of `queries.sql` will NOT
find it. Recall credit for #4 requires the agent to **treat `SELECT enrich_recent_orders()` as a
pointer into `procs.sql` and audit the body**. Missing #4 while finding 1–3 is the precise failure the
Routines section was written to prevent — call it out in scoring.

## Decoy (should NOT be flagged)

| Location | Why ignored |
|----------|-------------|
| `queries.sql` final query | `SELECT id, email FROM customers WHERE id = $1` is a primary-key seek returning one row with named columns — already optimal. "Add an index / avoid the scan" here is a precision failure. |

## Scoring

- **Recall** = (# of {1..5} found) / 5. **#4 only counts if the agent actually inspected the routine
  body** (not a generic "review your stored procedures" hand-wave).
- **Precision** = the PK-seek decoy not flagged; no fabricated index recommendations on already-indexed
  or trivially-bounded queries.
- **Routines discoverability** = did the agent follow the routine invocation into its definition? This
  is the fixture's distinguishing signal.

## How to run

Dispatch the relevant lane subagents (data-access, memory, algorithmic) with the shared preamble +
lane body from `../../lane-prompts.md`, the `sql.md` slices + Reading-the-plan + Routines notes +
`sql/postgres.md`, and **all three `.sql` files** as scope. Score against the tables above.

## Last run

**2026-06-04, Sonnet — GREEN (re-run after the Q2 fix).** Recall 5/5: the **Routines discoverability
held** — the agent followed `SELECT enrich_recent_orders()` into `procs.sql` and flagged the RBAR loop,
explicitly noting it is "only reachable by following the call into the function body." #2 now lands the
missing `orders.customer_id` index (email-driven query makes it bite). PK-seek decoy + VOLATILE + UUID +
`idx_orders_status` candidates all correctly rejected; zero fabrications.
