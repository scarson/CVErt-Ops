# Profile Pack: SQL (hand-written queries)

A **companion** pack for **hand-rolled SQL** — queries, views, **stored procedures, functions, and
triggers** written by hand (not ORM-generated). It loads *alongside* the application's language pack
whenever hand-written SQL is material to the scope, and sharpens the same lanes for relational query
performance. ORM-specific footguns live in the language packs' data modules (`dotnet/sql-server-data.md`,
`python/orm-database.md`, `go/database-sql.md`, `javascript-typescript/node-data.md`); this pack is about
the SQL itself — **including the SQL hidden inside routines** (see "Routines" below; it is the easiest
to miss).

**Assumes the schema (DDL) is available.** Reasoning about indexes, types, cardinality, and keys
requires the table/index definitions and ideally row-count statistics — when they are in scope, use
them; when they are not, drop confidence and say so. Signals below are durable and dialect-agnostic;
dialect specifics (PostgreSQL, T-SQL/SQL Server) load as modules — see the map at the bottom. Concrete
dialect features are tagged "(verify against the currency brief for your version)".

---

## Algorithmic / query complexity (lane `algorithmic`)
- **Row-by-row (RBAR)** where a set-based statement would do: a cursor/`WHILE` loop, or a per-row
  scalar function/round-trip, doing work the engine could express as one `UPDATE … FROM` / `INSERT …
  SELECT` / `MERGE` over the whole set.
- **Non-sargable predicates**: wrapping an indexed column in a function or expression
  (`WHERE lower(col)=…`, `WHERE col+0=…`, `WHERE date(ts)=…`), a leading-wildcard `LIKE '%x'`, or an
  implicit type cast on the column side — each forces a scan instead of a seek. Move the transform to
  the literal side, or index the expression.
- **Join fan-out before aggregation**: joining one-to-many and then aggregating multiplies rows the
  engine must process (and can double-count) — filter/aggregate the many side first (subquery or
  window) before joining, rather than `DISTINCT`/`GROUP BY` to paper over the explosion.
- **Correlated subquery per outer row** where a single `JOIN`, window function, or one grouped
  aggregate would compute the value once — a SQL-shaped N+1 inside one statement.
- **Accidental Cartesian / missing join predicate**, and `OR` across different columns that defeats
  any single index (often better as `UNION ALL` of sargable branches, or a rethought index).
- **Recomputed work**: the same derived table / subquery evaluated several times in one statement
  where a CTE, temp table, or window computes it once.

## Memory & intermediate results (lane `memory`)
- **Sorts / hash joins / aggregates that spill to disk** (`ORDER BY`, `GROUP BY`, `DISTINCT`, window,
  merge/hash join over large inputs) without a supporting index or enough working memory — the spill,
  not the logic, is the cost; an index that delivers rows in the needed order can remove the sort.
- **`SELECT *` / over-wide projection** pulling columns (especially large text/JSON/blob) the caller
  never uses — inflates I/O, network, sort width, and memory grants.
- **Unbounded result sets / deep `OFFSET` pagination**: `OFFSET N` scans and discards N rows every
  page; prefer keyset/seek pagination anchored on the last key. Missing `LIMIT`/`TOP` on exploratory
  or list queries.
- **Materializing a huge intermediate** (temp table / CTE / derived table) that could be filtered
  earlier or streamed, holding peak memory or tempdb for the whole statement.

## Data access & indexing (lane `data-access`)
- **Missing index** on columns used in `WHERE` / `JOIN` / `ORDER BY` / `GROUP BY` — check the actual
  DDL. For a composite index, column order is **equality predicates first, then the range/inequality,
  then `ORDER BY` columns**; an index in the wrong order can't seek the query.
- **Key/heap lookups that should be covered**: a query that seeks a secondary index then fetches extra
  columns row-by-row from the base table is a covering-index opportunity (include the projected
  columns) — but weigh the added write/storage cost.
- **Too many / redundant / unused indexes**: every index is paid for on every `INSERT`/`UPDATE`/
  `DELETE`; duplicate or never-served indexes are pure write tax — recommend the *minimal* index that
  serves the predicate and projection.
- **Stale statistics → wrong row estimates → wrong plan**: when the optimizer mis-estimates
  cardinality it picks the wrong join type, order, or access method; the estimate-vs-actual gap in the
  plan is the tell — refresh stats before blaming the query.
- **Type mismatch at the predicate** (column type ≠ literal/parameter type) forcing an implicit
  conversion and a scan — sargability at the type level, easy to miss without reading the plan.
- **Over-fetching / late filtering**: returning rows the application then filters or counts, or
  issuing one query per row from the app (the SQL side of the application `data-access` lane) — push
  the filter/aggregate into the query.
- **Non-parameterized / ad-hoc SQL defeating plan reuse**: queries built by string-concatenating
  literal values (`… WHERE id = 42`, a new literal every call) produce a distinct statement text each
  time, so the engine compiles and caches a separate plan per literal — plan-cache bloat and repeated
  compilation cost, and lost plan reuse. Parameterize (`WHERE id = $1` / `@id`); this is especially
  common in *hand-rolled* SQL and is also the same defect as SQL injection — the durable fix serves
  both (verify against the currency brief for your version — engines differ on forced/auto
  parameterization).

## Concurrency & locking (lane `concurrency`)
- **Long transactions holding locks** (and, under MVCC, holding back row-version cleanup): do external
  calls, user think-time, and heavy computation *outside* the transaction; keep the write window
  minimal.
- **Blocking chains & lock escalation**: a higher isolation level than the read actually needs, or
  bulk DML escalating row→table locks, serializes concurrent access on hot tables — right-size the
  isolation level and consider chunked DML.
- **Deadlocks from inconsistent lock ordering** across statements/procs — access tables/rows in a
  consistent order and hold the fewest locks for the least time.
- **Readers blocking writers (or vice versa)** under pessimistic isolation where row-versioning /
  snapshot isolation would let them not block — a real fix, but weigh the version-store cost
  (verify against the currency brief for your version).
- **One giant DML statement** (delete/update millions) where chunked batches would bound lock
  duration, transaction-log/WAL growth, and replication lag.

## Framework / dialect-idiom currency (lane `idiom-currency`)
- Consult the version index/brief for the dialect — flag the slow hand-rolled equivalent of a feature
  the engine now does better: window functions instead of self-joins, `MERGE`/upsert instead of
  load-then-write, `FILTER`/conditional aggregation, lateral/`APPLY`, native JSON functions,
  batch-mode/columnstore for analytics (verify against the currency brief for your version).
- Offline (no brief/index): note candidate idiom concerns at LOW confidence, flagged for manual
  currency check.

---

## Routines: stored procedures, functions & triggers (don't miss them)

The query the application *runs* is often not in the application code. A `EXEC sp_DoWork @id`, a
`CALL process_order(...)`, or a plain `INSERT`/`UPDATE` that silently fires a **trigger** hands the
real, hand-rolled SQL off to a routine whose body lives in a schema/migration `.sql` file — and an
audit that reads only the app's data-access code **never sees it**. This is the single easiest place
for expensive hand-rolled SQL to hide.

- **Follow the invocation into the definition.** Treat every `EXEC`/`CALL`/`SELECT … FROM
  function(…)`/proc-name reference, and every DML against a table that has triggers, as a pointer into
  a routine body — then audit that body with **all the lanes above** (the body is just SQL: it has its
  own joins, indexes, sargability, cursors, locking). With the schema/DDL in scope (this pack assumes
  it), the definitions are right there to read — read them, don't stop at the call site.
- **Triggers are invisible per-row work on every DML.** A row-level `AFTER`/`INSTEAD OF`/`BEFORE`
  trigger that does a lookup, an audit-table insert, or a cascade runs *per affected row* on every
  `INSERT`/`UPDATE`/`DELETE` — so a bulk operation that looks set-based becomes row-by-row, and the
  cost appears nowhere in the calling statement. Find the triggers on hot tables and audit their
  bodies; prefer statement-level / set-based trigger logic over per-row where the dialect allows
  (verify against the currency brief for your version).
- **Routine-level N+1 and fan-out.** A proc/function invoked once per row from the app (or from inside
  another routine — nested proc/function fan-out) is N+1 one level up; a function called in a
  `SELECT`/`WHERE` runs its body per row (see the dialect modules' scalar-function bullets). The fix is
  the same as any N+1: hoist the work into one set-based call.
- **Plans and parameters apply to routine bodies too.** Procedure plans are cached and sniffed, routine
  bodies recompile, and a routine's SQL has its own statistics dependence — the dialect modules carry
  the specifics (parameter sniffing, recompilation, function volatility/inlining). Don't assume a
  routine is cheap because the call site is one line.

---

## Reading the plan & schema (use for every SQL audit)

SQL performance is judged against the **execution plan** and the **schema**, not the query text alone
— this is the SQL analog of a runtime-notes section: how to observe and measure before concluding.

- **Get the *actual* plan, not just the estimate**: PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)`, SQL
  Server's actual execution plan + `SET STATISTICS IO, TIME ON`, run under representative data volume.
  Estimated plans built on stale statistics mislead (verify against the currency brief for your
  version).
- **Seek vs scan is a judgment, not a verdict**: a full scan is fine on a small or genuinely
  unfiltered table and a problem on a large, selectively-filtered one — weigh the operator against the
  table's row count and the predicate's selectivity, not the operator name.
- **Estimated vs actual rows is the highest-signal tell**: a large divergence means the optimizer is
  guessing wrong (stale/missing stats, correlated columns it can't model, a non-sargable predicate),
  so its join/order/memory choices downstream are probably wrong too.
- **Use the schema you have**: confirm which columns are actually indexed, the index column order,
  the declared types (for sargability), the primary/clustering key, and approximate row counts before
  recommending a change — and recommend the *minimal* index that serves the query, weighing its write
  cost.
- **Confirm impact, don't assume it**: estimate rows examined vs returned; a fix that should turn a
  scan into a seek must be validated against the new plan (and measured where possible). A hot region
  that is inherent — a report that must aggregate the whole table — is not automatically a bug.

## Framework / dialect modules (load on detection)

Load the lanes + plan/schema notes above for *every* hand-written-SQL audit. Additionally load the
dialect module matching the target database.

| Detected (signals) | Load module |
|---|---|
| **PostgreSQL** — `postgres`/`postgresql` driver or DSN, `psql`/`pg_dump` artifacts, Postgres syntax (`::type` casts, `RETURNING`, `jsonb`, `ON CONFLICT`, `ILIKE`) | [`sql/postgres.md`](sql/postgres.md) |
| **T-SQL / SQL Server** — `sqlserver`/`mssql` driver, `.sql` with `GO` batch separators, `[bracketed]` identifiers, `NVARCHAR`, `TOP`, `MERGE`, stored procedures | [`sql/tsql.md`](sql/tsql.md) |

## Sources

Durable signals here are grounded in vendor query-optimization documentation; dialect-specific facts
and per-entry citations belong in the dialect modules and (where built) a SQL version index.

- **PostgreSQL** — "Using EXPLAIN", "Planner/Optimizer", "Index Types", "Routine Vacuuming", "Server
  Configuration: Resource Consumption" (`work_mem`).
- **SQL Server** — "Query Processing Architecture Guide", "Execution plans", "SQL Server Index
  Architecture and Design Guide", "Statistics", "Transaction Locking and Row Versioning Guide".
- **Relational fundamentals** — Use The Index, Luke (sargability, composite-index column order,
  covering indexes); vendor pagination/keyset guidance.
