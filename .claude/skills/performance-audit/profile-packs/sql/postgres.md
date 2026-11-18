# SQL performance module: PostgreSQL
> Load when the SQL dialect is PostgreSQL (`postgres`/`postgresql` driver or DSN, `psql`/`pg_dump` artifacts, Postgres-specific syntax like `::type` casts, `RETURNING`, `jsonb`, `ON CONFLICT`) — see the module map in `../sql.md`. Dialect-agnostic SQL lanes live in `../sql.md`; this file is the PostgreSQL lens only.

## PostgreSQL

> Scope: hand-rolled queries against a PostgreSQL backend where the schema (DDL) is available for
> reasoning about indexes, types, and cardinality. Dialect-agnostic fundamentals (missing index on
> filter/sort columns, SELECT * over-fetch, correlated-subquery N+1, sargability in general, set-based
> vs cursor, keyset pagination, reading EXPLAIN in general) are owned by the **Data access** lane in
> `../sql.md` — this file specialises to Postgres-distinctive realities only. The recurring themes are:
> **MVCC bloat and vacuum** (dead tuples accumulate silently and degrade every scan until vacuumed),
> **the right index type** (Postgres offers more index kinds than most engines — pick the one that
> matches the data shape), **reading `EXPLAIN (ANALYZE, BUFFERS)`** (estimated vs actual row counts and
> buffer hits reveal the actual cost), **`work_mem` spills** (sorts and hash joins that exceed the
> per-operation budget land on disk), and **the process/pooler model** (each backend is a heavyweight
> OS process — connection count is a first-class resource).

- **MVCC bloat and autovacuum falling behind**: every `UPDATE` or `DELETE` leaves dead tuple versions
  in the heap; bloated tables and indexes pay that dead-tuple I/O on every scan. Long-running
  transactions hold back the oldest `xmin` horizon and can block autovacuum from cleaning any later
  rows across the whole table — a single idle-in-transaction connection can freeze cleanup
  cluster-wide. For tables with high churn, check whether autovacuum cost parameters or
  `vacuum_freeze_min_age` have been tuned, and whether `fillfactor < 100` is set to leave room for
  HOT updates (HOT avoids writing new index entries when no indexed column changes, a major win for
  frequently-updated rows) (verify against the currency brief for your version).

- **`EXPLAIN (ANALYZE, BUFFERS)` signals beyond the plan shape**: a large gap between *Estimated Rows*
  and *Actual Rows* means statistics are stale — run `ANALYZE` on the table and check
  `pg_stat_user_tables.last_analyze`. `Rows Removed by Filter` on a Seq Scan or Index Scan node
  indicates a non-sargable or unindexed predicate doing post-fetch filtering. `Buffers: shared
  read` vs `hit` reveals whether data is coming from disk or cache; `temp read`/`written` signals an
  on-disk spill (see the `work_mem` bullet). A `Bitmap Heap Scan` after a `Bitmap Index Scan` is
  normal for range or multi-condition queries but has a heap-recheck cost absent from a plain Index
  Scan — evaluate which is cheaper given selectivity (verify against the currency brief for your
  version).

- **Index-only scans blocked by a stale visibility map**: a covering index (or a query projecting only
  indexed columns) enables an index-only scan that never touches the heap — but Postgres still checks
  the visibility map to confirm tuple visibility. Pages dirtied by recent writes are marked
  "not all-visible" and force a heap fetch anyway, degrading to an effective Index Scan. Regular
  `VACUUM` updates the visibility map; on write-heavy tables an index-only scan may never be clean
  without explicit tuning. Also check that multicolumn index column ORDER places equality predicates
  before range predicates — a `(status, created_at)` index serves `WHERE status = 'open' AND
  created_at > $1` but the reverse order does not (cross-reference the **Data access** lane in
  `../sql.md` for general index-column-order fundamentals).

- **Wrong index type for the data shape**: Postgres provides index types beyond B-tree that the planner
  will only use when explicitly created. A `WHERE active = true` on a column that is `true` for 0.1%
  of rows is a candidate for a **partial index** (`CREATE INDEX … WHERE active = true`) — far smaller
  and faster than an index on the full column. Predicates on `lower(email)` or any computed expression
  require an **expression index** on that exact expression. `jsonb`/array membership and full-text
  predicates need a **GIN** index; range types and geometric data need **GiST**; huge
  naturally-ordered append-only tables (event logs, time-series) can use a tiny **BRIN** index
  instead of a B-tree. The `INCLUDE` clause on a B-tree adds non-key columns for covering without
  widening the index key (verify against the currency brief for your version).

- **`work_mem` spills to disk on sorts, hash joins, and hash aggregates**: each sort, hash join, or
  hash aggregate operation gets its own `work_mem` budget (a single query with multiple such nodes
  multiplies it). When the operation exceeds the budget, Postgres writes temp files — visible in
  `EXPLAIN ANALYZE` as `Sort Method: external merge Disk` or `Batches: N` on a Hash node. A
  session-level `SET work_mem` bump before an analytics-heavy query is the targeted fix; a
  cluster-wide increase must account for `max_connections × nodes_per_query × work_mem` as a
  worst-case memory ceiling. Conversely, a `work_mem` that's adequate individually can cause OOM
  under high concurrency (verify against the currency brief for your version).

- **CTE materialization fences and planner visibility**: before Postgres 12, every `WITH` clause was
  an optimization fence — materialized once, results opaque to the planner, preventing predicate
  pushdown and join reordering. Postgres 12+ inlines simple non-recursive CTEs unless `MATERIALIZED`
  is explicitly specified. Legacy queries written for the fence behavior (using CTEs intentionally to
  force a step) may silently change plan when run on 12+ without `MATERIALIZED`; conversely,
  pre-12-era code that assumed inlining will not get it. Audit CTEs for which behavior is intended,
  and whether the current version delivers it. Also flag `LATERAL` joins and `DISTINCT ON` as
  Postgres-idiomatic alternatives to correlated subqueries and window-function patterns that may
  deserve a plan check (verify against the currency brief for your version).

- **`NOT IN` with a nullable subquery, and OR-across-columns index defeat**: `NOT IN (SELECT col …)`
  returns zero rows if any value in the subquery is NULL — a silent correctness and performance trap.
  Prefer `NOT EXISTS` which handles NULLs correctly and typically enables an efficient anti-join.
  Separately, `WHERE a = $1 OR b = $2` across two differently-indexed columns usually forces a Seq
  Scan because a single index can't satisfy both branches; a `UNION ALL` of two indexed queries or a
  multicolumn index strategy is the usual fix (cross-reference the **Data access** lane in `../sql.md`
  for general sargability). Also note `= ANY(ARRAY[…])` as the Postgres idiom for `IN (…)` over a
  parameter array — both are index-compatible with the same B-tree.

- **Process-per-connection model and connection pooling**: each Postgres backend is a forked OS process
  (not a thread), carrying its own memory and overhead. High connection counts directly compete for
  shared memory, file descriptors, and lock table entries — `max_connections` is a hard ceiling, not
  a soft limit. At any meaningful concurrency a connection pooler (PgBouncer in transaction mode is
  the standard) is near-mandatory to multiplex application threads onto a smaller pool of backends.
  Also: prepared statements switch from a custom plan (optimized for the first execution's parameter
  values) to a generic plan after roughly 5 executions; for queries with highly skewed data
  distributions, a generic plan can be dramatically worse than a custom one — `plan_cache_mode` lets
  you force custom plans where needed (verify against the currency brief for your version).

- **Function volatility and row-level triggers — the planner reads volatility**: a PL/pgSQL or SQL
  function marked `VOLATILE` (the default) is re-evaluated for every row and is a planner optimization
  barrier — it cannot be folded into an index condition or hoisted. A function that is genuinely
  `STABLE` or `IMMUTABLE` should say so: only then can Postgres use it in an index scan's condition or
  call it once instead of per row, and only `IMMUTABLE` functions can back an expression index. Plain
  SQL functions (vs PL/pgSQL) can also be *inlined* by the planner when simple. Separately, **row-level
  triggers** (`FOR EACH ROW`) fire per affected row on bulk DML — a `FOR EACH STATEMENT` trigger (using
  transition tables) is often the set-based alternative. Check declared volatility on functions used in
  predicates, and whether hot tables carry per-row triggers doing lookups or cascades (verify against
  the currency brief for your version).

- **Data-type storage costs and UUIDv4 index fragmentation**: `jsonb` (binary, indexable, detoast on
  read) vs `json` (stored as text, re-parsed every read) — prefer `jsonb` for any queried or indexed
  JSON. Values wider than ~2 KB are automatically TOAST-ed out-of-line; queries that repeatedly
  detoast large `text`/`jsonb` columns (e.g. selecting a wide column in a high-frequency loop) pay
  decompression cost even when only a sub-key is needed — consider storing frequently-accessed
  sub-keys in their own typed columns. Random UUIDv4 primary keys insert at random B-tree positions,
  causing frequent page splits, poor cache locality, and index bloat; sequential keys (UUIDv7,
  `bigint`/`serial`, or `gen_random_uuid()` on v4 where inserts are low-frequency) avoid this. The
  `numeric` type is arbitrary-precision but significantly slower than `bigint` or `double precision`
  for arithmetic-heavy queries (verify against the currency brief for your version).
