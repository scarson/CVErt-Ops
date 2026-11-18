# .NET performance module: Data access — SQL Server (EF6 / EF Core / ADO.NET / Dapper)
> Load when EF6/EF Core (etc.) is detected — see the module map in `../dotnet.md`. Core lanes + Variant notes live in `../dotnet.md`; this file is the Data access — SQL Server (EF6 / EF Core / ADO.NET / Dapper) lens only.

## Data access — SQL Server (EF6 / EF Core / ADO.NET / Dapper)

> High-value focus for database-driven enterprise apps. Bullets are *conditions to look
> for* in application/query code (not DBA tasks). Be precise about API attribution:
> `AsNoTracking` exists in **both** EF6 and EF Core, but `AsSplitQuery` /
> `AsNoTrackingWithIdentityResolution` / `ExecuteUpdate` / `ExecuteDelete` /
> `AddDbContextPool` / compiled models / automatic `SaveChanges` batching are **EF Core
> only**. EF6 has none of those — its bulk story is third-party (EFCore.BulkExtensions is
> EF Core; for EF6 use **EFUtilities**, **EntityFramework.Extended**, or drop to
> `SqlBulkCopy` / TVPs / stored procs). Cross-reference the ORM and data-access entries in
> the version index.

### N+1 & loading strategy
- **Lazy-loading a navigation property inside a loop** fires one SQL query per iteration
  (the classic N+1). Both EF6 and EF Core: replace with eager `.Include()` or a projection.
  EF6 lazy loading is on by default for `virtual` navigations + a proxy-enabled context;
  EF Core requires the `Microsoft.EntityFrameworkCore.Proxies` package + `UseLazyLoading`
  (or a lazy-loading service injection) — but explicit `.Load()` in a loop reproduces N+1
  in either (verify against the currency brief for your version).
- **Explicit loading (`.Entry(e).Collection/Reference(...).Load()`) inside a loop** is N+1
  by another name; batch the parent keys and load related data with a single query or
  projection instead.
- **Cartesian explosion from multiple collection `.Include()`s**: each one-to-many `Include`
  multiplies rows (each blog row duplicated per post, etc.), inflating the result set and
  network/materialisation cost. EF Core: `AsSplitQuery()` issues one SQL statement per
  collection instead of a join (**EF Core 5.0+**; note it round-trips per query and
  buffers all-but-last result set unless MARS is on). EF6 has **no** split-query API —
  break the load into multiple explicit queries (verify against the currency brief for
  your version).
- **Materialising full entities when only a few columns are used**: project to a DTO with
  `.Select(...)` so EF emits a narrow `SELECT` and skips entity tracking/fixup. A projection
  that pulls only the needed columns also lets a covering index satisfy the query.
- **Loading a whole graph to read one related value**: prefer projecting the single value
  (`.Select(b => b.Posts.Count)` etc.) over `Include`-ing the whole collection.

### Change tracking & SaveChanges
- **Tracking on read-only queries**: the change tracker snapshots every materialised entity
  (memory + CPU). Add `AsNoTracking()` (both EF6 and EF Core) for queries whose results are
  never modified+saved. EF Core only: `AsNoTrackingWithIdentityResolution()` (**EF Core
  5.0+**) when you need no-tracking speed but still want related entities de-duplicated in
  the result graph (verify against the currency brief for your version).
- **`DetectChanges` is O(n) over all tracked entities** and is triggered implicitly by
  `Add`/`Remove`/`Find`/`Entry`/`SaveChanges`. In a large insert/update loop this becomes
  O(n²). Set `Configuration.AutoDetectChangesEnabled = false` (EF6) /
  `ChangeTracker.AutoDetectChangesEnabled = false` (EF Core) around the loop and re-enable
  after — or use `AddRange`/`RemoveRange`, which pay the `DetectChanges` cost once for the
  whole set instead of per entity.
- **A long-lived / accumulating `DbContext`**: the more entities tracked, the slower every
  `DetectChanges` and the larger the memory footprint. Use a short, per-unit-of-work /
  per-request `DbContext` lifetime; do not cache a context across requests. (EF Core:
  `AddDbContextPool` reuses *cleared* instances to skip per-request model init — **EF Core
  2.0+** — but does not change the per-context tracking-accumulation rule; ensure no
  request-scoped state leaks between pooled instances.)
- **EF6 `SaveChanges` issues one server round-trip per affected row** — no statement
  batching. For large writes this is a major latency sink; use `SqlBulkCopy`, table-valued
  parameters, a stored proc, or a third-party EF6 bulk library (EFUtilities /
  EntityFramework.Extended) instead of a per-row `Add` + `SaveChanges` loop.
- **EF Core batches `SaveChanges` automatically** into multi-statement round-trips (default
  cap ~42 statements/batch for SQL Server; batching is skipped when <4 statements as it
  isn't a win there). Tune with `MinBatchSize`/`MaxBatchSize` on the SQL Server options
  only with measurement. Still, even batched, EF Core sends one `UPDATE`/`DELETE` per
  entity — see the bulk-mutation bullet below (verify against the currency brief for your
  version).
- **Load-mutate-`SaveChanges` for bulk mutations (EF Core)**: replace with `ExecuteUpdate` /
  `ExecuteDelete` / `ExecuteUpdateAsync` / `ExecuteDeleteAsync` (**EF Core 7.0+**) — a
  single server-side `UPDATE`/`DELETE` over a predicate, no entity loading, no tracking.
  **EF6 has no equivalent** — use `Database.ExecuteSqlCommand` with parameterised raw
  SQL/stored proc (verify against the currency brief for your version).

### Query translation & plan reuse
- **Client-side evaluation of a predicate EF can't translate**: in **EF Core** an
  untranslatable `Where`/`OrderBy` in the server-evaluable part of a query **throws by
  default** (since EF Core 3.0) — but a predicate moved after `AsEnumerable()`/`ToList()`
  silently filters in memory after pulling all rows. **EF6 silently degrades**: it pulls
  rows and filters client-side without warning. Flag any LINQ predicate using a method EF
  can't translate (custom C# methods, non-mapped properties) feeding a large table.
- **Ad-hoc / string-concatenated SQL pollutes the SQL Server plan cache**: SQL Server
  matches cached plans **character-for-character**, so each distinct literal string forces
  a fresh compile and a new (low-value, evictable) ad-hoc plan entry, bloating the cache
  and starving reusable plans. EF, Dapper, and `sp_executesql` parameterise automatically;
  **raw `SqlCommand` built by string concatenation must use `SqlParameter`s** (also closes
  SQL injection). Flag `"... WHERE x = '" + value + "'"`-style command text.
- **Varying IN-clause / parameter-list length generates distinct cached plans**:
  `.Where(x => ids.Contains(x.Id))` produces a different parameter count per call, so each
  list size is a separately-compiled plan (cache churn). EF6 is especially affected (it
  also can't cache `Contains` over an in-memory collection at all — the values are treated
  as volatile and the query recompiles every call, slower with larger lists). EF Core 8/9
  used `OPENJSON`; **EF Core 10** parameterises the IN-list with EF-side padding to bound
  plan proliferation. Prefer a **TVP** or a temp-table join for large/variable sets (verify
  against the currency brief for your version).
- **`Skip`/`Take`/`Contains`/`DefaultIfEmpty` inline their arguments as constants (EF6)** —
  not parameters — so otherwise-identical paged queries pollute both the EF and SQL Server
  plan caches per distinct value. A known EF6 plan-cache pitfall; prefer parameterised
  shapes where possible (verify against the currency brief for your version).
- **Dynamically-built LINQ with a constant Expression node** recompiles every call and
  pollutes the DB plan cache; build the dynamic expression with a **parameter** node so the
  tree shape (and SQL) is stable. (EF Core query-cache hit rate staying below ~100% after
  warm-up is the diagnostic signal.)
- **Hot, identically-shaped queries**: pre-compile to skip the cache lookup. EF Core:
  `EF.CompileQuery` / `EF.CompileAsyncQuery` (**EF Core 2.0+**, scalar params only, single
  model). LINQ-to-SQL: `CompiledQuery.Compile`. **EF6 auto-caches** LINQ-to-Entities plans
  ("autocompiled queries", since EF5) so explicit `CompiledQuery` gives little extra and is
  **ObjectContext-only** (not `DbContext`) — rarely worth it on EF6 (verify against the
  currency brief for your version).

### SQL Server sargability & implicit conversions (app-side, high-ROI)
- **The classic EF6 `nvarchar`-vs-`varchar` implicit conversion**: EF6 maps `string` to
  **`nvarchar`** by default, so a `Where(x => x.Code == s)` against a `varchar`-typed,
  indexed column sends an `nvarchar` parameter → SQL Server applies an **implicit
  conversion that defeats the index seek and forces a scan**. Fix by mapping the property
  non-Unicode: `[Column(TypeName = "varchar")]` / Fluent `.IsUnicode(false)` (EF6 and EF
  Core both honour this). One of the highest-ROI, easily-missed findings on legacy EF6
  schemas with `varchar` keys (verify against the currency brief for your version).
- **Non-sargable predicates built in LINQ that wrap the column in a function**: e.g.
  `Where(x => x.Date.Year == 2025)` → `WHERE YEAR(col) = …`, `Where(x => x.Name.ToUpper()
  == v)` → `WHERE UPPER(col) = …`, or any computed expression on the column. The function
  on the column side prevents an index seek (full scan instead). Rewrite as a range
  (`x.Date >= start && x.Date < end`) or rely on a case-insensitive collation rather than
  `ToUpper`/`ToLower`.
- **Leading-wildcard `LIKE '%term'`** (from `Contains`/`EndsWith`) cannot use a B-tree
  index seek — full scan. Flag on large tables; consider full-text search or a redesigned
  predicate. (`StartsWith` → `LIKE 'term%'` *is* sargable.)
- **Parameter type/length mismatch generally**: a parameter whose CLR/SQL type or length
  differs from the column (e.g. wider `nvarchar(4000)` parameter vs `varchar(50)` column,
  `int` vs `bigint`) can trigger an implicit conversion and a scan. Verify EF mappings and
  hand-written `SqlParameter` types/sizes match the column definition.

### Round-trips, sets & paging
- **Row-by-row (RBAR) operations** — a loop issuing one `INSERT`/`UPDATE`/`DELETE` per row —
  vs a single set-based statement. Flag per-row DML loops; prefer set-based SQL,
  `ExecuteUpdate`/`ExecuteDelete` (EF Core 7+), or `SqlBulkCopy`/TVP for writes.
- **Table-Valued Parameters (TVPs)** pass an entire set to the server in **one round-trip**
  (as a `SqlDbType.Structured` parameter / EF Core raw SQL) — prefer over many individual
  calls or huge/variable IN-lists. TVPs also give the optimiser real cardinality and a
  stable plan shape.
- **Missing pagination pulling whole tables**: any unbounded query that could grow
  unboundedly should page. Offset paging (`Skip(n).Take(m)` → `OFFSET … FETCH`) re-scans
  `n` rows per page and degrades deep into the set; prefer **keyset/cursor pagination**
  (`WHERE key > @last ORDER BY key`) for production volumes.
- **`SELECT *` / over-fetching** materialises columns you don't use and **defeats covering
  indexes** (the engine can't satisfy the query from a narrow index and must look up the
  base rows). Project only needed columns.
- **`MultipleActiveResultSets=True` (MARS)** lets multiple readers share one connection
  (and EF Core relies on it to avoid buffering all-but-last result set in split queries),
  but it adds overhead and has interleaving/transaction gotchas — enable intentionally, not
  reflexively.
- **Multiple separate round-trips that could be one batch**: Dapper `QueryMultiple` (and
  raw `SqlDataReader.NextResult()`) return several result sets from a single command —
  batch related reads instead of N separate `Query` calls.

### ADO.NET & connections
- **Buffering a whole `DataSet`/`DataTable` for a large read** vs streaming a forward-only
  `SqlDataReader` (the reader is unbuffered — data isn't cached in memory). For large
  BLOB/CLOB columns add `CommandBehavior.SequentialAccess` so wide columns stream via
  `GetBytes`/`GetChars` rather than buffering the whole row.
- **Row-by-row inserts** → use **`SqlBulkCopy`** for bulk load (orders of magnitude faster
  for large batches; works on Framework and modern .NET).
- **Connection-pool fragmentation / defeat**: a pool is keyed by the **exact connection
  string** — strings that differ even slightly (different `Application Name`, integrated-
  security identity, or per-database `master`-then-`USE` patterns) spawn **separate pools**
  and waste connections. Keep connection strings byte-identical. Default `Max Pool Size` is
  100 and a connection request blocks up to ~15 s when the pool is exhausted, then throws —
  a leaked (un-disposed) connection silently shrinks usable pool capacity.
- **Not disposing connections/commands/readers**: a `SqlConnection` not closed via
  `using`/`Dispose` is not returned to the pool; under load this exhausts the pool and
  causes timeout exceptions. Always `using` connections, commands, and readers.
- **Holding connections open longer than needed / opening early**: open the connection as
  late as possible and close (return to pool) as early as possible; don't open a connection
  then do CPU work or call other services while holding it.
- **Synchronous DB calls on async request paths**: use `OpenAsync`/`ExecuteReaderAsync`/
  `ExecuteNonQueryAsync` to free the thread during I/O. EF6 async exists **since EF6.0** (on
  .NET 4.5+); flag sync EF6 calls on async paths.
- **Missing `CommandTimeout`**: relying on the default (30 s) for a heavy report query
  causes spurious failures; for a query that should be fast, a too-long timeout masks a
  runaway plan — set intentionally.

### Transactions & isolation
- **Long-running transactions hold locks and block other sessions**: keep transactions
  short; never wrap user think-time, external HTTP calls, or large client-side processing
  inside an open transaction. Flag a `TransactionScope`/`BeginTransaction` that spans
  network I/O or a long loop.
- **Default `READ COMMITTED` lock-based blocking** under write contention: read queries
  block behind writers' locks. **Read Committed Snapshot Isolation (RCSI)** serves readers
  from row-versions (no shared-lock blocking) — a database-level setting, but worth
  flagging from app code that shows reader/writer blocking; do not silently rely on it being
  on.
- **`TransactionScope` silently escalating to MSDTC (distributed transaction)**: when more
  than one connection (or another resource manager) enlists in the same ambient
  `TransactionScope`, it promotes to a **distributed transaction via MSDTC** — a large,
  easily-overlooked latency and locking cost, and a frequent prod failure when MSDTC isn't
  configured. Flag a `TransactionScope` that opens two `SqlConnection`s (even to the same
  server on older clients). (Modern SqlClient supports local→distributed promotion only when
  truly needed; keep it to a single connection to stay local.)
- **`NOLOCK` / `READ UNCOMMITTED` used "for performance"**: gives dirty reads, missing/
  duplicated rows, and read-skew — a **correctness hazard, not a perf technique**. Flag its
  presence (table hints in raw SQL, `IsolationLevel.ReadUncommitted` scopes); do not
  recommend it. The right fix for reader/writer blocking is RCSI, not `NOLOCK`.

### Dapper
- **Buffered by default**: `Query<T>` materialises the entire result set into a `List<T>`
  before returning. For very large streams pass `buffered: false` to stream rows lazily
  (lower peak memory; keeps the reader/connection open while enumerating).
- **Parameterise — never concatenate**: pass parameters via anonymous objects /
  `DynamicParameters` so commands are parameterised (plan reuse + injection-safe). Flag
  interpolated/concatenated SQL passed to Dapper.
- **IN-list expansion**: Dapper expands `IEnumerable<int>` parameters into
  `(@p1,@p2,…)` — convenient, but a different collection size yields a different SQL string
  and thus a distinct cached plan (same plan-churn caveat as EF). Prefer a TVP for
  large/highly-variable sets.
- **`QueryMultiple` for batching**: read several result sets from one command instead of
  several separate round-trips; combine with multi-mapping (`splitOn`) to hydrate related
  objects in a single query.
