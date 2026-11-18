# Rust performance module: Database access (sqlx / diesel / sea-orm / tokio-postgres)
> Load when a Rust database layer is detected — `sqlx`, `diesel`, `sea-orm`, `tokio-postgres`, `deadpool`, `redis` — see the module map in `../rust.md`. Core lanes + Runtime & build notes live in `../rust.md`; this file is the Database access lens only.

## Database access (sqlx / diesel / sea-orm / tokio-postgres)

> Scope: all patterns touching `sqlx::Pool`, `diesel::r2d2::Pool`, `deadpool_postgres::Pool`,
> `sea_orm::DatabaseConnection`, or `redis::aio::MultiplexedConnection`. The recurring themes are:
> **share the pool** (it is a cheap `Arc` clone — build once, share everywhere), **batch to cut
> round-trips** (N+1 is the dominant latency killer in any Rust async service), **stream large
> results** rather than materialising them into a `Vec`, **keep transactions short** (a live
> transaction holds a pooled connection and DB locks for its entire lifetime), and **never block
> the executor with a sync driver**. Bullets are *conditions to look for*; cross-reference the
> core **Data access & I/O** and **Concurrency** lanes in `../rust.md` for the language-level
> analogues, the `../rust/async-tokio.md` sibling for executor-blocking footguns, and — where
> hand-written SQL is in scope — `../sql.md` plus its relevant dialect module.

- **Pool built per-request or per-task instead of shared**: `sqlx::Pool`, `deadpool_postgres::Pool`,
  and `diesel::r2d2::Pool` each embed an `Arc` — cloning the pool handle is the intended sharing
  mechanism. Constructing a fresh pool per request bypasses the pool entirely, paying connection
  establishment (TCP, TLS, auth, protocol handshake) on every call and leaking descriptors when
  the pool is not explicitly closed. The signal to look for is `Pool::connect` / `Pool::new` /
  `r2d2::Builder::build` called inside a handler, a `tokio::spawn` closure, or a per-request
  function rather than at application startup (verify against the currency brief for your version).

- **Pool limits left at defaults under real load**: `sqlx` defaults `max_connections` to 10 and
  `min_connections` to 0; deadpool's default `max_size` is also small; r2d2 defaults to 10 max.
  Under burst traffic the pool exhausts and callers queue (or timeout); raising it beyond the
  database's own connection limit merely shifts the bottleneck and wastes server memory. Also look
  for missing `idle_timeout` / `max_lifetime` settings — without them, idle connections persist
  indefinitely and stale after a proxy or firewall reset (verify against the currency brief for
  your version).

- **N+1 in the Rust async idiom — queries inside loops or `join_all`**: issuing a `sqlx::query`
  (or a sea-orm `find` / diesel `load`) per item — whether in a `for` loop, a `.map(|id| async
  move { query… })` collected into `FuturesUnordered`, or a naïve `join_all` of per-item futures
  — multiplies round-trips linearly with the result set. Replace with a single batched query
  (`WHERE id = ANY($1)` with a `Vec` argument on Postgres, or `WHERE id IN (…)` on other
  databases); for sea-orm/diesel relation loading, look for per-row `.find_related()` or
  `.belonging_to()` calls that trigger a query per parent row instead of a single IN-batched load.
  A `dataloader`-pattern crate can batch across concurrent callers (verify against the currency
  brief for your version).

- **`sqlx::query!` / `query_as!` build-time coupling vs. runtime flexibility trade-off**: the
  compile-time macros verify SQL against a live database at compile time (requiring `DATABASE_URL`
  in the environment) or against a cached schema snapshot via `sqlx prepare` / the `.sqlx/`
  directory. This catches type mismatches and typos before runtime but couples every `cargo build`
  to database availability and adds prepare round-trips to incremental build time. The runtime
  `sqlx::query` / `query_as` variants skip the check. The condition to look for is a mismatch
  between the team's constraint (CI without a live DB, fast incremental builds) and which form is
  used — neither is universally better (verify against the currency brief for your version).

- **Dynamic SQL strings defeating prepared-statement caching**: sqlx caches prepared statements
  per connection using the query string as the cache key. A query whose shape is built with
  `format!` — embedding variable table names, dynamic column lists, or values directly into the
  string — produces a different key on every variation and forces a re-prepare cycle. The correct
  pattern is a fixed query shape with `$1`, `$2`, … (Postgres) or `?` (MySQL/SQLite) bind
  parameters; binding values through the parameter list also closes the SQL-injection surface.
  Look for `format!("… WHERE id = {}", id)` passed to `sqlx::query` on any hot path (verify
  against the currency brief for your version).

- **Sync diesel blocking the async executor**: diesel's built-in interface is synchronous — a
  diesel call inside a `tokio::spawn` or an `async fn` blocks the executor thread for the full
  DB round-trip, starving other tasks on that thread. The remedies are: wrap with
  `tokio::task::spawn_blocking`, use the `diesel-async` crate (which provides async-native
  interfaces over the same diesel query builder), or migrate the data layer to sqlx/sea-orm. The
  signal is a `diesel` import *and* an async runtime without any `spawn_blocking` boundary around
  the DB calls (cross-reference `../rust/async-tokio.md` for the general executor-blocking lane;
  verify against the currency brief for your version).

- **`fetch_all` materialising large result sets into a `Vec`**: `sqlx::query().fetch_all(&pool)`
  collects every matching row into a heap-allocated `Vec` before returning — on large exports,
  paginated scans, or administrative queries this causes a memory spike proportional to the result
  set. `fetch(&pool)` returns a `Stream` of rows that can be processed incrementally, bounding
  memory to a single row (or a small read-ahead buffer). Look for `fetch_all` on queries without
  a tight `LIMIT` on paths that could receive large or unbounded result sets (cross-reference the
  core **Memory** lane in `../rust.md`; verify against the currency brief for your version).

- **Transaction held across `.await` on external I/O or heavy computation**: a `sqlx::Transaction`
  (or diesel `Connection` in a transaction) holds one connection from the pool and, on the
  database side, holds row or page locks for its entire lifetime. Awaiting an HTTP call, a
  message-queue publish, or a CPU-heavy step between `begin_transaction` and `commit` drains the
  pool for other callers and extends lock duration. Look for `.await` on non-DB futures — or
  unbounded iteration — between transaction begin and commit; restructure so external I/O happens
  before or after the transaction, and ensure `rollback` is called on all error paths (a dropped
  `sqlx::Transaction` rolls back implicitly but relying on `Drop` can obscure logic; prefer
  explicit `commit`/`rollback`). Cross-reference the core **Concurrency** and **Data access**
  lanes in `../rust.md` (verify against the currency brief for your version).

- **redis-rs per-command round-trips and connection-per-call patterns**: issuing individual
  `cmd("GET")` / `cmd("SET")` calls in a loop sends one network round-trip per command. Use
  `redis::pipe()` (pipelining) or multi-key commands (`MGET` / `MSET`) to amortise latency.
  Separately, opening a new connection per call (via `Client::get_connection` or
  `Client::get_async_connection`) pays TCP/TLS overhead every time; prefer a
  `MultiplexedConnection` (single connection, concurrent in-flight commands) or a pool via
  `deadpool-redis` / `bb8-redis`. Also look for redis usage where the cached value is cheaper to
  recompute locally than to serialise, send, receive, and deserialise over the wire — the
  round-trip cost is not free (verify against the currency brief for your version).
