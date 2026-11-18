# Go performance module: Database access (database/sql / pgx / GORM / sqlx / sqlc)
> Load when `database/sql`, `github.com/jackc/pgx`, `gorm.io/gorm`, `github.com/jmoiron/sqlx`,
> `sqlc`, or `github.com/lib/pq` is detected — see the module map in `../go.md`. Core lanes +
> Runtime & GC notes live in `../go.md`; this file is the Database access lens only.

## Database access (database/sql / pgx / GORM / sqlx / sqlc)

> Scope: all patterns that touch `*sql.DB`, `pgxpool.Pool`, GORM's `*gorm.DB`, sqlx's `*sqlx.DB`,
> or the generated code from sqlc. The recurring themes are: **pool reuse** (the pool is the unit of
> connection management — open it once, share it everywhere), **batching to cut round-trips** (N+1
> is the dominant latency killer), **scanning only what's needed** (over-fetch inflates I/O and GC
> pressure), and **context cancellation** (every query should be cancellable so a dropped client
> doesn't hold a DB connection open). Bullets are *conditions to look for*; cross-reference the
> core **Data access & I/O** lane for the generic analogues and the **Concurrency** lane for
> pool-exhaustion and goroutine-leak interactions.

- **`*sql.DB` opened per request instead of shared**: `*sql.DB` is a goroutine-safe connection pool
  meant to be constructed once at startup and shared across the application for its lifetime.
  Opening a new `sql.Open` (or `pgxpool.New`) per request or per handler bypasses the pool
  entirely, pays connection-establishment overhead on every call, and leaks file descriptors if
  `Close` is forgotten (cross-reference the **Concurrency** lane: each leaked connection holds an
  OS-level socket and a goroutine waiting on it).

- **Pool defaults left unconfigured — exhaustion or idle-churn**: `*sql.DB` defaults leave
  `MaxOpenConns` unlimited (runaway connection count under burst load) and `MaxIdleConns` at a
  small value (idle connections closed and re-opened on the next request, incurring TCP + TLS +
  auth overhead). Look for missing calls to `SetMaxOpenConns`, `SetMaxIdleConns`,
  `SetConnMaxLifetime`, and `SetConnMaxIdleTime`; through a proxy or PgBouncer, stale conns with
  no lifetime cap cause silent errors. Set all four explicitly for any production workload
  (verify against the currency brief for your version).

- **N+1 queries — per-row `Query` inside a `range` loop**: issuing a separate `db.QueryContext`
  per item (e.g., loading each user's profile inside a `for _, id := range ids` loop) multiplies
  round-trips linearly with the result set. Replace with a single batched query (`WHERE id =
  ANY($1)` with a `pgtype`/pq array arg, or `IN (...)`) for reads; use `pgx.Batch` for
  heterogeneous statements; use `pgx.CopyFrom` for bulk inserts (cross-reference the **Data
  access & I/O** lane N+1 bullet). With GORM, look for `Find` or `First` inside a loop and for
  missing `Preload` on associations that trigger a query per parent row.

- **`rows.Close()` not deferred — connection leak under errors**: a `*sql.Rows` holds its
  underlying connection until `Close` is called. If the calling code returns early on an error
  without closing (or without fully iterating to `io.EOF`), that connection is stuck until the
  `ConnMaxLifetime` expires or the pool is exhausted. Always `defer rows.Close()` immediately
  after checking the `Query` error, and always check `rows.Err()` after the iteration loop — an
  interrupted scan leaves `rows.Err()` set. The same applies to `pgx.Rows` (verify against the
  currency brief for your version).

- **Queries without context — uncancellable DB work**: `db.Query` / `db.Exec` without a context
  keep the query running on the server even after the HTTP handler's `ResponseWriter` has
  returned, the client has disconnected, or the service is shutting down. Prefer
  `db.QueryContext(ctx, ...)` and `db.ExecContext(ctx, ...)` threaded from the request context
  (`r.Context()` or a derived context with a deadline), so the DB driver can cancel the in-flight
  statement when the context is cancelled (cross-reference the **Concurrency** lane: context
  propagation is the canonical Go cancellation contract).

- **GORM over-fetch and missing `Select` / `Preload` vs `Joins` confusion**: GORM's `Find` with
  no `Select` fetches all columns, inflating I/O and scan work on wide tables. `Preload` issues a
  *second* query for each association (one `IN (...)` per level), which compounds to N+1 across
  nested or repeated associations; `Joins` folds the association into a single SQL `JOIN` but
  returns only the root model columns unless `Select` is explicit. GORM also runs hooks and does
  reflection per row — on paths called at high QPS, switch to raw `database/sql`/pgx or sqlc-
  generated code (verify against the currency brief for your version).

- **Prepared statement churn vs reuse**: `db.QueryContext` re-parses and re-plans the query on
  every call in many drivers. For queries executed at high frequency, `db.PrepareContext` amortises
  the parse/plan cost — but with `database/sql`, a `*sql.Stmt` is re-prepared on each connection
  in the pool transparently, so pool size × prepare overhead matters. With pgx native (`pgxpool`),
  the extended query protocol and statement cache differ; understand the cache-hit behaviour before
  assuming prepare is free. sqlc-generated code uses `$N` placeholders and pairs well with pgx
  statement caching (verify against the currency brief for your version).

- **`lib/pq` instead of pgx on Postgres — missing binary protocol and batch support**: `lib/pq`
  is in maintenance mode and uses the text wire protocol; `github.com/jackc/pgx` uses the binary
  protocol (no text encode/decode round-trip for numerics, timestamps, UUIDs), supports `pgx.Batch`
  for sending multiple statements in a single round-trip, and `pgx.CopyFrom` for high-throughput
  bulk inserts. For greenfield Postgres work or any hot path, prefer pgx native (`pgxpool.Pool`)
  or the pgx `database/sql` adapter; audit remaining `lib/pq` imports as candidates for migration
  (verify against the currency brief for your version).

- **Transactions held open across network I/O or user latency**: a `*sql.Tx` (or `pgx.Tx`) holds
  one connection from the pool for its entire duration and acquires row locks on the database.
  Long-held transactions caused by performing HTTP calls, user prompts, or unbounded computation
  between `BeginTx` and `Commit`/`Rollback` drain the pool (cross-reference the **Concurrency**
  lane: pool exhaustion manifests as goroutines blocked on `db.BeginTx`). Look for transactions
  that span more than pure DB work, and for missing `defer tx.Rollback()` guards that leave
  transactions uncommitted on error paths (verify against the currency brief for your version).
