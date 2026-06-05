# JS/TS performance module: Node.js data layer (Prisma / TypeORM / Drizzle / Knex / Mongoose)
> Load when a Node data layer (`@prisma/client`, `typeorm`, `drizzle-orm`, `knex`, `sequelize`, `mongoose`, `pg`, `mysql2`, `ioredis`) is detected — see the module map in `../javascript-typescript.md`. Core lanes + Runtime notes live in `../javascript-typescript.md`; this file is the Node.js data layer lens only.

## Node.js data layer (Prisma / TypeORM / Drizzle / Knex / Mongoose)

> Scope: all patterns that touch `pg.Pool`, `mysql2` connection pools, ORM connection config,
> Mongoose connections, or the `ioredis` client. The recurring themes are: **share the pool** (one
> shared pool instance, not one per request), **batch to cut round-trips** (N+1 is the dominant
> latency killer at every ORM layer), **project and `.lean()` what you read** (hydration and
> over-fetch inflate memory and latency on read-heavy paths), and **read the generated query** (the
> ORM abstracts the SQL — `EXPLAIN` or ORM query logging is the only way to confirm cost before
> diagnosing). Cross-reference the core **Data access & I/O** lane for generic N+1/over-fetch/bulk
> basics, and the `node-backend` module for event-loop and concurrency interactions.

- **Pool opened per request instead of shared at module scope**: `pg.Pool`, `mysql2.createPool`,
  and Mongoose/TypeORM/Prisma connections are designed to be constructed once at startup and shared
  for the process lifetime. Constructing a new pool (or calling `$connect()` / `createConnection`)
  inside a request handler pays TCP + TLS + auth overhead on every call, bypasses pool reuse
  entirely, and leaks connections when `end()`/`destroy()` is omitted on error paths. Look for pool
  or client construction inside route handlers, middleware, or Lambda handlers (cross-reference the
  **Concurrency** lane for the goroutine/async-task leak analogue) (verify against the currency
  brief for your version).

- **Pool defaults left unconfigured under load — exhaustion or idle churn**: `pg.Pool` defaults
  (`max: 10`, no `idleTimeoutMillis` or `connectionTimeoutMillis`) and ORM equivalents (Prisma
  `connection_limit`, TypeORM `extra.max`, Sequelize `pool.max`) are conservative baselines that
  saturate quickly under moderate concurrency. A pool that is too small queues requests; one with
  no idle timeout churns TCP handshakes on every cold slot. Look for pools whose `max` is never
  set explicitly, for missing `idleTimeoutMillis` (connections held until NAT/LB kills them), and
  for missing `connectionTimeoutMillis` (requests block indefinitely when the pool is dry). Set
  all relevant parameters explicitly and verify they match the database's `max_connections` budget
  (verify against the currency brief for your version).

- **Serverless connection storms — new pool per invocation without a proxy**: in Lambda/Cloud
  Functions the process is short-lived, so a cold invocation opens a fresh database connection.
  Under burst concurrency, hundreds of invocations open hundreds of connections simultaneously —
  the database `max_connections` ceiling is hit long before CPU is a constraint. Look for direct
  `pg.Pool`/Prisma/TypeORM connections inside serverless handlers with no RDS Proxy, PgBouncer, or
  Prisma Data Proxy in front; look also for Prisma's default `connection_limit` (which sizes to CPU
  count and can be far too high in a many-replica serverless fleet). The fix is a connection pooler
  that multiplexes, not code that limits pool size alone (verify against the currency brief for
  your version).

- **N+1 from ORM relation loading beyond generic eager/lazy**: Prisma's `findMany` without
  `include` is safe, but calling `findMany` (or `findUnique` for each parent's ID) *inside a loop*
  is N+1 invisible to the ORM — look for `prisma.*.find*` calls nested inside `for`/`map` over a
  result set. TypeORM lazy relations (`@OneToMany` with `lazy: true`) fire a database query on
  property *access*; if the entity is accessed in a loop the relation resolves N times — the
  symptom is deferred async queries after the initial load. Mongoose `populate()` issues a *second*
  query per populated path; chaining `.populate('a').populate('b')` produces two extra queries per
  document, and calling `populate` inside a `for` loop of documents is N×paths queries. Use
  `dataloader`-style batching for GraphQL resolvers that call any ORM per-node (cross-reference
  the core **Data access & I/O** N+1 bullet).

- **Over-fetching and missing projection / `.lean()`**: Prisma exposes `select` and `omit` to
  project only needed fields at the query level — a `findMany` with no `select` on a wide table
  deserialises every column. TypeORM `find` with no `select` option does the same. Mongoose
  `.find()` without a projection (second argument or `.select(…)`) returns full BSON documents;
  chaining `.lean()` returns plain JavaScript objects, skipping the full Mongoose document
  hydration (virtuals, method attachment, change-tracking overhead) — on read-heavy paths with
  large result sets this is a large, low-risk speedup. Flag any Mongoose read path that is not
  followed by `.lean()` when the result is not modified before response (verify against the
  currency brief for your version).

- **Query shape hidden by the ORM — missing indexes, deep `OFFSET`, costly `count`**: the ORM
  emits SQL (or a query plan) the developer may never see. Filtering or sorting on unindexed
  columns, `skip(N)` / `OFFSET N` deep pagination (scans and discards N rows — replace with
  keyset pagination anchored on the last seen cursor value), and `count()` on large Mongo
  collections or SQL tables can each dominate latency while appearing as a single ORM call.
  Diagnostic path: enable Prisma query logging (`log: ['query']`), TypeORM `logging: true`, or
  Mongoose `mongoose.set('debug', true)`; then run `EXPLAIN ANALYZE` (Postgres/MySQL) or
  `cursor.explain('executionStats')` (MongoDB) on the emitted query. Push the audit to read the
  actual query before inferring cost. Use `$queryRaw` / `createQueryBuilder` / raw aggregation
  pipelines as the escape hatch for hot queries the ORM cannot express efficiently (verify against
  the currency brief for your version).

- **Bulk writes as per-row inserts in a loop**: inserting or updating rows one at a time — a
  `prisma.*.create(…)` or `Model.save()` or `repository.save(entity)` in a `for` loop — pays one
  round-trip and one statement parse per row. Replace with `prisma.*.createMany` / Sequelize
  `bulkCreate` / Mongoose `Model.insertMany` / TypeORM `repository.insert([…])` for inserts, and
  `prisma.$transaction([…writes])` to batch heterogeneous mutations in a single round-trip. For
  Redis, replace per-key `set`/`get` calls in a loop with `ioredis` `pipeline()` (fire-and-forget
  pipelining) or `mget`/`mset` (verify against the currency brief for your version).

- **Mongoose schema-level middleware and virtuals on large result sets**: Mongoose `pre`/`post`
  hooks (`save`, `find`, `findOne`) and virtuals run per-document on hydrated results. A `find`
  that returns 500 documents with three `post` hooks and two virtuals executes those callbacks
  2 500 times — visible when profiling as synchronous JS CPU time proportional to result-set size,
  not query latency. Look for `findMany`-style queries with no `lean()` that also have schema-level
  middleware on the model; `.lean()` bypasses hooks and virtuals entirely and is the correct choice
  when mutation or virtual access is not needed post-query (cross-reference the over-fetching
  bullet above).

- **ioredis per-call round-trips and per-request client construction**: each `client.get(key)`
  incurs a full TCP round-trip; a handler that calls `get` or `set` five times in sequence pays
  five serial round-trips. `pipeline()` enqueues multiple commands and sends them in one write, so
  the server processes and responds in a single round-trip; `multi()` wraps them in a MULTI/EXEC
  transaction when atomicity is needed. Also look for a new `new Redis(…)` constructed inside the
  request handler — ioredis connections should be a single shared module-level client (or a small
  cluster client) for the process lifetime, not a per-request socket (verify against the currency
  brief for your version).
