# Section 2: Database & Query Patterns

> **Reader context:** "I'm writing store methods, migrations, or SQL queries."

---

### DB-1 EPSS Unconditional UPDATE Writes 250k Dead Tuples Daily

**The Flaw:** The EPSS adapter issues `UPDATE cves SET epss_score = $1, date_epss_updated = now() WHERE cve_id = $2` for every row in the daily CSV feed.

**Why It Matters:** The EPSS CSV feed contains ~250,000 rows daily. Postgres MVCC writes a new physical tuple on every UPDATE — even when the value is identical to the stored value. Unconditional updates create 250,000 dead tuples per day while 99% of scores are unchanged. The EPSS rule evaluator uses `date_epss_updated > last_cursor` to find CVEs with changed data; bumping this timestamp for unchanged scores forces it to re-evaluate all 250,000 CVEs against every active alert rule daily, for zero benefit.

**The Fix:** Use `IS DISTINCT FROM` to make the write conditional:
```sql
UPDATE cves
SET epss_score = $1, date_epss_updated = now()
WHERE cve_id = $2 AND epss_score IS DISTINCT FROM $1
```
`IS DISTINCT FROM` is NULL-safe: `NULL IS DISTINCT FROM 0.5` -> true (write proceeds); `NULL IS DISTINCT FROM NULL` -> false (write suppressed). Only genuinely changed scores write a new tuple.

**The Lesson:** In Postgres, every UPDATE on a row writes a new physical tuple via MVCC — even if the value being set is identical to the current value. For high-frequency enrichment feeds that touch hundreds of thousands of rows daily, always use `WHERE col IS DISTINCT FROM new_value` to suppress no-op writes. This pattern applies to any column used as a cursor for downstream processing.

---

### DB-2 FTS GIN Index Write Churn from High-Frequency Column Updates

**The Flaw:** The initial design put `fts_document tsvector` directly on the `cves` table alongside canonical fields that are updated frequently (timestamps, epss_score).

**Why It Matters:** Postgres MVCC writes a new physical row tuple on every UPDATE to any column. The `cves` table is updated frequently — timestamps on every ingestion, `epss_score` on every daily EPSS run. Every such update forces GIN index maintenance for `fts_document`, even when the text content hasn't changed. GIN indexes are expensive to update. At scale, this becomes significant write amplification on a globally-shared table.

**The Fix:** Isolate `fts_document` in a dedicated 1:1 table `cve_search_index(cve_id text PK REFERENCES cves, fts_document tsvector NOT NULL)`. The merge function only writes to `cve_search_index` when text-contributing fields (description, CWE titles) actually change. Timestamp and score updates to `cves` never touch the GIN index. Search queries use a JOIN.

**The Lesson:** In Postgres, put high-churn columns (timestamps, scores, counters) and expensive-to-index columns (GIN, tsvector, JSONB) in separate tables whenever they live on the same logical entity. Any UPDATE to any column on a row triggers index maintenance for all indexed columns on that row. If a column is indexed but rarely changes, isolating it avoids write amplification from the columns that change constantly.

---

### DB-3 Advisory Lock Hash: Wrong Function + Imprecise Domain Isolation Claim

**The Flaw:** Initial plan used `pg_advisory_xact_lock(hashtext(cve_id))` — a Postgres-internal function — and described domain prefixes as creating "non-overlapping key spaces."

**Two distinct corrections were needed:**

1. **`hashtextextended` / `hashtext` are internal Postgres APIs.** They are partitioning utilities, unavailable or restricted in some managed Postgres environments (RDS, Cloud SQL, etc.). Computing the hash in application code is explicit, testable, and fully portable.

2. **"Non-overlapping key spaces" is mathematically wrong.** Domain prefixes ensure that *identical IDs in different domains* hash to different values (because the inputs differ). They do not create partitioned output spaces — all keys map to the same 64-bit pool. What makes cross-domain collisions negligible is the 64-bit pool size: at 250k+ CVE IDs, the Birthday Paradox probability is effectively zero.

**The Fix:** Compute the advisory lock key in Go with domain-prefixed input:
```go
func advisoryKey(domain, id string) int64 {
    h := fnv.New64a()
    h.Write([]byte(domain + ":" + id))
    return int64(h.Sum64())
}
// Usage: pg_advisory_xact_lock(advisoryKey("cve", cveID))
```

**The Lesson:** Don't rely on database-internal functions for business logic — they are implementation details that may be restricted in managed environments. Compute deterministic hashes in application code. Also: be precise about what domain prefixes actually guarantee. They prevent identical-input cross-domain collisions; they do not create non-overlapping output spaces. Imprecise wording in architectural documents leads to imprecise implementations.

---

### DB-4 RLS `missing_ok` Fail-Closed Blindfolds Background Workers

**The Flaw:** The RLS policy correctly used `current_setting('app.org_id', TRUE)::uuid` with `missing_ok=TRUE`, so unscoped queries (background workers, health checks) return NULL and see 0 rows — intentional fail-closed behavior for API routes.

**Why It Matters:** Background workers (batch alert evaluator, EPSS evaluator, retention cleanup) operate outside any user HTTP session and have no `app.org_id` context. With the fail-closed policy, every worker query returns 0 rows silently: 0 alert rules evaluated, 0 alerts fired, 0 CVEs cleaned up. There is no error — just silent, total inactivity. This failure mode is invisible in logs because the queries succeed; they simply match nothing.

**The Fix:** Add a `app.bypass_rls` session variable to the policy, set only in worker transactions:
```sql
CREATE POLICY org_isolation ON watchlists
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```
Worker transaction helper (only valid call site):
```go
func workerTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
    tx, _ := pool.Begin(ctx)
    defer tx.Rollback(ctx)
    tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'on'")
    if err := fn(tx); err != nil { return err }
    return tx.Commit(ctx)
}
```
`SET LOCAL` is transaction-scoped; the bypass auto-resets on commit/rollback and cannot leak to subsequent connections. The `WITH CHECK` bypass allows workers to write `alert_events` and `notification_deliveries` on behalf of any org.

**The Lesson:** Any RLS design that is "fail-closed" for unauthenticated queries will also blindfold background processes that legitimately need cross-tenant access. The policy must distinguish between "unauthenticated API caller who should see nothing" and "trusted internal worker who needs to see everything." A transaction-scoped session variable provides this distinction safely; a role-level `BYPASSRLS` attribute is the alternative but is coarser-grained.

---

### DB-5 `RowsAffected == 0` Is Ambiguous After `IS DISTINCT FROM` Guard

**The Flaw:** The EPSS adapter used `IS DISTINCT FROM` in the UPDATE to avoid writing dead tuples for unchanged scores. Go code then checked `RowsAffected() == 0` to decide whether to insert into `epss_staging`.

**Why It Matters:** After adding `IS DISTINCT FROM`, `RowsAffected == 0` has two completely different meanings:
- (A) CVE does not exist in `cves` -> score should go to staging
- (B) CVE exists, score unchanged -> do nothing

Code implementing `if rowsAffected == 0 { insertIntoStaging() }` inserts 250,000 unchanged EPSS scores into `epss_staging` every day — the exact write amplification the `IS DISTINCT FROM` clause was designed to prevent.

**The Fix:** Never inspect `RowsAffected` for this decision. Instead, run a second SQL statement unconditionally that delegates the existence check entirely to the database:
```sql
-- Statement 1: update if CVE exists AND score changed
UPDATE cves SET epss_score = $1, date_epss_updated = now()
WHERE cve_id = $2 AND epss_score IS DISTINCT FROM $1;

-- Statement 2: insert to staging only if CVE doesn't exist (WHERE NOT EXISTS)
INSERT INTO epss_staging (cve_id, epss_score, as_of_date)
SELECT $2, $1, $3
WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = $2)
ON CONFLICT (cve_id) DO UPDATE
    SET epss_score = EXCLUDED.epss_score,
        as_of_date = EXCLUDED.as_of_date;
```
Both statements run for every CSV row. The database handles all three cases correctly without any Go-side conditional logic.

**The Lesson:** `RowsAffected == 0` is a blunt instrument that becomes ambiguous whenever a WHERE clause can suppress writes for multiple independent reasons. When a SQL guard clause is added (like `IS DISTINCT FROM`), audit all downstream code that branches on `RowsAffected` — the meaning may have changed. Delegating conditional logic to DB-side `WHERE NOT EXISTS` / `ON CONFLICT` / `RETURNING` clauses eliminates ambiguity and reduces round-trips.

---

### DB-6 `SELECT expr WHERE condition` Without `FROM` — Reliable for Postgres, Unreliable for sqlc

**The Flaw:** The two-statement EPSS pattern used `SELECT $2, $1, $3 WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = $2)` — a SELECT without a FROM clause.

**Why It Matters:** This is valid PostgreSQL syntax (PostgreSQL allows `SELECT expr WHERE condition` without FROM, treating it as a zero-or-one-row evaluation). However, there is a real problem: the parameters are out-of-order (`$2, $1, $3`) in a typeless SELECT without a FROM clause. sqlc uses the INSERT target column list to infer parameter types, but out-of-order parameters in this context make that inference unreliable. sqlc may generate incorrect parameter types or fail to compile the query at all, blocking the entire `sqlc generate` step.

**The Fix:** Use a VALUES expression with explicit type casts as the FROM source, which makes types unambiguous:
```sql
INSERT INTO epss_staging (cve_id, epss_score, as_of_date)
SELECT t.cve_id, t.epss_score, t.as_of_date
FROM (VALUES ($2::text, $1::double precision, $3::date)) AS t(cve_id, epss_score, as_of_date)
WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = t.cve_id)
ON CONFLICT (cve_id) DO UPDATE
    SET epss_score = EXCLUDED.epss_score,
        as_of_date = EXCLUDED.as_of_date;
```
The VALUES approach also uses `t.cve_id` in the NOT EXISTS subquery (by name, not parameter position), making the query self-documenting and immune to parameter-order confusion.

**The Lesson:** Verify SQL correctness at two levels: (1) valid PostgreSQL, and (2) parseable by your code generation tool. A query can be valid Postgres but still fail `sqlc generate` if the tool cannot reliably infer parameter types. Always include explicit type casts (`$1::text`) in sqlc queries, especially for parameters in positions where type cannot be inferred from schema context alone.

---

### DB-7 EPSS Staging Table Has No Lifecycle Management in the Merge Pipeline

**The Flaw:** The merge transaction boundary listed 5 explicit steps (lock -> upsert sources -> recompute -> upsert cves -> commit). The PRD states that staged EPSS scores are "applied on next CVE upsert," but this is a requirements statement, not an implementation directive — the merge transaction steps contained no instructions to read from, apply, or clean up `epss_staging`.

**Why It Matters:** An AI implementing the 5-step merge function writes exactly those 5 steps and nothing else. Without explicit instruction:
- The staging table is never read — staged EPSS scores are orphaned permanently. CVEs added via bulk import or incremental ingest never get their EPSS scores, regardless of how long they wait in staging.
- If the staging table IS read but never deleted, it grows without bound and old staged scores take priority over fresh daily EPSS feed updates (since staging is only overwritten by `ON CONFLICT DO UPDATE`, meaning a score staged at Day 1 could suppress a higher-priority live score at Day 30).

**The Fix:** Add steps 4a and 4b to the merge transaction, inside the same transaction before commit:
```
4a) SELECT epss_score, as_of_date FROM epss_staging WHERE cve_id = $1
    If found: UPDATE cves SET epss_score = staged, date_epss_updated = now()
              WHERE cve_id = $1 AND epss_score IS DISTINCT FROM staged
4b) DELETE FROM epss_staging WHERE cve_id = $1
    (execute regardless of whether 4a found a row — prevents stale accumulation)
```
Both steps are inside the merge transaction. If the transaction rolls back, the staging row is preserved for retry.

**The Lesson:** "Applied on next upsert" in a PRD is an intent, not an implementation directive. Any time a data lifecycle operation spans two code paths (EPSS adapter writes to staging; merge pipeline reads from staging), the receiving side's implementation must explicitly be specified. "The merge pipeline applies staged data" requires listing it as a named step in the pipeline — otherwise it silently doesn't happen.

---

### DB-8 EPSS/CVE Upsert Race Condition — Missing Advisory Lock

**The Flaw:** The two-statement EPSS pattern (UPDATE cves + INSERT INTO epss_staging) ran as two independent SQL statements without acquiring the same advisory lock used by the CVE merge pipeline.

**Why It Matters:** The TOCTOU race: (1) EPSS worker executes Statement 1 — CVE not yet in DB, 0 rows affected; (2) CVE merge worker inserts the CVE, reads `epss_staging` (empty), commits; (3) EPSS worker executes Statement 2 — CVE now exists, WHERE NOT EXISTS is false, no-op. The EPSS score is silently dropped into the void: neither applied to `cves` nor saved in `epss_staging`. No error, no retry, no recovery.

**The Fix:** Before executing the two-statement EPSS sequence, acquire the same per-CVE advisory lock used by the merge pipeline: `SELECT pg_advisory_xact_lock(cveAdvisoryKey("cve:"+cveID))`. This serializes EPSS writes against CVE merges for the same CVE ID within the same transaction.

**The Lesson:** Any two code paths that read-then-write the same logical record must hold the same serialization primitive. "Advisory lock for CVE merges" only protects the merge path; the EPSS path, which also reads+writes the same CVE record, is unprotected unless it acquires the same lock.

---

### DB-9 Child Table RLS Bypass — `org_id` Denormalization Required

**The Flaw:** RLS was applied to parent tables (`watchlists`, `alert_rules`) but child tables (`watchlist_items`, `alert_events`, `notification_deliveries`) either had no RLS or used `EXISTS (SELECT 1 FROM parent WHERE ...)` policies.

**Why It Matters:** Omitting RLS on child tables lets any authenticated user access/modify rows by guessing a parent UUID. `EXISTS` subquery policies execute a nested loop join on every scanned row, destroying read performance for large orgs. In both cases, tenant isolation is either absent or unacceptably slow.

**The Fix:** Every tenant-owned table — including all child and join tables — must contain an `org_id UUID NOT NULL` column with a `BTREE(org_id)` index and an RLS policy using `org_id = current_setting('app.org_id', TRUE)::uuid`. The redundancy (parent and child both carry `org_id`) is intentional. Do NOT normalize it out.

**The Lesson:** RLS policies protect only the table they're defined on. There is no automatic inheritance to child tables. Any time you normalize `org_id` out of a child table (relying on a parent join to establish ownership), you lose both the RLS protection and the index-based performance it provides.

---

### DB-10 PostgreSQL Null Byte Poisoning from Feed Payloads

**The Flaw:** Feed adapter inserts raw string fields and JSON payloads to Postgres without sanitizing null bytes.

**Why It Matters:** PostgreSQL `TEXT` and `JSONB` columns reject the `\x00` null byte with a fatal `ERROR: invalid byte sequence for encoding "UTF8": 0x00`. Go strings permit null bytes natively. GHSA advisories and older NVD records may contain null bytes from raw hex dumps or malformed markdown. A single null byte in a description aborts the transaction and causes the worker to retry the same "poison pill" CVE indefinitely — blocking the feed forever.

**The Fix:** Before any insert, sanitize all string fields: `strings.ReplaceAll(s, "\x00", "")`, and raw JSON payloads: `bytes.ReplaceAll(payload, []byte{0}, []byte{})`.

**The Lesson:** PostgreSQL and Go have different null byte semantics. This is a known issue with vulnerability feed data. Sanitize at the adapter layer before anything touches the DB — not at query time, where it's too late to catch raw payloads.

---

### DB-11 `sqlc` UUID Type Pollution

**The Flaw:** Running `sqlc generate` without configuring UUID type overrides produces `pgtype.UUID` fields throughout the generated code.

**Why It Matters:** `pgtype.UUID` does not implement standard JSON marshaling. Every API handler and service function is forced to manually wrap/unwrap `pgtype.UUID` into strings or `google/uuid` types. The entire domain model is polluted with a cumbersome adapter type, and JSON responses require custom serialization for every UUID field.

**The Fix:** Add explicit type overrides to `sqlc.yaml`:
```yaml
overrides:
  go:
    overrides:
      - db_type: "uuid"
        go_type: "github.com/google/uuid.UUID"
      - db_type: "uuid"
        nullable: true
        go_type: "github.com/google/uuid.NullUUID"
```

**The Lesson:** `sqlc` defaults are not ergonomic for UUID-heavy schemas. Always configure type overrides before writing any schema; retrofitting after sqlc-generated code is used throughout the codebase requires touching every generated function signature and every call site.

---

### DB-12 Dynamic `IN` Clause Overflows Postgres 65,535 Parameter Limit

**The Flaw:** When evaluating large watchlists or SBOM dependency lists against the database, the natural pattern is a dynamically built `IN` clause: `SELECT * FROM cves WHERE package_name IN ($1, $2, ..., $N)`.

**Why It Matters:** PostgreSQL's wire protocol uses a 16-bit integer for parameter binding, imposing a hard limit of **65,535 parameters per query**. At 65,536 dependencies — easily reached by an enterprise Java or Node.js monolith SBOM — the `pgx` driver panics and crashes the worker. This is an unrecoverable hard limit; there is no configuration knob to raise it. A user with a large dependency list is permanently unable to run watchlist matching.

**The Fix:** Pass the entire list as a single Postgres array parameter using `ANY($1::text[])`:
```go
// WRONG — panics at 65,536 entries
query := "SELECT * FROM cves WHERE package_name IN (" + placeholders + ")"
args := []interface{}{dep1, dep2, dep3, ...}

// CORRECT — single parameter, no limit
rows, err := tx.Query(ctx,
    `SELECT c.* FROM cves c
     JOIN cve_affected_packages p ON c.cve_id = p.cve_id
     WHERE p.package_name = ANY($1::text[]) AND p.ecosystem = $2`,
    packages, // []string — pgx serializes entire slice as a Postgres array
    ecosystem,
)
```
`ANY($1::text[])` accepts a `[]string` slice as a single `$1` argument. Postgres expands it internally without consuming wire-protocol parameter slots. The fix applies to all dynamic list-membership checks: watchlist package matching, SBOM dependency scanning, CWE filter `IN` lists, and any other case where a user-provided list is matched against a DB column.

**Note:** This finding was independently flagged in two separate review rounds (as 2.12 and 12.1), confirming its importance. The `ANY` array pattern is the universal replacement for dynamic `IN` clauses.

**The Lesson:** Never use dynamic `IN ($1, $2, ..., $N)` construction for user-controlled lists. The limit is invisible during development (test watchlists are small) and catastrophic in production (one enterprise user brings down the worker). `ANY($1::type[])` is always the correct pattern.

---

### DB-13 Squirrel Dynamic Queries Bypass RLS Without `withOrgRawTx`

**The Flaw:** List methods built with squirrel (dynamic SQL builder) used `s.db.QueryContext(ctx, query, args...)` directly instead of running inside a transaction that sets `app.org_id`. The `withOrgTx` helper passes `*generated.Queries` (for sqlc), so squirrel queries that need a raw `*sql.Tx` had no wrapper — developers grabbed a bare connection from the pool.

**Why It Matters:** RLS policies check `current_setting('app.org_id')` per-transaction. Without `SET LOCAL app.org_id`, the setting is NULL, and `NULL::uuid = org_id` evaluates to NULL (false in WHERE), returning **zero rows** to every tenant. While this fails closed (no data leaks), it means all four list endpoints returned empty results for the `cvert_ops_app` role — a total loss of functionality for the non-superuser app path. Tests masked the bug because they used the superuser connection (BYPASSRLS), which ignores RLS entirely.

**The Fix:** Add `withOrgRawTx` — a sibling of `withOrgTx` that passes `*sql.Tx` instead of `*generated.Queries`:
```go
func (s *Store) withOrgRawTx(ctx context.Context, orgID uuid.UUID, fn func(*sql.Tx) error) error {
    // BEGIN -> SET LOCAL app.org_id -> fn(tx) -> COMMIT
}
```
Every squirrel list method must use `withOrgRawTx` instead of querying `s.db` directly. Refactor `withOrgTx` to delegate to `withOrgRawTx` to eliminate duplication.

**The Lesson:** When adding a new store method that uses squirrel (or any dynamic SQL), always wrap execution in `withOrgRawTx`. The type system enforces this for sqlc (requires `*generated.Queries` from `withOrgTx`), but squirrel queries bypass that guard. Any `s.db.QueryContext` or `s.db.ExecContext` call in an org-scoped method is a bug — search for these patterns during code review.

---

### DB-14 Store Tests Must Use AppStore for RLS Verification

**The Flaw:** Integration tests for list methods used `testutil.NewTestDB(t)` which embeds the superuser `*store.Store` (BYPASSRLS). All assertions ran against the superuser connection, which ignores RLS policies. The `AppStore` field (connecting as `cvert_ops_app` with NOBYPASSRLS) existed but was never used for list method tests.

**Why It Matters:** Tests that bypass RLS cannot detect RLS bugs. The four broken list methods (DB-13) passed all tests because the superuser connection returns all rows regardless of `app.org_id`. This created a false green signal that persisted through code review.

**The Fix:** Every store integration test for an org-scoped list method must include an RLS isolation assertion using `s.AppStore`:
```go
// Data setup uses superuser store (s.Store) — this is fine.
// RLS assertion uses AppStore — this catches RLS bugs.
got, err := s.AppStore.ListWatchlists(ctx, org1.ID, nil, nil, 10)
if len(got) != 1 { t.Fatalf("expected 1 watchlist for org1, got %d", len(got)) }
```
Pattern: create data in two orgs via superuser, then assert via `AppStore` that each org sees only its own data.

**The Lesson:** For any org-scoped store method, always add a test that queries through `AppStore` (NOBYPASSRLS) and verifies tenant isolation. Superuser-only tests give a false green for RLS compliance. This should be a code review checklist item for every new store method.

---

### DB-15 ON CONFLICT Must Match the Exact Partial Unique Index

**The Flaw:** When changing a partial unique index's `WHERE` clause (e.g., adding `AND kind = 'alert'` to a debounce index), the migration correctly created the new index but the hand-written `ON CONFLICT ... WHERE status = 'pending'` clause in application Go code was not updated to match.

**Why It Matters:** PostgreSQL requires the `ON CONFLICT` predicate to exactly match a unique index's `WHERE` clause. If the index is `(rule_id, channel_id) WHERE status = 'pending' AND kind = 'alert'` but the query says `ON CONFLICT (rule_id, channel_id) WHERE status = 'pending'`, Postgres raises `42P10: there is no unique or exclusion constraint matching the ON CONFLICT specification`. Every upsert fails at runtime.

**The Fix:** When altering a partial unique index, grep the codebase for all `ON CONFLICT` clauses referencing the same columns and update their `WHERE` predicates:
```bash
grep -rn 'ON CONFLICT.*rule_id.*channel_id' internal/
```
Also update the column list in the `INSERT INTO` clause if the new index references additional columns (e.g., adding `kind` to the inserted columns).

**The Lesson:** Partial unique indexes have two consumers: the index DDL in migrations and the `ON CONFLICT` clauses in application code. Schema review catches DDL issues but not application SQL that references the index. When changing a partial unique index, always search for `ON CONFLICT` clauses that target it. This is especially easy to miss when the index and the `ON CONFLICT` are in different files (migration SQL vs. Go constants). Consider adding a comment on both sides cross-referencing each other.

---

### DB-16 Semicolons in SQL Comments Break golang-migrate Statement Splitting

**The Flaw:** A SQL comment in a migration file contained a semicolon: `-- app-layer validation; FK impossible on arrays`. golang-migrate splits migration files into individual statements by semicolons before executing them.

**Why It Matters:** The semicolon inside the comment causes golang-migrate to split the `CREATE TABLE` statement mid-comment, producing two fragments — the first is a truncated `CREATE TABLE` (syntax error), the second is the orphaned comment tail plus remaining columns. Every test that runs migrations fails with `ERROR: syntax error at end of input (SQLSTATE 42601)`.

**The Fix:** Never use semicolons inside SQL comments in migration files. Rephrase to avoid them:
```sql
-- BAD:  -- app-layer validation; FK impossible on arrays
-- GOOD: -- App-layer validation only (FK impossible on arrays).
```

**The Lesson:** golang-migrate's statement splitter is naive — it splits on `;` without fully parsing SQL comment boundaries. This is a known limitation. Avoid semicolons in `--` line comments and `/* */` block comments in migration files. This is especially subtle because the SQL itself is syntactically valid — it only breaks at the migration runner level.

---

### DB-17 Transaction Helper Selection — When to Use Which

**The Flaw:** Store methods that query the database pool directly (without a transaction helper) silently bypass RLS. With `FORCE ROW LEVEL SECURITY` and `NOBYPASSRLS` on the app role, queries outside a transaction that sets `app.org_id` return 0 rows — fail-closed, but also fail-silently. The code appears to work in tests using the superuser store.

**The Fix:** Every store method must use exactly one of these transaction helpers:

| Helper | Sets | Use when | Example |
|--------|------|----------|---------|
| `withOrgTx` | `app.org_id = $orgID` | API handlers — org-scoped sqlc queries | `ListWatchlists`, `CreateAlertRule` |
| `withOrgRawTx` | `app.org_id = $orgID` | API handlers — org-scoped squirrel queries | `ListAlertRules` (dynamic DSL) |
| `withBypassTx` | *(nothing)* | Pre-context operations (auth middleware, org creation) | `GetOrgTier`, `LookupAPIKey`, `GetOrgMemberRole` |
| `WorkerTx` | `app.bypass_rls = 'on'` | Background workers — cross-org operations | Feed sync, alert evaluation, retention cleanup |
| `readTx` | *(nothing, read-only)* | Read-only evaluation against global tables | Alert rule dry-run |

**Critical rules:**
- **Never** use `s.db.QueryContext()` or `s.Pool().Query()` directly in store methods — always go through a helper
- **Never** call `WorkerTx` or `withBypassTx` from an HTTP handler's org-scoped code path
- `withBypassTx` is for operations that run **before** org context exists (middleware, auth) — even if the target table has no RLS today, use it for consistency and future-proofing
- Any `s.db.` call in an org-scoped store method is a bug — grep for these during code review

**Business logic MUST NOT duplicate store transaction helpers.** The alert evaluator historically held its own `*sql.DB` and reimplemented `bypassTx()` without panic-recovery defer. This created two divergent transaction management paths. If a service needs store-level operations, define a store interface — never copy transaction management code. Duplication of transaction management is a bug, not a shortcut.

**The Lesson:** The transaction helper is not just about "does this table have RLS?" — it encodes the **calling context** (API handler vs middleware vs worker). Using the right helper by convention prevents silent security regressions when RLS is added to tables later, and makes the code self-documenting about where it's called from.

---

### DB-18 JSONB TOAST Bloat from Unconditional Upserts

JSONB columns stored out-of-line via TOAST (Postgres's large-value storage) rewrite the entire TOAST tuple on every `ON CONFLICT DO UPDATE`, even when the value is unchanged. For `cve_sources.normalized_json`, which holds the full upstream payload, this produces significant daily TOAST write amplification from feed re-ingestion. The fix is the same `IS DISTINCT FROM` guard used for scalar columns: `ON CONFLICT (cve_id, source) DO UPDATE SET normalized_json = EXCLUDED.normalized_json WHERE cve_sources.normalized_json IS DISTINCT FROM EXCLUDED.normalized_json`. This suppresses the TOAST rewrite when the payload is byte-identical.

---

### DB-19 CREATE INDEX CONCURRENTLY Requires Migration Framework Coordination

**The Flaw:** A migration file contained `CREATE INDEX CONCURRENTLY` without the `-- migrate:no-transaction` directive as its first line.

**Why It Matters:** `golang-migrate` wraps each migration file in `BEGIN`/`COMMIT` by default. PostgreSQL forbids `CREATE INDEX CONCURRENTLY` inside a transaction block — it raises `ERROR: CREATE INDEX CONCURRENTLY cannot run inside a transaction block`. Without the no-transaction directive, the migration fails on first deploy. Meanwhile, using plain `CREATE INDEX` (without CONCURRENTLY) acquires an `AccessExclusiveLock` on the table, blocking all reads and writes for the duration of the index build — 5 to 30+ seconds on tables with hundreds of thousands of rows. During that window, the API is effectively down.

**The Fix:** Every migration file containing `CREATE INDEX CONCURRENTLY` MUST have `-- migrate:no-transaction` as the **first line** of both the up and down files:
```sql
-- migrate:no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cves_epss_score
    ON cves (epss_score);
```
Use `IF NOT EXISTS` on the index as a safety net — if a previous failed attempt left a partial index, the retry succeeds. The down migration must use `DROP INDEX CONCURRENTLY IF EXISTS` with the same `-- migrate:no-transaction` directive.

**The Lesson:** `CREATE INDEX CONCURRENTLY` is a Postgres feature that requires framework awareness to use correctly. The interaction between the migration runner's default transaction wrapping and Postgres's concurrency requirement is invisible until deployment. Every migration containing a concurrent index must be tested by running the full migration suite, not just validating the SQL syntax. This is a code review checklist item for all migration files.

---

### DB-20 Soft-Delete + UNIQUE Table Constraint Rejects Name Reuse

When a table uses soft-delete (`deleted_at TIMESTAMP NULL`) and has a `UNIQUE(org_id, name)` table constraint, deleting a record and creating a new one with the same name violates the unique constraint — the soft-deleted row still occupies the unique slot. The fix is a partial unique index: `CREATE UNIQUE INDEX idx_unique_name_active ON table (org_id, name) WHERE deleted_at IS NULL`. This allows name reuse after soft-delete while preventing duplicates among active records.

---

### DB-21 Notification Channel Hard-Delete Orphans Delivery History

`notification_channels` MUST use soft-delete (`deleted_at` column), not hard-delete. Hard-deleting a channel orphans all `notification_deliveries` rows that reference it via FK, breaking delivery history and audit trails. Active lookups filter with `WHERE deleted_at IS NULL`. Historical queries (delivery logs, audit reports) join against all channels including soft-deleted ones, preserving the full delivery chain.

---

### DB-22 Array Fields Must Be Sorted Before Material Hash Computation

All array-type fields — references (URLs), CWE IDs, CPEs, affected packages — MUST be sorted lexicographically before JSON Canonicalization Scheme (JCS) serialization for `material_hash` computation. Without sorting, cosmetic reordering of array elements (e.g., a feed source returning CWEs in a different order) changes the hash and fires spurious alert evaluations. The sort is applied in the merge pipeline before hashing: `sort.Strings(cweIDs)`, `sort.Strings(cpes)`, etc.

---

### DB-23 — *Merged into DB-12*

*Finding 12.1 (Dynamic `IN` clause 65k limit) is a duplicate of DB-12 (originally 2.12). See DB-12 for the consolidated entry.*

---

### DB-24 Child Table Upsert Sort Order — Deadlock Prevention

**Status: UNIMPLEMENTED (documented gap)**

The merge pipeline upserts child table rows (`cve_references`, `cve_affected_packages`, `cve_affected_cpes`) without sorting them by natural key before the batch upsert. The per-CVE advisory lock prevents deadlocks at the CVE level, so this is safe under the current single-CVE-per-transaction design. However, if the merge pipeline is extended to process multiple CVEs in a single transaction, or if a future code path inserts child rows in a different order, the lack of consistent lock ordering creates deadlock risk.

The prescribed sort order: `cve_references` by `url_canonical ASC`, `cve_affected_packages` by `(ecosystem, package_name, introduced) ASC`, `cve_affected_cpes` by `cpe_normalized ASC`. Adding `sort.Slice` calls before batch upserts is low-cost insurance (microseconds for ~20 rows) against sporadic deadlocks that cost hours to diagnose.

---

### DB-25 Nullable Integer Columns Where Zero Is a Valid Measurement

**The Flaw:** The `ai_request_log` table has `input_tokens INT NULL` and `output_tokens INT NULL`. A helper function `toNullInt32(v int32)` was used to convert Go values to `sql.NullInt32`. The implementation treated `0` as "no value" and mapped it to `NULL`.

**Status: DIVERGED — `toNullInt32()` maps 0 to NULL. Zero token counts are indistinguishable from "not measured."**

**Why It Matters:** An LLM response that consumed 0 output tokens (e.g., the model returned an empty structured response that was parsed from headers, or a cached response with no generation) is a valid measurement. Mapping `0 -> NULL` loses the distinction between "we measured the token count and it was zero" and "we didn't measure the token count." This corrupts analytics: `AVG(output_tokens)` excludes NULL rows, so zero-token responses are invisible in cost tracking. For billing purposes, the difference between "zero cost" and "unknown cost" matters.

**The Fix:** Use pointer types in the Go layer to distinguish nil (not measured) from zero (measured as 0):
```go
func toNullInt32FromPtr(v *int32) sql.NullInt32 {
    if v == nil {
        return sql.NullInt32{} // NULL — not measured
    }
    return sql.NullInt32{Int32: *v, Valid: true} // 0 is a valid value
}
```
Alternatively, if the helper takes a plain `int32`, document that `0` is a valid value and only use a sentinel like `-1` for "not measured" — but pointer types are clearer and less error-prone.

**The Lesson:** This is the database-side counterpart of the `omitempty` PATCH struct pitfall (where zero-value fields are silently dropped). Any nullable numeric column where zero is a meaningful value — token counts, scores, durations, retry counts — must not map zero to NULL. The Go zero value (`0`) and the SQL NULL are semantically different. When designing a `toNull*` helper, decide explicitly: does this column's zero mean "absent" or "measured as zero"? If the latter, use pointer types or an explicit sentinel.

---

## Review Checklist: Database & Query Patterns

Use this checklist when reviewing store methods, migrations, or SQL queries.

- [ ] **Transaction helper selection:** Does each store method use the correct helper (`withOrgTx`, `withOrgRawTx`, `withBypassTx`, `WorkerTx`, `readTx`)? No direct `s.db.` calls in org-scoped methods?
- [ ] **RLS on all org-scoped tables:** Does every tenant-owned table (including child/join tables) have `org_id UUID NOT NULL` + `BTREE(org_id)` index + RLS policy?
- [ ] **IS DISTINCT FROM guards:** Do upserts and enrichment updates use `IS DISTINCT FROM` to suppress no-op writes, especially on cursor columns (`date_epss_updated`, `date_modified_canonical`) and JSONB/TOAST columns?
- [ ] **CREATE INDEX CONCURRENTLY + no-transaction:** Do all migration files with `CREATE INDEX CONCURRENTLY` have `-- migrate:no-transaction` as the first line of both up and down files? Do they use `IF NOT EXISTS`/`IF EXISTS`?
- [ ] **ON CONFLICT matches partial index:** Does every `ON CONFLICT ... WHERE` clause exactly match the `WHERE` clause of the corresponding partial unique index? Have all referencing queries been updated when the index changes?
- [ ] **ANY() not IN():** Are all dynamic list-membership queries using `ANY($1::type[])` instead of `IN ($1, $2, ..., $N)`? No dynamic placeholder construction for user-controlled lists?
- [ ] **Null byte sanitization:** Are all string fields and JSON payloads sanitized via `StripNullBytes`/`StripNullBytesJSON` before any INSERT/UPDATE?
- [ ] **Soft-delete filtering:** Do active-record queries include `WHERE deleted_at IS NULL`? Do unique constraints use partial indexes (`WHERE deleted_at IS NULL`) instead of table constraints?
- [ ] **No semicolons in SQL comments:** Do migration file comments avoid semicolons (golang-migrate splits on `;` naively)?
- [ ] **sqlc type casts:** Do sqlc queries include explicit type casts (`$1::text`, `$1::uuid`) for parameters in positions where type inference is ambiguous?

---

### See Also
- Transaction helper verification in tests: see testing-pitfalls.md Section 7 (Transaction & Store Conventions)
- RLS dual-connection testing: see testing-pitfalls.md Section 10 (RLS & Tenant Isolation)
- EPSS staging in feed adapters: see FEED-1 (JSON Wire Format) for streaming patterns
