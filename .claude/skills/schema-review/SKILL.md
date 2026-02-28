---
name: schema-review
description: Audit a CVErt Ops database schema design or migration before writing SQL. Use when designing new tables, reviewing a migration plan, or verifying that a schema section is complete before implementation.
argument-hint: "<table name, migration number, or feature area (e.g., 'watchlists', '000013', 'alert evaluation')>"
---

# Schema Review

Auditing CVErt Ops schema for: **$ARGUMENTS**

Work through each section. For each item mark **✅ OK**, **❌ FAIL** (with what's wrong + fix), or **N/A**.

---

## 1. RLS Completeness (every new org-scoped table)

- [ ] `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY`
- [ ] `ALTER TABLE <t> FORCE ROW LEVEL SECURITY`
- [ ] Policy uses the **dual-escape** pattern — both branches present:
  ```sql
  USING (
      current_setting('app.bypass_rls', TRUE) = 'on'
      OR org_id = current_setting('app.org_id', TRUE)::uuid
  )
  WITH CHECK ( ... same ... )
  ```
- [ ] **Child/join tables** have `org_id` column denormalized — RLS on the parent does NOT protect children
- [ ] Global tables (`cves`, `feed_sync_state`, `job_queue`, `users`, `organizations`) correctly have **no** RLS — flag any that gained one by mistake

---

## 2. Migration Conventions

- [ ] `-- migrate:no-transaction` is the **first line** of any migration file containing a `CONCURRENTLY` index
- [ ] Every `CREATE INDEX` uses `CONCURRENTLY IF NOT EXISTS`
- [ ] Every `CREATE TABLE` uses `IF NOT EXISTS`
- [ ] `GRANT <appropriate-verbs> ON <table> TO cvert_ops_app` present for each new table
- [ ] Down migration drops everything the up migration creates, in reverse dependency order
- [ ] Migration number is sequential (no gaps, no collisions with existing files)

---

## 3. Grants — Right Verbs Per Table Type

| Table type | Typical grant |
|---|---|
| Soft-delete entity (has `deleted_at`) | `SELECT, INSERT, UPDATE` |
| Hard-delete child (no `deleted_at`) | `SELECT, INSERT, DELETE` |
| Append-only log (run log, event log) | `SELECT, INSERT, UPDATE` (UPDATE for mutable state columns like `last_match_state`, `finished_at`) |
| System / global (no org scope) | `SELECT, INSERT, UPDATE` or as appropriate |

- [ ] No unnecessary `DELETE` grant on soft-delete tables
- [ ] No unnecessary `UPDATE` grant on truly append-only tables

---

## 4. Uniqueness & Deduplication

- [ ] **Soft-delete entities** with a user-facing name use a partial unique index, not a table constraint:
  ```sql
  CREATE UNIQUE INDEX CONCURRENTLY name_uq ON t (org_id, name) WHERE deleted_at IS NULL;
  ```
- [ ] **Type-discriminated tables** (e.g., `item_type = 'package' | 'cpe'`) have **per-type** partial unique indexes, not a single composite index:
  ```sql
  CREATE UNIQUE INDEX CONCURRENTLY wi_pkg_uq ON watchlist_items (watchlist_id, ecosystem, package_name)
      WHERE item_type = 'package';
  CREATE UNIQUE INDEX CONCURRENTLY wi_cpe_uq ON watchlist_items (watchlist_id, cpe_pattern)
      WHERE item_type = 'cpe';
  ```
- [ ] **Child join tables** (e.g., `group_members`) have a unique constraint preventing duplicate relationships
- [ ] **JSONB upserts** use `IS DISTINCT FROM` in the `WHERE` clause to avoid TOAST churn on no-op updates
- [ ] **Dedup-by-insert** tables (e.g., `alert_events`) have a `UNIQUE(...)` constraint enabling `ON CONFLICT DO NOTHING RETURNING id`

---

## 5. Referential Integrity

- [ ] Every foreign key relationship has a `REFERENCES` constraint
- [ ] `ON DELETE` action is explicitly chosen and correct:
  - `CASCADE` — child is meaningless without parent (e.g., `watchlist_items` → `watchlists`)
  - `SET NULL` — child survives with nullable FK (e.g., optional group owner)
  - `RESTRICT` / default — preserve child, reject parent delete (rare in this schema)
- [ ] Where FK is **impossible** (e.g., `uuid[]` array column like `alert_rules.watchlist_ids`): document that app-layer validation is required, and add a comment in the migration
- [ ] Self-referential FKs (e.g., `replaced_by_jti`) are nullable and use `ON DELETE SET NULL` or `RESTRICT` as appropriate

---

## 6. Column Completeness

- [ ] **Type-discriminated tables** have CHECK constraints enforcing which columns are required per type:
  ```sql
  CONSTRAINT wi_package_fields CHECK (item_type != 'package' OR (ecosystem IS NOT NULL AND package_name IS NOT NULL)),
  CONSTRAINT wi_cpe_fields     CHECK (item_type != 'cpe'     OR cpe_pattern IS NOT NULL),
  CONSTRAINT wi_item_type      CHECK (item_type IN ('package', 'cpe'))
  ```
- [ ] Enum-like `text` columns have `CHECK (col IN (...))` constraints
- [ ] `NOT NULL` vs nullable is deliberate for every column — nullable means "legitimately absent"
- [ ] Timestamps: `created_at timestamptz NOT NULL DEFAULT now()` on all tables; `updated_at` on mutable entities; `deleted_at timestamptz NULL` on soft-delete entities
- [ ] `PATCH`-able structs will use pointer types in Go (`*string`, `*bool`, `*float64`) — flag columns whose zero value is meaningful

---

## 7. Index Coverage

- [ ] Every FK column has an index (a FK without an index causes sequential scans on joins and cascades)
- [ ] `org_id` has a `BTREE` index on every org-scoped table
- [ ] **Query-pattern indexes**: for each known query pattern (evaluator polling, keyset pagination, retention cleanup), a supporting index exists
- [ ] **Partial indexes** for filtered queries (e.g., `WHERE status IN ('active', 'activating') AND deleted_at IS NULL`; `WHERE last_match_state = true`)
- [ ] **Soft-delete tables**: most queries filter `WHERE deleted_at IS NULL` — confirm an index supports this pattern (often a partial index on `(org_id) WHERE deleted_at IS NULL` or the partial unique name index already covers it)
- [ ] **High-churn tables** have autovacuum tuned:
  ```sql
  ALTER TABLE t SET (
      autovacuum_vacuum_scale_factor = 0.01,
      autovacuum_vacuum_cost_delay   = 2,
      fillfactor                     = 70
  );
  ```
  Apply to: `job_queue`, `feed_sync_state`, and any table with frequent UPDATE-heavy workloads

---

## 8. Retention & Lifecycle

- [ ] **Soft-delete** (`deleted_at NULL`): for user-created entities the user can restore or where name reuse must be blocked
- [ ] **Hard-delete**: for child items with no identity of their own (e.g., `watchlist_items`)
- [ ] **Append-only with age-based retention** (no `deleted_at`): for audit/run logs (`alert_events`, `alert_rule_runs`, `feed_fetch_log`) — verify the table is listed in §21 retention policy
- [ ] Tables that accumulate indefinitely without a retention mechanism are flagged

---

## 9. Evaluator / Worker Cursors

For any table that a background job polls (batch evaluator, EPSS evaluator, feed sync):

- [ ] Cursor state is stored — either in `feed_sync_state` (reuse existing rows like `feed_name = 'alert:batch'`) or in a new purpose-built table
- [ ] Cursor column type matches the comparison (`timestamptz` for `date_modified_canonical > $cursor`)
- [ ] High-churn cursor rows have autovacuum tuned (see §7 above)

---

## Summary

```
Tables reviewed: N
❌ Failures: X  — must fix before writing migrations
⚠️  Warnings: Y
✅ OK: Z
```

List all ❌ failures. Confirm nothing proceeds to migration until all ❌ items are resolved.
