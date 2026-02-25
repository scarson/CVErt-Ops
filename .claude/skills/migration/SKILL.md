---
name: migration
description: Generate a golang-migrate SQL migration file pair for CVErt Ops following all PLAN.md Appendix A and implementation-pitfalls.md conventions. Use when creating tables, columns, indexes, constraints, or RLS policies.
argument-hint: "<brief description of the schema change>"
---

# Generate Migration

Generating a `golang-migrate` migration for CVErt Ops. Change: **$ARGUMENTS**

## Step 1: Determine the next migration number

Run `ls migrations/` to see existing files. The next number is highest existing + 1, zero-padded to 6 digits (e.g., `000007`). Create:
- `migrations/<number>_<slug>.up.sql`
- `migrations/<number>_<slug>.down.sql`

Slug: short, `snake_case`, descriptive (e.g., `create_cve_sources`, `add_org_id_to_watchlist_items`).

---

## Step 2: Mandatory conventions — apply every applicable rule

### A. Transaction directive
- **Default:** migrations run in a transaction — no directive needed.
- **REQUIRED EXCEPTION:** If the migration uses `CREATE INDEX CONCURRENTLY` or `DROP INDEX CONCURRENTLY`, add `-- migrate:no-transaction` as the **very first line** of **both** `.up.sql` and `.down.sql`. Running CONCURRENTLY inside a transaction block is a Postgres error.

### B. Index creation
Every `CREATE INDEX` MUST be `CREATE INDEX CONCURRENTLY`. No exceptions. Use `IF NOT EXISTS` for safety.

### C. Primary keys and timestamps
- Org-scoped tables: `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
- Global tables: domain-appropriate PK (`cve_id TEXT`, etc.)
- All timestamps: `timestamptz NOT NULL DEFAULT now()`

### D. New org-scoped tables — full checklist
Every table owned by an org MUST include all three:

**1. `org_id` column:**
```sql
org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
```

**2. `org_id` index (same migration file):**
```sql
CREATE INDEX CONCURRENTLY <table>_org_id_idx ON <table> (org_id);
```

**3. RLS policy (same migration file, after table creation):**
```sql
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <table> FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON <table>
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```

### E. Child/join tables — org_id denormalization (REQUIRED)
Child tables of an org-scoped parent MUST also carry `org_id UUID NOT NULL` with the same index and RLS policy as above. Do NOT omit it just because the parent already has it. The RLS policy on the parent table does NOT protect the child.

Tables requiring denormalization (non-exhaustive): `watchlist_items`, `alert_events`, `notification_deliveries`, `group_members`, `cve_annotations`, `report_runs`, `alert_rule_runs`.

### F. Soft-deletable entities with user-facing names
If the table has `deleted_at TIMESTAMPTZ NULL` and a unique name, use a **partial unique index**, not a table constraint:
```sql
CREATE UNIQUE INDEX CONCURRENTLY <table>_name_uq ON <table> (org_id, name)
WHERE deleted_at IS NULL;
```
Applies to: `watchlists`, `notification_channels`, `saved_searches`, `alert_rules`, `groups`.

### G. JSONB columns in upserts — comment required
When adding a JSONB column that will be upserted from feed data, add a comment reminding that the application MUST use `IS DISTINCT FROM` to prevent TOAST bloat:
```sql
-- Application upsert: ON CONFLICT DO UPDATE SET col = EXCLUDED.col
--   WHERE existing_table.col IS DISTINCT FROM EXCLUDED.col
```

### H. High-churn tables (job queues, event logs)
Tables with frequent INSERT+UPDATE+DELETE churn need AUTOVACUUM tuning:
```sql
ALTER TABLE <table> SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 70
);
```

### I. Retention cleanup index
Tables that will be pruned by the daily retention job need an index on their age column:
```sql
CREATE INDEX CONCURRENTLY <table>_created_at_idx ON <table> (created_at);
```
Applies to: `cve_raw_payloads`, `feed_fetch_log`, `notification_deliveries`, `alert_rule_runs`, `report_runs`, `job_queue` (on `finished_at`).

---

## Step 3: Down migration

The `.down.sql` must exactly reverse `.up.sql`:
- `DROP TABLE IF EXISTS <table> CASCADE` for new tables
- `DROP INDEX CONCURRENTLY IF EXISTS <name>` for new indexes
- `DROP POLICY IF EXISTS org_isolation ON <table>; ALTER TABLE <table> DISABLE ROW LEVEL SECURITY;` for RLS
- Restore dropped columns/constraints

Down migrations using `DROP INDEX CONCURRENTLY` also need `-- migrate:no-transaction` as the first line.

---

## Step 4: Pre-write validation

Check before writing:
- [ ] `-- migrate:no-transaction` needed? (is CONCURRENTLY used?)
- [ ] All indexes use `CONCURRENTLY`?
- [ ] New org-scoped table: `org_id` column + index + RLS policy?
- [ ] Child tables: `org_id` denormalized?
- [ ] Soft-delete table: partial unique index (not table constraint)?
- [ ] JSONB column: comment about `IS DISTINCT FROM`?
- [ ] High-churn table: AUTOVACUUM settings?
- [ ] Cleanup-eligible table: retention index on timestamp?
- [ ] Down migration is complete and reversible?

Write both files when validation passes.
