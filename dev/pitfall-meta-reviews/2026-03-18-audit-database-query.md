# Pitfall Audit: Database & Query Patterns

**Date:** 2026-03-18
**Auditor:** audit-db agent (Explore)
**Scope:** 23 pitfalls across store layer, merge pipeline, migrations, sqlc config
**Code paths:** `internal/store/*`, `internal/merge/*`, `migrations/*`, `sqlc.yaml`

---

## Summary Table

| ID | Title | Status | Evidence |
|---|---|---|---|
| 2.1 | EPSS Unconditional UPDATE (IS DISTINCT FROM) | VALIDATED | `store/queries/cves.sql:149`, `feed/epss/adapter.go:250-283` |
| 2.2 | FTS GIN Write Churn (separate table) | VALIDATED | `migrations/000002`, `store/queries/cves.sql:110-122` |
| 2.3 | Advisory Lock Hash (FNV-1a in Go) | VALIDATED | `merge/advisory.go:14-38` |
| 2.4 | RLS Fail-Closed + bypass_rls | VALIDATED | `migrations/000007:24-33`, `store/store.go:160-176` |
| 2.5 | RowsAffected Ambiguity (two-statement) | VALIDATED | `store/queries/cves.sql:124-137`, `feed/epss/adapter.go:106-109` |
| 2.6 | SELECT Without FROM (VALUES casts) | VALIDATED | `store/queries/cves.sql:129-137` |
| 2.7 | EPSS Staging Lifecycle | VALIDATED | `merge/pipeline.go:259-279` |
| 2.8 | EPSS/CVE Upsert Race (advisory lock) | VALIDATED | `feed/epss/adapter.go:260-261`, `merge/pipeline.go:60-62` |
| 2.9 | Child Table RLS (org_id denormalization) | VALIDATED | All child table migrations include org_id + RLS |
| 2.10 | Null Byte Poisoning | VALIDATED | `feed/util.go:55-64`, all adapters |
| 2.11 | sqlc UUID Type Pollution | VALIDATED | `sqlc.yaml:16-21` |
| 2.12 | Dynamic IN 65k Limit | VALIDATED | `ANY($1::type[])` pattern throughout |
| 2.13 | Squirrel Bypasses RLS (withOrgRawTx) | VALIDATED | `store/store.go:101-121` |
| 2.14 | Store Tests Use AppStore for RLS | VALIDATED | `store/store_test.go:69`, `store/rls_test.go:43-50` |
| 2.15 | ON CONFLICT Matches Partial Index | VALIDATED | `alert_rules.sql:78`, `notification_deliveries.sql:89` |
| 2.16 | Semicolons in SQL Comments | VALIDATED | All migrations clean |
| 2.17 | Transaction Helper Selection | VALIDATED | `store/store.go:44-176` |
| 11.1 | JSONB TOAST Bloat (IS DISTINCT FROM) | VALIDATED | `store/queries/cves.sql:67` |
| 11.2 | CREATE INDEX CONCURRENTLY | VALIDATED | All 20+ migrations have `migrate:no-transaction` |
| 11.3 | Soft-delete + UNIQUE (partial index) | VALIDATED | Partial unique indexes on soft-delete tables |
| 11.4 | notification_channels Soft-delete | VALIDATED | `store/notification_channel.go` |
| 11.5 | Array Fields Sorted Before Hash | VALIDATED | `merge/hash.go:56-68` |
| 12.1 | Dynamic IN 65k (duplicate of 2.12) | VALIDATED | ANY array pattern used |

**Totals:** 23 VALIDATED, 0 issues found

---

## Detailed Findings

### 2.1 EPSS Unconditional UPDATE (IS DISTINCT FROM guard)
**Status:** VALIDATED
**Evidence:** `internal/store/queries/cves.sql:149` (UpdateCVEEPSS uses IS DISTINCT FROM), `internal/feed/epss/adapter.go:250-283`
**All instances checked:** Merge pipeline applies staged EPSS with same guard at `pipeline.go:266-274`
**Notes:** Prevents 250k dead tuples/day from unchanged EPSS scores.

### 2.2 FTS GIN Index Write Churn
**Status:** VALIDATED
**Evidence:** `migrations/000002_create_cve_core.up.sql:64-70` (cve_search_index is separate 1:1 table), `store/queries/cves.sql:110-122` (UpsertCVESearchIndex with IS DISTINCT FROM)
**Notes:** GIN rewrite isolation is correct. FTS updates only when document actually changes.

### 2.3 Advisory Lock Hash (FNV-1a)
**Status:** VALIDATED
**Evidence:** `internal/merge/advisory.go:14-38` (advisoryKey uses fnv.New64a())
**Notes:** Hash computed in Go, not Postgres internal hashtext. Portable and testable.

### 2.4 RLS Fail-Closed + bypass_rls
**Status:** VALIDATED
**Evidence:** `migrations/000007:24-33` (RLS policy uses current_setting with TRUE for missing_ok), `store/store.go:160-176` (WorkerTx sets bypass_rls)
**All instances checked:** All org-scoped migrations have matching RLS policies
**Notes:** Dual-layer isolation with fail-closed default. Workers bypass safely within transactions.

### 2.5 RowsAffected Ambiguity
**Status:** VALIDATED
**Evidence:** `store/queries/cves.sql:124-137`, `feed/epss/adapter.go:106-109` (comments explicitly warn against RowsAffected)
**Notes:** Two-statement pattern runs both unconditionally. No RowsAffected branching.

### 2.6 SELECT Without FROM
**Status:** VALIDATED
**Evidence:** `store/queries/cves.sql:129-137` (VALUES with explicit type casts)
**Notes:** Uses `VALUES ($1::text, $2::double precision, $3::date)` for unambiguous sqlc type inference.

### 2.7 EPSS Staging Lifecycle
**Status:** VALIDATED
**Evidence:** `merge/pipeline.go:259-279` (Step 9: read, apply, delete — always cleans up)
**Notes:** Staging rows always deleted regardless of whether score was found.

### 2.8 EPSS/CVE Upsert Race
**Status:** VALIDATED
**Evidence:** `feed/epss/adapter.go:260-261` (acquires same advisory lock), `merge/pipeline.go:60-62`
**Notes:** Both paths coordinate via CVEAdvisoryKey. TOCTOU race prevented.

### 2.9 Child Table RLS Bypass
**Status:** VALIDATED
**Evidence:** All child table migrations include `org_id UUID NOT NULL` + BTREE index + RLS policy
**All instances checked:** alert_rules, alert_events, notification_channels, notification_deliveries, watchlists, etc.
**Notes:** No parent-join reliance for tenant isolation.

### 2.10 Null Byte Poisoning
**Status:** VALIDATED
**Evidence:** `feed/util.go:55-64` (StripNullBytes/StripNullBytesJSON), `merge/pipeline.go:49-50`, all adapters
**All instances checked:** NVD, MITRE, OSV, GHSA, EPSS adapters all call StripNullBytes
**Notes:** Comprehensive sanitization at feed adapter layer before DB writes.

### 2.11 sqlc UUID Type Pollution
**Status:** VALIDATED
**Evidence:** `sqlc.yaml:16-21` (overrides for uuid → google/uuid.UUID, nullable uuid → NullUUID)
**Notes:** No pgtype.UUID in generated code.

### 2.12 Dynamic IN Clause 65k Limit
**Status:** VALIDATED
**Evidence:** `notification_deliveries.sql:15` (ANY($1::uuid[])), `watchlist.sql:53` (ANY($1::uuid[]))
**All instances checked:** No dynamic `IN ($1, $2, ...)` construction found anywhere
**Notes:** Consistent ANY array pattern. No hard limit.

### 2.13 Squirrel Bypasses RLS
**Status:** VALIDATED
**Evidence:** `store/store.go:101-121` (withOrgRawTx implemented), `store/dsl_executor.go:175-183`
**Notes:** CVE reads use s.db.QueryContext directly — ACCEPTABLE because CVEs are global, non-org-scoped.

### 2.14 Store Tests Use AppStore
**Status:** VALIDATED
**Evidence:** `store/store_test.go:69`, `store/rls_test.go:43-50`
**Notes:** RLS tests use AppStore (NOBYPASSRLS role) for cross-tenant isolation verification.

### 2.15 ON CONFLICT Matches Partial Index
**Status:** VALIDATED
**Evidence:** `alert_rules.sql:78`, `notification_deliveries.sql:89`
**Notes:** ON CONFLICT predicates match corresponding partial unique indexes in migrations.

### 2.16 Semicolons in SQL Comments
**Status:** VALIDATED
**Notes:** No semicolons in SQL comments found across all migration files.

### 2.17 Transaction Helper Selection
**Status:** VALIDATED
**Evidence:** `store/store.go:44-176` (withBypassTx, withOrgTx, withOrgRawTx, WorkerTx)
**All instances checked:** Store methods consistently use appropriate helpers. No direct s.db calls in org-scoped methods.
**Notes:** Well-established pattern with clear semantic boundaries.

### 11.1 JSONB TOAST Bloat
**Status:** VALIDATED
**Evidence:** `store/queries/cves.sql:67` (WHERE cve_sources.normalized_json IS DISTINCT FROM EXCLUDED.normalized_json)
**Notes:** JSONB upserts properly guard against unnecessary TOAST writes.

### 11.2 CREATE INDEX CONCURRENTLY
**Status:** VALIDATED
**Evidence:** All 20+ migration files with concurrent indexes have `-- migrate:no-transaction` as first line
**Notes:** Consistent throughout. No violations found.

### 11.3 Soft-delete + UNIQUE
**Status:** VALIDATED
**Evidence:** `migrations/000017` and others use `WHERE deleted_at IS NULL` partial unique indexes
**Notes:** Name reuse for deleted rows works correctly.

### 11.4 notification_channels Soft-delete
**Status:** VALIDATED
**Evidence:** `store/notification_channel.go` implements soft-delete via deleted_at
**Notes:** Delivery history preserved. Active lookups filter by deleted_at IS NULL.

### 11.5 Array Fields Sorted Before Hash
**Status:** VALIDATED
**Evidence:** `merge/hash.go:56-68` (CWEIDs, CPEs, AffectedPkgs all sorted)
**Notes:** Lexicographic sort before JSON canonicalization ensures deterministic hash.

### 12.1 Dynamic IN 65k (duplicate of 2.12)
**Status:** VALIDATED
**Notes:** Same finding as 2.12 — should be merged in reorganized document.

---

## New Discoveries

1. **CVE queries run outside transaction context** — `store/cve.go:34` (GetCVEMaterialHash), `store/cve.go:210` (SearchCVEs) use s.db.QueryContext directly. SAFE because CVEs are global, non-org-scoped. No security issue.

2. **Null slice initialization before pq.Array** — `merge/pipeline.go:150-154` and `merge/hash.go:70-79` ensure nil slices become []. Prevents JSONB "null" vs "[]" mismatch.

3. **strings.Clone for CSV fields** — `feed/epss/adapter.go:212` uses strings.Clone on CSV record fields. Correctly addresses pitfall 6.2 (GC-invisible RAM retention from large buffers).

4. **Duplicate pitfall: 12.1 = 2.12** — These are the same finding (dynamic IN clause 65k limit). Should be merged during reorganization.

---

## Assessment

**All 23 pitfalls VALIDATED.** The database layer is the most thoroughly compliant area of the codebase. Every prescribed pattern is correctly implemented. The transaction helper system, RLS dual-layer isolation, and EPSS coordination patterns are all production-ready.
