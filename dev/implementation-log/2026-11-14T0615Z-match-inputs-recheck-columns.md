# Match inputs re-check columns on cves

## What was built

| Feature | Files | Description |
|---|---|---|
| Migration 000063 | `migrations/000063_match_inputs_recheck.up.sql`, `.down.sql` | `cves` gains `match_inputs_hash text` and `date_match_inputs_changed timestamptz`, both nullable with no default, and the partial index `cves_date_match_inputs_changed_idx ON cves (date_match_inputs_changed) WHERE date_match_inputs_changed IS NOT NULL`, created `CONCURRENTLY`. Both files start with `-- migrate:no-transaction`. The down file drops the index `CONCURRENTLY`, then both columns. |
| Migration test | `migrations/match_inputs_recheck_test.go` | Runs the down file on a migrated test database and checks the columns and index are gone, runs the up file and checks both columns (type, nullable, no default) and the index (indexed column, partial predicate, valid), runs the up file a second time, then the down file again. |

The columns carry the re-check signal for rule match inputs that are not `material_hash` inputs: CNA vendor and product names, and the `vulnerable` flag of NVD CPE matches (MATCH-2 design section 7, `dev/plans/2026-11-13-product-match-rules-design.md`; Sam's ruling in its section 15.1: a separate signal, never a `material_hash` change). The merge writes them in the next commit. Neither column is exposed by the API.

## Key decisions

- 000063 was the next free number on `origin/dev` (checked with `git ls-tree` after a fetch).
- `internal/store/generated` is not regenerated here. `GetCVE` and the other generated queries name their columns, so this schema change alone changes no scan. The merge commit runs `sqlc generate`.

## Schema review findings (`schema-review` skill)

No failures. Findings, each with what was done:

1. RLS: `cves` is a global table with no `org_id` and no RLS, and the change adds none. No action.
2. Grants: `cvert_ops_app` holds table-level `SELECT, INSERT, UPDATE` (000035) and `DELETE` (000055) on `cves`, which cover new columns. No new grant.
3. Index use: the batch scan's condition `date_match_inputs_changed > $1` uses a strict operator, so the planner proves the partial predicate `IS NOT NULL` and can use the index. The scan's `ORDER BY cve_id` sorts the range's rows, the same shape as the existing `date_modified_canonical` branch. Task 5.5 measures this statement on the disposable copy.
4. Warning, accepted by the design: a NULL hash counts as changed, so every CVE is stamped on its first merge after deploy. After that the partial predicate excludes few rows, and the index approaches a full index. The burst of stamped rows in the batch window is the one-time re-check cost design section 7.1 accepts, and sends no duplicate alerts.
5. Warning, no action: `ALTER TABLE ... ADD COLUMN` takes an `ACCESS EXCLUSIVE` lock briefly. The project sets no `lock_timeout` in migrations, and the binary requires the schema at exactly its version, so migrations run before the server serves.
6. Write amplification: the merge writes `match_inputs_hash` on every upsert, but `date_match_inputs_changed`, the only indexed new column, changes only when the hash changes, so an unchanged CVE adds no index entry. No action.
7. Other writers of `cves`: only `UpsertCVE` writes canonical rows. `internal/testutil/seed.go` and test fixtures insert with explicit column lists and leave both columns NULL. No action.
8. Cursor: the batch cursor is `timestamptz`, the same type as the new column, and the merge stamps both dates from one clock value, so the existing 2-minute rescan window covers the new column (Task 5.5).

## Quality checks

- `go test ./migrations/... -count=1`: pass (6 tests). The new test failed first on the missing down file.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
