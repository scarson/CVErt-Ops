# Plan review round 8: independent cross-model read (Codex, gpt-6.1-sol, high effort, cold)

Raw findings as returned, reviewing dev/plans/2026-11-13-product-match-rules-plan.md after round 7.

## Findings

1. **Location:** Task 5.3 — “Lower-casing is Go's `strings.ToLower`; the hash only detects change, so its locale independence from the SQL `lower()` does not matter.”
   
   **Dimension:** Implementation pitfalls — data integrity.
   
   **Claim:** Normalizing away a distinction that SQL preserves can suppress the re-check signal. For example, Go lower-cases both `Knode` and `knode` to `knode`, while PostgreSQL under the `C` locale distinguishes them. Changing between those CNA names can change a product match without changing either hash or advancing either batch timestamp.
   
   **Evidence:** Task 3.2 prescribes SQL `lower(a.product)` for matching; design §5.1 explicitly acknowledges locale-dependent lower-casing. I checked Go’s Unicode table: U+212A maps to ASCII `k` (`unicode/tables.go:8870`). Database execution is excluded from this review; the exact runner probe is:
   
   ```sql
   BEGIN READ ONLY;
   SELECT lower(U&'\212Anode' COLLATE "C") = 'knode' AS kelvin_matches,
          lower('knode' COLLATE "C") = 'knode' AS ascii_matches;
   ROLLBACK;
   ```
   
   The expected results are `false` and `true`, despite identical Go-normalized hash inputs.
   
   **Suggested fix:** Compute the CNA hash inputs using the same PostgreSQL normalization and collation as matching, within the existing merge transaction. Add a regression test showing that a SQL-visible name change advances the signal while preserving `material_hash`.

2. **Location:** Task 2.1 — “Test: `internal/alert/dsl/dsl_test.go`” and “Through `store.ExecuteDSLQuery` on a `SeedCorpus` database…”
   
   **Dimension:** Context gaps; cross-task dependencies.
   
   **Claim:** The only listed test destination cannot currently run the prescribed database-backed tests: the DSL package lacks the required TestMain.
   
   **Evidence:** Searching `internal/alert/dsl` found no `TestMain` or `NewTestDB` usage. `dsl_test.go:2` identifies these as pure logic tests. `internal/testutil/postgres.go:91–96,122–124` explicitly rejects `NewTestDB` unless TestMain calls `testutil.Run`; `internal/store/main_test.go:12` already provides that setup.
   
   **Suggested fix:** Assign the NULL/empty-array integration cases explicitly to `internal/store/dsl_executor_test.go` and include that file in Task 2.1’s changes. Keep the SQL-shape and parameter-count tests in the DSL package.

Substantive findings: 2
