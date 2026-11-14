# Plan review round 4: independent cross-model read (Codex, gpt-6.1-sol, high effort, cold)

Raw findings as returned, reviewing dev/plans/2026-11-13-product-match-rules-plan.md after round 3.

## Findings

1. **Location:** Task 5.6: “before committing… restore it (`git checkout -- internal/alert/evaluator.go`).”  
   **Dimension:** Cross-task dependencies; testing pitfalls.  
   **Claim:** This can discard Task 5.5’s implementation along with the temporary mutation. The prescribed commit groups Tasks 5.4–5.6, so the index need not contain the new batch branch yet.  
   **Evidence:** Plan lines 749 and 756; the current `internal/alert/evaluator.go:738–748` contains only the material-change scan. Checked `git checkout -h`; this is a whole-file checkout, not an inverse of the mutation.  
   **Suggested fix:** Save the implemented file before mutation and restore that exact snapshot, or reverse only the mutation hunk. Rerun the regression test after restoration.

2. **Location:** Task 3.3: “Full-name recheck… `v = strings.Repeat("x", 200)`… vendor is `v + strings.Repeat("y", 100)`.”  
   **Dimension:** Testing pitfalls.  
   **Claim:** This fixture does not test the full-name recheck: the truncated index keys already differ, so removing the full-vendor equality would still reject the row.  
   **Evidence:** `internal/check/keys.go:254–260` truncates vendor keys to 256 runes. A PowerShell calculation of the prescribed fixture returned key lengths 200 and 256, with `IndexKeysEqual: false`; the index uses that truncation in `migrations/000059_check_lookups.up.sql:22`.  
   **Suggested fix:** Add a direct SQL-builder integration test using synthetic names longer than 256 characters whose truncated keys collide. Keep the public parser’s 255-character limit tested separately.

3. **Location:** Task 4.2: “`pgx.ParseConfig(...)`… then `stdlib.OpenDB(*cfg)`.”  
   **Dimension:** Context gaps; measurement validity.  
   **Claim:** The prescribed configuration uses pgx’s default statement-cache mode instead of the application’s execution mode. It therefore does not reproduce production connection behavior for the measurement gate, including the repeated activation queries.  
   **Evidence:** The pinned pgx v5.9.2 `conn.go:191–217` defaults to `QueryExecModeCacheStatement`. Production explicitly uses `QueryExecModeCacheDescribe` in `internal/store/store.go:17–22`; test pools also set it in `internal/testutil/postgres.go:157,171`.  
   **Suggested fix:** Explicitly set `cfg.DefaultQueryExecMode = store.DefaultQueryExecMode` for both measurement connections. Record the selected mode in the results.

4. **Location:** Task 4.2, M5: “planning time reported separately”; Task 4.3: “Every threshold passes.”  
   **Dimension:** Ambiguity.  
   **Claim:** The gate does not specify whether thresholds compare execution time alone or planning plus execution, nor whether both first-run and warm results must pass. An executor could report expensive planning separately and still mark the limit rule as passing.  
   **Evidence:** Plan lines 617, 634 and 651 provide separate timings and one pass/fail threshold. The approved design explicitly requires the limit-rule measurement “including planning time” at `dev/plans/2026-11-13-product-match-rules-design.md:408`.  
   **Suggested fix:** Define the comparison formula and applicable runs explicitly. For the limit rule, include planning plus execution in the threshold comparison while retaining both components in the table.

Substantive findings: 4
