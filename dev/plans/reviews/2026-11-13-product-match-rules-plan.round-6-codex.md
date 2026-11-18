# Plan review round 6: independent cross-model read (Codex, gpt-6.1-sol, high effort, cold)

Raw findings as returned, reviewing dev/plans/2026-11-13-product-match-rules-plan.md after round 5.

## Findings

1. **Location:** Task 5.5, “`UNION` of two keyset scans,” and Task 4.3, “Its cost is not measured here. It is a range scan.”
   
   **Dimension:** Implementation pitfalls; measurement coverage.
   
   **Claim:** The plan excludes the new batch-selection query from measurement while assuming its access path. Unlike today’s directly limited query, the prescribed `UNION` places deduplication before the outer limit and has no branch limits. Whether it repeatedly processes the entire eligible set on each page needs verification.
   
   **Evidence:** Checked `internal/alert/evaluator.go:223` (repeated 1,000-ID pages) and `internal/alert/evaluator.go:738` (existing directly limited query). Database execution is outside this review’s authorization. On a populated disposable copy after Phase 5, run this exact probe with `since`, `after`, and `page_size` set to the evaluator’s actual parameters, for both first and later pages:
   
   ```sql
   EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
   SELECT cve_id FROM (
       SELECT cve_id FROM cves
       WHERE date_modified_canonical > :'since'::timestamptz
         AND cve_id > :'after'::text
       UNION
       SELECT cve_id FROM cves
       WHERE date_match_inputs_changed > :'since'::timestamptz
         AND cve_id > :'after'::text
   ) c
   ORDER BY cve_id ASC LIMIT :page_size;
   ```
   
   **Suggested fix:** Add this measurement after Phase 5 on the disposable copy, including a substantial eligible set and overlapping branches. Record the actual access paths and pagination cost before asserting that the query performs bounded range scans.

2. **Location:** Task 2.5, “create rules with `mustRule`; run `EvaluateActivation` or `EvaluateRealtime`; assert event rows.”
   
   **Dimension:** Context gaps; testing pitfalls.
   
   **Claim:** The setup omits the rule-status transition required for realtime evaluation. `mustRule` creates a draft rule; realtime ignores it, so negative cases can pass without exercising their predicates and positive cases fail for an unrelated reason.
   
   **Evidence:** Source checks show `Status: "draft"` at `internal/alert/evaluator_test.go:122`, the separate `activateRule` helper at `internal/alert/evaluator_test.go:134`, and the active-only query at `internal/store/queries/alert_rules.sql:49`. The referenced fixture explicitly calls both helpers at `internal/alert/watchlist_cve_test.go:51`. Activation’s final transition also requires the starting status to be `activating` (`internal/alert/evaluator.go:352`).
   
   **Suggested fix:** Specify `activateRule` before realtime/batch tests and `status='activating'` before activation tests. Make that setup explicit for Tasks 3.3 and 5.6 as well, and assert the expected status.

3. **Location:** Task 5.3, “Re-ingest with only a CNA product change … `date_match_inputs_changed` advanced.”
   
   **Dimension:** Testing pitfalls.
   
   **Claim:** The prescribed sequential-ingest assertion assumes that wall-clock timestamps increase between merges. A correct implementation can fail this assertion when the Windows clock steps backward—the exact failure mode documented by the project.
   
   **Evidence:** The merge timestamp comes from `time.Now().UTC()` at `internal/merge/pipeline.go:187`. `dev/testing-pitfalls.md:192` explicitly prohibits cross-operation clock-order assumptions and records backward steps on this host.
   
   **Suggested fix:** Test the upsert CASE using explicit clock arguments and fixed prior timestamps. For pipeline integration, age the existing re-check timestamp before the change and assert that material timestamps remain unchanged, without relying on consecutive live clock readings being ordered.

Substantive findings: 3
