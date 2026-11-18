# Bug-hunt kickoff — suspected bugs from the 2026-06-05 S2 alert-engine performance audit

Run: `bug-hunt-cycle` with the scope below. **Two items are security-relevant (missed alerts).**

**Scope:** `internal/alert/evaluator.go` (batch/EPSS sweep + realtime), `internal/alert/dsl/**`,
`internal/store/dsl_executor.go`. Surfaced incidentally during the S2 performance audit.

**Seed findings (verify, don't trust):**
- **[HIGH] Sweep can silently skip matches past the 5,000 candidate cap while advancing the cursor** —
  `internal/alert/evaluator.go:172-225`. The batch/EPSS sweep accumulates the whole window into
  `allCandidateIDs`, evaluates each rule with `candidateCap`, and on overflow returns `partial=true`
  (fail-closed) — but `writeCursor` still advances past the entire window afterward, so candidates beyond
  the cap are never evaluated and never revisited. For a security product this is **missed alerts**.
  Verify whether `partial` should block the cursor advance (or whether the window is otherwise re-scanned).
- **[LOW — likely FALSE POSITIVE, confirm] keyset predicate uses separate `date > $1 AND cve_id > $2`** —
  `internal/alert/evaluator.go:595-615` (`getCVEsModifiedSince`). A lane flagged this vs a row-value
  `(date,cve_id)` keyset. On re-reading: the query `ORDER BY cve_id ASC` with a **fixed** `date > since`
  floor pages by `cve_id` alone (date is a filter, not a sort key), which is complete. Likely **not** a
  bug — confirm rather than trust the lane.
- **[LOW] `candidates_evaluated` metric records input slice length, not rows actually evaluated** —
  `internal/alert/evaluator.go:414,463`. Metrics correctness only.
- **[GUARD] `totalMatches` accumulator + resolution-detection atomicity** — `evaluator.go:200-217`.
  Not a current bug; a guard the eventual sweep-parallelization fix (perf finding P7) must respect.

These were noticed while auditing performance and were NOT investigated. Treat them as leads, not
confirmed bugs. The HIGH item warrants priority.
