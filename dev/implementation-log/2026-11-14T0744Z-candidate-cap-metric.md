# Metric and log when a candidate query exceeds the candidate cap

## What was built

| Feature | Files | Description |
|---|---|---|
| Counter | `internal/metrics/alert.go` | `cvertops_alert_candidate_cap_exceeded_total`: candidate queries that returned more than the cap (5,000) and so matched nothing. |
| Emit point | `internal/alert/evaluator.go` (`queryCandidates`) | Increments the counter and logs a warning with the rule ID when the cap is exceeded. PLAN.md §10.2 requires an operator-facing metric and log entry for this case. |

## Key decisions

- **No `path` label.** `queryCandidates` does not know which evaluation path called it. Only the dry-run can exceed the cap today: realtime passes one candidate ID, and batch, EPSS and activation pass at most 5,000 IDs per statement (PLAN.md §10.2, chunked evaluation), so the prefilter cannot return more rows than the cap. The counter stays in `queryCandidates` so that a path added later without chunking is still counted.

## Quality checks

- `TestDryRun_CandidateCapFailClosed` asserts the counter rises by 1; failed to compile before the counter existed, passes now.
- `go test ./internal/metrics/ -run TestAlertMetricsRegistered`: pass.
