# Activation scan writes a page of events at once

## What was done

The alert evaluator's activation scan (`EvaluateActivation`) now records each 1,000-CVE page's matches with one store call, `RecordActivationAlertEvents` in `internal/store/alert_rule.go`. Before this, the scan made one `cveExists` query and one `InsertAlertEvent` transaction per matched CVE (plus a `ReopenAlertEvent` transaction when the event already existed). Each of those transactions took the org's alert-event feed lock. On a 2.6 M-CVE ingest, a rule matching 200,252 CVEs took 12 min 5 s to activate, about 8 min of it in those per-event transactions. That is close to the 15-minute limit after which `SweepZombieActivations` fails the job and sets the rule to `error`.

`RecordActivationAlertEvents` runs one transaction per page:

1. It takes the org's feed lock (`LockAlertEventFeed`) once.
2. `InsertActivationAlertEvents` inserts the page from two bound arrays (`unnest(cve_ids)`, `unnest(material_hashes)`) with `suppress_delivery = true` and `ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING`.
3. `ReopenActivationAlertEvents` is the set-based form of `ReopenAlertEvent`. It sets resolved events at a matched hash open again, with `suppress_delivery = true`, `times_fired + 1` and a new feed position.

Both statements skip a CVE that is no longer in `cves`. This replaces the per-event `cveExists` check for activation: a late-binding merge can rename a CVE after the candidate query returned it, and an event under the old ID could never resolve.

The realtime and batch paths are unchanged. They still write event by event, because each new or reopened event is fanned out to notification channels.

## Decisions and gotchas

- **Same results as the per-event path.** The insert runs before the reopen in the same transaction. A row inserted by the first statement is open, so the reopen does not touch it, which gives the per-event rule of reopening only when the insert found the event. `TestRecordActivationAlertEvents_MatchesPerEventPath` writes the same page both ways for two rules with the same history and compares the rows. The page covers a new CVE, an open event, a resolved event, a resolved event at an earlier hash, a CVE with no `cves` row, and a pair repeated in the page.
- **A pair repeated in the page is written once.** `ON CONFLICT DO NOTHING` treats the repeat as a conflict with the row inserted earlier in the same statement, and `UPDATE ... FROM` updates a row once even when it joins several times. Both behaviours are covered by the test above.
- **Feed ordering (implementation-pitfalls.md API-12, positions drawn under the org lock).** The lock is the first statement, before any `nextval` and before the reopen locks rows, so the lock order is the same as every other writer's. The whole page becomes visible at commit, and the lock is released after that. A conflicting insert still consumes a sequence value, as the per-event insert did. Gaps in `feed_seq` are allowed.
- **The rename gap is unchanged in kind.** The existence check now runs inside the writing statement, not before a separate transaction. A rename that commits after the statement's snapshot can still leave one event under the old ID. The `cveExists` comment already accepts this gap, because closing it would mean taking the merge pipeline's CVE lock on every write.
- **The store method returns the number of events inserted or reopened.** The evaluator ignores it. Tests use it.
- **Lint:** the `golangci-lint` in `~/go/bin` (v2.10.1, built with Go 1.26) refuses the Go 1.27.4 module. The CI pin works: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run --allow-parallel-runners <pkgs>`.

## Quality checks

- New store tests (`internal/store/alert_event_activation_test.go`) cover: equivalence with the per-event path, a full 1,000-match page with distinct feed positions, waiting for the feed lock, and writes and reopens through the application role.
- New evaluator tests (`internal/alert/activation_page_test.go`): a 2,005-CVE activation makes 3 page writes and no per-event inserts or reopens; a CVE renamed between the candidate read and the page write gets no event; a failed page write sets the rule to `error`. All three failed before the evaluator change.
- `go test ./internal/alert/... ./internal/store/...` passes. `golangci-lint` v2.15.0 reports 0 issues on both packages. The `/pitfall-check` skill found no issues.
- Timing on the test container (20,000 matches against a near-empty database): 1.667 ms per event written one by one, 0.118 ms per event written in 1,000-match pages, 14× faster. At the paged rate the 200,252-event activation's writes would take about 25 s instead of about 8 min, so the activation would take about 4.5 min with its candidate reads unchanged. This is an extrapolation. It was not re-measured on the 2.6 M-CVE copy.
