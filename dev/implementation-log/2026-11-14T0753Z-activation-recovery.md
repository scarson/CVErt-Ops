# Recover alert rules stuck in activating after a worker crash

## What was built

| Feature | Files | Description |
|---|---|---|
| Stale recovery honours `max_attempts` | `internal/store/queries/jobs.sql`, `internal/store/generated/jobs.sql.go`, `internal/store/jobs.go`, `internal/worker/pool.go` | `RecoverStaleJobs` returns a stuck job with attempts left to `pending`, and marks a job that has used its last attempt `dead`, with `finished_at` and a `last_error` saying its worker stopped responding. Applies to every queue. |
| Zombie activation sweeper | `internal/alert/evaluator.go` (`SweepZombieActivations`) | Finds rules in `activating`, not deleted, with `updated_at` older than 15 minutes and no `pending` or `running` `alert_activation` job under the rule's lock key; logs each and moves it to `error` with `SetAlertRuleStatusIf`. Does not touch job rows. Reads `alert_rules` in the evaluator's RLS bypass transaction. |
| Shared activation lock key | `internal/alert/evaluator.go` (`ActivationLockKey`), `internal/api/alert_rules.go` (`enqueueActivation`) | The API enqueues and the sweeper looks up the same `activation:<rule_id>` key. |
| Docs | `PLAN.md` §10.3 (zombie activating rule recovery), worker goroutines bullet; `dev/implementation-pitfalls.md` NOTIFY-5 | Describe the stale recovery attempt limit and the sweeper as built. |

## Key decisions

- **The sweeper matches jobs on `lock_key`, not on `payload->>'rule_id'`.** The lock key is what `EnqueueJob` dedups on (`ON CONFLICT (lock_key) WHERE status IN ('pending','running')`), and the partial unique index `job_queue_lock_key_active` serves the `NOT EXISTS` lookup. The prefix is a constant in the alert package so the API and the sweeper cannot drift apart.
- **`updated_at` is the age guard.** `CreateAlertRule` sets it by default, and `UpdateAlertRule` (the PATCH path that moves a rule back to `activating`) and `SetAlertRuleStatusIf` set it to `now()`. So a rule that has just been saved or re-enabled is not swept before its job is enqueued.
- **The sweeper no longer fails jobs.** The pool's stale recovery (threshold 12 minutes, every minute) owns stuck jobs: it re-queues them up to `max_attempts` (3 for activation) and then marks them `dead`. The sweeper only resolves the rule, and only once no live job remains, so a rule whose job is still being retried stays `activating`.
- **A rule moved to `error` cannot be activated by a late job.** `EvaluateActivation` moves a rule only from `activating` to `active`, so users retry by PATCHing the rule, which enqueues a new job.

## Gotchas

- The tests encoded the lock key as `alert:activation:<rule_id>`, while the API uses `activation:<rule_id>`. The old sweeper matched on the job's status and `locked_at` only, so the mismatch went unnoticed. The tests now build the key with `alert.ActivationLockKey`, and `TestAlertRule_ActivatingEnqueuesJob` asserts the API enqueues under that key.
- The old sweeper set job status `failed`, which is not a `job_queue` status (`pending`, `running`, `succeeded`, `dead`); retention cleanup only removes `succeeded` and `dead` rows.
- The sweeper test builds its evaluator on `tdb.AppStore` (NOBYPASSRLS), so a query against `alert_rules` outside the bypass transaction returns no rows and the test fails.
- `sqlc generate` rewrote every generated file with LF; only `jobs.sql.go` had content changes, and the rest were restored.

## Quality checks

- `go test ./internal/store/ -run RecoverStale -count=1`: 4 pass. `TestRecoverStaleJobs_ExhaustedJobBecomesDead` failed before the query change (exhausted job stayed `pending`).
- `go test ./internal/alert/ -run SweepZombie -count=1`: `TestEvaluatorSweepZombieActivations` (9 subtests) and `TestSweepZombieActivations_NoZombies` pass. Before the sweeper rewrite, the dead-job, no-job and running-job subtests failed.
- `go test ./internal/worker/ -count=1`: pass.
- `go test ./internal/api/ -run 'TestAlertRule_ActivatingEnqueuesJob|TestAlertRule_ReEnableSetsActivating' -count=1`: 2 pass.
- `golangci-lint` v2.15.0 on `internal/worker`, `internal/store`, `internal/alert`, `internal/api`, `cmd/cvert-ops`: 0 issues.
