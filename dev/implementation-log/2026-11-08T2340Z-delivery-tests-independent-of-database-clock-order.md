# Delivery tests independent of database clock order

## What was built

- `TestDB.ClaimUntilDeliveriesAttempted` in `internal/testutil/delivery_claims.go` repeats a claim until no pending delivery with `last_attempted_at IS NULL` and a `send_after` within 10 seconds remains, and fails after 10 seconds. Delivery tests in `internal/store` and `internal/notify` use it, through `claimDeliveries` and `runClaimUntilAttempted`, wherever a claim must find a just-written delivery.
- Tests that called `ResetStuckDeliveries(ctx, 0)` pass a negative threshold, because `updated_at < now()` has the same dependence on clock order.
- `TestWorker_BackoffSeconds_ReflectedInSendAfter` reads the backoff as `send_after - updated_at`, which `RetryDelivery` sets from one `now()`. It compared Go's `time.Now()` with the database's clock before.
- `TestClaimAndMarkProcessing_DeliveryAheadOfDatabaseClock` and `TestRunClaimUntilAttempted_DeliveryAheadOfDatabaseClock` move `send_after` 300 ms past the database's `now()`, the state a backward clock step leaves.

## Key decisions

- **Tests change, production does not.** A delivery that one claim misses stays `pending` and is claimed by a later tick of the 5-second claim ticker, so the delay is at most the clock step plus one tick. A grace period in `ClaimPendingDeliveries` would send every debounced delivery early to serve a test assumption.
- **Retry the claim rather than backdate `send_after`.** Backdating needs a separate path for each writer (`UpsertDelivery`, `InsertDigestDelivery`, `ReplayDelivery`, `ResetStuckDeliveries`), and it would remove the real write-then-claim sequence from the tests.
- **The stop condition is `last_attempted_at IS NULL`, not `status = 'pending'`.** A delivery that failed returns to `pending` for its backoff; repeating the claim for it would deliver it twice and break the attempt counts these tests assert.

## Gotchas

- The failures came from 2026-11-07 full runs, and their logs no longer exist. The only predicate that can exclude a committed due row from the claim is `send_after <= now()`, and the upsert and claim run in sequential transactions, so the claim's `now()` must have been earlier than the upsert's. **No backward step was caught directly.** The direct cause is inferred from the query and the failure signature.
- Measurements on 2026-11-08, from a probe in a Linux container reading `CLOCK_REALTIME` (on one thread in the first run, compared across 6 threads in the other two): the Docker Desktop VM's wall clock stepped forward by roughly 220 to 400 ms every 30 seconds, over 19 minutes of probing that covered a run with little other load, all 20 vCPUs saturated, and a full `go test ./...` run. It recorded no backward reading. About 167,000 upsert-then-claim cycles in the first two of those periods missed no claim.
- The Windows `Kernel-General` event log shows a real backward host step of 1.353 s at 2026-11-08T19:35Z, so backward steps occur on this machine. It records no step during the failing runs at about 21:36Z and 21:46Z on 2026-11-07. An NTP sample arrived at 21:44:06Z, shortly before the second run; a correction applied gradually does not produce that event. The trigger for those two failures remains unconfirmed.
- CPU saturation alone did not reproduce the failure.
- `TestRebuildSearchIndex_RetriesBatchAfterDeadlock` in `internal/merge` failed once in a full run during this work, with "expected the rebuild to be the deadlock victim", and passed 5 of 5 alone. It has a separate cause and is not addressed here.

## Quality checks

- Both new tests failed before the fix, the store test with the reported message "expected at least 1 claimed delivery, got 0", and pass after it.
- `go test ./internal/store/ ./internal/notify/ ./internal/testutil/ -count=3 -timeout=590s`: pass.
- `golangci-lint run ./internal/store/ ./internal/notify/ ./internal/testutil/`: 0 issues.
