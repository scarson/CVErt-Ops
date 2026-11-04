# Test Containers — Owner-Liveness Sweep and Start-Failure Cleanup

**Date:** 2026-11-03

## What was built

| Part | Files | Description |
|---|---|---|
| Owner labels and sweep | `internal/testutil/owner.go` | `ownedContainer` labels each container with the test process's PID and start time; the first call in a test binary force-removes labelled containers whose owner has exited |
| Postgres start | `internal/testutil/postgres.go` | `startPostgres` (extracted from `NewTestDB`) applies the owner labels and registers termination before checking `Run`'s error |
| SMTP start | `internal/testutil/smtp.go` | `NewTestSMTP` applies the owner labels and registers termination before checking `Run`'s error |
| Analysis | `docs/testing/testcontainers-leftover-containers.md` | Why containers piled up with Ryuk disabled, and the sweep's safety rules |

## Key implementation decisions

- **The owner is identified by PID and process start time**, so a reused PID is not mistaken for the original owner. A container whose owner is running is never removed, which makes the sweep safe while other sessions run tests on the same daemon.
- **Fail safe:** a container without both labels, or whose owner's start time cannot be read, is left alone. A failed sweep is logged, not a test failure.
- **testcontainers' own Docker client** (`testcontainers.NewDockerClientWithOpts`) lists and removes containers, so the sweep reaches the daemon the containers were started on. `github.com/moby/moby/client`, `github.com/shirou/gopsutil/v4` and `github.com/testcontainers/testcontainers-go` moved from indirect to direct in `go.mod` at the same versions; both new direct modules were checked as maintained.
- **Terminate errors stay logged**, as before, rather than failing the test as `testcontainers.CleanupContainer` would.

## Gotchas discovered

- **A passing `internal/alert` run never leaked.** The report that it left ~15 containers came from `org.testcontainers.sessionId`, which is a hash of the parent `go test` process. Every package in one `go test ./...` shares it, and the leftovers were from packages killed by the 10-minute timeout.
- **testcontainers prints its container lifecycle lines only with `-v`.** A non-verbose log cannot show which container a run created.

## Quality checks

- **Unit and integration tests:** `TestOwnerAlive`, `TestOrphaned` (7 cases), `TestRemoveOrphanedContainers` and `TestStartPostgres_RemovesContainerThatFailsToStart` pass; the whole `internal/testutil` package passes (93s). Break-tests: with the PID-reuse check, the orphan check or the error-path ordering removed, the matching test fails (the last reproduced a leaked container that failed to start).
- **End to end:** `go test -v -timeout=9s -run '^TestEvaluatorBatch$' ./internal/alert/` was killed mid-test and left its container running with owner labels; the next `internal/alert` run removed it and left no labelled container.
- **golangci-lint:** 0 issues on `internal/testutil`.
