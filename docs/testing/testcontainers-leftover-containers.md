# Leftover Postgres Test Containers When Ryuk Is Disabled

Analysis of 2026-11-03. It covers why `postgres:18-alpine` test containers pile up on a shared Docker daemon when integration tests run with `TESTCONTAINERS_RYUK_DISABLED=true`, and how the test helpers remove them.

## Background

At the time of this analysis, `testutil.NewTestDB` (`internal/testutil/postgres.go`) started one Postgres container per test and terminated it in `t.Cleanup`. It now starts one container per test binary, clones a migrated template database per test, and terminates the container from `testutil.Run`, which each package's `TestMain` calls; the findings below are stated for the per-test model, with the shared-container consequences noted. Ryuk, the testcontainers reaper, normally removes containers whose test process has died. When this analysis was done, Ryuk could not start on this Windows development host, because testcontainers-go bound a named pipe path as its Docker socket (`dev/research-findings/ryuk-named-pipe-socket-bind.md` — the cause and the `internal/testutil` setting that fixes it). The tests ran with `TESTCONTAINERS_RYUK_DISABLED=true`, and nothing removed a container that its own test did not terminate. Runs that still set that variable, including CI, are in the same position.

## Findings

### A passing package run does not leak

A full-suite run reported that `go test ./internal/alert/` had left about 15 containers even though it passed. This was rechecked by running the package alone with Ryuk off:

```bash
TESTCONTAINERS_RYUK_DISABLED=true go test -v ./internal/alert/ -count=1
```

It passed in 107 s. The log shows 24 "Container created" and 24 "Container terminated" lines and no `terminate postgres container` error. Afterwards, no container carried that run's session label. Per-test cleanup works when the test binary exits normally.

### The session label identifies a `go test` invocation, not a package

testcontainers-go v0.42.0 (`internal/core/bootstrap.go`) sets the `org.testcontainers.sessionId` label to a SHA-256 hash of the parent process ID and the parent's start time. The parent of a test binary is the `go test` process, so:

- every package run by one `go test ./...` invocation shares one session ID;
- each separate `go test ./internal/<pkg>/` invocation gets its own.

The label cannot attribute leftovers to a package. In the full run behind the report, `internal/alert`, `internal/api`, `internal/ingest` and `internal/store` all hit the 10-minute timeout, and their leftovers all carried the same label.

### Timed-out test binaries leave the containers of their running tests

When `go test -timeout` expires, the test binary panics and exits. Tests that had already finished have terminated their containers. Tests still running at the panic never reach their `t.Cleanup`, so their containers stay up:

- A package whose database tests run one at a time leaves one container. `internal/alert` is an example.
- A package that uses `t.Parallel` leaves up to `-parallel` containers, which defaults to GOMAXPROCS. `internal/api` is an example: two timed-out runs left 13 each.

The leftovers counted after one day of full-suite runs fit this: 27 from one full run in which four packages timed out, and 6 from an `internal/api` rerun that timed out. The extra containers slow the shared daemon, which pushes the slowest packages past the timeout again.

With one shared container per test binary, a binary killed by the timeout, or by a panic, skips `testutil.Run`'s cleanup and leaves exactly one Postgres container, plus any SMTP container it started.

### A container that fails to start is never removed

`tcpostgres.Run` can return a container together with an error, for example when the readiness wait times out on a busy daemon. `NewTestDB` called `t.Fatalf` before registering `Terminate`, so that container was never removed. `NewTestSMTP` (`internal/testutil/smtp.go`) had the same ordering. `NewTestSMTP` now registers termination for any non-nil container before checking the error, which is the order testcontainers documents for `testcontainers.CleanupContainer`. The shared Postgres start, `startCluster`, terminates a non-nil container before returning `Run`'s error. `TestStartCluster_RemovesContainerThatFailsToStart` uses a wait strategy that cannot succeed and checks that no container remains.

## Fix: owner-liveness sweep

Every container started by the test helpers carries two labels that name the test process that owns it:

| Label | Value |
|---|---|
| `cvert-ops.test.owner-pid` | the test binary's process ID |
| `cvert-ops.test.owner-start` | that process's start time, in milliseconds since the Unix epoch |

Before a test binary starts its first container, it lists containers carrying these labels and force-removes each one whose owner has exited. An owner has exited when no process has that PID, or when the process with that PID started at a different time (the PID was reused). The code is in `internal/testutil/owner.go`. `startCluster` applies it through `ownerOption`, and `NewTestSMTP` through `ownedContainer`. A failed sweep does not fail the test: `ownerOption` reports it on stderr. Every binary in `go test ./...` sweeps when it starts its container, so concurrent sweeps race for the same orphans; a removal that fails because the container is already gone (404) or already being removed (409) counts as done.

This was checked end to end. `go test -v -timeout=9s -run '^TestEvaluatorBatch$' ./internal/alert/` was killed mid-test and left its container running with the owner labels. The next `go test ./internal/alert/` run removed that container before starting its own, then terminated its own, leaving no labelled containers.

Properties:

- **Safe with concurrent test runs.** A container whose owner is still running is never touched, so a sweep cannot remove another session's live containers.
- **Fails safe.** A container without both labels is left alone, as is a container whose owner's start time cannot be read (for example because of access rights).
- **Self-healing.** Leftovers from a timed-out run are removed by the next run of any package that uses the helpers. No manual step and no Ryuk are needed.
- **One-time cleanup.** Containers created before the labels existed carry no owner labels, so the sweep ignores them. Remove those once by hand after confirming that no test process owns them.

Process lookup uses `github.com/shirou/gopsutil/v4`, and the container list and removal use the testcontainers Docker client (`github.com/moby/moby/client`). testcontainers-go already depends on both. Error classification uses `github.com/containerd/errdefs`, which the Docker client already depends on.

## Related

- `dev/research-findings/testcontainers-go-windows-panic.md` explains why the helpers set `DOCKER_HOST` on Windows: named-pipe discovery panics under load.
- `dev/research-findings/ryuk-named-pipe-socket-bind.md` explains why the helpers set `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` on Windows: without it, Ryuk exits at startup.
