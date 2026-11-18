# Ryuk starts on Windows with the daemon socket bound

> **Date:** 2026-11-09
> **Commits:** `1c06565` on `claude/ryuk-root-cause-69e130`

## What was built

| Feature | Files | Description |
|---|---|---|
| Docker socket override for Ryuk | `internal/testutil/postgres.go` | On Windows, `init` sets `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` to `//var/run/docker.sock` when it is unset |
| Root-cause record | `dev/research-findings/ryuk-named-pipe-socket-bind.md` | The captured exit code, logs and bind comparison, what was ruled out, and what remains unknown |
| Corrected explanation | `docs/testing/testcontainers-leftover-containers.md` | Replaces the unproven account of Ryuk failing after a Docker Desktop restart |

## Key implementation decisions

- **Override in `testutil`, not a host setting** — every test binary that starts a container imports `testutil`, so no developer or session has to set anything. `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` affects only the path bound into the reaper, not how the client reaches the daemon.
- **No change to the crash helper** — `exec.Cmd` with a nil `Env` inherits the environment that `testutil`'s `init` set in the test binary.
- **No separate unit test** — `TestRyuk_ReapsOrphanedContainers` already fails without the setting and passes with it. A test that reads the variable back would only repeat the assignment.

## Gotchas discovered

- **Ryuk's auto-remove destroys the evidence** — a `docker logs -f` started on the `create` event from `docker events` captures its output, and `docker inspect` at `create` captures the bind.
- **The test output printed the wrong path** — `Resolved Docker Socket Path: //./pipe/docker_engine` appears on every run. A Windows pipe path can never be correct for a Linux reaper.
- **Three error wordings have one cause** — `removing`, `No such container` and the `reaper_<hash>` name conflict all follow from the reaper dying during the retry loop.

## Quality checks

- **`TestRyuk_ReapsOrphanedContainers` before the change, on current `dev`:** failed in 6.6 s with `unexpected container status "removing"`
- **The same test after the change, with no environment settings:** passed; the orphan was reaped in 12 s
- **`go test ./internal/audit ./internal/retention ./internal/secure ./internal/testutil -count=1` with Ryuk on:** all four passed in parallel, and the reaper exited by itself afterwards. The first three packages failed with Ryuk on before the change.
- **`golangci-lint run ./internal/testutil/...`:** 0 issues
- **Full suite:** not run; Docker is shared with other sessions and the change affects only the reaper's bind on Windows
