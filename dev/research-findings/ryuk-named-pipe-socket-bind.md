# Ryuk Exits at Startup on Windows: Named Pipe Bound as the Docker Socket

**Date:** 2026-11-09
**Versions:** testcontainers-go v0.45.0 (Ryuk 0.14.0) and v0.42.0 (Ryuk 0.13.0), Docker Desktop 4.41.2, Engine 28.1.1, WSL 3.0.3, kernel 6.18.54.1, Windows 11 10.0.26300

## Summary

The reaper exits with status 1 about 400 ms after it starts, on every attempt, whether or not other sessions are using Docker. testcontainers-go binds `//./pipe/docker_engine`, a Windows named pipe path, over `/var/run/docker.sock` in the Linux reaper container. The path mounts as an empty directory, so Ryuk's first ping of the daemon fails.

testcontainers-go uses the correct path only when the daemon's `OperatingSystem` is exactly `Docker Desktop`. This daemon reports `Docker Desktop (containerized)`, so the check fails and the code falls through to the client's Docker host.

`internal/testutil/postgres.go` now sets `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=//var/run/docker.sock` on Windows.

## Evidence

### What the reaper did

`docker events` filtered on the Ryuk images, with `docker logs -f` attached when the `create` event arrived, captured one failed attempt of `TestRyuk_ReapsOrphanedContainers`:

```
01:36:51.088 create  reaper_cc31e7e7...
01:36:51.426 start
01:36:51.822 die     exitCode=1
01:36:51.862 destroy
```

The reaper's only log line:

```
ERROR run error="new reaper: ping: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
```

`docker inspect`, taken at `create`, showed the bind `//./pipe/docker_engine:/var/run/docker.sock` with `AutoRemove=true` and `Privileged=false`. The test's own output printed `Operating System: Docker Desktop (containerized)` and `Resolved Docker Socket Path: //./pipe/docker_engine`.

### Changing only the bind changes the outcome

Ryuk 0.14.0 was run by hand without auto-remove, one case after another, while other sessions were using the daemon:

| Bind source | Exit code | Log | `stat` of the mount from a Linux container |
|---|---|---|---|
| `//./pipe/docker_engine` | 1 | `ping: Cannot connect to the Docker daemon` | directory, mode 755 |
| `//var/run/docker.sock` | 0 | `Started address=[::]:8080`, then a clean shutdown at its connection timeout | socket, mode 660 |
| `/var/run/docker.sock` | 0 | as above | not run |

`TestRyuk_ReapsOrphanedContainers`, with no other change:

| Configuration | Result |
|---|---|
| Unmodified, two runs (one with `RYUK_VERBOSE`) | fails at container setup in 3–7 s |
| `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=//var/run/docker.sock` | passes; the orphan was reaped in 13 s |
| The `init` change in `internal/testutil/postgres.go`, no environment settings | passes; the orphan was reaped in 12 s |

### Why the path is wrong

`extractDockerSocketFromClient` in `internal/core/docker_host.go` (v0.45.0, and still on upstream `main` on 2026-11-09):

```go
if info.Info.OperatingSystem == "Docker Desktop" {
    if IsWindows() {
        return WindowsDockerSocketPath // "//var/run/docker.sock"
    }
    return DockerSocketPath
}
dockerHost, err := extractDockerHost(ctx)
...
return checkDockerSocketFn(dockerHost)
```

`extractDockerHost` returns `npipe:////./pipe/docker_engine`, and `checkDockerSocketFn` removes the `npipe://` scheme, which leaves `//./pipe/docker_engine`.

### Why the daemon says "containerized"

Moby v28.1.1 appends ` (containerized)` when `operatingsystem.IsContainerized()` returns true. That function returns true when any line of `/proc/1/cgroup` ends in something other than `:/` or `:/init.scope`. A container with `--pid=host --cgroupns=host` reads that file in the daemon's namespaces:

```
0::/non-systemd
```

PID 1 there is `/init`, and its cgroup is not the root, so the check returns true. The check looks only at the cgroup name.

## How this explains the other reports

- **`unexpected container status "removing"`** is testcontainers-go's wait loop reading the state of a reaper that has already died and is being auto-removed.
- **`No such container`** is the same read arriving after the removal finished.
- **`Conflict. The container name "/reaper_<hash>" is already in use`** comes from concurrent test binaries. Every package in one `go test` invocation shares a session ID and so a reaper name. While one binary's reaper is dying, another binary's create collides with the name. This wording was explained from the code and not reproduced separately.
- **"Exits with status 1 about once a second"** is `reaperSpawner.backoff`, which retries for up to 20 seconds. Each retry starts a new reaper, and each one dies the same way.

## Ruled out

- **Contention with other sessions.** The bind alone decides the result under the same load, and the failing bind fails when run by hand.
- **The testcontainers-go 0.42 to 0.45 bump or the Ryuk 0.14 image.** Both versions bind the pipe path. The failure is the same on both.
- **`DOCKER_HOST` set in `testutil`'s `init`.** With it unset, `dockerSocketPath` returns the same `npipe:////./pipe/docker_engine` as the fallback. Established from the code and not run, because the `init` sets it in every test binary.
- **Privileged mode and `~/.testcontainers.properties`.** The reaper runs fine unprivileged with the correct bind. The properties file holds only a comment; it no longer has the `ryuk.disabled=true` recorded in March.

## Still unknown

- **When the daemon started reporting `(containerized)`.** The first logged failure with Ryuk enabled is 2026-11-02, after a Docker Desktop restart. WSL 3.0.3 was installed on 2026-10-07. A WSL update placing PID 1 in a non-root cgroup would fit, but no record of the earlier state was found, so this is not established.
- **An earlier report that the same image and bind ran fine via `docker run`** (2026-11-02). That could not be repeated: the pipe bind exits 1 when run by hand. The report's exact command was not recorded.

## Fix

`internal/testutil/postgres.go` sets `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` to `//var/run/docker.sock` on Windows when the variable is unset. This is the value testcontainers-go uses itself for Docker Desktop on Windows. `docker/compose_test.go` imports `testutil`, so it gets the setting. `testdata/ryuk_crash_helper` inherits it from the test binary's environment.

`TESTCONTAINERS_RYUK_DISABLED=true` is no longer needed on this host. CI's use of it is a separate choice and is unaffected.

## Upstream

The exact-match comparison is a testcontainers-go bug: any Docker Desktop daemon whose PID 1 has a non-root cgroup gets a broken reaper on Windows. Comparing with `strings.HasPrefix(info.Info.OperatingSystem, "Docker Desktop")` would fix it. Two searches of the upstream issue tracker on 2026-11-09 found no matching issue, and none has been filed.

## Reproducing

Run these from PowerShell, with no containers of these names present:

```powershell
docker info --format '{{.OperatingSystem}}'
docker run -d --name ryuk-probe-pipe -v '//./pipe/docker_engine:/var/run/docker.sock' testcontainers/ryuk:0.14.0
docker wait ryuk-probe-pipe
docker logs ryuk-probe-pipe
docker rm ryuk-probe-pipe
```

To watch a real reaper before auto-remove deletes it, follow `docker events --filter image=testcontainers/ryuk:0.14.0` and start `docker logs -f <id>` on each `create` event.
