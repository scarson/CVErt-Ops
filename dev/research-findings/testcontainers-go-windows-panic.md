# testcontainers-go: Non-Deterministic Panic on Windows Under Parallel Test Load

**Date:** 2026-03-10
**Version:** testcontainers-go v0.40.0
**Platform:** Windows 11 Pro, Docker Desktop 4.41.2, Docker Engine 28.1.1, Go 1.26
**Hardware:** Intel i5-13600K (14 core / 20 logical processors)

## Summary

`go test ./...` non-deterministically panics with `panic: rootless Docker is not supported on Windows` when many test packages run in parallel. Different packages fail on different runs. Every test passes when run in isolation (`go test ./internal/merge/...`).

## Symptoms

```
--- FAIL: TestIngest_VendorEnrichmentNilData (0.00s)
panic: rootless Docker is not supported on Windows [recovered, repanicked]

goroutine 137 [running]:
...
github.com/testcontainers/testcontainers-go/internal/core.MustExtractDockerHost.func1()
    .../internal/core/docker_host.go:91 +0x65
sync.(*Once).doSlow(...)
    C:/Program Files/Go/src/sync/once.go:78 +0xac
```

Key observations:
- Test duration is always `(0.00s)` — the panic occurs before any container is created
- The panic is in `sync.(*Once).doSlow`, confirming this is the *first* `MustExtractDockerHost` call in that process
- On repeated runs, *different* packages fail (e.g., `internal/api`, `internal/notify`, `internal/merge`)
- Isolated package runs always succeed and show `Resolved Docker Host: npipe:////./pipe/docker_engine`

## Root Cause Analysis

### Docker Host Discovery Chain

testcontainers-go discovers the Docker host via a 6-strategy chain in `extractDockerHost()` (`internal/core/docker_host.go:122`):

| # | Strategy | Function | Windows behavior |
|---|----------|----------|-----------------|
| 1 | `tc.host` property | `testcontainersHostFromProperties` | Not set → skip |
| 2 | `DOCKER_HOST` env var | `dockerHostFromEnv` | Not set → skip |
| 3 | Context key | `dockerHostFromContext` | Not set → skip |
| 4 | Default socket path | `dockerSocketPath` | `os.Stat` on named pipe — **flaky under concurrency** |
| 5 | `docker.host` property | `dockerHostFromProperties` | Not set → skip |
| 6 | Rootless socket | `rootlessDockerSocketPath` | **Panics** with `ErrRootlessDockerNotSupportedWindows` |

### How Strategy 4 Works on Windows

`docker_socket.go` has an `init()` function (line 25) that reads `client.DefaultDockerHost` from the Docker Go client library. On Windows with Docker Desktop, this resolves to `npipe:////./pipe/docker_engine`. The init function parses the URL and sets:

```go
DockerSocketSchema = "npipe://"
DockerSocketPath = "//./pipe/docker_engine"
```

The `dockerSocketPath()` function (line 288) then calls `fileExists(DockerSocketPath)` which uses `os.Stat("//./pipe/docker_engine")`.

### The Real Root Cause: Named Pipe Instance Limit

**Windows named pipes have a limited number of concurrent connection instances.** `os.Stat` on a named pipe opens a connection to stat it. When multiple processes (test binaries) call `os.Stat` on the same named pipe simultaneously, they exhaust the available instances:

```
CreateFile //./pipe/docker_engine: All pipe instances are busy.
```

This was confirmed with a reproduction test:

```go
// 100 concurrent os.Stat calls on the Docker named pipe
// Result: 10 successes, 90 failures
// Error: "All pipe instances are busy"
```

Even just 2-3 concurrent calls can trigger this if Docker Desktop is handling other pipe connections (container management, health checks, etc.).

### The Failure Cascade

1. `go test ./...` defaults to `-p GOMAXPROCS` (20 on this system)
2. Up to 20 test packages start simultaneously, each a separate binary
3. Each binary has its own `sync.Once` for Docker host discovery
4. Strategy 4 calls `os.Stat("//./pipe/docker_engine")` which opens a named pipe connection
5. Multiple binaries hit this simultaneously → `"All pipe instances are busy"` → `os.Stat` returns error
6. `fileExists()` returns false → `dockerSocketPath()` returns `ErrSocketNotFoundInPath`
7. `ErrSocketNotFoundInPath` IS in `isHostNotSet()`, so it's silently filtered (not collected as error)
8. Falls through to strategy 6 → `rootlessDockerSocketPath()` returns `ErrRootlessDockerNotSupportedWindows`
9. This error is **not** in `isHostNotSet()`, so it's collected as a real error
10. `MustExtractDockerHost()` panics with the joined errors

### Why the Rootless Error is the Only One Visible

`errors.Join()` concatenates all collected errors. The rootless error (`ErrRootlessDockerNotSupportedWindows`) is often the ONLY error because:
- Strategies 1-3 and 5 return "host not set" errors → filtered by `isHostNotSet()`
- Strategy 4's `ErrSocketNotFoundInPath` → also filtered by `isHostNotSet()`
- Strategy 6's `ErrRootlessDockerNotSupportedWindows` → NOT filtered → surfaces in panic

## Reproduction Steps

### Prerequisites
- Windows 11 with Docker Desktop
- A Go project with 10+ test packages that each use testcontainers
- CPU with 8+ logical cores (to get high default `-p` value)

### Reproduce
```bash
# This will non-deterministically panic in 1-3 packages per run
go test ./...

# Run 3 times to confirm different packages fail each time
go test ./... 2>&1 | grep "FAIL\|panic"
go test ./... 2>&1 | grep "FAIL\|panic"
go test ./... 2>&1 | grep "FAIL\|panic"
```

### Confirm isolation works
```bash
# Any individual package passes reliably
go test -v ./internal/merge/...
go test -v ./internal/api/...
go test -v ./internal/notify/...
```

### Confirm named pipe instance limit is the cause
```go
// Save as pipetest.go and run: go run pipetest.go
package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

func main() {
	var failures, successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := os.Stat("//./pipe/docker_engine")
			if err != nil {
				failures.Add(1)
				fmt.Println("FAIL:", err)
			} else {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("Successes: %d, Failures: %d\n", successes.Load(), failures.Load())
}
// Expected: ~10 successes, ~90 failures with "All pipe instances are busy"
```

### Confirm DOCKER_HOST workaround fixes it
```bash
# Set DOCKER_HOST to bypass os.Stat-based discovery
export DOCKER_HOST="npipe:////./pipe/docker_engine"
go test ./...  # passes reliably with full parallelism
```

## Workaround (Applied)

Set `DOCKER_HOST` env var before testcontainers is imported. This makes strategy 2 (`dockerHostFromEnv`) succeed immediately — it reads the env var without touching the named pipe. The subsequent `dockerHostCheck()` validation uses the Docker Go client which handles named pipe connection pooling and retries internally, unlike raw `os.Stat`.

Applied in `internal/testutil/postgres.go`:

```go
func init() {
	if runtime.GOOS == "windows" && os.Getenv("DOCKER_HOST") == "" {
		os.Setenv("DOCKER_HOST", client.DefaultDockerHost)
	}
}
```

This reads `client.DefaultDockerHost` (which is `npipe:////./pipe/docker_engine` on Windows) and sets it as `DOCKER_HOST`. Every test binary that imports `testutil` gets this automatically.

**Result:** Full test suite (`go test ./...` with default `-p 20`) passes reliably — 30/30 packages, zero panics.

### Why `-p N` alone doesn't work

Reducing parallelism (`-p 4`, `-p 2`) reduces but doesn't eliminate the issue because:
- Even 2 concurrent `os.Stat` calls can fail if Docker Desktop is using pipe instances for container management
- The pipe instance limit is set by Docker Desktop, not configurable by users
- Internal test parallelism (`-parallel`) within a package also creates concurrent container load

## Upstream Issues (for filing)

### Bug 1: `fileExists()` uses `os.Stat` on Windows named pipes (critical)

**File:** `internal/core/docker_rootless.go` (line 76) and `internal/core/docker_host.go` (line 289)

`os.Stat` on a Windows named pipe opens a connection, consuming one of the pipe's limited instances. Under concurrent access (multiple test binaries starting simultaneously), this fails with `"All pipe instances are busy"`. The Docker Go client library handles named pipe connection pooling internally — testcontainers should use the client rather than raw `os.Stat` for pipe existence checks.

**Reproduction:**
```go
// 100 concurrent os.Stat("//./pipe/docker_engine") calls
// Result: 10 successes, 90 failures
// Error: "CreateFile //./pipe/docker_engine: All pipe instances are busy."
```

### Bug 2: `ErrRootlessDockerNotSupportedWindows` should be in `isHostNotSet()`

**File:** `internal/core/docker_host.go`, function `isHostNotSet()` (line 253)

The `ErrRootlessDockerNotSupportedWindows` error is semantically identical to the other "not found" errors — it means "this strategy cannot find a Docker host on this platform." It should be treated as "host not set" (filtered) rather than as a hard error (collected and surfaced in panics).

**Fix:** Add `errors.Is(err, ErrRootlessDockerNotSupportedWindows)` to the `isHostNotSet()` switch.

This alone would change the panic from the misleading "rootless Docker is not supported on Windows" to a more useful "socket not found" message.

### Bug 3: `MustExtractDockerHost()` should not panic

**File:** `internal/core/docker_host.go`, function `MustExtractDockerHost()` (line 87)

A `panic()` in library code is hostile to consumers. Returning an error would let callers handle transient Docker unavailability gracefully (retry, skip test, etc.) instead of crashing the entire test binary. The `sync.Once` makes this worse — once the panic fires, the Once is "done" and the cached result is empty, meaning subsequent calls silently return an empty host.

### Bug 4: No retry for transient named pipe failures

**File:** `internal/core/docker_host.go`, `dockerSocketPath()` (line 288)

When `fileExists()` fails due to "All pipe instances are busy," a single retry with a brief delay (100ms) would resolve the transient contention. The current code treats any `os.Stat` failure as "socket not found" and moves to the next strategy.

## Environment Details

```
Docker Desktop: 4.41.2 (191736)
Docker Engine: 28.1.1
Docker Context: desktop-linux
Docker Endpoint: npipe:////./pipe/dockerDesktopLinuxEngine
client.DefaultDockerHost: npipe:////./pipe/docker_engine
OS: Windows 11 Pro 10.0.26200
CPU: Intel i5-13600K (14P + 6E cores, 20 threads)
Go: 1.26
testcontainers-go: v0.40.0
~/.testcontainers.properties: ryuk.disabled=true
DOCKER_HOST: (not set)
```

## Named Pipes on Windows — Reference

```
Pipe Name                          Purpose
docker_engine                      Default Docker API endpoint
dockerDesktopLinuxEngine           Docker Desktop Linux VM endpoint
dockerDesktopWindowsEngine         Docker Desktop Windows containers
docker_cli                         CLI communication
docker_engine_linux                Linux-specific engine endpoint
```

Go `os.Stat` behavior:
- `os.Stat("//./pipe/docker_engine")` → succeeds (forward-slash UNC path)
- `os.Stat("\\.\pipe\docker_engine")` → fails from bash (shell escaping)
- Bash `test -e //./pipe/docker_engine` → fails (bash can't see named pipes)
