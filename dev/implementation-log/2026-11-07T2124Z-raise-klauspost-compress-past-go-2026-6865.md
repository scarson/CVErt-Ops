# Raise klauspost/compress past GO-2026-6865

## What was built

- `github.com/klauspost/compress` moves from v1.18.7 to v1.20.2, the first release with the fix for GO-2026-6865 (GHSA-fpmh-frq8-7rj8, a zstd decoder panic on crafted two-block frames). No other module changed.

## Key decisions

- Only test code reaches the module. `go list -deps ./cmd/cvert-ops` does not include it, and `govulncheck ./cmd/...` reports no vulnerabilities. Among this module's packages, only `internal/testutil` links it, through `github.com/moby/go-archive/compression`, which testcontainers uses.
- The govulncheck traces that start in production code (`dev/cmd/extract-fixtures` through `fmt.Fprintf`, and `internal/feed/redhat` through `json.Marshal` and `sync.Pool.Get`) are artifacts of whole-program analysis. `govulncheck ./...` builds one call graph for every package it scans, so once `internal/testutil` puts the zstd package into that graph, interface and `sync.Pool` calls anywhere can resolve to it. `go mod why -m` also names a test-only path (the `promhttp` package's own tests).
- Chose v1.20.2 over the newer v1.20.3: v1.20.2 is the smallest change that carries the fix, and v1.20.3 adds mostly decoder and encoder performance work.

## Quality checks

- `govulncheck ./...` no longer reports GO-2026-6865.
- `TESTCONTAINERS_RYUK_DISABLED=true go test -count=1 ./internal/testutil/... ./internal/notify/...` passes. These start the Postgres and Inbucket containers, the code paths that use the module.
