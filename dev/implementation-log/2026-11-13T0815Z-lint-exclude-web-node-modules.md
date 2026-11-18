# Lint: leave Go sources shipped in npm packages out of golangci-lint

## What was done

`.golangci.yml` now excludes `web/node_modules` under `linters.exclusions.paths`.

The CI lint job runs `npm ci` before `golangci-lint run`, so `web/node_modules` exists when the linter expands `./...`. The npm package `flatted` (3.4.2) ships a Go package at `web/node_modules/flatted/golang/pkg/flatted` without its own `go.mod`, so that package belongs to the CVErt-Ops module and is linted. govet's `inline` analyzer, which arrived with golangci-lint v2.15.0 and Go 1.27 (PR 223), reports two `reflect.Ptr should be inlined` findings in it. The draft CI-check PR 230 (dev at `5598af6` into main) failed Lint on those two findings. CI had last run on dev at `0af7737`, with golangci-lint v2.10.1.

## Decisions and gotchas

- **Why not a separate module for `web/`.** An empty `go.mod` in `web/` would drop `web/node_modules` from `./...` for build, vet, test and govulncheck as well. But `web/embed.go` is a Go package that embeds the built frontend (`//go:embed all:dist`), so `web/` must stay in the main module.
- **`flatted` did not change.** It is 3.4.2 at both `0af7737` and `5598af6`. The linter upgrade is what made the existing file fail.
- **A local run hides this when `web/node_modules` is absent**, and golangci-lint v2.10.1 (the version installed on this host) has no `inline` analyzer. To reproduce, run `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./web/...` with `web/node_modules` installed.

## Quality checks

- Before the change: golangci-lint v2.15.0 on `./web/...` reported the two govet findings in `flatted.go`, the same as the CI job.
- After the change: the same command reports no issues.
