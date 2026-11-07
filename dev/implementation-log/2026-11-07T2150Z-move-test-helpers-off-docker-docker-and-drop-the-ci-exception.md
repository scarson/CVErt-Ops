# Move test helpers off docker/docker and drop the CI exception

## What was built

- `internal/testutil/postgres.go`, `internal/testutil/ryuk_test.go` and `internal/testutil/testdata/ryuk_crash_helper/main.go` import `github.com/moby/moby/client` in place of `github.com/docker/docker/client` and `github.com/docker/docker/api/types/container`. `internal/testutil/owner.go` already used the moby client, and it is a direct requirement in `go.mod`, so no new dependency was added. `go mod tidy` then dropped three requirements that only `docker/docker/client` needed: `github.com/moby/sys/atomicwriter`, `github.com/pkg/errors` and `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp`.
- The `govulncheck` job in `.github/workflows/ci.yml` now runs `govulncheck ./...` with no exceptions. The exception list, its 2026-07-05 expiry and the filter on `Vulnerability #` lines are gone.

## Key decisions

- `github.com/docker/docker` will not get a release that fixes GO-2026-4887 (CVE-2026-34040, AuthZ plugin bypass through oversized request bodies) or GO-2026-4883 (CVE-2026-33997, off-by-one in plugin privilege validation). Its last release is v28.5.2. The Moby project now publishes the daemon as `github.com/moby/moby/v2`, fixed in v2.0.0-beta.8, and the client SDK as `github.com/moby/moby/client`, which neither advisory lists. Renewing the expiry would only have deferred the same failure, so the test helpers moved to the successor client.
- Both advisories are flaws in the Docker daemon (fixed in Docker Engine 29.3.1), not in client code. Neither one affected the `cvert-ops` binary: `go list -deps ./cmd/cvert-ops` never included `docker/docker`. govulncheck flagged them because neither advisory names vulnerable symbols, so any import of the module counts as a call.
- `docker/docker` stays in `go.mod` as `// indirect`. `go mod tidy` keeps it because the tests of `github.com/golang-migrate/migrate/v4/database/postgres` import `github.com/dhui/dktest`, which imports it. No package this module builds imports it, so govulncheck does not report it.
- In `ryuk_test.go`, `client.New(client.FromEnv)` replaces `NewClientWithOpts(FromEnv, WithAPIVersionNegotiation())`. In the moby client, `NewClientWithOpts` is deprecated in favour of `New`, and API version negotiation is on by default (`WithAPIVersionNegotiation` is a no-op). The moby inspect result wraps the container as `.Container`, whose `State` is a plain field rather than one promoted through an embedded pointer.

## Quality checks

- `govulncheck ./...` and `govulncheck -test ./...`: no vulnerabilities. The verbose module results list only GO-2026-5932 (`golang.org/x/crypto/openpgp`, a package this module does not import).
- `go build ./...`, `go vet ./internal/testutil/...`, and `go build ./internal/testutil/testdata/ryuk_crash_helper` succeed.
- `TESTCONTAINERS_RYUK_DISABLED=true go test -count=1 ./internal/testutil/... ./internal/notify/...` passes.
- `TestRyuk_ReapsOrphanedContainers`, the only test that runs the changed inspect, stop and remove calls, did not run to completion. With the reaper enabled, the crash helper failed to start its container with `reaper: new reaper: ... unexpected container status "removing"`, the shared-Docker reaper failure. The test failed the same way at the previous commit, before this change. CI runs with `TESTCONTAINERS_RYUK_DISABLED=true`, so the test is skipped there. golangci-lint reports no issues in `internal/testutil`.
