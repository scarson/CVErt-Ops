# Upgrade to Go 1.27.4 and golangci-lint v2.15

## What was built

- `go.mod` moves from `go 1.26.10` to `go 1.27.4`. The six `actions/setup-go` steps in `.github/workflows/ci.yml` move from `"1.26"` to `"1.27"`, and the `docker/Dockerfile` builder stage from `golang:1.26-alpine` to `golang:1.27-alpine`.
- The CI golangci-lint pin moves from v2.10.1 to v2.15.0.
- `internal/ingest/handler_deadline_test.go` takes the Go 1.27 gofmt alignment (whitespace only).
- `CLAUDE.md`, `AGENTS.md`, `README.md` and `PLAN.md` name Go 1.27.
- Lint cleanup for v2.15.0, which reports 240 findings that v2.10.1 did not:
  - 54 noctx: API tests build requests with `httptest.NewRequestWithContext(t.Context(), ...)`.
  - 171 gosec G124 in tests: 170 sites in `internal/api` use a new `requestCookie(name, value)` helper (`internal/api/request_cookie_test.go`), which holds the package's one G124 suppression. The one site in `cmd/cvert-ops/serve_test.go` has an inline suppression.
  - 13 gosec G124 in production auth and OAuth cookie setters, 1 G710 (OIDC redirect) and 1 G703 (`docker/compose_test.go`): inline `//nolint:gosec` with the reason.
- `dev/research-findings/2026-11-10-go-1-27-upgrade-assessment.md` now targets 1.27.4 and records the re-verification.

## Why

Go 1.27.4 and 1.26.11 (2026-11-10) carry security fixes to cgo, the go command, the compiler, the linker and `net/http`. The previous toolchain, 1.26.10, lacks them. The upgrade assessment had already shown Go 1.27 needs no code changes; the only blocker was golangci-lint.

## Decisions and gotchas

- **golangci-lint version.** v2.10.1 cannot lint a Go 1.27 module. v2.13.0 claims Go 1.27 support but cannot read 1.27.3's export data: it prints `0 issues.` and exits 7. v2.14.0 and v2.15.0 work and report the same findings. A v2.15.0 built with go1.27.3 lints a `go 1.27.4` module, so the CI release binary is compatible.
- **G124 is a false positive at every flagged site.** In tests, the cookies go on outgoing requests, and a `Cookie` request header carries only name and value. In production, every cookie sets HttpOnly and SameSite=Lax and takes `Secure` from `COOKIE_SECURE`; `validateConfig` refuses to start with HTTPS and insecure cookies outside development. All suppressions are inline, because `.golangci.yml` notes that path-based exclusions do not reliably suppress gosec or noctx.
- **Removing a trailing comment can break gofmt alignment.** The cookie rewrite dropped `//nolint:exhaustruct // test` from lines that no longer hold a struct literal. In `oauth_oidc_test.go` that comment had set the column for the `//nolint:gosec` comment on the next line, so gofmt realigned 10 lines.
- **`setup-go` with `"1.27"`** may pick a cached 1.27.x older than 1.27.4. The go command then switches to the `go.mod` version, because `GOTOOLCHAIN` defaults to `auto`. Official golang Docker images set `GOTOOLCHAIN=local`, so a stale local `golang:1.27-alpine` fails with "go.mod requires go >= 1.27.4" until it is pulled again.
- **Deferred.** golangci-lint v2.13+ deprecates `exhaustruct` (used here to enforce `http.Server` timeouts) in favour of `exhaustruct_v5`; 147 `nolint` comments name it. 23 files on `dev` are already not gofmt-clean, and CI does not run gofmt. Both are follow-ups, not part of this change.

## Quality checks

- Under Go 1.27.4: `go build ./...` and `go vet ./...` are clean, and `golangci-lint run` (v2.15.0) reports 0 issues.
- Full suite under Go 1.27.4: `go test ./... -count=1 -p 2 -timeout=900s`, 38 packages ok, 0 failures. It ran on the tree committed as `befbbe6`; the only later code change is the whitespace realignment in `oauth_oidc_test.go`.
- `internal/api`, `cmd/cvert-ops` and `docker` tests pass under Go 1.26.10 with the lint cleanup alone, before the version bump.
- Cross-toolchain `material_hash` probe (seed the golden corpus, dump each CVE's hash and a digest of the full row without timestamps): identical between Go 1.26.10 and 1.27.4 for all 68 CVEs from all eight feeds.
- gofmt (1.27.4): no file newly unformatted compared with `dev`.
