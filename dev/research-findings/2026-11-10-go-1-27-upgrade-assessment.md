# Go 1.27 Upgrade Assessment

> **Assessed:** 2026-11-10
> **Target:** Go 1.27.4 (released 2026-11-10). The assessment below was first run against Go 1.27.3; "Go 1.27.4 re-verification" records the checks repeated on 1.27.4.
> **Tree tested:** `origin/dev` at `4356557`. `dev` advanced to `72f8953` before this report was committed; that commit changes one implementation-log file only, so the results apply unchanged.
> **Sources:** [Go 1.27 release notes](https://go.dev/doc/go1.27), [Go release history](https://go.dev/doc/devel/release), [golangci-lint releases](https://github.com/golangci/golangci-lint/releases), [golangci-lint CHANGELOG](https://github.com/golangci/golangci-lint/blob/main/CHANGELOG.md)

---

## Summary

Upgrading to Go 1.27 is safe and low-risk. It was assessed on 1.27.3 and re-verified on 1.27.4. No production or test code needs to change for the new toolchain.

- `go build ./...` and `go vet ./...` are clean under 1.27.3.
- The full Go test suite passes under 1.27.3: 38 packages ok, 0 failures.
- `material_hash` and full canonical rows are byte-identical between Go 1.26.10 and 1.27.3 for all 68 CVEs in the golden corpus.

The real cost of the upgrade is golangci-lint. The pinned v2.10.1 cannot lint a Go 1.27 module, and every version that can (v2.14.0, v2.15.0) reports 240 new findings. All 240 are false positives or test-code noise, but each must be fixed or suppressed inline before the CI lint job passes.

**Security timing.** Go 1.27.4 and 1.26.11 (both released 2026-11-10) contain security fixes to cgo, the go command, the compiler, the linker and `net/http`. `dev` was on Go 1.26.10, which lacks them, so a toolchain move was due either way: to 1.26.11 or 1.27.4. Before that release, 1.26.10 and 1.27.3 carried the same `crypto/x509` fix (both 2026-10-19) and there was no deadline. Go 1.26 remains supported until Go 1.28 ships, expected around February 2027.

---

## Go 1.27.4 re-verification (2026-11-11)

Go 1.27.4 was released on 2026-11-10, after the assessment below was run on 1.27.3. The upgrade targets 1.27.4, so the key checks were repeated on the upgrade branch (`dev` plus the lint cleanup and version bump):

| Check | Result |
|---|---|
| `golang:1.27.4-alpine` and `golang:1.27-alpine` on Docker Hub | Both published |
| golangci-lint v2.15.0, built with go1.27.3, on a module with `go 1.27.4` | Works. The CI release binary predates 1.27.4, so this is the case CI runs. |
| `go build ./...` and `go vet ./...` under 1.27.4 | Clean |
| golangci-lint v2.15.0 on the upgrade branch under 1.27.4 | **0 issues** (one warning: `exhaustruct` deprecated) |
| gofmt 1.27.4 on the upgrade branch | No file newly unformatted compared with `dev`'s existing 23-file drift (after realigning `internal/api/oauth_oidc_test.go`, whose comment columns the cookie rewrite had shifted) |
| Full Go suite under 1.27.4 | **38 packages ok, 0 FAIL**, 4 packages without test files |
| `material_hash` probe, 1.26.10 vs 1.27.4 | **Identical for all 68 CVEs** from all eight feeds, with 68 distinct row digests. The dump is also byte-identical to the earlier 1.27.3 run. |

---

## Version pins before the upgrade (on `dev`)

| Location | Pin |
|---|---|
| `go.mod` line 3 | `go 1.26.10` |
| `.github/workflows/ci.yml` lines 22, 57, 95, 115, 149, 209 | `go-version: "1.26"` (six `actions/setup-go` steps; resolves to the latest 1.26.x) |
| `.github/workflows/ci.yml` line 37 | golangci-lint `version: v2.10.1` (via `golangci/golangci-lint-action` v9.3.0) |
| `.github/workflows/ci.yml` line 162 | `govulncheck@latest` (no pin; scans with the toolchain from `setup-go`) |
| `docker/Dockerfile` | `node:24-alpine` (frontend stage), `golang:1.26-alpine` (builder stage), `gcr.io/distroless/static-debian12:nonroot` (runtime) |
| Docs | `CLAUDE.md:7`, `AGENTS.md:7`, `README.md:153` and `:198`, `PLAN.md:7`, `:37` and `:1542` say "Go 1.26" |

Go release dates relevant to this assessment:

- go1.27.0: 2026-08-19. go1.27.1: 2026-09-01. go1.27.2: 2026-10-08 (security fixes to the go command, `crypto/tls`, `html/template`, `net/http`, `net/textproto`, `os`). go1.27.3: 2026-10-19 (security fix to `crypto/x509`). go1.27.4: 2026-11-10 (security fixes to cgo, the go command, the compiler, the linker and `net/http`; bug fixes to the assembler, compiler, runtime, toolchain bootstrapping, and the `crypto/fips140`, `crypto/hkdf`, `crypto/rsa`, `crypto/tls` and `net` packages).
- go1.26.10: 2026-10-19 (security fix to `crypto/x509`, matching 1.27.3). go1.26.11: 2026-11-10 (the same security fixes as 1.27.4).

---

## Method

All trials ran on an LF-normalized `git archive` export of the tree in a scratch directory, so the repository checkout was never modified. The export needs a placeholder `web/dist/index.html`, because `web/embed.go` embeds `all:dist` and the frontend was not built.

Toolchains: `GOTOOLCHAIN=go1.27.3` and `GOTOOLCHAIN=go1.26.10`, both from the local module cache.

Checks run:

1. `go build ./...` and `go vet ./...` under 1.27.3.
2. `gofmt -l .` under 1.26.10 and 1.27.3, with the two file lists compared.
3. Full suite: `go test ./... -count=1 -p 2 -timeout=900s` under 1.27.3 (`-p 2` limits concurrent testcontainers load).
4. Cross-toolchain hash probe: seed the golden corpus under each toolchain and diff the results (see "material_hash stability" below; the probe source is in the appendix).
5. golangci-lint v2.10.1 (current pin), v2.13.0, v2.14.0 and v2.15.0 against the repository's own `.golangci.yml`. The newer versions were built with Go 1.27.3 and run with `--max-issues-per-linter=0 --max-same-issues=0` so no findings were hidden.
6. Targeted searches for constructs affected by specific 1.27 changes (listed in the release-note mapping below).

---

## Results

| Check | Result |
|---|---|
| `go build ./...` (1.27.3) | Clean |
| `go vet ./...` (1.27.3), including the new printf check for `%w` with a pointer-to-error operand | Clean |
| Full Go suite (1.27.3) | **38 packages ok, 0 FAIL**, 4 packages without test files |
| `material_hash` across toolchains | **Identical for all 68 CVEs**; full-row digests also identical |
| gofmt alignment change | 1 file newly flagged (details below) |
| golangci-lint | v2.10.1: incompatible with a 1.27 module. v2.13.0: broken with 1.27.3. v2.14.0 / v2.15.0: 240 new findings |

### material_hash stability

**Why this matters.** Go 1.27 replaces the implementation behind `encoding/json` (it is now backed by `encoding/json/v2`) and changes `compress/flate` output. Feed adapters parse upstream JSON and gzip/zip payloads. If either change altered parsed values, the first deploy on 1.27 would change `material_hash` for many CVEs. Realtime alert evaluation fires when `material_hash` changes, so that would re-fire alerts across the corpus.

**Why existing tests could not catch it.** The tests in `internal/merge/hash_test.go` and `internal/merge/pipeline_integration_test.go` check determinism and field sensitivity within a single process. None pins an expected hash value, so a toolchain-wide shift would pass every one of them.

**Why `json.Marshal` formatting is not the risk.** `ComputeMaterialHash` (`internal/merge/hash.go`) hashes `sha256(jcs(json.Marshal(fields)))`. JCS (RFC 8785) re-serializes strings and numbers canonically, so differences in how the new backend formats `Marshal` output cannot reach the hash. The remaining risk is upstream: different parsed values from feed JSON or compressed fixtures.

**The probe.** A scratch-only test called `testutil.NewTestDB` and `testutil.SeedCorpus`, which runs the real feed adapters and the real merge pipeline over the golden fixtures. It then dumped, for each row in `cves`:

- `cve_id`
- `material_hash`
- `md5` of the full row as JSONB, minus every key matching `date%` or `%_at` (timestamps differ between runs)

**Results.**

- Both toolchains seeded 68 CVEs from all eight feeds: nvd, mitre, ghsa, osv, kev, msrc, redhat, epss.
- The two dumps are byte-identical.
- Sanity check: the 68 rows have 68 distinct row digests and 63 distinct material hashes. The comparison is per-CVE, not a constant. Some CVEs share material fields, so they share a hash.

The golden fixtures stored compressed (`internal/feed/epss/testdata/golden/scores.csv.gz`, `internal/feed/mitre/testdata/golden/cvelistV5.zip`, `internal/feed/osv/testdata/golden/all.zip`) are only decompressed by tests, never compared byte-for-byte against freshly compressed output. The `compress/flate` encoder change therefore cannot break them, and their golden tests pass.

### gofmt

Go 1.27 fixes how gofmt decides column alignment, so it can produce small whitespace changes on code that 1.26 considered formatted.

- Under 1.26.10, 23 files on `dev` are already not gofmt-clean. This drift exists today and has nothing to do with the upgrade.
- Under 1.27.3 the same 23 files are flagged, plus one more: `internal/ingest/handler_deadline_test.go`.
- The 1.27 diff for that file re-indents the bodies of two composite literals inside `return &mockAdapter{...}, &mockMerge{...}` statements (around lines 120-132 and 322-341). It is whitespace only.

`.golangci.yml` has no `formatters` section, and CI does not run gofmt separately, so neither the existing drift nor the 1.27 change can fail CI. The upgrade commit should run `gofmt -w internal/ingest/handler_deadline_test.go`.

The 23 files that are already not gofmt-clean under 1.26.10:

```
cmd/cvert-ops/quota.go
internal/ai/quota_test.go
internal/alert/dsl/types.go
internal/api/ai_test.go
internal/api/alert_events_test.go
internal/api/audit_log_test.go
internal/api/contract_test.go
internal/api/oauth_google_test.go
internal/api/server.go
internal/auth/apikey_test.go
internal/feed/csaf/parser.go
internal/feed/generic/adapter.go
internal/feed/generic/scheduler.go
internal/feed/generic/scheduler_test.go
internal/feed/kev/adapter.go
internal/feed/redhat/adapter.go
internal/feed/redhat/adapter_test.go
internal/ingest/scheduler_test.go
internal/store/admin_delivery.go
internal/store/ai.go
internal/store/security_events.go
internal/tier/resolver_test.go
migrations/embed.go
```

Fixing these is a separate cleanup. Adding gofmt to the `formatters` section of `.golangci.yml` would stop the drift from returning.

---

## golangci-lint: the real cost

### Version compatibility

| Version | Built with | Result on `dev` |
|---|---|---|
| v2.10.1 (current pin) | go1.26.0 | 0 issues on the current 1.26 module. Cannot lint a module whose `go` line is 1.27. |
| v2.13.0 | go1.27.3 | **Broken.** Fails with `could not load export data: internal error in importing "internal/goarch" (cannot decode "internal/goarch", export data version 5 is greater than maximum supported version 4)`, then prints `0 issues.` and exits 7. The "0 issues" line is false; only the exit code shows the failure. |
| v2.14.0 | go1.27.3 | Works. 240 issues. |
| v2.15.0 (latest) | go1.27.3 | Works. Same 240 issues. |

The golangci-lint CHANGELOG lists "go1.27 support" under v2.13.0, but v2.13.0 cannot read Go 1.27.3's export data. **Use v2.15.0.** v2.14.0 has the same findings, so no working version avoids the cleanup.

All versions from v2.13.0 on also warn that `exhaustruct` is deprecated in favour of `exhaustruct_v5` (see "Deferred" below).

### The 240 findings

| Linter / rule | Count | Where |
|---|---|---|
| gosec G124 (`http.Cookie` missing or has insecure Secure, HttpOnly or SameSite) | 184 | 13 production, 171 test |
| noctx (`httptest.NewRequest` must not be called; use `httptest.NewRequestWithContext`) | 54 | all test files |
| gosec G710 (open redirect via taint analysis) | 1 | production |
| gosec G703 (path traversal via taint analysis) | 1 | test (`docker/compose_test.go:162`) |

**G124 in production: 13 sites, all false positives.**

```
internal/api/auth.go:51, :60, :74, :83, :238, :252
internal/api/auth_mfa.go:568, :1325, :1339
internal/api/oauth_helpers.go:25, :44, :62, :81
```

What these sites have in common:

- Every one sets `HttpOnly: true` and `SameSite: http.SameSiteLaxMode`.
- `Secure` comes from config (`cfg.CookieSecure`, or a `secure` parameter derived from it). gosec only accepts a literal `true`.
- The OAuth state and nonce cookies use Lax rather than Strict on purpose: the identity provider's callback is a cross-site redirect, as the comments in `oauth_helpers.go` say.

How `COOKIE_SECURE` is controlled:

- **Code default:** `false` (`internal/config/config.go:43`), so `go run` works over plain HTTP in development.
- **Startup check:** `cmd/cvert-ops/main.go:825` refuses to start when `EXTERNAL_URL` is HTTPS outside development and `COOKIE_SECURE` is false.
- **Compose defaults:** `docker/compose.yml` defaults it to `true`, and `docker/compose.prod.yml` sets `"true"`.
- **Example env:** `.env.example` sets `false` and explains when to change it.

This is the "architecturally controlled" case in the project's linter-suppression rules (`CLAUDE.md`, Linter Suppressions). Each site gets an inline `//nolint:gosec // G124: Secure comes from COOKIE_SECURE, which startup validation requires to be true for HTTPS deployments` (or equivalent wording).

**G124 in tests: 171 sites, all false positives.** The flagged expressions add a cookie to an outgoing test *request*. Secure, HttpOnly and SameSite are response-cookie attributes and are never sent in a `Cookie` request header. Most common forms:

| Count | Expression |
|---|---|
| 68 | `req.AddCookie(&http.Cookie{Name: "access_token", Value: ...})` |
| 18 | `req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: ...})` |
| 17 | `verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: ...})` |
| 8 | `confirmCookies := append(cookies, &http.Cookie{Name: "mfa_enroll_token", Value: ...})` |
| 6 | `initReq.AddCookie(&http.Cookie{Name: "access_token", Value: ...})` |
| 5 | `cookies := []*http.Cookie{{Name: "mfa_pending_token", Value: ...}}` |
| 4 | `req2.AddCookie(&http.Cookie{Name: "refresh_token", Value: ...})` |
| 4 | `req.AddCookie(&http.Cookie{Name: "refresh_token", Value: ...})` |

Recommended fix: a test helper in the API test package that adds a named request cookie and carries one `//nolint:gosec` with the reason. Call sites switch to the helper. This removes the duplication and leaves a single, documented suppression instead of ~171.

**noctx: 54 sites, all in test files.** The fix is mechanical: `httptest.NewRequest(method, url, body)` becomes `httptest.NewRequestWithContext(t.Context(), method, url, body)`. Where a call already chains `.WithContext(ctx)`, pass `ctx` directly instead.

**G710 at `internal/api/oauth_oidc.go:100`: false positive.**

- The flagged call is `http.Redirect(w, r, authURL, http.StatusFound)` in `oidcInitRedirect`.
- `authURL` comes from `oauthCfg.AuthCodeURL(...)`. Its endpoint comes from OIDC discovery against the issuer in the org's admin-configured SSO connection, not from the incoming request.
- Redirecting to the configured identity provider is the purpose of the function.
- Fix: inline `//nolint:gosec` with that reason.

**G703 at `docker/compose_test.go:162`: false positive.** It is a test writing a fixture file to a path the test itself builds. Fix: inline `//nolint:gosec` with the reason.

The project's `.golangci.yml` notes that golangci-lint v2 path-based exclusion rules do not reliably suppress gosec or noctx, so all suppressions above should be inline rather than config exclusions.

### Deferred: `exhaustruct` to `exhaustruct_v5`

- golangci-lint v2.13.0 and later deprecate `exhaustruct` in favour of `exhaustruct_v5`. For now this is only a warning.
- In this project, `exhaustruct` is restricted (`include: net/http\.Server`) to enforce that every `http.Server` sets its Slowloris-related timeouts. It is a security control, not a style check.
- The codebase has 147 `nolint` comments that name `exhaustruct`.
- Migrating means renaming the linter in `.golangci.yml`, checking that `exhaustruct_v5` honours the same `include` setting, and updating or verifying those 147 comments.
- Do it as a separate change, before a golangci-lint release removes the old linter.

---

## Go 1.27 release notes mapped to this codebase

| Change | Effect on CVErt Ops |
|---|---|
| Generic methods; struct-literal keys may be field selectors; broader function type inference | Language additions only. No effect on existing code. |
| `encoding/json` now backed by the v2 implementation; behaviour preserved, error-message text may differ | Full suite passes; the hash probe shows identical parsed output for all eight feeds. No test asserts on `encoding/json` error text (no matches for `invalid character`, `cannot unmarshal` or `unexpected end of JSON` in `_test.go` files). Error text that huma returns in RFC 9457 problem details for malformed request bodies may read differently; this is cosmetic. Unmarshal is "significantly faster" per the release notes, which benefits feed ingestion. Opt-out if ever needed: `GOEXPERIMENT=nojsonv2` at build time. |
| New `encoding/json/v2` and `encoding/json/jsontext` packages | Optional. No adoption proposed. |
| `compress/flate` faster; encoded output may differ (affects gzip, zlib, zip, png) | No test compares freshly compressed bytes; compressed golden fixtures are only read. Tests pass. |
| `net/http`: HTTP/1 `Response.Body` drains unread content on `Close` (up to a limit) | Helps connection reuse for the webhook client and feed adapters. Notify, feed and ingest tests pass. |
| `net/http`: HTTP/2 server honours RFC 9218 client priority | The Go server only negotiates HTTP/2 over TLS, and deployments put Caddy in front. The protocol between Caddy and the backend was not checked. Nothing in the code depends on stream ordering. |
| `net/http`: new `Server.MaxHeaderValueCount`, default `DefaultMaxHeaderValueCount` | Default applies. The API test suite passes. |
| `go vet` printf check: `%w` with an operand of type `*E` where `E` implements `error` | `go vet ./...` is clean (617 `%w` uses on `main`, none flagged on `dev`). |
| `go test` runs the `stdversion` vet check by default | Clean; the suite passes. |
| GODEBUG settings removed: `asynctimerchan`, `tlsunsafeekm`, `tlsrsakex`, `tls3des`, `tls10server`, `x509keypairleaf`, `gotypesalias` | The project sets none: no `godebug` block in `go.mod`, no `//go:debug` lines. |
| Tracebacks include `runtime/pprof` goroutine labels (modules with `go 1.27`+) | The project sets no pprof labels and does not import `net/http/pprof`. No effect. |
| Goroutine leak profile (`goroutineleak`) now generally available | Optional. Usable only if a pprof endpoint is added later. |
| Closures get simpler names; identical function literals may share code | No test checks symbol names or compares function pointers. |
| gofmt alignment fix | One test file re-indented; see "gofmt" above. |
| `go mod tidy` merges duplicate `require` blocks (modules with `go 1.27`+) | `go.mod` already has exactly two blocks (direct and indirect). No effect. |
| `go fix`: new modernizers `atomictypes`, `embedlit`, `slicesbackward`, `unsafefuncs`; `fmtappendf` removed; `waitgroup` renamed `waitgroupgo` | `go fix` is not part of CI. Optional. |
| `go tool trace -http=:port` binds localhost only | Not used. |
| bzr VCS support removed from the go command | No bzr-hosted modules. |
| Compiler: size-specialized small allocations (~1% gain in allocation-heavy programs, ~60 KB larger binary) | Small benefit. Opt-out `GOEXPERIMENT=nosizespecializedmalloc` (expected to be removed in 1.28). |
| `crypto/ecdsa` `PrivateKey.Sign` checks hash length | JWTs use HS256; go-oidc only verifies signatures. No effect. |
| `crypto/x509` `SystemCertPool` honours `SSL_CERT_FILE` / `SSL_CERT_DIR` on Windows and Darwin | Only affects development on Windows; production is Linux (distroless). |
| `crypto/tls` `Config.Rand` deprecated; ML-DSA and ML-KEM additions | Not used. |
| New stdlib `uuid` package | Not worth adopting now. See "Dependency note" below. |
| Unicode 15 to 17 | Go-side string functions only; PostgreSQL full-text search is unaffected. |
| `bytes.CutLast`, `strings.CutLast`, `net/url` `Clone` methods, `testing/synctest.Sleep`, `httptest.NewTestServer`, `math/big` `Int.Divide` | Optional conveniences. |
| macOS 13 minimum; ppc64 ELFv2 | Not relevant to the targets (Windows development, Linux amd64 containers). |

### Dependency note: stdlib `uuid`

The project imports `github.com/google/uuid` in 209 files. These dependencies also require it, so rewriting those files would not remove `google/uuid` from the module graph:

- `github.com/danielgtaylor/huma/v2`
- `github.com/golang-migrate/migrate/v4`
- `github.com/testcontainers/testcontainers-go` and its `postgres` and `inbucket` modules
- `cloud.google.com/go` and `cloud.google.com/go/auth`
- `github.com/googleapis/gax-go/v2`
- `github.com/google/osv-scalibr`
- `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`

There is no supply-chain reduction to gain, so the switch is not recommended.

---

## Benefits of upgrading

- **Faster JSON unmarshalling.** Feed ingestion (NVD, OSV, GHSA, MITRE, and others) is dominated by JSON parsing.
- **Cheaper small allocations** (up to 30% for allocations under 80 bytes; about 1% overall in allocation-heavy programs).
- **Better connection reuse** from the HTTP/1 body-drain change.
- **Small library additions** useful in tests: `testing/synctest.Sleep`, `httptest.NewTestServer`, `strings.CutLast`.
- **Earlier move to the next support window.** Go 1.26 stops receiving fixes when Go 1.28 ships (around February 2027).

---

## Upgrade change list

On a branch from `dev`:

1. `go.mod`: `go 1.26.10` → `go 1.27.4`.
2. `.github/workflows/ci.yml`: the six `go-version: "1.26"` lines (22, 57, 95, 115, 149, 209) → `"1.27"`; golangci-lint `version: v2.10.1` (line 37) → `v2.15.0`.
3. `docker/Dockerfile`: builder stage `golang:1.26-alpine` → `golang:1.27-alpine`. `golang:1.27-alpine`, `golang:1.27.3-alpine` and `golang:1.27.4-alpine` are published on Docker Hub. Official golang images set `GOTOOLCHAIN=local`, so a locally cached `golang:1.27-alpine` older than 1.27.4 fails with "go.mod requires go >= 1.27.4"; pull the image again in that case.
4. `gofmt -w internal/ingest/handler_deadline_test.go`.
5. Lint cleanup:
   - 54 noctx fixes (`httptest.NewRequestWithContext(t.Context(), ...)`).
   - A request-cookie test helper to replace the 171 test-file G124 sites.
   - Inline `//nolint:gosec` with reasons on the 13 production G124 sites, the G710 site and the G703 site.
6. Docs: change "Go 1.26" to "Go 1.27" in `CLAUDE.md:7`, `AGENTS.md:7`, `README.md:153` and `:198`, and `PLAN.md:7` and `:37`. Leave `PLAN.md:1542` and the dated plans under `dev/plans/` alone; they record what was true when written.
7. Verify: `golangci-lint run` (v2.15.0) exits 0, and the full suite passes under 1.27.4.

Separate follow-ups, not part of the upgrade:

- Migrate `exhaustruct` to `exhaustruct_v5` (147 `nolint` references).
- Fix the 23 files that are already not gofmt-clean, and enable gofmt in the `formatters` section of `.golangci.yml`.

---

## Notes on the assessment environment

- The session's worktree was first created from `origin/main` (`74ab722`), which is 392 commits behind `dev`.
  - On that tree, every testcontainers-backed test failed with `reaper: new reaper ... unexpected container status "removing"` or `reaper_<hash> is already in use`.
  - The cause is that `main` lacks the Windows fix on `dev` (`internal/testutil/postgres.go` sets `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=//var/run/docker.sock`). Go 1.27 is not involved.
  - All results in this report come from `origin/dev`.
- golangci-lint v2.10.1 on the `main` tree also reported 0 issues, and v2.15.0 reported 212 on that older tree. The `dev` numbers above supersede those.
- Local default toolchain: go1.26.2. `GOTOOLCHAIN` selects the version from `go.mod`, so builds on `dev` already use 1.26.10.

---

## Appendix: cross-toolchain hash probe

This test was added only to the scratch export and is not part of the repository. To rerun the comparison:

1. Place this file in `internal/testutil/` of an exported tree.
2. Run `HASHDUMP_OUT=<file> GOTOOLCHAIN=<version> go test -count=1 -run '^TestHashDump$' ./internal/testutil` once per toolchain.
3. Diff the two output files.

```go
package testutil_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestHashDump(t *testing.T) {
	out := os.Getenv("HASHDUMP_OUT")
	if out == "" {
		t.Skip("HASHDUMP_OUT not set")
	}
	db := testutil.NewTestDB(t)
	stats := testutil.SeedCorpus(t, db)
	t.Logf("seeded %d CVEs from %v", stats.TotalCVEs, stats.FeedNames)

	const q = `
SELECT c.cve_id, c.material_hash,
       md5((to_jsonb(c) - ARRAY(SELECT k FROM jsonb_object_keys(to_jsonb(c)) k
                                 WHERE k LIKE 'date%' OR k LIKE '%_at'))::text)
FROM cves c ORDER BY c.cve_id`
	rows, err := db.DB().QueryContext(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, mh, digest string
		if err := rows.Scan(&id, &mh, &digest); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %s %s\n", id, mh, digest)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
```

A permanent version of this check would be a test that pins expected `material_hash` values for a few corpus CVEs. Any toolchain or dependency change that alters canonical output would then fail CI instead of silently re-firing alerts.
