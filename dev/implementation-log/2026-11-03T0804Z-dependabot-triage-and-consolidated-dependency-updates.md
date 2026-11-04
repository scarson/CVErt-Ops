# Dependabot Triage and Consolidated Dependency Updates (2026-11-03)

Triage of 24 open Dependabot PRs. Most were months old and either superseded on `dev` or pinned versions that no longer cleared current advisories. The live updates were applied together on one branch from `dev` at the versions current supply-chain checks support.

| Dependabot PR(s) | Outcome |
|------|-------|
| #114 postcss, #115 js-cookie, #122 undici, #127 js-yaml/redocly, #128 vite, #135 shell-quote (security, base `main`) | Closed: superseded by #142 on `dev` |
| #101 typescript 6.0.3 | Closed: superseded by #148 on `dev` (adds the `openapi-typescript` peer override that `npm ci` needs) |
| #102 eslint-plugin-oxlint 1.61.0 | Closed: already on `dev` |
| #126 x/net, #130 and #111 x/crypto, #131 safeurl, #134 grpc, #106 env, #110 gjson, #112 go-mail, #113 genai | Superseded by the Go module commit on this branch (newer versions) |
| #123 checkout, #132 setup-node, #133 setup-go, #129 golangci-lint-action | Superseded by the actions commit (newer releases where available) |
| #100 @tailwindcss/vite, #103 vue-router, #104 plugin-vue | Superseded by the web commit |

## What changed

| Area | Files | Change |
|------|-------|--------|
| Go toolchain | `go.mod` | `go 1.26.10`: govulncheck found reachable stdlib advisories in go1.26.2 (crypto/x509, crypto/tls, net/http, net/textproto, html/template) |
| Go modules | `go.mod`, `go.sum` | x/crypto v0.58.0, x/net v0.62.0, x/text v0.43.0, grpc v1.83.2, safeurl v0.2.5, moby/go-archive v0.3.3, genai v1.77.0, go-mail v0.7.3, gjson v1.20.0, env v11.4.1 |
| CI | `.github/workflows/ci.yml` | checkout v7.0.1, setup-go v7.0.0, setup-node v7.1.0, golangci-lint-action v9.3.0, pinned by commit SHA |
| Web | `web/package.json`, `web/package-lock.json` | tailwindcss and @tailwindcss/vite 4.2.4, vue-router 5.0.6, @vitejs/plugin-vue 6.0.10 |

## Key implementation decisions

- **govulncheck 47 → 5 reachable advisories.** Remaining: chi `middleware.RealIP` (GO-2026-5774/5775/5777) and docker/docker (GO-2026-4883/4887, no fixed release, test helpers only).
- **chi not bumped.** chi 5.3+ only deprecates `RealIP`, without changing its behaviour, and staticcheck SA1019 would fail lint. The actual bug: `RealIP` trusts `X-Forwarded-For`/`True-Client-IP` from any client, and `TRUSTED_PROXIES` (PLAN.md rate-limiting section, documented in `docs/deployment/`) is parsed but never used, so clients can spoof the IP the auth rate limiter keys on. This needs its own fix.
- **safeurl v0.2.5:** `errors.go` is unchanged since v0.2.2, so the tests' exact refusal text still matches. v0.2.4 adds missing IPv6 blocklist ranges.
- **grpc floor is 1.83.1, not Dependabot's 1.82.1:** GO-2026-6348 is fixed only in 1.83.1.
- **vue-router 5.0.6, not 5.0.7:** 5.0.7 moves to Babel 8 through `@babel/generator` 8.1.0 (one day old), which pins a `@jridgewell/gen-mapping` beta. Tailwind 4.3 and vue-router 5.4 were skipped because they change default font stack and scroll restoration.
- **x/net v0.62.0** also fixes x/net/html advisories GO-2026-6860 and GO-2026-6866, which govulncheck did not list.

## Gotchas discovered

- CI (`.github/workflows/ci.yml`) runs only for pushes and PRs to `main`, so PRs to `dev` get no CI; local targeted tests gate them.
- CI's govulncheck step fails on every run since 2026-07-05: its docker/docker exception has expired.
- Local Node 24.14.0 is below the `web/` engines floor (`^24.15.0 || >=26.0.0`, from #148), so every npm command warns EBADENGINE.

## Quality checks

- `go build ./...`, `go vet ./...`, `golangci-lint run`: clean.
- Go tests: `internal/notify`, `internal/feed/...`, `internal/auth`, `internal/ai`, `internal/config`, `internal/testutil`, `cmd/cvert-ops`, and `internal/api -run 'Channel|Webhook|Login|Password|APIKey|MFA|Register'` pass. Full suite not run.
- Web: type-check, 430 unit tests, lint and build pass; `npm ci` with npm 11.4.2 succeeds.
