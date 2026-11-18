# Fix — Client IP from Trusted Proxies Only; chi v5.5.0

> **Date:** 2026-11-03
> **Branch:** `fix/trusted-proxy-client-ip` (from `dev` at `5bc7f99`)

`middleware.RealIP` rewrote `r.RemoteAddr` from `X-Forwarded-For`, `X-Real-IP` or `True-Client-IP` for any client, and the auth rate limiter keyed on `r.RemoteAddr`, so a client could take a fresh rate-limit bucket on every request by changing those headers. `TRUSTED_PROXIES` was parsed but never read. govulncheck reported this as GO-2026-5774/5775/5777; the Dependabot consolidation (PR #154) left chi at v5.2.5 because a version bump alone only deprecates `RealIP`.

## What was built

| Feature | Files | Description |
|---|---|---|
| Client IP resolution | `internal/api/ratelimit.go`, `internal/api/server.go` | `clientIPMiddleware(srv.trustedProxies)` wraps chi's `ClientIPFromRemoteAddr` (no trusted proxies) or `ClientIPFromXFF(cidrs...)`, and stores the result as `ctxClientIP`; if chi resolves nothing it uses the TCP peer. `authRateLimit` reads `ctxClientIP` instead of `r.RemoteAddr` |
| Startup validation | `internal/api/ratelimit.go` | `parseTrustedProxies` rejects any `TRUSTED_PROXIES` entry that `netip.ParsePrefix` rejects; `NewServer` returns the error |
| chi v5.2.5 → v5.5.0 | `go.mod`, `go.sum` | `ClientIPFromXFF` treats `RemoteAddr` as the rightmost hop from v5.4.0 (GHSA-j6qf-3m9c-vwj3) |
| Docs | `docs/deployment/tls.md`, `.env.example`, `dev/implementation-pitfalls.md` | How the client IP is resolved and what `TRUSTED_PROXIES` accepts; API-5 and ARCH-24 no longer recommend `RealIP` |
| Tests | `internal/api/client_ip_test.go`, `internal/api/ratelimit_test.go` | Through `srv.Handler()`: spoofed forwarded headers without trusted proxies, rightmost untrusted hop from a trusted proxy with a varying spoofed left-most hop, XFF from an untrusted peer. Table test of `ctxClientIP` (v4-mapped, IPv6, fallbacks, `RemoteAddr` untouched). `TRUSTED_PROXIES` validation |

## Key implementation decisions

- **`ClientIPFromXFF`, not `ClientIPFromXFFTrustedProxies`** — the latter counts hops and never checks `r.RemoteAddr`, so a client that reaches the server directly can spoof its IP. `TRUSTED_PROXIES` is a CIDR list, which is what `ClientIPFromXFF` takes.
- **Fallback to the TCP peer** — when the peer is trusted but no untrusted XFF entry resolves (no header, all hops trusted, unparseable hop), the key is the proxy address, as PLAN.md's rate-limiting section specifies. It cannot be spoofed.
- **`X-Real-IP` is not read** — PLAN.md allows it from a trusted proxy, but every documented proxy (nginx `$proxy_add_x_forwarded_for`, Caddy, ALB, App Gateway) sets `X-Forwarded-For`, and one trusted header is less to get wrong.

## chi 5.3–5.5 behaviour changes checked

- Inline middleware propagation across mounted subrouters (5.3.0) and colliding `Mount()`/`Route()` handlers (5.3.2) change only `Walk()`/`Routes()`; this project calls neither.
- `NewCompressor` wildcard panic (5.3.2), RFC 8594 `Sunset` (5.5.0), `SupressNotFound`, `Throttle` and `ContentCharset` changes: not used.
- `Request.Pattern` is now set from `RoutePattern()` (5.3.0); `httpMetricsMiddleware` reads `RoutePattern()` and its tests pass.

## Gotchas discovered

- `go test ./internal/api/` with Ryuk enabled fails every DB test at setup ("unexpected container status \"removing\"") on this host; run with `TESTCONTAINERS_RYUK_DISABLED=true`, as CI does.

## Quality checks

- **Tests:** the four new Handler and validation tests failed before the fix (501 where 429 was expected; invalid CIDRs accepted). `TESTCONTAINERS_RYUK_DISABLED=true go test ./internal/api/... -count=1`: ok (25 s).
- **golangci-lint run:** 0 issues
- **govulncheck ./...:** only docker/docker GO-2026-4883/4887 remain (no fixed release)
