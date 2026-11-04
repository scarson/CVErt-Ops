# Fix — SCIM X-Forwarded-Proto Only from Trusted Proxies

> **Date:** 2026-11-03
> **Branch:** `fix/scim-forwarded-proto` (from `dev` at `f829b66`)

The security review of the trusted-proxy client IP fix (PR #161) found that `scimScheme` accepted `X-Forwarded-Proto` from any client, so a client could choose the scheme of the SCIM resource URLs (`meta.location`) in its own responses, including downgrading a TLS connection's URLs to `http`.

## What was built

| Feature | Files | Description |
|---|---|---|
| Trusted-peer flag | `internal/api/ratelimit.go`, `internal/api/context.go` | `clientIPMiddleware` sets `ctxTrustedProxyPeer` when the TCP peer is inside `TRUSTED_PROXIES` (`peerInPrefixes` folds v4-mapped addresses and strips zones, as chi does) |
| SCIM scheme | `internal/api/scim_users.go` | `scimScheme` reads `X-Forwarded-Proto` only when `ctxTrustedProxyPeer` is set; otherwise the scheme follows `r.TLS` |
| Docs | `docs/deployment/tls.md` | Trusted Proxies section covers `X-Forwarded-Proto` |
| Tests | `internal/api/scim_scheme_test.go` | Through `clientIPMiddleware`: no trusted proxies, untrusted peer (cannot set or downgrade the scheme), trusted IPv4, v4-mapped and IPv6 peers, missing, invalid and unparseable inputs; checks `scimScheme` and `scimBaseURL` |

## Key implementation decisions

- **Context flag, not a signature change** — `scimScheme` is called from three free functions (`scimUserLocation`, `buildSCIMUser`, `scimBaseURL`); the flag keeps their signatures and puts the trust decision in the one middleware that owns `TRUSTED_PROXIES`.
- **Not switched to `EXTERNAL_URL`** — it would also stop trusting the `Host` header, but `EXTERNAL_URL` defaults to `http://localhost:8080`, so deployments that leave it unset would get wrong SCIM URLs. The `Host` header is chosen by the authenticated SCIM client and appears only in its own responses.

## Quality checks

- **Tests:** the five untrusted-peer cases failed before the fix (header honoured, TLS downgraded). `TESTCONTAINERS_RYUK_DISABLED=true go test ./internal/api -run 'SCIM|Scim'`: 90 passed.
- **golangci-lint run:** 0 issues
