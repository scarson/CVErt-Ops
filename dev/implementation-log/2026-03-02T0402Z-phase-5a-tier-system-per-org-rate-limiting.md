# Phase 5A — Tier System & Per-Org Rate Limiting

> **Date:** 2026-03-01
> **Commits:** `b11d356`..`9caba0b` on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`

## What was built

| Feature | Files | Description |
|---|---|---|
| Tier migration | `migrations/000025_org_tier.{up,down}.sql` | Added `tier TEXT NOT NULL DEFAULT 'free'` with CHECK constraint and `tier_overrides JSONB` to `organizations` table |
| Tier resolver | `internal/tier/resolver.go` | Resolves effective limits with override precedence: per-org override > tier default > free fallback. `IntLimit()` and `BoolFlag()` methods |
| Store: org tier queries | `internal/store/org.go`, `internal/store/queries/org.sql` | `GetOrgTier`, resource count queries for alert rules, watchlists, members (+ pending invitations) via sqlc |
| Tier resolution middleware | `internal/api/middleware_tier.go` | Loads org tier from DB (or cache), injects `*tier.Resolver` into request context |
| Per-org rate limiter | `internal/api/org_ratelimit.go` | Token-bucket rate limiter keyed by org UUID. Background goroutine evicts idle entries. Tier-aware rates: free=60, pro=300, enterprise=1000 req/min |
| Resource count gating | `internal/api/alert_rules.go`, `internal/api/watchlists.go`, `internal/api/orgs.go` | Tier-gated limits on alert rules, watchlists, and org members (including pending invitations) |
| Channel type gating | `internal/api/channels.go` | Free tier restricted to webhook channel type only |
| GET org tier endpoint | `internal/api/org_tier.go` | Returns resolved tier limits for the authenticated org |
| AI quota wiring | `internal/api/ai.go` | Wired AI summary quota resolution to real org tier instead of hardcoded defaults |
| Tier cache | `internal/api/tier_cache.go` | 30s TTL in-memory cache for org tier data. `maps.Clone` for copy safety on overrides. Background eviction loop |

## Key implementation decisions

- **Override precedence: per-org JSONB > tier defaults > free** — enables sales-driven customization without schema changes
- **30s tier cache TTL** — avoids per-request DB query while keeping tier changes responsive. `maps.Clone` for copy safety since override values are scalars
- **Fail-closed tier gating** — if `tier.Resolver` is missing from context (middleware ordering bug), handlers return 500 rather than silently allowing the request
- **Pending invitations count toward member limits** — prevents circumventing limits by sending many invitations before acceptance

## Tests added

| Test | File | What it verifies |
|---|---|---|
| Tier resolver unit tests | `internal/tier/resolver_test.go` | Override precedence, tier fallback, free default |
| Org tier store integration | `internal/store/org_tier_test.go` | GetOrgTier, resource count queries against real Postgres |
| Tier middleware unit tests | `internal/api/middleware_tier_test.go` | Context injection, DB error handling, cache hit/miss |
| Org rate limiter unit tests | `internal/api/org_ratelimit_test.go` | Allow/deny, burst, idle eviction, rate change handling |
| Tier gating integration | `internal/api/tier_gating_test.go` | Resource limits, channel type gating, rate limiting, fail-closed behavior |
| Tier cache unit tests | `internal/api/tier_cache_test.go` | TTL expiration, idle eviction, copy safety (mutation isolation) |

## Quality checks

- All tests pass (`go test ./...`)
- Code review remediation applied (copy safety test for tier cache, doc comments)
