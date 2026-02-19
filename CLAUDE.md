# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CVErt Ops is an open-source vulnerability intelligence and alerting application (Go 1.26, PostgreSQL 15+). API-first, single static binary, multi-tenant with RBAC. Self-hosted first, SaaS later. See @PLAN.md for the full PRD and @research.md for research findings.

## Build & Dev Commands

# IMPORTANT: This is a Windows development environment. Use PowerShell and/or CMD, not bash.

```bash
golangci-lint run                    # lint (NOT go vet alone)
sqlc generate                        # regenerate type-safe query code after changing .sql files
migrate -path migrations -database "$DATABASE_URL" up      # run migrations
migrate -path migrations -database "$DATABASE_URL" down 1  # rollback one migration
docker compose up -d                 # start dev Postgres + Mailpit
go run ./cmd/cvert-ops serve         # run server (HTTP + worker)
go run ./cmd/cvert-ops worker        # run standalone worker
go run ./cmd/cvert-ops migrate       # run migrations programmatically
```

## Tech Stack

| Layer | Choice |
|-------|--------|
| HTTP | huma + chi (code-first OpenAPI 3.1, RFC 9457 errors) |
| DB queries | sqlc (static CRUD) + squirrel (dynamic alert DSL) |
| Auth | golang-jwt/jwt/v5 + coreos/go-oidc/v3 + argon2id |
| AI | Google Gemini via `google.golang.org/genai` behind `LLMClient` interface |
| Logging | slog (stdlib) |
| Config | caarlos0/env/v10 |
| CLI | cobra (subcommands: serve, worker, migrate) |
| SSRF | doyensec/safeurl for all outbound webhooks |
| Metrics | prometheus/client_golang at /metrics |

## Architecture (Key Points)

- **Single binary**: HTTP server + worker pool in one process via cobra subcommands; no external queue
- **Global vs org-scoped data**: CVE corpus is global/shared; watchlists, alert rules, channels, reports are org-scoped. Every org-scoped method MUST take `orgID` as a parameter
- **Feed adapters**: implement `FeedAdapter` interface; must be pure functions with injected HTTP client for testability; each adapter manages its own upstream rate limiter
- **Merge**: per-CVE serialization via `pg_advisory_xact_lock(hashtext(cve_id))`; canonical record recomputed from all `cve_sources` rows on every write; field precedence is per-field not global (PLAN.md 5.1)
- **Alert DSL**: compiles to parameterized SQL via squirrel; regex uses Go `regexp` (RE2) as post-filter only, with mandatory SQL prefilter and candidate cap (5,000 default, fail-closed)
- **Job queue**: single Postgres `job_queue` table with `SKIP LOCKED`; `lock_key` partial unique index for per-class concurrency control
- **Notifications**: at-least-once delivery; HMAC-SHA256 webhook signatures; SSRF prevention via doyensec/safeurl
- **Graceful shutdown**: configurable hard deadline (default 60s, `SHUTDOWN_TIMEOUT_SECONDS`)

## Conventions

- API base path: `/api/v1`, org context in URL path: `/api/v1/orgs/{org_id}/...`
- Error format: RFC 9457 Problem Details (huma auto-generates)
- Cursor-based pagination ordered by `date_modified_canonical` desc, `cve_id` tiebreak
- UUIDv4 PKs for org-scoped tables; `cve_id` text PK for CVE tables
- Migrations: one up/down SQL pair per change via `golang-migrate`; embedded via `embed.FS`
- Static queries: sqlc in `.sql` files. Dynamic DSL queries: squirrel (parameterized, never string concat)
- RBAC roles: owner > admin > member > viewer (permission matrix in PLAN.md 7.3)
- Registration mode: configurable via `REGISTRATION_MODE` env var (`invite-only` default)
- Keep code idiomatic Go with extra comments/docs for clarity
- This is a security product — no shortcuts on input validation, auth checks, or tenant isolation

## Project Layout

```
cmd/cvert-ops/     # cobra CLI entry points
internal/api/      # huma HTTP handlers + middleware
internal/config/   # caarlos0/env config structs
internal/feed/     # feed adapters (nvd, mitre, kev, osv, ghsa, epss)
internal/merge/    # CVE merge pipeline
internal/alert/    # alert DSL compiler + evaluator
internal/notify/   # notification channels + delivery
internal/auth/     # JWT, OAuth, API keys, argon2id
internal/worker/   # job queue + goroutine pool
internal/search/   # FTS + facets
internal/store/    # repository layer (sqlc + squirrel)
internal/metrics/  # Prometheus counters/histograms
migrations/        # SQL files (embedded)
templates/         # notification + watchlist templates (embedded)
```
