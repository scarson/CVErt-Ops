# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CVErt Ops is an open-source vulnerability intelligence and alerting application (Go 1.26, PostgreSQL 15+). API-first, single static binary, multi-tenant with RBAC. Self-hosted first, SaaS later.

**PLAN.md** — full PRD. Key sections: §3 feed adapters · §4–5 data model + merge · §6 RLS/multi-tenancy · §7 auth · §9 watchlists · §10 alert DSL · §11 notifications · §12 reports · §16 API contract · §18 phases · §21 retention · Appendix A schema · Appendix B endpoints.

**dev/research.md** — decision rationale (read when you need the *why* behind an architectural choice).
**dev/implementation-pitfalls.md** — Go/Postgres mistakes to avoid; referenced by `/pitfall-check`.

## Build & Dev Commands

# NOTE: Claude Code's Bash tool runs bash (Unix syntax). Use bash/forward-slash paths in Bash commands.
# PowerShell is available if explicitly needed for Windows-specific tasks.

```bash
golangci-lint run                    # lint (NOT go vet alone)
sqlc generate                        # regenerate type-safe query code after changing .sql files
migrate -path migrations -database "$DATABASE_URL" up      # run migrations
migrate -path migrations -database "$DATABASE_URL" down 1  # rollback one migration
docker compose -f docker/compose.yml --env-file .env up -d   # start dev Postgres + Mailpit
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
| Config | caarlos0/env/v11 |
| CLI | cobra (subcommands: serve, worker, migrate) |
| SSRF | doyensec/safeurl for all outbound webhooks |
| Metrics | prometheus/client_golang at /metrics |

## Architecture (Key Points)

**Data model**
- Single binary: HTTP server + worker pool via cobra subcommands (`serve`, `worker`, `migrate`, `import-bulk`); no external queue
- CVE corpus is global/shared; all tenant data is org-scoped — every org-scoped store method MUST take `orgID` as a parameter
- `cve_search_index(cve_id, fts_document tsvector)` is a separate 1:1 table — never put FTS on `cves`; GIN rewrites on every timestamp/score update cause severe write amplification
- `material_hash = sha256(jcs(material_fields))`; EPSS score explicitly excluded (§5.3). Before hashing: normalize CVSS vectors to canonical spec metric order; sort all string arrays (URLs, CWE IDs, CPEs) lexicographically
- Merge re-reads all `cve_sources` rows and recomputes the canonical `cves` row from scratch on every source write — not incremental; field precedence is per-field (§5.1)

**Feed adapters**
- Implement `FeedAdapter` interface; pure functions with injected HTTP client; each manages its own upstream rate limiter
- GHSA/OSV alias resolution: if `aliases[]` contains a CVE ID, use it as the primary key — not the native ID. Late-binding PK migration required for aliases added after initial ingest
- Streaming parse required for all large responses: `json.Decoder` with `Token()`/`More()` loop; `Decode(&slice)` is forbidden for large feeds

**EPSS (special handling)**
- `epss_score` excluded from `material_hash`; write via `UPDATE ... WHERE epss_score IS DISTINCT FROM $1` — never inspect `RowsAffected` (ambiguous)
- Two-statement pattern: Statement 1 updates `cves` if CVE exists + score changed; Statement 2 inserts `epss_staging` if CVE doesn't exist yet
- EPSS writes must acquire the same FNV advisory lock as the merge pipeline to prevent TOCTOU races (§5.3)
- `date_epss_updated` is a separate cursor used only by the EPSS evaluator; `date_modified_canonical` is for the batch evaluator

**Tenant isolation (dual-layer)**
- Layer 1: `orgID` parameter on every org-scoped method. Layer 2: `SET LOCAL app.org_id = $1` per-transaction + Postgres RLS policies
- Fail-closed: unset `app.org_id` → `NULL::uuid = org_id` evaluates to NULL (false in WHERE) → 0 rows returned
- `FORCE ROW LEVEL SECURITY` + app DB role `NOBYPASSRLS` on all org-scoped tables
- `org_id` denormalized on every child/join table — RLS on a parent does NOT protect its children
- Workers use `workerTx()` helper (`SET LOCAL app.bypass_rls = 'on'`); this helper must never be called from API handlers

**Alert evaluation (three paths)**
- Realtime: fires on CVE upsert when `material_hash` changes
- Batch: periodic job using `date_modified_canonical > last_cursor`; skips rules whose only conditions reference `epss_score`
- EPSS-specific: daily job using `date_epss_updated > last_cursor`; only rules with `epss_score` conditions
- All paths: filter `cves.status NOT IN ('rejected', 'withdrawn')`; regex rules fail-closed if candidate cap (5,000) exceeded
- New rule activation: handler inserts rule with `status='activating'`, enqueues scan job, returns 202 immediately — never runs the scan inline
- `alert_events` UNIQUE on `(org_id, rule_id, cve_id, material_hash)`; inserts use `ON CONFLICT DO NOTHING RETURNING id` — fan-out only if the row was actually inserted

**Notification delivery**
- Never hold an open DB transaction during an outbound webhook HTTP call — claim job → commit → call webhook → update status in a new transaction
- Fan-out: `sync.WaitGroup` with independent per-channel error recording; never `errgroup` (cancels siblings on first error)
- Delivery worker: `continue` on per-channel HTTP failures; only propagate errors on DB transaction failure
- Webhook client: `doyensec/safeurl`, redirect following disabled, 10s timeout, `MaxConnsPerHost: 50`

**API correctness**
- PATCH request structs: every optional field must be a pointer type (`*bool`, `*string`, `*int`) — non-pointer `omitempty` silently discards zero-value updates
- Keyset pagination: composite cursor `(sort_col, cve_id)` in both `ORDER BY` and `WHERE`; nullable sort columns use `COALESCE` with a sentinel value

**HTTP server**
- Always initialize `http.Server` with `ReadHeaderTimeout: 5s` (Slowloris), `ReadTimeout: 15s`, `IdleTimeout: 120s`; never `http.ListenAndServe`
- `WriteTimeout` omitted globally; apply per non-streaming handler via `http.TimeoutHandler`
- `middleware.RequestSize(1 << 20)` registered globally before routes
- Security headers early in middleware chain: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`
- Background goroutines from handlers: `context.WithoutCancel(r.Context())` — never `r.Context()` directly (cancelled when response is sent)

**Binary init (`cmd/cvert-ops/main.go`)**
- `import _ "time/tzdata"` — embeds IANA timezone database (distroless container has no `/usr/share/zoneinfo`)
- `import _ "github.com/KimMachineGun/automemlimit"` — auto-sets GOMEMLIMIT from cgroup limit; prevents OOM-kill in containers
- pgxpool: `DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol` for PgBouncer transaction-mode compatibility
- DB connection retry loop on startup — Postgres isn't ready immediately in Docker Compose

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

## Skills & Subagents

Use these proactively — don't wait to be asked.

**Skills** (invoke with `/skill-name`):

| Skill | When to use |
|-------|-------------|
| `/migration` | Before writing any migration SQL |
| `/feed-adapter` | Before scaffolding a new feed adapter |
| `/pitfall-check` | Before committing significant business logic |
| `/plan-check` | Before merging any feature — specify the PLAN.md section |
| `/security-review` | Before merging auth, webhook, tenant-isolation, or public API code |

**Subagents** (invoke via `Task` tool):

| Agent | When to use |
|-------|-------------|
| `feed-researcher` | Research a CVE data source API before implementing its adapter |
| `plan-auditor` | Full compliance audit across multiple PLAN.md sections |
