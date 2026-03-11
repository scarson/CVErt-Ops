# CVErt Ops

> **Status: Work in Progress** — CVErt Ops is under active development. Core functionality is implemented and working, but the project is not yet production-ready. APIs may change. Contributions and feedback are welcome.

CVErt Ops is an open-source vulnerability intelligence and alerting platform. It continuously ingests data from major public CVE feeds, merges them into a single canonical corpus, and lets teams build watchlists and alert rules to stay on top of the vulnerabilities that matter to them. A single static Go binary runs the HTTP API and background workers — no external queue or message broker required.

## Key Features

### Multi-Source CVE Aggregation

CVErt Ops pulls from 10 vulnerability data sources and merges them into a unified view:

- **NVD** — NIST National Vulnerability Database
- **MITRE** — Upstream CVE records
- **CISA KEV** — Known Exploited Vulnerabilities catalog
- **GHSA** — GitHub Security Advisories (with CVE alias resolution)
- **OSV** — Open Source Vulnerabilities
- **EPSS** — Exploit Prediction Scoring System (daily probability scores)
- **MSRC** — Microsoft Security Response Center advisories
- **Red Hat** — Red Hat Security Advisories
- **CSAF** — Common Security Advisory Framework documents
- **Generic** — Configurable adapter for custom or internal feeds

Each source is ingested independently, and a merge pipeline recomputes the canonical CVE record from all available sources on every update. A material hash (SHA-256 over normalized fields) tracks meaningful changes and drives alert evaluation — cosmetic updates don't trigger false alerts.

### Full-Text Search and Faceted Filtering

The CVE corpus is searchable via PostgreSQL full-text search with a dedicated `tsvector` index. Keyset pagination keeps large result sets fast. Filter by severity, CVSS/EPSS score ranges, CWE IDs, affected products, status, and date ranges.

### Watchlists

Curate lists of CVE IDs your team cares about. Watchlists are org-scoped and support add/remove/list operations through the API and the web UI.

### Alert Rules and a Condition DSL

Define alert rules using a declarative DSL with conditions like:

- CVSS score thresholds (`cvss_score >= 9.0`)
- EPSS probability thresholds (`epss_score >= 0.5`)
- Severity levels (`severity IN (critical, high)`)
- CWE categories (`cwe_ids CONTAINS CWE-79`)
- Affected product patterns (`affected_products MATCHES log4j`)
- Description regex matching (`description MATCHES /remote code execution/i`)

Rules compile to an internal bytecode representation and evaluate across three paths: **realtime** (on CVE upsert when the material hash changes), **batch** (periodic sweep of recently modified CVEs), and **EPSS-specific** (daily sweep for rules that reference EPSS scores). Dry-run support lets you preview what a rule would match before activating it.

### Notification Channels

Alert events fan out to configurable notification channels:

- **Webhook** — Outbound HTTP POST with HMAC signing, SSRF protection, and automatic retry
- **Email** — SMTP delivery with templated messages
- **Digest** — Scheduled summary reports with severity threshold filtering

Delivery is transactionally safe — the worker claims a job, commits the transaction, makes the outbound call, then records the result. No open database transactions during HTTP calls. Failed deliveries can be inspected and replayed through the API.

### Scheduled Reports

Configure recurring digest reports scoped to an org. Reports query for CVEs matching a severity threshold over a time window and deliver results to bound notification channels. Timezone-aware scheduling ensures reports arrive when expected.

### AI-Powered Features

Optional LLM integration (currently Google Gemini) provides:

- **Natural language search** — Describe what you're looking for in plain English; the LLM translates it to the alert rule DSL
- **CVE summarization** — Generate plain-language summaries of CVE records

AI features are quota-managed per org, with response caching, token/cost tracking, and input sanitization before anything reaches the LLM.

### Multi-Tenant with RBAC

Every org gets full data isolation through dual-layer tenant separation:

1. **Application layer** — Every org-scoped query takes an explicit `orgID` parameter
2. **Database layer** — PostgreSQL Row-Level Security (RLS) policies with `FORCE ROW LEVEL SECURITY` on all org-scoped tables. The database role has `NOBYPASSRLS`. An unset org context returns zero rows (fail-closed).

Four RBAC roles control access: **Owner** > **Admin** > **Member** > **Viewer**. Per-route middleware enforces minimum role requirements. API key authentication is supported with org-scoping and role caps.

### Enterprise SSO

Organizations can configure OIDC-based single sign-on with domain-based auto-discovery. Supports GitHub OAuth, Google OIDC, and generic OIDC providers. Users can link SSO identities to existing accounts. SCIM provisioning for automated user lifecycle management is planned.

### Site Administration

Site admins get a dedicated set of endpoints and UI views for:

- Feed management (trigger, pause, resume, view logs)
- Org and user management (disable/enable accounts, reset passwords, unlock lockouts)
- Delivery inspection and bulk retry
- Full-text reindexing, system config, and audit log access
- System health checks (`doctor` command and endpoint)

### Testing

CVErt Ops has extensive test coverage — over 1,600 Go test functions across 147 test files, plus 32 frontend test suites. Aggregate statement coverage is 62%, but that number is diluted by generated code (sqlc output), test infrastructure, and CLI boilerplate — all at 0%. Business logic packages where coverage matters most range from 80% to 100%: alert DSL 94%, feed adapters 84-100%, auth 89%, merge 87%, retention 96%, worker 91%.

**Integration tests hit real infrastructure.** Over 70 test files run against a real PostgreSQL instance (via testcontainers) with full RLS enforcement, real migrations, and seeded data. API tests stand up real HTTP servers and exercise the full middleware stack — auth, RBAC, CSRF, tier enforcement, rate limiting. No mocking away the hard parts.

**Shared test infrastructure** in `internal/testutil/` provides reusable helpers: a managed test database with automatic migration, seed data utilities, a mock OIDC provider for SSO testing, and a local SMTP server for email delivery tests. This keeps individual test files focused on the behavior under test rather than setup boilerplate.

**Feed adapter tests** use recorded HTTP responses to verify parsing, streaming, error handling, and rate limit compliance without hitting upstream APIs. Alert DSL tests cover the compiler, evaluator, and all three evaluation paths (realtime, batch, EPSS). Notification delivery tests verify the transactional safety guarantees — claim, commit, deliver, record — with real database state.

The frontend uses Vitest with happy-dom and Vue Test Utils for component and composable testing.

A maintained [`testing-pitfalls.md`](dev/testing-pitfalls.md) documents recurring test anti-patterns and hard-won lessons specific to this codebase — things like testcontainers lifecycle gotchas, RLS-aware test setup, and common assertion mistakes. It serves as onboarding material and a guard against regressing on test quality.

## Development Tooling

This project is developed with [Claude Code](https://claude.com/claude-code) using a disciplined, AI-assisted workflow. The development process is as much a part of the project as the code itself.

**Test-driven development** is enforced — every feature and bugfix starts with a failing test. No production code is written without a test that demonstrates the need for it.

**Static analysis** runs on every commit via pre-commit hooks: `golangci-lint` for Go (with `gosec` for security-specific checks) and `oxlint` + `eslint` for the frontend. Linter suppressions require documented justification.

**Documented pitfalls** in [`implementation-pitfalls.md`](dev/implementation-pitfalls.md) and [`testing-pitfalls.md`](dev/testing-pitfalls.md) capture project-specific mistakes and their fixes. These are living documents that grow as new edge cases are discovered, and are checked against code before commits.

**AI-assisted code review** uses specialized bug-hunting agents that perform multi-pass semantic analysis — targeting contract violations, pattern deviations, failure modes, concurrency issues, and error propagation. Periodic project health reviews run adversarial quality assessments across multiple dimensions.

**Structured planning** — features are designed in `docs/plans/` before implementation, with research notes in `dev/research-findings/` capturing technical investigations and trade-off analyses for architectural decisions.

## Architecture

CVErt Ops is a single Go binary with three runtime modes:

| Command | What it runs |
|---------|-------------|
| `cvert-ops serve` | HTTP API server + embedded background worker pool |
| `cvert-ops worker` | Standalone worker pool (no HTTP) |
| `cvert-ops migrate` | Database migrations |

The background worker handles feed ingestion, alert evaluation, notification delivery, retention cleanup, and report generation — all via an internal job queue in PostgreSQL. No Redis, no RabbitMQ, no external dependencies beyond Postgres.

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.26 |
| HTTP framework | chi + huma (code-first OpenAPI 3.1) |
| Database | PostgreSQL 15+ with Row-Level Security |
| Queries | sqlc (static) + squirrel (dynamic DSL) |
| Auth | JWT (HS256) + Argon2id + OAuth/OIDC |
| AI | Google Gemini via `google.golang.org/genai` |
| Outbound HTTP | doyensec/safeurl (SSRF protection) |
| Metrics | Prometheus at `/metrics` |
| Frontend | Vue 3 + TypeScript + Vite + Tailwind CSS 4 + shadcn-vue |

### Project Layout

```
cmd/cvert-ops/       CLI entry points (cobra subcommands)
internal/
  ai/                LLM client, quota, sanitization
  alert/             Alert DSL compiler and evaluator
  api/               HTTP handlers and middleware
  audit/             Audit logging
  auth/              JWT, OAuth, API keys, Argon2id
  config/            Environment-based configuration
  feed/              Feed adapters (NVD, MITRE, KEV, OSV, GHSA, EPSS, ...)
  ingest/            Feed ingestion orchestrator
  merge/             CVE merge pipeline
  notify/            Notification channels and delivery
  report/            Scheduled report generation
  retention/         Data retention policies
  search/            Full-text search and facets
  store/             Repository layer (sqlc + squirrel)
  worker/            Job queue and worker pool
migrations/          SQL migration files (embedded)
templates/           Notification and report templates (embedded)
web/                 Vue 3 SPA
```

## Getting Started

### Prerequisites

- Go 1.26+
- PostgreSQL 15+
- Node.js 20+ (for frontend development)
- Docker and Docker Compose (recommended for local Postgres)

### Development Setup

```bash
# Generate TLS cert for dev Postgres (idempotent)
bash docker/postgres-tls/generate-cert.sh

# Start Postgres + Mailpit
docker compose -f docker/compose.yml --env-file .env up -d

# Run migrations
go run ./cmd/cvert-ops migrate

# Start the backend
go run ./cmd/cvert-ops serve

# In a separate terminal, start the frontend dev server
cd web && npm install && npm run dev
```

The frontend is available at `http://localhost:5173` (Vite proxies API calls to the Go backend on `:8080`). Mailpit UI for email testing is at `http://localhost:8025`.

### Running Tests

```bash
go test ./...                        # All Go tests
go test ./internal/store/... -count=1  # Store tests (needs test DB)
cd web && npm run test:unit          # Frontend unit tests
```

### Linting

```bash
golangci-lint run                    # Go linting
cd web && npm run lint               # Frontend linting (oxlint + eslint)
cd web && npm run type-check         # TypeScript type checking
```

## Configuration

CVErt Ops is configured via environment variables. Copy `.env.example` to `.env` and adjust for your environment. Key variables include:

- `DATABASE_URL` — PostgreSQL connection string
- `JWT_SECRET` — Secret for signing JWTs
- `REGISTRATION_MODE` — `open` or `invite-only` (default: `invite-only`)
- `SMTP_*` — SMTP server settings for email notifications
- `GEMINI_API_KEY` — Google Gemini API key (optional, for AI features)
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` — GitHub OAuth (optional)
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — Google OIDC (optional)

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
