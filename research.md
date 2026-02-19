# CVErt Ops — Research Report

> **Date:** 2026-02-19
> **Scope:** All 5 research decisions, infrastructure choices, competitive analysis, Go 1.26 features
> **Status:** Complete — all decisions resolved

---

## Table of Contents

1. [Go 1.26 Release — Relevant Features](#1-go-126-release--relevant-features)
2. [OpenCVE Competitive Analysis](#2-opencve-competitive-analysis)
3. [Research Decision #1: HTTP Framework + OpenAPI Strategy](#3-research-decision-1-http-framework--openapi-strategy)
4. [Research Decision #2: CWE Dictionary Ingestion](#4-research-decision-2-cwe-dictionary-ingestion)
5. [Research Decision #3: OIDC/OAuth Library](#5-research-decision-3-oidcoauth-library)
6. [Research Decision #4: LLM Vendor](#6-research-decision-4-llm-vendor)
7. [Research Decision #5: Postgres RLS](#7-research-decision-5-postgres-rls)
8. [Infrastructure Decisions](#8-infrastructure-decisions)

---

## 1. Go 1.26 Release — Relevant Features

Go 1.26.0 was released February 10, 2026. PLAN.md originally targeted Go 1.23+, which is now EOL. We target Go 1.26.

### Performance

- **Green Tea Garbage Collector** is now default: 10–40% reduction in GC overhead. Significant for a long-running server processing feed data.
- **`io.ReadAll()`** allocates ~50% less memory and is ~2x faster. Relevant for reading HTTP response bodies from feed APIs.
- **Stack-allocated slices**: compiler allocates slice backing stores on the stack in more situations, reducing GC pressure.
- **Faster cgo calls**: ~30% baseline overhead reduction (relevant if we ever use CGo-based libraries).

### Security

- **Heap base address randomization** on 64-bit platforms. Defense-in-depth against memory corruption exploits.
- **Post-quantum TLS by default**: `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` hybrid key exchanges enabled. Our outbound HTTPS calls to NVD/GHSA/OSV are future-proofed.
- **FIPS 140-3 support**: `crypto/fips140` package with `WithoutEnforcement()` and `Enforced()`. Relevant for Enterprise/government users.
- **`net/url.Parse()` rejects malformed URLs** with colons in host (e.g., `http://::1/`). Helps SSRF prevention.
- **`crypto/rsa.EncryptPKCS1v15` deprecated** (unsafe padding). Won't affect us but signals Go's security direction.

### Standard Library

- **`slog.NewMultiHandler()`**: Distribute log records to multiple handlers (e.g., stdout + file + remote). Valuable for our logging strategy.
- **`errors.AsType[T](err)`**: Type-safe, faster variant of `errors.As()`. Cleaner error handling throughout.
- **`new()` accepts expressions**: `new(yearsSince(born))` creates pointer to computed value. Minor convenience.
- **`testing.T.ArtifactDir()`**: Write test output files to a dedicated directory. Useful for feed adapter test fixtures.
- **`bytes.Buffer.Peek(n)`**: Read next n bytes without advancing. Useful for parsing feed responses.
- **Self-referential generic types**: Enables patterns like `type Adder[A Adder[A]]`. May be useful for DSL type constraints.

### Tooling

- **`go fix` revamp**: Now home of "modernizers" — push-button code updates to latest Go idioms. Useful for keeping code current.
- **`go mod init`** now defaults to one minor release behind toolchain (Go 1.26 creates `go 1.25.0` in go.mod).
- **Goroutine leak detection** (experimental): `GOEXPERIMENT=goroutineleakprofile` enables `/debug/pprof/goroutineleak`. Valuable for debugging worker pool issues.

### Deprecations to Watch

- Go 1.27 will remove several GODEBUG settings and require macOS 13+
- `crypto/rsa.EncryptPKCS1v15` deprecated
- `net/http/httputil.ReverseProxy.Director` deprecated in favor of `Rewrite`

---

## 2. OpenCVE Competitive Analysis

**OpenCVE** (https://www.opencve.io/) is the most direct open-source competitor. Built with Django + Airflow + Redis + PostgreSQL.

### Architecture Comparison

| Aspect | OpenCVE | CVErt Ops |
|--------|---------|-----------|
| Stack | Django + Airflow + Redis + Nginx + Postgres | Single Go binary + Postgres |
| Min hardware | 4 cores, 4 GB RAM, 25–30 GB disk | ~1–2 cores, 1 GB RAM, 5–10 GB disk |
| Deployment | 5+ containers | 2 containers (app + Postgres) |
| Job orchestration | Airflow DAGs | Embedded goroutine pool + Postgres queue |
| Feed aggregation | Centralized KB (GitHub repo) | Per-instance, independent |

**Our advantage**: Dramatically simpler self-hosted deployment. No Redis, no Airflow, no Nginx.

### Vendor/Product Model vs Watchlists

OpenCVE uses CPE-based vendor/product subscriptions — automatic but limited by CPE data quality. CVEs without CPE entries won't match any subscription.

CVErt Ops watchlists support packages (ecosystem + name), CPE patterns, and vendors. This is stronger for modern package ecosystems (npm, PyPI, Go modules) where GHSA/OSV data excels but CPE coverage is sparse.

**Action taken**: Added watchlist bootstrap templates to reduce onboarding friction (the main advantage of OpenCVE's vendor auto-discovery).

### Notification/Alerting

OpenCVE: Notifications are a side-effect of subscriptions. No DSL, no regex, limited filtering (CVSS threshold only).

CVErt Ops: First-class alert DSL with composable rules, decoupled channels, HMAC webhook signatures, SSRF prevention. Significantly more powerful.

### Search

OpenCVE: Field-based syntax (`vendor:microsoft AND cvss31>=9`), max 5 fields per query, no regex.

CVErt Ops: Full DSL with regex (RE2, guardrailed), plus NL search via LLM (Phase 4). Superior for both power users and non-technical users.

### Key Gaps We Exploit

1. No alert DSL or regex — our DSL is a major differentiator
2. CPE-dependent vendor discovery — fails for modern packages
3. No webhook security (SSRF/HMAC) documented
4. No package ecosystem awareness (npm, PyPI, etc.)
5. No API versioning
6. No audit logging
7. No rule versioning

### Features Adopted from OpenCVE

1. **CVE assignment** — assign CVEs to team members for triage (added as P1)
2. **Saved searches** — reusable filter presets independent of alert rules (added)
3. **Watchlist bootstrap templates** — preset watchlists for common software (added)
4. **Digest grouping by severity** — group notification emails by severity level

---

## 3. Research Decision #1: HTTP Framework + OpenAPI Strategy

### Decision: **huma + chi** (code-first, OpenAPI 3.1)

### Options Evaluated

**Option A: Spec-first with oapi-codegen + chi**
- Write OpenAPI spec, generate Go server interfaces
- OpenAPI 3.0.x only (3.1 in progress, not stable)
- Strongest contract enforcement
- 21.7k GitHub stars (chi)

**Option B: Code-first with huma + chi**
- Write Go types and handlers, OpenAPI 3.1 generated automatically
- Native OpenAPI 3.1 with full JSON Schema support
- RFC 9457 Problem Details error responses
- Automatic struct-tag validation
- Requires Go 1.25+ (satisfied by Go 1.26)
- 3.8k GitHub stars, active development (v2.37.1, Feb 2026)

**Option C: Code-first with swaggo/swag**
- Comment annotations → Swagger 2.0
- Spec drift risk, no OpenAPI 3.1
- Not recommended for a security product

### Rationale

1. **Go 1.26 compatibility**: huma requires Go 1.25+, which Go 1.26 satisfies
2. **OpenAPI 3.1 native**: Future-proof; oapi-codegen only supports 3.0.x
3. **Natural for a solo Go learner**: Write Go code, not OpenAPI YAML
4. **Automatic validation**: Struct tags (`minLength`, `maxLength`, `format:"uuid"`) validated automatically — reduces security bugs from missing validation
5. **RFC 9457 errors**: Modern, structured error responses out of the box
6. **chi middleware preserved**: huma wraps chi, so the full chi middleware ecosystem (20+ built-in, 100+ third-party) is available
7. **Living documentation**: Generated spec can never drift from code
8. **Spec exportable**: `/openapi` endpoint serves the spec for client generation

### chi's Continued Value

Even with Go 1.22+ stdlib mux improvements (method routing, path wildcards), chi adds:
- Route grouping for middleware scoping
- Subrouters for organizational structure
- Nested middleware chains
- Mature middleware ecosystem

### Implementation Pattern

```go
r := chi.NewMux()
r.Use(middleware.RequestID)
r.Use(middleware.RealIP)
r.Use(loggingMiddleware(logger))

api := humachi.New(r, huma.DefaultConfig("CVErt Ops API", "1.0.0"))

huma.Register(api, huma.Operation{
    OperationID: "getWatchlist",
    Method:      http.MethodGet,
    Path:        "/api/v1/orgs/{org_id}/watchlists/{id}",
}, getWatchlistHandler)
```

---

## 4. Research Decision #2: CWE Dictionary Ingestion

### Decision: **Full dictionary ingestion**

Ingest MITRE CWE list into `cwe_dictionary(id, name, description)` table. Include CWE `name` in the FTS `tsvector` document for search enrichment.

### Rationale

- Users can search "buffer overflow" and find CVEs with CWE-120
- OpenCVE does this and it improves search UX significantly
- MITRE CWE data is freely available (XML/JSON, no licensing issues)
- Update cadence is low (CWE list changes infrequently)
- Implementation effort is minimal (one-time ingestion + periodic refresh)

### Implementation

- Data source: https://cwe.mitre.org/data/downloads.html (XML or JSON)
- Table: `cwe_dictionary(cwe_id TEXT PK, name TEXT, description TEXT)`
- Ingestion: CLI command `cvert-ops import-cwe` or auto-ingest on first run
- FTS integration: join CWE names into CVE's `fts_document` tsvector

---

## 5. Research Decision #3: OIDC/OAuth Library

### Decision: **coreos/go-oidc/v3 + golang.org/x/oauth2**

### Status

- `coreos/go-oidc/v3` latest release: v3.17.0 (November 2025), actively maintained
- Standard pairing with `golang.org/x/oauth2` in the Go ecosystem
- No deprecation notices; v3 is the current recommended version

### MVP Auth Scope

1. **Native email/password** — argon2id hashing (see section 8)
2. **GitHub OAuth** — natural for security/DevSecOps audience
3. **Google OAuth** — broad appeal
4. **Generic OIDC** — deferred to Enterprise
5. **SAML** — deferred to Enterprise (crewjam/saml if needed)

### Implementation Pattern

```go
provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
oauth2Config := oauth2.Config{
    ClientID:     clientID,
    ClientSecret: clientSecret,
    RedirectURL:  redirectURL,
    Endpoint:     provider.Endpoint(),
    Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
}
// Exchange code → verify ID token → extract claims
```

### Multi-Auth Pattern

- `user_identities` table: `(user_id, provider, provider_user_id, email, linked_at)`
- Users can link/unlink multiple identity providers
- Email uniqueness enforced at application level when linking
- State parameter validation for CSRF protection on OAuth flows

---

## 6. Research Decision #4: LLM Vendor

### Decision: **Google Gemini** (`google.golang.org/genai`)

### Rationale

- Official Go SDK (GA status) — first-party maintenance
- Supports structured output / JSON mode for NL → query JSON
- Competitive pricing
- `LLMClient` interface in PLAN.md ensures vendor is swappable if needed

### Implementation

```go
type LLMClient interface {
    GenerateStructuredQuery(ctx context.Context, prompt string) (json.RawMessage, error)
    Summarize(ctx context.Context, input CVESummaryInput) (string, error)
}

// GeminiClient implements LLMClient
type GeminiClient struct {
    client *genai.Client
    model  string
}
```

### Alternatives Considered

- **OpenAI** (`github.com/openai/openai-go`): Official Go SDK, strong JSON mode. Viable alternative.
- **Anthropic**: No official Go SDK. REST API via `net/http` works but requires hand-rolled client. More maintenance burden.

---

## 7. Research Decision #5: Postgres RLS

### Decision: **Implement for SaaS mode using `SET LOCAL app.org_id` per-transaction**

Deferred to P1 implementation but fully researched to avoid architectural mistakes in MVP.

### Session Variable Strategy

```sql
-- Per-transaction (auto-resets on commit/rollback)
SET LOCAL app.org_id = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx';
```

In Go with pgx:
```go
tx, _ := pool.Begin(ctx)
tx.Exec(ctx, "SET LOCAL app.org_id = $1", orgID.String())
// All queries in this transaction respect RLS policies
```

### Policy Pattern

```sql
ALTER TABLE watchlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlists FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON watchlists
    USING (org_id = current_setting('app.org_id')::uuid)
    WITH CHECK (org_id = current_setting('app.org_id')::uuid);
```

Apply to all org-scoped tables: `watchlists`, `alert_rules`, `notification_channels`, `scheduled_reports`, `cve_annotations`, `saved_searches`, etc.

### Performance

- Simple tenant comparison policies add <5% overhead
- Require `BTREE(org_id)` index on every org-scoped table (already planned)
- Keep policy conditions simple — avoid joins or subqueries in policies

### Bypass Prevention

- App database role: `CREATE ROLE app_user NOBYPASSRLS`
- `FORCE ROW LEVEL SECURITY` on every tenant table
- Superuser access restricted to migrations and emergency maintenance
- All queries via sqlc/squirrel (parameterized, no raw SQL)

### Self-Hosted vs SaaS

**Strategy: Always enable RLS, manage org_id dynamically.**
- Self-hosted: fixed org_id set at startup (from env or auto-generated)
- SaaS: org_id extracted from JWT claims per-request
- Same codebase, same migrations, same policies

### Migration Strategy

- Disable RLS during schema changes, re-enable after
- Keep migrations idempotent (check policy exists before creating)
- RLS policies are part of the migration files, not applied separately

### Testing

- Integration tests must verify cross-org isolation with RLS enabled
- Test pattern: Org A creates data → Org B queries → 0 results
- Test raw SQL bypass attempts → blocked by RLS

---

## 8. Infrastructure Decisions

### Logging: **slog** (Go stdlib)

- Zero dependencies, built-in since Go 1.21
- Go 1.26 adds `slog.NewMultiHandler()` for distributing to multiple destinations
- JSON output in production, text output in dev
- Context propagation: custom handler adds request_id, org_id, user_id from request context
- Secret redaction: implement `slog.LogValuer` interface on types containing sensitive data

Alternatives considered: zerolog (zero-allocation, faster), zap (Uber, widely used). Both are excellent but slog is adequate for our workload and adds zero dependencies. If profiling shows logging is a bottleneck, switch to zerolog as an slog backend handler.

### Configuration: **caarlos0/env/v10 + go-playground/validator**

- Struct-tag based env var parsing — natural for Docker Compose deployments
- Validation at startup via validator struct tags (`required`, `min`, `max`, `url`)
- Nested config structs supported
- Secret redaction via custom `String()` method on config types
- `.env.example` file documents all available config vars

Why not Viper: over-engineered for our use case (no need for YAML/TOML/remote config), case sensitivity issues, large binary size impact.

### CLI: **cobra**

Subcommands:
- `cvert-ops serve` — HTTP server + worker pool (default/combined mode)
- `cvert-ops worker` — standalone worker (for scaling workers independently)
- `cvert-ops migrate` — run database migrations
- Shared flags: `--log-level`, `--log-format`

### Metrics: **prometheus/client_golang**

- `/metrics` endpoint from Phase 0
- Default Go runtime metrics (goroutines, memory, GC)
- Custom metrics: HTTP request latency/count, feed ingestion items/errors, job queue depth, notification delivery success/failure

### SSRF Prevention: **doyensec/safeurl**

- Drop-in replacement for `net/http.Client`
- Blocks private IPs (RFC 1918), loopback, link-local by default
- Mitigates DNS rebinding attacks
- Used for all outbound webhook HTTP calls

### JSON Canonicalization: **cyberphone/json-canonicalization** (JCS/RFC 8785)

- Standards-compliant deterministic JSON serialization
- Used for computing `material_hash = sha256(jcs(material_fields))`
- RFC 8785 ensures reproducible hashes across platforms

### Password Hashing: **argon2id** via `alexedwards/argon2id`

Per OWASP Password Storage Cheat Sheet:
- Algorithm: argon2id
- Memory: 19456 KiB (19 MiB)
- Iterations: 2
- Parallelism: 1
- Salt: 16 bytes (cryptographically random)
- Key length: 32 bytes
- Target hash time: 100–300ms

Storage format: `$argon2id$v=19$m=19456,t=2,p=1$[base64(salt)]$[base64(hash)]`

`password_hash_version` column on `users` table enables future algorithm migration (lazy upgrade on login).

### Testing: **testcontainers-go**

- Ephemeral Postgres containers per test suite — realistic, isolated
- Pre-populated DB snapshots for feed-dependent tests (avoid hitting real APIs and rate limits)
- Mock HTTP responses (recorded fixtures) for feed adapter unit tests
- Mailpit in docker-compose for email notification testing
- Requires Docker running during tests

### CI: **GitHub Actions**

Pipeline:
1. `golangci-lint run`
2. `go vet ./...`
3. `go test ./...` (with testcontainers)
4. `govulncheck ./...`
5. Build binary
6. Build Docker image

### Project Layout

```
cvert-ops/
├── cmd/cvert-ops/        # cobra CLI entry points
├── internal/
│   ├── api/              # HTTP handlers + middleware (huma operations)
│   ├── config/           # caarlos0/env config structs
│   ├── feed/             # Feed adapters (nvd, mitre, kev, osv, ghsa, epss)
│   ├── merge/            # CVE merge pipeline
│   ├── alert/            # Alert DSL compiler + evaluator
│   ├── notify/           # Notification channels + delivery
│   ├── auth/             # JWT, OAuth, API keys, argon2id
│   ├── worker/           # Job queue + goroutine pool
│   ├── search/           # FTS + facets
│   ├── report/           # Digest generation
│   ├── ai/               # LLMClient + Gemini adapter
│   ├── metrics/          # Prometheus counters/histograms
│   └── store/            # Repository layer (sqlc + squirrel)
├── migrations/           # SQL migration files (embedded via embed.FS)
├── templates/            # Notification templates (embedded via embed.FS)
├── openapi/              # Exported OpenAPI spec
├── research/             # Research decision docs (this file's children)
├── .github/workflows/    # GitHub Actions CI
├── docker-compose.yml    # Dev stack (Postgres + Mailpit)
├── Dockerfile            # Multi-stage build → distroless
├── .env.example          # Documented env vars
└── go.mod / go.sum
```

### Binary Modes (cobra subcommands)

- `serve` (default): runs HTTP server + embedded worker pool. Suitable for self-hosted single-instance.
- `worker`: standalone worker process. For SaaS scaling where API and workers run separately.
- `migrate`: run pending database migrations and exit.

### Graceful Shutdown

Hard deadline with configurable timeout:
- Default: 60 seconds (`SHUTDOWN_TIMEOUT_SECONDS=60`)
- On SIGTERM/SIGINT: stop accepting new HTTP requests and new jobs
- Wait for in-flight requests and jobs to complete (up to deadline)
- After deadline: force exit; in-flight jobs are reclaimed by stale lock detection (worker heartbeat timeout)

### Registration Mode

Configurable via `REGISTRATION_MODE` env var:
- `invite-only` (default): only org owners/admins can add members
- `open`: anyone can register and create their own org
- First user auto-becomes owner of a default org regardless of mode

### Embed Strategy

Use `embed.FS` to bundle into the single binary:
- SQL migration files (`migrations/`)
- Notification templates (`templates/`)
- Watchlist bootstrap templates (`templates/watchlists/`)
- Default OpenAPI spec export

External files that are NOT embedded:
- `.env` / configuration (user-provided)
- Database data (obviously)

---

## Sources

### Go 1.26
- https://go.dev/doc/go1.26
- https://go.dev/doc/devel/release

### OpenCVE
- https://docs.opencve.io/ (all subpages)
- https://github.com/opencve/opencve

### HTTP Framework
- https://github.com/go-chi/chi
- https://github.com/danielgtaylor/huma
- https://huma.rocks/
- https://github.com/oapi-codegen/oapi-codegen

### OIDC/OAuth
- https://github.com/coreos/go-oidc
- https://pkg.go.dev/github.com/coreos/go-oidc/v3

### Postgres RLS
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- AWS Multi-Tenant RLS Guide

### Password Hashing
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://pkg.go.dev/golang.org/x/crypto/argon2
- https://pkg.go.dev/github.com/alexedwards/argon2id

### Logging
- https://betterstack.com/community/guides/logging/best-golang-logging-libraries/
- https://www.dash0.com/guides/logging-in-go-with-slog

### SSRF Prevention
- https://github.com/doyensec/safeurl

### JSON Canonicalization
- https://github.com/cyberphone/json-canonicalization
- RFC 8785
