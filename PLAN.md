# Product Requirements Document: **CVErt Ops**

> **Version:** 6.0.0
> **Author:** Sam (Enterprise Solutions Architect)
> **Date:** 2026-02-19
> **Status:** All research decisions resolved. Ready for implementation. See `research.md` for detailed findings.
> **Language:** Go 1.26

---

## How to Use This Document (AI Agent Workflow)

1. This file is `plan.md`. All research decisions have been resolved; see `research.md` for detailed findings.
2. Annotate in this document after each planning/research pass before allowing implementation.
3. Do not implement until explicitly told. Planning ends in written artifacts, not code.
4. Prescriptive snippets are decisions, not suggestions.
5. Security is first-class. Treat CVErt Ops as a security product; shortcuts that weaken security are not allowed.

---

## 1. Executive Summary

**CVErt Ops** is an open-source vulnerability intelligence and alerting application that aggregates multiple public vulnerability feeds (NVD, MITRE, CISA KEV, GHSA, OSV, EPSS) into a unified, searchable corpus. Users define watchlists and alert rules to receive notifications (email, Slack, webhooks) and scheduled digests. Optional AI features provide natural-language search (LLM → structured query), CVE summaries, and digest summarization.

The product ships as:
- **Open-source core** for self-hosted deployment (Docker Compose). The MVP is **API-first**; the web frontend is planned but out-of-scope for this plan (see section 20). The backend compiles to a single static binary for minimal container footprint.
- **Optional hosted SaaS** with tiered plans (Free / Pro / Enterprise) enforced via feature flags, and multi-tenant orgs with RBAC.

---

## 1.1 Technology Stack Summary

| Layer | Choice | Notes |
|---|---|---|
| **Language** | Go 1.26 | Single binary; goroutine concurrency; stdlib `regexp` (RE2-equivalent); Green Tea GC |
| **HTTP framework** | `huma` + `chi` | Code-first OpenAPI 3.1; automatic struct-tag validation; RFC 9457 errors. See section 18.2 |
| **Database** | Postgres 15+ | `pgx` (driver) + `sqlc` (type-safe SQL codegen) + `squirrel` (dynamic DSL queries) |
| **Migrations** | `golang-migrate` | SQL migration files; one per change; embedded via `embed.FS` |
| **Validation** | `go-playground/validator` + huma struct tags | Struct tag validation (huma auto-validates requests) + handwritten rules for security-critical inputs |
| **Auth / JWT** | `golang-jwt/jwt/v5` | Access + refresh tokens |
| **OAuth / OIDC** | `coreos/go-oidc/v3` + `golang.org/x/oauth2` | GitHub + Google OAuth (MVP); generic OIDC deferred to Enterprise |
| **Password hashing** | `argon2id` via `alexedwards/argon2id` | OWASP params: m=19456, t=2, p=1. See section 7.1 |
| **Templates** | Go `html/template` / `text/template` | Notification rendering; sandboxed by design; embedded via `embed.FS` |
| **AI / LLM** | Google Gemini (`google.golang.org/genai`) | Official Go SDK; `LLMClient` interface for vendor abstraction. See section 13.4 |
| **Background jobs** | Goroutine worker pool + Postgres job queue | See section 18.1 |
| **CLI** | `cobra` | Subcommands: `serve`, `worker`, `migrate` |
| **Logging** | `slog` (stdlib) | Structured JSON logging; `NewMultiHandler` (Go 1.26) for multi-destination |
| **Configuration** | `caarlos0/env/v10` + `go-playground/validator` | Env var parsing with startup validation |
| **Metrics** | `prometheus/client_golang` | `/metrics` endpoint from Phase 0 |
| **SSRF prevention** | `doyensec/safeurl` | Drop-in safe HTTP client for outbound webhooks |
| **JSON canonicalization** | `cyberphone/json-canonicalization` | JCS/RFC 8785 for deterministic `material_hash` |
| **Static analysis** | `go vet`, `staticcheck`, `gosec`, `govulncheck` | CI pipeline (GitHub Actions) |
| **Container** | `distroless:static-debian12` (default) | Includes CA certs/timezone data; still minimal for a static Go binary. See Decision D1. |

---


### Decision D1 — Runtime container base image (MVP)

**Decision (MVP):** Use **`gcr.io/distroless/static-debian12`** (or equivalent distroless static image with CA certificates) as the default runtime image.

**Why this decision exists:** A pure `scratch` image does not include CA certificates, so HTTPS calls to NVD/GHSA/OSV and outbound webhooks will fail unless we bundle a CA bundle manually.

**Considerations (multiple angles):**
- **Security / attack surface:**  
  - `scratch` is smallest, but forces you to manage certs yourself (easy to misconfigure).  
  - distroless is slightly larger but still removes shells/package managers; practical minimal surface.
- **Operational reliability:**  
  - distroless includes CA certs and sane defaults; fewer “works locally, fails in prod” issues.
- **Supply chain:**  
  - distroless images are maintained and frequently patched; pin by digest for reproducibility.
- **Self-host friendliness:**  
  - distroless avoids requiring users to understand cert bundling.

**Alternative (revisit later):** `scratch` + copy CA bundle + optional `tzdata`. If choosing this later, document the exact CA path and add CI tests that verify outbound TLS succeeds.

---

## 2. Target Users & Personas

| Persona | Description | Key Needs | Likely Tier |
|---|---|---|---|
| Security Engineer | Vulnerability management | Triaged alerts; reporting | Pro/Ent |
| DevSecOps/SRE | CI/CD + infra | Webhook automation; package ecosystem matching | Pro |
| OSS Maintainer | Maintains libraries | CVE/advisory monitoring | Free/Pro |
| CISO/Sec Manager | Reporting & trends | Digests; executive summaries | Ent |
| Homelab Operator | Self-hosted | Simple install; key software monitoring | Free |

---

## 3. Data Sources & Ingestion

### 3.1 Core Feeds (MVP)
| Source | Format | Update | Notes |
|---|---|---|---|
| NVD (NIST) | JSON (API 2.0) | every 2 hours | CVSS, CPE, references |
| MITRE CVE | CVE 5.0 JSON | daily | authoritative CVE IDs/status |
| CISA KEV | JSON | daily | high-signal "known exploited" |
| GitHub Security Advisories (GHSA) | GraphQL | periodic poll (MVP) | maps packages/ecosystems + ranges |
| OSV.dev | JSON | periodic poll (MVP) | strong package version range data |
| FIRST.org EPSS | CSV/JSON | daily | exploit prediction scoring; enriches `epss_score` |

**MVP note:** Webhooks (e.g., GHSA) are deferred; polling only.

**EPSS note:** EPSS is an enrichment feed, not a CVE source. The adapter writes only to `cves.epss_score` (keyed by CVE ID) and does not participate in the merge pipeline described in section 5. If a CVE ID from EPSS does not yet exist in the corpus, the score is held in a staging table and applied on next CVE upsert.

### 3.2 Feed Adapter Contract (Deterministic)
Each feed adapter must implement the `FeedAdapter` interface:
```go
type FeedAdapter interface {
    // Fetch returns a batch of results starting from the given cursor.
    Fetch(ctx context.Context, cursor json.RawMessage) (*FetchResult, error)
}

type FetchResult struct {
    Patches    []CanonicalPatch   // normalized partial documents
    RawPayload json.RawMessage    // original response (stored for audit)
    SourceMeta SourceMeta         // feed name, fetch timestamp, cursor metadata, request ID
    NextCursor json.RawMessage    // nil if no more pages
}
```

Adapters must be pure functions + minimal I/O wrappers (HTTP client injected), so they can be unit-tested with recorded responses.

**Per-adapter rate limiting:** Each adapter manages its own client-side rate limiter based on the upstream API's constraints (e.g., NVD: 5 req/30s with API key; GHSA: GitHub token rate limits). Rate limiters are configured per adapter, not shared globally, since each upstream has different limits.

**Exception:** The EPSS adapter returns `[]EnrichmentPatch` (just `{cve_id, epss_score}`) rather than `[]CanonicalPatch`, since it is not a CVE source.

### 3.3 Ingestion Scheduling, Cursoring, and Idempotency

**State tables**
- `feed_sync_state(feed_name PK, cursor_json, last_success_at, last_attempt_at, consecutive_failures, last_error, backoff_until)`
- `feed_fetch_log(id, feed_name, started_at, ended_at, status, items_fetched, items_upserted, cursor_before, cursor_after, error_summary)`

**Cursor policy**
- Use "last modified" or equivalent incremental cursor when supported.
- Persist cursor **only** after a fully successful page/window.
- On failure: retry with exponential backoff; do not advance cursor.

**Idempotency**
- All writes are **upserts** keyed by `cve_id`.
- Each upsert updates `date_modified_canonical` only if the merge result (including `material_hash`) actually changes.
- `date_first_seen` never changes after first insert.
- `date_modified_source_max` is the maximum of all per-source `source_date_modified` values and is recomputed on each merge.

**Backfill**
- First run performs a full historical sync per feed, with rate limiting + progress logging.
- Backfill runs in bounded windows (e.g., NVD pages) to avoid huge transactions.

**Backfill ordering and serialization**
- Feeds are backfilled sequentially in precedence order: MITRE → NVD → CISA KEV → OSV → GHSA → EPSS. This ensures higher-precedence sources establish the baseline before lower-precedence sources merge in.
- Within a single feed's backfill, pages are processed serially.
- After all feeds complete initial backfill, the system switches to normal concurrent polling.

### Decision D4 — Per-CVE merge serialization (MVP)

**Decision (MVP):** Serialize merges **per CVE ID** using `pg_advisory_xact_lock(hashtext(cve_id))` so concurrent feed polls cannot clobber each other.

**Transaction boundary (required):**
Within the same DB transaction:
1) `SELECT pg_advisory_xact_lock(hashtext($cve_id));`
2) Upsert/replace the per-source normalized row in `cve_sources` (and store raw payload separately).
3) Recompute the canonical CVE row **from the current set of `cve_sources`** for that CVE (read-your-writes).
4) Upsert the canonical `cves` row and dependent rows (`cve_references`, `cve_affected_*`) and compute `material_hash`.
5) Commit.

**Considerations (multiple angles):**
- **Correctness:** prevents lost updates when two sources update the same CVE near-simultaneously.
- **Performance:** lock contention should be low because contention only occurs per single CVE ID; different CVEs merge in parallel.
- **Operational debugging:** advisory locks are invisible unless queried; add metrics on “lock wait time” to detect contention.
- **Failure mode:** the lock is xact-scoped; crashes release it automatically.

**Alternative (revisit later):**
- Serialize with row-level locks on a dedicated `cves_lock` table (more visible in DB).
- Queue per-CVE merges into a single “merge” worker to avoid locks (simpler correctness; lower concurrency).

---

## 4. Canonical Data Model (Global CVE Corpus)

### 4.1 Core Principle
**CVE records are global/shared.** Tenant/org data (tags, notes, suppression state, alert history) is stored separately in org-scoped tables.

### 4.2 Tables (High level)
**Global**
- `cves` (canonical fields + computed material-change hash)
- `cve_sources` (per-source normalized subdocuments)
- `cve_references`
- `cve_affected_packages` (ecosystem + package + version range)
- `cve_affected_cpes` (CPE URIs)
- `cwe_dictionary` (optional; see 8.2)
- `cve_raw_payloads` (audit/debug)

**Org/Tenant scoped**
- `organizations`, `users`, `user_identities` (federated login links), `org_members`, `groups`, `group_members`
- `watchlists`, `watchlist_items`
- `alert_rules`, `alert_rule_runs`, `alert_events`
- `notification_channels`, `notification_deliveries`
- `scheduled_reports`, `report_runs`
- `cve_annotations` (org tags/notes/snoozes)
- `ai_usage_counters` (per-org AI quota tracking)

### 4.3 Canonical CVE Record (`cves`)
Fields (illustrative):
- `cve_id` (PK)
- `status` (`new|modified|analyzed|rejected|unknown`)
- `date_published`, `date_modified_source_max`, `date_modified_canonical`, `date_first_seen`
- `description_primary`
- `severity` (`none|low|medium|high|critical`)
- `cvss_v3_score`, `cvss_v3_vector`, `cvss_v4_score`, `cvss_v4_vector`
- `cwe_ids[]`
- `exploit_available` (bool)
- `in_cisa_kev` (bool)
- `epss_score` (float, nullable)
- `material_hash` (hash of "material fields" used for alert dedupe)
- `fts_document` (tsvector) for Postgres full-text search

**Timestamp semantics:**
- `date_modified_source_max`: the latest `source_date_modified` across all sources for this CVE. Tracks when upstream data last changed.
- `date_modified_canonical`: when the CVErt Ops canonical record itself was last changed (i.e., when a merge resulted in a different `material_hash` or any field change). Used for cursor-based polling by alert batch jobs and API pagination.
- `date_first_seen`: when CVErt Ops first ingested this CVE. Immutable after insert.

### 4.4 Per-Source Storage (`cve_sources`)
Store normalized per-feed JSON (not raw) to preserve provenance and enable "show source differences."
- PK: `(cve_id, source_name)`
- fields: `normalized_json`, `source_date_modified`, `source_url`, `ingested_at`

### 4.5 Raw Payload Storage
Raw payloads are kept separately in `cve_raw_payloads` keyed by `(cve_id, source_name, ingested_at)` to support auditing/debugging. This avoids bloating the canonical row.

---

## 5. Merge Rules & Conflict Resolution (Deterministic)

### 5.1 Source Precedence by Field
Define precedence **per field**, not globally:

| Field group | Preferred sources (highest → lowest) |
|---|---|
| `cve_id`, status | MITRE → NVD → OSV/GHSA |
| CVSS v3/v4 scores/vectors | NVD → vendor advisories (future) → OSV/GHSA |
| "Known exploited" | CISA KEV (authoritative for that flag) |
| Package ecosystems + version ranges | OSV → GHSA → NVD (if present) |
| Description | MITRE → NVD → OSV/GHSA (fallback) |
| References | Union (dedupe by URL canonicalization), keep tags per-source |
| `epss_score` | FIRST.org EPSS (sole source; not merged) |

### 5.2 Merge Strategy
- Build a canonical record by selecting highest-precedence non-null value per field.
- For list-like fields (CWEs, references, affected products): **union + normalize + dedupe**.
- Preserve all per-source normalized documents in `cve_sources`.
- On each adapter write, the merge function re-reads all `cve_sources` rows for the given `cve_id` and recomputes the canonical record from scratch. This ensures consistency regardless of ingestion order and makes the merge purely a function of current source state. The write amplification (~5 source rows read per CVE upsert) is acceptable at MVP scale; an incremental merge approach would be more complex and prone to drift.

### 5.3 Material Change Definition (for Alert Dedup)
A "material change" is any change to one of these, after normalization:
- `severity`
- `cvss_v3_score`, `cvss_v3_vector`
- `cvss_v4_score`, `cvss_v4_vector`
- `exploit_available`
- `in_cisa_kev`
- `epss_score` (change exceeding configurable threshold, default 0.1)
- affected packages (ecosystem/package/version range set)
- affected CPE set
- `status` transition to `rejected` or from `rejected` to active
- description changes are **non-material by default** (stored but do not re-fire alerts)

Implementation: `material_hash = sha256(json_canonical(material_fields))`. If hash changes, alerts may re-fire depending on rule settings. JSON canonicalization uses deterministic key ordering and encoding (e.g., `github.com/cyberphone/json-canonicalization` or equivalent).

**Note on EPSS:** Because EPSS scores update daily for many CVEs, raw score changes would create excessive alert noise. EPSS changes are material only when the score crosses a configurable threshold delta (default: absolute change ≥ 0.1). The `material_hash` computation buckets `epss_score` into bands (0.0–0.1, 0.1–0.2, …, 0.9–1.0) so that minor fluctuations within a band do not trigger re-firing.

---

## 6. Multi-Tenancy & Isolation

### 6.1 What is Tenant-Scoped vs Global
| Data | Scope |
|---|---|
| CVE corpus | Global |
| Watchlists, alert rules, channels, reports, RBAC | Org |
| Annotations/tags/snoozes | Org |
| AI quota usage + billing counters | Org |

### 6.2 Enforcement Model (MVP Decision)
**MVP decision:** enforce tenant isolation at the **application query layer** with:
- a required `orgID` parameter in every org-scoped repository/service method
- integration tests asserting no cross-org access
- defensive DB constraints: every tenant table includes `org_id` NOT NULL + indexed

**Postgres RLS (P1 — RESOLVED, implementation deferred)**

RLS will be implemented in P1 for SaaS hardening. Research is complete (see `research.md` section 7):

- **Session variable strategy:** `SET LOCAL app.org_id = $1` per-transaction via pgx. Auto-resets on commit/rollback.
- **Policy pattern:** `USING (org_id = current_setting('app.org_id')::uuid)` + `WITH CHECK (...)` on all org-scoped tables. `FORCE ROW LEVEL SECURITY` to prevent owner bypass.
- **Performance:** <5% overhead with simple comparison policies. Requires `BTREE(org_id)` index on every org-scoped table (already planned).
- **Bypass prevention:** App DB role uses `NOBYPASSRLS`. No raw SQL paths; all queries via sqlc/squirrel.
- **Self-hosted vs SaaS:** Always enable RLS; self-hosted uses a fixed org_id from env or auto-generated at first startup. Same codebase, same migrations, same policies.
- **Migration strategy:** Disable RLS during schema changes, re-enable after. Policies are part of migration files.

---

## 7. Authentication, Authorization, Sessions, and Identity

### 7.1 Session Strategy (MVP)
- JWT access tokens (short-lived, ≤15 min) + refresh tokens (rotating, 7-day max), using `golang-jwt/jwt/v5`
- **Transport:** HttpOnly secure cookies (SameSite=Lax) for the web app
- API keys for automation (hashed-at-rest with `crypto/sha256`, scoped to org + role)

**Password hashing (native auth):**
- Algorithm: argon2id via `alexedwards/argon2id` wrapper (uses `golang.org/x/crypto/argon2`)
- Parameters per OWASP Password Storage Cheat Sheet: memory=19456 KiB (19 MiB), iterations=2, parallelism=1, salt=16 bytes, key=32 bytes
- Storage format: `$argon2id$v=19$m=19456,t=2,p=1$[base64(salt)]$[base64(hash)]`
- `users` table includes `password_hash_version INT DEFAULT 2` column (1=bcrypt legacy, 2=argon2id) for future algorithm migration via lazy upgrade on login

**CSRF**
- Use SameSite cookies + CSRF token for state-changing requests (double-submit token or header token).

### 7.2 Federation Strategy (RESOLVED)
**Decision:** `coreos/go-oidc/v3` for OIDC discovery/verification + `golang.org/x/oauth2` for OAuth2 flows. This is the standard pairing in the Go ecosystem (v3.17.0, actively maintained as of Nov 2025).

**MVP auth scope:**
- Native email/password (argon2id hashing, see 7.1)
- GitHub OAuth
- Google OAuth
- Generic OIDC and SAML deferred to Enterprise milestones (`crewjam/saml` if needed)

**`user_identities` table:** Each row links a `user_id` to a federated identity provider (e.g., `provider=github, provider_user_id=12345, email=...`). A user may have multiple identities (e.g., email/password + GitHub). This table is the reason `user_identities` appears in org/tenant tables (see 4.2) and is required for MVP to support the native + GitHub auth paths.

### 7.3 RBAC Model (MVP)

**Roles**

| Role | Scope | Description |
|---|---|---|
| `owner` | org | Full control including org deletion, billing, and ownership transfer. Exactly one owner per org (transferable). |
| `admin` | org | Manage members, groups, watchlists, alert rules, channels, reports, and org settings. Cannot delete org or transfer ownership. |
| `member` | org | Create/edit own watchlists and alert rules. View all org watchlists, alerts, and reports. Cannot manage members or channels. |
| `viewer` | org | Read-only access to CVE data, watchlists, alerts, and reports within the org. Cannot create or modify any org resources. |

Roles are stored on `org_members(org_id, user_id, role)`. A user's effective role in an org is determined solely by their `org_members` row; group membership does not escalate role.

**Groups**

Groups (`groups`, `group_members`) are org-scoped collections of users used for:
- **Notification routing:** a notification channel can target a group (e.g., "send digest to the AppSec team group").
- **Watchlist ownership:** a watchlist can be owned by a group, making it visible/editable by all group members (subject to their role permissions).
- **Future: fine-grained permissions.** Groups provide the structural foundation for per-resource ACLs if needed post-MVP (e.g., "only the Platform team group can edit this watchlist"). MVP does not implement per-resource ACLs.

Groups do **not** define roles. Every user's permissions come from their org-level role; groups are purely an organizational/routing construct.

**Permission Matrix (MVP)**

| Action | owner | admin | member | viewer |
|---|---|---|---|---|
| Manage org settings / billing | Y | — | — | — |
| Delete org / transfer ownership | Y | — | — | — |
| Invite / remove members | Y | Y | — | — |
| Assign roles (up to admin) | Y | Y | — | — |
| Manage groups | Y | Y | — | — |
| CRUD notification channels | Y | Y | — | — |
| CRUD watchlists (any) | Y | Y | — | — |
| CRUD own watchlists | Y | Y | Y | — |
| CRUD alert rules (any) | Y | Y | — | — |
| CRUD own alert rules | Y | Y | Y | — |
| CRUD scheduled reports | Y | Y | Y | — |
| View all org data (CVEs, alerts, reports) | Y | Y | Y | Y |
| Use AI features (within quota) | Y | Y | Y | Y |
| Manage API keys (own) | Y | Y | Y | — |
| View audit log (Enterprise) | Y | Y | — | — |

**Enforcement:**
- Every org-scoped endpoint checks `(org_id, user_id) → role` before processing.
- Permission checks are implemented as reusable middleware (chi middleware chain or echo middleware), not inline per-handler. The middleware extracts the authenticated user's role from the JWT claims + `org_members` lookup (cached per-request) and injects it into the request context.
- Integration tests must cover: each role × each endpoint = expected allow/deny.
- The `owner` role cannot be assigned via the normal role-assignment endpoint; ownership transfer is a separate, confirmation-gated action.

**Self-hosted single-user mode:** For homelab/self-hosted deployments with a single user, the first user to register is automatically assigned `owner` of a default org. This avoids requiring org setup ceremony for simple deployments.

---

## 8. Search & Indexing

### 8.1 Search Requirements (MVP)
- Full text search across: description + vendor/product tokens + package names + CWE titles (if dictionary present)
- Facets: severity, CVSS range, date range, CWE, ecosystem/package, exploit status, CISA KEV, EPSS range

### 8.2 CWE Titles (RESOLVED)
**Decision: Full dictionary ingestion.**

Ingest MITRE CWE list into `cwe_dictionary(cwe_id TEXT PK, name TEXT, description TEXT)` and include `name` in FTS `tsvector` document for search enrichment. Users can search "buffer overflow" and find CVEs with CWE-120.

- **Data source:** https://cwe.mitre.org/data/downloads.html (XML or JSON, freely available)
- **Update cadence:** Low (CWE list changes infrequently); periodic refresh via CLI command or scheduled job
- **Ingestion:** `cvert-ops import-cwe` CLI command or auto-ingest on first run
- **FTS integration:** Join CWE names into CVE's `fts_document` tsvector during merge

---

## 9. Watchlists

### 9.1 Concept
A watchlist is an org-defined set of things the org cares about:
- Packages: `(ecosystem, name, optional namespace)`
- CPE patterns / exact CPEs
- Vendors/products (optional convenience)

### 9.2 Matching Semantics
- For packages: match if CVE has affected package entry with same ecosystem + normalized package name.
- For CPE: match exact or prefix-pattern match (define pattern rule: "startsWith on normalized CPE string").

### 9.3 Watchlist–Alert Rule Binding

Alert rules and watchlists are **independent but composable.** An alert rule optionally references one or more watchlists as a pre-filter:

- `alert_rules.watchlist_ids` (nullable array of UUIDs): if present, the rule evaluates **only** against CVEs that match at least one of the referenced watchlists. If null/empty, the rule evaluates against the entire CVE corpus.
- This binding is a filter, not a join condition in the DSL. Conceptually: `matched_cves = (watchlist_matches ∩ dsl_filter_results)` when watchlists are bound, or `matched_cves = dsl_filter_results` when unbound.
- Scheduled digests (section 12) can also be scoped to a watchlist independently of alert rules.

This design means:
- Simple use case (homelab): create a watchlist of your packages, create a rule "severity ≥ high", bind the rule to the watchlist → you get alerts only for high-severity CVEs affecting your packages.
- Advanced use case (security team): create a rule "in_cisa_kev = true" with no watchlist binding → you get alerts for all newly KEV-listed CVEs across the entire corpus.
- Watchlists are reusable across multiple rules and reports.

---

## 10. Alert Rules (DSL + Execution)

### 10.1 DSL: Allowed Fields and Types (MVP)
Only these fields can be referenced in rules:

| Field | Type | Notes |
|---|---|---|
| `cve_id` | string | |
| `severity` | enum | |
| `cvss_v3_score` | float | |
| `cvss_v4_score` | float | |
| `epss_score` | float | |
| `date_published` | datetime | |
| `date_modified_source_max` | datetime | |
| `cwe_ids` | string[] | membership checks |
| `in_cisa_kev` | bool | |
| `exploit_available` | bool | |
| `affected.ecosystem` | string | via join to affected packages |
| `affected.package` | string | via join |
| `description_primary` | text | `contains`, `regex` |

### 10.2 Operators (MVP)
- Numeric: `gt|gte|lt|lte|eq|neq`
- Enum/bool: `eq|neq|in|not_in`
- Arrays: `contains_any|contains_all`
- Text: `contains` (case-insensitive), `starts_with`, `ends_with`, `regex`

**Regex support (MVP, RE2-equivalent via Go stdlib):**  
Regex is enabled using Go's `regexp` package (RE2-equivalent semantics: linear time, no catastrophic backtracking). This avoids ReDoS while still allowing powerful matching.

**Decision (MVP):** Regex is allowed, but **only as a post-filter** after a selective SQL prefilter, with strict guardrails to prevent accidental “scan the world in Go.”

**Validation constraints**
- max pattern length: 256 characters
- `regexp.Compile` must succeed (invalid patterns rejected)
- implicit RE2 limitations apply (no backreferences/lookarounds)

**Execution constraints (guardrails)**
- Regex rules **MUST** include at least one selective SQL-side constraint:
  - watchlist binding (`watchlist_id`), **or**
  - `severity >= X`, **or**
  - `in_cisa_kev = true`, **or**
  - `date_published` / `date_modified_*` bounded window (e.g., last N days), **or**
  - `affected.ecosystem/package` filter
- Candidate cap: the SQL prefilter may return at most **N candidates** (default `N=5,000`). If the cap is exceeded:
  - the run is marked `status=partial` with a warning
  - **no alerts are fired** for that rule/run (fail-closed to avoid incomplete evaluation)
  - operator-facing metric + log entry emitted
- Compiled `*regexp.Regexp` objects are cached per rule (safe for concurrent use).

**Why these guardrails (multiple angles):**
- **Correctness:** without a cap, a “wide” regex rule can silently degrade into long runtimes and partial results.  
- **Performance:** bounded candidates protect DB and worker CPU.  
- **Security:** even linear-time regex can be abused if applied to millions of rows.  
- **Operator UX:** fail-closed + explicit warning prevents false confidence.

**Alternatives (revisit later):**
- Implement trigram/GIN prefilters on `description_primary` to increase selectivity before regex.
- Offer a “regex-disabled” mode for conservative deployments.


### 10.3 Execution Model (Deterministic)
- Rules compile to SQL queries over canonical tables (no "scan in Go"), with the exception of regex post-filtering described in 10.2.
- **Query builder:** Dynamic DSL queries use `squirrel` (safe query builder with parameterized output). All static CRUD queries use `sqlc`. This split exists because `sqlc` requires all queries written upfront in `.sql` files, but DSL rules produce dynamic WHERE clauses at runtime. `squirrel` generates parameterized SQL (never string concatenation).
- Alerts run:
  - **Realtime**: on CVE upsert that results in changed `material_hash`
  - **Batched**: periodic job evaluates "changed CVEs since last run" (uses `date_modified_canonical` as cursor)
  - **Digest-only**: no immediate alerts; included in scheduled reports

### 10.4 Dedup Model
Table `alert_events(org_id, rule_id, cve_id, material_hash, first_fired_at, last_fired_at, times_fired)`
- A rule fires again only if `material_hash` changes OR if `rule.fire_on_non_material_changes=true` (default false).

### 10.5 DSL Versioning

Alert rules are versioned to handle schema evolution safely:
- Each saved rule stores a `dsl_version` integer (starting at `1`).
- The rule compiler maintains support for all active DSL versions. When the DSL evolves (new fields added, operators changed), the version is bumped, and a migration path is defined.
- **Adding fields:** backward-compatible; existing rules at older versions simply don't reference the new field. No migration needed.
- **Removing or renaming fields:** the old version's compiler continues to support the field with a deprecation warning. A background migration job rewrites affected rules to the new version (with admin review for ambiguous cases). Rules that cannot be auto-migrated are **disabled with an admin notification**, never silently dropped or allowed to fail open.
- **Fail-closed policy:** if a rule references a field or operator that the current compiler does not recognize (e.g., due to a corrupted or hand-edited rule), the rule evaluation fails closed (no alerts fire, an error is logged, and the rule is marked `status=error`). This is a security product; a broken rule must not silently miss alerts.

### 10.6 Rule Validation & Dry-Run Endpoints

- `POST /api/v1/orgs/{org_id}/alert-rules/validate` — Syntax/schema validation without saving. Returns parsed rule structure and any validation errors. Allows users to check a rule before committing.
- `POST /api/v1/orgs/{org_id}/alert-rules/{id}/dry-run` — Runs the saved rule against current CVE data and returns matching CVEs **without firing alerts or creating alert events**. Returns the match count, sample CVEs, and execution metadata (candidates evaluated, time elapsed). Subject to the same candidate cap as real execution.

These endpoints prevent users from discovering rule errors only at the next batch evaluation (which could be hours later).

---

## 11. Notification Channels & Delivery Semantics

### 11.1 Channels (MVP)
- Email (SMTP)
- Slack incoming webhook
- Generic webhook (POST JSON)
- Teams: Enterprise (post-MVP if needed)

### 11.2 Delivery Guarantees
- **At-least-once** delivery.
- Each delivery has an **idempotency key**: `sha256(org_id + event_id + channel_id)`.
- Retry policy: 3 retries with exponential backoff (e.g., 1m, 5m, 30m), then dead-letter.

### 11.3 Webhook Security (Required)
- HMAC signature header: `X-CVErtOps-Signature: sha256=<hex>` (using `crypto/hmac` + `crypto/sha256`)
- Prevent SSRF using `doyensec/safeurl` as the HTTP client for all outbound webhook calls:
  - blocks private IPs (RFC 1918) and link-local ranges by default
  - mitigates DNS rebinding attacks
  - disallows non-HTTP(S)
  - enforce timeout + max response size (`http.Client` with `Timeout`; `io.LimitReader` on response body)
- Validate webhook URLs at registration time (not just request time)
- Allow per-channel headers but denylist dangerous ones (`Host`, `Content-Length`, etc.)

### 11.4 Notification Content & Templates

Notifications use a **structured payload model** with per-channel rendering. The core payload is channel-agnostic; renderers format it for each channel type.

**Core notification payload** (per alert event):
```
cve_id, severity, cvss_v3_score, cvss_v4_score, epss_score,
description_primary (truncated to 280 chars),
exploit_available, in_cisa_kev,
affected_packages (list, max 10),
rule_name, rule_id,
watchlist_name (if bound),
cvert_ops_url (deep link to CVE detail)
```

**Channel renderers (MVP):**

| Channel | Format | Notes |
|---|---|---|
| **Email** | HTML with plaintext fallback | Subject: `[CVErt Ops] {severity} — {cve_id}`. Body uses a simple HTML template (inline CSS, no external assets). Digest emails group CVEs by severity. |
| **Slack** | Block Kit JSON | Uses `section`, `divider`, and `context` blocks. Severity is color-coded via sidebar attachment color. |
| **Generic webhook** | Raw JSON | Posts the core payload as-is (JSON object). Consumers parse as needed. |

**Template extensibility:**
- Templates are stored as Go `html/template` (for email) and `text/template` (for Slack/webhook) files, embedded via `embed.FS` for the built-in defaults. One template per channel type per notification kind (alert vs. digest).
- Go's `html/template` is auto-escaped by design, preventing XSS in email HTML without needing a sandbox mode.
- MVP ships with built-in templates. Custom templates are a P1/Enterprise feature (loaded from filesystem or DB, parsed with `template.New().Parse()` at channel-config time, not per-render).

---

## 12. Scheduled Reports (Digests)

MVP:
- Daily digest (new + materially modified CVEs last 24h)
- Weekly summary (optional P1)

Configurable:
- scope by watchlist and severity threshold
- delivery time with timezone support
- optional AI executive summary (Pro+)

---

## 13. AI Features

### 13.1 Hard Rule: No "AI decides truth"
AI augments UX; canonical data remains sourced from feeds.

### 13.2 Natural Language Search (MVP)
- LLM transforms user text → structured query JSON (filters + sort + limit).
- The app executes query locally against Postgres.
- Prompts contain:
  - schema/field list + operator constraints
  - **no CVE content**

### 13.3 Summaries (P1)
AI summary for a CVE may include CVE content (description, scores, affected products) but must:
- cite source fields, not invent
- be cached per `(cve_id, prompt_version, model)`
- be opt-in by tier (Pro+)

### 13.4 AI Gateway Requirements
Central service enforces:
- per-org quota + rate limit
- request logging (no sensitive data)
- caching keyed by `(org_id, feature, prompt_version, input_hash)`
- cost tracking counters

**`ai_usage_counters` table:** Tracks per-org, per-feature usage (e.g., `nl_search_count`, `summary_count`) with daily and monthly rollup columns. Used for quota enforcement (section 14) and billing metering. Resets are configurable per tier (monthly for Pro, custom for Enterprise).

**AI gateway design:** The gateway is implemented as an internal Go interface, with vendor-specific adapters behind it:
```go
type LLMClient interface {
    // GenerateStructuredQuery sends a NL query and returns structured JSON.
    GenerateStructuredQuery(ctx context.Context, prompt string) (json.RawMessage, error)
    // Summarize generates a CVE summary from structured input.
    Summarize(ctx context.Context, input CVESummaryInput) (string, error)
}
```
This abstraction allows swapping LLM vendors without changing application code.

**Decision: Google Gemini** (`google.golang.org/genai`, official Go SDK, GA status).

Gemini was chosen for:
- Official first-party Go SDK with structured output support
- Competitive pricing
- JSON-mode reliability for NL → structured query JSON

The `LLMClient` interface ensures the vendor choice is not permanent; switching to OpenAI or another provider requires only implementing the interface.

---

## 14. Account Tiers & Feature Flags

Maintain tier matrix (Free/Pro/Enterprise) with hard API enforcement:
- max alert rules, watchlists, members
- AI quotas
- channels availability
- exports and retention

Feature flag precedence:
1. org override
2. tier default
3. global default

---

## 15. Security Requirements (Non-negotiable)

- Parameterized queries only (`sqlc` + `pgx` parameterized queries; no string concatenation)
- Auth required for all non-public endpoints
- Strict input validation via `go-playground/validator` struct tags with length bounds; security-critical fields (webhook URLs, regex patterns, etc.) validated with additional handwritten checks
- Secrets never logged; use env + secret manager pattern
- Dependency pinning (`go.sum`) + vulnerability scanning (`govulncheck` on CI)
- Security tests:
  - tenant isolation test per org endpoint
  - authz test per endpoint (role × endpoint matrix from 7.3)
  - SSRF tests for webhook URLs
- Static scanning: `go vet` + `staticcheck` + `gosec` on CI

---

## 16. API Contract Standards

- Base path: `/api/v1`
- Pagination: `limit`, `cursor` (opaque), deterministic ordering (by `date_modified_canonical` desc, then `cve_id` for tiebreak, unless otherwise specified)
- Error format: RFC 9457 Problem Details (generated automatically by huma):
```json
{ "type": "https://api.cvertops.dev/errors/validation", "title": "Validation Error", "status": 422, "detail": "Request validation failed", "errors": [{ "location": "body.name", "message": "minimum length is 3" }] }
```
- All timestamps UTC ISO8601.
- OpenAPI 3.1 spec is generated automatically by huma from Go type definitions. Served at `/openapi` endpoint. Used for client type generation and API documentation.

### Decision D5 — How org context is carried in the API (MVP)

**Decision (MVP):** Carry org context in the **URL path**: `/api/v1/orgs/{org_id}/...`

**Considerations (multiple angles):**
- **Clarity:** explicit and visible; easy to reason about in logs and OpenAPI.
- **Authorization:** makes it straightforward to validate `{org_id}` against the authenticated principal’s org memberships.
- **Caching / proxies:** path-based routing works cleanly with reverse proxies/CDNs.
- **Ergonomics:** avoids “hidden” coupling to custom headers for every client call.

**Alternatives (revisit later):**
- `X-Org-ID` header (clean URLs, but easy to omit/misconfigure; harder to debug).
- Subdomain per org (nice UX; complicates self-hosted and local dev; requires wildcard DNS).
- Derive org from token only (simplest URLs, but complicates “switch org” UX and auditing).


### 16.1 API Rate Limiting

Rate limiting is enforced at the API middleware layer to protect against abuse and ensure fair usage across tiers.

**Strategy:** Token-bucket per org, with per-endpoint overrides for expensive operations.

| Scope | Free | Pro | Enterprise |
|---|---|---|---|
| Global API (requests/min/org) | 60 | 300 | 1000 (configurable) |
| CVE search (requests/min/org) | 20 | 100 | 500 |
| AI NL search (requests/day/org) | 10 | 100 | 1000 |
| Webhook delivery retries | n/a | n/a | n/a |

### Decision D6 — Rate limiting storage (MVP)

**Decision (MVP):** Use **in-process** token buckets for rate limiting **with the explicit constraint** that hosted/SaaS MVP runs as **a single API instance** (or accepts “best-effort” limits). Self-hosted commonly runs a single instance, so this is acceptable for MVP.

**Considerations (multiple angles):**
- **Simplicity:** in-process is easy and fast; no extra dependencies.
- **Correctness in multi-instance:** in-process counters are not shared; limits become approximate when horizontally scaled.
- **Operational posture:** Redis introduces new failure modes and operational overhead; Postgres-based counters add contention and complexity.
- **Roadmap:** once SaaS requires >1 API instance, shared rate-limit state becomes mandatory.

**Alternatives (P1+):**
- **Redis** token buckets (recommended for SaaS scale): shared state, fast, well-understood.
- **Postgres-backed** rate limit table using `INSERT ... ON CONFLICT DO UPDATE` (works, but can become hot-row contention).
 SaaS.
- Exceeded limits return `429 Too Many Requests` with `Retry-After` header.
- API keys inherit the rate limits of their org's tier.
- Internal/worker goroutine calls (e.g., feed ingestion, notification delivery) bypass API rate limits; they call service functions directly, not through the HTTP layer.

---

## 17. Operational / Admin Controls (MVP)

- `/healthz` for API, worker, DB connectivity
- Feed status endpoint (last success, cursor, failures)
- Admin actions:
  - re-run feed window
  - rebuild search index
  - retry dead-letter deliveries
- Audit log (Enterprise P1)

---

## 18. Implementation Phases (Tracker)

**Phase 0 — Repo + CI skeleton** (no product code)
- Go 1.26 module init (`github.com/scarson/cvert-ops`), linter config (`golangci-lint`), test harness (`testcontainers-go`), docker compose dev stack (Postgres + Mailpit)
- Skeleton HTTP server (huma + chi) + worker process (cobra subcommands) + DB migrations (`golang-migrate`, embedded)
- Prometheus `/metrics` + `/healthz` endpoints
- GitHub Actions CI pipeline
- `.env.example` with documented config vars

**Phase 1 — Data ingestion + canonical storage + search** (MVP core)
- adapters: NVD, MITRE, CISA KEV, OSV, GHSA, EPSS (poll)
- merge rules + material_hash
- FTS + facets + CVE detail API

**Phase 2 — Org model + RBAC + watchlists + alert rules**
- org/user auth, org-scoped tables, RBAC (section 7.3)
- watchlist CRUD + matching joins
- alert DSL compiler → SQL + event generation

**Phase 3 — Notifications + reports**
- email/slack/webhook channels + notification templates (section 11.4)
- delivery retries + DLQ
- daily digest reports

**Phase 4 — AI gateway + NL search**
- LLMClient interface + vendor adapter
- NL → query JSON + execution
- quotas + caching + metrics

**Phase 5 — Hardening and SaaS readiness**
- optional Postgres RLS (if chosen)
- audit log, billing hooks, SSO (as planned)
- data retention policy automation (section 21)

### 18.1 Worker Architecture (Decision)

Go's goroutine model makes the task queue decision fundamentally different from Python. The system does not need an external task queue framework for MVP.

**Architecture: single binary with embedded worker pool, cobra subcommands**

The CVErt Ops binary uses cobra for CLI subcommands:
- `cvert-ops serve` (default) — runs HTTP server + worker pool in one process. Suitable for self-hosted single-instance deployments.
- `cvert-ops worker` — runs standalone worker pool only. For SaaS scaling where API and workers run separately.
- `cvert-ops migrate` — runs pending database migrations and exits.

**Graceful shutdown:**
- On SIGTERM/SIGINT: stop accepting new HTTP requests and new jobs
- Wait for in-flight requests and jobs to complete (up to configurable deadline, default 60s via `SHUTDOWN_TIMEOUT_SECONDS`)
- After deadline: force exit; in-flight jobs are reclaimed by stale lock detection (worker heartbeat timeout)

The binary runs two logical components:
- **HTTP server** (goroutines managed by `net/http`)
- **Worker pool** (goroutines managed by an internal scheduler)

The worker pool processes jobs from a **Postgres-backed job queue** using `SELECT ... FOR UPDATE SKIP LOCKED`, which provides:
- reliable at-least-once delivery (jobs are claimed transactionally)
- retry with configurable backoff (failed jobs are re-enqueued with a `run_after` timestamp)
- dead-letter visibility (jobs exceeding max retries are moved to a dead-letter table)
- priority support (jobs have a `priority` column; workers poll highest priority first)
- concurrency control via optional `lock_key` + partial unique index (e.g., `lock_key='feed:nvd'`) to enforce max-1-concur**Job table (MVP):**
```sql
-- Decision: single-table queue with optional dedupe/lock semantics.
-- Status: pending -> running -> succeeded | dead
CREATE TABLE job_queue (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    queue        text NOT NULL,                -- 'feed_ingest', 'notify', 'report', 'cleanup'
    priority     int  NOT NULL DEFAULT 0,      -- higher = more urgent
    payload      jsonb NOT NULL,

    -- Optional lock/dedupe key used to constrain concurrency for a class of jobs.
    -- Examples:
    --   'feed:nvd', 'feed:mitre', 'cleanup:retention'
    lock_key     text NULL,

    status       text NOT NULL DEFAULT 'pending',  -- pending | running | succeeded | dead
    run_after    timestamptz NOT NULL DEFAULT now(),

    attempts     int  NOT NULL DEFAULT 0,
    max_attempts int  NOT NULL DEFAULT 3,

    locked_by    text NULL,                    -- worker ID
    locked_at    timestamptz NULL,

    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz NULL,
    last_error   text NULL
);

-- Fast polling of runnable jobs by queue/priority.
CREATE INDEX job_queue_runnable_idx
ON job_queue (queue, status, run_after, priority DESC);

-- Concurrency control: at most one RUNNING job per lock_key.
-- (NULL lock_key jobs are unconstrained.)
CREATE UNIQUE INDEX job_queue_lock_key_running_uq
ON job_queue (lock_key)
WHERE lock_key IS NOT NULL AND status = 'running';
```

### Decision D2 — Job queue concurrency model (MVP)

**Decision (MVP):** Use a **single Postgres job table** with `SELECT ... FOR UPDATE SKIP LOCKED`, plus an optional `lock_key` and partial unique index to enforce “max-1 running job per class” (e.g., one ingest job per feed).

**Considerations (multiple angles):**
- **Simplicity:** one table is easy to reason about, migrate, observe, and operate in self-hosted deployments.
- **Correctness:** `SKIP LOCKED` prevents double-claim; `lock_key` prevents accidental parallel ingest of the same feed.
- **Performance:** works well at moderate scale; Postgres can handle high job volumes if indexes are correct.
- **SaaS multi-instance:** safe across multiple API/worker instances because locking occurs in the DB.
- **Future extensibility:** if scale demands, you can replace/augment with Redis/Sidekiq-like systems later.

**Alternatives (revisit later):**
- Separate per-queue tables (more complexity, sometimes faster polling).
- External queue (Redis, NATS, SQS) for very high throughput.
- Advisory locks instead of partial unique index (more flexible; harder to inspect in DB).

ptz,
    last_error  text
);
```

**Worker goroutines:**
- One goroutine per queue type (configurable concurrency per queue).
- Each goroutine polls with `SKIP LOCKED`, processes the job, and updates status — all within a single transaction.
- Stale lock detection: a periodic goroutine reclaims jobs where `locked_at` exceeds a timeout (e.g., 5 min), to handle worker crashes.

**Why not an external queue for MVP:**
- No Redis dependency → simpler Docker Compose stack → better for self-hosted/homelab persona.
- Transactional consistency: a feed ingestion job can claim a job, write CVE data, and update the job status in the same transaction.
- Throughput ceiling of Postgres `SKIP LOCKED` is well above MVP needs (thousands of jobs/sec).
- If SaaS scaling demands exceed Postgres queue throughput, the `job_queue` table can be replaced with Redis/NATS without changing the worker goroutine structure — only the "claim next job" function changes.

### 18.2 HTTP Framework + OpenAPI Strategy (RESOLVED)

**Decision: huma + chi (code-first, OpenAPI 3.1)**

huma (`github.com/danielgtaylor/huma`, v2.37.1) wraps chi as the underlying router. Go types and handler definitions automatically generate an OpenAPI 3.1 specification served at `/openapi`.

**Why huma + chi:**
1. **OpenAPI 3.1 native** — future-proof; oapi-codegen only supports 3.0.x
2. **Automatic struct-tag validation** — `minLength`, `maxLength`, `format:"uuid"` validated without manual code; reduces security bugs
3. **RFC 9457 Problem Details** — modern structured error responses out of the box
4. **Chi middleware preserved** — huma wraps chi, so the full chi middleware ecosystem (20+ built-in, 100+ third-party) is available for auth, CORS, rate limiting, request ID
5. **Natural for Go development** — write Go code, not OpenAPI YAML; spec can never drift from code
6. **Go 1.26 compatible** — requires Go 1.25+ (satisfied)

**Alternative considered:** Spec-first with oapi-codegen + chi. Stronger contract enforcement but OpenAPI 3.0 only, more ceremony for a solo developer, and higher learning curve (OpenAPI YAML + generated code).

---

## 19. Research Decision Backlog (ALL RESOLVED)

All research decisions have been resolved. See `research.md` for detailed findings and rationale.

1) ~~OIDC/OAuth library selection~~ → **RESOLVED:** `coreos/go-oidc/v3` + `golang.org/x/oauth2`. MVP: email/password + GitHub + Google OAuth. See section 7.2.
2) ~~CWE dictionary ingestion~~ → **RESOLVED:** Full dictionary ingestion from MITRE CWE. See section 8.2.
3) ~~Postgres RLS for hosted mode~~ → **RESOLVED:** `SET LOCAL app.org_id` per-transaction; always enable RLS; implementation deferred to P1. See section 6.2.
4) ~~LLM vendor/model~~ → **RESOLVED:** Google Gemini (`google.golang.org/genai`). See section 13.4.
5) ~~HTTP framework + OpenAPI strategy~~ → **RESOLVED:** huma + chi (code-first, OpenAPI 3.1). See section 18.2.

---

## 19.1 Observability

**Logging:** `slog` (Go stdlib, zero dependencies). JSON output in production, text in dev. Go 1.26 adds `slog.NewMultiHandler()` for distributing to multiple destinations.

Context propagation: HTTP middleware adds `request_id`, `org_id`, `user_id` to request context. Custom slog handler extracts these and includes them in all downstream log records. Implement `slog.LogValuer` interface on types containing sensitive data to ensure redaction.

**Metrics:** `prometheus/client_golang` with `/metrics` endpoint from Phase 0. Expose:
- Go runtime metrics (goroutines, memory, GC)
- HTTP request latency/count per endpoint
- Feed ingestion items/errors per source
- Job queue depth and processing time
- Notification delivery success/failure counts

**Tracing:** Deferred to P1. Structured logs with request_id provide basic correlation for MVP.

## 19.2 Configuration

**Library:** `caarlos0/env/v10` for env var parsing + `go-playground/validator` for startup validation.

All configuration via environment variables (12-factor). Docker Compose `.env` files are the primary config surface for self-hosted deployments.

- Nested config structs supported (e.g., `SMTPConfig`, `DatabaseConfig`)
- Validation at startup via struct tags (`required`, `min`, `max`, `url`)
- Secret redaction: config types implement custom `String()` method that masks sensitive fields
- `.env.example` file in repo documents all available config vars with defaults and descriptions

## 19.3 Testing Strategy

- **Unit tests:** Table-driven tests for pure logic (merge rules, DSL compiler, validation). Mock HTTP responses (recorded fixtures) for feed adapter tests.
- **Integration tests:** `testcontainers-go` for ephemeral Postgres containers per test suite. Realistic database testing without a shared dev instance.
- **Pre-populated DB snapshots:** For tests that need feed data (alert evaluation, search, digests), load pre-built Postgres snapshots to avoid hitting real APIs and rate limits during CI.
- **Email testing:** Mailpit in docker-compose as a local SMTP trap for dev/test. Real SMTP configured via env vars for production.
- **CI pipeline:** GitHub Actions — lint (`golangci-lint`), vet (`go vet`), test (`go test` with testcontainers), vulnerability scan (`govulncheck`), build binary, build Docker image.
- **RBAC test matrix:** Integration tests must cover each role × each endpoint from the permission matrix (section 7.3).
- **RLS isolation tests (P1):** Verify cross-org isolation with RLS enabled (Org A creates data → Org B queries → 0 results).

## 19.4 Registration Mode

Configurable via `REGISTRATION_MODE` env var:
- `invite-only` (default): only org owners/admins can invite new members. Most secure for self-hosted security teams.
- `open`: anyone can register and create their own org. Suitable for SaaS or community instances.
- First user auto-becomes owner of a default org regardless of mode (preserves homelab single-user simplicity).

## 19.5 New Features (from Competitive Analysis)

### CVE Assignment (P1)
Add `assignee_user_id UUID REFERENCES users(id)` to `cve_annotations` table. Allows security teams to assign CVEs to team members for triage.
- Endpoint: `PATCH /api/v1/orgs/{org_id}/cves/{cve_id}/annotations` (set assignee, tags, notes, snooze state)
- Shows in digest emails and future dashboard widgets
- Inspired by OpenCVE's "assigned CVEs" feature

### Saved Searches
Reusable filter presets independent of alert rules. Users save search queries and share them within an org.
- Table: `saved_searches(id UUID PK, org_id UUID NOT NULL, user_id UUID NOT NULL, name TEXT NOT NULL, query_json JSONB NOT NULL, is_shared BOOLEAN DEFAULT false, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ)`
- Constraints: `UNIQUE(org_id, name)`
- Endpoints: `GET/POST /api/v1/orgs/{org_id}/saved-searches`, `GET/PATCH/DELETE /api/v1/orgs/{org_id}/saved-searches/{id}`
- `is_shared` flag controls org-wide visibility (respects RBAC: viewers can use shared searches, members can create their own, admins can manage all)

### Watchlist Bootstrap Templates
Pre-built watchlist templates that users can import during onboarding to reduce friction (inspired by OpenCVE's vendor/product auto-discovery).

Ship embedded preset watchlists (JSON files via `embed.FS`):
- **Web frameworks:** React, Angular, Vue, Django, Rails, Express, Spring, etc.
- **Databases:** PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, etc.
- **Container base images:** alpine, debian, ubuntu, node, python, golang, etc.
- **Language runtimes:** Node.js, Python, Go, Java, Rust, Ruby, PHP, etc.
- **Infrastructure:** Nginx, Apache, OpenSSL, Linux kernel, curl, etc.

Endpoints:
- `GET /api/v1/watchlist-templates` — list available templates (public, no auth required)
- `POST /api/v1/orgs/{org_id}/watchlists/from-template` — create a watchlist from a template

## 19.6 Project Layout

```
cvert-ops/
├── cmd/cvert-ops/        # cobra CLI (main.go, serve.go, worker.go, migrate.go)
├── internal/
│   ├── api/              # HTTP handlers + huma operations + middleware
│   ├── config/           # caarlos0/env config structs
│   ├── feed/             # Feed adapters (nvd, mitre, kev, osv, ghsa, epss)
│   ├── merge/            # CVE merge pipeline
│   ├── alert/            # Alert DSL compiler + evaluator
│   ├── notify/           # Notification channels + delivery
│   ├── auth/             # JWT, OAuth, API keys, argon2id
│   ├── worker/           # Job queue + goroutine pool
│   ├── search/           # FTS + facets
│   ├── report/           # Digest generation
│   ├── ai/               # LLMClient interface + Gemini adapter
│   ├── metrics/          # Prometheus counters/histograms
│   └── store/            # Repository layer (sqlc generated + squirrel dynamic)
├── migrations/           # SQL migration files (embedded via embed.FS)
├── templates/            # Notification + watchlist templates (embedded via embed.FS)
├── openapi/              # Exported OpenAPI spec (generated by huma)
├── research/             # Research decision docs
├── .github/workflows/    # GitHub Actions CI
├── compose.yml           # Dev stack (Postgres + Mailpit)
├── Dockerfile            # Multi-stage build → distroless:static-debian12
├── .env.example          # Documented env vars
├── go.mod / go.sum
├── PLAN.md
├── CLAUDE.md
├── research.md
└── README.md
```

---

## 20. Frontend (Deferred)

The MVP is **API-first**. This `plan.md` covers the backend: API, ingestion, alerting, notifications, and AI gateway. The web frontend is planned but **out of scope** for this document and the initial implementation phases (0–5).

### 20.1 Why Deferred
- The API contract (Appendix B) must stabilize before frontend work begins. Building the UI against a moving API wastes effort.
- The backend can be fully validated via API tests, CLI tools, and webhook/notification delivery without a UI.
- Self-hosted users and DevSecOps personas (the earliest adopters) are comfortable with API-only interaction.

### 20.2 Decisions Required Before Frontend Work Begins

These decisions are **not needed now** but are listed here so they are not forgotten:

| Decision | Options to evaluate | Notes |
|---|---|---|
| **Rendering strategy** | SPA (React/Vue + API calls) vs. server-rendered (Go templates + HTMX) vs. hybrid (Next.js) | Go + HTMX is appealing for simplicity (single binary serves both API and UI); SPA gives richer interactivity. |
| **Framework / library** | React, Vue, Svelte, HTMX | Evaluate based on team familiarity, component ecosystem, and SSR needs. |
| **Packaging** | Embedded in Go binary (`embed.FS`) vs. separate frontend container vs. static CDN | Embedding static assets in the Go binary is uniquely attractive: single binary = single Docker image = simplest self-hosted install. |
| **Open-source scope** | Full UI in open-source core vs. API-only OSS with UI in SaaS only | Business decision with community implications. |
| **Design system** | Tailwind + headless UI, shadcn/ui, custom | Affects velocity and consistency. |
| **Accessibility / browser support** | WCAG 2.1 AA target, evergreen browsers only, mobile-responsive | Should be decided before any UI code. |

### 20.3 Provisional Page Inventory

For future planning reference, the frontend will likely need at minimum:

- **Public:** Login / register, OAuth callback, password reset
- **CVE views:** Search/list (with facets + NL search bar), CVE detail (scores, affected packages, source comparison, AI summary), CVE timeline/history
- **Org management:** Org settings, member management, group management, billing (SaaS)
- **Watchlists:** List, create/edit, item management
- **Alert rules:** List, rule builder (visual DSL editor), alert event history
- **Notifications:** Channel configuration (SMTP, Slack, webhook), delivery log
- **Reports:** Scheduled report config, report viewer / digest preview
- **Admin:** Feed status dashboard, rerun/rebuild controls, audit log (Enterprise)

### 20.4 API Design Implications

Even though the frontend is deferred, the API should be designed with frontend consumption in mind:
- Pagination and filtering patterns should be consistent and UI-friendly (cursor-based, not offset).
- Error responses should include machine-readable codes suitable for i18n.
- Bulk operations (e.g., "add 50 packages to a watchlist") should be supported to avoid N+1 UI patterns.
- The OpenAPI spec should be the single source for both generated client types and eventual API documentation pages.

---

## 21. Data Retention & Cleanup Policy

### 21.1 Principle
Retention defaults should be generous enough to be useful out-of-the-box but bounded enough to prevent unbounded storage growth, especially for high-volume tables. All retention periods are configurable via org settings (within tier-allowed bounds) or global defaults for self-hosted.

### 21.2 Retention Defaults

| Data | Default retention | Tier override | Notes |
|---|---|---|---|
| `cves` (canonical records) | Indefinite | — | CVE records are never deleted; `rejected` CVEs are soft-flagged. |
| `cve_sources` | Indefinite | — | Needed for provenance and "show source differences." |
| `cve_raw_payloads` | 90 days | Enterprise: configurable (30–365 days) | Largest growth table. Cleanup job deletes rows older than threshold. |
| `feed_fetch_log` | 90 days | Enterprise: configurable | Operational/debug data; safe to prune. |
| `alert_events` | 1 year | Enterprise: configurable (90 days–indefinite) | Historical alert record. Older events are archived or deleted. |
| `notification_deliveries` | 90 days | Enterprise: configurable | Delivery log; useful for debugging. |
| `report_runs` | 1 year | Enterprise: configurable | Includes rendered report content. |
| `ai_usage_counters` | Indefinite (rolled up monthly) | — | Daily granularity retained for 90 days; monthly aggregates kept indefinitely for billing/audit. |

### 21.3 Cleanup Implementation

**Decision D3 — Retention cleanup batching strategy (MVP)**

**Decision (MVP):** Perform retention cleanup using **bounded batches via a CTE** (not `DELETE ... LIMIT`, which Postgres does not support), to avoid long transactions and reduce lock contention.

**Considerations (multiple angles):**
- **DB correctness:** Postgres requires a subquery/CTE to limit deletions deterministically.
- **Operational safety:** small batches reduce vacuum pressure, WAL spikes, and long-lived row locks.
- **Performance:** requires appropriate indexes on the timestamp column used for retention (e.g., `ingested_at`, `created_at`, `started_at`) to avoid sequential scans.
- **SaaS vs self-host:** SaaS needs predictable runtime; self-host may disable cleanup entirely.

**Implementation (required pattern):**
- A scheduled **retention cleanup job** runs daily (off-peak, configurable time) via the Postgres job queue (section 18.1), with `lock_key='cleanup:retention'` to prevent concurrent runs.
- The job processes one table at a time, deleting in bounded batches (default batch size: **10,000** rows).

Example (repeat until 0 rows deleted):
```sql
WITH doomed AS (
  SELECT id
  FROM cve_raw_payloads
  WHERE ingested_at < $1
  ORDER BY ingested_at
  LIMIT 10000
)
DELETE FROM cve_raw_payloads p
USING doomed
WHERE p.id = doomed.id;
```

**Required indexes (per table):**
- `cve_raw_payloads(ingested_at)`
- `notification_deliveries(created_at)` (or whichever timestamp drives retention)
- `feed_fetch_log(started_at)`
- `alert_rule_runs(started_at)`
- etc.

**Logging:**
- Log rows deleted per table per run to a dedicated `system_jobs_log` table (preferred) or reuse `feed_fetch_log` with a distinct `feed_name='system.retention'`.

**Config flags:**
- Self-hosted deployments can disable cleanup: `RETENTION_CLEANUP_ENABLED=false`
- Batch size and max runtime per run are configurable.

**Alternative (revisit later):**
- Partition large tables by time (monthly partitions) and `DROP PARTITION` for near-instant retention, at the cost of more complex migrations.


---

# Appendix A — Schema-First Plan (Models, Keys, Indexes, Migrations)

## A.1 Conventions
- **DB:** Postgres 15+  
- **PKs:** UUIDv4 for org-scoped (generated via `gen_random_uuid()`); `cve_id` (text) for CVEs
- **Times:** `timestamptz` UTC, default `now()`
- **JSON:** `jsonb`
- **Migrations:** `golang-migrate`; SQL migration files; one pair (up/down) per change.
- **Query codegen:** `sqlc` generates type-safe Go code from SQL queries. Queries are defined in `.sql` files with `sqlc` annotations.

## A.2 Global Tables (Core)

### `cves`
PK `cve_id text`. Key columns: `status`, `date_published`, `date_modified_source_max`, `date_modified_canonical`, `date_first_seen`, `description_primary`, `severity`, CVSS v3/v4 scores/vectors, `cwe_ids text[]`, `exploit_available`, `in_cisa_kev`, `epss_score`, `material_hash`, `fts_document`.
Indexes: `GIN(fts_document)`, BTREE on severity/kev/exploit, BTREE dates (including `date_modified_canonical`), `GIN(cwe_ids)`.

### `cve_sources`
PK `(cve_id, source_name)`. Columns: `normalized_json jsonb`, `source_date_modified`, `source_url`, `ingested_at`. Indexes: `source_name`, `source_date_modified`.

### `cve_raw_payloads`
PK `id uuid`. Columns: `cve_id`, `source_name`, `ingested_at`, `payload jsonb`. Index: `(cve_id, source_name, ingested_at desc)`.

### `cve_references`
PK `id uuid`. Columns: `cve_id`, `url`, `url_canonical`, `tags text[]`. Constraint: `UNIQUE(cve_id, url_canonical)`. Indexes: `cve_id`, `url_canonical`.

### `cve_affected_packages`
PK `id uuid`. Columns: `cve_id`, `ecosystem`, `package_name`, `namespace`, `range_type`, `introduced`, `fixed`, `last_affected`, `events jsonb`. Indexes: `(ecosystem, package_name)`, `cve_id`.

### `cve_affected_cpes`
PK `id uuid`. Columns: `cve_id`, `cpe`, `cpe_normalized`. Constraint: `UNIQUE(cve_id, cpe_normalized)`. Indexes: `cpe_normalized`, `cve_id`.


### `epss_staging`
Stores EPSS scores for CVE IDs not yet present in the corpus (see EPSS note in section 3.1). When a CVE is first created/merged, the merge pipeline applies any staged EPSS score and deletes the staging row.

- **PK:** `cve_id text`
- Columns: `epss_score double precision not null`, `as_of_date date not null`, `ingested_at timestamptz not null default now()`
- Indexes: `BTREE(ingested_at)`


### `feed_sync_state` / `feed_fetch_log`
See sections 3.3 and earlier schema notes.

### `system_jobs_log` (recommended)
Append-only log of internal system jobs (retention cleanup, index rebuilds, etc.). Useful when `feed_fetch_log` semantics feel too feed-specific.

- **PK:** `id uuid`
- Columns: `job_type text not null`, `started_at timestamptz not null`, `ended_at timestamptz null`, `status text not null`, `details jsonb null`, `error_summary text null`
- Indexes: `BTREE(job_type, started_at desc)`

### `job_queue`
See section 18.1 for full schema.

## A.3 Org/Tenant Tables (Core)
`organizations`, `users` (includes `password_hash_version int`), `user_identities`, `org_members` (includes `role`), `groups`, `group_members`, `watchlists` (includes `group_id` nullable), `watchlist_items`, `cve_annotations` (includes `assignee_user_id uuid` nullable), `alert_rules` (includes `watchlist_ids uuid[]`, `dsl_version int`), `alert_rule_runs`, `alert_events`, `notification_channels`, `notification_deliveries`, `scheduled_reports`, `report_runs`, `ai_usage_counters`, `saved_searches` (includes `query_json jsonb`, `is_shared boolean`).

## A.4 Migration Order
1) Global CVE tables + CWE dictionary + feed state/log + job_queue
2) Org/auth tables (including `user_identities`, `groups`, `group_members`, `password_hash_version`)
3) Watchlists + annotations (including `assignee_user_id`)
4) Saved searches
5) Alerts (including `dsl_version`, `watchlist_ids`)
6) Notifications
7) Reports
8) AI counters

---

# Appendix B — Endpoint Skeleton (API v1)

**Public / Global:**
- `GET /api/v1/healthz`
- `GET /api/v1/cves` — paginated search with filters/facets
- `GET /api/v1/cves/{cve_id}` — canonical detail
- `GET /api/v1/cves/{cve_id}/sources` — per-source comparison

**Admin (requires `admin` or `owner` role, or system-level API key):**
- `GET /api/v1/admin/feeds` — feed sync status
- `POST /api/v1/admin/feeds/{feed}/run` — trigger feed re-run

**Auth:**
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`
- `GET /api/v1/auth/oauth/{provider}`, `GET /api/v1/auth/oauth/{provider}/callback`

**Org management (role-gated per section 7.3):**
- `POST /api/v1/orgs` — create org
- `GET/PATCH /api/v1/orgs/{org_id}` — org settings
- `GET/POST /api/v1/orgs/{org_id}/members` — list/invite members
- `PATCH/DELETE /api/v1/orgs/{org_id}/members/{user_id}` — update role / remove
- `GET/POST /api/v1/orgs/{org_id}/groups`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/groups/{group_id}`
- `GET/POST/DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members`

**Watchlists:**
- `GET/POST /api/v1/orgs/{org_id}/watchlists`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/watchlists/{id}`
- `GET/POST/DELETE /api/v1/orgs/{org_id}/watchlists/{id}/items`

**Alert rules:**
- `GET/POST /api/v1/orgs/{org_id}/alert-rules`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/alert-rules/{id}`
- `POST /api/v1/orgs/{org_id}/alert-rules/validate` — syntax/schema validation without saving
- `POST /api/v1/orgs/{org_id}/alert-rules/{id}/dry-run` — run rule against current data without firing alerts
- `GET /api/v1/orgs/{org_id}/alert-rules/{id}/events` — alert history for a rule

**Notification channels:**
- `GET/POST /api/v1/orgs/{org_id}/channels`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/channels/{id}`
- `POST /api/v1/orgs/{org_id}/channels/{id}/test` — send test notification

**Reports:**
- `GET/POST /api/v1/orgs/{org_id}/reports`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/reports/{id}`

**API keys:**
- `GET/POST /api/v1/orgs/{org_id}/api-keys`
- `DELETE /api/v1/orgs/{org_id}/api-keys/{id}`

**Saved searches:**
- `GET/POST /api/v1/orgs/{org_id}/saved-searches`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/saved-searches/{id}`

**CVE annotations (including assignment):**
- `GET/PATCH /api/v1/orgs/{org_id}/cves/{cve_id}/annotations` — set assignee, tags, notes, snooze state

**Watchlist templates:**
- `GET /api/v1/watchlist-templates` — list available bootstrap templates (public)
- `POST /api/v1/orgs/{org_id}/watchlists/from-template` — create watchlist from template

**AI:**
- `POST /api/v1/orgs/{org_id}/ai/nl-search`
- `POST /api/v1/orgs/{org_id}/ai/summarize/{cve_id}` (P1)
