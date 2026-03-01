# Phase 4 Design — AI Gateway, NL Search, Summarization & Saved Searches

**Date:** 2026-02-28
**PLAN.md refs:** §13 (AI Features), §14 (Tiers/Quotas), §16.1 (AI Rate Limiting), §19.5 (Saved Searches), Appendix A (Schema), Appendix B (Endpoints)
**Phase 4 scope from §18:** "AI gateway + NL search — LLMClient interface + vendor adapter, NL → query JSON + execution, quotas + caching + metrics"

---

## 1. LLMClient Interface & Gemini Adapter

**Package:** `internal/ai/`

**Interface:**

```go
type LLMClient interface {
    GenerateStructuredQuery(ctx context.Context, prompt string) (json.RawMessage, error)
    Summarize(ctx context.Context, input CVESummaryInput) (string, error)
}
```

**Gemini adapter** (`google.golang.org/genai` SDK, selected per §13.4):

- `GenerateStructuredQuery` uses Gemini's **structured output mode** — a JSON schema matching the DSL `Rule` format is provided to the model, constraining it to produce conforming JSON. No JSON parsing failures.
- `Summarize` uses plain text generation. Model instance configured with **zero tool access** (no function calling, no code execution) per §13.4.
- Configurable timeout on all Gemini calls (default 30s, `GEMINI_TIMEOUT` env var).
- Existing config fields: `GEMINI_API_KEY`, `GEMINI_MODEL`.

**CI/testing support:** `GEMINI_MOCK=true` config swaps in a deterministic mock client returning canned responses, enabling CI without Gemini credentials.

### Prompt injection mitigations (Summarize)

Per §13.4 — CVE descriptions are attacker-controlled content:

- Strip markdown link syntax (`[text](url)`), HTML tags, and control characters from CVE text before sending to the LLM
- System prompt explicitly frames input as untrusted external content to be summarized, not instructions to be followed
- Context window: only structured CVE fields (cve_id, severity, scores, affected packages, CWE IDs) + sanitized description — never user session data, org context, or credentials

NL search has minimal injection risk: the user IS the one typing, Gemini's structured output constrains the response, and the DSL compiler validates the output before execution with parameterized SQL.

---

## 2. DSL Extension — FTS Operator

**Change:** Add a new field `fts_query` to the DSL field registry.

| Property | Value |
|----------|-------|
| Field name | `fts_query` |
| Kind | `fts` (new kind) |
| Operator | `matches` (single operator) |
| Value type | JSON string (search text) |
| SQL | JOIN `cve_search_index si ON c.cve_id = si.cve_id` + WHERE `si.fts_document @@ websearch_to_tsquery('english', $1)` |

**Compiler change:** The DSL compiler currently returns WHERE predicates only. It must also support optional JOINs. When the compiler encounters an `fts_query` field, it adds both the JOIN and the WHERE clause. The compiled output carries a `joins []string` alongside the existing predicates.

**Universal availability:** Adding `fts_query` to the field registry makes it available everywhere the DSL is used — NL search, alert rules, saved search execution, and dry-run validation. FTS in alert rules is a natural capability and GIN-indexed FTS queries are fast enough for the evaluator.

**Prompt integration:** The dynamic schema description generator (`BuildSchemaDescription()`) automatically picks up `fts_query` and describes it to the LLM. NL queries like "find CVEs mentioning buffer overflow" naturally map to `{"field": "fts_query", "operator": "matches", "value": "buffer overflow"}`.

---

## 3. NL Search Endpoint

**Endpoint:** `POST /api/v1/orgs/{org_id}/ai/nl-search`

**Request:**

```json
{ "query": "critical OpenSSL CVEs from the last 30 days with known exploits" }
```

- Max input length: 1000 characters (422 if exceeded).
- Auth: JWT or API key. Minimum role: viewer.

**Flow:**

1. **Quota check** — atomic increment on `ai_usage_counters(org_id, 'nl_search', today)`. If `AI_QUOTA_ENABLED=true` and returned count > limit, return 429 with reset time (next UTC midnight). Standard rate-limiter behavior: count the attempt, deny if over limit, no decrement on denial.
2. **Cache lookup** — compute `input_hash = sha256(query)`. Check `ai_cache` for `(org_id, 'nl_search', prompt_version, input_hash)` with `expires_at > now()`. On hit, skip to step 5.
3. **Build prompt** — system prompt built dynamically from `dsl.FieldRegistry` via `BuildSchemaDescription()`. Includes field names, valid operators per field, value types, enum values. Fields iterated in deterministic order (sorted by name) for stable `prompt_version = sha256(system_prompt)[:8]`.
4. **LLM call** — `LLMClient.GenerateStructuredQuery()` with system prompt + user query. Gemini structured output constrains response to valid DSL JSON.
5. **Validate + compile** — pass DSL JSON through the existing compiler. Catches invalid field/operator combos the schema constraint might miss. On compilation failure, return 422 ("couldn't interpret your query, try rephrasing").
6. **Execute** — compiled query runs against the CVE corpus via the same squirrel path as alert evaluation, extended with FTS JOIN support. Keyset-paginated with `cursor` + `limit` params.
7. **Log + cache** — write to `ai_request_log` (always). Write to `ai_cache` on cache miss.
8. **Infrastructure failure** — on Gemini network error/500, decrement the quota counter and return 503.

**Response:**

```json
{
  "interpreted_query": { /* DSL Rule JSON */ },
  "results": [ /* CVE objects */ ],
  "cursor": "...",
  "cached": true
}
```

`interpreted_query` enables transparency and powers the "save this search" client flow — the query JSON can be POSTed directly to saved searches.

---

## 4. CVE Summarization Endpoint

**Endpoint:** `POST /api/v1/orgs/{org_id}/ai/summarize/{cve_id}`

**Request:** No body — CVE ID in path.

**Flow:**

1. **Quota check** — atomic increment on `ai_usage_counters(org_id, 'summarize', today)`. Same enforcement logic as NL search.
2. **Fetch CVE** — load from store. 404 if not found.
3. **Cache lookup** — `input_hash = sha256(cve_id + material_hash)`. Cache is invalidated when the CVE content materially changes. Check `ai_cache` for `(org_id, 'summarize', prompt_version, input_hash)`.
4. **Sanitize** — strip markdown links, HTML tags, control characters from description and advisory text.
5. **Build input** — `CVESummaryInput` with structured fields only: cve_id, severity, CVSS scores, EPSS score, affected packages, CWE IDs, sanitized description.
6. **LLM call** — `LLMClient.Summarize()` with zero-tool-access model instance.
7. **Log + cache** — write to `ai_request_log` and `ai_cache`. Decrement quota on infrastructure failure.

**Response:**

```json
{
  "cve_id": "CVE-2024-1234",
  "summary": "...",
  "model": "gemini-2.0-flash",
  "cached": true
}
```

---

## 5. Caching — `ai_cache` Table

```sql
CREATE TABLE ai_cache (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES orgs(id),
    feature        TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    input_hash     TEXT NOT NULL,
    response       JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX ai_cache_lookup_idx
    ON ai_cache (org_id, feature, prompt_version, input_hash);
```

- **TTLs:** NL search = 1 hour (CVE data changes frequently). Summarize = 24 hours (keyed to material_hash).
- **Cleanup:** daily periodic job — `DELETE FROM ai_cache WHERE expires_at < now()`.
- **Write behavior:** `INSERT ... ON CONFLICT DO UPDATE SET response = EXCLUDED.response, expires_at = EXCLUDED.expires_at` — refreshes TTL on repeated queries.
- **Cache miss fallthrough:** if the cache lookup query fails (DB error), fall through to the LLM call. Cache is optimization, not critical path.
- RLS policy on `org_id`.

**Note on per-org caching:** the cache key includes `org_id` per §13.4. For NL search and summarization on global CVE data, this means identical queries from different orgs produce duplicate cache entries. This is the safe default — prevents cross-org leakage if org-specific prompt context is added later. The cost is redundant LLM calls, acceptable at MVP scale.

---

## 6. Quota Enforcement

### `ai_usage_counters` table

```sql
CREATE TABLE ai_usage_counters (
    org_id        UUID NOT NULL REFERENCES orgs(id),
    feature       TEXT NOT NULL,
    date          DATE NOT NULL DEFAULT CURRENT_DATE,
    count         INT NOT NULL DEFAULT 0,
    input_tokens  INT NOT NULL DEFAULT 0,
    output_tokens INT NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, feature, date)
);
```

**Increment (atomic, single statement):**

```sql
INSERT INTO ai_usage_counters (org_id, feature, date, count, input_tokens, output_tokens)
VALUES ($1, $2, CURRENT_DATE, 1, 0, 0)
ON CONFLICT (org_id, feature, date)
DO UPDATE SET count = ai_usage_counters.count + 1
RETURNING count;
```

The RETURNING clause gives the new count for limit checking in one round-trip. Token counts are updated in a separate statement after the LLM call returns (tokens aren't known at request time).

**Monthly aggregation:** computed on the fly via `SUM(count) WHERE date >= month_start`. No denormalized monthly rollup column — avoids sync complexity for a Phase 5 billing concern.

### `ai_quota_overrides` table

```sql
CREATE TABLE ai_quota_overrides (
    org_id      UUID NOT NULL REFERENCES orgs(id),
    feature     TEXT NOT NULL,
    daily_limit INT NOT NULL,
    PRIMARY KEY (org_id, feature)
);
```

### Limit resolution

Precedence: per-org override > tier default (config) > hardcoded fallback.

### Config

| Env var | Default | Notes |
|---------|---------|-------|
| `AI_QUOTA_ENABLED` | `true` | When false, counters increment but limits aren't enforced. Self-hosters disable this. |
| `AI_NL_SEARCH_LIMIT_FREE` | 10 | Per §14 |
| `AI_NL_SEARCH_LIMIT_PRO` | 100 | Per §14 |
| `AI_NL_SEARCH_LIMIT_ENTERPRISE` | 1000 | Per §14 |
| `AI_SUMMARIZE_LIMIT_FREE` | 5 | Not specified in §14; reasonable default |
| `AI_SUMMARIZE_LIMIT_PRO` | 50 | |
| `AI_SUMMARIZE_LIMIT_ENTERPRISE` | 500 | |

### CLI command

`cvert-ops quota` subcommand, direct DB connection (bypasses RLS, like `migrate`):

- `cvert-ops quota set --org <id> --feature nl_search --limit 500`
- `cvert-ops quota get --org <id>`
- `cvert-ops quota list`
- `cvert-ops quota delete --org <id> --feature nl_search`

### Failure handling

- **Quota denial:** return 429. Count stays incremented (attempt was made). No decrement.
- **LLM infrastructure failure:** decrement count, return 503. User isn't charged for our infra problems.
- **Concurrent race:** two simultaneous requests can both pass the check (count goes from 9→10 and 9→11). At daily quotas of 10-1000, one extra request slipping through is negligible. Standard rate-limiter behavior.

### Future

Platform admin role + admin API for managing overrides (not Phase 4).

---

## 7. Saved Searches

### Schema

Per §19.5, refined with `nl_query` column and `ON DELETE SET NULL`:

```sql
CREATE TABLE saved_searches (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES orgs(id),
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    name       TEXT NOT NULL,
    query_json JSONB NOT NULL,
    nl_query   TEXT,
    is_shared  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);
```

- **No unique constraint on name** — UUID is the identifier, name is a label. Avoids friction for both private and shared searches.
- **`user_id ON DELETE SET NULL`** — org-scoped searches survive user deletion with null attribution.
- **Orphan cleanup:** before deleting a user, `DELETE FROM saved_searches WHERE user_id = $1 AND is_shared = false`. Private searches are removed; shared searches gracefully go to `SET NULL`.
- **`nl_query`** — nullable. Stores the original NL text when created from NL search. Display-only ("Created from: 'critical OpenSSL CVEs with known exploits'").
- **Soft-delete** via `deleted_at`.
- RLS policy on `org_id`.

### RBAC

| Action | Private (is_shared=false) | Org-scoped (is_shared=true) |
|--------|--------------------------|----------------------------|
| Create | member+ | member+ (set is_shared=true) |
| Read/List | creator only | anyone in org (viewer+) |
| Update | creator only | creator + admin/owner |
| Delete | creator only | creator + admin/owner |

Orphaned shared searches (`user_id = NULL`): only admin/owner can modify or delete.

### Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/orgs/{org_id}/saved-searches` | List. Filters: `visibility` (private/shared/all). |
| POST | `/api/v1/orgs/{org_id}/saved-searches` | Create. |
| GET | `/api/v1/orgs/{org_id}/saved-searches/{id}` | Get. |
| PATCH | `/api/v1/orgs/{org_id}/saved-searches/{id}` | Update. Pointer-type fields per §16 PATCH pattern. |
| DELETE | `/api/v1/orgs/{org_id}/saved-searches/{id}` | Soft-delete. |
| POST | `/api/v1/orgs/{org_id}/saved-searches/{id}/execute` | Compile query_json via DSL, return paginated CVE results. Accepts `cursor` + `limit` query params. |

---

## 8. Request Logging — `ai_request_log` Table

```sql
CREATE TABLE ai_request_log (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES orgs(id),
    user_id        UUID NOT NULL,
    feature        TEXT NOT NULL,
    input_hash     TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    model          TEXT NOT NULL,
    cache_hit      BOOLEAN NOT NULL,
    input_tokens   INT,
    output_tokens  INT,
    latency_ms     INT NOT NULL,
    status         TEXT NOT NULL,
    error_type     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- RLS policy on `org_id`.
- **No sensitive data stored:** no raw query text, no CVE content, no LLM response. `input_hash` allows correlation with cache entries.
- **`user_id` is NOT a FK** — avoids cascade complexity; log survives user deletion as an audit record.
- **Full detail at slog debug level:** query text, DSL output, summary content logged ephemerally for operators who need it. Piped to whatever log collector the operator uses.
- **Retention:** 90-day cleanup job — `DELETE FROM ai_request_log WHERE created_at < now() - interval '90 days'`. Runs alongside cache cleanup.

---

## 9. Prometheus Metrics

Extending the existing `/metrics` endpoint:

| Metric | Type | Labels |
|--------|------|--------|
| `cvertops_ai_requests_total` | Counter | `feature`, `status` |
| `cvertops_ai_request_duration_seconds` | Histogram | `feature` |
| `cvertops_ai_cache_hits_total` | Counter | `feature` |
| `cvertops_ai_cache_misses_total` | Counter | `feature` |
| `cvertops_ai_quota_denials_total` | Counter | `feature` |
| `cvertops_ai_tokens_total` | Counter | `feature`, `direction` (input/output) |

No `org_id` label — high cardinality risk. Per-org usage is queryable from `ai_usage_counters` and `ai_request_log`.

---

## 10. Migrations

Four migrations, one per logical domain:

| Migration | Tables | Notes |
|-----------|--------|-------|
| 000020 | `ai_usage_counters`, `ai_quota_overrides` | Quota domain. Both org-scoped + RLS. |
| 000021 | `ai_cache` | Caching domain. Org-scoped + RLS. Unique index on lookup key. |
| 000022 | `ai_request_log` | Logging domain. Org-scoped + RLS. Index on `(org_id, created_at)` for retention cleanup. |
| 000023 | `saved_searches` | Search domain. Org-scoped + RLS. Soft-delete. |

All tables: standard RLS policies (`org_id = current_setting('app.org_id')::uuid`), `FORCE ROW LEVEL SECURITY`, btree index on `org_id`.

---

## 11. Dependencies on Phase 3b

Phase 4 has no hard dependencies on Phase 3b completion. The one connection point:

- `DigestTemplateData.AISummary` field already exists in the template data structs (Phase 3b). Phase 4's summarization could eventually feed digest emails, but that integration is not in Phase 4 scope — it would be wired when both phases are complete.

Phase 4 can be implemented in parallel with remaining Phase 3b work.

---

## 12. Future Items (Not Phase 4)

- **Platform admin role** — `platform_admin` flag or table, with admin API for quota management, org management, and system configuration. Required for SaaS operation. Phase 5.
- **Redis-backed rate limiting** — for multi-instance SaaS deployment. Phase 5.
- **Data retention automation** — ai_request_log and ai_usage_counters integrated with §21 retention policies. Phase 5.
