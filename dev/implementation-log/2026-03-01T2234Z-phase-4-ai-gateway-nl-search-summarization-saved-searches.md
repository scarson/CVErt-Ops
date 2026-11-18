# Phase 4 — AI Gateway, NL Search, Summarization & Saved Searches

> **Dates:** 2026-03-01
> **Branch:** `dev`
> **Commits:** `8464e6d`–`89dfa49` (migrations), `d7eaed4` (config), `3c4a8ad` (DSL extension), `619da89`–`c8b0215` (ai package + metrics), `681881c`–`64bbc8b` (store), `b30caf1`–`148be86` (ai + DSL executor), `014eda7` (CLI), `3130316`–`044c71e` (api handlers), `5e0d526` (wiring), `b7a8459` (audit fixes), `2c5885d`–`914540c` (test coverage), `9ac07e7` (code review remediation)
> **Deliverables:** Migrations 000020–000024, `internal/ai` package, NL search & summarize handlers, saved search CRUD, Gemini adapter, quota/cache/logging system, Prometheus metrics, `quota` CLI command

## Files created / modified

| File | Purpose |
|---|---|
| `migrations/000020_create_ai_quota_tables.{up,down}.sql` | `ai_usage_counters`, `ai_quota_overrides` |
| `migrations/000021_create_ai_cache.{up,down}.sql` | `ai_cache` with unique index on `(org_id, feature, prompt_version, input_hash)` |
| `migrations/000022_create_ai_request_log.{up,down}.sql` | `ai_request_log` (audit log, `user_id` NOT a FK — survives user deletion) |
| `migrations/000023_create_saved_searches.{up,down}.sql` | `saved_searches` (soft-delete, `user_id ON DELETE SET NULL`) |
| `migrations/000024_saved_searches_constraints.{up,down}.sql` | Partial unique index on name, CHECK on nl_query length |
| `internal/ai/ai.go` | `LLMClient` interface, `GenerateResult`, `SummarizeResult`, `CVESummaryInput` types |
| `internal/ai/gemini.go` | `GeminiClient` — structured output for NL search, zero-tool-access for summarize, temp 0/0.2 |
| `internal/ai/schema.go` | `BuildSchemaDescription()` + `PromptVersion()` with `sync.Once` caching, SHA-256 prompt versioning |
| `internal/ai/mock.go` | `MockClient` with `Err` field for failure injection |
| `internal/ai/sanitize.go` | `Sanitize()` — strip markdown links, HTML tags, control chars |
| `internal/ai/quota.go` | `TierLimits`, `ResolveLimit()` (override > tier > free fallback) |
| `internal/metrics/ai.go` | 6 Prometheus counters/histograms for AI requests, cache, quotas, tokens |
| `internal/store/ai.go` | 13 store methods for quota, cache, and request log operations |
| `internal/store/saved_search.go` | Saved search CRUD with visibility filtering |
| `internal/store/dsl_executor.go` | `ExecuteDSLQuery` — shared between NL search, saved search execute, and future uses; handles FTS JOINs, keyset pagination, `limit+1` trick |
| `internal/alert/dsl/field.go` | `fts_query` field with `matches` operator for full-text search; `ExportFieldDescriptions()` |
| `internal/api/ai.go` | `nlSearchHandler`, `summarizeHandler`, `parseIntParam`, `isValidCVEID`, `truncateForLog` |
| `internal/api/saved_searches.go` | Full CRUD + execute endpoint, RBAC via `canModifySavedSearch()` |
| `cmd/cvert-ops/main.go` | LLM client init, `SetAIDeps` wiring, AI cleanup tickers, `expectedSchemaVersion = 24` |
| `cmd/cvert-ops/quota.go` | `quota` CLI subcommand for managing per-org overrides |

## Key implementation decisions

**`GenerateResult`/`SummarizeResult` wrap response + token counts.** Enriched beyond design doc to avoid a second call to get token counts from the same response object.

**`sync.Once` for schema description.** `BuildSchemaDescription()` and `PromptVersion()` computed once per process. Deterministic output (fields sorted by name) ensures stable SHA-256 `prompt_version` for cache key stability.

**DSL compiler extended with `Joins []string`.** `CompiledRule` gained a `Joins` field. `ExecuteDSLQuery` iterates `compiled.Joins` and calls squirrel `.Join()` for each. The `fts_query` field generates `JOIN cve_search_index si ON c.cve_id = si.cve_id`. FTS available universally wherever DSL is compiled.

**`ExecuteDSLQuery` queries `s.db` directly (no org transaction).** The `cves` table is global, unscoped, no RLS. Shared `cveColumns` and `scanCVERow` prevent column-order drift with `SearchCVEs`.

**Quota: increment-before-call, decrement-on-infra-failure.** Count increments atomically before LLM call. On Gemini network/500 errors, `DecrementAIUsage` called and 503 returned. Over-quota races accepted as negligible.

**Cache is non-critical-path.** `GetAICache` and `PutAICache` failures logged but do not abort the request.

**Per-org cache keys.** Prevents cross-org leakage if org-specific context added to prompts later.

**Summarize cache key = `cve_id + material_hash`.** Auto-invalidates when CVE content materially changes.

**Summarize uses `FunctionCallingConfigModeNone`.** Prevents prompt injection via attacker-controlled CVE descriptions from enabling Gemini tool use.

**Temperature 0 for NL search, 0.2 for summarize.** Deterministic for cache hit rates vs. natural language variance.

**Tier resolution hardcoded to "free".** No `tier` column on `orgs` yet. Wired but dormant until Phase 5.

**RBAC for saved searches is application-layer.** RLS enforces org isolation; private-vs-shared enforced in handler via `canModifySavedSearch()`.

## Gotchas discovered

- **Table name is `ai_request_log` (singular)** — used `ai_request_logs` in test SQL queries, causing `relation does not exist` errors.
- **`toNullInt32(0)` maps zero to NULL** — intentional to distinguish "not measured" from "measured zero" in request log.
- **`hasBlockingErrors` needed, not `len(valErrs) > 0`** — DSL validator distinguishes warnings from blocking errors.
- **`genai.Schema{}` (empty) for polymorphic `value` field** — specifying a type would break number/boolean condition values.
- **`ai_request_log.user_id` is NOT a FK** — log survives user deletion as audit record.
- **`dsl_executor.go` column list must stay in sync with `cve.go`** — main fragility point of shared `scanCVERow`.
- **`CleanupOrphanedPrivateSavedSearches` uses `bypassTx`** — must operate across all orgs for a given user.
- **MockClient `OutputTokens` values** — `GenerateStructured` returns 20, `Summarize` returns 25. Test expectations must match.

## Test coverage

| Test file | New tests | Coverage |
|---|---|---|
| `internal/api/ai_test.go` | 17 | NL search success/empty/long/quota/cache/LLM-failure/unauth/1000-char boundary, summarize success/not-found/invalid-id/quota/cache/LLM-failure/unauth, token persistence, parseIntParam (9 subtests) |
| `internal/api/saved_searches_test.go` | 12+ | CRUD, execute, RBAC (viewer create, shared modify, private access), cross-org isolation, name/nl_query length validation, patch validation |
| `internal/notify/worker_test.go` | 1 | AI cleanup retention gate |

## Quality check results

**plan-audit (§13, §14, §19.5):** Found missing RBAC alignment, Gemini tool access, validation gaps. All fixed in `b7a8459`.
**security-review:** Found CVE ID format bypass (no validation), log truncation missing. Fixed.
**pitfall-check:** Found `ai_cache` upsert missing `IS DISTINCT FROM`. Fixed.
**Test coverage audit (2 rounds):** Round 1 found 8 gaps (CVE ID validation, saved search limits, retention gate, token persistence, invalid CVE format). Round 2 found 6 more (LLM failure paths, unauth access, 1000-char boundary, parseIntParam). All addressed in commits `2c5885d` and `914540c`.
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.

## Code review remediation (`9ac07e7`)

Full code review of Phase 4 (`163c6a0..914540c`) identified 2 Important and 3 Minor issues. All addressed:

| ID | Severity | Finding | Fix |
|---|---|---|---|
| I-1 | Important | `saved_searches_name_uq` scoped to `(org_id, name)` — contradicts design doc's per-user uniqueness | Changed to `(org_id, user_id, name)` in migration 000024 |
| I-2 | Important | `ListSavedSearches` returns unbounded result set | Added `LIMIT @result_limit::int` to sqlc query, handler validates 1–200 (default 200) |
| M-1 | Minor | `SearchCVEs` uses `c.*` while `ExecuteDSLQuery` uses `cveColumns` — column drift risk | Changed `SearchCVEs` to use shared `cveColumns` slice |
| M-2 | Minor | Quota consumed on cache hits (cache hits are free — no LLM API cost) | Moved cache check before quota in both NL search and summarize handlers |
| M-3 | Minor→Important | `NewGeminiClient` makes network call at startup — blocks startup if Gemini unreachable | Rewrote to lazy initialization with `sync.Mutex`; `getClient(ctx)` creates underlying client on first use, retries automatically on failure |

**M-2 testing implication:** Quota exhaustion tests now use unique inputs per request (unique query strings for NL search, unique CVE IDs for summarize) to prevent cache hits from silently not consuming quota.

**M-3 design principle:** No external networking dependencies in the critical startup path. Self-hosters may not use AI features or may block outbound Gemini traffic. Application startup must depend only on local resources (config, database, filesystem).

## Open items for Phase 5

- [x] Tier enforcement (org tiers, tier-gated quotas — currently hardcoded to "free") — completed in Phase 5A
- [x] Data retention automation (ai_request_log, ai_usage_counters integrated with §21 policies) — completed in Phase 5B
- [ ] AI summary execution in digests (field plumbed, no LLM call yet)
- [ ] Burst/rate limiting on AI endpoints (per-minute, complementing daily quotas)
- [ ] CVE enumeration defense (predictable sequential IDs in summarize path)
