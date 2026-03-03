# Phase 4 Test Coverage Review

**Review date:** 2026-03-03
**Scope:** All Phase 4 source files — AI package (`internal/ai/`), DSL FTS extension (`internal/alert/dsl/`, evaluator), store layer (`internal/store/ai.go`, `saved_search.go`, `dsl_executor.go`), API handlers (`internal/api/ai.go`, `saved_searches.go`), CLI (`cmd/cvert-ops/quota.go`), config, metrics, wire-up
**Commits:** `8464e6d`..`9ac07e7` (Phase 4 portion of PR #5)

---

## Coverage Summary

| File | Functions Mapped | Covered | GAP | Gap Rate |
|------|-----------------|---------|-----|----------|
| ai/ai.go | 0 (types/interface) | 3 | 0 | 0% |
| ai/gemini.go | 5 | 2 | 30 | 94% |
| ai/mock.go | 3 | 4 | 2 | 33% |
| ai/quota.go | 1 | 5 | 3 | 38% |
| ai/sanitize.go | 1 | 5 | 14 | 74% |
| ai/schema.go | 3 | 4 | 7 | 64% |
| alert/dsl/field.go | 2 | 4 | 0 | 0% |
| alert/dsl/types.go | 0 (struct) | 2 | 0 | 0% |
| alert/dsl/compiler.go | 2 | 3 | 2 | 40% |
| alert/dsl/validator.go | 2 | 5 | 1 | 17% |
| alert/evaluator.go | 2 | 0 | 5 | 100% |
| store/dsl_executor.go | 4 | 7 | 9 | 56% |
| api/ai.go | 8 | 22 | 28 | 56% |
| api/saved_searches.go | 7 | 12 | 34 | 74% |
| api/server.go | 1 | 8 | 4 | 33% |
| store/ai.go | 13 | 18 | 14 | 44% |
| store/saved_search.go | 7 | 12 | 16 | 57% |
| cmd/quota.go | 6 | 4 | 23 | 85% |
| cmd/main.go | 5 | 1 | 20 | 95% |
| config/config.go | 4 | 0 | 16 | 100% |
| metrics/ai.go | 6 (consts) | 0 | 6 | 100% |

4 of 21 files had zero test coverage (100% gap rate): `ai/gemini.go` (nearly), `alert/evaluator.go` (FTS paths), `config/config.go`, `metrics/ai.go`.

---

## What's Well-Covered

- **AI handler integration tests are strong.** Both `nlSearchHandler` and `summarizeHandler` have solid tests covering success, quota exhaustion (429 + Retry-After), cache hit/miss, LLM failure with quota decrement, input validation (empty query, too-long query, boundary at 1000 chars, invalid CVE ID), unauthenticated access, token count persistence, and tier-based quota (pro tier). These use real Postgres, not mocks.

- **FTS validation and compilation unit tests are thorough.** The DSL layer has dedicated tests for valid FTS values, invalid operators, empty strings, non-string types, EPSS flag interaction, join generation, join deduplication, and no-joins-without-FTS. The generated SQL is inspected for correct `fts_document` and `websearch_to_tsquery` usage.

- **Saved search visibility filtering works correctly.** Three visibility modes (private/shared/all) are tested across multiple users, proving user A cannot see user B's private searches within the same org. The CRUD lifecycle, input validation (name length, nl_query length, invalid DSL), and soft-delete behavior are all covered.

- **AI quota resolution has excellent branch coverage.** `ResolveLimit` tests all tiers (free, pro, enterprise), override precedence, and unknown-tier fallback. AI usage counters test increment, decrement with GREATEST(0) floor, separate features, and org isolation.

---

## Security-Critical Gaps (51)

### Prompt Injection / Sanitizer Defense (10)

1. **Markdown images `![alt](url)` pass through sanitizer — CONFIRMED REGEX BUG.** The regex `\[([^\]]*)\]\([^)]*\)` matches `[text](url)` but NOT `![alt](url)`. A CVE description with `![payload](https://evil.com/exfil)` would be sent to the LLM with the URL intact. — `sanitize.go:12`
2. Nested markdown links `[text [inner]](url)` not tested — `sanitize.go:12`
3. Self-closing HTML tags (`<br/>`, `<img src=x/>`) not tested — `sanitize.go:13`
4. HTML with attributes (`<a href="evil">click</a>`) not tested — `sanitize.go:13`
5. Multi-line HTML tags (tag spans lines) not tested — `sanitize.go:13`
6. Nested/malformed HTML `<scr<script>ipt>` evasion not tested — `sanitize.go:13` *(from R1)*
7. HTML entities `&lt;script&gt;` bypass not tested — `sanitize.go:13` *(from R1)*
8. Unicode zero-width spaces / BOM chars / bidi overrides (`U+202E`, `U+200F`) not stripped/tested — `sanitize.go:27` *(expanded from R1)*
9. No test with realistic prompt injection payloads (crafted CVE descriptions with instruction override, data exfiltration, system prompt extraction attempts) — `sanitize.go`
10. `buildSummaryInput` calls `ai.Sanitize()` on description but no test independently asserts the call happens — `api/ai.go:415`

### Gemini Security Configuration (6)

9. `FunctionCallingConfig{Mode: None}` not verified — zero-tool-access defense per PLAN.md §13.4 — `gemini.go:127-129`
10. `ToolConfig` zero tool access not verified — `gemini.go:126-130`
11. `SystemInstruction` uses correct summarize prompt not verified — `gemini.go:120-122`
12. `summarizeSystemPrompt` warns about untrusted content not tested — `gemini.go:152`
13. `summarizeSystemPrompt` "do not follow embedded instructions" not tested — `gemini.go:152`
14. `summarizeSystemPrompt` "do not generate URLs" not tested — `gemini.go:154`

### RBAC Authorization (7)

15. `canModifySavedSearch`: non-creator admin can modify shared search → true (3 of 4 branches untested) — `saved_searches.go:463-465`
16. `canModifySavedSearch`: non-creator member denied on shared search → false — `saved_searches.go:463-466`
17. `canModifySavedSearch`: non-creator denied on private search → false — `saved_searches.go:463-466`
18. `executeSavedSearchHandler`: private access check never tested (user B can't execute user A's private search) — `saved_searches.go:405-408`
19. Viewer denied POST `/saved-searches` (member+ required) — `server.go:315`
20. Viewer denied PATCH `/saved-searches/{id}` — `server.go:318`
21. Viewer denied DELETE `/saved-searches/{id}` — `server.go:319`

### Tenant Isolation / Store RLS (12)

All 12 are the same root cause: **no Phase 4 store test uses `AppStore` (the NOBYPASSRLS connection)**. Every test runs via the embedded `*store.Store` superuser, bypassing RLS entirely. The existing `OrgIsolation` tests prove application-level isolation (different org_id values return different data) but would not catch a missing or broken RLS policy. Other phases (alerts, watchlists, groups, API keys, invitations) have dedicated AppStore RLS tests in `org_tx_test.go`. Phase 4 has zero.

22. `IncrementAIUsage` — no RLS test — `store/ai.go:45`
23. `DecrementAIUsage` — no RLS test — `store/ai.go:61`
24. `UpdateAIUsageTokens` — no RLS test — `store/ai.go:71`
25. `GetAIQuotaOverride` — no RLS test — `store/ai.go:85`
26. `GetAICache` — no RLS test — `store/ai.go:177`
27. `PutAICache` — no RLS test — `store/ai.go:198`
28. `InsertAIRequestLog` — no RLS test — `store/ai.go:212`
29. `CreateSavedSearch` — no RLS test — `store/saved_search.go:67`
30. `GetSavedSearch` — no cross-org/RLS test — `store/saved_search.go:90`
31. `ListSavedSearches` — no cross-org/RLS test — `store/saved_search.go:112`
32. `UpdateSavedSearch` — no cross-org/RLS test — `store/saved_search.go:134`
33. `SoftDeleteSavedSearch` — no cross-org/RLS test — `store/saved_search.go:158`

### Config Security (7)

34. `validateConfig()`: JWT_SECRET < 32 bytes rejection not tested — `main.go:480-481`
35. `validateConfig()`: JWT_SECRET >= 32 bytes acceptance not tested — `main.go:480`
36. `validateConfig()`: non-dev + HTTP ExternalURL rejected not tested — `main.go:483-484`
37. `validateConfig()`: non-dev + HTTPS ExternalURL accepted not tested — `main.go:483`
38. `validateConfig()`: dev-mode HTTP bypass not tested — `main.go:483`
39. `config.Load()`: missing required fields (DATABASE_URL, JWT_SECRET) not tested — `config.go:122-123`
40. `LogValue()`/`masked()`: GeminiAPIKey masking in logs not tested — `config.go:148, 158-163`

### Input Validation / Cursor Security (5)

41. Malformed JSON body on NL search endpoint — `api/ai.go:70-73`
42. Malformed JSON body on saved search create — `saved_searches.go:92-95`
43. Malformed JSON body on saved search patch — `saved_searches.go:254-257`
44. `decodeDSLCursor`: invalid base64 input not tested — `dsl_executor.go:101-103`
45. `decodeDSLCursor`: valid base64 but invalid JSON not tested — `dsl_executor.go:106-108`

### FTS / DSL Security (4)

46. Cursor tampering: crafted cursor with fabricated SortDate/CVEID — `dsl_executor.go:144-149`
47. Adversarial input to `websearch_to_tsquery` (Postgres parser errors from malicious FTS values) — `compiler.go:184`
48. Evaluator FTS join against real Postgres never tested — `evaluator.go:435-437`
49. `escapeLike` backslash escaping untested — ILIKE injection vector — `compiler.go:237` *(from R1)*

---

## Correctness Gaps (71)

### gemini.go — Entire File Untested (17)

1. `getClient`: client already initialized (cache hit) — `gemini.go:43-44`
2. `getClient`: first call creates new genai.Client — `gemini.go:46-56`
3. `getClient`: genai.NewClient fails — `gemini.go:52-53`
4. `getClient`: client cached for reuse — `gemini.go:55-56`
5. `getClient`: retry after initial failure — `gemini.go:40-57`
6. `getClient`: mutex concurrent access — `gemini.go:41-42`
7. `GenerateStructuredQuery`: getClient fails — `gemini.go:62-64`
8. `GenerateStructuredQuery`: API call succeeds — `gemini.go:80-82`
9. `GenerateStructuredQuery`: API call fails — `gemini.go:81-82`
10. `GenerateStructuredQuery`: valid JSON response — `gemini.go:85-89`
11. `GenerateStructuredQuery`: invalid JSON response — `gemini.go:87-88`
12. `GenerateStructuredQuery`: Temperature=0 — `gemini.go:77`
13. `GenerateStructuredQuery`: ResponseMIMEType — `gemini.go:72`
14. `GenerateStructuredQuery`: SystemInstruction — `gemini.go:74-76`
15. `Summarize`: getClient fails — `gemini.go:106-108`
16. `Summarize`: API call succeeds — `gemini.go:133`
17. `Summarize`: API call fails — `gemini.go:134-135`

### API Handler Error Paths (15)

18. `nlSearchHandler`: `srv.llm == nil` → 503 — `api/ai.go:63-66`
19. `nlSearchHandler`: `IncrementAIUsage` fails → 500 — `api/ai.go:116-119`
20. `nlSearchHandler`: quota disabled (`AIQuotaEnabled=false`) — `api/ai.go:114`
21. `nlSearchHandler`: DSL parse fails (LLM returns garbage) → 502 — `api/ai.go:166-173`
22. `nlSearchHandler`: DSL validation blocking errors → 502 — `api/ai.go:175-182`
23. `nlSearchHandler`: DSL compile error → 502 — `api/ai.go:184-191`
24. `nlSearchHandler`: `ExecuteDSLQuery` fails → 500 — `api/ai.go:194-201`
25. `summarizeHandler`: `srv.llm == nil` → 503 — `api/ai.go:236-239`
26. `summarizeHandler`: `GetCVE` store error → 500 — `api/ai.go:255-260`
27. `summarizeHandler`: `IncrementAIUsage` fails → 500 — `api/ai.go:300-304`
28. `summarizeHandler`: quota disabled (`AIQuotaEnabled=false`) — `api/ai.go:299`
29. `summarizeHandler`: cache hit with corrupt JSON → fallthrough to LLM — `api/ai.go:286-288`
30. `resolveAIQuotaLimit`: tier resolver missing from context — `api/ai.go:377-378`
31. `buildSummaryInput`: all nil/valid optional field branches — `api/ai.go:411-428`
32. `listSavedSearchesHandler`: invalid visibility param → 400 — `saved_searches.go:159-162`

### Saved Search Handler Paths (9)

33. `listSavedSearchesHandler`: `visibility=private` filter — `saved_searches.go:159`
34. `patchSavedSearchHandler`: existing search not found → 404 — `saved_searches.go:240-243`
35. `patchSavedSearchHandler`: patch with invalid DSL → 422 — `saved_searches.go:287-290`
36. `patchSavedSearchHandler`: updated row nil (race) → 404 — `saved_searches.go:306-309`
37. `executeSavedSearchHandler`: search not found → 404 — `saved_searches.go:399-402`
38. `executeSavedSearchHandler`: DSL parse/validate/compile errors — `saved_searches.go:415-434`
39. `executeSavedSearchHandler`: `ExecuteDSLQuery` error → 500 — `saved_searches.go:437-441`
40. Various handlers: invalid UUID `id` param → 400 — `saved_searches.go` (get, patch, delete, execute)
41. Various handlers: `orgID` context extraction guard — `api/ai.go`, `saved_searches.go` (8 handlers)

### Store Layer (14)

42. `DecrementAIUsage` when no row exists (no-op UPDATE) — `store/ai.go:60-67`
43. `UpdateAIUsageTokens` when no row exists (no-op UPDATE) — `store/ai.go:70-79`
44. `GetAICache` with expired TTL → cache miss (core TTL mechanism untested) — `ai_cache.sql:7`
45. `PutAICache` IS DISTINCT FROM skip-update optimization — `ai_cache.sql:14-15`
46. `DecrementAIUsage`/`UpdateAIUsageTokens` WHERE date=CURRENT_DATE (yesterday's row untouched) — `ai_usage.sql:14,20`
47. Feature CHECK constraint on AI tables — `ai_usage.sql:8`
48. Status CHECK constraint on ai_request_log — `ai_request_log.sql:18`
49. `ListSavedSearches` invalid visibility string → falls through to "all" behavior — `saved_searches.sql:21`
50. `ListSavedSearches` soft-deleted searches excluded — `saved_searches.sql:16`
51. `UpdateSavedSearch` not-found returns `(nil, nil)` — `saved_search.go:143-145`
52. Unique name index `saved_searches_name_uq` — duplicate name rejection — `migration 000024`
53. `SearchCVEs()` FTS JOIN path — zero tests for the `cve_search_index` JOIN at store level — `store/cve.go:112-116` *(from R1)*
54. Saved search `LIMIT` parameter not tested — `saved_search.go` *(from R1)*
55. Saved search `name>255`, `nl_query>1000` DB constraint violation paths untested — `migration 000024` *(from R1)*

### DSL / Executor (6)

56. `conditionToSQL` kindFTS non-string unmarshal error — `compiler.go:181-182`
57. `fts_query` as selective field with regex — `validator.go:21`
58. `ExecuteDSLQuery` limit clamping (<=0 or >100 → 25) — `dsl_executor.go:119-121`
59. `ExecuteDSLQuery` with `compiled.SQL == nil` — `dsl_executor.go:132-134`
60. `encodeDSLCursor`/`decodeDSLCursor` roundtrip — `dsl_executor.go:87-110`
61. `DryRun()` method — 6 code paths with zero integration tests — `evaluator.go:297-341` *(from R1)*

### Schema / Quota (5)

62. `BuildSchemaDescription`: Nullable annotation present — `schema.go:55-57`
63. `BuildSchemaDescription`: EnumValues present — `schema.go:52-54`
64. `PromptVersion`: hash changes when schema changes — `schema.go:32-35`
65. `buildSchema`: fields sorted by name — `schema.go:39-41`
66. `ResolveLimit`: override=0 with hasOverride=true — `quota.go:15-16`

### CLI / Config (5)

67. CLI quota commands: `quotaGetCmd`, `quotaListCmd`, `quotaDeleteCmd` never exercised through cobra — `cmd/quota.go`
68. `config.Load()`: default values never verified — `config.go:69-80`
69. `IsDevelopment()` never tested — `config.go:129-131`
70. `main.go` LLM client init: three-way branch untested (GeminiMock / GeminiAPIKey / neither) — `main.go:120-130`
71. `main.go` AI deps wiring (`SetAIDeps`) untested — `main.go:144-146`

---

## Nice-to-Have (61)

These are internal error paths, unlikely runtime failures, metrics verification, and defensive edge cases.

**gemini.go** (9): context timeouts on lazy init/API calls, UsageMetadata nil/present branches (x4), json.Marshal fails, Temperature/format config.

**mock.go** (2): prompt argument ignored (no forwarding test), CVESummaryInput fields ignored.

**sanitize.go / schema.go** (5): tab preservation, empty/whitespace input, non-enum/non-nullable schema branch, SHA-256 hash correctness.

**quota.go** (1): empty string tier falls back to free.

**API handlers** (14): non-fatal logging paths for cache get/put errors (x4), DecrementAIUsage double-fault (x2), token update errors (x2), custom cursor/limit pagination, retryAfterMidnight secs<=0, logAIRequest store error, resolveAIQuotaLimit store error, listSavedSearches limit param.

**Store layer** (14): error propagation paths (IncrementAIUsage, GetAIQuotaOverride, GetAICache, CreateSavedSearch, GetSavedSearch, UpdateSavedSearch DB errors), DeleteAIQuotaOverride non-existent, empty result lists (x2), ListAIQuotaOverrides errors (x2), soft-delete idempotency, CleanupOrphanedPrivate no-op.

**CLI / main.go / config** (14): config.Load parse error, newPool retry loop (6 paths), newLogger branches (4 paths), LogValue AI fields, quotaCmd subcommand registration.

**DSL / executor** (3): build query error with joins, encodeDSLCursor error in next-page, scanCVERow column mismatch.

**Metrics** (6): all 6 AI metrics declared but no test reads counter values after handler invocations (AIRequestsTotal, AIRequestDuration, AICacheHitsTotal, AICacheMissesTotal, AIQuotaDenialsTotal, AITokensTotal). Cross-reference verified: all are used in production code with consistent label dimensions.

---

## Key Observations

### 1. Systemic RLS Testing Gap (12 gaps, one root cause)

Every Phase 4 store test runs via the embedded superuser `*store.Store`, bypassing RLS entirely. Other phases have dedicated `AppStore` RLS tests in `org_tx_test.go` (alert rules, watchlists, groups, API keys, invitations). Phase 4 has zero such tests across 4 tables: `ai_usage_counters`, `ai_cache`, `ai_request_log`, `saved_searches`. The existing `OrgIsolation` tests prove application-level isolation but would not catch a misconfigured RLS policy.

### 2. `canModifySavedSearch` — 3 of 4 Branches Untested

This pure RBAC function has 4 branches: creator (always allowed), non-creator admin + shared, non-creator member + shared, non-creator + private. Only the creator branch is exercised. The 3 non-creator branches are the ones that matter for authorization enforcement and are completely untested.

### 3. Confirmed Regex Bug in Sanitizer

The markdown link regex `\[([^\]]*)\]\([^)]*\)` does not match markdown image syntax `![alt](url)`. The `!` prefix is unaccounted for. Fix: change to `!?\[([^\]]*)\]\([^)]*\)`. This is a real defect, not just a missing test — URLs in markdown images would reach the LLM unsanitized.

### 4. `gemini.go` Entirely Untested — Security Configs Unverified

The file has 30 correctness gaps and 6 security-critical gaps. While the API calls require HTTP mocking, the security-critical configurations (`FunctionCallingConfig{Mode: None}`, system prompt content, safety settings) could be verified by extracting config-building into testable functions or using an HTTP-level fake.

### 5. FTS Has Excellent Unit Tests but Zero Integration Tests

The DSL compiler correctly generates `websearch_to_tsquery` SQL (verified by unit tests), but no test executes this SQL against real Postgres with a seeded `cve_search_index` table. A broken JOIN, missing index, or tsvector incompatibility would go undetected.

### 6. Malformed JSON Input Never Tested on Any Phase 4 Endpoint

The `json.Decoder.Decode` error path is untested on NL search, saved search create, and saved search patch — three handlers with the same gap pattern.

### 7. `validateConfig()` and `internal/config/` Have Zero Tests

`validateConfig()` enforces JWT secret minimum length (32 bytes) and HTTPS-in-production. The entire config package has no test file — no default value verification, no required field rejection, no `IsDevelopment()` test, no `masked()` test. A regression could let the server start with a 1-byte JWT secret.

### 8. CLI Quota Commands Test Store Layer, Not CLI Wiring

`TestQuotaCmd_SetAndGet` and `TestQuotaCmd_Delete` call store methods directly, bypassing cobra commands. Only `TestQuotaCmd_SetInvalidFeature` exercises a cobra command end-to-end. The `quotaGetCmd`, `quotaListCmd`, and `quotaDeleteCmd` have zero CLI-level tests.

### 9. Quota-Disabled Path Never Tested

Both AI handlers have an `if srv.cfg.AIQuotaEnabled` guard. All tests use `AIQuotaEnabled: true`. The path where quota checking is skipped entirely is never exercised. If the guard were accidentally inverted, all non-quota deployments would break.

### 10. Missing Expired TTL Cache Test

The `GetAICache` SQL filters on `expires_at > now()`, but no test puts a cache entry with a short/expired TTL and verifies a cache miss. This is the core cache eviction mechanism.

### 11. `withBypassTx` on Quota Override Methods *(from R1)*

`SetAIQuotaOverride` and `DeleteAIQuotaOverride` use `withBypassTx` (RLS bypass) because they're designed for CLI use. This is correct and safe in the current codebase, but has no guardrail test proving they're not callable from API handlers. If either method were wired to an API route in future, it would silently bypass RLS.

### 12. `SeedTestCVE` Doesn't Populate `cve_search_index` *(from R1)*

The test seed helper creates CVE rows but not corresponding `cve_search_index` entries. This blocks FTS integration testing — any test that uses a seeded CVE and runs a FTS query will get zero results even if the code is correct. This is a test infrastructure gap that must be fixed before FTS integration tests can be written.

### 13. `ctxOrgID` Fail-Closed Guards Need Defense-in-Depth Tests *(from R1)*

All 8 Phase 4 handlers extract `orgID` from context via `ctxOrgID()`. If the context is missing, they return 400. This is correct fail-closed behavior, but zero handlers have tests proving this guard works. R1 classified these as security-critical; R2 grouped them as a single correctness item. The concern: if `ctxOrgID()` were refactored to return a zero-value UUID instead of an error, all 8 handlers would silently query with a nil org ID.

---

## Priority Recommendations

**P0 — Fix before merge:**
- Fix sanitizer regex bug (`![alt](url)`)
- Add `canModifySavedSearch` RBAC tests (3 non-creator branches)
- Add execute handler private access test
- Add viewer RBAC denial tests (POST/PATCH/DELETE)

**P1 — Fix soon:**
- Add AppStore RLS tests for Phase 4 tables (follow `org_tx_test.go` pattern)
- Add decodeDSLCursor malformed input tests
- Add expired TTL cache miss test
- Add `validateConfig()` unit tests
- Test `escapeLike` backslash escaping (ILIKE injection) *(from R1)*

**P2 — Should fix:**
- Add malformed JSON body tests across Phase 4 handlers
- Add FTS integration test with seeded `cve_search_index` (requires `SeedTestCVE` update)
- Add sanitizer tests with realistic prompt injection payloads (including `<scr<script>ipt>`, `&lt;script&gt;` entities, bidi overrides)
- Add `AIQuotaEnabled=false` handler path test
- Add config package test file
- Test `DryRun()` method paths *(from R1)*

**P3 — Nice-to-have (defer):**
- Gemini HTTP-level fake for security config verification
- CLI quota command end-to-end tests
- Metrics counter increment verification
- `main.go` LLM branching tests

---

## Reconciliation Note

This report was produced by running the test coverage review twice (R1 and R2) and merging unique findings from both runs. Items marked *(from R1)* were caught by the first run but missed by the second. Key differences:

- **R1 found `escapeLike` ILIKE injection gap, specific HTML evasion techniques (`<scr<script>ipt>`, `&lt;script&gt;` entities), and Unicode bidi overrides** — all added to the security-critical section.
- **R1 found `DryRun()` method, `SearchCVEs()` FTS path, `SeedTestCVE` infrastructure gap, and saved search LIMIT/constraint paths** — all added to the correctness section.
- **R1 classified 8 `ctxOrgID` fail-closed guards as security-critical** (8 items); R2 classified them as a single correctness item. Added as observation #13 to flag the defense-in-depth concern.
- **R2 was more thorough on RLS enumeration** (12 vs 6), **config security** (7 vs 3), and **malformed JSON body testing** (3 handlers, not flagged by R1).
- **Final merged counts:** 51 security-critical (+3 from R1), 71 correctness (+4 from R1), 61 nice-to-have (unchanged).

---

## Appendix: Individual Subagent Reports

Detailed per-function tables are preserved in these evidence files:

- `2026-03-03-phase4-subagent-ai-package.md` — `internal/ai/` (6 files)
- `2026-03-03-phase4-subagent-dsl-evaluator.md` — DSL FTS + evaluator + executor (9 files)
- `2026-03-03-phase4-subagent-api-handlers.md` — `internal/api/` handlers + server.go
- `2026-03-03-phase4-subagent-store-layer.md` — `internal/store/ai.go` + `saved_search.go` + SQL queries
- `2026-03-03-phase4-subagent-cli-config-metrics.md` — CLI, config, metrics, main.go wire-up
