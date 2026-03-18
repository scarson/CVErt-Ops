# Phase 4 Test Coverage Review — AI Handlers + Saved Searches

**Date:** 2026-03-03
**Files reviewed:**
- `internal/api/ai.go` + `internal/api/ai_test.go`
- `internal/api/saved_searches.go` + `internal/api/saved_searches_test.go`
- `internal/api/server.go` (route registration)

---

## 1. `internal/api/ai.go` — `nlSearchHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails (`!ok`) | 56-59 | GAP | security-critical |
| 2 | `userID` extraction from context (underscore error) | 61 | Covered (integration — success path sets it) | — |
| 3 | `srv.llm == nil` → 503 | 63-66 | GAP | correctness |
| 4 | Malformed JSON body → 400 | 70-73 | GAP | security-critical |
| 5 | Empty query after trim → 422 | 76-80 | Covered (`TestNLSearchHandler_EmptyQuery`) | — |
| 6 | Query > 1000 chars → 422 | 81-84 | Covered (`TestNLSearchHandler_QueryTooLong`) | — |
| 7 | Query exactly 1000 chars → 200 | 81 | Covered (`TestNLSearchHandler_1000CharQueryAccepted`) | — |
| 8 | Pagination params parsed (cursor, limit) | 87-88 | GAP — no test exercises custom cursor/limit params | nice-to-have |
| 9 | Cache get error (non-fatal, continues) | 101-105 | GAP | nice-to-have |
| 10 | Cache hit path (skip LLM, return cached) | 106-109 | Covered (`TestNLSearchHandler_CacheHit`) | — |
| 11 | Cache miss → quota check enabled, `IncrementAIUsage` error → 500 | 114-119 | GAP | correctness |
| 12 | Cache miss → quota exceeded → 429 + Retry-After | 126-131 | Covered (`TestNLSearchHandler_QuotaDenied`) | — |
| 13 | Cache miss → quota disabled (skip quota check entirely) | 114 | GAP — no test with `AIQuotaEnabled=false` | correctness |
| 14 | LLM call error → decrement quota + 503 | 135-146 | Covered (`TestNLSearchHandler_LLMFailure`) | — |
| 15 | LLM call error → `DecrementAIUsage` also errors (double-fault logging) | 139-141 | GAP | nice-to-have |
| 16 | Token count update error (non-fatal, logged) | 153-155 | GAP | nice-to-have |
| 17 | Token counts persisted in ai_request_log | 152-157 | Covered (`TestNLSearchHandler_TokenCountsPersisted`) | — |
| 18 | Cache put error (non-fatal, logged) | 160-162 | GAP | nice-to-have |
| 19 | DSL parse error → 502 | 166-173 | GAP | correctness |
| 20 | DSL validation blocking errors → 502 | 175-182 | GAP | correctness |
| 21 | DSL compile error → 502 | 184-191 | GAP | correctness |
| 22 | `ExecuteDSLQuery` error → 500 | 194-201 | GAP | correctness |
| 23 | Success path (full pipeline, results returned) | 203-221 | Covered (`TestNLSearchHandler_Success`) | — |
| 24 | Pro tier quota limit used instead of free | 121-125 | Covered (`TestNLSearchHandler_ProTierQuota`) | — |
| 25 | Unauthenticated access → 401 | middleware | Covered (`TestNLSearchHandler_Unauthenticated`) | — |

---

## 2. `internal/api/ai.go` — `summarizeHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails (`!ok`) | 229-232 | GAP | security-critical |
| 2 | `srv.llm == nil` → 503 | 236-239 | GAP | correctness |
| 3 | `cveID == ""` → 400 | 242-244 | GAP — URL pattern makes this unlikely but handler checks it | nice-to-have |
| 4 | Invalid CVE ID format → 400 | 246-249 | Covered (`TestSummarizeHandler_InvalidCVEID`) | — |
| 5 | `GetCVE` store error → 500 | 255-260 | GAP | correctness |
| 6 | CVE not found (nil) → 404 | 261-263 | Covered (`TestSummarizeHandler_NotFound`) | — |
| 7 | `materialHash` invalid (null) path for input hash | 267-271 | GAP — no test with CVE that has null material hash explicitly checked | nice-to-have |
| 8 | Cache get error (non-fatal) | 279-281 | GAP | nice-to-have |
| 9 | Cache hit → unmarshal error → fall through to LLM | 286-288 | GAP | correctness |
| 10 | Cache hit → success | 282-292 | Covered (`TestSummarizeHandler_CacheHit`) | — |
| 11 | Cache miss → quota `IncrementAIUsage` error → 500 | 300-304 | GAP | correctness |
| 12 | Cache miss → quota exceeded → 429 + Retry-After | 311-316 | Covered (`TestSummarizeHandler_QuotaDenied`) | — |
| 13 | Cache miss → quota disabled (skip check entirely) | 299 | GAP — no test with `AIQuotaEnabled=false` | correctness |
| 14 | LLM call error → decrement + 503 | 323-333 | Covered (`TestSummarizeHandler_LLMFailure`) | — |
| 15 | LLM error → `DecrementAIUsage` also fails | 326-328 | GAP | nice-to-have |
| 16 | Token count update error (non-fatal) | 340-342 | GAP | nice-to-have |
| 17 | Cache put error (non-fatal) | 348-350 | GAP | nice-to-have |
| 18 | Success path (full pipeline) | 352-364 | Covered (`TestSummarizeHandler_Success`) | — |
| 19 | Unauthenticated access → 401 | middleware | Covered (`TestSummarizeHandler_Unauthenticated`) | — |

---

## 3. `internal/api/ai.go` — Helper Functions

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `isValidCVEID` — valid/invalid patterns | 436-438 | Covered (`TestIsValidCVEID`) | — |
| 2 | `truncateForLog` — under/at/over limit | 441-446 | Covered (`TestTruncateForLog`) | — |
| 3 | `parseIntParam` — all branches | 449-464 | Covered (`TestParseIntParam`) | — |
| 4 | `retryAfterMidnight` — normal case | 468-476 | GAP — exercised in quota tests but never asserted on returned value being a valid numeric seconds string | nice-to-have |
| 5 | `retryAfterMidnight` — `secs <= 0` clamp to 1 | 472-474 | GAP | nice-to-have |
| 6 | `resolveAIQuotaLimit` — store error for quota override | 371-375 | GAP | nice-to-have |
| 7 | `resolveAIQuotaLimit` — tier resolver missing from context | 377-379 | GAP | correctness |
| 8 | `buildSummaryInput` — all nil/valid branches for optional fields | 405-430 | GAP — no dedicated unit tests; only exercised indirectly via success path | correctness |
| 9 | `logAIRequest` — store insert error (logged, non-fatal) | 386-401 | GAP | nice-to-have |

---

## 4. `internal/api/saved_searches.go` — `createSavedSearchHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails | 84-88 | GAP | security-critical |
| 2 | Malformed JSON body → 400 | 92-95 | GAP | security-critical |
| 3 | Empty name → 400 | 97-100 | Covered (`TestSavedSearch_CreateValidation`) | — |
| 4 | Name > 255 chars → 422 | 101-104 | Covered (`TestSavedSearch_CreateValidation_NameLength`) | — |
| 5 | Name exactly 255 chars → 201 | 101 | Covered (`TestSavedSearch_CreateValidation_NameLength`) | — |
| 6 | `nl_query` > 1000 chars → 422 | 105-108 | Covered (`TestSavedSearch_CreateValidation_NlQueryLength`) | — |
| 7 | `nl_query` exactly 1000 chars → 201 | 105 | Covered (`TestSavedSearch_CreateValidation_NlQueryLength`) | — |
| 8 | Empty `query_json` → 400 | 110-113 | GAP | correctness |
| 9 | Invalid DSL in `query_json` → 422 | 115-118 | Covered (`TestSavedSearch_CreateValidation`) | — |
| 10 | Store `CreateSavedSearch` error → 500 | 127-131 | GAP | nice-to-have |
| 11 | Success path | 133-143 | Covered (`TestSavedSearch_CRUD`) | — |

---

## 5. `internal/api/saved_searches.go` — `listSavedSearchesHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails | 148-152 | GAP | security-critical |
| 2 | `visibility` defaults to "all" | 155-157 | Covered (integration — CRUD test uses default) | — |
| 3 | Invalid `visibility` value → 400 | 159-162 | GAP | correctness |
| 4 | `visibility=shared` filter | 159 | Covered (`TestSavedSearch_PrivateVisibility`) | — |
| 5 | `visibility=private` filter | 159 | GAP — never tested with `?visibility=private` | correctness |
| 6 | `limit` param parsing | 164 | GAP — no test with custom limit | nice-to-have |
| 7 | Store `ListSavedSearches` error → 500 | 167-171 | GAP | nice-to-have |
| 8 | Success path (returns entries) | 173-178 | Covered (`TestSavedSearch_CRUD`, `TestSavedSearch_PrivateVisibility`) | — |

---

## 6. `internal/api/saved_searches.go` — `getSavedSearchHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails | 182-186 | GAP | security-critical |
| 2 | Invalid UUID `id` → 400 | 190-193 | GAP | correctness |
| 3 | Store `GetSavedSearch` error → 500 | 197-200 | GAP | nice-to-have |
| 4 | Search not found → 404 | 202-205 | Covered (integration — via delete-then-get and private visibility tests) | — |
| 5 | Private access control: non-shared, different user → 404 | 208-211 | Covered (`TestSavedSearch_PrivateVisibility`) | — |
| 6 | Success path | 213 | Covered (`TestSavedSearch_CRUD`) | — |

---

## 7. `internal/api/saved_searches.go` — `patchSavedSearchHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails | 218-222 | GAP | security-critical |
| 2 | Invalid UUID `id` → 400 | 227-230 | GAP | correctness |
| 3 | Existing search not found → 404 | 240-243 | GAP | correctness |
| 4 | `canModifySavedSearch` returns false → 403 | 248-251 | GAP (see RBAC section below) | security-critical |
| 5 | Malformed JSON body → 400 | 254-257 | GAP | security-critical |
| 6 | Patch with empty name → 400 | 271-274 | Covered (`TestSavedSearch_PatchValidation`) | — |
| 7 | Patch with name > 255 → 422 | 275-278 | Covered (`TestSavedSearch_PatchValidation`) | — |
| 8 | Patch with `nl_query` > 1000 → 422 | 281-284 | Covered (`TestSavedSearch_PatchValidation`) | — |
| 9 | Patch with invalid DSL → 422 | 287-290 | GAP | correctness |
| 10 | Patch `is_shared` field | 296-298 | Covered (`TestSavedSearch_CRUD` — patches `is_shared` to true) | — |
| 11 | Store `UpdateSavedSearch` error → 500 | 301-305 | GAP | nice-to-have |
| 12 | Updated row nil → 404 (race condition / concurrent delete) | 306-309 | GAP | correctness |
| 13 | Success path | 311-323 | Covered (`TestSavedSearch_CRUD`) | — |

---

## 8. `internal/api/saved_searches.go` — `deleteSavedSearchHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails | 327-331 | GAP | security-critical |
| 2 | Invalid UUID `id` → 400 | 336-339 | GAP | correctness |
| 3 | Existing search not found → 404 | 349-352 | GAP | correctness |
| 4 | `canModifySavedSearch` returns false → 403 | 354-357 | GAP (see RBAC section below) | security-critical |
| 5 | Store `SoftDeleteSavedSearch` error → 500 | 360-363 | GAP | nice-to-have |
| 6 | Success path (204) | 365-374 | Covered (`TestSavedSearch_CRUD`, `TestSavedSearch_DeleteReturns404`) | — |

---

## 9. `internal/api/saved_searches.go` — `executeSavedSearchHandler`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | `orgID` context extraction fails | 379-383 | GAP | security-critical |
| 2 | Invalid UUID `id` → 400 | 387-390 | GAP | correctness |
| 3 | Search not found → 404 | 399-402 | GAP | correctness |
| 4 | Private access control: non-shared, different user → 404 | 405-408 | GAP — execute-specific private check never tested | security-critical |
| 5 | Pagination params (cursor, limit) | 411-412 | GAP | nice-to-have |
| 6 | DSL parse error → 422 | 415-419 | GAP | correctness |
| 7 | DSL validation error → 422 | 422-427 | GAP | correctness |
| 8 | DSL compile error → 422 | 429-434 | GAP | correctness |
| 9 | `ExecuteDSLQuery` error → 500 | 437-441 | GAP | correctness |
| 10 | Success path (results returned) | 443-452 | Covered (`TestSavedSearch_Execute`) | — |

---

## 10. `internal/api/saved_searches.go` — `canModifySavedSearch`

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | Caller is creator → true (always allowed) | 459-462 | Covered (implicitly — CRUD test patches/deletes own search) | — |
| 2 | Non-creator, shared search, caller is admin+ → true | 463-465 | GAP | security-critical |
| 3 | Non-creator, shared search, caller is member → false | 463-466 | GAP | security-critical |
| 4 | Non-creator, private search → false | 463-466 | GAP | security-critical |

---

## 11. `internal/api/server.go` — Route Registration

| # | Code Path | Lines | Test Status | Severity |
|---|-----------|-------|-------------|----------|
| 1 | AI routes at `/ai/nl-search` (viewer+) | 307-310 | Covered (integration — AI tests hit these routes) | — |
| 2 | AI routes at `/ai/summarize/{cve_id}` (viewer+) | 307-310 | Covered (integration — AI tests hit these routes) | — |
| 3 | Saved search routes: `GET /saved-searches` (viewer) | 313-314 | Covered (integration) | — |
| 4 | Saved search routes: `POST /saved-searches` (member+) | 315 | Covered (integration) | — |
| 5 | Saved search routes: `GET /saved-searches/{id}` (viewer) | 317 | Covered (integration) | — |
| 6 | Saved search routes: `PATCH /saved-searches/{id}` (member+) | 318 | Covered (integration) | — |
| 7 | Saved search routes: `DELETE /saved-searches/{id}` (member+) | 319 | Covered (integration) | — |
| 8 | Saved search routes: `POST /saved-searches/{id}/execute` (viewer) | 320 | Covered (integration) | — |
| 9 | Viewer denied POST `/saved-searches` (needs member+) | 315 | GAP — no test verifies viewer gets 403 on create | security-critical |
| 10 | Viewer denied PATCH `/saved-searches/{id}` | 318 | GAP — no test verifies viewer gets 403 on patch | security-critical |
| 11 | Viewer denied DELETE `/saved-searches/{id}` | 319 | GAP — no test verifies viewer gets 403 on delete | security-critical |
| 12 | Middleware chain: `RequireAuthenticated` → `RequireOrgRole` → `tierMiddleware` → `orgRateLimitMiddleware` | 188-194 | GAP — no test verifies full middleware ordering for saved search routes | nice-to-have |

---

## What's Well Covered

- **AI handler happy paths and core validation**: Both `nlSearchHandler` and `summarizeHandler` have solid integration tests covering the full success pipeline (LLM call, DSL compilation, query execution, response format). Input validation (empty query, too-long query, invalid CVE ID format) is well-tested with boundary cases (exactly 1000 chars accepted, 1001 rejected).

- **Quota and caching flows**: Both endpoints have dedicated tests for quota exhaustion (429 + Retry-After assertion), cache hit/miss behavior (verifying the `cached` field), and tier-based quota resolution (pro tier test for NL search). The LLM failure path with quota decrement is also tested for both handlers.

- **Saved search CRUD lifecycle and validation**: The CRUD test covers create, get, list, patch, and delete in a single flow. Input validation tests cover name length, nl_query length, and invalid DSL for both create and patch. The delete-then-get-returns-404 test confirms soft-delete behavior.

---

## Summary of All Gaps by Severity

### Security-Critical: 14 gaps

1. **`orgID` context extraction fails** — All 7 handlers (`nlSearch`, `summarize`, `create/list/get/patch/delete/executeSavedSearch`) have an `orgID` fail-open guard (line `if !ok`). None are individually tested. While the middleware normally guarantees `orgID` is set, if the middleware chain changes or is misconfigured, these become fail-open paths. (7 instances)
2. **Malformed JSON body on NL search** — No test sends `{broken json` to `POST /ai/nl-search`. (1 instance)
3. **Malformed JSON body on saved search create** — No test sends malformed JSON to `POST /saved-searches`. (1 instance)
4. **Malformed JSON body on saved search patch** — No test sends malformed JSON to `PATCH /saved-searches/{id}`. (1 instance)
5. **`canModifySavedSearch` — non-creator admin can modify shared search** — No test for branch where a non-creator admin modifies a shared search. (1 instance)
6. **`canModifySavedSearch` — non-creator member denied on shared search** — No test for a member (not admin) trying to modify someone else's shared search. (1 instance)
7. **`canModifySavedSearch` — non-creator denied on private search** — No test for a non-creator trying to modify a private search. (1 instance)
8. **Execute handler private access control** — No test verifies that a user cannot execute another user's private saved search. (1 instance)
9. **Viewer RBAC denial on saved search POST/PATCH/DELETE** — No test verifies viewer role gets 403 on create, patch, or delete. (3 instances counted as 1 gap in route registration)

### Correctness: 18 gaps

1. `nlSearchHandler` — `srv.llm == nil` path not tested
2. `nlSearchHandler` — `IncrementAIUsage` error → 500 not tested
3. `nlSearchHandler` — quota disabled path not tested
4. `nlSearchHandler` — DSL parse error (from LLM returning garbage) → 502 not tested
5. `nlSearchHandler` — DSL validation blocking errors → 502 not tested
6. `nlSearchHandler` — DSL compile error → 502 not tested
7. `nlSearchHandler` — `ExecuteDSLQuery` error → 500 not tested
8. `summarizeHandler` — `srv.llm == nil` path not tested
9. `summarizeHandler` — cache hit unmarshal error fallthrough not tested
10. `summarizeHandler` — `IncrementAIUsage` error → 500 not tested
11. `summarizeHandler` — quota disabled path not tested
12. `summarizeHandler` — `GetCVE` store error not tested
13. `buildSummaryInput` — no unit tests for nil/valid optional field branches
14. `resolveAIQuotaLimit` — tier resolver missing from context (falls back to "free")
15. `listSavedSearchesHandler` — invalid visibility param → 400 not tested
16. `listSavedSearchesHandler` — `visibility=private` filter not tested
17. `patchSavedSearchHandler` — patch with invalid DSL → 422 not tested
18. Various handlers — invalid UUID `id` param → 400 not tested (get, patch, delete, execute)

### Nice-to-Have: 14 gaps

1. `nlSearchHandler` — cache get error (non-fatal logging)
2. `nlSearchHandler` — LLM error + decrement also errors (double-fault)
3. `nlSearchHandler` — token update error (non-fatal)
4. `nlSearchHandler` — cache put error (non-fatal)
5. `nlSearchHandler` — custom cursor/limit pagination params
6. `summarizeHandler` — cache get error (non-fatal)
7. `summarizeHandler` — LLM error + decrement also errors
8. `summarizeHandler` — token update error (non-fatal)
9. `summarizeHandler` — cache put error (non-fatal)
10. `retryAfterMidnight` — `secs <= 0` edge case
11. `logAIRequest` — store insert error
12. `resolveAIQuotaLimit` — store error for quota override
13. `listSavedSearchesHandler` — custom limit param
14. Various store error → 500 paths on saved search handlers

---

## Key Observations

### Cross-Cutting Patterns

1. **`orgID` context guard is never directly tested**: Every handler has `if !ok { return 400 }` for `orgID` extraction. This is a defensive guard against middleware misconfiguration. While the middleware tests in `middleware_rbac_test.go` verify that the middleware correctly sets context, there's no test that directly exercises a handler when the context value is missing. Given that this is a multi-tenant app, a regression in middleware ordering that drops `orgID` could silently return empty data instead of erroring.

2. **Malformed JSON input is never tested for any endpoint**: Neither AI nor saved search handlers have tests for `{broken` or empty body. The `json.Decoder.Decode` error path (400 response) is untested across all handlers.

3. **No cross-org isolation test for saved searches**: The `PrivateVisibility` test uses two users in the *same org*. There is no test where Org A creates a saved search and a user from Org B tries to access it. The RLS layer and `orgID` scoping provide defense, but the handler-level test suite doesn't verify this.

4. **`canModifySavedSearch` has 4 branches, only 1 is tested**: The function has distinct paths for (creator=true, non-creator+shared+admin, non-creator+shared+member, non-creator+private). Only the creator path is exercised by the existing CRUD test. The 3 non-creator paths are security-critical RBAC decisions with zero dedicated test coverage.

5. **DSL error paths from LLM output are untested**: The NL search handler has 3 sequential DSL processing steps (parse, validate, compile) that each return 502 on failure. None are tested. Since these process untrusted LLM output, a test with a mock that returns invalid DSL JSON would be valuable to confirm the handler doesn't panic or leak data.

6. **Quota-disabled codepath is never tested**: Both AI handlers have an `if srv.cfg.AIQuotaEnabled` branch. No test sets `AIQuotaEnabled=false`, so the path where quota checking is entirely skipped is never exercised.
