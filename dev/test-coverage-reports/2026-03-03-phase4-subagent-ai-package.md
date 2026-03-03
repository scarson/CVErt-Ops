# Phase 4 AI Package — Test Coverage Review

**Date:** 2026-03-03
**Scope:** `internal/ai/` (6 files) + consumer tests in `internal/api/ai_test.go`

---

## File: `internal/ai/ai.go` (types/interface)

No logic to test directly. Contains `LLMClient` interface, `GenerateResult`, `SummarizeResult`, `CVESummaryInput` types.

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| `LLMClient` interface compliance (GeminiClient) | 12-18 | Covered (`gemini_test.go:34` compile-time check) | — |
| `LLMClient` interface compliance (MockClient) | 12-18 | Covered (`mock.go:11` compile-time check) | — |
| `CVESummaryInput` struct field population | 35-46 | Covered (integration: `api/ai_test.go` TestSummarizeHandler_Success) | — |

**No gaps.** This is a types-only file.

---

## File: `internal/ai/gemini.go`

### `NewGeminiClient` (lines 30-35)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Empty API key returns error | 31-33 | Covered (`gemini_test.go:12-18`) | — |
| Valid config returns non-nil client | 34 | Covered (`gemini_test.go:20-31`) | — |

### `getClient` — lazy initialization (lines 40-57)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Client already initialized (cache hit) | 43-44 | **GAP** | correctness |
| First call creates new genai.Client | 46-56 | **GAP** | correctness |
| genai.NewClient fails — returns wrapped error | 52-53 | **GAP** | correctness |
| genai.NewClient succeeds — client cached for reuse | 55-56 | **GAP** | correctness |
| Retry after initial failure succeeds | 40-57 | **GAP** | correctness |
| Context timeout (10s) on init | 46-47 | **GAP** | nice-to-have |
| Mutex protects concurrent lazy init | 41-42 | **GAP** | correctness |

### `GenerateStructuredQuery` (lines 61-102)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| getClient fails — returns error | 62-64 | **GAP** | correctness |
| GenerateContent API call succeeds | 80-82 | **GAP** | correctness |
| GenerateContent API call fails — returns wrapped error | 81-82 | **GAP** | correctness |
| result.Text() returns valid JSON | 85-89 | **GAP** | correctness |
| result.Text() returns invalid JSON — error | 87-88 | **GAP** | correctness |
| UsageMetadata is nil — tokens default to 0 | 91-95 | **GAP** | nice-to-have |
| UsageMetadata is present — tokens populated | 92-95 | **GAP** | nice-to-have |
| Temperature set to 0 (deterministic) | 77 | **GAP** | correctness |
| ResponseMIMEType set to application/json | 72 | **GAP** | correctness |
| SystemInstruction uses BuildSchemaDescription() | 74-76 | **GAP** | correctness |
| Context timeout applied from g.timeout | 67-68 | **GAP** | nice-to-have |

### `Summarize` (lines 105-149)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| getClient fails — returns error | 106-108 | **GAP** | correctness |
| json.Marshal(input) fails | 114-116 | **GAP** | nice-to-have |
| GenerateContent API call succeeds | 133 | **GAP** | correctness |
| GenerateContent API call fails — returns wrapped error | 134-135 | **GAP** | correctness |
| FunctionCallingConfig Mode = None (prompt injection defense) | 126-130 | **GAP** | security-critical |
| ToolConfig sets zero tool access | 126-130 | **GAP** | security-critical |
| UsageMetadata nil — tokens default to 0 | 138-142 | **GAP** | nice-to-have |
| UsageMetadata present — tokens populated | 139-142 | **GAP** | nice-to-have |
| SystemInstruction uses summarizeSystemPrompt | 120-122 | **GAP** | security-critical |
| Temperature set to 0.2 | 123 | **GAP** | nice-to-have |
| Context timeout applied from g.timeout | 111-112 | **GAP** | nice-to-have |

### `buildDSLResponseSchema` (lines 159-182)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Schema type is Object with logic + conditions | 160-181 | **GAP** | correctness |
| Conditions items require field, operator, value | 175 | **GAP** | correctness |
| Logic enum restricted to "and" / "or" | 165 | **GAP** | correctness |

### `summarizeSystemPrompt` (lines 151-155)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Prompt warns about untrusted content | 152 | **GAP** | security-critical |
| Prompt instructs not to follow embedded instructions | 152 | **GAP** | security-critical |
| Prompt instructs not to generate URLs | 154 | **GAP** | security-critical |

**gemini.go summary:** 0 covered, 30 gaps. This is expected — `getClient`, `GenerateStructuredQuery`, and `Summarize` make real API calls to Gemini, so they're not unit-testable without HTTP mocking. However, the lack of any HTTP-level integration test (e.g., httptest server faking Gemini responses) means critical security configs (FunctionCallingConfig, system prompt, safety settings) are completely unverified.

---

## File: `internal/ai/mock.go`

### `NewMockClient` (line 20-22)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Returns non-nil MockClient | 21 | Covered (integration: used by `api/ai_test.go:45`) | — |

### `MockClient.GenerateStructuredQuery` (lines 25-35)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Err is set — returns error | 26-28 | Covered (integration: `api/ai_test.go:514-515` TestNLSearchHandler_LLMFailure) | — |
| Err is nil — returns canned response | 29-34 | Covered (integration: `api/ai_test.go` TestNLSearchHandler_Success) | — |

### `MockClient.Summarize` (lines 38-47)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Err is set — returns error | 39-41 | Covered (integration: `api/ai_test.go:556-557` TestSummarizeHandler_LLMFailure) | — |
| Err is nil — returns canned summary with CVE ID | 42-46 | Covered (integration: `api/ai_test.go` TestSummarizeHandler_Success) | — |

### Mock correctness concerns

| Concern | Status | Severity |
|---------|--------|----------|
| Mock's canned JSON is valid DSL (parseable by `dsl.Parse`) | Covered (integration: handler parses it successfully in TestNLSearchHandler_Success) | — |
| Mock ignores prompt argument — no test that prompt is forwarded | **GAP** | nice-to-have |
| Mock ignores CVESummaryInput fields except CVEID — no test that full input is forwarded | **GAP** | nice-to-have |

**mock.go summary:** Well-covered via integration tests. 2 minor gaps.

---

## File: `internal/ai/quota.go`

### `ResolveLimit` (lines 14-26)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| hasOverride=true returns override value | 15-16 | Covered (`quota_test.go:11-17`) | — |
| orgTier="pro" returns Pro limit | 19-20 | Covered (`quota_test.go:29`) | — |
| orgTier="enterprise" returns Enterprise limit | 21-22 | Covered (`quota_test.go:30`) | — |
| orgTier="free" returns Free limit (default case) | 23-24 | Covered (`quota_test.go:28`) | — |
| Unknown tier falls back to Free | 23-24 | Covered (`quota_test.go:31`) | — |
| Override=0 with hasOverride=true returns 0 (valid zero override) | 15-16 | **GAP** | correctness |
| Negative override value with hasOverride=true | 15-16 | **GAP** | correctness |
| Empty string tier falls back to Free | 23-24 | **GAP** | nice-to-have |

**quota.go summary:** Core logic well-covered. 3 gaps (edge cases around zero/negative overrides and empty tier string).

---

## File: `internal/ai/sanitize.go`

### `Sanitize` (lines 18-33)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Strips markdown links `[text](url)` | 20 | Covered (`sanitize_test.go:11-18`) | — |
| Strips HTML tags | 22 | Covered (`sanitize_test.go:20-27`) | — |
| Strips control chars (NUL, SOH, STX) | 24-31 | Covered (`sanitize_test.go:29-36`) | — |
| Preserves newlines | 27 | Covered (`sanitize_test.go:38-45`) | — |
| Preserves tabs | 27 | **GAP** | nice-to-have |
| Combined stripping | 20-31 | Covered (`sanitize_test.go:47-55`) | — |
| Strips markdown images `![alt](url)` | 20 | **GAP** | security-critical |
| Nested markdown links `[text [inner]](url)` | 20 | **GAP** | security-critical |
| Markdown links with parentheses in URL `[text](url(1))` | 20 | **GAP** | correctness |
| Self-closing HTML `<br/>`, `<img src=x />` | 22 | **GAP** | security-critical |
| HTML with attributes `<a href="evil">` | 22 | **GAP** | security-critical |
| Multi-line HTML tags (tag spans lines) | 22 | **GAP** | security-critical |
| Empty string input | 18-33 | **GAP** | nice-to-have |
| Unicode control chars (U+200B zero-width space, U+FEFF BOM) | 27 | **GAP** | security-critical |
| Prompt injection: "Ignore previous instructions" embedded in description | — | **GAP** | security-critical |
| Prompt injection: system prompt override attempt via description | — | **GAP** | security-critical |
| Prompt injection: data exfiltration via crafted description | — | **GAP** | security-critical |
| Realistic CVE description with embedded malicious markdown/HTML | — | **GAP** | security-critical |
| String with only whitespace | 18-33 | **GAP** | nice-to-have |

### Regex analysis

The regex `\[([^\]]*)\]\([^)]*\)` matches `[text](url)` but does NOT match `![alt](url)`. The `!` before `[` in markdown image syntax means image URLs will pass through unsanitized. This is a **confirmed regex bug**, not just a missing test.

**sanitize.go summary:** 5 paths covered, 14 gaps. Heavy on security-critical gaps because this is the prompt injection defense layer.

---

## File: `internal/ai/schema.go`

### `BuildSchemaDescription` (lines 25-28)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Returns non-empty string | 25-28 | Covered (`schema_test.go:12-27`) | — |
| Contains all registered DSL fields | 25-28 | Covered (`schema_test.go:15-26`) | — |
| Contains operators | 25-28 | Covered (`schema_test.go:29-37`) | — |
| Deterministic output (sync.Once) | 26 | Covered (`schema_test.go:39-46`) | — |
| Contains Nullable annotation for nullable fields | 55-57 | **GAP** | correctness |
| Contains EnumValues for enum fields | 52-54 | **GAP** | correctness |
| Contains "Notes:" section with usage guidance | 61-67 | **GAP** | nice-to-have |

### `PromptVersion` (lines 32-35)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Returns stable 8-character hex string | 32-35 | Covered (`schema_test.go:48-58`) | — |
| Hash changes when schema changes | 32-35 | **GAP** | correctness |

### `buildSchema` (lines 37-71)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Fields sorted by name | 39-41 | **GAP** | correctness |
| Enum field branch (f.EnumValues > 0) | 52-54 | **GAP** | correctness |
| Nullable field branch (f.Nullable) | 55-57 | **GAP** | correctness |
| Non-enum, non-nullable field branch | 49-51 | **GAP** | nice-to-have |
| SHA-256 hash truncated to first 4 bytes (8 hex chars) | 69-70 | Covered (indirectly via PromptVersion length check) — but no assertion on hash correctness | **GAP** | nice-to-have |

**schema.go summary:** 4 paths covered, 7 gaps. The existing tests are good for smoke-testing but don't validate specific formatting branches.

---

## Consumer Tests: `internal/api/ai_test.go` + `internal/api/ai.go`

These are integration tests that exercise the handlers end-to-end with a real Postgres database and mock LLM.

### Handler-level paths tested

| Handler Path | Test | Status |
|-------------|------|--------|
| NL search happy path (200) | TestNLSearchHandler_Success | Covered |
| NL search empty query (422) | TestNLSearchHandler_EmptyQuery | Covered |
| NL search query too long (422) | TestNLSearchHandler_QueryTooLong | Covered |
| NL search quota exceeded (429) | TestNLSearchHandler_QuotaDenied | Covered |
| NL search cache hit | TestNLSearchHandler_CacheHit | Covered |
| NL search LLM failure (503) | TestNLSearchHandler_LLMFailure | Covered |
| NL search unauthenticated (401) | TestNLSearchHandler_Unauthenticated | Covered |
| NL search boundary 1000-char (200) | TestNLSearchHandler_1000CharQueryAccepted | Covered |
| NL search token counts persisted | TestNLSearchHandler_TokenCountsPersisted | Covered |
| NL search pro tier quota | TestNLSearchHandler_ProTierQuota | Covered |
| Summarize happy path (200) | TestSummarizeHandler_Success | Covered |
| Summarize CVE not found (404) | TestSummarizeHandler_NotFound | Covered |
| Summarize invalid CVE ID (400) | TestSummarizeHandler_InvalidCVEID | Covered |
| Summarize quota exceeded (429) | TestSummarizeHandler_QuotaDenied | Covered |
| Summarize LLM failure (503) | TestSummarizeHandler_LLMFailure | Covered |
| Summarize unauthenticated (401) | TestSummarizeHandler_Unauthenticated | Covered |
| Summarize cache hit | TestSummarizeHandler_CacheHit | Covered |
| Helper: isValidCVEID | TestIsValidCVEID | Covered |
| Helper: truncateForLog | TestTruncateForLog | Covered |
| Helper: parseIntParam | TestParseIntParam | Covered |

### Handler-level paths NOT tested (from `internal/api/ai.go`)

| Code Path | Line(s) | Severity |
|-----------|---------|----------|
| NL search: srv.llm == nil (503) | 63-66 | correctness |
| NL search: invalid request body (400) | 70-72 | correctness |
| NL search: whitespace-only query (422) | 76-78 | correctness |
| NL search: cache get error (non-fatal, falls through) | 102-104 | nice-to-have |
| NL search: IncrementAIUsage fails (500) | 116-119 | correctness |
| NL search: DecrementAIUsage after LLM failure fails | 139-141 | nice-to-have |
| NL search: UpdateAIUsageTokens fails (non-fatal) | 153-155 | nice-to-have |
| NL search: PutAICache fails (non-fatal) | 160-162 | nice-to-have |
| NL search: DSL parse fails (502) | 166-172 | correctness |
| NL search: DSL validation fails (502) | 175-181 | correctness |
| NL search: DSL compile fails (502) | 184-190 | correctness |
| NL search: ExecuteDSLQuery fails (500) | 194-200 | correctness |
| NL search: pagination params (cursor, limit) | 87-88 | correctness |
| NL search: quota disabled (AIQuotaEnabled=false) | 114 | correctness |
| Summarize: srv.llm == nil (503) | 236-239 | correctness |
| Summarize: cve_id empty string in URL param | 242-244 | correctness |
| Summarize: GetCVE internal error (500) | 256-259 | correctness |
| Summarize: cache hit with corrupt JSON (falls through to LLM) | 286-291 | correctness |
| Summarize: DecrementAIUsage after LLM failure fails | 326-328 | nice-to-have |
| Summarize: UpdateAIUsageTokens fails (non-fatal) | 340-342 | nice-to-have |
| Summarize: PutAICache fails (non-fatal) | 348-350 | nice-to-have |
| Summarize: quota disabled | 299 | correctness |
| Summarize: cve.MaterialHash.Valid = false (empty hash in input hash) | 268-270 | correctness |
| resolveAIQuotaLimit: GetAIQuotaOverride fails (falls through) | 372-374 | correctness |
| resolveAIQuotaLimit: ctxTierResolver missing (defaults to "free") | 377-378 | correctness |
| retryAfterMidnight: secs <= 0 guard | 472-473 | nice-to-have |
| buildSummaryInput: all nil/valid optional field branches | 411-428 | correctness |
| buildSummaryInput: Sanitize is called on description | 415 | security-critical |
| NL search: orgID assertion fails (no ctxOrgID in context) | 56-59 | correctness |
| Summarize: orgID assertion fails (no ctxOrgID in context) | 230-233 | correctness |

---

## Gap Summary

### Security-Critical Gaps: **14**

1. `gemini.go` Summarize: FunctionCallingConfig Mode=None not verified (line 127-129)
2. `gemini.go` Summarize: ToolConfig zero tool access not verified (line 126-130)
3. `gemini.go` Summarize: SystemInstruction uses correct prompt not verified (line 120-122)
4. `gemini.go` summarizeSystemPrompt: untrusted content warning not tested (line 152)
5. `gemini.go` summarizeSystemPrompt: "do not follow embedded instructions" not tested (line 152)
6. `gemini.go` summarizeSystemPrompt: "do not generate URLs" not tested (line 154)
7. `sanitize.go`: Markdown images `![alt](url)` not stripped — **confirmed regex bug** (line 12)
8. `sanitize.go`: Nested markdown links not tested (line 12)
9. `sanitize.go`: Self-closing HTML tags not tested (line 13)
10. `sanitize.go`: HTML with attributes not tested (line 13)
11. `sanitize.go`: Multi-line HTML tags not tested (line 13)
12. `sanitize.go`: Unicode zero-width/BOM control chars not tested (line 27)
13. `sanitize.go`: Prompt injection with realistic attack payloads not tested
14. `api/ai.go` buildSummaryInput: Sanitize call on description not independently tested (line 415)

### Correctness Gaps: **36**

1. `gemini.go` getClient: client already initialized path (line 43-44)
2. `gemini.go` getClient: first call creates client (line 46-56)
3. `gemini.go` getClient: creation fails returns error (line 52-53)
4. `gemini.go` getClient: client cached after success (line 55-56)
5. `gemini.go` getClient: retry after failure (line 40-57)
6. `gemini.go` getClient: mutex concurrent access (line 41-42)
7. `gemini.go` GenerateStructuredQuery: getClient fails (line 62-64)
8. `gemini.go` GenerateStructuredQuery: API call succeeds (line 80-82)
9. `gemini.go` GenerateStructuredQuery: API call fails (line 81-82)
10. `gemini.go` GenerateStructuredQuery: valid JSON response (line 85-89)
11. `gemini.go` GenerateStructuredQuery: invalid JSON response (line 87-88)
12. `gemini.go` GenerateStructuredQuery: Temperature=0 (line 77)
13. `gemini.go` GenerateStructuredQuery: ResponseMIMEType (line 72)
14. `gemini.go` GenerateStructuredQuery: SystemInstruction (line 74-76)
15. `gemini.go` Summarize: getClient fails (line 106-108)
16. `gemini.go` Summarize: API call succeeds (line 133)
17. `gemini.go` Summarize: API call fails (line 134-135)
18. `gemini.go` buildDSLResponseSchema: schema structure (line 160-181)
19. `gemini.go` buildDSLResponseSchema: conditions required fields (line 175)
20. `gemini.go` buildDSLResponseSchema: logic enum (line 165)
21. `quota.go` ResolveLimit: override=0 with hasOverride=true (line 15-16)
22. `quota.go` ResolveLimit: negative override (line 15-16)
23. `schema.go` BuildSchemaDescription: Nullable annotation present (line 55-57)
24. `schema.go` BuildSchemaDescription: EnumValues present (line 52-54)
25. `schema.go` PromptVersion: hash changes when schema changes (line 32-35)
26. `schema.go` buildSchema: fields sorted by name (line 39-41)
27. `schema.go` buildSchema: enum field branch (line 52-54)
28. `schema.go` buildSchema: nullable field branch (line 55-57)
29. `api/ai.go` nlSearchHandler: srv.llm == nil (line 63-66)
30. `api/ai.go` nlSearchHandler: invalid body (line 70-72)
31. `api/ai.go` nlSearchHandler: whitespace-only query (line 76-78)
32. `api/ai.go` nlSearchHandler: DSL parse/validate/compile failure paths (line 166-190)
33. `api/ai.go` nlSearchHandler: ExecuteDSLQuery failure (line 194-200)
34. `api/ai.go` nlSearchHandler: pagination params (line 87-88)
35. `api/ai.go` summarizeHandler: corrupt cache JSON fallthrough (line 286-291)
36. `api/ai.go` buildSummaryInput: all optional field branches (line 411-428)

### Nice-to-Have Gaps: **18**

1. `gemini.go` getClient: context timeout on init (line 46-47)
2. `gemini.go` GenerateStructuredQuery: UsageMetadata nil (line 91-95)
3. `gemini.go` GenerateStructuredQuery: UsageMetadata present (line 92-95)
4. `gemini.go` GenerateStructuredQuery: context timeout (line 67-68)
5. `gemini.go` Summarize: json.Marshal fails (line 114-116)
6. `gemini.go` Summarize: UsageMetadata nil (line 138-142)
7. `gemini.go` Summarize: UsageMetadata present (line 139-142)
8. `gemini.go` Summarize: Temperature=0.2 (line 123)
9. `gemini.go` Summarize: context timeout (line 111-112)
10. `mock.go`: prompt argument ignored (no forwarding test)
11. `mock.go`: CVESummaryInput fields ignored (no forwarding test)
12. `quota.go` ResolveLimit: empty string tier (line 23-24)
13. `sanitize.go`: tab preservation (line 27)
14. `sanitize.go`: empty string input (line 18-33)
15. `sanitize.go`: whitespace-only string (line 18-33)
16. `schema.go` buildSchema: non-enum, non-nullable branch (line 49-51)
17. `schema.go` buildSchema: SHA-256 hash correctness (line 69-70)
18. `api/ai.go` retryAfterMidnight: secs <= 0 guard (line 472-473)

Plus several non-fatal error logging paths in `api/ai.go` (cache get error, UpdateAIUsageTokens error, PutAICache error, DecrementAIUsage error) — 8 additional nice-to-have paths not individually listed above.

---

## What's Well-Covered

- **Integration test coverage for the handler happy paths and key error paths is strong.** Both NL search and summarize have success, quota denial, LLM failure, cache hit, unauthenticated, and input validation tests with real Postgres.
- **Quota resolution logic (`quota.go`) has excellent branch coverage** including each tier, override precedence, and unknown-tier fallback.
- **Helper functions** (`isValidCVEID`, `truncateForLog`, `parseIntParam`) have thorough unit tests with boundary conditions.

---

## Key Observations

### 1. `gemini.go` is entirely untested at the unit level

All 30 code paths in `gemini.go` are gaps. The file has real Gemini API calls that can't be tested without mocking the HTTP layer. However, this means the **security-critical Gemini config** — `FunctionCallingConfig{Mode: None}` (prompt injection defense per PLAN.md 13.4), the system prompt content, and the structured output schema — are **never verified by any test**. A regression that removes the zero-tool-access config would go undetected.

**Recommendation:** Consider an HTTP-level fake that validates the request payload sent to Gemini, verifying that FunctionCallingConfig, system prompt, and schema are correctly configured. Alternatively, extract the config-building logic into testable functions that return `*genai.GenerateContentConfig` structs, and unit-test those.

### 2. `sanitize.go` has a confirmed regex bug for markdown images

The regex `\[([^\]]*)\]\([^)]*\)` does NOT match `![alt](url)` (markdown image syntax). A CVE description containing `![payload](https://evil.com/exfil)` would pass through the sanitizer with the URL intact, potentially enabling prompt injection via image references. The `!` prefix on the image syntax is not accounted for.

**Recommendation:** Change the regex to `!?\[([^\]]*)\]\([^)]*\)` to match both links and images.

### 3. Sanitize tests use toy inputs, not realistic attack payloads

The test inputs are simple examples like `[this link](https://evil.com/inject)`. Real CVE descriptions used in prompt injection attacks would contain multi-line payloads, Unicode obfuscation, nested syntax, and instruction override attempts. The sanitizer's effectiveness against realistic threats is unproven.

### 4. `buildSummaryInput` lacks dedicated unit tests

This function (in `api/ai.go`, lines 405-430) handles 7 conditional branches for optional fields (Severity, Description, CVSSV3Score, CVSSV4Score, EPSSScore, CWEIDs) and calls `ai.Sanitize` on the description. It's exercised indirectly via TestSummarizeHandler_Success, but that test only seeds a basic CVE — the nil/valid branches for CVSS scores, EPSS, and CWE IDs are untested, and the sanitization call is not independently asserted.

### 5. No test verifies that quota is NOT enforced when `AIQuotaEnabled=false`

All integration tests use `AIQuotaEnabled: true`. The `if srv.cfg.AIQuotaEnabled` guard (lines 114 and 299 of `api/ai.go`) has no test for the disabled case. If the guard were accidentally inverted, it would break all non-quota deployments.

### 6. Mock client masks real integration concerns

The `MockClient` returns a hardcoded DSL response regardless of input. This means the integration tests prove the handler pipeline works with one specific DSL structure, but they don't test how the handler behaves when the LLM returns edge-case DSL (e.g., empty conditions array, single condition, deeply nested OR logic, FTS-only queries).

---

## Totals

| Severity | Gap Count |
|----------|-----------|
| Security-Critical | **14** |
| Correctness | **36** |
| Nice-to-Have | **18** |
| **Total Gaps** | **68** |
| **Total Covered** | ~30 paths across all files |
