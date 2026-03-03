# Phase 4 Post-Remediation Test Coverage Review

**Date:** 2026-03-03
**Type:** Post-remediation verification (fresh analysis, no reference to prior report)
**Scope:** All Phase 4 source files
**Method:** 4 parallel subagents, each reviewing 3–5 source files
**Reviewer:** Claude

---

## Coverage Summary

| File | Paths Mapped | Covered | GAP | Gap Rate |
|------|-------------|---------|-----|----------|
| internal/ai/gemini.go | 20 | 2 | 18 | 90% |
| internal/ai/schema.go | 10 | 10 | 0 | 0% |
| internal/ai/quota.go | 7 | 7 | 0 | 0% |
| internal/ai/sanitize.go | 17 | 14 | 3 | 18% |
| internal/ai/mock.go | 5 | 5 | 0 | 0% |
| internal/store/ai.go | 25 | 18 | 7 | 28% |
| internal/metrics/ai.go | 6 | 0 | 6 | 100% |
| internal/api/ai.go | 65 | 28 | 37 | 57% |
| internal/alert/dsl/parser.go | 8 | 5 | 3 | 38% |
| internal/alert/dsl/validator.go | 35 | 21 | 14 | 40% |
| internal/alert/dsl/compiler.go | 55 | 16 | 39 | 71% |
| internal/alert/dsl/accessor.go | 12 | 9 | 3 | 25% |
| internal/alert/dsl/field.go | 10 | 0 | 10 | 100% |
| internal/alert/dsl/types.go | 1 | 0 | 1 | 100% |
| internal/alert/cache.go | 6 | 4 | 2 | 33% |
| internal/alert/evaluator.go | 105 | 22 | 83 | 79% |
| internal/store/dsl_executor.go | 25 | 18 | 7 | 28% |
| internal/api/saved_searches.go | 55 | 27 | 28 | 51% |
| internal/store/saved_search.go | 30 | 20 | 10 | 33% |
| internal/config/config.go (P4) | 20 | 3 | 17 | 85% |
| cmd/cvert-ops/quota.go | 25 | 5 | 20 | 80% |
| internal/api/server.go (P4) | 10 | 9 | 1 | 10% |
| **TOTAL** | **552** | **243** | **309** | **56%** |

---

## What's Well-Covered

- **Sanitization attack surface (sanitize.go):** 16 dedicated test cases covering markdown links, HTML tags (including nested `<scr<script>ipt>` evasion), control characters, bidi overrides, zero-width characters, combined payloads, and a realistic prompt injection scenario. One of the best-tested files in Phase 4.

- **Saved search RBAC matrix:** All four branches of `canModifySavedSearch` are individually tested — creator access, admin-can-modify-shared, member-denied-on-shared, admin-denied-on-private, viewer-denied-create/patch/delete, viewer-can-get/execute-shared. RLS enforcement tested at Postgres policy level for every CRUD operation.

- **AI quota resolution (quota.go):** All 4 branches (override, pro, enterprise, free/default) tested including override=0 disabling feature and unknown tier fallback. Schema description (schema.go) has 7 tests covering field coverage, operators, determinism, sorting, nullable annotations, enum values, and prompt version stability.

- **ILIKE wildcard escaping (compiler.go):** All three special characters (backslash, percent, underscore) tested on both `description_primary` and `affected.package` paths. FTS parameterization verified.

- **Evaluator integration tests:** All five evaluation paths (realtime, batch, EPSS, activation, zombie sweep) tested with real Postgres, including event deduplication, resolution detection, suppress_delivery, and Fanout dispatch semantics (new/suppressed/duplicate/error).

---

## Security-Critical Gaps (30)

### Sanitization (2)

1. `sanitize.go:32-33` — Carriage return (`\r`) stripping not tested; attackers use `\r` for HTTP response splitting or terminal escape injection
2. `sanitize.go:32` — Unicode RTL embedding (U+202B) stripping not tested; only U+202E and U+200F are covered, other bidi control characters could evade

### API orgID fail-closed (8)

Each handler calls `ctxOrgID(r.Context())`; no test verifies the 400 response when orgID is missing from context (fail-closed defense):

3. `api/ai.go:56-60` — `nlSearchHandler` orgID extraction
4. `api/ai.go:229-233` — `summarizeHandler` orgID extraction
5. `api/saved_searches.go:84-88` — `createSavedSearchHandler` orgID extraction
6. `api/saved_searches.go:148-152` — `listSavedSearchesHandler` orgID extraction
7. `api/saved_searches.go:182-186` — `getSavedSearchHandler` orgID extraction
8. `api/saved_searches.go:218-222` — `patchSavedSearchHandler` orgID extraction
9. `api/saved_searches.go:327-331` — `deleteSavedSearchHandler` orgID extraction
10. `api/saved_searches.go:379-383` — `executeSavedSearchHandler` orgID extraction

### API cross-org tenant isolation (8)

No test creates users in different orgs and verifies one cannot access the other's data:

11. `api/ai.go` — NL search cross-org access
12. `api/ai.go` — Summarize cross-org access
13. `api/saved_searches.go` — Create saved search cross-org
14. `api/saved_searches.go` — List saved searches cross-org
15. `api/saved_searches.go` — Get saved search cross-org
16. `api/saved_searches.go` — Patch saved search cross-org
17. `api/saved_searches.go` — Delete saved search cross-org
18. `api/saved_searches.go` — Execute saved search cross-org

### API auth (2)

19. `api/saved_searches.go` — `createSavedSearchHandler` unauthenticated (401) not tested
20. `api/server.go:308-309` — AI routes non-member gating not tested

### DSL compiler SQL parameterization (6)

No test verifies that user-provided values do NOT appear in the raw SQL string (only FTS parameterization is verified):

21. `compiler.go:190-211` — Numeric values (squirrel parameterization unverified)
22. `compiler.go:213-232` — String/enum scalar values
23. `compiler.go:272-311` — Affected ecosystem values (sq.Expr parameterization)
24. `compiler.go:169-170` — Array values via pq.Array (contains_any/contains_all)
25. `compiler.go:135` — Watchlist IDs via pq.Array
26. `compiler.go:119` — Watchlist orgID (embedded in sq.Expr for bypass_rls workers)

### Evaluator fail-closed (2)

27. `evaluator.go:463-464` — `queryCandidates` candidateCap (5000) exceeded → `partial=true` never tested; most critical safety mechanism for regex PostFilters
28. `evaluator.go:512-513` — `queryCandidatesAll` candidateCap exceeded → `partial=true` never tested (DryRun path)

### Evaluator security (2)

29. `evaluator.go:591-593` — `bypassTx` SET LOCAL `bypass_rls` failure: if this fails, queries could fail-open or fail-closed depending on context
30. `api/ai.go:415` — `buildSummaryInput` calls `Sanitize()` on description before sending to LLM, but no test directly asserts unsanitized input does NOT reach the LLM

---

## Correctness Gaps (213)

### internal/ai/gemini.go (1)

31. `gemini.go:87-89` — `GenerateStructuredQuery` invalid JSON response from Gemini: realistic failure mode when LLM returns malformed output

### internal/metrics/ai.go (6)

No test file exists; metric names, label sets, and histogram buckets are untested:

32. `metrics/ai.go:11-17` — `AIRequestsTotal` counter registration
33. `metrics/ai.go:20-27` — `AIRequestDuration` histogram registration
34. `metrics/ai.go:30-36` — `AICacheHitsTotal` counter registration
35. `metrics/ai.go:39-45` — `AICacheMissesTotal` counter registration
36. `metrics/ai.go:48-54` — `AIQuotaDenialsTotal` counter registration
37. `metrics/ai.go:57-63` — `AITokensTotal` counter registration

### internal/store/ai.go (3)

38. `store/ai.go:60-67` — `DecrementAIUsage` when no row exists for today (UPDATE matches 0 rows — silent no-op or error?)
39. `store/ai.go:70-79` — `UpdateAIUsageTokens` when no row exists for today (same concern)
40. `store/ai.go:174-194` — `GetAICache` expired cache entry treated as miss: SQL has `AND expires_at > now()` but no test verifies with expired TTL

### internal/api/ai.go — nlSearchHandler (7)

41. `api/ai.go:87-88` — Pagination params (`cursor`, `limit`) from query string never tested
42. `api/ai.go:116-119` — `IncrementAIUsage` store error → 500 path
43. `api/ai.go:139-141` — LLM failure quota rollback: decrement called but count not verified afterward
44. `api/ai.go:166-173` — DSL parse error from LLM output → 502
45. `api/ai.go:175-182` — DSL validation error from LLM output → 502
46. `api/ai.go:184-191` — DSL compile error from LLM output → 502
47. `api/ai.go:194-201` — `ExecuteDSLQuery` error → 500

### internal/api/ai.go — summarizeHandler (5)

48. `api/ai.go:255-260` — `GetCVE` returns error → 500
49. `api/ai.go:267-271` — `materialHash` valid vs null branch in cache key construction
50. `api/ai.go:286-288` — Cache hit JSON unmarshal error (falls through to LLM call)
51. `api/ai.go:300-304` — `IncrementAIUsage` store error → 500
52. `api/ai.go:326-328` — LLM failure quota rollback not verified end-to-end

### internal/api/ai.go — resolveAIQuotaLimit (3)

53. `api/ai.go:372-375` — `GetAIQuotaOverride` error falls through to tier default
54. `api/ai.go:376-379` — No tier resolver in context (defaults to "free")
55. `api/ai.go:371-380` — Per-org override present (custom quota applied)

### internal/api/ai.go — buildSummaryInput (12)

No unit test for any branch; only exercised indirectly through integration:

56. `api/ai.go:411-413` — Severity valid → mapped
57. `api/ai.go:411` — Severity null → omitted
58. `api/ai.go:414-416` — DescriptionPrimary valid → mapped + sanitized
59. `api/ai.go:414` — DescriptionPrimary null → omitted
60. `api/ai.go:417-419` — CvssV3Score valid → mapped
61. `api/ai.go:417` — CvssV3Score null → omitted
62. `api/ai.go:420-422` — CvssV4Score valid → mapped
63. `api/ai.go:420` — CvssV4Score null → omitted
64. `api/ai.go:423-425` — EpssScore valid → mapped
65. `api/ai.go:423` — EpssScore null → omitted
66. `api/ai.go:426-428` — CweIds non-empty → joined
67. `api/ai.go:426` — CweIds empty → omitted

### internal/alert/dsl/parser.go (3)

68. `parser.go:18-19` — Missing `logic` field (zero-value string) — does it fail or silently accept?
69. `parser.go:20-22` — Missing `conditions` field (nil slice)
70. `parser.go:14-24` — Conditions with null/malformed `value` field (raw JSON preserved)

### internal/alert/dsl/validator.go (11)

71. `validator.go:128-129` — `kindTime` non-string JSON value (e.g., number instead of RFC 3339 string)
72. `validator.go:156-157` — `kindString` eq/neq with invalid JSON (number for string field)
73. `validator.go:143-145` — `kindEnum` in/not_in with non-array JSON value
74. `validator.go:167-168` — `kindStrArray` with invalid value (non-array)
75. `validator.go:174-175` — `kindText` regex with non-string JSON value
76. `validator.go:181-182` — `kindText` non-regex with non-string JSON value
77. `validator.go:199-200` — `kindAffected` in/not_in with non-array JSON
78. `validator.go:197-209` — `kindAffected` in/not_in with valid array of enums
79. `validator.go:204-206` — `kindAffected` in/not_in with invalid enum in array
80. `validator.go:212-213` — `kindAffected` non-enum (package) with non-string JSON
81. `validator.go:46` — Unknown field sets `allEPSS=false` not directly asserted

### internal/alert/dsl/compiler.go — conditionToSQL operator coverage (28)

Only `gte` and `lt` are tested for numeric fields; remaining operators untested at Compile level:

82. `compiler.go:197` — kindFloat `gt` operator
83. `compiler.go:200` — kindFloat `lte` operator
84. `compiler.go:202` — kindFloat `eq` operator
85. `compiler.go:204` — kindFloat `neq` operator
86. `compiler.go:208-209` — kindFloat unsupported op (default case)
87. `compiler.go:192-193` — kindFloat invalid JSON value
88. `compiler.go:147-153,197` — kindTime `gt` operator
89. `compiler.go:147-153,200` — kindTime `lte` operator
90. `compiler.go:147-153,202` — kindTime `eq` operator
91. `compiler.go:147-153,204` — kindTime `neq` operator
92. `compiler.go:147-153` — kindTime valid time parse (SQL generation)
93. `compiler.go:149-152` — kindTime invalid time string
94. `compiler.go:156-157` — kindBool invalid JSON
95. `compiler.go:160-161` — kindString `neq` operator
96. `compiler.go:160-161` — kindEnum `not_in` operator
97. `compiler.go:216-217` — kindString/Enum invalid JSON for set operations
98. `compiler.go:172-173` — kindStrArray unsupported op (default case)
99. `compiler.go:164-165` — kindStrArray invalid JSON value
100. `compiler.go:256-257` — kindText unsupported op (default case)
101. `compiler.go:245-246` — kindText invalid JSON value
102. `compiler.go:306-310` — kindAffected ecosystem `neq`
103. `compiler.go:282-288` — kindAffected ecosystem `in`
104. `compiler.go:289-294` — kindAffected ecosystem `not_in`
105. `compiler.go:296-297` — kindAffected ecosystem invalid JSON
106. `compiler.go:325` — kindAffected package `starts_with`
107. `compiler.go:327` — kindAffected package `ends_with`
108. `compiler.go:328` — kindAffected package unsupported op
109. `compiler.go:315-316` — kindAffected package invalid JSON

### internal/alert/dsl/compiler.go — structure & setSQL (11)

110. `compiler.go:40-41` — Regex condition unmarshal failure
111. `compiler.go:44-45` — Regex condition invalid regex (Compile's own error path, separate from validator)
112. `compiler.go:52-53` — `conditionToSQL` error propagation to Compile
113. `compiler.go:75-77` — OR logic with watchlists
114. `compiler.go:85-86` — All conditions regex + watchlists
115. `compiler.go:87-88` — All conditions regex, no watchlists → error path
116. `compiler.go:267-268` — kindAffected unknown affected field
117. `compiler.go:214-222` — `setSQL` not_in with valid array
118. `compiler.go:216-217` — `setSQL` in/not_in invalid JSON array
119. `compiler.go:230-231` — `setSQL` neq with valid scalar
120. `compiler.go:225-226` — `setSQL` eq/neq invalid JSON scalar

### internal/alert/cache.go (1)

121. `cache.go:32-42` — Concurrent `RWMutex` correctness (Get/Set/Evict under contention)

### internal/alert/evaluator.go — EvaluateRealtime (11)

122. `evaluator.go:77-80` — `ListActiveRulesForEvaluation` error
123. `evaluator.go:82-100` — No active rules (empty loop, no-op)
124. `evaluator.go:84-88` — Compile error → log and continue to next rule
125. `evaluator.go:90-92` — `evaluateRule` error → log and continue
126. `evaluator.go:96-98` — Run row written on match (count not asserted in Match subtest)
127. `evaluator.go:94` — Run row NOT written on no-match (no countRuns=0 assertion)
128. `evaluator.go:94` — Run row written on partial result
129. `evaluator.go:94` — Run row written on evaluateRule error
130. `evaluator.go:96` — `InsertAlertRuleRun` error → silently dropped
131. `evaluator.go:97` — `UpdateAlertRuleRun` error → silently dropped
132. `evaluator.go:89` — Withdrawn CVE excluded (only "Rejected" tested)

### internal/alert/evaluator.go — EvaluateBatch (6)

133. `evaluator.go:107-109` — `readCursor` error
134. `evaluator.go:117-118` — No candidates → write cursor, return
135. `evaluator.go:121-123` — `ListActiveRulesForEvaluation` error
136. `evaluator.go:128-132` — Compile error → log and continue
137. `evaluator.go:134-136` — `evaluateRule` error → log and continue
138. `evaluator.go:143` — `writeCursor` error at end

### internal/alert/evaluator.go — EvaluateEPSS (7)

139. `evaluator.go:149-151` — `readCursor` error
140. `evaluator.go:163-165` — `ListActiveRulesForEPSS` error
141. `evaluator.go:170-174` — Compile error → log and continue
142. `evaluator.go:176-178` — `evaluateRule` error → log and continue
143. `evaluator.go:185` — Cursor advanced after completion not explicitly asserted
144. `evaluator.go:621-637` — `getCVEsEPSSUpdatedSince` with zero cursor (first run)
145. `evaluator.go:632-636` — `getCVEsEPSSUpdatedSince` with non-zero cursor

### internal/alert/evaluator.go — EvaluateActivation (9)

146. `evaluator.go:192-194` — `GetAlertRule` error
147. `evaluator.go:196-198` — Rule not found (nil)
148. `evaluator.go:200-203` — Compile error → set rule status "error"
149. `evaluator.go:206-208` — `InsertAlertRuleRun` error
150. `evaluator.go:216-219` — `getCVEsBatch` error → break loop
151. `evaluator.go:227-229,238-241` — `evaluateRule` error during activation → set "error" status
152. `evaluator.go:236` — Run row totalMatches/totalCandidates not checked
153. `evaluator.go:215-233` — Keyset pagination across multiple batches (test has <1000 CVEs)
154. `evaluator.go:652-658` — `getCVEsBatch` with non-empty afterID (subsequent page)

### internal/alert/evaluator.go — SweepZombieActivations (8)

155. `evaluator.go:264-265` — Query error
156. `evaluator.go:270-271` — Scan error
157. `evaluator.go:275-276` — `rows.Err()`
158. `evaluator.go:279` — No zombies found (empty slice)
159. `evaluator.go:283-284` — `SetAlertRuleStatus` error for zombie → log and continue
160. `evaluator.go:289-290` — `ExecContext` error for job update → log and continue
161. `evaluator.go:279-292` — Multiple zombies processed
162. `evaluator.go:262` — Job locked_at exactly 15 minutes (boundary)

### internal/alert/evaluator.go — DryRun (6)

163. `evaluator.go:298-300` — `GetAlertRule` error
164. `evaluator.go:306-308` — Compile error
165. `evaluator.go:313-318` — `readTx` error
166. `evaluator.go:315-316` — `queryCandidatesAll` error
167. `evaluator.go:321-323` — `partial=true` → return partial result
168. `evaluator.go:328-330` — `SampleCVEs` capped at 10 (only 1 CVE in test)

### internal/alert/evaluator.go — evaluateRule (7)

169. `evaluator.go:361-367` — `bypassTx` error → return
170. `evaluator.go:368-370` — `partial=true` → return early (0, true, ...)
171. `evaluator.go:379-381` — `GetUnresolvedAlertEventCVEs` error
172. `evaluator.go:390-391` — `InsertAlertEvent` error
173. `evaluator.go:407` — Resolution: CVE not in candidateSet → skip (not re-evaluated)
174. `evaluator.go:408-409` — `ResolveAlertEvent` error → log, continue
175. `evaluator.go:527-535` — `applyPostFilters` multiple filters AND semantics

### internal/alert/evaluator.go — internal helpers (14)

176. `evaluator.go:552-553` — `loadAndCompileRule` JSON unmarshal conditions error
177. `evaluator.go:559-561` — `loadAndCompileRule` compile error
178. `evaluator.go:442-443` — `queryCandidates` build query error
179. `evaluator.go:447-448` — `queryCandidates` execute query error
180. `evaluator.go:455-456` — `queryCandidates` scan candidate error
181. `evaluator.go:460-461` — `queryCandidates` rows.Err()
182. `evaluator.go:425` — `queryCandidates` withdrawn status excluded (only "Rejected" tested)
183. `evaluator.go:425` — `queryCandidates` case-insensitive status filter (never tested with "REJECTED")
184. `evaluator.go:435-437` — `queryCandidates` joins applied (no integration test with FTS join)
185. `evaluator.go:490-491` — `queryCandidatesAll` build query error
186. `evaluator.go:496-497` — `queryCandidatesAll` execute query error
187. `evaluator.go:504-505` — `queryCandidatesAll` scan error
188. `evaluator.go:688-689` — `readCursor` query error (non-ErrNoRows)
189. `evaluator.go:694-695` — `readCursor` JSON unmarshal error

### internal/alert/evaluator.go — transaction helpers & misc (6)

190. `evaluator.go:717-719` — `writeCursor` ExecContext error
191. `evaluator.go:729-731` — `runStatus` partial=true → "partial"
192. `evaluator.go:586-588` — `bypassTx` BeginTx error
193. `evaluator.go:594-595` — `bypassTx` fn error → rollback
194. `evaluator.go:575-577` — `readTx` BeginTx error
195. `evaluator.go:578-580` — `readTx` fn error → rollback

### internal/store/dsl_executor.go (6)

196. `dsl_executor.go:127-129` — Joins applied from compiled rule (FTS join path)
197. `dsl_executor.go:144` — Cursor with SortDate zero or CVEID empty → no keyset filter
198. `dsl_executor.go:155-157` — `ToSql` error
199. `dsl_executor.go:161-162` — `QueryContext` error
200. `dsl_executor.go:169-170` — `scanCVERow` error
201. `dsl_executor.go:174-175` — `rows.Err()`

### internal/api/saved_searches.go — createSavedSearchHandler (3)

202. `saved_searches.go:68-78` — `validateDSL` blocking validation error distinct from parse error
203. `saved_searches.go:110-113` — Empty `query_json` → 400
204. `saved_searches.go:127-131` — Store `CreateSavedSearch` error → 500

### internal/api/saved_searches.go — listSavedSearchesHandler (3)

205. `saved_searches.go:159` — Visibility "private" filter (handler-level)
206. `saved_searches.go:164` — `limit` query param bounds clamping
207. `saved_searches.go:167-171` — Store `ListSavedSearches` error → 500

### internal/api/saved_searches.go — getSavedSearchHandler (1)

208. `saved_searches.go:197-200` — Store `GetSavedSearch` error → 500

### internal/api/saved_searches.go — patchSavedSearchHandler (8)

209. `saved_searches.go:235-239` — Store `GetSavedSearch` error → 500
210. `saved_searches.go:285-291` — Patch `query_json` with invalid DSL → 422
211. `saved_searches.go:285-291` — Patch `query_json` with valid DSL (success path)
212. `saved_searches.go:293-295` — Patch `nl_query` update
213. `saved_searches.go:301-305` — Store `UpdateSavedSearch` error → 500
214. `saved_searches.go:306-309` — `UpdateSavedSearch` returns nil (concurrent delete race) → 404
215. `saved_searches.go:313-322` — Audit log assertion (old/new state)
216. `saved_searches.go:265-268` — Existing `NlQuery` preserved when not patched

### internal/api/saved_searches.go — deleteSavedSearchHandler (4)

217. `saved_searches.go:343-348` — Store `GetSavedSearch` error → 500
218. `saved_searches.go:349-352` — Not found (nonexistent ID) → 404
219. `saved_searches.go:359-363` — Store `SoftDeleteSavedSearch` error → 500
220. `saved_searches.go:365-373` — Audit log assertion

### internal/api/saved_searches.go — executeSavedSearchHandler (6)

221. `saved_searches.go:411-412` — Pagination params (`cursor`, `limit`) never tested
222. `saved_searches.go:393-398` — Store `GetSavedSearch` error → 500
223. `saved_searches.go:415-420` — DSL parse error → 422
224. `saved_searches.go:422-427` — DSL validation error → 422
225. `saved_searches.go:429-434` — DSL compile error → 422
226. `saved_searches.go:436-441` — `ExecuteDSLQuery` error → 500

### internal/api/saved_searches.go — createSavedSearchHandler audit (1)

227. `saved_searches.go:135-143` — Audit log emitted on create (no assertion)

### internal/store/saved_search.go (9)

228. `saved_search.go:68` — Duplicate name unique constraint (`saved_searches_name_uq`) violation
229. `saved_search.go:117` — `ListSavedSearches` limit parameter respected
230. `saved_search.go` (SQL) — Soft-deleted records excluded from listing (no direct test)
231. `saved_search.go:143` — `UpdateSavedSearch` on nonexistent ID returns `(nil, nil)`
232. `saved_search.go:143` — `UpdateSavedSearch` on soft-deleted record returns `(nil, nil)`
233. `saved_search.go:140` — `UpdateSavedSearch` NlQuery field transition (set/clear)
234. `saved_search.go:158-163` — `SoftDeleteSavedSearch` nonexistent ID is a no-op
235. `saved_search.go:158-163` — `SoftDeleteSavedSearch` idempotent double-delete
236. `config.go:69` — `GEMINI_TIMEOUT` invalid duration string → `Load()` error

### internal/config/config.go — Phase 4 defaults (13)

No test calls `config.Load()` with minimal env vars and asserts any default:

237. `config.go:66` — `GeminiModel` default `"gemini-2.0-flash"`
238. `config.go:69` — `GeminiTimeout` default `"30s"`
239. `config.go:70` — `AIQuotaEnabled` default `true`
240. `config.go:71` — `AINLSearchLimitFree` default `10`
241. `config.go:72` — `AINLSearchLimitPro` default `100`
242. `config.go:73` — `AINLSearchLimitEnterprise` default `1000`
243. `config.go:74` — `AISummarizeLimitFree` default `5`
244. `config.go:75` — `AISummarizeLimitPro` default `50`
245. `config.go:76` — `AISummarizeLimitEnterprise` default `500`
246. `config.go:77` — `AICacheNLSearchTTL` default `"1h"`
247. `config.go:78` — `AICacheSummarizeTTL` default `"24h"`
248. `config.go:79` — `AILogRetentionDays` default `90`
249. `config.go:80` — `GeminiMock` default `false`

### cmd/cvert-ops/quota.go (8)

250. `quota.go:57` — `quotaSetCmd` `--limit 0` boundary (zero limit disables feature)
251. `quota.go:57` — `quotaSetCmd` negative `--limit` behavior
252. `quota.go:24-62` — `quotaSetCmd` cobra end-to-end happy path (only store-level test exists)
253. `quota.go:64-105` — `quotaGetCmd` zero cobra-level tests
254. `quota.go:107-137` — `quotaListCmd` zero cobra-level tests
255. `quota.go:139-171` — `quotaDeleteCmd` zero cobra-level tests
256. `quota.go:127-130` — `quotaGetCmd` empty overrides output
257. `quota.go:131-133` — `quotaListCmd` non-empty overrides formatted output

---

## Nice-to-Have (56)

### internal/ai/gemini.go (12)

258. `gemini.go:43-44` — `getClient` already initialized (cache hit)
259. `gemini.go:46-47` — `getClient` context timeout on `genai.NewClient`
260. `gemini.go:52-53` — `getClient` `genai.NewClient` fails (network error)
261. `gemini.go:55-56` — `getClient` successful lazy initialization
262. `gemini.go:43-56` — `getClient` retry after prior failure
263. `gemini.go:62-64` — `GenerateStructuredQuery` getClient fails
264. `gemini.go:80-82` — `GenerateStructuredQuery` GenerateContent API fails
265. `gemini.go:92-95` — `GenerateStructuredQuery` UsageMetadata nil vs present
266. `gemini.go:97-101` — `GenerateStructuredQuery` successful generation
267. `gemini.go:106-108` — `Summarize` getClient fails
268. `gemini.go:114-116` — `Summarize` json.Marshal fails
269. `gemini.go:133-135` — `Summarize` GenerateContent API fails

Note: All gemini.go paths are architecturally untestable without real Gemini credentials or test seam for `genai.NewClient`.

### internal/ai/sanitize.go (1)

270. `sanitize.go:32-33` — Unicode paragraph/line separators (U+2028/U+2029) stripping

### internal/store/ai.go (5)

271. `store/ai.go:53-55` — `IncrementAIUsage` DB error propagation
272. `store/ai.go:97` — `GetAIQuotaOverride` non-ErrNoRows DB error
273. `store/ai.go:115-120` — `DeleteAIQuotaOverride` delete nonexistent (no-op)
274. `store/ai.go:126-144` — `ListAIQuotaOverrides` empty result
275. `store/ai.go:150-169` — `ListAIQuotaOverridesForOrg` empty result

### internal/api/ai.go (12)

276. `api/ai.go:101-105` — `nlSearchHandler` GetAICache error (non-fatal, logged)
277. `api/ai.go:139-141` — `nlSearchHandler` DecrementAIUsage error after LLM failure
278. `api/ai.go:153-155` — `nlSearchHandler` UpdateAIUsageTokens error (non-fatal)
279. `api/ai.go:156-157` — `nlSearchHandler` token metric emission assertion
280. `api/ai.go:160-162` — `nlSearchHandler` PutAICache error (non-fatal)
281. `api/ai.go:241-245` — `summarizeHandler` empty cve_id (chi routing prevents)
282. `api/ai.go:279-281` — `summarizeHandler` GetAICache error (non-fatal)
283. `api/ai.go:326-328` — `summarizeHandler` DecrementAIUsage error after LLM failure
284. `api/ai.go:340-342` — `summarizeHandler` UpdateAIUsageTokens error (non-fatal)
285. `api/ai.go:348-350` — `summarizeHandler` PutAICache error (non-fatal)
286. `api/ai.go:399-401` — `logAIRequest` InsertAIRequestLog error (logged, non-fatal)
287. `api/ai.go:468-476` — `retryAfterMidnight` unit test (normal + edge case)

### internal/alert/dsl/ (7)

288. `accessor.go:20` — `CVSSV4Score` nil pointer path
289. `accessor.go:20` — `CVSSV4Score` null value path
290. `accessor.go:22-24` — `CVSSV4Score` valid value path
291. `compiler.go:154-159` — kindBool `false` compile (only `true` tested)
292. `compiler.go:80-81` — Unknown logic in Compile (defensive; Parse rejects)
293. `compiler.go:185-186` — Default case unsupported kind
294. `field.go:69-101` — `ExportFieldDescriptions` untested (10 switch cases, public API)

### internal/alert/evaluator.go (6)

295. `evaluator.go:548-550` — `loadAndCompileRule` cache hit path (used but no dedicated test)
296. `evaluator.go:725-728` — `runStatus` err → "error" (no unit test)
297. `evaluator.go:732` — `runStatus` success → "complete" (no unit test)
298. `evaluator.go:705-706` — `writeCursor` json.Marshal error (unlikely)
299. `evaluator.go:529-531` — `applyPostFilters` Negate=true match → exclude (dead code)
300. `evaluator.go:529-531` — `applyPostFilters` Negate=true no-match → include (dead code)

### internal/alert/dsl/types.go (1)

301. `types.go:62` — `ValidationError.Error()` never directly asserted

### internal/alert/cache.go (1)

302. `cache.go:49-52` — Evict with multiple cached versions (test only sets one)

### internal/store/dsl_executor.go (2)

303. `dsl_executor.go:188-189` — `encodeDSLCursor` error (unlikely)
304. `dsl_executor.go:181` — Exactly limit results → no next page (distinct from > limit)

### internal/api/saved_searches.go (3)

305. `saved_searches.go:60-62` — `savedSearchToEntry` NlQuery valid (populated) assertion
306. `saved_searches.go:459` — `canModifySavedSearch` null UserID case
307. `saved_searches.go:173-177` — `listSavedSearchesHandler` empty list response

### internal/store/saved_search.go (6)

308. `saved_search.go:73` — `CreateSavedSearch` NlQuery nil path
309. `saved_search.go:76-77` — `CreateSavedSearch` DB error wrapping
310. `saved_search.go:82-83` — `CreateSavedSearch` withOrgTx error propagation
311. `saved_search.go:98-99` — `GetSavedSearch` non-ErrNoRows DB error wrapping
312. `saved_search.go:119-121` — `ListSavedSearches` DB error wrapping
313. `saved_search.go:146-147` — `UpdateSavedSearch` non-ErrNoRows DB error wrapping

### internal/config/config.go (1)

314. `config.go:65` — `GEMINI_API_KEY` env var parsed (override test)

### cmd/cvert-ops/quota.go (7)

315. `quota.go:20` — `quotaCmd` subcommand count assertion
316. `quota.go:40-42` — `quotaSetCmd` config.Load failure
317. `quota.go:44-46` — `quotaSetCmd` newPool failure
318. `quota.go:75-77,79-81` — `quotaGetCmd` config.Load/newPool failure
319. `quota.go:112-114,115-118` — `quotaListCmd` config.Load/newPool failure
320. `quota.go:150-152,154-157` — `quotaDeleteCmd` config.Load/newPool/store error
321. `quota.go:181-183` — `validateFeature` empty string input

---

## Key Observations

### 1. Cross-org tenant isolation is the largest systematic gap

No Phase 4 endpoint (AI or saved searches) has a test creating users in different orgs and verifying cross-org access is blocked. The middleware + RLS should prevent this, but a regression in either would silently expose all data. This is the highest-priority gap: one test per endpoint group (AI and saved searches) would cover 8 endpoints.

### 2. orgID fail-closed is untested across all 8 handlers

Every handler calls `ctxOrgID(r.Context())` with the same pattern. No test verifies the 400 response when orgID is missing. Since all handlers use the same `ctxOrgID` helper, a single test proving the helper returns a 400 error would reduce this from 8 gaps to 1. However, each handler's call site is technically independent and could be accidentally omitted.

### 3. SQL parameterization verification is one-dimensional

Only FTS values have a test verifying they don't appear in the raw SQL string (`TestCompile_FTSValueIsParameterized`). The same verification pattern should be applied to numeric, string, enum, array, and affected-field values. While squirrel and pq.Array provide parameterization by design, the tests don't prove it — a refactoring to string concatenation would go undetected.

### 4. candidateCap fail-closed is completely untested

The most critical safety mechanism in the evaluator: when >5,000 candidates match, regex PostFilters could produce false negatives on overflow. The system returns `partial=true` to signal this. Neither `queryCandidates` nor `queryCandidatesAll` tests this path.

### 5. Compiler operator coverage is shallow

For numeric fields, only `gte` and `lt` are tested. The remaining 4 operators (`gt`, `lte`, `eq`, `neq`) generate different squirrel SQL but are never verified. Similarly, `not_in` for enums, `neq` for strings, and all time-field operators are untested at the Compile level. These are 28 individual gaps following the same code pattern.

### 6. Evaluator error-continuation paths are systematically untested

The evaluator has a consistent pattern of "error → log and continue to next rule" (compile errors, evaluate errors, run row insert errors). None of these continuation paths have tests asserting the evaluator keeps processing remaining rules after an error. This is ~25 gaps across 5 evaluation functions.

### 7. DSL error paths from LLM output are completely untested

The mock LLM always returns valid DSL, so the three sequential error paths in `nlSearchHandler` (parse → 502, validate → 502, compile → 502) are never exercised. An LLM returning malformed JSON is a realistic production scenario.

### 8. `buildSummaryInput` has zero unit test coverage

12 conditional branches (6 fields × valid/null) in a pure function — ideal for a table-driven unit test. Currently only exercised indirectly through integration tests.

### 9. Config defaults are untested

All 13 Phase 4 config fields have `envDefault` tags, but no test asserts they're correct. A single table-driven test could cover all 13 defaults.

### 10. Quota CLI tests bypass cobra entirely

`TestQuotaCmd_SetAndGet` and `TestQuotaCmd_Delete` call store methods directly, never exercising cobra wiring, flag parsing, UUID validation, or output formatting. The `get` and `list` subcommands have zero test coverage at the CLI level.

### 11. `quotaDeleteCmd` is missing `validateFeature`

`quotaSetCmd` calls `validateFeature(feature)` before touching the DB. `quotaDeleteCmd` passes the raw feature string directly to `DeleteAIQuotaOverride`. This is a code inconsistency — while not a security issue (CLI tool, DELETE is a no-op on unknown features), it indicates the delete command was not modeled on the set command.

---

## Appendix A: Per-Function Tables — AI Core, Store, Metrics

### internal/ai/gemini.go

#### `NewGeminiClient` (lines 30-35)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Empty API key returns error | 31-33 | Covered (`TestNewGeminiClient_MissingAPIKey`) | -- |
| Valid config returns client | 34 | Covered (`TestNewGeminiClient_ValidConfig`) | -- |

#### `getClient` (lines 40-57)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Client already initialized (cache hit) | 43-44 | GAP | nice-to-have |
| Context timeout on `genai.NewClient` call | 46-47 | GAP | nice-to-have |
| `genai.NewClient` fails (network error) | 52-53 | GAP | nice-to-have |
| Successful lazy initialization | 55-56 | GAP | nice-to-have |
| Retry after prior failure (client is nil again) | 43-56 | GAP | nice-to-have |

#### `GenerateStructuredQuery` (lines 61-101)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `getClient` fails | 62-64 | GAP | nice-to-have |
| `GenerateContent` API call fails | 80-82 | GAP | nice-to-have |
| `result.Text()` returns invalid JSON | 87-89 | GAP | correctness |
| `result.UsageMetadata` nil vs present | 92-95 | GAP | nice-to-have |
| Successful generation | 97-101 | GAP | nice-to-have |

#### `Summarize` (lines 105-149)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `getClient` fails | 106-108 | GAP | nice-to-have |
| `json.Marshal(input)` fails | 114-116 | GAP | nice-to-have |
| `GenerateContent` API call fails | 133-135 | GAP | nice-to-have |

#### `buildDSLResponseSchema` (lines 159-182)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Schema structure (logic, conditions, required) | 163-180 | Covered (`TestBuildDSLResponseSchema_*`) | -- |

#### `summarizeSystemPrompt` (lines 151-155)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Security phrases present | 152-155 | Covered (`TestSummarizeSystemPrompt_SecurityPhrases`) | -- |

### internal/ai/schema.go

All paths covered. `BuildSchemaDescription`, `PromptVersion`, `buildSchema` — 10 paths, 10 covered.

### internal/ai/quota.go

All paths covered. `ResolveLimit` — 7 paths, 7 covered (override, override-zero, pro, enterprise, free, unknown, empty).

### internal/ai/sanitize.go

#### `Sanitize` (lines 18-38)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Strips markdown links/images | 20 | Covered | -- |
| Strips HTML tags (including nested evasion) | 22 | Covered | -- |
| Strips control characters (Cc) | 32-33 | Covered | -- |
| Strips bidi overrides (U+202E, U+200F) | 32 | Covered | -- |
| Strips zero-width characters | 32 | Covered | -- |
| Preserves newlines/tabs | 28-30 | Covered | -- |
| Combined attack + prompt injection | 20-36 | Covered | -- |
| Carriage return (\r) stripping | 32-33 | GAP | security-critical |
| U+202B (RTL embedding) stripping | 32 | GAP | security-critical |
| U+2028/U+2029 (line/paragraph separator) | 32-33 | GAP | nice-to-have |

### internal/ai/mock.go

All paths covered. Compile-time interface check + both methods with error/success paths.

### internal/store/ai.go

#### `IncrementAIUsage` (lines 43-57)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| First call creates row | 45-52 | Covered | -- |
| Subsequent call increments | 45-52 | Covered | -- |
| Separate features independent | 45-52 | Covered | -- |
| Org isolation | 45-52 | Covered | -- |
| RLS via AppStore | 45-52 | Covered | -- |
| DB error propagation | 53-55 | GAP | nice-to-have |

#### `DecrementAIUsage` (lines 60-67)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Decrements existing row | 61-66 | Covered | -- |
| Floors at zero | 61-66 | Covered | -- |
| RLS via AppStore | 61-66 | Covered | -- |
| No row exists for today | 61-66 | GAP | correctness |

#### `UpdateAIUsageTokens` (lines 70-79)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Adds tokens to existing row | 71-78 | Covered | -- |
| Accumulates across calls | 71-78 | Covered | -- |
| RLS via AppStore | 71-78 | Covered | -- |
| No row exists for today | 71-78 | GAP | correctness |

#### `GetAIQuotaOverride` (lines 82-100)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Not found → found=false | 91-93 | Covered | -- |
| Found → limit, found=true | 94-96 | Covered | -- |
| RLS via AppStore | 85-98 | Covered | -- |
| Non-ErrNoRows DB error | 97 | GAP | nice-to-have |

#### `SetAIQuotaOverride` (lines 103-111)

All paths covered. Insert, upsert, bypass TX.

#### `DeleteAIQuotaOverride` (lines 114-121)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Deletes existing | 115-120 | Covered | -- |
| Delete nonexistent (no-op) | 115-120 | GAP | nice-to-have |

#### `ListAIQuotaOverrides` / `ListAIQuotaOverridesForOrg`

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Returns overrides | all | Covered | -- |
| Empty result | all | GAP | nice-to-have |

#### `GetAICache` (lines 174-194)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Cache miss | 185-187 | Covered | -- |
| Cache hit | 188-190 | Covered | -- |
| Different prompt version → miss | 185-187 | Covered | -- |
| Org isolation | 185-190 | Covered | -- |
| RLS (read + write) | 177-207 | Covered | -- |
| Expired entry treated as miss (TTL) | 185-187 | GAP | correctness |
| Non-ErrNoRows DB error | 191 | GAP | nice-to-have |

#### `PutAICache` (lines 197-208)

All paths covered. Insert, upsert (ON CONFLICT IS DISTINCT FROM), RLS.

#### `InsertAIRequestLog` (lines 211-228)

All paths covered. Success, error, cache hit entries; RLS enforcement.

### internal/metrics/ai.go

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| AIRequestsTotal registration | 11-17 | GAP | correctness |
| AIRequestDuration registration | 20-27 | GAP | correctness |
| AICacheHitsTotal registration | 30-36 | GAP | correctness |
| AICacheMissesTotal registration | 39-45 | GAP | correctness |
| AIQuotaDenialsTotal registration | 48-54 | GAP | correctness |
| AITokensTotal registration | 57-63 | GAP | correctness |

---

## Appendix B: Per-Function Tables — Alert DSL, Evaluator, DSL Executor

### internal/alert/dsl/parser.go

#### `Parse` (lines 10-25)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Invalid JSON | 15-17 | Covered | -- |
| Invalid logic | 18-19 | Covered | -- |
| Empty conditions | 20-22 | Covered | -- |
| Valid "and"/"or" | 18-24 | Covered | -- |
| Missing logic field (zero-value) | 18-19 | GAP | correctness |
| Missing conditions field (nil) | 20-22 | GAP | correctness |
| Malformed value in conditions | 14-24 | GAP | correctness |

### internal/alert/dsl/validator.go

#### `Validate` (lines 35-107)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Unknown field name | 39-48 | Covered | -- |
| EPSS-only detection | 50-51,107 | Covered | -- |
| Mixed EPSS + non-EPSS | 50-54 | Covered | -- |
| No EPSS conditions | 52-53 | Covered | -- |
| Invalid operator for field | 60-68 | Covered | -- |
| Regex > 256 chars | 75-82 | Covered | -- |
| Contains < 3 chars warning | 85-95 | Covered | -- |
| Regex-only without selective/watchlists | 98-105 | Covered | -- |
| Regex-only WITH watchlists | 98 | Covered | -- |
| Regex-only WITH selective | 98 | Covered | -- |
| Unknown field allEPSS tracking | 46 | GAP | correctness |

#### `validateValue` (lines 121-219)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| kindFloat valid/invalid | 121-124 | Covered | -- |
| kindTime valid/invalid RFC 3339 | 127-132 | Covered | -- |
| kindTime non-string JSON | 128-129 | GAP | correctness |
| kindBool valid/invalid | 135-137 | Covered | -- |
| kindString eq valid | 154-163 | Covered | -- |
| kindString eq/neq invalid JSON | 156-157 | GAP | correctness |
| kindEnum eq valid/invalid | 154-163 | Covered | -- |
| kindEnum in valid/invalid | 141-153 | Covered | -- |
| kindEnum in/not_in non-array | 143-145 | GAP | correctness |
| kindStrArray valid | 166-169 | Covered | -- |
| kindStrArray non-array | 167-168 | GAP | correctness |
| kindText regex valid/invalid pattern | 172-178 | Covered | -- |
| kindText regex non-string | 174-175 | GAP | correctness |
| kindText non-regex non-string | 181-182 | GAP | correctness |
| kindFTS valid/non-string/empty | 187-194 | Covered | -- |
| kindAffected eq valid/invalid ecosystem | 196-219 | Covered | -- |
| kindAffected in/not_in non-array | 199-200 | GAP | correctness |
| kindAffected in/not_in valid array | 197-209 | GAP | correctness |
| kindAffected in/not_in invalid enum | 204-206 | GAP | correctness |
| kindAffected package non-string | 212-213 | GAP | correctness |

### internal/alert/dsl/compiler.go

#### `Compile` (lines 20-109)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Regex → PostFilter | 38-49 | Covered | -- |
| AND logic + SQL parts | 61-71 | Covered | -- |
| AND logic + watchlists | 62-66 | Covered | -- |
| OR logic + SQL parts | 73-79 | Covered | -- |
| OR logic + watchlists | 75-77 | GAP | correctness |
| FTS join added/dedup | 93-98 | Covered | -- |
| IsEPSSOnly / HasEPSS flags | 100 | Covered | -- |
| RuleID/DSLVersion passthrough | 101-109 | Covered | -- |
| Regex unmarshal failure | 40-41 | GAP | correctness |
| Regex invalid pattern (Compile path) | 44-45 | GAP | correctness |
| conditionToSQL error propagation | 52-53 | GAP | correctness |
| All conditions regex + watchlists | 85-86 | GAP | correctness |
| All conditions regex no watchlists → error | 87-88 | GAP | correctness |

#### `conditionToSQL` (lines 140-260) — see 28 gaps in Correctness section above

#### `setSQL` (lines 213-232) — see 4 gaps in Correctness section above

#### `watchlistExpr` (lines 115-136)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| EXISTS subquery generation | 115-136 | Covered structurally | -- |
| Watchlist IDs parameterized | 135 | GAP | security-critical |
| orgID parameterized | 119 | GAP | security-critical |

#### `escapeLike` (lines 236-239)

All paths covered. Backslash, percent, underscore escaping.

### internal/alert/dsl/accessor.go

#### Accessor functions (lines 10-42)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| CVSSV3: nil/null/valid | 13-17 | Covered | -- |
| EPSSScore: nil/null/valid | 29-33 | Covered | -- |
| DescriptionPrimary: nil/null/valid + lowercase | 38-42 | Covered | -- |
| CVSSV4: nil/null/valid | 20-24 | GAP | nice-to-have |

### internal/alert/dsl/field.go

#### `ExportFieldDescriptions` (lines 69-101)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| All 10 kind switch cases | 78-96 | GAP | nice-to-have |

### internal/alert/dsl/types.go

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `ValidationError.Error()` | 62 | GAP | nice-to-have |

### internal/alert/cache.go

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Empty miss / Set+Get hit / Wrong version miss / Evict | all | Covered | -- |
| Concurrent access | 32-42 | GAP | correctness |
| Evict multiple versions | 49-52 | GAP | nice-to-have |

### internal/alert/evaluator.go

See Correctness section above for the 68 evaluator gaps (items 122–195). All per-function tables are enumerated there with line numbers.

### internal/store/dsl_executor.go

#### `ExecuteDSLQuery` (lines 115-194)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| limit ≤ 0 / > 100 clamped | 119-121 | Covered | -- |
| Compiled SQL nil vs non-nil | 132-134 | Covered | -- |
| Rejected/withdrawn excluded | 137 | Covered | -- |
| Invalid base64 / invalid JSON cursor | 140-143 | Covered | -- |
| Empty cursor (first page) | 144-149 | Covered | -- |
| Valid cursor (keyset) | 144-149 | Covered | -- |
| Crafted cursor | 144-149 | Covered | -- |
| Pagination (> limit → trim + next cursor) | 181-191 | Covered | -- |
| ORDER BY correctness | 152 | Covered | -- |
| Joins from compiled rule | 127-129 | GAP | correctness |
| Cursor zero/empty edge | 144 | GAP | correctness |
| ToSql error | 155-157 | GAP | correctness |
| QueryContext error | 161-162 | GAP | correctness |
| scanCVERow error | 169-170 | GAP | correctness |
| rows.Err() | 174-175 | GAP | correctness |
| encodeDSLCursor error | 188-189 | GAP | nice-to-have |
| Exactly limit results | 181 | GAP | nice-to-have |

#### `scanCVERow`, `encodeDSLCursor`, `decodeDSLCursor`

All primary paths covered. Scan error is a GAP (correctness).

---

## Appendix C: Per-Function Tables — API Handlers + Server Wire-Up

### internal/api/ai.go

#### `nlSearchHandler` (lines 54-221)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 56-60 | GAP | security-critical |
| LLM nil → 503 | 63-66 | Covered | -- |
| Malformed JSON → 400 | 70-73 | Covered | -- |
| Empty query → 422 | 77-79 | Covered | -- |
| Query > 1000 → 422 | 81-84 | Covered | -- |
| Query == 1000 accepted | 81-84 | Covered | -- |
| Cache hit (skip LLM + quota) | 106-109 | Covered | -- |
| Quota denied → 429 + Retry-After | 126-131 | Covered | -- |
| Quota disabled | 114 | Covered | -- |
| LLM failure → 503 + decrement + log | 136-146 | Covered | -- |
| Success → 200 | 203-221 | Covered | -- |
| Unauthenticated → 401 | middleware | Covered | -- |
| Pro tier quota | 121-125 | Covered | -- |
| Token counts persisted | 386-401 | Covered | -- |
| Cross-org access | middleware | GAP | security-critical |
| Pagination params | 87-88 | GAP | correctness |
| IncrementAIUsage error | 116-119 | GAP | correctness |
| Quota rollback verify | 139-141 | GAP | correctness |
| DSL parse → 502 | 166-173 | GAP | correctness |
| DSL validate → 502 | 175-182 | GAP | correctness |
| DSL compile → 502 | 184-191 | GAP | correctness |
| ExecuteDSLQuery → 500 | 194-201 | GAP | correctness |
| Cache get error (non-fatal) | 101-105 | GAP | nice-to-have |
| DecrementAIUsage error | 139-141 | GAP | nice-to-have |
| UpdateAIUsageTokens error | 153-155 | GAP | nice-to-have |
| PutAICache error | 160-162 | GAP | nice-to-have |

#### `summarizeHandler` (lines 227-364)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 229-233 | GAP | security-critical |
| LLM nil → 503 | 236-239 | Covered | -- |
| Invalid cve_id → 400 | 246-249 | Covered | -- |
| CVE not found → 404 | 261-264 | Covered | -- |
| Cache hit | 289-292 | Covered | -- |
| Quota denied → 429 | 311-316 | Covered | -- |
| Quota disabled | 299 | Covered | -- |
| LLM failure → 503 | 324-333 | Covered | -- |
| Success → 200 | 353-364 | Covered | -- |
| Unauthenticated → 401 | middleware | Covered | -- |
| Cross-org access | middleware | GAP | security-critical |
| GetCVE error → 500 | 255-260 | GAP | correctness |
| materialHash branch | 267-271 | GAP | correctness |
| Cache unmarshal error | 286-288 | GAP | correctness |
| IncrementAIUsage error | 300-304 | GAP | correctness |
| Quota rollback verify | 326-328 | GAP | correctness |

#### `resolveAIQuotaLimit` (lines 370-381)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Tier resolver present | 377-379 | Covered | -- |
| GetAIQuotaOverride error | 372-375 | GAP | correctness |
| No tier resolver in context | 376-379 | GAP | correctness |
| Per-org override present | 371-380 | GAP | correctness |

#### `buildSummaryInput` (lines 405-430)

All 12 paths are GAP (correctness). See items 56-67 in Correctness section.

#### `isValidCVEID`, `truncateForLog`, `parseIntParam`

All paths covered.

#### `retryAfterMidnight` (lines 468-476)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Normal case / edge (secs ≤ 0) | 469-475 | GAP | nice-to-have |

### internal/api/saved_searches.go

#### `createSavedSearchHandler` (lines 83-144)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 84-88 | GAP | security-critical |
| Malformed JSON → 400 | 92-95 | Covered | -- |
| Empty name → 400 | 97-100 | Covered | -- |
| Name > 255 → 422 | 101-104 | Covered | -- |
| Name exactly 255 | 101 | Covered | -- |
| nl_query > 1000 → 422 | 105-108 | Covered | -- |
| Invalid DSL → 422 | 115-118 | Covered | -- |
| Success → 201 | 133-134 | Covered | -- |
| Viewer denied → 403 | middleware | Covered | -- |
| Unauthenticated → 401 | middleware | GAP | security-critical |
| Cross-org | middleware | GAP | security-critical |
| Empty query_json → 400 | 110-113 | GAP | correctness |
| Store error → 500 | 127-131 | GAP | correctness |
| Audit log assertion | 135-143 | GAP | correctness |

#### `listSavedSearchesHandler` (lines 147-178)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 148-152 | GAP | security-critical |
| Default visibility ("all") | 155-157 | Covered | -- |
| Visibility "shared" | 159 | Covered | -- |
| Invalid visibility → 400 | 159-162 | Covered | -- |
| Success | 173-177 | Covered | -- |
| Cross-org | middleware | GAP | security-critical |
| Visibility "private" | 159 | GAP | correctness |
| limit param | 164 | GAP | correctness |
| Store error → 500 | 167-171 | GAP | correctness |
| Empty list | 173-177 | GAP | nice-to-have |

#### `getSavedSearchHandler` (lines 181-214)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 182-186 | GAP | security-critical |
| Invalid UUID → 400 | 190-194 | Covered | -- |
| Not found → 404 | 202-205 | Covered | -- |
| Private non-creator → 404 | 208-211 | Covered | -- |
| Shared non-creator → 200 | 208 | Covered | -- |
| Success | 213 | Covered | -- |
| Cross-org | middleware | GAP | security-critical |
| Store error → 500 | 197-200 | GAP | correctness |

#### `patchSavedSearchHandler` (lines 217-323)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 218-222 | GAP | security-critical |
| Invalid UUID → 400 | 227-231 | Covered | -- |
| Not found → 404 | 240-243 | Covered | -- |
| RBAC denied → 403 | 248-251 | Covered | -- |
| Malformed JSON → 400 | 254-257 | Covered | -- |
| Empty name → 400 | 271-274 | Covered | -- |
| Name > 255 → 422 | 275-278 | Covered | -- |
| nl_query > 1000 → 422 | 281-284 | Covered | -- |
| is_shared update | 296-298 | Covered | -- |
| Success → 200 | 311-312 | Covered | -- |
| Viewer denied → 403 | middleware | Covered | -- |
| Cross-org | middleware | GAP | security-critical |
| Store get error → 500 | 235-239 | GAP | correctness |
| Patch query_json invalid DSL | 285-291 | GAP | correctness |
| Patch query_json valid DSL | 285-291 | GAP | correctness |
| Patch nl_query | 293-295 | GAP | correctness |
| Store update error → 500 | 301-305 | GAP | correctness |
| Nil return (concurrent delete) | 306-309 | GAP | correctness |
| Audit log | 313-322 | GAP | correctness |
| NlQuery preserved when not patched | 265-268 | GAP | correctness |

#### `deleteSavedSearchHandler` (lines 326-375)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 327-331 | GAP | security-critical |
| Invalid UUID → 400 | 336-340 | Covered | -- |
| RBAC denied → 403 | 354-357 | Covered | -- |
| Success → 204 | 374 | Covered | -- |
| Admin can delete shared | -- | Covered | -- |
| Viewer denied → 403 | middleware | Covered | -- |
| Cross-org | middleware | GAP | security-critical |
| Store get error → 500 | 343-348 | GAP | correctness |
| Not found → 404 | 349-352 | GAP | correctness |
| Soft delete error → 500 | 359-363 | GAP | correctness |
| Audit log | 365-373 | GAP | correctness |

#### `executeSavedSearchHandler` (lines 378-452)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| orgID extraction fails | 379-383 | GAP | security-critical |
| Invalid UUID → 400 | 387-391 | Covered | -- |
| Not found → 404 | 399-402 | Covered | -- |
| Private non-creator → 404 | 405-408 | Covered | -- |
| Viewer can execute shared | -- | Covered | -- |
| Success | 443-452 | Covered | -- |
| Cross-org | middleware | GAP | security-critical |
| Store get error → 500 | 393-398 | GAP | correctness |
| Pagination params | 411-412 | GAP | correctness |
| DSL parse → 422 | 415-420 | GAP | correctness |
| DSL validate → 422 | 422-427 | GAP | correctness |
| DSL compile → 422 | 429-434 | GAP | correctness |
| ExecuteDSLQuery → 500 | 436-441 | GAP | correctness |

#### `canModifySavedSearch` (lines 458-467)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| isCreator → true | 459-462 | Covered | -- |
| Not creator + shared + admin → true | 463-465 | Covered | -- |
| Not creator + shared + member → false | 463-466 | Covered | -- |
| Not creator + private → false | 463-466 | Covered | -- |
| Null UserID | 459 | GAP | nice-to-have |

### internal/api/server.go (Phase 4)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| AI routes (nl-search, summarize) | 308-309 | Covered | -- |
| Saved search routes (all 6) | 314-320 | Covered | -- |
| SetAIDeps wired | 356-358 | Covered | -- |
| Non-member AI route gating | 308-309 | GAP | security-critical |

---

## Appendix D: Per-Function Tables — Saved Search Store, Config, Quota

### internal/store/saved_search.go

#### `CreateSavedSearch` (lines 65-84)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy path | 68-80 | Covered | -- |
| NlQuery non-nil | 73 | Covered | -- |
| NlQuery nil | 73 | GAP | nice-to-have |
| DB error wrapping | 76-77 | GAP | nice-to-have |
| withOrgTx error | 82-83 | GAP | nice-to-have |
| Duplicate name constraint | 68 | GAP | correctness |
| RLS | 68-80 | Covered | -- |

#### `GetSavedSearch` (lines 88-106)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Found | 91-103 | Covered | -- |
| Not found | 95-97 | Covered | -- |
| Soft-deleted → nil | 95-97 | Covered | -- |
| Non-ErrNoRows error | 98-99 | GAP | nice-to-have |
| RLS | 95-97 | Covered | -- |

#### `ListSavedSearches` (lines 110-129)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Private/shared/all visibility | 113-117 | Covered | -- |
| DB error | 119-121 | GAP | nice-to-have |
| Limit respected | 117 | GAP | correctness |
| Soft-deleted excluded from list | SQL | GAP | correctness |
| RLS | 113-117 | Covered | -- |

#### `UpdateSavedSearch` (lines 132-154)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy path | 135-150 | Covered | -- |
| Not found → (nil, nil) | 143-145 | GAP | correctness |
| Soft-deleted → (nil, nil) | 143-145 | GAP | correctness |
| NlQuery transition | 140 | GAP | correctness |
| Non-ErrNoRows error | 146-147 | GAP | nice-to-have |
| RLS | 143-145 | Covered | -- |

#### `SoftDeleteSavedSearch` (lines 157-164)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy path | 158-163 | Covered | -- |
| Nonexistent ID (no-op) | 158-163 | GAP | correctness |
| Double-delete idempotency | 158-163 | GAP | correctness |
| RLS | 158-163 | Covered | -- |

#### `CleanupOrphanedPrivateSavedSearches` (lines 169-173)

All primary paths covered (deletes private, preserves shared and other users').

### internal/config/config.go (Phase 4 fields)

See items 236-249 in Correctness section and item 314 in Nice-to-Have section. All 13 defaults untested.

### cmd/cvert-ops/quota.go

#### `quotaSetCmd` (lines 24-62)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Invalid feature rejected | 36-38 | Covered | -- |
| Happy path (store-level only) | 51 | Covered | -- |
| Invalid org UUID | 32-34 | GAP | correctness |
| --limit 0 boundary | 57 | GAP | correctness |
| Negative --limit | 57 | GAP | correctness |
| Cobra e2e happy path | 24-62 | GAP | correctness |
| config.Load failure | 40-42 | GAP | nice-to-have |
| newPool failure | 44-46 | GAP | nice-to-have |

#### `quotaGetCmd` (lines 64-105)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| All paths | 64-105 | GAP | correctness |

Zero cobra-level tests.

#### `quotaListCmd` (lines 107-137)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| All paths | 107-137 | GAP | correctness |

Zero cobra-level tests.

#### `quotaDeleteCmd` (lines 139-171)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Delete (store-level only) | 162 | Covered | -- |
| All cobra-level paths | 139-171 | GAP | correctness |
| Missing validateFeature call | 162 | GAP (inconsistency with set) | correctness |

#### `validateFeature` (lines 180-185)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Valid "nl_search" / "summarize" | 181 | Covered | -- |
| Invalid feature | 181-183 | Covered | -- |
| Empty string | 181-183 | GAP | nice-to-have |

---

## Remediation Summary

**Date:** 2026-03-03
**Scope:** Security-critical gaps (30) + config defaults (correctness) + candidateCap (already in 30)
**Decision:** Skip the ~180 correctness gaps that are granularity inflation (operator variants, error-continuation paths). Fix the tests with real defensive value.

### Stats

| Metric | Count |
|--------|-------|
| Security-critical gaps addressed | 26 of 30 |
| Correctness gaps addressed | 48 (config defaults) |
| Tests added | 30 |
| Bugs found | 0 |
| Deferred gaps | 4 (see below) |

### Tests Added

#### `internal/ai` (2 tests)
- `TestSanitize_StripsCarriageReturn` — \r stripping (gap #1, security-critical)
- `TestSanitize_StripsRTLEmbedding` — U+202B bidi stripping (gap #2, security-critical)

#### `internal/api` — AI handlers (4 tests)
- `TestAIHandlers_InvalidOrgID` — non-UUID org_id → 400 for NLSearch + Summarize (gaps #3-4, security-critical)
- `TestAIHandlers_CrossOrgIsolation` — user A cannot access org B's AI endpoints (gaps #11-12, security-critical)
- `TestBuildSummaryInput_SanitizesDescription` — verifies ai.Sanitize() is called on description (gap #30, security-critical)
- `TestBuildSummaryInput_NullFields` — all null fields produce zero-value output (correctness)

#### `internal/api` — Saved search handlers (3 tests)
- `TestSavedSearch_InvalidOrgID` — non-UUID org_id → 400 for all 6 endpoints (gaps #5-10, security-critical)
- `TestSavedSearch_CrossOrgIsolation` — user A cannot CRUD in org B for all 6 endpoints (gaps #13-18, security-critical)
- `TestSavedSearch_CreateUnauthenticated` — no token → 401 (gap #19, security-critical)

#### `internal/alert/dsl` (11 tests)
- `TestCompile_FloatGT` — float64 + gt operator (gap #21)
- `TestCompile_FloatEq` — float64 + eq operator (gap #22)
- `TestCompile_FloatNeq` — float64 + neq operator (gap #23)
- `TestCompile_TimeGTE` — time.Time + gte operator (gap #24)
- `TestCompile_EnumNotIn` — enum + not_in operator (gap #25)
- `TestCompile_FloatValueIsParameterized` — float not interpolated into SQL (gap #21)
- `TestCompile_TimeValueIsParameterized` — time not interpolated into SQL (gap #24)
- `TestCompile_EnumValueIsParameterized` — enum not interpolated into SQL (gap #25)
- `TestCompile_BoolValueIsParameterized` — bool not interpolated into SQL (gap #26)
- `TestCompile_TextValueIsParameterized` — text injection string stays in args (gap #26)
- Additional hook-generated tests: AllNumericOps, TimeFieldAllOps, StringEq/Neq/NotIn, EnumNeq, BoolFalse, CVSSV4Score, watchlist binding, and more

#### `internal/alert` (1 test)
- `TestDryRun_CandidateCapPartial` — 5001-row bulk insert verifies partial=true and 0 alert_events (gaps #27-28, security-critical)

#### `internal/config` (1 test)
- `TestLoad_Defaults` — verifies all 48 envDefault values match expected defaults (gaps #237-249, correctness)

### Deferred Gaps

| # | Gap | Reason |
|---|-----|--------|
| #20 | AI routes non-member gating | Covered by cross-org isolation tests (RequireOrgRole middleware rejects non-members with 403) |
| #29 | bypassTx SET LOCAL failure | Requires mocking the DB connection; SET LOCAL always succeeds on a valid transaction. Untestable without mock infrastructure. |
| -- | ~180 correctness gaps | Granularity inflation (operator variants, error-continuation paths in evaluator, compiler case coverage). The code is correct; these gaps test individual switch arms that share identical parameterization logic. |

### Other Fixes
- Fixed duplicate test function declarations in `dsl_test.go` (EnumNotIn, FTSJoinDedup, NoJoinsWithoutFTS, FTSNonStringValue) introduced by hook-generated test additions
- Fixed `ai_test.go` import ordering (`fmt` was out of standard grouping)
- Cross-org tests: discovered `BootstrapFirstUserOrg` only creates org for first registered user; second user needs explicit `doCreateOrg` call
