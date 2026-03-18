# Phase 4 Store Layer — Test Coverage Review

**Date:** 2026-03-03
**Scope:** `internal/store/ai.go`, `internal/store/saved_search.go`, associated test files, SQL query files
**Reviewer:** Claude

---

## File: `internal/store/ai.go`

### Function: `IncrementAIUsage` (lines 43-57)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Happy path: first increment (row created via ON CONFLICT INSERT) | 43-57 | Covered (`TestIncrementAIUsage_CreatesAndIncrements`) | — |
| 2 | Happy path: subsequent increment (ON CONFLICT DO UPDATE) | 43-57 | Covered (`TestIncrementAIUsage_CreatesAndIncrements`) | — |
| 3 | Separate features have independent counters | 43-57 | Covered (`TestIncrementAIUsage_SeparateFeatures`) | — |
| 4 | Cross-org counters are independent | 43-57 | Covered (`TestAIUsage_OrgIsolation`) | — |
| 5 | Error from `withOrgTx` (e.g., DB down) — returns `(0, err)` | 53-55 | GAP | nice-to-have |
| 6 | RLS enforcement: AppStore call with wrong orgID returns error / 0 rows | 45 | GAP | security-critical |

### Function: `DecrementAIUsage` (lines 60-67)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Decrement existing row to 0 | 60-67 | Covered (`TestDecrementAIUsage_FloorsAtZero`) | — |
| 2 | Decrement below 0 — GREATEST floors at 0 | 60-67 | Covered (`TestDecrementAIUsage_FloorsAtZero`) | — |
| 3 | Decrement when no row exists for today (no-op UPDATE matching 0 rows) | 60-67 | GAP | correctness |
| 4 | RLS enforcement via AppStore | 61 | GAP | security-critical |

### Function: `UpdateAIUsageTokens` (lines 70-79)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Happy path: add tokens to existing row | 70-79 | Covered (`TestUpdateAIUsageTokens`) | — |
| 2 | Token accumulation (multiple calls) | 70-79 | Covered (`TestUpdateAIUsageTokens`) | — |
| 3 | Update when no row exists (no-op UPDATE matching 0 rows) | 70-79 | GAP | correctness |
| 4 | Verification of accumulated token totals (no read-back assertion) | 70-79 | GAP | correctness |
| 5 | RLS enforcement via AppStore | 71 | GAP | security-critical |

### Function: `GetAIQuotaOverride` (lines 82-100)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Override not found — returns `(0, false, nil)` | 91-93 | Covered (`TestGetAIQuotaOverride_NotFound`) | — |
| 2 | Override found — returns `(limit, true, nil)` | 94-96 | Covered (`TestSetAndGetAIQuotaOverride`) | — |
| 3 | DB error (non-ErrNoRows) — returns wrapped error | 97 | GAP | nice-to-have |
| 4 | RLS enforcement via AppStore (org A reading org B's override) | 85 | GAP | security-critical |

### Function: `SetAIQuotaOverride` (lines 103-111)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Insert new override | 103-111 | Covered (`TestSetAndGetAIQuotaOverride`) | — |
| 2 | Upsert existing override (ON CONFLICT DO UPDATE) | 103-111 | Covered (`TestSetAndGetAIQuotaOverride`) | — |
| 3 | Uses `withBypassTx` (not org-scoped) — correct for CLI/admin path | 104 | Covered (structural) | — |

### Function: `DeleteAIQuotaOverride` (lines 114-121)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Delete existing override | 114-121 | Covered (`TestDeleteAIQuotaOverride`) | — |
| 2 | Delete non-existent override (no-op DELETE) | 114-121 | GAP | nice-to-have |

### Function: `ListAIQuotaOverrides` (lines 124-145)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Returns overrides from multiple orgs | 124-145 | Covered (`TestListAIQuotaOverrides`) | — |
| 2 | Empty list (no overrides set) | 124-145 | GAP | nice-to-have |
| 3 | Error from inner query — returns `(nil, err)` | 128-129, 141-143 | GAP | nice-to-have |

### Function: `ListAIQuotaOverridesForOrg` (lines 148-170)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Returns overrides for specific org, ordered by feature | 148-170 | Covered (`TestListAIQuotaOverridesForOrg`) | — |
| 2 | Empty list (no overrides for org) | 148-170 | GAP | nice-to-have |
| 3 | Error from inner query — returns `(nil, err)` | 153-154, 166-168 | GAP | nice-to-have |

### Function: `GetAICache` (lines 174-194)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Cache miss (no row) — returns `(nil, false, nil)` | 185-187 | Covered (`TestGetAICache_Miss`) | — |
| 2 | Cache hit — returns `(response, true, nil)` | 188-190 | Covered (`TestPutAndGetAICache`) | — |
| 3 | Different prompt version = cache miss | 174-194 | Covered (`TestGetAICache_DifferentPromptVersion`) | — |
| 4 | **Expired TTL returns cache miss** (SQL `WHERE expires_at > now()`) | 185 | GAP | correctness |
| 5 | DB error (non-ErrNoRows) — returns wrapped error | 191 | GAP | nice-to-have |
| 6 | Cross-org cache isolation | 174-194 | Covered (`TestAICache_OrgIsolation`) | — |
| 7 | RLS enforcement via AppStore | 177 | GAP | security-critical |

### Function: `PutAICache` (lines 197-208)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Insert new cache entry | 197-208 | Covered (`TestPutAndGetAICache`) | — |
| 2 | Upsert existing entry (ON CONFLICT DO UPDATE) | 197-208 | Covered (`TestPutAICache_Upsert`) | — |
| 3 | Upsert skipped when response+expires_at identical (IS DISTINCT FROM) | 197-208 | GAP | correctness |
| 4 | RLS enforcement via AppStore | 198 | GAP | security-critical |

### Function: `InsertAIRequestLog` (lines 211-228)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Success entry with tokens | 211-228 | Covered (`TestInsertAIRequestLog`) | — |
| 2 | Error entry with error_type | 211-228 | Covered (`TestInsertAIRequestLog`) | — |
| 3 | Cache hit entry (zero tokens → NULL via toNullInt32) | 211-228 | Covered (`TestInsertAIRequestLog`) | — |
| 4 | RLS enforcement via AppStore | 212 | GAP | security-critical |

### Function: `toNullInt32` (lines 232-237)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Zero → NULL | 233-234 | Covered (via `TestInsertAIRequestLog` cache-hit entry) | — |
| 2 | Non-zero → Valid | 236 | Covered (via `TestInsertAIRequestLog` success entry) | — |

### Function: `toNullString` (lines 240-245)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Empty → NULL | 241-242 | Covered (via `TestInsertAIRequestLog` success entry, no ErrorType) | — |
| 2 | Non-empty → Valid | 244 | Covered (via `TestInsertAIRequestLog` error entry) | — |

---

## File: `internal/store/saved_search.go`

### Function: `CreateSavedSearch` (lines 65-84)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Happy path: private search with NlQuery | 65-84 | Covered (`TestSavedSearch_Create`) | — |
| 2 | Shared search creation | 65-84 | Covered (indirectly via `TestSavedSearch_List_Shared` setup) — but this is a setup step, not an assertion on create fields for shared. However `TestSavedSearch_Create` fully validates fields, and shared is tested in update. Counting as covered. | — |
| 3 | NlQuery = nil (NULL) | 73 | GAP | nice-to-have |
| 4 | Duplicate name within same (org, user) violates unique index | 65-84 | GAP | correctness |
| 5 | DB error on insert — returns `(nil, err)` | 76-77 | GAP | nice-to-have |
| 6 | RLS enforcement via AppStore | 67 | GAP | security-critical |

### Function: `GetSavedSearch` (lines 88-106)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Found — returns row | 100-103 | Covered (`TestSavedSearch_Get`) | — |
| 2 | Not found (ErrNoRows) — returns `(nil, nil)` | 95-97 | Covered (`TestSavedSearch_Get_NotFound`) | — |
| 3 | Soft-deleted row not visible | 95-97 | Covered (`TestSavedSearch_SoftDelete`) | — |
| 4 | DB error (non-ErrNoRows) — returns wrapped error | 98-99 | GAP | nice-to-have |
| 5 | Cross-org isolation: org A cannot GET org B's search | 90-91 | GAP | security-critical |
| 6 | RLS enforcement via AppStore | 90 | GAP | security-critical |

### Function: `ListSavedSearches` (lines 110-129)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | visibility="private" — returns only caller's private searches | 110-129 | Covered (`TestSavedSearch_List_Private`) | — |
| 2 | visibility="shared" — returns all shared searches in org | 110-129 | Covered (`TestSavedSearch_List_Shared`) | — |
| 3 | visibility="all" — returns caller's private + all shared | 110-129 | Covered (`TestSavedSearch_List_Visibility_Filter`) | — |
| 4 | User1 cannot see User2's private searches (via "all") | 110-129 | Covered (`TestSavedSearch_List_Visibility_Filter` — user2 sees 2, not 3) | — |
| 5 | **Invalid visibility string (e.g., "bogus")** — CASE ELSE matches `(is_shared = true OR user_id = @user_id)`, same as "all" | 110-129 | GAP | correctness |
| 6 | Soft-deleted searches excluded from list | 110-129 | GAP | correctness |
| 7 | Empty result set | 110-129 | GAP | nice-to-have |
| 8 | Limit enforcement | 110-129 | GAP | nice-to-have |
| 9 | Cross-org isolation: searches in org B not visible when listing org A | 110-129 | GAP | security-critical |
| 10 | RLS enforcement via AppStore | 112 | GAP | security-critical |

### Function: `UpdateSavedSearch` (lines 132-154)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Happy path: update all fields | 132-154 | Covered (`TestSavedSearch_Update`) | — |
| 2 | Not found (ErrNoRows) — returns `(nil, nil)` | 143-145 | GAP | correctness |
| 3 | Soft-deleted row — UPDATE matches 0 rows (WHERE deleted_at IS NULL) | 143-145 | GAP | correctness |
| 4 | DB error (non-ErrNoRows) — returns wrapped error | 146-147 | GAP | nice-to-have |
| 5 | Cross-org: updating a search from another org returns nil | 134-135 | GAP | security-critical |
| 6 | RLS enforcement via AppStore | 134 | GAP | security-critical |

### Function: `SoftDeleteSavedSearch` (lines 157-164)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Happy path: marks as deleted | 157-164 | Covered (`TestSavedSearch_SoftDelete`) | — |
| 2 | Already soft-deleted row (no-op, WHERE deleted_at IS NULL) | 157-164 | GAP | nice-to-have |
| 3 | Non-existent ID (no-op) | 157-164 | GAP | nice-to-have |
| 4 | Cross-org: cannot soft-delete another org's search | 158-159 | GAP | security-critical |
| 5 | RLS enforcement via AppStore | 158 | GAP | security-critical |

### Function: `CleanupOrphanedPrivateSavedSearches` (lines 169-173)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | Deletes user's private searches, keeps shared | 169-173 | Covered (`TestSavedSearch_CleanupOrphanedPrivate`) | — |
| 2 | Does not affect other users' searches | 169-173 | Covered (`TestSavedSearch_CleanupOrphanedPrivate`) | — |
| 3 | User with no private searches (no-op) | 169-173 | GAP | nice-to-have |
| 4 | Uses bypassTx (no org context) — correct for worker path | 170 | Covered (structural) | — |

### Function: `savedSearchFromGenerated` (lines 49-62)

| # | Code Path | Line(s) | Test Status | Severity |
|---|-----------|---------|-------------|----------|
| 1 | All fields mapped correctly | 49-62 | Covered (implicitly via all CRUD tests that read back fields) | — |

---

## SQL Query Files

### `queries/ai_usage.sql`

| # | Query | Key Logic | Test Status | Severity |
|---|-------|-----------|-------------|----------|
| 1 | `IncrementAIUsage` — ON CONFLICT (org_id, feature, date) DO UPDATE count + 1 | Upsert behavior | Covered | — |
| 2 | `DecrementAIUsage` — GREATEST(count - 1, 0) | Floor at zero | Covered | — |
| 3 | `DecrementAIUsage` — WHERE date = CURRENT_DATE | Only today's row affected | GAP (no test for yesterday's row being untouched) | correctness |
| 4 | `UpdateAIUsageTokens` — WHERE date = CURRENT_DATE | Only today's row | GAP (no test proving no-op when no row exists) | correctness |
| 5 | `SetAIQuotaOverride` — ON CONFLICT DO UPDATE daily_limit | Upsert | Covered | — |
| 6 | Feature CHECK constraint: only 'nl_search' or 'summarize' | DB rejects invalid features | GAP | correctness |

### `queries/ai_cache.sql`

| # | Query | Key Logic | Test Status | Severity |
|---|-------|-----------|-------------|----------|
| 1 | `GetAICache` — WHERE expires_at > now() | TTL expiry filtering | GAP (no test with expired TTL) | correctness |
| 2 | `PutAICache` — ON CONFLICT with IS DISTINCT FROM guard | Skip-update optimization | GAP (no test proving no-op on identical data) | correctness |
| 3 | `PutAICache` — `make_interval(secs => $6)` TTL computation | TTL duration to timestamp | Covered (implicit; cache hit works after put with 1h TTL) | — |

### `queries/ai_request_log.sql`

| # | Query | Key Logic | Test Status | Severity |
|---|-------|-----------|-------------|----------|
| 1 | `InsertAIRequestLog` — nullable columns (input_tokens, output_tokens, error_type) | NULL handling | Covered | — |
| 2 | Feature CHECK constraint: only 'nl_search' or 'summarize' | DB rejects invalid features | GAP | correctness |
| 3 | Status CHECK constraint: only 'success' or 'error' | DB rejects invalid status | GAP | correctness |

### `queries/saved_searches.sql`

| # | Query | Key Logic | Test Status | Severity |
|---|-------|-----------|-------------|----------|
| 1 | `ListSavedSearches` — CASE/WHEN visibility routing | Three branches tested | Covered | — |
| 2 | `ListSavedSearches` — ELSE branch on invalid visibility | Falls through to "all" behavior | GAP (no test with invalid visibility string) | correctness |
| 3 | `ListSavedSearches` — ORDER BY updated_at DESC | Ordering | GAP (no assertion on ordering) | nice-to-have |
| 4 | `ListSavedSearches` — LIMIT @result_limit | Result capping | GAP | nice-to-have |
| 5 | `UpdateSavedSearch` — WHERE deleted_at IS NULL | Prevents updating deleted row | GAP | correctness |
| 6 | `SoftDeleteSavedSearch` — WHERE deleted_at IS NULL | Idempotency | GAP | nice-to-have |
| 7 | `CleanupOrphanedPrivateSavedSearches` — hard DELETE, no soft-delete | Permanent removal | Covered | — |
| 8 | Unique partial index `saved_searches_name_uq` — (org_id, user_id, name) WHERE deleted_at IS NULL | Duplicate name rejection | GAP | correctness |

---

## What's Well-Covered

- **AI usage counter lifecycle**: The increment/decrement/separate-features flow is thoroughly tested including the GREATEST(0) floor for decrement, with proper assertions on returned counts.
- **AI cache basic CRUD + org isolation**: Cache miss, hit, upsert, different prompt version, and cross-org isolation are all directly tested with assertions.
- **Saved search visibility filtering**: The three visibility modes (private/shared/all) are well-tested across multiple users, proving that user1 cannot see user2's private searches within the same org.

---

## Summary of Gaps by Severity

### Security-Critical: 14 gaps

All 14 are the same root cause: **no Phase 4 store test uses `s.AppStore` (the NOBYPASSRLS connection)**. Every test runs via the embedded `*store.Store` superuser, which bypasses RLS entirely. This means:

1. `IncrementAIUsage` — no RLS test (ai.go:45)
2. `DecrementAIUsage` — no RLS test (ai.go:61)
3. `UpdateAIUsageTokens` — no RLS test (ai.go:71)
4. `GetAIQuotaOverride` — no RLS test (ai.go:85)
5. `GetAICache` — no RLS test (ai.go:177)
6. `PutAICache` — no RLS test (ai.go:198)
7. `InsertAIRequestLog` — no RLS test (ai.go:212)
8. `GetSavedSearch` — no cross-org test and no RLS test (saved_search.go:90)
9. `ListSavedSearches` — no cross-org test and no RLS test (saved_search.go:112)
10. `UpdateSavedSearch` — no cross-org test and no RLS test (saved_search.go:134)
11. `SoftDeleteSavedSearch` — no cross-org test and no RLS test (saved_search.go:158)
12. `CreateSavedSearch` — no RLS test (saved_search.go:67)

Note: The `TestAIUsage_OrgIsolation` and `TestAICache_OrgIsolation` tests prove logical isolation (different org_id parameters return independent data), but they do NOT prove RLS enforcement because they run as superuser. A misconfigured RLS policy would not be caught.

### Correctness: 14 gaps

1. `DecrementAIUsage` when no row exists for today (ai.go:60-67)
2. `UpdateAIUsageTokens` when no row exists (ai.go:70-79) — silently no-ops
3. `UpdateAIUsageTokens` — no read-back verification of accumulated totals (ai.go:70-79)
4. `GetAICache` with expired TTL — the critical cache-miss-on-expiry path is untested (ai_cache.sql:7)
5. `PutAICache` IS DISTINCT FROM skip-update optimization untested (ai_cache.sql:14-15)
6. `DecrementAIUsage` SQL WHERE date = CURRENT_DATE — no test that yesterday's row is unaffected (ai_usage.sql:14)
7. `UpdateAIUsageTokens` SQL WHERE date = CURRENT_DATE — same as above (ai_usage.sql:20)
8. Feature CHECK constraint not tested on any AI table (ai_usage.sql:8, ai_request_log.sql:8)
9. Status CHECK constraint not tested on ai_request_log (ai_request_log.sql:18)
10. `ListSavedSearches` invalid visibility string falls through to "all" behavior (saved_searches.sql:21)
11. `ListSavedSearches` soft-deleted searches excluded (saved_searches.sql:16)
12. `UpdateSavedSearch` not-found path returns `(nil, nil)` (saved_search.go:143-145)
13. `UpdateSavedSearch` on soft-deleted row (saved_searches.sql:34)
14. Duplicate name unique index `saved_searches_name_uq` — no test proves it rejects duplicates (migration 000024)

### Nice-to-Have: 14 gaps

1. `IncrementAIUsage` error propagation (ai.go:53-55)
2. `DeleteAIQuotaOverride` on non-existent row (ai.go:114-121)
3. `ListAIQuotaOverrides` empty result (ai.go:124-145)
4. `ListAIQuotaOverrides` error propagation (ai.go:128-129)
5. `ListAIQuotaOverridesForOrg` empty result (ai.go:148-170)
6. `ListAIQuotaOverridesForOrg` error propagation (ai.go:153-154)
7. `GetAIQuotaOverride` DB error (non-ErrNoRows) (ai.go:97)
8. `GetAICache` DB error (non-ErrNoRows) (ai.go:191)
9. `CreateSavedSearch` with NlQuery=nil (saved_search.go:73)
10. `CreateSavedSearch` DB error (saved_search.go:76-77)
11. `GetSavedSearch` DB error (non-ErrNoRows) (saved_search.go:98-99)
12. `UpdateSavedSearch` DB error (saved_search.go:146-147)
13. `SoftDeleteSavedSearch` already-deleted or non-existent (saved_search.go:157-164)
14. `CleanupOrphanedPrivateSavedSearches` with no matching rows (saved_search.go:169-173)

---

## Key Observations

### 1. Systemic RLS Testing Gap (Security-Critical Pattern)
Every Phase 4 test calls methods on the embedded superuser `*store.Store`. Other phases (alert rules, watchlists, invitations, groups, API keys) have dedicated `AppStore` RLS tests in `org_tx_test.go`. Phase 4 has zero such tests. The existing `TestAIUsage_OrgIsolation` and `TestAICache_OrgIsolation` tests prove application-level isolation (passing different org_id values yields different data) but do NOT exercise Postgres RLS policies. If the RLS policy on `ai_usage_counters`, `ai_cache`, `ai_request_log`, or `saved_searches` were misconfigured or missing, these tests would still pass.

**Recommendation:** Add `AppStore`-based RLS tests for all four Phase 4 tables to `org_tx_test.go`, following the established pattern (e.g., `TestListOrgGroups_AppStoreRLS`, `TestGroup_RLSFailClosed`).

### 2. Missing Expired TTL Cache Test (Correctness — High Priority)
The `GetAICache` SQL query filters on `expires_at > now()`. There is no test that puts a cache entry with a very short TTL (or past expiry), waits, and asserts a cache miss. This is the entire point of the cache TTL mechanism and is the single most important correctness gap. Since `PutAICache` uses `make_interval(secs => $6)`, a test could use a negative or zero TTL, or use `time.Nanosecond` and `time.Sleep`, to verify expiry behavior.

### 3. No-Op UPDATE Paths Are Invisible
`DecrementAIUsage` and `UpdateAIUsageTokens` use `WHERE date = CURRENT_DATE`. If no row exists for today (e.g., user never incremented), the UPDATE matches 0 rows and silently succeeds. This is by design (`:exec` queries don't return affected row counts), but there's no test proving this silent no-op behavior is intentional and safe.

### 4. Invalid Visibility String Is a Soft Fail-Open
The `ListSavedSearches` SQL CASE/WHEN has an `ELSE` branch that maps to `(is_shared = true OR user_id = @user_id)` — the same as "all". An invalid visibility string like `"bogus"` silently returns the broadest result set. If the handler pre-validates, this is harmless, but the store layer itself does not reject invalid input.

### 5. Unique Index on Saved Search Names Is Untested
Migration 000024 adds a partial unique index `saved_searches_name_uq ON saved_searches (org_id, user_id, name) WHERE deleted_at IS NULL`. No test proves this constraint works (i.e., that creating two searches with the same name for the same user in the same org returns a DB error). This is also relevant for understanding what error the store returns on duplicate names.

### 6. CHECK Constraints on AI Tables Are Untested
The `ai_usage_counters`, `ai_cache`, and `ai_request_log` tables all have CHECK constraints on `feature` (only 'nl_search' or 'summarize'). The `ai_request_log` also constrains `status` to 'success' or 'error'. No test verifies that the DB rejects invalid values. If the handler pre-validates, this is defense-in-depth, but the store layer's behavior on constraint violation is unknown.
