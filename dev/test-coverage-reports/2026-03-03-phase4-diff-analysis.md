# Phase 4 Test Coverage Review — Diff Analysis

**Date:** 2026-03-03
**Purpose:** Compare original review (pre-remediation) vs fresh post-remediation review to measure what a second pass catches that the first missed, and identify skill improvement opportunities.

---

## Scope Differences

| Aspect | Original | Post-Remediation |
|--------|----------|-----------------|
| Scope includes `cmd/cvert-ops/main.go` | Yes (20 nice-to-have) | No (not in scope list) |
| Scope includes `cmd/cvert-ops/main.go validateConfig` | Yes (7 security-critical) | No |
| Review runs merged | 2 runs merged (R1 + R2) | 1 fresh run |
| Post-remediation context | N/A | 69 tests added, 3 bugs fixed |

**Impact:** ~27 gaps from the original are out-of-scope in the post-remediation run. The comparison below adjusts for this where relevant.

---

## Headline Numbers

| Severity | Original | Post-Remediation | Delta | Notes |
|----------|----------|-----------------|-------|-------|
| Security-Critical | 51 | 30 | -21 (-41%) | 37 original gaps fixed; 16 new gaps found |
| Correctness | 71 | 213 | +142 (+200%) | Granularity explosion, not quality regression |
| Nice-to-Have | 61 | 56 | -5 (-8%) | Scope reduction + some promoted to correctness |
| **Total** | **183** | **299** | **+116 (+63%)** | Net: deeper review, not worse code |

---

## Security-Critical: What Changed

### Gaps FIXED by remediation (37 from original, now covered)

| Area | Count | What was fixed |
|------|-------|----------------|
| Sanitizer regex bug + attack vectors | 10 | Bug fixed, 11 tests added (nested HTML, entities, bidi, images, prompt injection) |
| Gemini security config (zero-tool, prompts) | 6 | `TestSummarizeSystemPrompt_SecurityPhrases`, `TestBuildDSLResponseSchema_*` |
| RBAC canModifySavedSearch branches | 4 | Admin/member/non-creator tests added |
| Store RLS via AppStore | 12 | 12 `_AppStoreRLS` tests added across 4 tables |
| Config validateConfig + LogValue | 5 | JWT secret, HTTPS, masked secrets tests |
| Input validation (JSON, cursors) | 5 | Malformed JSON, base64, crafted cursor tests |
| DSL/FTS security | 4 | FTS parameterization, escapeLike, cursor tampering |

### Gaps NOT found by post-remediation that were in original (0 unfixed)

All 37 fixed gaps are correctly absent from the post-remediation report. No false negatives.

### NEW security-critical gaps found by post-remediation (16)

These are gaps the ORIGINAL REVIEW MISSED entirely:

| # | Gap | Why the original missed it |
|---|-----|---------------------------|
| 1-2 | Sanitize \r and U+202B stripping | Original found U+202E/U+200F but stopped; didn't enumerate all bidi/control chars |
| 3-10 | orgID fail-closed for all 8 handlers | Original classified as 1 correctness item (#41); post-remediation escalated to 8 security-critical |
| 11-18 | Cross-org API tenant isolation (8 endpoints) | Original only flagged store-level RLS, completely missed API-level cross-org testing |
| 19 | createSavedSearch unauthenticated (401) | Original didn't flag unauthenticated tests for saved searches |
| 20 | AI routes non-member gating | Original didn't check route-level role enforcement |
| 21-26 | SQL parameterization for 6 value types | Original only verified FTS and ILIKE; didn't ask "are ALL value types parameterized?" |
| 27-28 | candidateCap fail-closed (2 paths) | Original barely reviewed evaluator internals |
| 29 | bypassTx SET LOCAL failure | Original didn't review evaluator transaction helpers |
| 30 | buildSummaryInput Sanitize() assertion | Original flagged this (#10) but remediation may not have fully addressed it |

### Key insight: The original review was better at finding REAL BUGS

The original found 3 genuine defects:
1. Sanitizer regex didn't handle `![alt](url)` (prompt injection vector)
2. `SearchCVEs` FTS JOIN alias mismatch (latent query bug)
3. Test flakiness from IP rate limiter interference

The post-remediation found 0 real bugs — all 30 security-critical items are "missing tests for correct code." This suggests **the first pass has a bug-finding advantage** because it reviews unvalidated code, while the second pass reviews code that's already been through one round of scrutiny.

---

## Correctness: Why the Count Tripled (71 → 213)

### Granularity differences (accounts for ~120 of the 142 increase)

| Area | Original Count | Post-Rem Count | Cause |
|------|---------------|----------------|-------|
| Evaluator error paths | 5 | 68 | Original mapped 5 evaluation paths; post-remediation mapped every error branch in every internal function |
| Compiler operator variants | 2 | 39 | Original said "conditionToSQL kindFTS"; post-remediation listed gt/lte/eq/neq × each field type |
| buildSummaryInput branches | 1 | 12 | Original: "all nil/valid branches"; post-remediation: each field × valid/null |
| Validator edge cases | 1 | 11 | Original: "fts_query selective"; post-remediation: non-string JSON per kind, non-array for in/not_in |
| Parser edge cases | 0 | 3 | Original didn't flag missing logic/conditions fields |
| Transaction helpers | 0 | 6 | Original didn't review bypassTx/readTx error paths |
| SweepZombieActivations | 0 | 8 | Original didn't review zombie sweep at all |

### Genuinely new correctness findings (not granularity)

These are areas the original SHOULD have flagged but didn't:

1. **Config defaults (13 gaps):** No test asserts any envDefault value is correct. Original flagged this as 1 item (#68: "default values never verified"); post-remediation enumerated all 13.

2. **Saved search not-found/idempotency (6 gaps):** Update on nonexistent ID, update on soft-deleted, double soft-delete, nonexistent soft-delete. Original had 2 of these (#51, #52); post-remediation found 4 more.

3. **Cache TTL expiry (1 gap):** Both reviews found this. Post-remediation correctly re-flagged it.

4. **Quota CLI cobra-level tests (4 gaps):** Original had 1 item (#67: "quotaGetCmd, quotaListCmd, quotaDeleteCmd never exercised through cobra"). Post-remediation broke this into individual subcommand gaps plus limit boundary and formatting.

5. **Audit log assertions (3 gaps):** Post-remediation flagged that create/patch/delete saved search handlers emit audit logs but no test verifies them. Original didn't mention audit logging at all.

6. **PATCH query_json + nl_query (4 gaps):** Post-remediation found that no test ever PATCHes the query_json or nl_query fields. Original had 1 of these (#35: "patch with invalid DSL").

### Gaps from the original NOT re-found by post-remediation

1. **DB CHECK constraints** (2 gaps, original #47-48): Feature and status CHECK constraints on AI tables. Post-remediation didn't flag constraint testing at all.
2. **PutAICache IS DISTINCT FROM** (original #45): Post-remediation says this is "Covered (TestPutAICache_Upsert)" — the remediation test covered it.
3. **SavedSearch name/nl_query DB constraint violations** (original #55): Post-remediation found the unique name index (#228) but not the length constraint paths.
4. **SeedTestCVE infrastructure gap** (original observation #12): Infrastructure gap was fixed; post-remediation correctly doesn't flag it.
5. **withBypassTx guardrail** (original observation #11): No API route can call quota override methods — post-remediation didn't flag this architectural concern.
6. **config.IsDevelopment()** (original #69): Not flagged by post-remediation.
7. **mock.go prompt forwarding** (original nice-to-have): Not flagged by post-remediation.

---

## Nice-to-Have: Minor Changes

The post-remediation found 56 vs the original's 61. The difference is explained by:
- Scope reduction (no main.go = -14)
- Some items promoted to correctness (metrics: original=nice-to-have, post-remediation=correctness)
- Some new nice-to-have items found (retryAfterMidnight, ExportFieldDescriptions)

---

## Cross-Cutting Observations for Skill Improvement

### 1. Depth inconsistency is the biggest problem

The original review mapped 5 paths for `evaluator.go` (733 lines). The post-remediation mapped 83. That's a **16x difference** for the same file. The skill should enforce a minimum depth threshold — perhaps "a 700-line file with <20 mapped paths should be re-reviewed."

**Recommendation:** Add a sanity check formula: `paths mapped / source lines` should be >0.1 (1 path per 10 lines) for any file with complex logic. Flag files below this threshold for re-review.

### 2. Granularity of "one gap" is interpreted inconsistently

The skill says "each gap is ONE row" and gives the example "8 ctxOrgID failures = 8 gaps." But the first pass collapsed "buildSummaryInput nullable branches" into 1 item, while the second pass listed 12. The skill's example is clear for IDENTICAL patterns, but ambiguous for RELATED patterns.

**Recommendation:** Add examples distinguishing:
- **Same pattern, same code:** "8 handlers call ctxOrgID" = 8 gaps (each handler could independently fail)
- **Same function, different branches:** "buildSummaryInput has 6 nullable fields" = 12 gaps (valid/null for each) or 6 gaps (one per field)? Clarify which.
- **Same operator type, different field types:** "float gt, float lte, float eq" = 3 gaps? Or "float operators other than gte/lt" = 1 gap? The skill should specify.

### 3. Security checklist should be explicit, not emergent

The original found store-level RLS gaps but completely missed API-level cross-org testing. The post-remediation found cross-org but didn't flag DB CHECK constraints. Both reviews had blind spots.

**Recommendation:** Add a mandatory security checklist to the skill:
- [ ] Store RLS (AppStore/NOBYPASSRLS tests)
- [ ] API cross-org (user in org A cannot access org B's endpoints)
- [ ] API unauthenticated (every endpoint returns 401 without token)
- [ ] orgID fail-closed (handler returns error when orgID missing)
- [ ] SQL parameterization (verify user values don't appear in raw SQL)
- [ ] DB constraints (CHECK, UNIQUE, FK violations produce correct errors)
- [ ] Fail-closed defenses (candidateCap, bypass_rls, rate limits)

### 4. "Covered by remediation" vs "still a gap" boundary

The post-remediation found that `buildSummaryInput Sanitize() assertion` is still a gap (#30), even though the original flagged it (#10) and remediation added sanitizer tests. The issue is that remediation tested the sanitizer IN ISOLATION but didn't test that the handler CALLS the sanitizer. The skill should emphasize: "defense-in-depth means testing at EACH layer independently."

### 5. Bug-finding advantage of first reviews

The original found 3 real bugs. The post-remediation found 0. This suggests first reviews are better at catching actual defects (unvalidated code has more bugs), while subsequent reviews are better at catching MISSING TESTS (the code is correct but unproven). The skill could acknowledge this and adjust severity expectations: first reviews should prioritize bug hunting, subsequent reviews should prioritize defense-in-depth.

### 6. Scope consistency matters for comparison

The original included `cmd/cvert-ops/main.go` (27 gaps) and the post-remediation didn't. This makes numerical comparison misleading. The skill should specify that re-reviews use the SAME scope as the original, or explicitly document scope differences.

### 7. The evaluator pattern: "error → log and continue" needs special attention

The evaluator has ~25 gaps where the pattern is "DB operation fails → log → continue to next rule." The original found 0 of these. The skill should explicitly call out: "For loop-based processing with error handling, test that the loop CONTINUES after an error and doesn't skip remaining items."

### 8. Operator coverage: "one operator tested ≠ all operators work"

The compiler generates different SQL for gt vs gte vs eq vs neq. The original assumed testing gte and lt was sufficient. The post-remediation correctly flagged gt, lte, eq, neq as separate gaps. The skill should warn: "If a switch statement has N cases, testing 2 of N is not coverage — each case generates different output."

---

## Verdict

**The post-remediation review justifies running the skill twice.** Despite being applied to already-remediated code, it found:
- 16 new security-critical gaps (not found by original)
- 68 evaluator error paths (barely reviewed in original)
- 28 compiler operator variants (assumed covered in original)
- Cross-org API testing pattern (completely missed by original)
- SQL parameterization verification (new category)

**However, the count inflation is real.** The 213 correctness gaps include ~120 that are granularity expansion (the same logical gap counted at finer resolution), not new findings. A skill improvement that standardizes granularity would make the numbers more comparable across runs.

**Net assessment:** A second pass catches **different things** than a first pass. The first pass finds bugs and high-level gaps. The second pass finds depth gaps and systematic blind spots. Both are valuable; the skill should recommend running twice for critical code.
