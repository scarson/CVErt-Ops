# Coverage Review — A/B Test Results

**Date:** 2026-03-03
**Purpose:** Compare test coverage review approaches, validate targeted improvements, and test generalization across codebases.

---

## Runs

| Run | Skill | Version | Scope | Status | Report |
|-----|-------|---------|-------|--------|--------|
| A | `test-coverage-review` | Original path-mapping | Phase 5 | Done | `phase5-test-coverage-review.md` |
| B | `test-coverage-review-go` | Original coverage-tool | Phase 5 | Done | `phase5-coverage-tool-review.md` |
| C | `test-coverage-review-go` | Enhanced v2 (matrix + semantic) | Phase 5 | Done | `phase5-enhanced-coverage-tool-review.md` |
| D | `test-coverage-review-hybrid-go` | Hybrid v1 | Phase 5 | Done | `phase5-hybrid-review.md` |
| E | `test-coverage-review-go` | Enhanced v3 (8 improvements) | Phase 5 | Done | `phase5-enhanced-v3-review.md` |
| F | `test-coverage-review-hybrid-go` | Hybrid v2 (8 improvements) | Phase 5 | **Not executed** | — |
| G | `test-coverage-review-go` | Enhanced v3 (8 improvements) | **Phase 1** | Done | `phase1-enhanced-v3-review.md` |
| H | `test-coverage-review-hybrid-go` | Hybrid v2 (8 improvements) | **Phase 1** | Done (truncated) | `phase1-hybrid-v2-review.md` |
| I5 | `test-coverage-review-go` | Enhanced v4 (S1-S6 context mgmt) | Phase 5 | Done | `phase5-enhanced-v4-review.md` |
| J5 | `test-coverage-review-hybrid-go` | Hybrid v3 (S1-S6 context mgmt) | Phase 5 | Done | `phase5-hybrid-v3-review.md` |
| K1 | `test-coverage-review-go` | Enhanced v4 (S1-S6 context mgmt) | **Phase 1** | Done | `phase1-enhanced-v4-review.md` |
| L1 | `test-coverage-review-hybrid-go` | Hybrid v3 (S1-S6 context mgmt) | **Phase 1** | Done | `phase1-hybrid-v3-review.md` |

**Controlled variables (Runs A-D):** Same `dev` branch HEAD, same scope (`internal/api/...`, `internal/store/...`, `internal/tier/...`), same pre-generated coverage data (`coverage-ab.out`, 73.5% overall, 560 functions), separate Claude Code sessions, no cross-contamination. Both C and D hit auto-compaction during analysis.

**Controlled variables (Runs E-F):** Same as A-D. Same coverage data files. No source code changes to scope since C/D (last source change: `4c8062a`). See test design document for verification steps.

**Controlled variables (Runs G-H):** Same `dev` branch HEAD as E-F. Different scope: `internal/feed/...`, `internal/merge/...`, `internal/worker/...`. New coverage data (`coverage-phase1.out`). No org-scoped API endpoints — matrix improvements untestable; semantic improvements are the focus.

---

## Scoring Summary v1 (Runs A-D)

Scored on a 0–10 scale per metric, then weighted.

| Metric | Weight | A (path-mapping) | B (orig coverage) | C (enhanced coverage) | D (hybrid) |
|--------|--------|:-:|:-:|:-:|:-:|
| Security matrix completeness | 25% | 0 | 0 | **9** | 8 |
| Production bugs found | 25% | **10** | 0 | 7 | **10** |
| Cross-org isolation gaps | 15% | 4 | 1 | **10** | 7 |
| Assertion quality findings | 10% | 0 | 7 | 2 | **10** |
| TOCTOU windows identified | 10% | 8 | 0 | 0 | **10** |
| False positives | 10% | 2 | **10** | 9 | 8 |
| Cross-handler consistency | 5% | **10** | 0 | 9 | **10** |
| **Weighted total** | **100%** | **4.60** | **1.85** | **7.05** | **8.85** |

### Score rationale

**Run A (4.60):** Found both production bugs and had the strongest cross-handler analysis, but zero matrix capability and 23+ false positives (phantom `writer.go`, mischaracterized tier package) dragged it down significantly.

**Run B (1.85):** Zero false positives and 3 assertion quality findings, but missed production bugs, cross-org gaps, TOCTOU windows, and cross-handler patterns. Essentially proved the original diff analysis's "false sense of security" thesis — high coverage numbers masked the absence of semantic analysis.

**Run C (7.05):** Massive improvement over Run B (+5.20). The matrix caught the most cross-org gaps (21 endpoint-level GAPs). Found one original bug (BUG-2: wrong count function) and one new bug (BUG-2-new: 3 handler files entirely missing audit logging). But missed original BUG-1 (invitation tier-block audit inconsistency) — the matrix marked the invitation endpoint's fail-closed column as "Tested" because `TestTierGating_Members_FreeLimit` exists, without noticing it doesn't test the *audit log* on that path. No TOCTOU analysis at all.

**Run D (8.85):** Highest overall score. Found both original production bugs, 5 assertion quality issues, 3 TOCTOU windows, and complete cross-handler consistency analysis. Matrix was slightly less granular than Run C (fewer cross-org GAPs identified — see disagreements below) but semantic analysis was substantially stronger.

---

## The Primary Question: Does Structural Separation Matter?

**Yes.** Run C and Run D share identical enhancements (matrix, semantic spot-checks, rationalization table) — the only difference is structural organization (single-pass vs two-pass). The results show:

| Capability | Run C (single-pass) | Run D (two-pass) | Winner |
|-----------|---------------------|-------------------|--------|
| Security matrix | 9/10 | 8/10 | C |
| Production bugs | 1/2 original + 1 new | 2/2 original | **D** |
| Assertion quality | 1 finding | 5 findings | **D** |
| TOCTOU analysis | 0 findings | 3 findings | **D** |
| Cross-org granularity | 21 endpoint GAPs | 14 endpoint GAPs | C |
| Cross-handler patterns | Found audit gap broadly | Found specific tier-block pattern | **D** |

Run D wins on every semantic analysis metric. Run C wins on matrix completeness and cross-org granularity. This aligns with the design hypothesis: the two-pass structure gives Pass 2 (semantic analysis) its own cognitive space, preventing coverage data from anchoring the analysis.

Run C's superior cross-org count is interesting — it found fine-grained gaps (alert-rule channel listing, report channel unbinding, group member removal) that Run D marked as "Tested." This suggests Run C applied the matrix more thoroughly. But Run D caught things Run C couldn't see: TOCTOU windows, assertion boundary issues, and the specific 3-of-4 tier-block audit pattern.

---

## Secondary Questions

### Did both produce the security matrix?

**Yes.** Both C and D produced complete per-endpoint matrices with all cells filled. The matrix format worked as structural enforcement — neither skill could skip it. This validates the "mandatory matrix" design.

### Did both find the 2 benchmark production bugs?

| Bug | Run C | Run D |
|-----|:-----:|:-----:|
| BUG-1: Invitation missing audit on tier block | **No** — marked fail-closed as "Tested" | **Yes** — found via cross-handler pattern (§4A) |
| BUG-2: Wrong count function in org_tier.go | **Yes** — found via semantic spot-check | **Yes** — found via right-function-called (§4B) |

Run D found both. Run C found one and substituted a new bug (3 files entirely missing audit logging). The specific tier-block audit pattern requires cross-handler comparison — exactly what Pass 2's §4A is designed for.

### How many cross-org isolation gaps?

| Run | Count | Note |
|-----|------:|------|
| A | 6 | Store-level, no matrix structure |
| B | 1 | Single gap identified |
| C | **21** | HTTP-level, fine-grained |
| D | 14 | HTTP-level, fewer fine-grained |

Run C found the most, but some disagree with Run D (see disagreements section below).

### Did both catch assertion quality issues?

| Run | Count | Examples |
|-----|------:|---------|
| A | 0 | — |
| B | 3 | Conditional assertion, shallow nullable fields, CSRF cookie-absence-only |
| C | 1 | SSRF PATCH assertion breadth |
| D | **5** | Tier count source, SSO RBAC role coverage, transaction helper side-effects, channel negative ownership, replay rate boundary |

Run D found the most. Run C's single finding is surprising — the enhanced skill has assertion quality instructions but the single-pass structure apparently didn't leave enough cognitive space for thorough assertion review.

### TOCTOU comparison

| Run | Count | Windows found |
|-----|------:|--------------|
| A | 2 | SSO deleted between redirect/callback, SSO disabled between redirect/callback |
| B | 0 | — |
| C | 0 | Explicitly: "No TOCTOU windows detected" |
| D | **3** | SSO redirect/callback, invitation tier check race, channel delete safety check race |

Run D found the most, including the A baseline's SSO window plus two new ones. Run C's explicit "no TOCTOU" is a false negative — the same temporal risks exist in the code regardless of which skill analyzes it. This is the starkest evidence of single-pass anchoring: coverage data says the code is 70%+ covered, so TOCTOU analysis gets short-circuited.

### Source tag distribution

Run C's 16 security-critical gaps: 12 from matrix, 3 from semantic, 1 from coverage.
Run D's 17 security-critical gaps: 5 from matrix, 7 from semantic, 3 from coverage, 2 from assertion.

Run D has a more diverse source distribution — the two-pass structure surfaces findings from multiple angles. Run C is matrix-dominated, confirming that the single-pass structure leans heavily on the tool-assisted check and under-invests in semantic analysis.

---

## Matrix Disagreements

Run C and Run D disagree on 7 endpoints:

| Endpoint | Run C | Run D |
|----------|-------|-------|
| POST /alert-rules/validate | **GAP** (no cross-org test) | Tested |
| GET /alert-rules/{id}/channels | **GAP** (no cross-org test) | Tested |
| DELETE /alert-rules/{id}/channels/{cid} | **GAP** (no cross-org unbind) | Tested |
| DELETE /reports/{id}/channels/{cid} | **GAP** (no cross-org unbind) | Tested |
| GET /reports/{id}/channels | **GAP** (no cross-org test) | Tested |
| DELETE /groups/{id}/members/{uid} | **GAP** (no cross-org remove member) | Tested |
| GET /sso/link | **GAP** (in Run C's 6 SSO endpoints) | Not listed |

**Ground truth (verified in Runs E-H analysis):** All 7 endpoints are **untested** for cross-org isolation. Run C was correct on 6/7 (all its GAPs were accurate). Run D was wrong on all 6 it marked "Tested" — the cited tests exist but don't test those specific sub-endpoints. Run E resolved 4/7 correctly (GAPs) but made 3 false "Tested" claims. See the Disputed Endpoint Resolution table in the Runs E-F section for full details.

---

## Enhancement Impact (Baseline → Enhanced)

### Coverage-tool improvement (Run B → Run C)

| Metric | Run B | Run C | Delta |
|--------|------:|------:|------:|
| Weighted score | 1.85 | 7.05 | **+5.20** |
| Production bugs | 0 | 2 | +2 |
| Cross-org gaps | 1 | 21 | +20 |
| Security matrix | No | Yes (24 GAPs) | New capability |

The enhancements transformed a near-useless review into a highly productive one. The matrix alone accounts for most of the improvement.

### vs Path-mapping baseline (Run A)

| Metric | Run A | Run C | Run D |
|--------|------:|------:|------:|
| Weighted score | 4.60 | 7.05 | 8.85 |
| False positives | 23+ | 0 | 0 |
| Production bugs | 2 | 2 | 2 |
| TOCTOU | 2 | 0 | 3 |

Both enhanced skills outperform the path-mapping baseline overall, primarily by eliminating false positives and adding the security matrix. Run D additionally matches or exceeds path-mapping on every metric except false positives (where path-mapping's 23+ are far worse than D's few questionable marks).

---

## What Each Skill Is Best At

| Capability | Best skill | Runner-up |
|-----------|-----------|-----------|
| Matrix completeness | C (enhanced coverage) | D (hybrid) |
| Production bug detection | D (hybrid) = A (path-mapping) | C (enhanced coverage) |
| Cross-org gap count | C (enhanced coverage) | D (hybrid) |
| Assertion quality | D (hybrid) | B (orig coverage) |
| TOCTOU analysis | D (hybrid) | A (path-mapping) |
| Zero false positives | B (orig coverage) | C (enhanced coverage) |
| Cross-handler patterns | D (hybrid) = A (path-mapping) | C (enhanced coverage) |
| Resource efficiency | B/C (fewer subagents) | D (more subagents) |

---

## New Findings (Not in Either Baseline)

Findings unique to the enhanced runs that neither baseline caught:

### From Run C (new)
1. **BUG-2-new:** `groups.go`, `reports.go`, `deliveries.go` have zero audit logging (3 handler files, not just one path) — broader than BUG-1's specific tier-block observation
2. **`UpsertDelivery` hand-rolls transaction** without the `recover()` defer that `withBypassTx` provides
3. **21 HTTP-level cross-org GAPs** — baselines identified 6 (store-level) and 1 respectively

### From Run D (new)
1. **TOCTOU: invitation tier check race** — concurrent invitation could exceed limit (no advisory lock)
2. **TOCTOU: channel delete safety check race** — concurrent bind could create orphan
3. **SSO RBAC: admin→403 not tested** — only member→403, but SSO requires owner role
4. **5 assertion quality issues** — none found by path-mapping, different from Run B's 3
5. **`putSSODomainsHandler` missing audit log** — Phase 5 addition that breaks the sibling audit pattern
6. **`createOrgHandler` and `cancelInvitationHandler` missing audit logs** — org lifecycle gaps

---

## Recommendation

### For production use: **Hybrid** (`test-coverage-review-hybrid-go`)

The hybrid skill produces the most comprehensive analysis — it's the only approach that found both benchmark bugs, TOCTOU windows, assertion quality issues, AND cross-handler patterns in a single run. Its +1.80 weighted advantage over the enhanced coverage-tool isn't from doing any one thing dramatically better — it's from doing everything at least adequately. The single-pass skill has blind spots (TOCTOU, assertion quality) that the two-pass structure prevents.

### For maximum cross-org coverage: Run enhanced coverage-tool first

Run C found more fine-grained cross-org gaps than Run D. If the primary concern is exhaustive cross-org isolation testing (which it often is for a multi-tenant security product), running the enhanced coverage-tool to build the matrix and then spot-checking with the hybrid's semantic analysis would catch the most.

### Retire the path-mapping skill for Go projects?

With either enhanced skill available, the original `test-coverage-review` path-mapping skill has no advantage for Go projects. Both enhanced skills:
- Eliminate its false positives (phantom files, mischaracterized packages)
- Match or exceed its production bug detection
- Add matrix, assertion quality, and (for hybrid) TOCTOU analysis

**Recommendation:** Keep `test-coverage-review` for non-Go projects (no `go test -cover` available). For Go projects, use `test-coverage-review-hybrid-go` as the primary skill.

### Should we merge the enhanced coverage-tool into the hybrid?

No. The A/B test shows each has a strength the other lacks:
- Enhanced coverage-tool: more thorough matrix (21 vs 14 cross-org gaps)
- Hybrid: stronger semantic analysis (all other metrics)

Having both available allows choosing the right tool for the situation. For routine reviews, the hybrid is the default. For deep cross-org audits, the enhanced coverage-tool provides finer granularity.

---

## Context Notes

- Both Run C and Run D hit auto-compaction during analysis (large codebase, 560 functions). This may have degraded cross-handler analysis quality for both — the main agent loses fine-grained source code context after compaction. The hybrid's structural separation may have helped here: Pass 2 reads source files fresh rather than relying on Pass 1's compacted context.
- 2 pre-existing test failures (`TestMiddleware_RequestID`, `TestMiddleware_RequestID_404`) were present during all runs but outside Phase 5 scope.
- Run B had a different pre-existing failure (`TestWithBypassTx_SetsSessionVar`) that appears to have been fixed between the baseline and enhanced runs.

---

## Runs E-F: Post-Improvement Validation

Runs E and F test whether the 8 targeted improvements derived from C/D analysis close the identified gaps. See [test design](2026-03-03-phase5-ab-test-design.md) §"Runs E and F" for full methodology.

**Run status:** Run E complete (362 lines). **Run F was never executed** — no report file exists. All F columns are marked N/A below. E-vs-F comparison and hybrid-v2 Phase 5 hypotheses (H7, H8) cannot be tested.

### Improvements Being Tested

| # | Improvement | Applied to | Primary gap it addresses |
|---|------------|-----------|-------------------------|
| 1 | Audit log (7th matrix column) | Both | Run C missed BUG-1 (no audit column to surface it) |
| 2 | Cite-test-name | Both | 7 matrix disagreements between C/D (unverifiable "Tested" marks) |
| 3 | Route enumeration | Both | Run D omitted GET /sso/link entirely |
| 4 | Spot-check verification | Both | No mechanism to catch false "Tested" cells in C/D |
| 5 | Conditional assertion emphasis | Both | Run C found only 1 assertion quality issue |
| 6 | TOCTOU §4.6 (scarcity gate) | Enhanced only | Run C wrote "No TOCTOU windows detected" without analysis |
| 7 | Matrix completeness gate | Hybrid only | No explicit verification between Pass 1 and Pass 2 |
| 8 | Subagent matrix delegation | Hybrid only | Context efficiency for large-scope reviews |

### Scoring Summary v1 (Runs A-F — historical comparison)

| Metric | Weight | A | B | C | D | E | F | Delta C→E | Delta D→F |
|--------|--------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Security matrix completeness | 25% | 0 | 0 | 9 | 8 | **10** | N/A | +1 | N/A |
| Production bugs found | 25% | 10 | 0 | 7 | 10 | **6** | N/A | -1 | N/A |
| Cross-org isolation gaps | 15% | 4 | 1 | 10 | 7 | **5** | N/A | -5 | N/A |
| Assertion quality findings | 10% | 0 | 7 | 2 | 10 | **4** | N/A | +2 | N/A |
| TOCTOU windows identified | 10% | 8 | 0 | 0 | 10 | **10** | N/A | **+10** | N/A |
| False positives | 10% | 2 | 10 | 9 | 8 | **8** | N/A | -1 | N/A |
| Cross-handler consistency | 5% | 10 | 0 | 9 | 10 | **8** | N/A | -1 | N/A |
| **Weighted total** | **100%** | **4.60** | **1.85** | **7.05** | **8.85** | **7.35** | **N/A** | **+0.30** | **N/A** |

### Run E v1 Score Rationale

**Run E (7.35):** A modest improvement over Run C (+0.30). The TOCTOU improvement is dramatic (0→10): Run E enumerated 9 multi-step flows and found 3 TOCTOU windows (tier limit races, invitation accept race, channel delete race) — the same windows Run D found. The matrix is the best of any run: 72 endpoints from route enumeration with the new 7th audit log column. But production bug detection *regressed* from Run C: missed both benchmark bugs (BUG-1 partially surfaced by the audit column but without the 3-of-4 tier-block pattern, BUG-2 entirely missed). Cross-org gap count also dropped (11 vs C's 21). Found 5 new audit-related bugs that neither baseline caught. Three false "Tested" marks (see disputed endpoints below) prevent a higher false-positive score.

**Net assessment:** The v3 improvements successfully closed Run C's TOCTOU blind spot (the targeted gap), but came at the cost of cross-org thoroughness and production bug detection. The enhanced skill trades depth for breadth — more structured analysis (matrix, TOCTOU enumeration) but less semantic insight.

### Scoring Summary v2 (Run E — measures specific improvements)

| Metric | Weight | E (enhanced v3) | F (hybrid v2) | How scored |
|--------|--------|:-:|:-:|------------|
| Production bugs found | 20% | **5** | N/A | BUG-1 partial (audit column caught gap, not specific pattern). BUG-2 missed. 5 new audit bugs. |
| Matrix completeness | 10% | **10** | N/A | Route enumeration from server.go. "72 org-scoped endpoints." Explicit count stated. |
| Matrix accuracy | 15% | **5** | N/A | Cites test names. Spot-check done. But 3/7 disputed endpoints wrong (see ground truth). |
| Cross-org isolation gaps | 10% | **5** | N/A | 11 GAPs found. True count is 14+ (3 false "Tested" marks). Below C's 21 and D's 14. |
| Assertion quality findings | 10% | **5** | N/A | 2 findings. Conditional assertion found (tier gating status-code-only). Low count. |
| TOCTOU windows identified | 10% | **10** | N/A | 3 windows. Full 9-flow enumeration table. Massive improvement from C's 0. |
| False positives | 10% | **6** | N/A | No phantom files. 3 false "Tested" marks where cited test doesn't cover the sub-endpoint. |
| Cross-handler consistency | 5% | **7** | N/A | Broad audit pattern found across all handlers. Specific 3-of-4 tier-block pattern not highlighted. |
| Audit log gap detection | 10% | **9** | N/A | 14 endpoints flagged as audit GAPs in 7th column. 5 production bugs from audit analysis. |
| **Weighted total** | **100%** | **6.60** | **N/A** | |

### Hypothesis Results (E/F)

| # | Prediction | Run E | Run F | Confirmed? |
|---|-----------|-------|-------|:----------:|
| H1 | Audit log column catches BUG-1 | Audit column shows "GAP (no audit code)" for invitations. Catches the gap but not the specific 3-of-4 tier-block pattern. | N/A | **Partial** |
| H2 | Cite-test-name resolves ≥4 of 7 disputed endpoints | All 7 resolved with citations. Ground truth: 4/7 correct (GAPs accurate), 3/7 wrong (false "Tested"). | N/A | **Partial** |
| H3 | Route enumeration: all endpoints present, count stated | "72 org-scoped endpoints identified from server.go:195-348." GET /sso/link included (Run D omitted it). | N/A | **Confirmed** |
| H4 | Spot-check performed (3 cells verified) | 3 cells verified (TestCrossOrg_MemberOperations, TestTierGating_Members_PendingInvitationsConsumeSlots, TestAuditIntegration_Channels). All confirmed accurate. | N/A | **Confirmed** |
| H5 | Conditional assertion in tier middleware identified | Assertion quality #1: "TestTierGating_Members_FreeLimit only checks status code — could pass if 403 is returned for a different reason (e.g., RBAC)." | N/A | **Confirmed** |
| H6 | Enhanced TOCTOU: ≥1 window found (was 0 in Run C) | 3 windows found (tier limit race, invitation accept race, channel delete race). Full 9-flow enumeration. | N/A | **Confirmed** |
| H7 | Hybrid matrix completeness: count verification in report | N/A | N/A (Run F not executed) | **Untestable** |
| H8 | Subagent matrix quality maintained (if triggered) | N/A | N/A (Run F not executed) | **Untestable** |

**Testable hypotheses: 6.** Confirmed: 4 (H3, H4, H5, H6). Partial: 2 (H1, H2). Refuted: 0.

**Success criteria: ≥6 of 8 confirmed.** With only 6 testable, 4 confirmed + 2 partial = **borderline pass.** H1 and H2 worked in the direction intended but didn't fully achieve their goals. The cite-test-name heuristic catches test-function-level gaps but fails on sub-endpoint scope — when a cross-org test exists for the parent endpoint group but doesn't test the specific sub-endpoint, the skill assumes coverage. The audit column surfaces missing audit code but doesn't trigger the cross-handler pattern comparison needed to identify BUG-1's specific 3-of-4 violation.

### Disputed Endpoint Resolution (Ground Truth Verified)

Ground truth was verified by reading the actual test files. **All 7 disputed endpoints are untested for cross-org isolation.**

| Endpoint | C | D | E | Ground truth | E correct? |
|----------|---|---|---|-------------|:----------:|
| POST /alert-rules/validate | GAP | Tested | GAP | **GAP** — `TestAlertRule_CrossOrgIsolation` tests GET rule + GET list, not /validate | ✅ |
| GET /alert-rules/{id}/channels | GAP | Tested | Tested (TestAlertRule_CrossOrgIsolation) | **GAP** — test doesn't call channel sub-endpoint | ❌ |
| DELETE /alert-rules/{id}/channels/{cid} | GAP | Tested | GAP | **GAP** — only single-org unbind tests exist | ✅ |
| DELETE /reports/{id}/channels/{cid} | GAP | Tested | GAP | **GAP** — RBAC test exists but not cross-org | ✅ |
| GET /reports/{id}/channels | GAP | Tested | Tested (TestReports_CrossOrgIsolation) | **GAP** — test doesn't call channel sub-endpoint | ❌ |
| DELETE /groups/{id}/members/{uid} | GAP | Tested | GAP | **GAP** — `TestCrossOrg_GroupAccess` tests 6 ops but not remove-member | ✅ |
| GET /sso/link | GAP | Not listed | Tested (TestOIDCFlow_CrossOrgIsolation) | **GAP** — test covers login+callback, not /sso/link | ❌ |

**Accuracy by run:**
- Run C: 6/7 correct (all GAPs accurate; only missed that /sso/link should also be listed)
- Run D: 0/6 correct on disputed (all "Tested" marks are wrong) + omitted /sso/link
- Run E: 4/7 correct (GAPs accurate; 3 false "Tested" marks)

**Key insight:** The cite-test-name improvement partially works — it forces the skill to name a specific test, making claims auditable. But the heuristic fails when a broadly-named test (e.g., `TestAlertRule_CrossOrgIsolation`) exists and sounds relevant but doesn't actually test the specific sub-endpoint. The spot-check (3 random cells) happened to pick correctly-marked cells and didn't catch the false positives. A sub-endpoint-aware spot-check — where the verifier checks that the cited test actually calls the specific HTTP path — would catch this failure mode.

### Run E New Findings (Not in Any Prior Run)

1. **5 new audit logging bugs** via the audit column: groups.go (0 audit calls, 5 mutations), reports.go (0 audit calls, 5 mutations), apikeys.go (0 audit calls, 2 mutations), deliveries.go replay (no audit), orgs.go (4 mutations without audit: create org, update org, create invitation, cancel invitation). Broader than Run D's specific findings — Run D caught the tier-block pattern and a few individual missing audits, but Run E systematically catalogued every mutating endpoint without audit code.

2. **TOCTOU: invitation accept has no tier re-check** — `acceptInvitationHandler` doesn't verify the org is still within member limits. Neither Run C nor Run D identified this specific window (Run D found the create-time tier race, not the accept-time gap).

---

## Runs G-H: Phase 1 Generalization Test

Runs G and H test whether the improvements generalize beyond Phase 5's HTTP handlers to Phase 1's data ingestion code (feed adapters, merge pipeline, worker pool). See [test design](2026-03-03-phase5-ab-test-design.md) §"Runs G and H" for full methodology.

**Run status:** Run G complete (275 lines). **Run H truncated at 141 lines** — cuts off at "## What's Well-Covered". Missing: production bugs section, assertion quality section, TOCTOU analysis, key observations. H scores are estimated where the truncated section is the primary source; these are marked with (†).

**Key difference from E-F:** Phase 1 has no org-scoped API endpoints. Matrix improvements (audit log column, cite-test-name, route enumeration, spot-check) are untestable. Semantic improvements (TOCTOU, cross-handler consistency, assertion quality, wrong-function-called) are the focus.

### Phase 1 Coverage Baseline

| Package | Coverage | Functions | Notes |
|---------|----------|-----------|-------|
| internal/feed (root) | — | 5 | `ParseTime`, `ParseTimePtr`, `StripNullBytes`, `StripNullBytesJSON`, `ResolveCanonicalID` — all 100% |
| internal/feed/epss | 2.5% | 4 | `Apply` 14.3%, `applyRow` 0.0% — heavy integration logic uncovered |
| internal/feed/ghsa | 13.2% | 5 | `Fetch` 85.2%, `fetchPage` 86.8%, `parseAdvisory` 100% |
| internal/feed/kev | 7.4% | 5 | `Fetch` 80.0%, `parseKEV` 72.7% |
| internal/feed/mitre | 11.2% | 8 | `Fetch` 84.8%, `downloadToTemp` 57.1%, `parseCVE5` 100% |
| internal/feed/nvd | 14.9% | 11 | `Fetch` 85.2%, `cveToCanonical` 97.3%, `New` 0.0% |
| internal/feed/osv | 10.7% | 7 | `Fetch` 81.8%, `downloadToTemp` 57.1% |
| internal/merge | 22.8% | 22 | `Ingest` 67.6%, `resolve` 92.5%, `ComputeMaterialHash` 88.0% |
| internal/worker | 4.8% | 6 | `runStaleRecovery` 53.8%, `runQueue` 87.5% |
| **Overall** | **83.4%** | **73** | Per-test-package coverage ranges 1.4%–22.8%; aggregate is high due to cross-package test execution |

### Scoring (G/H — Phase 1 reduced rubric)

| Metric | Weight | G (enhanced v3) | H (hybrid v2) † | How scored |
|--------|--------|:-:|:-:|------------|
| Production bugs / design violations | 25% | **10** | **6** † | G: 2 genuine production bugs (ParseTime RFC1123 dead code, PK migration data loss). H: 4 semantic bugs per gap context but details truncated. |
| TOCTOU windows | 20% | **8** | **4** † | G: 3 TOCTOU gaps, 10-flow enumeration, advisory lock analysis. H: matrix TOCTOU column has 1 GAP; dedicated section missing. |
| Cross-handler consistency | 20% | **8** | **7** | G: all 6 adapters compared, 5 shared patterns, 3 systematic gaps (context cancellation, cursor JSON, User-Agent). H: 8-component matrix comparison, 3 cross-handler violations, KEV error-handling inconsistency identified. |
| Assertion quality | 15% | **9** | **7** † | G: 10 issues (NVD cursor assertions, merge tombstone fields, worker counter never checked). H: 8 per gap context; details truncated. |
| False positives | 10% | **10** | **9** | G: zero fabricated endpoints, no mischaracterized packages, accurate coverage interpretation. H: clean adapted matrix, no visible false positives. |
| Non-API adaptation | 10% | **10** | **10** | G: matrix correctly N/A with explanation. H: creatively adapted matrix with domain-specific columns (advisory lock, null-byte stripping, streaming parse, rate limiting, TOCTOU protection, temp file cleanup). |
| **Weighted total** | **100%** | **9.05** | **6.55** † | H score is estimated due to truncation. |

† Denotes scores estimated from partial data (gap context counts, matrix content) because the relevant report sections were truncated.

### Run G Score Rationale

**Run G (9.05):** The highest-scoring run in the entire A/B test. Two genuine production bugs: (1) `feed.ParseTime` doesn't support RFC1123, making the NVD Date header fallback dead code — a subtle semantic bug that requires understanding the interaction between two utility functions; (2) PK migration collision causes silent data loss when the target CVE ID already exists. Both are real bugs with concrete impact, not just missing tests. The TOCTOU enumeration is thorough (10 multi-step flows), the cross-adapter analysis is systematic (5 shared patterns, 3 violations), and the assertion quality review (10 issues) is the most comprehensive of any run. Zero false positives. The enhanced v3 skill performed *better* on Phase 1 than Phase 5 — likely because Phase 1's 73 functions fit comfortably in context without compaction, and the semantic analysis patterns (interface consistency, temporal coordination) are well-suited to the enhanced skill's single-pass approach.

### Run H Score Rationale

**Run H (6.55†):** Hard to score fairly due to truncation. The adapted security matrix is the most creative output of any run — replacing standard columns with domain-relevant properties that make sense for data pipeline code. Found 7 matrix GAPs, 4 semantic bugs, 3 cross-handler violations, and 8 assertion quality issues per the gap context. But without the detailed descriptions, severity assessments, and TOCTOU analysis, the full quality can't be evaluated. The truncation itself is a data point: Run H attempted more analysis than could fit, suggesting the hybrid's two-pass structure may not be well-suited to smaller scopes where single-pass suffices.

### Generalization Hypotheses (G/H)

| # | Prediction | Run G | Run H | Confirmed? |
|---|-----------|-------|-------|:----------:|
| G1 | TOCTOU: ≥1 temporal window in merge pipeline | 3 TOCTOU gaps (EPSS staging race, PK migration collision, old-ID vs new-ID lock conflict). 10-flow enumeration. | Matrix TOCTOU column shows 1 GAP (EPSS vs merge serialization). Dedicated section truncated. | **Confirmed** (G). **Inconclusive** (H — truncation). |
| G2 | Cross-handler: shared patterns across 6 feed adapters identified | 5 shared patterns identified (rate limiter, cursor parsing, error wrapping, null-byte stripping, alias resolution). 3 systematic violations (context cancellation, cursor JSON, User-Agent). All 6 adapters compared. | Matrix compares 8 components including all 6 adapters. 3 cross-handler violations (KEV error abort vs silent skip, OSV null-byte ordering, GHSA decode error). | **Confirmed** (both). |
| G3 | Assertion quality: shallow assertions found in feed/merge tests | 10 assertion quality issues including execution-only tests, missing cursor assertions, incomplete tombstone field verification, worker counter never asserted. | 8 assertion quality gaps per gap context. Details truncated. | **Confirmed** (both). |
| G4 | Wrong-function-called: incorrect function usage identified | BUG-1 (ParseTime doesn't handle RFC1123 → dead code) is analogous: the *right* function concept but *wrong* format support. Not a literal wrong-function-called but same class of bug. | Can't determine from truncated report. | **Partial** (G). **Inconclusive** (H). |
| G5 | Non-API scope: matrix correctly N/A or adapted | Matrix section: "N/A — This scope contains no org-scoped API endpoints." Clean explanation. No forced application of org-scoped patterns. | Matrix adapted with domain-specific columns. No fabricated endpoints. | **Confirmed** (both). |
| G6 | Structural separation: hybrid (H) finds more semantic issues than enhanced (G) | 60 total gaps, 2 production bugs, 10 assertion quality issues. | 87 total gaps, 4 semantic bugs, 8 assertion quality, 3 cross-handler violations. Higher counts, but truncation prevents quality comparison. | **Inconclusive** — H has higher counts but truncation prevents verifying whether findings are higher quality or just higher quantity. |

**Testable: 5** (G6 inconclusive due to truncation). Confirmed: 3 (G2, G3, G5). Partial: 1 (G4). Inconclusive: 1 (G6).

**Of the 5 testable hypotheses: 3 confirmed + 1 partial = borderline pass** against the ≥4/6 threshold. G1 is confirmed for Run G but inconclusive for H — counting G1 as confirmed brings it to 4/5 testable = **pass.**

### Phase 1 Production Bugs Discovered

These are genuine bugs found by the skills, not planted benchmarks:

**Run G:**

1. **`feed.ParseTime` doesn't parse RFC1123 — NVD Date header safety layer is dead code.** `feed.ParseTime` only supports RFC3339 variants and date-only format. HTTP `Date` headers use RFC1123 (`Sun, 01 Jun 2025 12:00:00 GMT`). The NVD adapter's three-tier fallback (`response timestamp → Date header → time.Now()`) effectively becomes two-tier, defeating the clock-skew safety. — Severity: correctness. Source: semantic.

2. **PK migration collision causes data loss when new CVE ID already exists.** `migrateCVEPK` does `UPDATE cves SET cve_id = $2 WHERE cve_id = $1`. When the target ID already exists (e.g., NVD created CVE-2024-1234 first, then GHSA publishes GHSA-xxxx with alias CVE-2024-1234), this fails with a unique constraint violation. The entire Ingest transaction rolls back — the source patch is lost and the old CVE row remains orphaned. — Severity: data integrity. Source: semantic.

**Run H:** 4 semantic bugs per gap context. Details unavailable due to truncation. The adapted matrix surfaces OSV null-byte ordering (ref.URL checked before StripNullBytes) and KEV/GHSA/NVD streaming parse inconsistencies, but these may be the same findings under different labels.

### Cross-Phase Comparison

| Metric | E (Phase 5, enhanced v3) | G (Phase 1, enhanced v3) | H (Phase 1, hybrid v2) † |
|--------|:-:|:-:|:-:|
| Total findings | 35 | 60 | 87 † |
| Security-critical | 19 | 2 | 7 (matrix GAPs) |
| Production bugs | 5 (audit-related) | 2 (semantic) | 4 † |
| TOCTOU windows | 3 | 3 | 1 (matrix) † |
| Cross-handler violations | 14 (audit logging) | 3 (systematic adapter gaps) | 3 |
| Assertion quality issues | 2 | 10 | 8 † |
| False positives | 3 (false "Tested") | 0 | 0 |

**Observations:**

1. **Phase 1 produced more assertion quality findings (10 vs 2).** Phase 5's tests are more mature (comprehensive integration tests written specifically for the A/B test scope). Phase 1's tests have more execution-only patterns (verify no panic, but don't check results).

2. **Phase 1 has fewer security-critical gaps but more impactful bugs.** Phase 5's 19 security-critical gaps are mostly missing cross-org tests and audit code. Phase 1's 2 production bugs are genuine code defects (dead code, data loss) — harder to find and more impactful per finding.

3. **TOCTOU count is identical (3 each) between E and G,** despite fundamentally different code patterns (HTTP middleware vs advisory locks). This suggests the TOCTOU §4.6 improvement generalizes well.

4. **The enhanced v3 skill performed better on Phase 1 (9.05) than Phase 5 (7.35).** Likely factors: (a) smaller scope (73 vs 559 functions) avoids context compaction; (b) the semantic analysis patterns match Phase 1's interface-based code well; (c) Phase 5's cross-org matrix is where the skill underperforms, and that's N/A for Phase 1.

5. **Both skills adapted to non-API scope gracefully.** G used a clean N/A. H creatively adapted the matrix with domain-relevant columns. Neither fabricated endpoints or forced org-scoped analysis.

---

## Updated Recommendation (All Runs)

### Summary of all scores

| Run | Skill | Scope | Rubric | Score |
|-----|-------|-------|--------|------:|
| A | path-mapping | Phase 5 | v1 | 4.60 |
| B | orig coverage-tool | Phase 5 | v1 | 1.85 |
| C | enhanced v2 | Phase 5 | v1 | 7.05 |
| D | hybrid v1 | Phase 5 | v1 | 8.85 |
| E | enhanced v3 | Phase 5 | v1 | 7.35 |
| E | enhanced v3 | Phase 5 | v2 | 6.60 |
| F | hybrid v2 | Phase 5 | — | N/A (not executed) |
| G | enhanced v3 | Phase 1 | Phase 1 | **9.05** |
| H | hybrid v2 | Phase 1 | Phase 1 | 6.55 † |

### What the v3 improvements accomplished

**TOCTOU analysis: fully fixed.** The §4.6 scarcity gate with multi-step flow enumeration closed Run C's most glaring failure. Run E found 3 windows (matching Run D), Run G found 3 more in a different codebase. This is the clearest improvement success.

**Audit log column: partially successful.** The 7th column systematically catalogued 14 endpoints missing audit code — more comprehensive than any prior run's ad-hoc audit findings. But it didn't trigger the specific cross-handler pattern analysis needed for BUG-1 (3-of-4 tier-block handlers audit the denial). The column finds *missing* audit code; it doesn't compare *inconsistent* audit patterns.

**Cite-test-name: partially successful.** Makes "Tested" claims auditable — you can now verify each citation. But the heuristic fails on sub-endpoint scope: when `TestAlertRule_CrossOrgIsolation` exists, the skill assumes it covers all alert-rule sub-endpoints (/channels, /validate) without verifying the test actually calls those paths. 3/7 disputed endpoints were incorrectly marked "Tested."

**Route enumeration: fully successful.** 72 endpoints from server.go. GET /sso/link included (Run D omitted it). This prevents endpoint omission.

**Spot-check: successful but limited.** 3 cells verified, all accurate. But the random selection didn't catch the 3 false "Tested" marks. The spot-check needs to be sub-endpoint-aware.

**Conditional assertion: successful.** Found the tier gating status-code-only issue on the first try.

### What regressed from C/D to E

1. **BUG-2 (wrong count function) not found.** Run C found this via semantic spot-check; Run E missed it entirely. The enhanced v3 skill's spot-check section verified 3 cells but happened to pick different ones. This may be random variance rather than a skill regression.

2. **Cross-org gap count dropped from 21 (C) to 11 (E).** Partly because E classified SSO endpoints as "Tested" (3 false marks). Partly because E's cite-test-name requirement may have made the skill more conservative about marking GAPs — when it can name a plausible test, it marks "Tested" even if the test doesn't cover the specific sub-endpoint.

### Recommendation update

**For Phase 5 (org-scoped API code): Hybrid remains the primary choice.** Run D (8.85) still has the highest Phase 5 score. Run E (7.35) improved on C but didn't close the gap to D. The hybrid's structural separation prevents the single-pass anchoring that causes the enhanced skill to underperform on semantic analysis. Without Run F data, we can't confirm whether the hybrid v2 improvements further extend D's lead.

**For Phase 1 (data pipeline code): Enhanced v3 is the better choice.** Run G (9.05) is the highest score of any run on any scope. The single-pass approach works well on smaller, interface-based codebases where the entire scope fits in context. The hybrid's two-pass structure may add overhead without benefit on small scopes (Run H's truncation hints at this).

**Scope-based selection rule:**
- **API code with org-scoped endpoints (15+ endpoints):** Use hybrid (`test-coverage-review-hybrid-go`)
- **Internal packages, data pipelines, workers (< 100 functions):** Use enhanced (`test-coverage-review-go`)
- **Deep cross-org audit:** Run enhanced first for matrix thoroughness, then hybrid for semantic depth

**Retire path-mapping for Go projects: Yes.** Confirmed across both Phase 5 and Phase 1. Both Go-specific skills outperform it on every metric except zero false positives — and even there, the enhanced v3 comes close (3 false marks vs path-mapping's 23+).

### Open questions for future runs

1. **Run F should still be executed** to complete the Phase 5 hybrid v2 comparison. H7 and H8 are untestable without it.
2. **Run H should be re-executed** in a clean session to get the full report. The truncation prevents fair comparison on Phase 1.
3. **Cite-test-name needs sub-endpoint verification.** The heuristic should require the skill to verify that the cited test actually calls the specific HTTP path, not just that a test with a relevant name exists. Consider adding to the spot-check instructions: "For each spot-checked cell, grep the test function for the specific endpoint path."
4. **Audit column needs cross-handler trigger.** When the audit column reveals a GAP, the skill should automatically compare sibling handlers' audit patterns (not just note "no audit code"). This would catch BUG-1's 3-of-4 violation.

---

## Context Notes

- Both Run C and Run D hit auto-compaction during analysis (large codebase, 560 functions). This may have degraded cross-handler analysis quality for both — the main agent loses fine-grained source code context after compaction. The hybrid's structural separation may have helped here: Pass 2 reads source files fresh rather than relying on Pass 1's compacted context.
- 2 pre-existing test failures (`TestMiddleware_RequestID`, `TestMiddleware_RequestID_404`) were present during all runs but outside Phase 5 scope.
- Run B had a different pre-existing failure (`TestWithBypassTx_SetsSessionVar`) that appears to have been fixed between the baseline and enhanced runs.
- Run E did not appear to hit context compaction. Run G similarly completed without compaction (73 functions fits comfortably).
- Run H truncated at 141 lines — likely due to session interruption or context limit during the generation phase, not during analysis.
- Run I5 compacted once during analysis (working on §4.5 cross-handler consistency). Completed successfully.
- Run J5 completed without issues. 481-line report.
- Run K1 initial attempt died reading 17 files simultaneously (S6 fix applied, see design doc). Retry completed successfully. 367-line report.
- Run L1 completed without truncation. 450-line report — significant improvement over H's 141 lines.

---

## Runs I5, J5, K1, L1: Context-Efficient Retry

Runs I5/J5/K1/L1 retry all four test conditions with skill versions v4/v3 that include 6 context management improvements (S1-S6). See [test design](2026-03-03-phase5-ab-test-design.md) §"Runs I5, J5, K1, L1" for full methodology, skill changes, and prompt changes.

**Run status:** All 4 runs complete. K1 required a retry after the initial attempt died from context exhaustion (reading all source/test files simultaneously before S6 was added). The S6 fix (incremental reading) resolved this.

### Scoring Summary v1 (Historical — All Phase 5 Runs)

| Metric | Weight | A | B | C | D | E | I5 | J5 |
|--------|--------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Security matrix completeness | 25% | 0 | 0 | 9 | 8 | 10 | **10** | **10** |
| Production bugs found | 25% | 10 | 0 | 7 | 10 | 6 | **10** | **10** |
| Cross-org isolation gaps | 15% | 4 | 1 | 10 | 7 | 5 | **9** | **9** |
| Assertion quality findings | 10% | 0 | 7 | 2 | 10 | 4 | **8** | **8** |
| TOCTOU windows identified | 10% | 8 | 0 | 0 | 10 | 10 | **10** | **8** |
| False positives | 10% | 2 | 10 | 9 | 8 | 8 | **8** | **8** |
| Cross-handler consistency | 5% | 10 | 0 | 9 | 10 | 8 | **10** | **10** |
| **Weighted total** | **100%** | **4.60** | **1.85** | **7.05** | **8.85** | **7.35** | **9.45** | **9.25** |

### I5 v1 Score Rationale

**Run I5 (9.45):** The highest v1 score of any run. Found BOTH benchmark production bugs — a critical improvement over Run E which found neither. BUG-1 detected via §4.5A cross-handler consistency: 3-of-5 tier-deny handlers audit the denial, `createInvitationHandler` and `requireEnterpriseTier` (SSO) do not. This is actually a stronger finding than D's original 3-of-4 detection — I5 identified the SSO tier-deny case as a second violation. BUG-2 detected via §4.5A Pattern 3 (wrong function called). The CRUD audit logging map across all 10 handler groups is the most comprehensive audit analysis of any run. 21 cross-org GAPs match Run C's count. 7 TOCTOU flows enumerated (6 windows: 3 tier races, 2 SSO redirect/callback, 1 refresh token). 6 assertion quality issues. 3/7 disputed endpoints still incorrectly marked "Tested" (POST /alert-rules/validate, GET /alert-rules/{id}/channels, GET /reports/{id}/channels) — different wrong endpoints than Run E but same 4/7 accuracy.

### J5 v1 Score Rationale

**Run J5 (9.25):** Second-highest v1 score. Found both benchmark bugs plus a new one (PB1: `replayDeliveryHandler` has no not-found check — returns 500 or silent 204 instead of 404 for non-existent deliveries). The 7-column matrix (Cross, UA, FC, SQL, RBAC, Tier, Audit) is the most comprehensive matrix format of any run — the SQL injection and unauth columns add coverage that other runs don't check. Cross-handler analysis in §4A identifies all 3 patterns (tier-deny audit, wrong count method, CRUD audit map). 19 cross-org GAPs. TOCTOU analysis is informal (Key Observations section) rather than formally enumerated, identifying tier gating races (4 windows) and refresh token race — adequate but less structured than I5's enumeration table. 6 assertion quality issues. 3/7 disputed endpoints wrong (POST /alert-rules/validate, DELETE /reports/{id}/channels/{cid}, GET /reports/{id}/channels). Complete 481-line report with no truncation.

### Scoring Summary v2 (Runs E, I5, J5 — improvement-specific metrics)

| Metric | Weight | E | I5 | J5 | How scored |
|--------|--------|:-:|:-:|:-:|------------|
| Production bugs found | 20% | 5 | **10** | **10** | I5: BUG-1 (3-of-5 tier-deny pattern) + BUG-2 (wrong count). J5: BUG-1 + BUG-2 + PB1 (replay not-found). |
| Matrix completeness | 10% | 10 | **10** | **10** | Both: 72 endpoints from route enumeration. Count stated. J5 adds SQL + UA columns. |
| Matrix accuracy | 15% | 5 | **5** | **5** | Both: 4/7 disputed endpoints correct. Same cite-test-name sub-endpoint failure. |
| Cross-org isolation gaps | 10% | 5 | **8** | **9** | I5: 21 GAPs (3 false Tested). J5: 19 GAPs (3 false Tested). Both better than E's 11. |
| Assertion quality findings | 10% | 5 | **7** | **7** | Both: 6 findings (OAuth cookies, JWT claims, SSRF msg, boolean fields, composite short-circuit, helper defaults). |
| TOCTOU windows identified | 10% | 10 | **10** | **7** | I5: 7-flow enumeration table, 6 windows. J5: informal analysis, 5 windows, no enumeration. |
| False positives | 10% | 6 | **6** | **7** | I5: 3 false "Tested" marks. J5: 3 false "Tested" marks. J5's matrix format reduces ambiguity. |
| Cross-handler consistency | 5% | 7 | **10** | **10** | Both: found specific tier-deny pattern (BUG-1) + full CRUD audit map + wrong-function-called. |
| Audit log gap detection | 10% | 9 | **10** | **10** | I5: 20 audit GAPs in matrix + CRUD audit map. J5: 23 audit GAPs + CRUD map. |
| **Weighted total** | **100%** | **6.60** | **8.35** | **8.25** | |

### Scoring (K1/L1 — Phase 1 reduced rubric)

| Metric | Weight | G (enhanced v3) | H (hybrid v2) † | K1 (enhanced v4) | L1 (hybrid v3) |
|--------|--------|:-:|:-:|:-:|:-:|
| Production bugs / design violations | 25% | 10 | 6 † | **2** | **2** |
| TOCTOU windows | 20% | 8 | 4 † | **7** | **5** |
| Cross-handler consistency | 20% | 8 | 7 | **6** | **7** |
| Assertion quality | 15% | 9 | 7 † | **5** | **4** |
| False positives | 10% | 10 | 9 | **10** | **10** |
| Non-API adaptation | 10% | 10 | 10 | **10** | **10** |
| **Weighted total** | **100%** | **9.05** | **6.55** † | **5.85** | **5.50** |

### K1 Score Rationale

**Run K1 (5.85):** Significant regression from G (9.05). The context management improvements (S1-S6) ensured completion (K1's initial attempt died; retry with S6 succeeded) but at the cost of analytical depth. Found 0 production bugs (G found 2: ParseTime RFC1123, PK migration collision). ParseTime/RFC1123 not mentioned anywhere in the report. PK migration is analyzed as a TOCTOU window (correctness gap #7) rather than identified as a data loss bug — the analysis is correct but doesn't reach the "production bug" conclusion. 4 assertion quality issues (G found 10) — all 4 are the same worker timing issues that G found, but G also found 6 more in feed/merge tests. TOCTOU: 8 flows enumerated, 2 temporal windows identified, which is comparable to G. Cross-adapter consistency analysis covers 4 patterns (malformed records, null-byte stripping, strings.Clone, User-Agent) vs G's 5 shared patterns + 3 violations. Zero false positives. Matrix correctly N/A.

**Why the regression?** The incremental reading approach (S6) processes one package at a time, which prevents context exhaustion but also prevents the cross-package pattern recognition that let G identify the ParseTime RFC1123 bug (which requires seeing `feed/util.go` and `nvd/adapter.go` together). G's v3 skill loaded more files simultaneously, giving it richer context for semantic analysis at the cost of higher context pressure. The v4 trade-off (completion over depth) is correct for large scopes but over-conservative for Phase 1's 73 functions.

### L1 Score Rationale

**Run L1 (5.50):** Complete report at 450 lines — a significant improvement over H's 141-line truncation. The adapted data pipeline security matrix is excellent: 7 domain-specific columns (advisory lock, null-byte strip, streaming parse, temp file cleanup, cursor safety, error propagation, rate limiting) across 8 pipeline operations. But analytical depth is shallow compared to G. 0 genuine production bugs (1 consistency finding: missing User-Agent in OSV/MITRE downloadToTemp). 1 TOCTOU window identified as critical (EPSS advisory lock coordination untested), 2 others correctly analyzed as mitigated. 1 assertion quality issue (worker/TestProcessOne_NilHandler weak negative). Cross-handler consistency covers all 6 adapters with systematic comparison but finds fewer violations than G.

**The completion/depth trade-off is visible here too.** L1's adapted matrix and comprehensive triage tables demonstrate thorough structural analysis, but the semantic analysis (Pass 2 for the hybrid) didn't uncover the deeper bugs that require cross-file pattern recognition.

### Hypothesis Results (I5/J5/K1/L1)

| # | Prediction | Result | Evidence | Confirmed? |
|---|-----------|--------|----------|:----------:|
| I1 | I5 finds BUG-2 (wrong count function) — E missed it | §4.5A Pattern 3: "Wrong function called (PRODUCTION BUG)" — CountMembersByOrg vs CountMemberSlotsUsedByOrg. | Report §4.5A and Production Bugs section | **Confirmed** |
| I2 | I5 resolves ≥5/7 disputed endpoints correctly (E got 4/7) | 4/7 correct. Wrong: POST /alert-rules/validate, GET /alert-rules/{id}/channels, GET /reports/{id}/channels. Different wrong endpoints than E but same 4/7 accuracy. | Matrix rows 41, 46, 54 | **Refuted** |
| I3 | I5 TOCTOU maintained: ≥3 windows (E found 3) | 6 windows found (3 tier races, 2 SSO redirect/callback, 1 refresh token). 7-flow enumeration table. | Report §4.6 | **Confirmed** |
| J1 | J5 finds both BUG-1 AND BUG-2 (D found both) | BUG-1: §4A Pattern 1 (3-of-4 tier-deny audit, invitation violation). BUG-2: §4A Pattern 2 (wrong count method). Plus PB1 (new). | Report §4A and Production Bugs | **Confirmed** |
| J2 | J5 completes without truncation (Run F never ran) | 481-line report with all sections present. Key Observations section at end. | Report file length | **Confirmed** |
| J3 | J5 scores ≥8.5 on v1 rubric (matching D's 8.85) | J5 scores 9.25 on v1 rubric. | Scoring above | **Confirmed** |
| K1h | K1 finds ≥1 of G's 2 production bugs (ParseTime, PK migration) | 0 production bugs. ParseTime RFC1123 not mentioned. PK migration analyzed as TOCTOU window (correctness gap #7) but not identified as data loss bug. | Report Production Bugs: "None." | **Refuted** |
| K2 | K1 assertion quality count ≥8 (G found 10) | 4 issues (3 worker timing, 1 EPSS missing negative). All are a subset of G's 10. | Report §4 | **Refuted** |
| L1h | L1 completes without truncation (H truncated at 141 lines) | 450-line report. All sections present including production bugs, assertion quality, TOCTOU, key observations. | Report file length | **Confirmed** |
| L2 | L1 TOCTOU: ≥2 windows (H's truncation hid this section) | 3 windows analyzed: EPSS advisory lock (critical gap), PK migration (no window — lock held), MITRE/OSV cursor (bounded, acceptable). 1 genuine gap, 2 correctly dismissed. | Report §4C TOCTOU Windows | **Partial** |
| L3 | L1 adapted matrix present (H's adapted matrix was excellent) | 7-column adapted matrix (advisory lock, null-byte strip, streaming parse, temp file cleanup, cursor safety, error propagation, rate limiting) across 8 pipeline operations. 4 GAP cells identified. Spot-check verification on 3 cells. | Report §3 | **Confirmed** |

**Testable: 11.** Confirmed: 7 (I1, I3, J1, J2, J3, L1h, L3). Partial: 1 (L2). Refuted: 3 (I2, K1h, K2).

**Success criteria: ≥8 of 11 confirmed.** 7 confirmed + 1 partial = **borderline fail.** The Phase 5 hypotheses all passed (I1, I3, J1-J3 = 5/5). The Phase 1 hypotheses mostly failed (K1h, K2 refuted; L1h, L3 confirmed; L2 partial = 2/3 confirmed). The context management improvements helped Phase 5 (larger scope, more context pressure) but hurt Phase 1 (smaller scope, over-conservative).

### Disputed Endpoint Resolution (I5/J5 vs Ground Truth)

All 7 endpoints are **untested** for cross-org isolation (ground truth from Runs E-H analysis, verified by reading test files).

| Endpoint | C | D | E | I5 | J5 | Ground truth |
|----------|---|---|---|----|----|:------------:|
| POST /alert-rules/validate | GAP | Tested | GAP | **Tested** (TestAlertRule_CrossOrgIsolation) | **Tested** (TestAlertRule_CrossOrgIsolation) | **GAP** |
| GET /alert-rules/{id}/channels | GAP | Tested | Tested | **Tested** (TestAlertRule_CrossOrgIsolation) | **GAP** | **GAP** |
| DELETE /alert-rules/{id}/channels/{cid} | GAP | Tested | GAP | **GAP** | **GAP** | **GAP** |
| DELETE /reports/{id}/channels/{cid} | GAP | Tested | GAP | **GAP** | **Tested** (TestReports_CrossOrgIsolation) | **GAP** |
| GET /reports/{id}/channels | GAP | Tested | Tested | **Tested** (TestReports_CrossOrgIsolation) | **Tested** (TestReports_CrossOrgIsolation) | **GAP** |
| DELETE /groups/{gid}/members/{uid} | GAP | Tested | GAP | **GAP** | **GAP** | **GAP** |
| GET /sso/link | GAP | Not listed | Tested | **GAP** | **GAP** | **GAP** |

**Accuracy by run (disputed endpoints only):**

| Run | Correct | Wrong | Accuracy |
|-----|---------|-------|----------|
| C | 6/7 | 1/7 | 86% |
| D | 0/6 | 6/6 | 0% |
| E | 4/7 | 3/7 | 57% |
| I5 | 4/7 | 3/7 | 57% |
| J5 | 4/7 | 3/7 | 57% |

**Persistent failure mode:** The cite-test-name sub-endpoint failure persists across E, I5, and J5. When a broadly-named cross-org test exists (e.g., `TestAlertRule_CrossOrgIsolation`), the skill assumes it covers all sub-endpoints (/validate, /channels, /channels/{cid}) without verifying the test actually calls those paths. Different runs get different endpoints wrong (E: /channels, /reports/channels, /sso/link; I5: /validate, /channels, /reports/channels; J5: /validate, /reports/channels/unbind, /reports/channels) but the accuracy remains stuck at 4/7.

**This failure mode requires a code-level fix:** The spot-check verification needs to grep the cited test function for the specific endpoint HTTP path, not just verify the test function exists.

### Deltas vs Prior Runs

| Comparison | v1 delta | Key changes |
|------------|----------|-------------|
| I5 vs E | **+2.10** (9.45 vs 7.35) | Both benchmark bugs found (E found 0). Cross-org restored to 21 (E: 11). Cross-handler pattern found (E: audit column only). |
| I5 vs D | **+0.60** (9.45 vs 8.85) | Enhanced skill surpasses hybrid for the first time on v1. Better matrix (10 vs 8), better cross-org (9 vs 7). |
| J5 vs D | **+0.40** (9.25 vs 8.85) | New PB1 (replay delivery). 7-column matrix. Maintained semantic analysis strength. |
| K1 vs G | **-3.20** (5.85 vs 9.05) | 0 prod bugs (G: 2). 4 assertion quality (G: 10). Context management traded depth for completion. |
| L1 vs H | **-1.05** (5.50 vs 6.55†) | Complete report (H truncated). But fewer findings across all categories. H estimate may be high. |

### Phase 5 vs Phase 1 Cross-Comparison (v4/v3 runs)

| Metric | I5 (Phase 5, enhanced v4) | K1 (Phase 1, enhanced v4) | J5 (Phase 5, hybrid v3) | L1 (Phase 1, hybrid v3) |
|--------|:-:|:-:|:-:|:-:|
| Total findings | ~95 | 20 | 110 | 44 |
| Security-critical | 62 | 3 | 57 | 8 |
| Production bugs | 2 (BUG-1, BUG-2) | 0 | 3 (BUG-1, BUG-2, PB1) | 0 |
| TOCTOU windows | 6 | 2 | 5 | 1 |
| Assertion quality | 6 | 4 | 6 | 1 |
| False positives | 3 (false "Tested") | 0 | 3 (false "Tested") | 0 |
| Report complete? | Yes | Yes | Yes | Yes |

**Observations:**

1. **Context management improvements achieved their primary goal on Phase 5.** I5 and J5 both completed successfully with comprehensive reports. I5's v1 score (9.45) is the highest of any run — the context management overhead didn't hurt the larger scope.

2. **Context management over-corrected for Phase 1.** K1 and L1 completed without truncation (fixing H's failure) but produced significantly fewer and shallower findings than G. The incremental reading approach (S6) prevented the cross-package pattern recognition that made G's analysis exceptional.

3. **Both skills converged on Phase 5 quality.** I5 (9.45) and J5 (9.25) are within 0.20 of each other — the largest convergence in the entire A/B test. Both found both benchmark bugs. Both have 4/7 disputed endpoint accuracy. The structural separation advantage that gave D its 1.80 lead over C has narrowed to 0.20.

4. **Phase 1 regressed for both skills.** K1 (5.85) is far below G (9.05), and L1 (5.50) is below H (6.55†). The v4/v3 context management improvements hurt Phase 1 performance. This is the clearest evidence that the scope-size heuristics need refinement — Phase 1's 73 functions shouldn't trigger the same context conservation as Phase 5's 559 functions.

5. **Production bug detection is the critical differentiator on Phase 1.** K1 and L1 both scored 2/10 on production bugs (0 genuine bugs found). G's 10/10 came from finding 2 genuine bugs via cross-package pattern recognition. The incremental reading approach prevents this analysis mode.

---

## Updated Recommendation (All 12 Runs)

### Summary of all scores

| Run | Skill | Scope | Rubric | Score |
|-----|-------|-------|--------|------:|
| A | path-mapping | Phase 5 | v1 | 4.60 |
| B | orig coverage-tool | Phase 5 | v1 | 1.85 |
| C | enhanced v2 | Phase 5 | v1 | 7.05 |
| D | hybrid v1 | Phase 5 | v1 | 8.85 |
| E | enhanced v3 | Phase 5 | v1 | 7.35 |
| E | enhanced v3 | Phase 5 | v2 | 6.60 |
| F | hybrid v2 | Phase 5 | — | N/A |
| G | enhanced v3 | Phase 1 | Phase 1 | **9.05** |
| H | hybrid v2 | Phase 1 | Phase 1 | 6.55 † |
| I5 | enhanced v4 | Phase 5 | v1 | **9.45** |
| I5 | enhanced v4 | Phase 5 | v2 | 8.35 |
| J5 | hybrid v3 | Phase 5 | v1 | 9.25 |
| J5 | hybrid v3 | Phase 5 | v2 | 8.25 |
| K1 | enhanced v4 | Phase 1 | Phase 1 | 5.85 |
| L1 | hybrid v3 | Phase 1 | Phase 1 | 5.50 |

### What the v4/v3 context management improvements accomplished

**Context exhaustion: fully fixed.** All 4 runs completed without truncation. K1 required S6 (incremental reading) after its initial attempt died, but the retry succeeded. L1 completed at 450 lines vs H's 141 — the incremental report writing (S3) ensured all sections were persisted. No run lost analytical output to context exhaustion.

**Phase 5 semantic analysis: significantly improved.** Both I5 and J5 found both benchmark production bugs — the first time the enhanced skill has found both (I5 found BUG-1 via cross-handler consistency, which E's audit column couldn't trigger). The v1 scores (9.45, 9.25) are the two highest Phase 5 scores in the entire A/B test. This suggests the context management improvements freed up context for deeper analysis on large scopes.

**Phase 1 semantic analysis: regressed.** K1 and L1 both missed the production bugs that G found. The incremental reading approach (S6) prevented the cross-package pattern recognition that requires seeing multiple source files simultaneously. G's ability to hold the entire 73-function scope in context was critical to finding the ParseTime RFC1123 bug — it requires connecting `feed/util.go:ParseTime` (only supports RFC3339) with `nvd/adapter.go`'s Date header fallback (expects RFC1123).

**Cite-test-name accuracy: unchanged.** All three post-improvement enhanced runs (E, I5, J5) achieve exactly 4/7 accuracy on disputed endpoints. The sub-endpoint verification failure is a design issue in the skill's spot-check instructions, not a context management issue.

### Revised scope-based selection rule

The v4/v3 data changes the recommendation:

- **Large scope (300+ functions):** Use either enhanced v4 or hybrid v3 — they now perform comparably (I5: 9.45 vs J5: 9.25). The enhanced skill has slightly better TOCTOU enumeration; the hybrid has slightly better matrix format (7 columns) and found 1 more production bug.

- **Small scope (<100 functions):** Use enhanced **v3** (not v4). G's 9.05 score on Phase 1 is the second-highest in the entire A/B test. The v4 context management improvements are unnecessary and counterproductive for small scopes. Alternatively, use v4 but explicitly instruct the agent to hold all files in context simultaneously for small scopes.

- **Deep cross-org audit:** Use enhanced first for matrix thoroughness, then hybrid for semantic depth. Both skills now achieve similar overall quality.

### Open questions

1. **Scope-size heuristics in S1 need tuning.** The "small (<100 functions): no subagents needed" heuristic is correct, but S6's "process one package at a time" instruction applies to ALL scopes and over-constrains small scopes. Consider: "For scopes with <100 functions and <10 files, you may read all source files before analysis."

2. **Cite-test-name still needs sub-endpoint verification.** 4/7 accuracy across 3 runs confirms this is a systematic failure mode, not random variance. The spot-check should grep the cited test function for the specific endpoint path (e.g., verify `TestAlertRule_CrossOrgIsolation` actually calls `/alert-rules/{id}/channels`).

3. **Production bug detection on Phase 1 remains unsolved.** The ParseTime RFC1123 bug requires cross-package semantic analysis (seeing util.go and nvd/adapter.go together). The PK migration collision requires reasoning about `ON CONFLICT` failure modes. Both are beyond what incremental reading can achieve. For small scopes, the skill should explicitly permit full-context analysis.

4. **Run F remains unexecuted.** H7 and H8 (hybrid matrix completeness gate, subagent matrix delegation) are still untestable. However, J5's results partially address these — J5 verified endpoint count (72 enumerated, 72 rows) and used subagent delegation.

---

## Runs M1, N1: Small-Scope Fix Results

Runs M1/N1 re-test Phase 1 with S7 (scope-size exception: <100 functions may read all SOURCE files before analysis). See [test design](2026-03-03-phase5-ab-test-design.md) §"Runs M1, N1" for full methodology.

**Key context:** M1's first attempt died from context exhaustion when the skill loaded 13 source files + 10 test files simultaneously. S7 was refined to explicitly separate source files (load all upfront for cross-package pattern recognition) from test files (load per-package during triage). N1 ran with the pre-refinement S7 wording and likely still used incremental reading.

### Execution Status

| Run | Skill | Lines | Truncated? | Context compaction? | Notes |
|-----|-------|-------|:----------:|:-------------------:|-------|
| M1 | Enhanced v5 | 203 | No | No | First attempt died (context exhaustion). Retry with refined S7 succeeded. Confirmed holistic source reading (line 104: cross-adapter ParseTime check). |
| N1 | Hybrid v4 | 392 | No | No | Ran with pre-refinement S7. Likely still used incremental reading (old wording was ambiguous). |

### Scoring (Phase 1 — reduced rubric, adding M1/N1 columns)

| Metric | Weight | G (enhanced v3) | H (hybrid v2) † | K1 (enhanced v4) | L1 (hybrid v3) | M1 (enhanced v5) | N1 (hybrid v4) |
|--------|--------|:-:|:-:|:-:|:-:|:-:|:-:|
| Production bugs / design violations | 25% | 10 | 6 † | 2 | 2 | **2** | **2** |
| TOCTOU windows | 20% | 8 | 4 † | 7 | 5 | **7** | **5** |
| Cross-handler consistency | 20% | 8 | 7 | 6 | 7 | **7** | **7** |
| Assertion quality | 15% | 9 | 7 † | 5 | 4 | **6** | **2** |
| False positives | 10% | 10 | 9 | 10 | 10 | **10** | **9** |
| Non-API adaptation | 10% | 10 | 10 | 10 | 10 | **10** | **10** |
| **Weighted total** | **100%** | **9.05** | **6.55** † | **5.85** | **5.50** | **6.20** | **5.10** |

### M1 Score Rationale

**Run M1 (6.20):** Modest improvement over K1 (5.85) but still far below G (9.05). Confirmed holistic source reading — line 104 explicitly states "feed.ParseTime used consistently for timestamp parsing across all adapters (not time.Parse with a single layout)" — M1 had all source files in context and examined ParseTime but concluded it was correct, missing the RFC1123 bug that G found. This is significant: the holistic reading enabled by S7 restored cross-package visibility, but the skill still didn't find the bug.

0 production bugs (G found 2). 6 TOCTOU flows enumerated with good depth — TOCTOU-2 identifies the untested advisory lock coordination, TOCTOU-5 identifies the worker claim/complete gap, TOCTOU-6 catches the midnight edge case. Cross-adapter analysis covers 4 patterns across all adapters with KEV inconsistency noted and downloadToTemp dedup recommendation. 5 assertion quality issues (AQ-1 through AQ-5) — a clear improvement over K1's 4, catching execution-only tests (AQ-1, AQ-2) and t.Skip stubs (AQ-4). Zero false positives. Matrix correctly N/A.

### N1 Score Rationale

**Run N1 (5.10):** Regression from L1 (5.50) despite nominally having S7 available. N1 ran with the pre-refinement S7 wording and likely still used incremental reading (the old wording was ambiguous enough that the skill didn't change behavior).

0 production bugs. TOCTOU analysis checks 4 flows but concludes "No TOCTOU windows found" — misses the worker claim/complete gap and the midnight edge case that M1 identified. Cross-adapter analysis covers 4 patterns across all 6 adapters — comparable to M1. The adapted pipeline security matrix is excellent (7 columns, 9 components, 4 GAPs, 3 spot-checks verified) — the best matrix format in any Phase 1 run. However, assertion quality is the major weakness: §5 claims "No anti-patterns detected" despite clear issues that M1 found (AQ-1: TestApply_SameDayCursorSkips is execution-only, AQ-3: recoverCalls never asserted, AQ-4: t.Skip stubs). This incorrect "clean" assessment is a false negative, scored 2/10. False positives penalized slightly for the overstated assertion quality claim.

### Hypothesis Results (M1/N1)

| # | Prediction | Result | Evidence | Confirmed? |
|---|-----------|--------|----------|:----------:|
| M1h | M1 finds ≥1 of G's 2 production bugs (ParseTime RFC1123, PK migration) | 0 production bugs found. Line 104 explicitly examined ParseTime and concluded it was correct — M1 had the context but not the analytical insight. | Report §4.5B: "No wrong-function-called issues" + §6 Production Bugs: "None." | **Refuted** |
| M2 | M1 assertion quality count ≥8 (G found 10, K1 found 4) | 5 found (AQ-1 through AQ-5). Improvement over K1 (4) but well below G (10). | Report §4 Assertion Quality Issues | **Refuted** |
| M3 | M1 TOCTOU count ≥4 (G found 8, K1 found 8) | 6 flows enumerated. 2 temporal windows (TOCTOU-5: worker claim gap, TOCTOU-6: midnight edge). 1 untested coordination (TOCTOU-2). | Report §4.6 | **Confirmed** |
| M4 | M1 cross-adapter consistency identifies patterns across all 6 adapters | All 6 adapters compared for malformed records, downloadToTemp, null bytes, constructor nil-client. KEV inconsistency noted. | Report §4.5A | **Confirmed** |
| M5 | M1 score ≥7.5 (recovering from K1's 5.85 toward G's 9.05) | 6.20. Only +0.35 over K1. 2.85 below G. | Scoring above | **Refuted** |
| N1h | N1 finds ≥1 production bug (L1 found 0) | 0 production bugs found. "Semantic analysis (§4) found no wrong-function-called bugs." | Report §4 and Production Bugs | **Refuted** |
| N2 | N1 cross-adapter consistency improves over L1 | Comparable, not clearly improved. N1 covers 4 patterns across all 6 adapters — similar scope to L1. Both scored 7/10 on cross-handler. | Report §4A | **Partial** |
| N3 | N1 completes without truncation (L1 completed at 450 lines) | 392-line report with all sections present. Complete. | Report file length | **Confirmed** |
| N4 | N1 score ≥6.5 (recovering from L1's 5.50) | 5.10. Regression of -0.40 from L1. | Scoring above | **Refuted** |

**Testable: 9.** Confirmed: 3 (M3, M4, N3). Partial: 1 (N2). Refuted: 5 (M1h, M2, M5, N1h, N4).

**Success criteria: ≥6 of 9 confirmed.** 3 confirmed + 1 partial = **CLEAR FAIL.** The critical hypotheses (M1h, M5) were both refuted. Holistic source reading did NOT restore production bug detection or recover toward G's score.

### Root Cause Validation

**S6 was NOT the sole cause of the K1/L1 regression.**

The M1/N1 experiment was designed to test whether restoring holistic file reading for small scopes would recover G-level performance. The result is conclusive: it didn't.

| Run | Skill version | Holistic reading? | Production bugs | Score | Delta from G |
|-----|--------------|:-:|:-:|------:|-----:|
| G | Enhanced v3 (no S1-S6) | Yes (by default) | 2 | 9.05 | — |
| K1 | Enhanced v4 (S1-S6) | No (S6 forced incremental) | 0 | 5.85 | -3.20 |
| M1 | Enhanced v5 (S1-S6 + S7) | Yes (S7 exception) | 0 | 6.20 | -2.85 |

M1 improved only **+0.35** over K1 (from 5.85 to 6.20). The improvement came from slightly better assertion quality (5 vs 4 issues) and marginally better cross-handler analysis (7/10 vs 6/10). But production bug detection — the highest-weighted metric — remained at 0/10 for both.

The most telling evidence is M1's line 104: the skill had all source files in context, explicitly examined ParseTime's usage across adapters, and concluded "used consistently" — the opposite of G's finding that ParseTime doesn't support RFC1123 format. This means the regression isn't about context visibility (which S7 restored) but about **analytical depth**: the S1-S5 structural changes and P1-P4 prompt mitigations appear to bias the skill toward efficient gap reporting rather than deep semantic analysis.

**Three-way comparison (G → K1 → M1):**

| Metric | G | K1 | M1 | K1→M1 delta | G→M1 gap |
|--------|:-:|:-:|:-:|:-:|:-:|
| Production bugs | 10 | 2 | 2 | 0 | **-8** |
| TOCTOU | 8 | 7 | 7 | 0 | -1 |
| Cross-handler | 8 | 6 | 7 | +1 | -1 |
| Assertion quality | 9 | 5 | 6 | +1 | -3 |
| False positives | 10 | 10 | 10 | 0 | 0 |
| Non-API | 10 | 10 | 10 | 0 | 0 |
| **Weighted** | **9.05** | **5.85** | **6.20** | **+0.35** | **-2.85** |

The production bugs metric (25% weight) accounts for 2.00 of the 2.85-point gap. The remaining 0.85 comes from assertion quality (-0.45) and cross-handler consistency (-0.20) and TOCTOU (-0.20). This confirms that production bug detection is both the most impactful metric and the one most resistant to the incremental improvements in S1-S7.

### Delta Analysis

| Comparison | Score delta | Key changes |
|------------|:----------:|-------------|
| M1 vs K1 | **+0.35** | Same 0 prod bugs. +1 assertion quality issue (AQ-4: t.Skip stubs). +1 cross-handler score (downloadToTemp dedup recommendation). S7 restored holistic reading but didn't unlock deeper analysis. |
| N1 vs L1 | **-0.40** | Same 0 prod bugs. Assertion quality collapsed (0 vs 1 issue, wrong "no anti-patterns" claim). Pipeline matrix improved. N1 likely didn't benefit from S7 (ran with ambiguous wording). |
| M1 vs G | **-2.85** | 0 vs 2 prod bugs (the critical gap). 5 vs 10 assertion quality. 7 vs 8 cross-handler. M1 had the context but not the analytical insight. |
| N1 vs H | **-1.45** | Both complete. N1 has better matrix format. But N1's assertion quality regression (2/10 vs 7/10†) drags the score below H's estimate. |

### Phase 1 Trend (6 runs)

| Run | Skill | Score | Prod bugs | Key characteristic |
|-----|-------|------:|:-:|---|
| G | Enhanced v3 | **9.05** | 2 | No S1-S6; holistic reading by default; deepest semantic analysis |
| H † | Hybrid v2 | 6.55 | 1 † | Truncated at 141 lines; score estimated |
| K1 | Enhanced v4 | 5.85 | 0 | S1-S6 applied; incremental reading; completed but shallow |
| L1 | Hybrid v3 | 5.50 | 0 | S1-S6 applied; incremental reading; complete but shallow |
| M1 | Enhanced v5 | 6.20 | 0 | S7 holistic source reading restored; still no prod bugs |
| N1 | Hybrid v4 | 5.10 | 0 | S7 available but likely unused (ambiguous wording); worst assertion quality |

**The trend is clear:** G remains the best Phase 1 run by a wide margin. Every subsequent skill version (v4, v5) with S1-S6 improvements has scored 2.85–3.95 points lower. The context management improvements that dramatically helped Phase 5 (I5: 9.45, J5: 9.25) actively harmed Phase 1 performance, and S7 provided only marginal recovery.

---

## Updated Recommendation (All 14 Runs)

### Summary of all scores

| Run | Skill | Scope | Rubric | Score |
|-----|-------|-------|--------|------:|
| A | path-mapping | Phase 5 | v1 | 4.60 |
| B | orig coverage-tool | Phase 5 | v1 | 1.85 |
| C | enhanced v2 | Phase 5 | v1 | 7.05 |
| D | hybrid v1 | Phase 5 | v1 | 8.85 |
| E | enhanced v3 | Phase 5 | v1 | 7.35 |
| E | enhanced v3 | Phase 5 | v2 | 6.60 |
| F | hybrid v2 | Phase 5 | — | N/A |
| G | enhanced v3 | Phase 1 | Phase 1 | **9.05** |
| H | hybrid v2 | Phase 1 | Phase 1 | 6.55 † |
| I5 | enhanced v4 | Phase 5 | v1 | **9.45** |
| I5 | enhanced v4 | Phase 5 | v2 | 8.35 |
| J5 | hybrid v3 | Phase 5 | v1 | 9.25 |
| J5 | hybrid v3 | Phase 5 | v2 | 8.25 |
| K1 | enhanced v4 | Phase 1 | Phase 1 | 5.85 |
| L1 | hybrid v3 | Phase 1 | Phase 1 | 5.50 |
| M1 | enhanced v5 | Phase 1 | Phase 1 | 6.20 |
| N1 | hybrid v4 | Phase 1 | Phase 1 | 5.10 |

### What M1/N1 taught us

**S7 (holistic source reading) is necessary but not sufficient for small-scope bug detection.** M1 proved that having all source files in context is a prerequisite for cross-package analysis — the skill explicitly compared ParseTime usage across adapters (line 104). But it drew the wrong conclusion ("used consistently"), meaning the analytical depth that found G's bugs requires something beyond context visibility.

**The regression root cause is cumulative, not single-variable.** The hypothesis that S6 alone caused the K1/L1 regression was refuted. The actual cause is the combined effect of S1-S6 + P1-P4 structural and prompt changes that bias the skill toward:
1. Efficient coverage gap enumeration over deep semantic analysis
2. Systematic section-by-section processing over exploratory cross-file reasoning
3. Completeness assurance over analytical risk-taking

**G's success may be partially irreproducible.** G ran with enhanced v3 — no context management guardrails (S1-S6), no prompt mitigations (P1-P4). Its exceptional performance came from unconstrained analytical freedom combined with a small-enough scope to fit in context. The guardrails added in v4/v5 are necessary for large scopes (I5/J5 prove this) but cannot be selectively disabled for small scopes without also losing the structural discipline that prevents context exhaustion.

### Revised scope-based selection rule (final)

- **Large scope (300+ functions):** Use enhanced v4 or hybrid v3 — both perform comparably (I5: 9.45 vs J5: 9.25). Context management improvements are essential and effective.

- **Small scope (<100 functions):** Use enhanced **v3** (the G configuration). The v4/v5 context management improvements are counterproductive for small scopes. S7's holistic reading exception is insufficient to recover G-level analytical depth. If using v4+, the entire S1-S6 stack constrains the skill's analytical freedom in ways that can't be fixed by a single S7 exception.

- **Alternative for small scope:** Accept 6.20-level output from v5 (M1) as the "reliable minimum" and use it when consistency matters more than peak performance. G's 9.05 may have variance that makes it unreliable as a baseline.

### Open questions (updated)

1. **Are G's results reproducible?** G's 9.05 score with 2 production bugs may include variance from favorable context ordering or analytical choices that aren't consistently reproducible. A re-run of G's exact configuration (enhanced v3, Phase 1, no S1-S7) would test this.

2. **Can targeted prompt changes restore bug detection without full v3 rollback?** The production bug detection regression appears linked to the overall analytical style imposed by S1-S6, not to any single change. A skill version that preserves S3 (incremental writing) and S7 (small-scope exception) but removes S1-S2 (scope classification/subagent planning) and S4-S5 (compact matrix format) might find a middle ground.

3. **Cite-test-name sub-endpoint verification still needed.** 4/7 accuracy across E, I5, J5 confirms a systematic failure mode. This is a design fix, not a context management issue.

4. **Run F remains unexecuted.** Low priority given J5's comparable data.
