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
| E | `test-coverage-review-go` | Enhanced v3 (8 improvements) | Phase 5 | **Planned** | `phase5-enhanced-v3-review.md` |
| F | `test-coverage-review-hybrid-go` | Hybrid v2 (8 improvements) | Phase 5 | **Planned** | `phase5-hybrid-v2-review.md` |
| G | `test-coverage-review-go` | Enhanced v3 (8 improvements) | **Phase 1** | **Planned** | `phase1-enhanced-v3-review.md` |
| H | `test-coverage-review-hybrid-go` | Hybrid v2 (8 improvements) | **Phase 1** | **Planned** | `phase1-hybrid-v2-review.md` |

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

**Implication:** These disagreements need ground-truth verification against the actual test files. If Run C is right, Run D under-reports cross-org gaps (its matrix is less thorough). If Run D is right, Run C over-reports (false GAPs). Either way, the matrix format makes these disagreements visible and auditable — an improvement over prose-based reviews where such conflicts would be invisible.

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

## Runs E-F: Post-Improvement Validation (Planned)

Runs E and F test whether the 8 targeted improvements derived from C/D analysis close the identified gaps. See [test design](2026-03-03-phase5-ab-test-design.md) §"Runs E and F" for full methodology.

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

### Scoring Summary v1 (Runs E-F — for historical comparison with A-D)

*To be filled after runs complete.*

| Metric | Weight | C (enhanced v2) | D (hybrid v1) | E (enhanced v3) | F (hybrid v2) | Delta C→E | Delta D→F |
|--------|--------|:-:|:-:|:-:|:-:|:-:|:-:|
| Security matrix completeness | 25% | 9 | 8 | — | — | — | — |
| Production bugs found | 25% | 7 | 10 | — | — | — | — |
| Cross-org isolation gaps | 15% | 10 | 7 | — | — | — | — |
| Assertion quality findings | 10% | 2 | 10 | — | — | — | — |
| TOCTOU windows identified | 10% | 0 | 10 | — | — | — | — |
| False positives | 10% | 9 | 8 | — | — | — | — |
| Cross-handler consistency | 5% | 9 | 10 | — | — | — | — |
| **Weighted total** | **100%** | **7.05** | **8.85** | **—** | **—** | **—** | **—** |

### Scoring Summary v2 (Runs E-F Only — measures specific improvements)

*To be filled after runs complete.*

| Metric | Weight | E (enhanced v3) | F (hybrid v2) | How scored |
|--------|--------|:-:|:-:|------------|
| Production bugs found | 20% | — | — | BUG-1? BUG-2? New bugs? |
| Matrix completeness | 10% | — | — | Route enumeration performed? All endpoints present? Count verified? |
| Matrix accuracy | 15% | — | — | Test names cited? Spot-check performed? Score against 7 disputed endpoints. |
| Cross-org isolation gaps | 10% | — | — | Count. |
| Assertion quality findings | 10% | — | — | Count. Conditional assertion found? |
| TOCTOU windows identified | 10% | — | — | Count. Multi-step flow enumeration performed? |
| False positives | 10% | — | — | Phantom files? False GAPs? False "Tested" marks? |
| Cross-handler consistency | 5% | — | — | Audit pattern identified? All siblings compared? |
| Audit log gap detection | 10% | — | — | Audit-specific findings from 7th column. Count. |
| **Weighted total** | **100%** | **—** | **—** | |

### Hypothesis Results

*To be filled after runs complete.*

| # | Prediction | Run E | Run F | Confirmed? |
|---|-----------|-------|-------|:----------:|
| H1 | Audit log column catches BUG-1 | — | — | — |
| H2 | Cite-test-name resolves ≥4 of 7 disputed endpoints | — | — | — |
| H3 | Route enumeration: all endpoints present, count stated | — | — | — |
| H4 | Spot-check performed (3 cells verified) | — | — | — |
| H5 | Conditional assertion in tier middleware identified | — | — | — |
| H6 | Enhanced TOCTOU: ≥1 window found (was 0 in Run C) | — | N/A | — |
| H7 | Hybrid matrix completeness: count verification in report | N/A | — | — |
| H8 | Subagent matrix quality maintained (if triggered) | N/A | — | — |

**Success criteria:** ≥6 of 8 hypotheses confirmed.

### Disputed Endpoint Resolution

*To be filled after runs complete. E/F should produce cited test function names (or GAP) for each, resolving the C/D disagreements.*

| Endpoint | Run C | Run D | Run E | Run F | Ground truth |
|----------|-------|-------|-------|-------|-------------|
| POST /alert-rules/validate | GAP | Tested | — | — | — |
| GET /alert-rules/{id}/channels | GAP | Tested | — | — | — |
| DELETE /alert-rules/{id}/channels/{cid} | GAP | Tested | — | — | — |
| DELETE /reports/{id}/channels/{cid} | GAP | Tested | — | — | — |
| GET /reports/{id}/channels | GAP | Tested | — | — | — |
| DELETE /groups/{id}/members/{uid} | GAP | Tested | — | — | — |
| GET /sso/link | GAP | Not listed | — | — | — |

---

## Runs G-H: Phase 1 Generalization Test (Planned)

Runs G and H test whether the improvements generalize beyond Phase 5's HTTP handlers to Phase 1's data ingestion code (feed adapters, merge pipeline, worker pool). See [test design](2026-03-03-phase5-ab-test-design.md) §"Runs G and H" for full methodology.

**Key difference from E-F:** Phase 1 has no org-scoped API endpoints. Matrix improvements (audit log column, cite-test-name, route enumeration, spot-check) are untestable. Semantic improvements (TOCTOU, cross-handler consistency, assertion quality, wrong-function-called) are the focus.

### Phase 1 Coverage Baseline

*To be filled after coverage data generation.*

| Package | Coverage | Functions | Uncovered |
|---------|----------|-----------|-----------|
| internal/feed/... | — | — | — |
| internal/merge/... | — | — | — |
| internal/worker/... | — | — | — |
| **Overall** | **—** | **—** | **—** |

### Scoring (G/H — Phase 1 reduced rubric)

*To be filled after runs complete. Matrix-specific metrics are N/A for Phase 1.*

| Metric | Weight | G (enhanced v3) | H (hybrid v2) | How scored |
|--------|--------|:-:|:-:|------------|
| Production bugs / design violations | 25% | — | — | Wrong function called, missing side effects, pattern violations. No benchmarks — all genuine. |
| TOCTOU windows | 20% | — | — | Count. Multi-step flow enumeration? Advisory lock analysis? |
| Cross-handler consistency | 20% | — | — | Feed adapter patterns compared (all 6?). Violations found. |
| Assertion quality | 15% | — | — | Count. Conditional assertion check applied? |
| False positives | 10% | — | — | Fabricated endpoints, mischaracterized packages, wrong coverage interpretation. |
| Non-API adaptation | 10% | — | — | Matrix correctly N/A? No forced org-scoped analysis? |
| **Weighted total** | **100%** | **—** | **—** | |

### Generalization Hypotheses

*To be filled after runs complete.*

| # | Prediction | Run G | Run H | Confirmed? |
|---|-----------|-------|-------|:----------:|
| G1 | TOCTOU: ≥1 temporal window in merge pipeline | — | — | — |
| G2 | Cross-handler: shared patterns across 6 feed adapters identified | — | — | — |
| G3 | Assertion quality: shallow assertions found in feed/merge tests | — | — | — |
| G4 | Wrong-function-called: incorrect function usage identified | — | — | — |
| G5 | Non-API scope: matrix correctly N/A, no fabricated endpoints | — | — | — |
| G6 | Structural separation: hybrid (H) finds more semantic issues than enhanced (G) | N/A | — | — |

**Success criteria:** ≥4 of 6 hypotheses confirmed.

### Cross-Phase Comparison

*To be filled after all 8 runs complete. Compares findings density and type distribution between Phase 5 (E/F) and Phase 1 (G/H).*

| Metric | E (Phase 5) | F (Phase 5) | G (Phase 1) | H (Phase 1) |
|--------|:-:|:-:|:-:|:-:|
| Total findings | — | — | — | — |
| Security-critical | — | — | — | — |
| TOCTOU windows | — | — | — | — |
| Cross-handler violations | — | — | — | — |
| Assertion quality issues | — | — | — | — |
| False positives | — | — | — | — |
