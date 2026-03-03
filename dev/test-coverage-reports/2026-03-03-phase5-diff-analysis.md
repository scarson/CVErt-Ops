# Phase 5 Coverage Review — Diff Analysis (Coverage-Tool vs Path-Mapping)

**Date:** 2026-03-03
**Purpose:** Compare the coverage-tool-guided review (`test-coverage-review-go` skill) against the path-mapping review (`test-coverage-review` skill) on the same codebase to evaluate which approach produces more actionable, accurate results.

---

## Headline Numbers

| Metric | Path-Mapping (v1) | Coverage-Tool (v2) | Delta |
|--------|-------------------|-------------------|-------|
| Total gaps | 223 | 137 | -86 (-39%) |
| Security-critical | 36 | 19 | -17 (-47%) |
| Correctness | 144 | 73 | -71 (-49%) |
| Nice-to-have | 43 | 42 | -1 (-2%) |
| Assertion quality | 0 | 3 | +3 (new) |
| Production bugs found | 2 | 0 | -2 |
| False positives | 0 | 1 (phantom file note) | — |
| Phantom files flagged | 1 (writer.go) | 0 | -1 |
| Mischaracterized packages | 1 (tier/limits.go) | 0 | -1 |
| Subagents dispatched | 6 | 3 | -3 |

The coverage-tool review found **39% fewer total gaps** — but the real story is which gaps each approach uniquely caught and which were noise.

---

## Accuracy Wins for Coverage-Tool

### 1. Eliminated the phantom file (writer.go)

The path-mapping review flagged `internal/api/writer.go` as a highest-risk file (60% gap rate, 9 gaps) with "audit log writer, URL redaction." **No such file exists.** The `writeJSON` helper lives in `orgs.go:44` and is a 7-line JSON encoder. The path-mapping approach hallucinated a file name and then enumerated gaps for it. The coverage-tool approach cannot hallucinate files — it works from `go tool cover -func` output which only lists real functions.

**Impact:** 9 gaps in the path-mapping report are against a nonexistent file. At least 5 of these were security-critical (gaps #20, #75-82 in the path-mapping report).

### 2. Correctly identified tier package coverage

The path-mapping review reported `tier/limits.go` as having "100% gap rate, no test file" with 14 correctness gaps. In reality:
- `resolver_test.go` exists and is comprehensive
- `limits.go` functions (`ResolveInt`/`ResolveBool`) are one-line delegations to `resolver.go`
- `-coverpkg` reveals 100% cross-package coverage

The coverage-tool approach saw 100% on all 4 tier functions and correctly categorized the package as well-covered. Path-mapping structurally cannot detect cross-package coverage — it only looks at whether a file has a `_test.go` companion.

**Impact:** 14 gaps in the path-mapping report were false positives. The "100% gap rate" designation made `limits.go` appear as the highest-risk file when it's actually the best-tested.

### 3. Assertion quality as a first-class finding

The coverage-tool review identified 3 assertion quality issues:
1. Conditional assertion in `TestTierMiddleware_ResolverHasCorrectTier` that silently passes
2. `InsertAuditEntry` at 100% line coverage but shallow on nullable fields
3. OIDC CSRF test only checks missing cookie, not tampered value

These are structurally invisible to path-mapping. Path-mapping asks "does a test exist for this path?" — it cannot check whether the test's assertions are meaningful. The CSRF test is especially important: the path-mapping review counted the CSRF path as covered, while the coverage-tool review correctly identified that only cookie-absence (not cookie-mismatch) is tested.

### 4. Precise coverage percentages guide prioritization

Every function in the coverage-tool report has an objective coverage percentage. This enables:
- Knowing exactly which functions need the most work (e.g., `oidcVerifyCallback` at 48.4%)
- Distinguishing "75% covered, one error branch missing" from "0% covered, everything missing"
- Tracking remediation progress with before/after metrics

Path-mapping provides "gap rate" percentages but these are based on estimated path counts, which vary with reviewer thoroughness.

---

## Accuracy Wins for Path-Mapping

### 1. Found 2 production bugs the coverage-tool missed

**BUG-1:** Invitation handler missing audit log on tier block (`orgs.go:404-407`). All other tier-gated handlers write an audit entry with `Success: false` when a tier limit is hit — the invitation handler doesn't. This is a cross-handler consistency issue detectable only by reading the code and comparing patterns.

**BUG-2:** `org_tier.go:61` uses `CountMembersByOrg` (active members only) instead of `CountMemberSlotsUsedByOrg` (members + pending invitations). This is a semantic correctness issue — the wrong function is called. Coverage tools show the line is executed; they can't tell it's the wrong function.

**Why the coverage-tool missed these:** Both bugs are in code paths with nonzero coverage. The lines execute successfully — they just do the wrong thing. Coverage tools measure execution, not intent. Path-mapping reads the code semantically and compares it against design intent, which is how these were caught.

### 2. Higher security-critical count with more granular OIDC analysis

Path-mapping found 36 security-critical gaps vs 19. The difference isn't just noise — path-mapping identified:

- **4 handler fail-closed defense gaps** (gaps #5-9): resolver missing → 500 paths for `createAlertRuleHandler`, `createChannelHandler`, `createWatchlistHandler`, `createInvitationHandler`. The coverage-tool flagged only 1 (tier middleware passthrough). These test defense-in-depth — the middleware should prevent this, but the handler's safety net needs its own test.

- **6 cross-org isolation store-level gaps** (gaps #10-15): `UpdateOrgTier`, count functions, `ListAuditEntries`, SSO store methods. The coverage-tool found 1 (`updateOrgHandler` cross-org). Path-mapping's security checklist systematically checked every store method.

- **5 audit/redaction security gaps** (gaps #18-22): URL query param redaction, userinfo leakage, marshal error dropping audit entries. The coverage-tool classified most of these as correctness or nice-to-have.

- **OIDC callback: 11 gaps vs 10.** Path-mapping distinguished between wrong-key, wrong-issuer, wrong-audience, and expired token verification (4 separate gaps at the same line range). Coverage-tool rolled these into 1 gap ("ID token verification failure") because they're the same coverage line. The path-mapping granularity is more useful here — each is a distinct attack vector requiring a distinct test.

### 3. TOCTOU analysis identified real temporal risks

Path-mapping explicitly flagged TOCTOU risks:
- Gap #28: SSO connection deleted between redirect and callback
- Gap #29: SSO connection disabled between redirect and callback

The coverage-tool noted "No TOCTOU windows detected" — because it evaluated from the perspective of code coverage, not temporal attack surfaces. The coverage-tool saw these as "not found in DB" error branches (correctness), not as security-relevant timing attacks. Whether these are security-critical depends on threat model, but the path-mapping review's framing is more useful.

---

## Gap Overlap Analysis

### Gaps found by both approaches

Both reviews identified the same core gaps, with the coverage-tool being more precise about which specific line is untested:

| Area | Path-mapping gaps | Coverage-tool gaps | Overlap |
|------|------------------|-------------------|---------|
| OIDC callback validation | 11 | 10 | ~95% — same branches, different granularity on token verification |
| Org handler error branches | ~25 | 25 | ~90% — coverage-tool has exact line numbers |
| SSO handler branches | 32 | 16 | ~50% — coverage-tool consolidated error patterns |
| Store error wrapping | ~15 | ~40 (as nice-to-have) | ~100% — reclassified but same gaps |
| Tier middleware | 4 (security) + 6 (correctness) | 1 (security) + 1 (correctness) | Coverage-tool was more conservative |

### Gaps unique to path-mapping

1. **Production bugs** (BUG-1, BUG-2) — semantic correctness issues invisible to coverage
2. **Cross-handler pattern consistency** (audit log on tier block not asserted across handlers)
3. **Design-doc validation** (constant values not asserted against design doc, 6 gaps)
4. **Mock IdP adversarial modes** (gaps #145-146) — identifies what the test infrastructure itself needs
5. **Cache stale → privilege escalation** (gap #27) — security implication of a caching bug
6. **Worker panic recovery** (gap #67) — crash kills entire worker, no recovery

### Gaps unique to coverage-tool

1. **Assertion quality issues** (3 gaps) — tests that execute but don't assert
2. **`AcceptInvitation` standalone RLS bypass** (gap #18) — exported method bypasses transaction helpers
3. **Transaction helper panic recovery** (observation #7) — 4 paths in `withBypassTx`/`withOrgRawTx`
4. **Pre-existing test failure** noted (observation #10)

---

## Severity Classification Comparison

The reviews differ significantly on what's "security-critical" vs "correctness":

| Gap type | Path-mapping classification | Coverage-tool classification |
|----------|---------------------------|---------------------------|
| Handler missing ctxOrgID → 400 | security-critical (fail-closed) | correctness |
| Resolver missing → 500 | security-critical (defense-in-depth) | correctness |
| Cross-org store isolation | security-critical | security-critical (but fewer found) |
| Store error → 500 | correctness | nice-to-have (~37 reclassified) |
| OIDC token verification variants | 4 security-critical gaps | 1 security-critical gap |

The path-mapping review was more aggressive about escalating severity, especially for fail-closed defense gaps. The coverage-tool review treated handler error branches more uniformly.

---

## Resource Efficiency

| Metric | Path-Mapping | Coverage-Tool |
|--------|-------------|--------------|
| Subagents dispatched | 6 | 3 |
| Time to complete | ~25 min (estimated) | ~15 min (estimated) |
| False positives | 23+ (phantom file + tier package) | 0 |
| Scope | ~32 source files | Same, but coverage-guided triage |

The coverage-tool approach used 50% fewer subagents because it knew which functions to focus on. Path-mapping dispatched subagents per file group without knowing which files had meaningful coverage gaps — wasting analysis time on well-covered code.

---

## Key Takeaways

### 1. Coverage-tool is more accurate but less insightful

The coverage-tool eliminated all false positives (phantom files, mischaracterized packages) and provided precise coverage data. But it missed the 2 production bugs and was less thorough on security analysis. **Coverage tools answer "is this line executed?" — they cannot answer "does this line do the right thing?"**

### 2. Path-mapping finds semantic bugs that coverage tools structurally cannot

Both production bugs (BUG-1: missing audit log, BUG-2: wrong count method) were in code with nonzero coverage. The lines execute — they just call the wrong function or omit a side effect. This is the highest-value finding type and it's exclusive to the semantic approach.

### 3. The security checklist is more effective in path-mapping

Path-mapping's systematic per-endpoint security checklist found 6 cross-org isolation gaps, 5 fail-closed defense gaps, and 5 audit/redaction gaps that the coverage-tool either missed or classified lower. The coverage-tool has the same checklist in its skill definition but applied it less rigorously — likely because the coverage data provided a false sense of security for functions with 60-80% coverage.

### 4. Assertion quality is unique to coverage-tool and high value

The 3 assertion quality findings are structurally invisible to path-mapping. The conditional assertion in tier middleware is especially dangerous — it silently passes regardless of actual behavior. This is a new class of finding that justifies the coverage-tool approach.

### 5. The approaches are genuinely complementary

| Strength | Path-Mapping | Coverage-Tool |
|----------|-------------|--------------|
| Accuracy (no false positives) | Weak | **Strong** |
| Semantic bug detection | **Strong** | Weak |
| Cross-handler consistency | **Strong** | Weak |
| Assertion quality | None | **Strong** |
| Security checklist rigor | **Strong** | Moderate |
| Prioritization data | Estimated | **Objective** |
| Resource efficiency | Higher cost | **Lower cost** |
| TOCTOU / timing analysis | **Strong** | Weak |

---

## Recommendation

**Neither skill replaces the other.** The optimal workflow is:

1. **Run coverage-tool first** — get objective baseline, eliminate phantom-file risk, identify assertion quality issues, focus analysis time on functions that actually need it
2. **Run path-mapping second** on the security-critical functions identified by step 1 — apply the security checklist, check for semantic correctness, look for cross-handler consistency issues, identify TOCTOU windows

This two-pass approach would have caught everything both reviews found while avoiding the 23+ false positives from path-mapping-first. The coverage-tool provides the map; path-mapping provides the judgment.

Alternatively: merge the best of both into a single skill that uses coverage data as the foundation but layers the security checklist and semantic analysis from path-mapping on top. This is essentially what `test-coverage-review-go` was designed to do, but the Phase 5 run shows it needs stronger enforcement of the security checklist and cross-handler pattern analysis.
