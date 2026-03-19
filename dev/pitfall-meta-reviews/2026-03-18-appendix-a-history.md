
---

# Appendix A: Historical Changelog

This appendix preserves the provenance and validation history of every finding in this document. It serves documentation-maintaining agents who need to understand when a finding was discovered, whether it was theoretical or empirical, and whether it has been validated against the actual codebase.

---

## A.1 Pre-Implementation Architectural Review (2026-02-21)

**Source:** 52 rounds of Gemini Pro architectural review of PLAN.md before implementation began.
**Nature:** Theoretical — predictions about implementation traps based on the architecture document.
**Scope:** Rounds 1-23 produced the original sections 1-5 (Go traps, DB pitfalls, security vulnerabilities, operational footguns, architecture decisions). Rounds 24-52 added findings in categories 6-12 (additional Go traps, feed specifics, security refinements, operational corrections, architectural additions, schema patterns).

These findings were predictive. Many proved accurate when implementation began; a few were superseded by different architectural choices that avoided the predicted trap entirely. The 2026-03-18 validation audit confirmed 106 of ~120 pre-implementation findings were correctly implemented.

**Key meta-observations from this review:**
- Iterative patches rarely fix flawed foundations (EPSS went through four rounds before the correct solution emerged: remove from material_hash entirely)
- Wording precision matters when the document is an AI coding spec — imprecise architecture docs produce imprecise implementations
- Library interface details must be in the spec (archive/zip needing io.ReaderAt, GitHub lacking OIDC)
- Security assumptions deserve adversarial review — ask "what if someone abuses this?" not just "does this work?"
- "Already handled" findings validate design decisions and prevent over-engineering
- Child table data model correctness: always denormalize org_id, never rely on parent-join RLS

## A.2 Post-Implementation Findings

| Date | Source | Section | Nature |
|------|--------|---------|--------|
| 2026-02-28 | Phase 2a code review | Process Guardrails (now ARCH-34–39) | Empirical — patterns that slipped through implementation |
| 2026-03-01 | Phase 3b test coverage audit | Operational (now API-8, API-9) | Empirical — found while closing 24 test gaps |
| 2026-03-01 | Phase 4 AI Gateway | Architecture (now ARCH-25–29) | Empirical — discovered building Gemini integration |
| 2026-03-11 | Health review retrospective | Cross-cutting (now ARCH-30–33) | Empirical — 6 re-occurrences of documented pitfalls in different code locations |
| 2026-03-16 | Phase 8 bug hunts | Multiple sections | Empirical — scheduler ignoring paused_at, lockout state disconnect, admin feed endpoints |
| 2026-03-17 | Phase 8E bug hunts | Architecture (now ARCH-41) | Empirical — hot-reload infrastructure disconnected from consumers |
| 2026-03-17 | Phase 11 MFA bug hunts | Auth (now AUTH-23) | Empirical — password reset MFA bypass, stale token_version |
| 2026-03-18 | Health review + audit | Multiple sections | Empirical — 10 new pitfalls added; 7 existing pitfalls strengthened |

## A.3 Meta-Observations on the Review Process

**From rounds 24-52:**
- Library defaults are unsafe by default. Go's http.Client follows redirects. time.After leaks timers. omitempty drops zero values. CREATE INDEX takes exclusive lock. None are wrong in isolation; each becomes a production failure under CVErt Ops's workload.
- The redirect SSRF is a multi-layer validation gap — safeurl validates inputs but not intermediate redirect states. Audit all outbound HTTP for re-validation gaps.
- Notification delivery is where most bugs accumulate — the most complex stateful path with DB writes, outbound HTTP, retry logic, fan-out, debouncing, and Slack quirks.
- Timezone handling is deceptively hard — 24*time.Hour is correct 364 days/year and wrong once. Always use timezone-aware arithmetic for calendar-semantic scheduling.

**From the 2026-03-18 reorganization:**
- 47 raw bug hunt candidates collapsed to 10 genuinely new patterns — most bugs are instances of a few recurring meta-patterns (flag not checked at enforcement point, infrastructure without consumers, silent error suppression, non-atomic token consumption)
- The documents implementation-pitfalls.md and testing-pitfalls.md are complementary: one specifies WHAT/WHY, the other specifies HOW TO VERIFY. Neither replaces the other.
- A pitfall document that isn't maintained drifts. Appendix C exists to prevent the next drift.

## A.4 Validation Audit (2026-03-18)

**Method:** 10-agent parallel audit of all ~120 findings against the actual codebase, plus 4 harvest agents mining bug hunts and health reviews for undocumented patterns, plus 1 cross-reference agent comparing against testing-pitfalls.md.

**Results:**
| Status | Count | Notes |
|--------|-------|-------|
| VALIDATED | 106 | Code matches prescription |
| DIVERGED (better) | 2 | 5.8 (chi RealIP vs custom TRUSTED_PROXIES), 6.2 (strings.Clone in 8/9 adapters) |
| DIVERGED (gap) | 2 | 10.3s (toNullInt32 maps 0→NULL), 13.1 (Docker Compose superuser) |
| PARTIALLY IMPLEMENTED | 2 | 8.8 (query string rejection), 9.1 (23505→409 coverage) |
| UNIMPLEMENTED (expected) | 3 | 5.2 (bulk import Phase 2), 9.5 (Slack), 5.17 (child sort) |
| SUPERSEDED | 1 | 5.12 (semver — not implemented yet) |
| DUPLICATE (merged) | 2 | 6.3→1.8, 12.1→2.12 |

**Audit artifacts:** `dev/pitfall-meta-reviews/2026-03-18-audit-*.md` (6 domain audits), `dev/pitfall-meta-reviews/2026-03-18-harvest-*.md` (3 harvest reports), `dev/pitfall-meta-reviews/2026-03-18-xref-testing-pitfalls.md` (cross-reference analysis).
