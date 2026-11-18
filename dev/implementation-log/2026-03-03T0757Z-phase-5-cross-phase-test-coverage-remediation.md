# Phase 5 — Cross-Phase Test Coverage Remediation

> **Date:** 2026-03-03
> **Commits:** `b636323`..`a473b05` on `dev`

## What was built

Systematic test coverage review across all phases (1-5), driven by per-phase coverage gap reports. 92 new test functions and 21 subtests added across 23 test files (2,669 insertions).

| Phase | Tests Added | Areas Covered |
|---|---|---|
| Phase 5 | ~30 | Identity linking security, SSO input validation, tier gating (enterprise unlimited), audit log input validation, retention unlimited-skip, OIDC login edge cases |
| Phase 4 | ~69 | RLS isolation for `ai_*` and `saved_search` tables (12 gaps), RBAC for saved search access control, handler error paths, DSL executor cursor tampering and limit clamping, FTS + `escapeLike`, Gemini security config white-box tests, `validateConfig` + `IsDevelopment` + `LogValue` masking |
| Phase 2 | ~210 | DSL compiler/evaluator, alert event/rule API handlers, watchlist API, RBAC middleware, CSRF middleware, auth handlers, rate limiting, store-layer RLS for all org-scoped tables |
| Phase 1 | ~60 | Pure function unit tests for all 5 feed adapter parsers, merge pipeline helpers, FTS document builder, advisory lock, worker pool; Fetch-level integration tests for all adapters |
| Cross-phase | — | Code review findings: rate limiter burst cap, SSO domain validation (RFC 1035), client_secret audit redaction, OIDC provider cache eviction, tier limit constants extracted |

## Bugs found during coverage review

| Bug | Commit | Severity | Description |
|---|---|---|---|
| Sanitizer regex bypass | `cf3e20b` | Security | `![alt](url)` markdown images passed through the LLM sanitizer. Also added stripping of Unicode format characters (bidi overrides, zero-width spaces, BOM) |
| SearchCVEs FTS JOIN broken | `05b3a4c` | Correctness | `SearchCVEs` used `FROM "cves c"` alias but `cveColumns` references unaliased `"cves.col"`. When FTS JOIN was present, Postgres rejected the query. Never integration-tested, shipped silently |
| Test flakiness | `3749f1b` | Test quality | Quota and rate limiter tests had timing-sensitive assertions; fixed with tolerance adjustments |

## Quality checks

- **golangci-lint:** 0 issues
- Coverage review reports: `dev/test-coverage-reports/2026-03-03-phase{1,2,3a,3b,4,5}-*-review.md` (10 reports)
