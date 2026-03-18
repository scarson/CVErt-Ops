# Remediation Execution Sequencing Guide

**Date:** 2026-03-18
**Scope:** Coordinates execution of three remediation plans to avoid conflicts and respect dependencies.

**Plans:**
1. `dev/plans/2026-03-18-health-review-remediation.md` — **HR** (30 issues + 5 design decisions)
2. `dev/plans/2026-03-18-phase8-coverage-remediation-plan.md` — **P8** (1 bug, 2 code gaps, 3 design decisions, 63 coverage gaps)
3. `dev/plans/2026-03-18-phase11-mfa-coverage-remediation-plan.md` — **P11** (36 MFA coverage gaps)

---

## Execution Stages

### Stage 1: Health Review Code Fixes

**Plan:** HR Groups A, B, C, D, E, G (code fixes only), H
**Nature:** Production code changes — the highest-priority items including the critical evaluator OOM fix, shutdown safety, auth corrections, and ops readiness.

Execute these HR tasks in this order:

| Order | HR Task | Summary |
|-------|---------|---------|
| 1 | A1 | Stale job threshold alignment |
| 2 | A2 | Retry-After header on org rate limiter |
| 3 | A3 | UpsertDelivery use withBypassRawTx |
| 4 | A4 | TestOrgTx_CommitsOnSuccess fix |
| 5 | A5 | password_change_required + stale comment |
| 6 | A6 | Docker metrics port |
| 7 | A7 | API key query string rejection middleware |
| 8 | B1 | Evaluator bypassTx panic recovery |
| 9 | B2 | Extract evaluateBatchPath helper |
| 10 | B3 | **CRITICAL** — Paginate batch/EPSS candidate loading |
| 11 | C1 | Delivery worker shutdown coordination |
| 12 | C2 | Security event writer bounded goroutines + timeout |
| 13 | D1 | CVE endpoints require authentication |
| 14 | D2 | JWT parse generic helper (4x dedup) |
| 15 | E2 | Container healthcheck binary |
| 16 | E3 | Job queue depth metric |
| 17 | E4 | Log level reload |
| 18 | E6 | Circuit breaker for feed adapters (gobreaker) |
| 19 | G2 | NullString audit |
| 20 | G3 | isPermanentDeliveryError type assertion |
| 21 | G4 | Cache-Control headers |
| 22 | G5 | testChannelHandler 502 on failure |
| 23 | H1 | PLAN.md import-bulk description update |

**Skip in this stage (moved to later stages):**
- HR D3 → Stage 4 (combine with P8 Task 17)
- HR E5 → Stage 2 (merge with P8 Task 6)
- HR F1–F5 → Stage 4 (test-only tasks)
- HR G6 → Stage 4 (frontend changes)

**Critical dependency created:** HR C2 changes the security event writer. HR D2 refactors JWT parsing. Both must complete before Stage 3.

---

### Stage 2: Phase 8 Code Fixes

**Plan:** P8 Batch 1 (Tasks 1–8)
**Nature:** Production bug fix, audit logging gaps, webhook HMAC fix, safeurl wrapping.

| Order | P8 Task | Summary | Notes |
|-------|---------|---------|-------|
| 1 | Task 1 | Generic feed cursor pagination infinite fetch | Bug fix |
| 2 | Task 2 | Audit logging: groups handler | Code gap |
| 3 | Task 3 | Audit logging: ingest handler | Code gap |
| 4 | Task 4 | Skip webhook HMAC when secret empty | Code fix — **combine with HR F3** (both modify webhook_test.go) |
| 5 | Task 5 | Lockout fail-open regression test | Test |
| 6 | Task 6 | Wrap feed client in SafeURL | Code fix — **merge HR E5 here** (compose safeurl + body size limit on feed client) |
| 7 | Task 7 | Audit logging: reports handler | Code gap |
| 8 | Task 8 | Audit logging: API keys handler | Code gap |

**Merged tasks:**
- **P8 Task 4 + HR F3:** Both modify `webhook_test.go`. Execute together: add empty-secret HMAC test AND improve BuildSafeClient assertions in one pass.
- **P8 Task 6 + HR E5:** Both modify the feed client in `main.go`. Apply safeurl wrap AND body size limit transport together. The transport composition should be: `safeurl.Transport` (inner) → `maxBodyTransport` (outer).

---

### Stage 3: Phase 11 MFA Test Coverage

**Plan:** P11 Tasks 1–7 (full plan)
**Nature:** Almost entirely test additions. One possible interface extraction.

| Order | P11 Task | Summary | Notes |
|-------|----------|---------|-------|
| 1 | Task 1 | Event writer test infrastructure | **Must account for HR C2's semaphore/drop behavior** |
| 2 | Task 2 | JWT enrollment token security tests | Validates HR D2's refactored code |
| 3 | Task 3 | Store direct MFA tests | Independent |
| 4 | Task 4 | Admin MFA test gaps | Depends on Task 1 |
| 5 | Task 5 | MFA verify/challenge tests | Depends on Task 1 |
| 6 | Task 6 | Auth handler MFA paths | Independent |
| 7 | Task 7 | Additional MFA API tests | Independent |

**Dependency on Stage 1:**
- P11 Task 1 builds on the event writer that HR C2 modified. The `Stop()` behavior and the semaphore must be understood. If the bounded writer drops events when at capacity, the P11 test infrastructure must either (a) set a high-enough semaphore bound that tests never hit it, or (b) account for potential drops.
- P11 Task 2 tests `ParseEnrollmentToken` which HR D2 refactored into a generic helper. These tests validate the refactored code.

---

### Stage 4: Phase 8 Coverage Tests + Remaining HR Tasks

**Plan:** P8 Batches 2–5 (Tasks 9–23+) interleaved with HR test tasks
**Nature:** Test additions across many packages.

Execute in this order for minimal file conflicts:

| Order | Source | Task(s) | Notes |
|-------|--------|---------|-------|
| 1 | HR | F1 | Fix discarded test errors — establishes pattern before more tests are written |
| 2 | P8 | Task 9 | Admin config secret redaction test |
| 3 | P8 | Task 10 | Admin user management tests |
| 4 | P8 | Task 11 | Admin audit log + deliveries tests |
| 5 | P8+HR | Task 12 + Task 17 + HR D3 | **Combined:** All modify `middleware_auth_test.go` — see unified description below |
| 6 | P8 | Task 13 | Login handler critical paths |
| 7 | P8 | Task 14 | Refresh handler theft detection |
| 8 | P8 | Task 15 | MFA handler coverage |
| 9 | P8 | Task 16 | Cross-org isolation tests (depends on HR G5 — testChannel 502 already done in Stage 1) |
| 10 | P8 | Task 18 | SSO handler encryption tests |
| 11 | P8 | Task 19 | Doctor security checks |
| 12 | P8 | Task 20 | Store security method tests |
| 13 | P8 | Task 21 | Worker periodic job tests |
| 14 | P8 | Task 22 | Generic feed error paths |
| 15 | P8 | Task 23 | Notify package error paths |
| 16 | HR | F2 | EPSS two-statement pattern test |
| 17 | HR | F4 | Feed adapter integration test (ONE adapter) |
| 18 | HR | D3 | (if not already combined in step 5 above) |
| 19 | HR | G6 | Frontend raw fetch migration |

**Removed tasks:**
- **HR F5** (webhook safeurl integration test) — subsumed by P8 Task 6 in Stage 2

#### Stage 4, Step 5 — Unified Task Description (P8 Task 12 + P8 Task 17 + HR D3)

All three tasks modify `middleware_auth_test.go`. Execute as a single unit in one pass:

1. **P8 Task 12 — Revoked API key returns 401:** Add a test that creates an API key, revokes it via the store, then sends a request with the revoked key and asserts 401. See P8 plan Task 12 for full details.
2. **P8 Task 17 — Disabled user + checkAdminMFAPermission:** Add tests for (a) a request from a disabled user (`disabled_at IS NOT NULL`) returns 403, (b) `checkAdminMFAPermission` returns 403 when caller lacks MFA admin role. See P8 plan Task 17 for full details.
3. **HR D3 — Pending token rejection:** Add a test that presents a pending/restricted JWT token to a non-pending endpoint and asserts 401. The middleware must reject tokens with `typ: "pending"` on endpoints that require full access tokens. See HR plan Task D3 for full details.

**Scope boundary:** Do NOT refactor middleware code in this step — test-only changes to `middleware_auth_test.go`. If a test reveals a production bug, document it and raise it; do not fix it inline.

**File:** `internal/api/middleware_auth_test.go` (all additions in this single file)

#### Stage 4 — Cross-stage file dependency warnings

- **`admin_mfa_test.go`:** P11 Task 4 (Stage 3) adds tests to this file. P8 Task 16 (Stage 4, step 9) also adds tests. The Stage 4 subagent must read the file as-is (after Stage 3 merged) before adding tests — do NOT assume the file matches the `dev` branch state at the start of the overall remediation.
- **`auth_test.go`:** P11 Task 6 (Stage 3) adds tests to this file. P8 Tasks 13 and 14 (Stage 4, steps 6–7) also add tests. Same rule: read the file as-is after Stage 3, not from a stale checkout.

---

### Stage 5: Final Cleanup

1. Update `dev/implementation-log.md` with all stages
2. Verify no remaining lint issues: `golangci-lint run`
3. Run full test suite: `go test ./... -count=1`
4. Run frontend checks: `cd web && npm run test:unit && npm run type-check && npm run lint`

**If any test or lint check fails in steps 2–4:** Fix the issue before proceeding to the next step. Do NOT skip failures — they indicate a regression introduced during remediation.

---

## Conflict Resolution Reference

### Direct Code Conflicts

| Files | HR Task | P8/P11 Task | Resolution |
|-------|---------|-------------|------------|
| `main.go` feed client | E5 (body limit) | P8 Task 6 (safeurl) | Merged into Stage 2, P8 Task 6. Compose: safeurl inner, body limit outer. |
| `secure/writer.go` | C2 (bounded writer) | P11 Task 1 (test infra) | HR C2 in Stage 1. P11 Task 1 in Stage 3 must account for semaphore. |

### File-Level Conflicts (sequential execution required)

| File | Tasks (in execution order) |
|------|---------------------------|
| `middleware_auth_test.go` | P8 Task 12 → P8 Task 17 → HR D3 (combined in Stage 4, step 5) |
| `webhook_test.go` | P8 Task 4 + HR F3 (combined in Stage 2, step 4) |
| `admin_mfa_test.go` | P11 Task 4 (Stage 3) → P8 Task 16 (Stage 4) |
| `auth_test.go` | P11 Task 6 (Stage 3) → P8 Task 13 → P8 Task 14 (Stage 4) |
| `main.go` | HR C1 + E4 (Stage 1) → P8 Task 6 + HR E5 (Stage 2) |
| `jwt_test.go` | P11 Task 2 (Stage 3) |
| `pool_test.go` | HR A1 (Stage 1) → P8 Task 21 (Stage 4) |

### Removed / Subsumed Tasks

| Removed | Reason | Subsumed By |
|---------|--------|-------------|
| HR F5 (webhook safeurl test) | P8 Task 6 wraps feed client with safeurl + adds SSRF test | P8 Task 6 |

---

## Session Planning

Each stage can be its own worktree session:

| Session | Stage | Estimated Scope | Worktree Branch |
|---------|-------|-----------------|-----------------|
| 1 | Stage 1 | ~23 HR tasks (code fixes) | `fix/health-review-code` |
| 2 | Stage 2 | ~8 P8 tasks (code fixes) | `fix/phase8-code` |
| 3 | Stage 3 | 7 P11 tasks (MFA tests) | `test/phase11-mfa-coverage` |
| 4 | Stage 4 | ~19 tasks (mixed coverage) | `test/coverage-backfill` |
| 5 | Stage 5 | Cleanup | On `dev` directly |

Sessions 1 and 2 produce code changes that must merge to `dev` before sessions 3 and 4 start.
Sessions 3 and 4 share `admin_mfa_test.go` and `auth_test.go` — they MUST run sequentially (Stage 3 first, then Stage 4). Do NOT attempt to parallelize them.

**Precedence rule:** When the task ordering in an individual plan (HR, P8, or P11) conflicts with the ordering in this sequencing document, this document takes precedence. Specifically: P8's internal batch ordering (Batches 2–5) is preserved within Stage 4 but is interleaved with HR tasks per the Stage 4 table above.
