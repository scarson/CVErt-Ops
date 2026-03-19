# Audit Missing Tests — 2026-03-18

Four tests identified by the plan-vs-implementation audit, now implemented and passing.

## Test 1: A7 Enforcement — Middleware Wiring Verification

**File:** `internal/api/middleware_apikey_query_test.go`
**Test:** `TestRejectAPIKeyQueryParams_IntegrationWired`

Proves the `rejectAPIKeyQueryParams` middleware is actually wired into the HTTP
server's middleware chain by going through the full HTTP stack (testutil.NewTestDB,
newRegisterServer, register, login, authenticated request). Sends a request with
`?api_key=test` and asserts 400, then sends one without and asserts 200.

## Test 2: B3 Multi-page Batch Pagination

**File:** `internal/alert/evaluator_test.go`
**Test:** `TestEvaluateBatch_PaginatesMultiplePages`

Seeds 1050 CVEs (exceeding the `candidatePageSize = 1000` threshold), creates an
active rule matching all CVEs, runs `EvaluateBatch`, and verifies:
- `candidates_evaluated` in the rule run record equals the total CVE count
- All CVEs generated alert events

This confirms the pagination loop in `evaluateBatchPath` collects candidates
across multiple pages before evaluating rules.

## Test 3: C2 Bounded Goroutine Pool

**File:** `internal/secure/writer_test.go`
**Test:** `TestEventWriter_BoundedConcurrency`

Uses a PostgreSQL `LOCK TABLE ... IN EXCLUSIVE MODE` to block all INSERT calls,
then fires 100 concurrent Write calls (each with a unique IP to bypass the rate
limiter). With the table locked, the first 50 goroutines fill the semaphore; the
remaining writes are dropped by the `select default` path. Verifies:
- At most 50 events written (semaphore bound enforced)
- No goroutine leak after `Stop()` completes

## Test 4: G3 Typed SendError Detection

**File:** `internal/notify/permanent_error_test.go`
**Tests:** `TestIsPermanentDeliveryError_*` (8 subtests)

Exercises all three branches of `isPermanentDeliveryError`:
1. `permanentDeliveryError` wrapper (direct and `fmt.Errorf`-wrapped)
2. String fallback for SMTP 5xx codes (550-555)
3. Negative cases: nil, generic errors, 4xx codes

**Limitation documented:** `mail.SendError` has unexported fields (`isTemp`,
`errcode`), so the `*mail.SendError` type assertion path cannot be fully exercised
from outside the `go-mail` package. A zero-value `SendError` has `ErrorCode() = 0`
which fails the `>= 500` check. The string-based fallback covers the same SMTP 5xx
detection logic in practice.
