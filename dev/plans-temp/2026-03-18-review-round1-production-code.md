# Review Round 1: Production Code Correctness

**Reviewer:** Claude Opus 4.6 (1M context)
**Date:** 2026-03-18
**Scope:** All production code changes from `ea8e123..HEAD`, excluding test files, docs, markdown, and frontend.
**Base plan:** `dev/plans/2026-03-18-health-review-remediation-plan.md`

---

## Critical Issues (must fix)

### CRIT-1: Circuit breaker never trips -- failures are not reported to gobreaker

**File:** `internal/ingest/handler.go:104`
**Severity:** Critical (feature is non-functional)

The circuit breaker is checked at the top of the ingest handler, but the actual feed fetch is never wrapped in `cb.Execute()`. The current code:

```go
cb := getBreaker(p.FeedName)
if _, cbErr := cb.Execute(func() (struct{}, error) { return struct{}{}, nil }); cbErr != nil {
    if errors.Is(cbErr, gobreaker.ErrOpenState) || errors.Is(cbErr, gobreaker.ErrTooManyRequests) {
        slog.Warn("feed circuit breaker open, skipping", "feed", p.FeedName)
        return nil
    }
}
```

The function passed to `Execute()` always returns `nil` error (success). This means:
1. `ConsecutiveFailures` in the breaker will never increment
2. The breaker will never trip to `StateOpen`
3. The feature is entirely decorative -- it adds overhead but provides zero protection

The plan (Task E6, Step 3) explicitly specifies wrapping the actual fetch:
```go
_, err := breaker.Execute(func() (struct{}, error) {
    return struct{}{}, adapter.Fetch(ctx)
})
```

**Fix:** The entire ingest handler body (from `adapter.Fetch` through the pagination loop and merge) should either be wrapped inside `cb.Execute()`, or at minimum the breaker should be explicitly told about success/failure after the ingest completes. The simplest correct approach: after the ingest loop, call `cb.Execute()` with the final error result, or restructure so the fetch is inside the Execute callback.

Since the ingest handler has a complex pagination loop, the cleanest fix is probably to record success/failure after the loop:
```go
// After the fetch/merge loop, at the point where fetchErr is resolved:
if fetchErr != nil {
    cb.Execute(func() (struct{}, error) { return struct{}{}, fetchErr })
} else {
    cb.Execute(func() (struct{}, error) { return struct{}{}, nil })
}
```

However, this is architecturally awkward since `Execute` also acts as a gate. A better approach may be to restructure the handler so the entire body (minus the initial breaker check) runs inside `Execute`. Discuss with Sam which approach fits best.

---

### CRIT-2: maxBodyTransport leaks TCP connections via io.NopCloser

**File:** `internal/feed/client.go:29`
**Severity:** Critical (resource leak in production)

```go
resp.Body = io.NopCloser(io.LimitReader(resp.Body, t.maxBytes))
```

`io.NopCloser` wraps the reader with a `Close()` that does nothing. The original `resp.Body` (which owns the underlying TCP connection) is never closed. When callers do `defer resp.Body.Close()`, they close the NopCloser (no-op), and the underlying connection leaks.

Every feed adapter in the codebase calls `defer resp.Body.Close()` (GHSA, NVD, KEV, EPSS, MSRC, Red Hat, generic). With the NopCloser transport, none of these actually release the connection.

The plan itself (Task E5, Step 1) identified this exact problem:
> "But this loses the original closer. Better: `limitedReadCloser{ Reader: io.LimitReader(resp.Body, t.maxSize), Closer: resp.Body }`"

**Fix:** Replace `io.NopCloser` with a struct that preserves the original closer:

```go
type limitedReadCloser struct {
    io.Reader
    io.Closer
}

func (t *maxBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    resp, err := t.inner.RoundTrip(req)
    if err != nil {
        return nil, err
    }
    resp.Body = limitedReadCloser{
        Reader: io.LimitReader(resp.Body, t.maxBytes),
        Closer: resp.Body,
    }
    return resp, nil
}
```

---

## Major Issues (should fix)

### MAJ-1: Batch evaluator writes cursor even when zero candidates exist

**File:** `internal/alert/evaluator.go:157-216`
**Severity:** Major (behavior change from original code)

The original `EvaluateBatch` had an early return that wrote the cursor when zero candidates existed:
```go
if len(candidateIDs) == 0 {
    return e.writeCursor(ctx, batchFeedName, batchTime)
}
```

The refactored `evaluateBatchPath` no longer has this early return. Instead, when the first page returns zero candidates, the loop breaks and execution falls through to `writeCursor` at line 216. This is functionally equivalent -- the cursor still gets written. However, it also lists rules unnecessarily (line 165) when there are no candidates. This is a minor inefficiency: if there are 0 candidates, fetching the rule list is wasted work.

The original code fetched candidates first, then rules only if candidates > 0. The new code fetches rules first, then candidates. This reversed order means rules are always fetched even when there's nothing to evaluate.

**Fix:** Move the `rules, err := cfg.listRules(ctx)` call inside the pagination loop, after confirming the first page has candidates. Or add an early return before the rules fetch if the first page is empty. This is a performance concern, not correctness, but on systems with many rules it's measurable.

### MAJ-2: Batch evaluator inserts duplicate rule runs per page

**File:** `internal/alert/evaluator.go:197-199`
**Severity:** Major (data integrity)

The paginated loop runs all rules against each page of candidates. For each rule on each page, it calls `InsertAlertRuleRun` + `UpdateAlertRuleRun`. This means a batch with 3 pages and 10 rules creates 30 rule run records instead of 10.

The original code created one rule run per rule per batch. The paginated version creates one rule run per rule per *page*. This inflates the `alert_rule_runs` table and makes monitoring metrics misleading: `AlertRulesEvaluatedTotal` will report `rules * pages` instead of the actual number of distinct rules evaluated.

The `totalRuleRuns` counter (line 195) similarly counts rule*page combinations, not unique rules.

**Fix:** Move rule run recording outside the pagination loop. Accumulate per-rule results across pages, then insert a single rule run per rule after all pages are processed. This requires tracking `matchCount`, `partial`, `candidatesEval`, and `evalErr` per rule across pages.

### MAJ-3: BuildFeedClient returns error but can never fail

**File:** `internal/feed/client.go:36`, `cmd/cvert-ops/main.go:178-181`
**Severity:** Major (misleading API)

`BuildFeedClient` has signature `func BuildFeedClient(timeout time.Duration, maxBodyBytes int64) (*http.Client, error)` but can never return a non-nil error. `safeurl.Client()` returns `*WrappedClient` (not an error). The function always returns `(inner, nil)`.

In `main.go`, this causes an unnecessary `os.Exit(1)` error path that can never execute:
```go
feedClient, err := feed.BuildFeedClient(5*time.Minute, 0)
if err != nil {
    slog.Error("build feed client", "error", err)
    os.Exit(1)
}
```

This appears twice (both `runServe` and `runWorker`). It's dead code that creates a false sense that initialization can fail.

**Fix:** Either remove the error return from `BuildFeedClient` (since it cannot fail), or add actual validation that could produce an error (e.g., validate timeout > 0, maxBodyBytes > 0). The simpler fix is to remove the error return.

### MAJ-4: noCacheMiddleware not applied to CVE endpoints or admin routes

**File:** `internal/api/server.go:291`
**Severity:** Major (security gap)

`noCacheMiddleware` is only applied to the `/orgs` route group. The CVE endpoints (registered via huma at line 233-235) and admin routes (lines 252-286) are authenticated but do not set `Cache-Control: no-store`. This means:
- CVE search results (which may reveal what a user is researching) can be cached by browsers/proxies
- Admin endpoints (user lists, security events, audit logs, config) can be cached

The plan (Task G4) specifies "Add Cache-Control: no-store to all authenticated responses" but the implementation only covers org-scoped routes.

**Fix:** Either apply `noCacheMiddleware` globally on `apiRouter` (after CSRF, before huma registration), or add it to both the admin route group and as a huma middleware on CVE operations. The global approach is simpler and more correct.

---

## Minor Issues (nice to fix)

### MIN-1: Healthcheck binary uses LISTEN_ADDR env var inconsistently

**File:** `cmd/healthcheck/main.go:13-16`
**Severity:** Minor

The healthcheck reads `LISTEN_ADDR` and prepends `http://localhost`. If `LISTEN_ADDR` is set to `0.0.0.0:8080` (a common pattern), the URL becomes `http://localhost0.0.0.0:8080/healthz` which is invalid. The env var is expected to be in `:port` format (e.g., `:8080`), but there's no validation or documentation of this expectation.

**Fix:** Either parse the port from `LISTEN_ADDR` or document that it must be in `:port` format. Or use a separate `HEALTH_PORT` env var for clarity.

### MIN-2: Evaluator bypassTx has redundant double-rollback on panic

**File:** `internal/alert/evaluator.go:548-554`
**Severity:** Minor (no bug, just style)

The panic recovery defer calls `tx.Rollback()` explicitly, then `panic(p)` re-panics which triggers the `defer tx.Rollback()` at line 548. The second rollback is a no-op (tx is already rolled back), but the intent is unclear. This matches the pattern specified in the plan (Task B1), so it's not a deviation.

No action needed -- this is working as intended per the plan's explicit guidance about LIFO defer ordering.

### MIN-3: Whitespace-only formatting changes across multiple files

**Files:** `internal/api/cves.go`, `internal/api/ingest.go`, `internal/api/channels.go`, `internal/api/reports.go`, `internal/notify/webhook.go`, `internal/feed/generic/config.go`
**Severity:** Minor

Multiple files have whitespace alignment changes (e.g., struct field alignment in `CVEItem`, `createReportBody`, `deniedHeaders`, etc.). These are cosmetic and don't affect behavior, but CLAUDE.md says "YOU MUST NOT manually change whitespace that does not affect execution or output. Otherwise, use a formatting tool."

These appear to be manual alignment changes rather than gofmt output. If they came from a formatter, fine. If manual, they violate the whitespace rule.

### MIN-4: logLevel is a package-level var in main.go

**File:** `cmd/cvert-ops/main.go:832`
**Severity:** Minor (testability)

`var logLevel slog.LevelVar` is a package-level global. This makes it harder to test log level reload in isolation. However, for a CLI entry point this is acceptable -- the slog library is designed around global state. No action needed unless testing becomes difficult.

### MIN-5: Pagination config validation could reject valid configs

**File:** `internal/feed/generic/config.go:128-139`
**Severity:** Minor

The new pagination validation for `cursor` type requires both `cursor_param` and `cursor_path`. For some APIs, the cursor might be in a header or the URL path itself rather than a query param. However, based on the current generic adapter implementation, both fields are likely needed. This is a reasonable defensive check.

No action needed unless users report false validation failures.

---

## Observations (no action needed)

### OBS-1: JWT generic helper is well-implemented

**File:** `internal/auth/jwt.go:11-37`

The `parseTokenWithRotation[T jwt.Claims]` generic helper correctly:
- Uses a `newClaims func() T` factory to get fresh claims for each parse attempt (avoiding the in-place mutation pitfall)
- Preserves `WithValidMethods` and `WithExpirationRequired` on both attempts
- Only retries on `ErrTokenSignatureInvalid` (not expiry or other validation errors)
- Returns zero value on error paths

This matches the plan specification exactly and eliminates ~100 lines of duplicated code.

### OBS-2: Delivery worker shutdown coordination is correct

**File:** `cmd/cvert-ops/main.go:263-265, 359-365`

The `deliveryDone` channel pattern correctly ensures the delivery worker drains before the function returns (and thus before `defer db.Close()` executes). The pattern is applied identically in both `runServe` and `runWorker`. The shutdown timeout reuse is correct.

### OBS-3: Security event writer bounded concurrency is well-designed

**File:** `internal/secure/writer.go`

The semaphore pattern with non-blocking `select` for slot acquisition, `context.WithTimeout` for write deadline, and bounded `Stop()` timeout are all well-implemented. The defer ordering (wg.Done, sem release, cancel, panic recovery) is correct for LIFO execution.

### OBS-4: Audit logging additions follow established patterns

**Files:** `internal/api/apikeys.go`, `internal/api/groups.go`, `internal/api/ingest.go`, `internal/api/reports.go`

All new `srv.auditLog()` calls follow the existing pattern from `admin_mfa.go` and `alert_rules.go`. They correctly:
- Log after successful operations (not before)
- Include `OldState`/`NewState` where applicable
- Use the request context for actor ID extraction
- Are fire-and-forget (the `auditLog` method handles nil writer gracefully)

### OBS-5: Circuit breaker construction is correct

**File:** `internal/feed/breaker.go`

The `NewBreaker` function correctly:
- Uses `ConsecutiveFailures` (not total failures) for tripping
- Logs state changes at WARN level
- Updates a Prometheus gauge in `OnStateChange`
- Does not make network calls in the constructor (per plan pitfall warning)

The breaker *definition* is correct. The *integration* with the ingest handler (CRIT-1) is the problem.

### OBS-6: Webhook HMAC skip for empty secrets is correct

**File:** `internal/notify/webhook.go:57-70`

The conditional HMAC block (`if cfg.SigningSecret != ""`) correctly omits all three signature headers when no secret is configured. This prevents sending an HMAC computed with an empty key, which would be cryptographically meaningless. The test channel use case (which has no signing secret) will work correctly.

### OBS-7: Stale threshold alignment is correct

**File:** `internal/worker/pool.go:36`

Changing `staleThreshold` from 5 to 10 minutes aligns it with `maxJobDuration` (10 minutes), preventing premature job reclamation. The comment explains the invariant clearly.

---

## Summary

| Severity | Count | Key Items |
|----------|-------|-----------|
| Critical | 2 | Circuit breaker non-functional (CRIT-1), TCP connection leak (CRIT-2) |
| Major | 4 | Duplicate rule runs (MAJ-2), dead error path (MAJ-3), Cache-Control gap (MAJ-4), wasted rule fetch (MAJ-1) |
| Minor | 5 | Healthcheck addr parsing, redundant rollback, whitespace, global var, pagination validation |
| Observation | 7 | JWT helper, shutdown, writer, audit, breaker definition, HMAC skip, stale threshold |

**Priority recommendation:** Fix CRIT-1 and CRIT-2 immediately. MAJ-2 and MAJ-4 should be addressed before the next release. MAJ-1 and MAJ-3 are lower priority but should be cleaned up.
