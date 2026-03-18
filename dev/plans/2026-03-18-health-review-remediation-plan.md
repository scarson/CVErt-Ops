# Health Review Remediation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 30 confirmed issues from the 2026-03-18 health review (1 critical, 14 major, 15 minor) plus 5 design decisions.

**Architecture:** Eight groups ordered by dependency: (A) quick wins, (B) evaluator critical path, (C) shutdown safety, (D) auth + security, (E) ops readiness, (F) test quality, (G) minor code/API, (H) PLAN.md update. Each group is independently committable.

**Tech Stack:** Go 1.26, chi, huma, pgxpool, sony/gobreaker v2.4.0 (`github.com/sony/gobreaker/v2`), Prometheus client_golang

**Source:** `dev/health-reviews/2026-03-18T03-08-full-validated.md`

---

## Cross-Plan Sequencing

This plan is part of a coordinated three-plan remediation. See `dev/plans/2026-03-18-remediation-sequencing.md` for the master execution order.

**This plan executes in two stages:**
- **Stage 1:** Groups A, B, C, D (D1+D2), E (E2-E6), G (G2-G5), H — production code fixes
- **Stage 4:** Groups D3, F (F1-F4), G6 — test and frontend tasks (interleaved with P8 coverage)

**Tasks moved or merged with other plans:**
- **E5 (feed body size limit)** → merged into P8 Task 6 (Stage 2). Both modify the feed client in main.go. Apply safeurl + body limit together.
- **F3 (TestBuildSafeClient assertions)** → combined with P8 Task 4 (Stage 2). Both modify webhook_test.go.
- **F5 (webhook safeurl integration test)** → **REMOVED**, subsumed by P8 Task 6 which wraps the feed client with safeurl and adds an SSRF test.
- **D3 (pending token rejection test)** → combined with P8 Tasks 12+17 (Stage 4). All modify middleware_auth_test.go.

**Dependencies this plan creates for other plans:**
- HR C2 (security event writer changes) must complete before P11 Task 1 (event writer test infrastructure)
- HR D2 (JWT refactor) must complete before P11 Task 2 (enrollment token tests)
- HR G5 (testChannel 502) must complete before P8 Task 16 (cross-org channel tests)

---

## Standing Rules

BEFORE starting any task:
1. Read `dev/testing-pitfalls.md`
2. Read `dev/implementation-pitfalls.md`
3. Read the TDD skill at `.claude/skills/test-driven-development/` (or invoke `/test-driven-development`)
4. Follow TDD: write failing test → implement fix → verify green.

BEFORE marking any task complete:
1. Review your tests against `dev/testing-pitfalls.md`
2. Verify test coverage of the fix (are error paths tested? edge cases?)
3. Run `go test ./...` (or the relevant subset) and confirm green
4. Run `golangci-lint run` on changed packages and confirm clean

After every logical group of tasks:
You MUST carefully review the batch of work from multiple perspectives
and revise/refine as appropriate. Repeat this review loop (you must do
a minimum of three review rounds; if you still find substantive issues
in the third review, keep going with additional rounds until there are
no findings) until you're confident there aren't any more issues. Then
update your private journal and continue onto the next tasks.

---

## Group A: Quick Wins (Trivial Fixes)

These are independent, localized fixes. Commit after each logical sub-group.

### Task A1: Fix stale job threshold vs max job duration (I16)

**Files:**
- Modify: `internal/worker/pool.go:34-39`
- Test: `internal/worker/pool_test.go` (existing tests should still pass)

**Step 1: Fix the constant**

In `internal/worker/pool.go`, change `staleThreshold` from `5 * time.Minute` to `10 * time.Minute` so it equals `maxJobDuration`. A job cannot be considered stale before its maximum allowed runtime expires.

Do NOT change `maxJobDuration`. Do NOT change `staleCheckInterval`.

**Step 2: Run tests**

```bash
go test ./internal/worker/... -count=1 -v
```

**Step 3: Commit**

```bash
git add internal/worker/pool.go
git commit -m "fix(worker): align staleThreshold with maxJobDuration to prevent premature reclaim"
```

### Task A2: Add Retry-After header to per-org rate limiter (I8)

**Files:**
- Modify: `internal/api/middleware_tier.go:70`
- Modify: `internal/api/middleware_tier_test.go` (add assertion)

**Step 1: Write failing test**

Add a test (or modify an existing org rate limit test) that asserts the 429 response includes a `Retry-After` header. The test should fail because the header is currently absent.

**Step 2: Fix the middleware**

In `middleware_tier.go`, before the `writeProblem` call at line 70, add:
```go
w.Header().Set("Retry-After", "60")
```

Match the same pattern used by `authRateLimit()` in `ratelimit.go:89`.

**Step 3: Run tests and commit**

```bash
go test ./internal/api/... -run TestOrgRateLimit -count=1 -v
git add internal/api/middleware_tier.go internal/api/middleware_tier_test.go
git commit -m "fix(api): add Retry-After header to per-org rate limiter 429 response"
```

### Task A3: Convert UpsertDelivery to use withBypassRawTx (I13)

**Files:**
- Modify: `internal/store/notification_delivery.go:39-52`

**Step 1: Understand current code**

Read `internal/store/notification_delivery.go:39-52`. It hand-rolls a bypass transaction. Read `internal/store/store.go:70-93` for the `withBypassRawTx` helper which does the same thing but includes panic recovery.

**Step 2: Replace the hand-rolled transaction**

Replace the body of `UpsertDelivery` with:
```go
func (s *Store) UpsertDelivery(ctx context.Context, orgID, ruleID, channelID uuid.UUID, payload []byte, debounceSeconds int) error {
	return s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, upsertDeliverySQL, orgID, ruleID, channelID, payload, debounceSeconds)
		if err != nil {
			return fmt.Errorf("upsert delivery: %w", err)
		}
		return nil
	})
}
```

Remove the now-unnecessary `database/sql` import if it becomes unused (it won't — `sql.Tx` is used by `withBypassRawTx`'s callback signature). Keep the `upsertDeliverySQL` constant unchanged.

**Step 3: Run tests and commit**

```bash
go test ./internal/store/... -count=1 -v
go test ./internal/notify/... -count=1 -v
git add internal/store/notification_delivery.go
git commit -m "fix(store): use withBypassRawTx in UpsertDelivery for panic recovery"
```

### Task A4: Fix TestOrgTx_CommitsOnSuccess to verify commit persistence (I14)

**Files:**
- Modify: `internal/store/store_test.go:80-98`

**Step 1: Rewrite the test**

Replace the test body so it:
1. Creates an org (existing setup)
2. Inside `OrgTx`, inserts a watchlist via raw SQL: `tx.Exec(ctx, "INSERT INTO watchlists (id, org_id, name, created_at, updated_at) VALUES (gen_random_uuid(), $1, 'commit-test', now(), now())", org.ID)`
3. After `OrgTx` returns (no error), query watchlists for that org and assert the 'commit-test' watchlist exists

Use the store's existing `ListWatchlists` method (or a raw query) to verify persistence. The key assertion: the row inserted inside OrgTx MUST be visible after the function returns, proving the transaction committed.

Do NOT delete the `TestOrgTx_RollsBackOnError` test — it's fine.

**Step 2: Run tests and commit**

```bash
go test ./internal/store/... -run TestOrgTx -count=1 -v
git add internal/store/store_test.go
git commit -m "fix(store): TestOrgTx_CommitsOnSuccess now verifies write persists after commit"
```

### Task A5: Fix stale comment and password_change_required response (I20, I24)

**Files:**
- Modify: `internal/api/middleware_auth.go:87-94` (I20 — use writeProblem)
- Modify: `internal/api/alert_events.go:34` (I24 — fix stale comment)
- Add test: verify password_change_required returns RFC 9457 format with `status` field

**Step 1: Write failing test for password_change_required response format**

Add a test that triggers the `password_change_required` response and asserts:
- `Content-Type: application/problem+json`
- Response body contains `"status": 403`
- Response body contains `"type": "password_change_required"`

This test should currently FAIL because the response uses inline JSON encoding without `status`.

**Step 2: Fix the middleware**

Replace the inline JSON block at `middleware_auth.go:87-94` with:
```go
writeProblemTyped(w, http.StatusForbidden, "password_change_required", "Your password must be changed before continuing")
```

If `writeProblemTyped` doesn't exist, use `writeProblem` and add the `type` field. Check `contract.go` for existing helpers. The key requirement: the response MUST include `"status": 403` and use `Content-Type: application/problem+json`.

**Step 3: Fix the stale comment**

In `alert_events.go:34`, change `?after=` to `?cursor=` in the function comment.

**Step 4: Run tests and commit**

```bash
go test ./internal/api/... -run TestPasswordChangeRequired -count=1 -v
git add internal/api/middleware_auth.go internal/api/alert_events.go internal/api/middleware_auth_test.go
git commit -m "fix(api): password_change_required uses writeProblem, fix stale ?after comment"
```

### Task A6: Expose metrics port in Docker (I4)

**Files:**
- Modify: `docker/Dockerfile:39` — add `EXPOSE 9090`
- Modify: `docker/compose.prod.yml` — add metrics port mapping on internal network

**Step 1: Add EXPOSE to Dockerfile**

After `EXPOSE 8080`, add `EXPOSE 9090`.

**Step 2: Add port mapping in compose.prod.yml**

In the `app` service section, add a `ports` entry mapping 9090 to 9090 on the internal network only. Check the base `compose.yml` for the network topology — metrics should be accessible on `cvert-data-net` (internal) but NOT on the public network.

If compose.prod.yml is an override, just add the port mapping. If `compose.yml` doesn't have an `app` service with `ports`, you may need to add it there.

**Step 3: Commit**

```bash
git add docker/Dockerfile docker/compose.prod.yml
git commit -m "fix(docker): expose metrics port 9090 in Dockerfile and production compose"
```

### Task A7: Add API key query string rejection middleware (D4)

**Files:**
- Create: middleware in `internal/api/` — either a new file `middleware_apikey_query.go` or add to an existing middleware file
- Test: new test file or add to existing middleware test

**Step 1: Write failing test**

Write a test that sends a request with `?api_key=something` or `?apikey=something` or `?token=something` in the query string, and asserts a 400 response with a problem detail message like "API keys must not be sent in query parameters".

Also test that a request WITHOUT these query parameters passes through normally.

Common parameter names to scan: `api_key`, `apikey`, `api-key`, `token`, `access_token`, `key`, `secret`, `bearer`.

**Step 2: Implement the middleware**

Create a middleware function `rejectAPIKeyQueryParams` that:
1. Checks `r.URL.Query()` for any of the known parameter names
2. If found, returns 400 with `writeProblem(w, http.StatusBadRequest, "API keys must not be sent in query parameters; use the Authorization header")`
3. If not found, calls `next.ServeHTTP(w, r)`

**Step 3: Wire the middleware**

In `server.go`, add the middleware early in the chain (before auth middleware) on the API router. It should apply to all `/api/v1/` routes.

**Step 4: Run tests and commit**

```bash
go test ./internal/api/... -run TestRejectAPIKeyQuery -count=1 -v
git add internal/api/middleware_apikey_query.go internal/api/middleware_apikey_query_test.go internal/api/server.go
git commit -m "feat(api): reject requests with API keys in query parameters"
```

**Review Group A** — run `go test ./... -count=1` and `golangci-lint run`. Review all changes.

---

## Group B: Evaluator Critical Path (I1, I6, I12)

**STRICT ORDERING — do not parallelize or reorder:**
1. B1 (panic recovery) — standalone safety fix
2. B2 (extract helper) — refactors the code that B3 will modify
3. B3 (pagination) — CRITICAL fix, builds on B2's refactored structure

### Task B1: Add panic recovery to evaluator.bypassTx (I6)

**Files:**
- Modify: `internal/alert/evaluator.go:544-562`

**Step 1: Add the defer recovery**

Add a panic-recovery defer to `bypassTx`, matching the pattern in `store.withBypassRawTx` at `store.go:78-83`:

```go
func (e *Evaluator) bypassTx(ctx context.Context, statementTimeoutMS int, fn func(*sql.Tx) error) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bypass tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	// ... rest unchanged
```

Remove the existing `defer tx.Rollback() //nolint:errcheck` — the explicit rollback on error paths and the panic-recovery defer together replace it. Actually, keep `defer tx.Rollback()` as a safety net — it's no-op after Commit succeeds and protects against early-return paths. But the panic recovery MUST come BEFORE the rollback defer (defers execute LIFO, so the panic recovery must be added AFTER the rollback defer so it executes FIRST).

Wait — that means: `defer tx.Rollback()` first (executes second), then `defer func() { recover }()` second (executes first). This is correct: panic recovery fires, does explicit rollback, re-panics; the deferred Rollback is then a no-op.

**Step 2: Run tests and commit**

```bash
go test ./internal/alert/... -count=1 -v
git add internal/alert/evaluator.go
git commit -m "fix(alert): add panic recovery to evaluator.bypassTx matching store pattern"
```

### Task B2: Extract evaluateBatchPath helper to reduce duplication (I12)

**Files:**
- Modify: `internal/alert/evaluator.go`
- Test: existing tests must still pass

**Step 1: Identify the common pattern**

`EvaluateBatch` (lines 124-169) and `EvaluateEPSS` (lines 173-218) share this structure:
1. Read cursor
2. Fetch candidate CVE IDs
3. Short-circuit if no candidates, writing cursor
4. List rules
5. Iterate rules: loadAndCompileRule → evaluateRule → record run
6. Record metrics
7. Write cursor

The differences are:
- Cursor feed name (`"alert_batch"` vs `"alert_epss"`)
- Candidate fetch function (`getCVEsModifiedSince` vs `getCVEsEPSSUpdatedSince`)
- Rule list function (`ListActiveRulesForEvaluation` vs `ListActiveRulesForEPSS`)
- Metrics label (`"batch"` vs `"epss"`)

**Step 2: Create the helper**

```go
type batchConfig struct {
	feedName      string
	metricsLabel  string
	getCandidates func(ctx context.Context, since time.Time) ([]string, error)
	listRules     func(ctx context.Context) ([]store.AlertRuleForEval, error)
}

func (e *Evaluator) evaluateBatchPath(ctx context.Context, cfg batchConfig) error {
	start := time.Now()
	cursor, err := e.readCursor(ctx, cfg.feedName)
	if err != nil {
		return fmt.Errorf("read %s cursor: %w", cfg.feedName, err)
	}
	batchTime := time.Now().UTC()

	candidateIDs, err := cfg.getCandidates(ctx, cursor)
	if err != nil {
		return fmt.Errorf("get %s candidates: %w", cfg.feedName, err)
	}
	if len(candidateIDs) == 0 {
		return e.writeCursor(ctx, cfg.feedName, batchTime)
	}

	rules, err := cfg.listRules(ctx)
	if err != nil {
		return fmt.Errorf("list rules for %s: %w", cfg.feedName, err)
	}

	var totalMatches int
	for i := range rules {
		rule := &rules[i]
		compiled, compErr := e.loadAndCompileRule(rule)
		if compErr != nil {
			e.log.Error("compile rule for "+cfg.metricsLabel, "rule_id", rule.ID, "err", compErr)
			continue
		}
		matchCount, partial, candidatesEval, evalErr := e.evaluateRule(ctx, compiled, candidateIDs, rule.OrgID, false, false, 0)
		if evalErr != nil {
			e.log.Error("evaluate rule "+cfg.metricsLabel, "rule_id", rule.ID, "err", evalErr)
		}
		totalMatches += matchCount
		status, errMsg := runStatus(partial, evalErr)
		if run, runErr := e.rules.InsertAlertRuleRun(ctx, rule.ID, rule.OrgID, cfg.metricsLabel); runErr == nil {
			_ = e.rules.UpdateAlertRuleRun(ctx, run.ID, status, int32(candidatesEval), int32(matchCount), errMsg)
		}
	}

	metrics.AlertRulesEvaluatedTotal.WithLabelValues(cfg.metricsLabel).Add(float64(len(rules)))
	metrics.AlertMatchesTotal.WithLabelValues(cfg.metricsLabel).Add(float64(totalMatches))
	metrics.AlertEvaluationDuration.WithLabelValues(cfg.metricsLabel).Observe(time.Since(start).Seconds())

	return e.writeCursor(ctx, cfg.feedName, batchTime)
}
```

**Step 3: Refactor EvaluateBatch and EvaluateEPSS to use the helper**

```go
func (e *Evaluator) EvaluateBatch(ctx context.Context) error {
	return e.evaluateBatchPath(ctx, batchConfig{
		feedName:      batchFeedName,
		metricsLabel:  "batch",
		getCandidates: e.getCVEsModifiedSince,
		listRules:     e.rules.ListActiveRulesForEvaluation,
	})
}

func (e *Evaluator) EvaluateEPSS(ctx context.Context) error {
	return e.evaluateBatchPath(ctx, batchConfig{
		feedName:      epssFeedName,
		metricsLabel:  "epss",
		getCandidates: e.getCVEsEPSSUpdatedSince,
		listRules:     e.rules.ListActiveRulesForEPSS,
	})
}
```

Do NOT change `EvaluateRealtime` — it has a different structure (single CVE, conditional run writes).

**Scope boundary:** Do NOT refactor the evaluator's database access pattern (the `*sql.DB` and raw SQL) in this task. That is a separate concern (I6 already addressed panic recovery). Do NOT move evaluator queries to the store layer — that is future work. Only extract the helper and reduce duplication.

**Step 4: Run ALL evaluator tests to verify no behavior change**

```bash
go test ./internal/alert/... -count=1 -v
```

**Step 5: Commit**

```bash
git add internal/alert/evaluator.go
git commit -m "refactor(alert): extract evaluateBatchPath helper to deduplicate Batch/EPSS evaluation"
```

### Task B3: Paginate batch/EPSS candidate loading — CRITICAL (I1)

**Files:**
- Modify: `internal/alert/evaluator.go` — change `evaluateBatchPath` to paginate candidates
- Test: `internal/alert/evaluator_test.go` — add test for large candidate sets

**Step 1: Write a failing test**

Add a test that:
1. Seeds >1000 CVEs in the test database (use a loop of raw SQL inserts — this is the evaluator test pattern)
2. Sets the batch cursor to `time.Time{}` (zero — triggers "get all" path)
3. Calls `EvaluateBatch`
4. Asserts all CVEs were evaluated (check run rows or match counts)

This test should pass with the current code but will verify the pagination doesn't break anything.

Also add a test that specifically verifies the pagination: seed 2500 CVEs, evaluate, verify all were processed. With page size 1000, this exercises 3 pages.

**Step 2: Add pagination to candidate fetching**

Change `getCVEsModifiedSince` and `getCVEsEPSSUpdatedSince` to accept a LIMIT and an `afterID` parameter (keyset pagination by `cve_id`), matching the pattern already used by `getCVEsBatch`:

```go
func (e *Evaluator) getCVEsModifiedSincePage(ctx context.Context, since time.Time, afterID string, limit int) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if since.IsZero() {
		if afterID == "" {
			rows, err = e.db.QueryContext(ctx,
				`SELECT cve_id FROM cves
				 WHERE lower(status) NOT IN ('rejected', 'withdrawn')
				 ORDER BY cve_id ASC LIMIT $1`, limit)
		} else {
			rows, err = e.db.QueryContext(ctx,
				`SELECT cve_id FROM cves
				 WHERE cve_id > $1
				   AND lower(status) NOT IN ('rejected', 'withdrawn')
				 ORDER BY cve_id ASC LIMIT $2`, afterID, limit)
		}
	} else {
		if afterID == "" {
			rows, err = e.db.QueryContext(ctx,
				`SELECT cve_id FROM cves
				 WHERE date_modified_canonical > $1
				   AND lower(status) NOT IN ('rejected', 'withdrawn')
				 ORDER BY cve_id ASC LIMIT $2`, since, limit)
		} else {
			rows, err = e.db.QueryContext(ctx,
				`SELECT cve_id FROM cves
				 WHERE date_modified_canonical > $1
				   AND cve_id > $2
				   AND lower(status) NOT IN ('rejected', 'withdrawn')
				 ORDER BY cve_id ASC LIMIT $3`, since, afterID, limit)
		}
	}
	return scanCVEIDs(rows, err)
}
```

Do the same for `getCVEsEPSSUpdatedSincePage`.

**Step 3: Update evaluateBatchPath to paginate**

Change `evaluateBatchPath` to loop over pages of candidates instead of fetching all at once. The page size should be a constant (e.g., `const candidatePageSize = 1000`). For each page:
1. Fetch candidate IDs (up to `candidatePageSize`)
2. Run all rules against this page's candidates
3. If the page was full (`len(page) == candidatePageSize`), fetch next page using last ID as cursor
4. If the page was smaller, we're done

The `batchConfig.getCandidates` function signature changes to accept `(ctx, since, afterID, limit)` — update the type and both callers accordingly.

**CRITICAL:** The cursor must only be written AFTER all pages have been processed. If we write the cursor after page 1 and then crash on page 2, we skip page 2's CVEs permanently.

**Step 4: Remove old unbounded functions**

Delete `getCVEsModifiedSince` and `getCVEsEPSSUpdatedSince` (the original unbounded versions). Callers now use the paginated versions.

**Step 5: Run ALL evaluator tests**

```bash
go test ./internal/alert/... -count=1 -v
```

**Step 6: Commit**

```bash
git add internal/alert/evaluator.go internal/alert/evaluator_test.go
git commit -m "fix(alert): paginate batch/EPSS candidate loading to prevent OOM on catch-up"
```

**Review Group B** — run `go test ./internal/alert/... -count=1 -v` and `golangci-lint run ./internal/alert/...`. Review all changes against `dev/implementation-pitfalls.md`.

---

## Group C: Shutdown Safety (I2, I3)

### Task C1: Await delivery worker shutdown before DB close (I2)

**Files:**
- Modify: `cmd/cvert-ops/main.go` — both `runServe` (~line 261) and `runWorker` (~line 446)

**Step 1: Understand the current problem**

`go deliveryWorker.Start(ctx)` is fire-and-forget. `defer db.Close()` races in-flight deliveries. `Start` blocks until ctx is cancelled, then internally calls `wg.Wait()` for in-flight deliveries. The goroutine needs to be joined before `db.Close()`.

**Step 2: Add shutdown coordination**

Replace the fire-and-forget goroutine with a pattern that captures completion:

```go
deliveryDone := make(chan struct{})
go func() {
	deliveryWorker.Start(ctx) //nolint:contextcheck // ctx is the process-lifetime context
	close(deliveryDone)
}()
```

Then, in the shutdown sequence (after `ctx.Done()` fires and before returning), wait for the delivery worker with a timeout:

```go
// Wait for delivery worker to drain in-flight deliveries.
select {
case <-deliveryDone:
	slog.Info("delivery worker stopped")
case <-shutdownCtx.Done():
	slog.Warn("delivery worker did not stop within shutdown timeout")
}
```

This MUST happen BEFORE `db.Close()` (i.e., before the function returns, since `db.Close()` is deferred).

Apply to BOTH `runServe` and `runWorker`. In `runWorker`, the shutdown context is created at line 489 — reuse it.

**Step 3: Run the full test suite** (this is wiring code, not directly unit-testable)

```bash
go build ./cmd/cvert-ops
go test ./... -count=1
```

**Step 4: Commit**

```bash
git add cmd/cvert-ops/main.go
git commit -m "fix(cmd): await delivery worker shutdown before closing DB pool"
```

### Task C2: Bound security event writer goroutines and add timeout (I3)

**Files:**
- Modify: `internal/secure/writer.go`
- Test: `internal/secure/writer_test.go` — add test for concurrency bound

**Step 1: Write failing test**

Add a test that:
1. Creates an EventWriter with a mock store that blocks on insert (e.g., uses a channel to control when inserts complete)
2. Fires more Write calls than the concurrency limit
3. Asserts that extra calls don't spawn additional goroutines (they're dropped or queued)

**Step 2: Add semaphore and timeout to EventWriter**

Add a `sem chan struct{}` field to `EventWriter`, initialized in the constructor with a buffer size of 50 (or configurable).

In the `Write` method, change the goroutine spawn to:
```go
select {
case w.sem <- struct{}{}:
	// Got a slot
default:
	// All slots full — drop this event
	slog.Warn("security event writer at capacity, dropping event",
		"event_type", event.Type)
	metrics.SecurityEventsDropped.Inc()
	return
}

writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

w.wg.Add(1)
go func() {
	defer w.wg.Done()
	defer func() { <-w.sem }()
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("security event writer panic", "recover", r)
		}
	}()

	err := w.store.InsertSecurityEvent(writeCtx, store.InsertSecurityEventParams{...})
	// ... rest unchanged
}()
```

**Step 3: Add Stop timeout**

Change `Stop()` to use a timeout so it doesn't block indefinitely:
```go
func (w *EventWriter) Stop() {
	w.rateLimiter.Stop()

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// All writes drained
	case <-time.After(10 * time.Second):
		slog.Warn("security event writer: timed out waiting for pending writes")
	}

	if sw := w.syslog.Load(); sw != nil {
		if err := sw.Close(); err != nil {
			slog.Error("syslog close failed", "error", err)
		}
	}
}
```

**Step 4: Run tests and commit**

```bash
go test ./internal/secure/... -count=1 -v
git add internal/secure/writer.go internal/secure/writer_test.go
git commit -m "fix(secure): bound event writer goroutines with semaphore and add write timeout"
```

**Review Group C** — review shutdown paths in main.go holistically. Verify the ordering: delivery worker drain → metrics shutdown → HTTP shutdown → DB close.

---

## Group D: Auth + Security (D1, I7, I26)

### Task D1: Require authentication on CVE endpoints (D1)

**Files:**
- Modify: `internal/api/server.go:234` — wrap CVE routes with auth middleware
- Modify: `internal/api/cves.go:22` — fix stale comment
- Modify: existing CVE tests — add auth tokens to requests

**Step 1: Understand current wiring**

`registerCVERoutes(api, srv.store)` is called on the huma API instance at `server.go:234`. The huma API is mounted on `apiRouter` which has CSRF middleware but NOT `RequireAuthenticated`. CVE routes need authentication but do NOT need org context (CVEs are global).

**Step 2: Add auth middleware to CVE routes**

The CVE routes use huma registration on `apiRouter`. Currently `registerCVERoutes(api, srv.store)` is called at `server.go:234` on the main huma API instance, which means CVE routes inherit the apiRouter's middleware chain but NOT `RequireAuthenticated` (which is only on the org-scoped chi sub-router).

**Required approach:** Use huma's middleware support to add authentication to CVE operations. Huma supports `Middlewares` in the `huma.Operation` struct. Add the `RequireAuthenticated` middleware to each CVE operation registration in `registerCVERoutes`.

Alternatively, restructure the router so CVE routes are on a chi sub-router with `RequireAuthenticated`, then mount huma on that sub-router. But this changes the URL path resolution — test carefully.

**Whichever approach you choose, verify:**
1. `GET /api/v1/cves` without auth returns 401
2. `GET /api/v1/cves` with a valid JWT cookie returns 200
3. `GET /api/v1/cves` with a valid API key Bearer token returns 200
4. The OpenAPI spec still generates correctly for CVE endpoints
5. Auth/MFA/OAuth routes remain unauthenticated (they're the login flow)

**Do NOT** add org middleware to CVE routes — CVEs are global, not org-scoped. Only `RequireAuthenticated` (user identity), not `RequireOrgRole`.

**Step 3: Fix the stale comment**

In `cves.go:22`, change "All endpoints are public read-only — auth middleware is added in Phase 2." to "All endpoints require authentication. CVE data is global (not org-scoped)."

**Step 4: Update all CVE tests — this is the highest-impact step**

**WARNING:** Every existing CVE test will break because they currently make unauthenticated requests. You MUST update every test in `internal/api/cves_test.go` (and any other file that calls CVE endpoints) to include authentication. Use the existing test helper pattern for creating a test user and getting an auth cookie — search for `doLogin` or `loginCookie` in other `*_test.go` files in `internal/api/` for the established pattern.

Expect ~10-20 tests to need auth setup. Do NOT skip any — a test that passes only because it was excluded is worse than a test that fails.

**Step 5: Run tests and commit**

```bash
go test ./internal/api/... -count=1 -v
git add internal/api/server.go internal/api/cves.go internal/api/cves_test.go
git commit -m "feat(api): require authentication on CVE endpoints — fix Phase 2 oversight"
```

### Task D2: Extract generic JWT parse helper to deduplicate 4 functions (I7)

**Files:**
- Modify: `internal/auth/jwt.go`
- Test: existing `internal/auth/jwt_test.go` must still pass

**Step 1: Create the generic helper**

Add a private generic function that encapsulates the dual-key rotation logic:

```go
// parseTokenWithRotation tries activeSecret first, then previousSecret on signature error only.
func parseTokenWithRotation[T jwt.Claims](tokenStr string, claims T, activeSecret, previousSecret []byte, label string) (T, error) {
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
		return activeSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		return claims, nil
	}

	if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		// Need a fresh claims instance for the retry — the first parse may have partially populated it.
		// Use reflect or require callers to pass a factory. Simplest: require a pointer type and create new.
		// Actually, jwt.ParseWithClaims modifies claims in-place. For the retry, we need a fresh instance.
		// The cleanest approach: accept a factory function.
	}
	// ...
}
```

**Important consideration:** `jwt.ParseWithClaims` modifies the claims struct in-place. On retry with a different secret, we need a fresh claims struct. The generic helper should accept a claims factory:

```go
func parseTokenWithRotation[T jwt.Claims](
	tokenStr string,
	newClaims func() T,
	activeSecret, previousSecret []byte,
	label string,
) (T, error) {
	claims := newClaims()
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
		return activeSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		return claims, nil
	}

	if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		fallback := newClaims()
		_, err2 := jwt.ParseWithClaims(tokenStr, fallback, func(_ *jwt.Token) (any, error) {
			return previousSecret, nil
		},
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithExpirationRequired(),
		)
		if err2 == nil {
			return fallback, nil
		}
		var zero T
		return zero, fmt.Errorf("parse %s token: %w", label, err2)
	}

	var zero T
	return zero, fmt.Errorf("parse %s token: %w", label, err)
}
```

**Step 2: Refactor all four Parse functions**

Each becomes a one-liner:

```go
func ParseAccessToken(tokenStr string, activeSecret, previousSecret []byte) (*AccessClaims, error) {
	return parseTokenWithRotation(tokenStr, func() *AccessClaims { return &AccessClaims{} }, activeSecret, previousSecret, "access")
}
```

Repeat for `ParseRefreshToken`, `ParsePendingToken`, `ParseEnrollmentToken`.

**Scope boundary:** Do NOT change the Issue* functions (IssueAccessToken, etc.) — they are not duplicated. Do NOT add token type checking (e.g., rejecting pending tokens as access tokens) — that is a separate task (D3). Only deduplicate the Parse functions.

**Step 3: Run ALL auth tests**

```bash
go test ./internal/auth/... -count=1 -v
go test ./internal/api/... -count=1 -v
```

**Step 4: Commit**

```bash
git add internal/auth/jwt.go
git commit -m "refactor(auth): extract generic parseTokenWithRotation to deduplicate JWT parsing"
```

### Task D3: Add pending-token-as-access-token rejection test (I26)

**Files:**
- Modify: `internal/api/middleware_auth_test.go`

**Step 1: Write the test**

Add a test that:
1. Issues a pending token via `auth.IssuePendingToken(...)` with `pending: ["mfa_challenge"]`
2. Sends a request with this pending token in the auth cookie to a route protected by `RequireAuthenticated`
3. Asserts the response is 401 or 403 (the pending token should NOT grant access)

If the test passes (meaning the pending token IS rejected), that's good — it means the existing code already differentiates. If it fails (pending token IS accepted as access token), that's a security bug that needs fixing.

**Step 2: Run and assess**

```bash
go test ./internal/api/... -run TestPendingTokenRejected -count=1 -v
```

If the test fails, the fix is in `RequireAuthenticated` middleware — it should check the claims type or the presence of the `pending` field and reject tokens that aren't proper access tokens.

**Step 3: Commit**

```bash
git add internal/api/middleware_auth_test.go
git commit -m "test(api): verify pending MFA tokens are rejected as access tokens"
```

**Review Group D** — review all auth changes carefully. Run the full API test suite.

---

## Group E: Ops Readiness (D3, I5, I10, I21, I31, D2)

### Task E1: Add pgxpool AcquireTimeout (D3)

**Files:**
- Modify: `cmd/cvert-ops/main.go:692-711` (newPool function)
- Optionally: `internal/config/config.go` (add `DBAcquireTimeout` config)

**Step 1: Add config field**

In `config.go`, add:
```go
DBAcquireTimeout time.Duration `env:"DB_ACQUIRE_TIMEOUT" envDefault:"5s"`
```

**Step 2: Set in pool config**

In `newPool` at `main.go`, after the existing pool config lines, add:
```go
poolCfg.MaxConnLifetime = 30 * time.Minute // prevent stale connections
poolCfg.MaxConnLifetimeJitter = 5 * time.Minute
```

Wait — the task is specifically AcquireTimeout. pgxpool doesn't have a direct `AcquireTimeout` field, but it does via context. Actually, let me check — pgxpool v5 does NOT have an `AcquireTimeout` field directly on the config. The timeout is controlled by the context passed to `Acquire()`.

The actual fix: pass a context with timeout to all pool operations. But that's already handled by the `statement_timeout` on the Postgres side. The goroutine accumulation problem is specifically about requests waiting for a pool connection when all 25 are busy.

pgxpool does have `poolCfg.MaxConnLifetime` and `poolCfg.HealthCheckPeriod`, but NOT an acquire timeout. Pgxpool blocks on `Acquire()` until a connection is available or the context is cancelled.

**Correct approach:** Use `context.WithTimeout` in the store layer or middleware to limit how long requests wait. Or set `pgxpool.Config.MaxConnLifetime` to prevent stale connections, and rely on the existing `statement_timeout` for query-level protection.

Actually, the simplest effective approach: the HTTP server's `ReadTimeout` (15s) and per-handler `http.TimeoutHandler` already provide request-level deadlines. Worker jobs have `maxJobDuration` (10min). These propagate through context to pool Acquire. The pool won't block longer than the request context allows.

**Revised assessment:** The existing timeout architecture (HTTP ReadTimeout → context → pool acquire → statement_timeout) already provides adequate backpressure. Adding a separate AcquireTimeout would be redundant. Skip this task or add a short note documenting why it's unnecessary.

If Sam still wants an explicit acquire timeout, the approach is to wrap pool operations with `context.WithTimeout`. But this is a larger change touching every store method.

**Decision: Skip this task** — document in the plan that existing timeout architecture provides adequate protection. The HTTP ReadTimeout (15s) flows through context to pool acquire.

### Task E2: Add container healthcheck binary for production (I5)

**Files:**
- Create: `cmd/healthcheck/main.go` — tiny Go binary
- Modify: `docker/Dockerfile` — build and copy the healthcheck binary
- Modify: `docker/compose.prod.yml` — add HEALTHCHECK directive

**Step 1: Create healthcheck binary**

```go
// cmd/healthcheck/main.go
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("LISTEN_ADDR")
	if port == "" {
		port = ":8080"
	}
	url := fmt.Sprintf("http://localhost%s/healthz", port)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
```

Add ABOUTME comments at the top.

**Step 2: Update Dockerfile**

In the builder stage, add a second build step:
```dockerfile
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /healthcheck ./cmd/healthcheck
```

In the runtime stage:
```dockerfile
COPY --from=builder /healthcheck /healthcheck
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
  CMD ["/healthcheck"]
```

**Step 3: Update compose.prod.yml**

Remove the "No healthcheck" comment. The Dockerfile HEALTHCHECK is sufficient for Docker Compose. If you want to override in compose.prod.yml:
```yaml
healthcheck:
  test: ["/healthcheck"]
  interval: 10s
  timeout: 3s
  start_period: 30s
  retries: 3
```

**Step 4: Test locally**

```bash
docker build -f docker/Dockerfile -t cvert-ops-test .
docker run --rm cvert-ops-test /healthcheck  # should exit 1 (no server running)
```

**Step 5: Commit**

```bash
git add cmd/healthcheck/main.go docker/Dockerfile docker/compose.prod.yml
git commit -m "feat(docker): add healthcheck binary for production container"
```

### Task E3: Add job queue depth metric (I10)

**Files:**
- Modify: `internal/metrics/worker.go` — add gauge
- Modify: `internal/worker/pool.go` — report pending count after each poll
- Modify: `internal/store/` — add `CountPendingJobs` query if not exists
- Test: verify metric is registered and updated

**Step 1: Add the Prometheus gauge**

In `internal/metrics/worker.go`:
```go
var WorkerJobsPending = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: "cvertops",
	Subsystem: "worker",
	Name:      "jobs_pending",
	Help:      "Number of pending jobs in the queue.",
})
```

**Step 2: Add store method**

If not already present, add a `CountPendingJobs(ctx) (int64, error)` method to the store that runs:
```sql
SELECT count(*) FROM job_queue WHERE status = 'pending'
```

**Step 3: Report in poll loop**

In `worker/pool.go`, after each poll cycle (after claiming jobs), call `CountPendingJobs` and update the gauge. Do this in the stale check goroutine (which runs every minute) rather than every poll (every 2s) to avoid excessive DB queries:

```go
if count, err := p.store.CountPendingJobs(ctx); err == nil {
	metrics.WorkerJobsPending.Set(float64(count))
}
```

**Step 4: Run tests and commit**

```bash
go test ./internal/worker/... -count=1 -v
git add internal/metrics/worker.go internal/worker/pool.go internal/store/...
git commit -m "feat(metrics): add worker jobs pending gauge"
```

### Task E4: Fix log level reload (I21)

**Files:**
- Modify: `cmd/cvert-ops/main.go` — use `slog.LevelVar` for logger
- Modify: `internal/config/reload.go` or the reload callback — update level on reload

**Step 1: Use LevelVar in logger creation**

In `newLogger` (main.go), change the handler to use a `*slog.LevelVar`:

```go
var logLevel slog.LevelVar

func newLogger(cfg *config.Config) *slog.Logger {
	logLevel.Set(parseLogLevel(cfg.LogLevel))
	// ... create handler with &logLevel instead of a fixed level
}
```

**Step 2: Wire reload callback**

In the config reload callback (wherever SIGHUP or admin reload is handled), add:
```go
logLevel.Set(parseLogLevel(newCfg.LogLevel))
slog.Info("log level changed", "level", newCfg.LogLevel)
```

**Step 3: Test and commit**

```bash
go build ./cmd/cvert-ops
git add cmd/cvert-ops/main.go
git commit -m "fix(config): wire log level reload to slog.LevelVar"
```

### Task E5: Add feed HTTP client response body size limit (I31)

**Files:**
- Modify: `cmd/cvert-ops/main.go` (~line 177) or create a wrapper transport

**Step 1: Add a size-limiting transport wrapper**

Create a transport wrapper that wraps response bodies with `io.LimitReader`:

```go
type maxBodyTransport struct {
	base    http.RoundTripper
	maxSize int64
}

func (t *maxBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, t.maxSize)
	return resp, nil
}
```

Wait — `http.MaxBytesReader` requires an `http.ResponseWriter` (first param). For client-side limiting, use `io.LimitReader` instead:

```go
resp.Body = io.NopCloser(io.LimitReader(resp.Body, t.maxSize))
```

But this loses the original closer. Better:

```go
type limitedReadCloser struct {
	io.Reader
	io.Closer
}

resp.Body = limitedReadCloser{
	Reader: io.LimitReader(resp.Body, t.maxSize),
	Closer: resp.Body,
}
```

Set `maxSize` to 512 MB (generous for the largest feeds like MITRE's ZIP). Configurable via env var if desired.

**Step 2: Apply to feed client**

In `main.go` where the feed HTTP client is created, wrap the transport:

```go
feedClient := &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &maxBodyTransport{
		base:    http.DefaultTransport,
		maxSize: 512 << 20, // 512 MB
	},
}
```

**Step 3: Test and commit**

```bash
go test ./internal/feed/... -count=1 -v
git add cmd/cvert-ops/main.go
git commit -m "fix(feed): limit feed HTTP response body size to 512 MB"
```

### Task E6: Add circuit breaker to feed adapters using gobreaker (D2)

**Files:**
- Add dependency: `github.com/sony/gobreaker/v2`
- Create: `internal/feed/breaker.go` — circuit breaker wrapper
- Modify: `internal/ingest/handler.go` — integrate breaker per feed
- Modify: `internal/metrics/` — add breaker state metrics
- Test: `internal/feed/breaker_test.go`

**Step 1: Add the dependency**

```bash
go get github.com/sony/gobreaker/v2@v2.4.0
```

**Step 2: Create the breaker wrapper**

In `internal/feed/breaker.go`:

```go
package feed

import (
	"fmt"
	"log/slog"

	"github.com/sony/gobreaker/v2"
)

// NewBreaker creates a circuit breaker for a feed adapter.
// Opens after consecutiveFailures consecutive failures.
// Stays open for the timeout duration before allowing a probe request.
func NewBreaker(name string, consecutiveFailures uint32, timeout time.Duration) *gobreaker.CircuitBreaker[struct{}] {
	return gobreaker.NewCircuitBreaker[struct{}](gobreaker.Settings{
		Name: name,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= consecutiveFailures
		},
		Timeout: timeout,
		OnStateChange: func(name string, from, to gobreaker.State) {
			slog.Warn("feed circuit breaker state change",
				"feed", name,
				"from", from.String(),
				"to", to.String(),
			)
		},
	})
}
```

**Step 3: Integrate with ingest handler**

In the ingest handler, before calling `adapter.Fetch()`, check the circuit breaker:

```go
_, err := breaker.Execute(func() (struct{}, error) {
	return struct{}{}, adapter.Fetch(ctx)
})
if err != nil {
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		slog.Warn("feed circuit breaker open, skipping", "feed", feedName)
		return nil // skip this feed, don't fail the job
	}
	return err
}
```

Create breakers per feed in the ingest handler initialization, stored in a `map[string]*gobreaker.CircuitBreaker`. Default: 5 consecutive failures, 5-minute timeout.

**Step 4: Add metrics**

Add a Prometheus gauge for breaker state per feed:
```go
var FeedCircuitBreakerState = promauto.NewGaugeVec(...)
```

Update in the `OnStateChange` callback.

**Step 5: Write tests**

Test that:
- After N consecutive failures, the breaker opens and subsequent calls return `ErrOpenState`
- After the timeout, one probe request is allowed (half-open)
- A successful probe closes the breaker

**Step 6: Run tests and commit**

```bash
go test ./internal/feed/... -count=1 -v
go test ./internal/ingest/... -count=1 -v
git add internal/feed/breaker.go internal/feed/breaker_test.go internal/ingest/handler.go internal/metrics/feed.go go.mod go.sum
git commit -m "feat(feed): add per-feed circuit breaker using sony/gobreaker"
```

**Review Group E** — run full test suite. Review all ops changes.

---

## Group F: Test Quality (I11, I15, I19, I25, I27)

### Task F1: Fix store test helpers that discard errors (I19)

**Files:**
- Modify: multiple `*_test.go` files across `internal/store/`, `internal/notify/`, `internal/alert/`

**Step 1: Find all instances**

Search for `_, _ :=` and `x, _ :=` patterns in test files where the discarded error is from `CreateOrg`, `CreateUser`, or similar setup functions.

```bash
rg ', _ := s\.(Create|Insert|Upsert)' --type go --glob '*_test.go'
```

**Step 2: Replace with proper error handling**

For each instance, replace `x, _ := s.Foo(...)` with:
```go
x, err := s.Foo(...)
if err != nil {
	t.Fatalf("setup: Foo: %v", err)
}
```

Or use `require.NoError(t, err)` if testify is available.

This is mechanical but important. Do NOT change the test logic — only add error checking to setup calls.

**Step 3: Run tests and commit**

```bash
go test ./... -count=1
git add -u
git commit -m "fix(tests): check errors from setup helpers instead of discarding"
```

### Task F2: Add EPSS two-statement pattern integration test (I25)

**Files:**
- Create or modify: `internal/feed/epss/adapter_integration_test.go`

**Step 1: Write integration tests**

Two test cases:
1. **CVE exists:** Insert a CVE via merge pipeline, run EPSS adapter with a score for that CVE, verify `cves.epss_score` is updated
2. **CVE doesn't exist:** Run EPSS adapter with a score for a CVE that's NOT in the database, verify an `epss_staging` row is created

These require a test database. Use the existing `testutil.NewTestDB(t)` pattern.

**Step 2: Run and commit**

```bash
go test ./internal/feed/epss/... -count=1 -v
git add internal/feed/epss/
git commit -m "test(epss): add integration tests for two-statement write pattern"
```

### Task F3: Improve TestBuildSafeClient assertions (I27)

**Files:**
- Modify: `internal/notify/webhook_test.go:230-235`

**Step 1: Add assertions**

After the existing timeout check, add:
- Assert redirect following is disabled (attempt a redirect and verify it doesn't follow)
- Assert the transport has `MaxConnsPerHost: 50` (type-assert to `*http.Transport` if the safeurl client exposes this)

If the safeurl library wraps the transport opaquely and doesn't expose these settings, document that limitation and test what you can.

**Step 2: Run and commit**

```bash
go test ./internal/notify/... -run TestBuildSafe -count=1 -v
git add internal/notify/webhook_test.go
git commit -m "test(notify): add redirect and MaxConnsPerHost assertions to BuildSafeClient test"
```

### Task F4: Add feed adapter integration test (I11) — pick ONE adapter

**Files:**
- Create: `internal/feed/nvd/adapter_integration_test.go` (or similar)

**Step 1: Design the test**

Pick the NVD adapter (highest-value, most fields). The test:
1. Starts a httptest server serving canned NVD JSON response
2. Calls `adapter.Fetch()` which produces `CanonicalPatch` structs
3. Passes each patch through `merge.Ingest()`
4. Queries the database and verifies: CVE row exists, CVSS fields populated, CWE IDs present, references present, affected products present

Use an existing NVD test fixture JSON from `internal/feed/nvd/testdata/` or the canned response from existing adapter tests.

This is a higher-effort task. If testcontainers or the test DB setup is complex, start with a simpler adapter (KEV — fewer fields).

**Step 2: Run and commit**

```bash
go test ./internal/feed/nvd/... -count=1 -v -tags=integration
git add internal/feed/nvd/adapter_integration_test.go
git commit -m "test(feed): add NVD adapter-to-store integration test"
```

### Task F5: Add webhook safeurl integration test (I15)

**Files:**
- Add test in `internal/notify/webhook_test.go` or a new file

**Step 1: Design the test**

This is tricky because safeurl blocks loopback addresses (127.0.0.1). Options:
- Test that the safeurl client BLOCKS a private IP delivery (this verifies integration)
- Test that the safeurl client configuration (redirect disabled, timeout, MaxConnsPerHost) is correct by inspecting the client struct

At minimum: verify that `BuildSafeClient()` returns a client that blocks SSRF attempts. This IS already tested in `TestBuildSafeClient_BlocksPrivateIPs`. The gap is that no functional delivery test uses the real client.

Add a test that calls the webhook `Send` function with the real safeurl client against a private IP and verifies SSRF is blocked in the delivery path (not just the client constructor).

**Step 2: Run and commit**

```bash
go test ./internal/notify/... -count=1 -v
git add internal/notify/
git commit -m "test(notify): add safeurl SSRF blocking test in delivery path"
```

**Review Group F** — run `go test ./... -count=1`. Review test quality.

---

## Group G: Minor Code Quality + API Fixes

### Task G2: Fix NullString empty-string behavior (I22)

**Files:**
- Modify: `internal/dbutil/null.go:10-12`

**Step 1: Audit callers**

Before changing behavior, search for all callers of `dbutil.NullString`:
```bash
rg 'dbutil\.NullString' --type go
```

Determine if any caller INTENTIONALLY depends on empty-string → NULL. If the merge pipeline is the primary caller and empty strings are never valid source data, the current behavior may be correct by convention.

**Step 2: If change is warranted**

Rename current `NullString` to clarify its behavior, or add a `NullStringPreserveEmpty` variant. The safest approach is to NOT change existing behavior but add a clearly named alternative and update callers that need it.

**Important:** Do NOT change the function signature without Sam's approval if many callers depend on it. Flag this for discussion.

**Step 3: Commit**

```bash
git add internal/dbutil/null.go
git commit -m "refactor(dbutil): clarify NullString empty-string-is-NULL behavior"
```

### Task G3: Fix isPermanentDeliveryError to use typed SMTP errors (I23)

**Files:**
- Modify: `internal/notify/worker.go:349-365`
- Test: add test cases for permanent vs transient SMTP errors

**Step 1: Investigate go-mail error types**

Check if the go-mail library (`github.com/wneessen/go-mail`) exposes a typed SMTP error with a status code. If it does, use type assertion instead of string matching. If it doesn't, document the limitation and consider improving the string matching (e.g., use a regex for `\b5\d{2}\b` instead of `strings.Contains` with hardcoded codes).

**Step 2: Implement and test**

**Step 3: Commit**

```bash
git add internal/notify/worker.go internal/notify/worker_test.go
git commit -m "fix(notify): improve permanent delivery error detection"
```

### Task G4: Add Cache-Control headers (I30)

**Files:**
- Modify: `internal/api/server.go` — add middleware for authenticated routes
- Optionally modify CVE handlers for public caching (if CVE endpoints become authenticated, use `no-store`)

**Step 1: Add no-store middleware**

Add a middleware that sets `Cache-Control: no-store` on all authenticated responses. Wire it on the org-scoped router.

**Step 2: Commit**

```bash
git add internal/api/
git commit -m "feat(api): add Cache-Control: no-store to authenticated responses"
```

### Task G5: Fix testChannelHandler status code (I29)

**Files:**
- Modify: `internal/api/channels.go:521`

**Step 1: Change status code on failure**

When `resp.Success` is false, return HTTP 502 instead of 200. This makes the test-channel endpoint consistent with HTTP semantics.

**Step 2: Update tests and commit**

```bash
go test ./internal/api/... -run TestChannel -count=1 -v
git add internal/api/channels.go internal/api/channels_test.go
git commit -m "fix(api): testChannelHandler returns 502 on delivery failure instead of 200"
```

### Task G6: Frontend raw fetch migration (I28)

**Files:**
- Modify: `web/src/stores/auth.ts`
- Modify: `web/src/views/admin/AdminSystemView.vue`
- Modify: `web/src/views/LoginView.vue`, `RegisterView.vue`

**Step 1: Migrate auth store methods**

Replace raw `fetch` calls for `forgot-password`, `reset-password`, `verify-email` with the typed openapi-fetch client. These are unauthenticated endpoints — check if the typed client supports unauthenticated calls or if a separate client instance is needed.

**Step 2: Migrate admin doctor view**

Replace raw `fetch` for `/admin/doctor` with the typed client. This IS authenticated and should use the main client with refresh interceptor.

**Step 3: Migrate auth providers fetch**

Replace raw `fetch` for `/auth/providers` in LoginView and RegisterView.

**Step 4: Run frontend tests**

```bash
cd web && npm run test:unit && npm run type-check && npm run lint
```

**Step 5: Commit**

```bash
git add web/src/
git commit -m "fix(web): migrate raw fetch calls to typed openapi-fetch client"
```

**Review Group G** — run full test suite (Go + frontend).

---

## Group H: PLAN.md Update (D5)

### Task H1: Update import-bulk description in PLAN.md

**Files:**
- Modify: `PLAN.md` — section 3.3 or wherever import-bulk is described

**Step 1: Find the import-bulk references**

```bash
rg 'import.bulk' PLAN.md
```

**Step 2: Update description**

Change the description from "bulk import from NVD/MITRE downloads" to clarify its role as a dev/test seed corpus loader, aligned with the Phase 10 test fixture corpus plan:

> `import-bulk` loads CVE data from local files (captured feed snapshots, golden test fixtures) into the database. Primary use cases: (1) seeding a development environment from the test fixture corpus (see Phase 10 plan), (2) offline/airgapped deployments where API access is unavailable. NOT the primary mechanism for initial production data population — use the feed adapters' normal API sync for that.

Do NOT remove the command or its stub implementation — Phase 10 will implement it.

**Step 3: Commit**

```bash
git add PLAN.md
git commit -m "docs(plan): clarify import-bulk as dev seed / airgapped loader, not primary sync"
```

---

## Appendix: Issues Identified But Not Fixed in This Cycle

### I9. serve/worker command initialization duplicated ~80%
**Severity:** MAJOR
**Dimensions:** Architecture, Ops Readiness
**Evidence:** `cmd/cvert-ops/main.go:105-351` and `:363-495` share ~80% identical initialization
**Why deferred:** Large refactor with high blast radius. The delivery worker shutdown fix (I2) and other quick wins in main.go reduce the immediate risk. The full extraction should be its own dedicated plan to avoid scope creep.
**Recommended approach:** Extract shared initialization into a `buildApp()` function returning configured components. Make this a dedicated refactoring task.

### I18. Inconsistent pagination — 6 list endpoints have no pagination
**Severity:** MINOR
**Dimensions:** API Design
**Evidence:** channels, members, invitations, API keys, reports, feeds list endpoints have no pagination
**Why deferred:** Low risk at MVP scale. Collections are naturally small. Adding pagination is a breaking API change that should be coordinated.
**Recommended approach:** Add pagination when any collection is observed to grow beyond ~50 items in production.

### E1. pgxpool AcquireTimeout
**Severity:** Design decision D3
**Why deferred:** Existing timeout architecture (HTTP ReadTimeout → context → pool acquire → statement_timeout) already provides adequate backpressure. Adding a separate AcquireTimeout would be redundant.
