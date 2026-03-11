# Health Review Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address all 45 findings from the 2026-03-10 project health review, organized into 6 phases by dependency and risk.

**Architecture:** Findings are grouped by root cause and dependency order. Phase 1 (quick wins) and Phase 2 (critical security + core feature) are detailed with full code. Phases 3-6 are outlined and will get their own detailed plans when reached.

**Tech Stack:** Go 1.26, PostgreSQL 15+, huma/chi, sqlc, squirrel, Prometheus, Vue 3 + openapi-fetch

---

## Prerequisites: Phase 8 Merges First

Phase 8 (Operational Maturity) worktrees merge before this plan executes. This resolves several findings outright and affects the scope of others:

| Phase 8 Pillar | Findings Resolved | Impact on This Plan |
|---|---|---|
| 8B Observe | **#10** (no metrics) | Task 4B removed — 8B adds all needed metrics |
| 8C Operate | **#3** (no health check), **#38** (no readiness probe) | Task 4A removed — 8C adds /healthz, /readyz, Docker HEALTHCHECK |
| 8C Operate | **#45** (schema version sync) | Reduced impact — auto-migrate checks currency at startup |
| 8B Observe | #1 (alert metrics wired but read zero) | Alert metrics exist after 8B; Task 2C makes them non-zero |
| 8C Operate | #2 (RLS doctor checks added) | Doctor detects the issue; Task 2A.1 still needed to fix it |

**Post-merge follow-up risks:**
- **Phase 2B (evaluator refactor)** may shift metric instrumentation points added by 8B Observe. If `applyPostFilters` or `queryCandidates` move, a small follow-up to re-wire metrics may be needed. The plan notes this per-task.
- **Phase 3 (chi→huma)** must include the admin API endpoints added by 8C Operate.
- **Task 4C (runServe/runWorker dedup)** is harder post-Phase 8 since 8B/8C/8D all add code to both functions. Deferred to Phase 6.

---

## Phase Overview

```
Phase 1: Quick Wins ──────────── Independent, low-risk, parallelizable
Phase 2: Critical Fixes ──────── RLS security + alert pipeline wiring
Phase 3: Chi→Huma Migration ──── Addresses 10+ API consistency findings (incl. 8C admin endpoints)
Phase 4: Ops Hardening ────────── Semaphore eviction, statement timeout (reduced scope)
Phase 5: Test Quality ─────────── Golden files, integration tests
Phase 6: Architecture ─────────── Deferred refactoring (incl. runServe/runWorker dedup)
```

**Dependency graph:**
- Phase 1: No dependencies. All tasks independent of each other.
- Phase 2A (RLS): Independent. Complements Phase 8C doctor checks (makes them pass).
- Phase 2B (Alert refactor): Independent. Must complete before 2C. May need small follow-up for 8B Observe metric instrumentation points.
- Phase 2C (Alert wiring): Depends on 2B. After this, 8B Observe alert metrics start registering.
- Phase 3: Independent of Phase 2. Largest phase, needs its own detailed plan. Must include Phase 8C admin endpoints.
- Phase 4: Reduced scope (4A/4B removed, 4C moved to Phase 6).
- Phase 5: Independent.
- Phase 6: Defer until Phases 2-4 are done. Now includes Task 4C (runServe/runWorker dedup).

**Resolved findings (no action needed):**
- **Finding 11** (REGISTRATION_MODE default): Already fixed — config.go shows `envDefault:"invite-only"`.
- **Finding 10** (No metrics): Resolved by Phase 8B Observe.
- **Finding 3** (No health check): Resolved by Phase 8C Operate.
- **Finding 38** (No readiness probe): Resolved by Phase 8C Operate.

---

## Subagent Execution Guidance

### Common pitfalls for subagents executing this plan

1. **Don't change what you weren't asked to change.** Each task specifies exact files and exact changes. Don't "improve" surrounding code, add comments, or refactor nearby functions.

2. **Match existing code style exactly.** This codebase uses tabs for indentation in Go. Error messages are lowercase. Comments use `//` with a space. Read surrounding code before writing.

3. **Run the exact test commands specified.** Don't substitute `go test ./...` when the task says to run a specific package test. The full suite takes too long and failures in other packages aren't your problem.

4. **TDD means TDD.** Write the failing test FIRST. Run it. See it fail. THEN write the implementation. Don't write both at once.

5. **One commit per task.** Don't batch. Don't skip commits.

6. **When the plan says "delete," delete.** Don't comment out. Don't rename with underscore prefix. Delete the code.

7. **Read referenced files before editing.** Every task lists files to modify. Read them first, even if you think you know what's there. Line numbers may have shifted from prior tasks.

---

# Phase 1: Quick Wins

All tasks in this phase are independent and can be dispatched to parallel subagents.
Each task is self-contained with no cross-task dependencies.

---

## Task 1.1: Close api.Server on shutdown (Finding 4)

**Finding:** `api.Server.Close()` is defined but never called — 4 background goroutines leak.

**Files:**
- Modify: `cmd/cvert-ops/main.go` (~line 135, after `apiSrv` creation)
- Test: `cmd/cvert-ops/main.go` (manual verification — no unit test needed for a `defer` call)

**Step 1: Read the file**

Read `cmd/cvert-ops/main.go` and find where `apiSrv` is created in `runServe`. It should be around line 132:
```go
apiSrv, err := api.NewServer(st, cfg)
if err != nil {
    return fmt.Errorf("api server init: %w", err)
}
```

**Step 2: Add defer Close()**

Immediately after the error check for `NewServer`, add:
```go
defer apiSrv.Close()
```

This must go BEFORE the `defer db.Close()` in execution order (defers run LIFO), but that's fine — stopping rate limiter goroutines before closing the DB pool is correct.

**Step 3: Verify it compiles**

Run: `go build ./cmd/cvert-ops/`
Expected: Clean build, no errors.

**Step 4: Commit**

```
fix: close api.Server on shutdown to stop leaked goroutines

Adds defer apiSrv.Close() in runServe to stop the rate limiter,
org rate limiter, tier cache, and lockout manager cleanup goroutines
on shutdown. Fixes health review finding #4.
```

---

## Task 1.2: Close stdlib.OpenDBFromPool wrappers (Finding 5)

**Finding:** `stdlib.OpenDBFromPool(db)` returns `*sql.DB` wrappers that are never closed.

**Files:**
- Modify: `cmd/cvert-ops/main.go` — both `runServe` (~line 140) and `runWorker` (~line 259)

**Step 1: Read the file**

Find both `stdlib.OpenDBFromPool(db)` calls. They're currently inlined into the `alert.New()` call:
```go
alertEval := alert.New(stdlib.OpenDBFromPool(db), st, alertCache, slog.Default())
```

**Step 2: Extract and defer close in runServe**

Replace the inline call with:
```go
alertDB := stdlib.OpenDBFromPool(db)
defer alertDB.Close()
alertEval := alert.New(alertDB, st, alertCache, slog.Default())
```

**IMPORTANT:** The `defer alertDB.Close()` must execute BEFORE `defer db.Close()` (the pool close). Since defers are LIFO, place the `alertDB` lines AFTER the pool creation and its defer. This is already the natural position since the pool is created earlier in the function.

**Step 3: Do the same in runWorker**

Find the identical pattern in `runWorker` and apply the same change.

**Step 4: Verify it compiles**

Run: `go build ./cmd/cvert-ops/`
Expected: Clean build.

**Step 5: Commit**

```
fix: close stdlib sql.DB wrappers on shutdown

Extract stdlib.OpenDBFromPool result into a named variable and defer
Close() in both runServe and runWorker. Fixes health review finding #5.
```

---

## Task 1.3: Validate COOKIE_SECURE in production (Finding 12)

**Finding:** `COOKIE_SECURE` defaults to `false` with no production validation.

**Files:**
- Modify: `cmd/cvert-ops/main.go` — `validateConfig` function (~line 509)
- Modify: `cmd/cvert-ops/validate_config_test.go` — add test cases

**Step 1: Write the failing test**

Read `cmd/cvert-ops/validate_config_test.go` to see the existing test pattern. Add two new test cases to the existing table-driven test (or as standalone tests matching the file's pattern):

```go
func TestValidateConfig_CookieSecureRequired(t *testing.T) {
	cfg := validConfig() // copy whatever helper creates a valid config in the test file
	cfg.CookieSecure = false
	cfg.AppEnv = "production"
	cfg.ExternalURL = "https://example.com"

	err := validateConfig(&cfg)
	if err == nil {
		t.Fatal("expected error when CookieSecure=false in production with HTTPS")
	}
	if !strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Errorf("error should mention COOKIE_SECURE, got: %v", err)
	}
}

func TestValidateConfig_CookieSecureNotRequiredInDev(t *testing.T) {
	cfg := validConfig()
	cfg.CookieSecure = false
	cfg.AppEnv = "development"
	cfg.ExternalURL = "http://localhost:8080"

	err := validateConfig(&cfg)
	if err != nil {
		t.Errorf("should not require CookieSecure in development: %v", err)
	}
}
```

**IMPORTANT:** Look at the existing test file to match the exact helper function name and pattern. The above is a template — adapt to match the file's style. If it uses table-driven tests, add rows to the table instead.

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/cvert-ops/ -run TestValidateConfig_CookieSecure -v`
Expected: FAIL — the new test expects an error but `validateConfig` doesn't check `CookieSecure` yet.

**Step 3: Add the validation**

In `cmd/cvert-ops/main.go`, find `validateConfig` (~line 509). Add after the existing HTTPS check:

```go
if !cfg.IsDevelopment() && strings.HasPrefix(cfg.ExternalURL, "https://") && !cfg.CookieSecure {
	return fmt.Errorf("COOKIE_SECURE must be true when EXTERNAL_URL uses HTTPS in non-development environments")
}
```

**Why this condition:** We only enforce when HTTPS is in use AND not development. If someone runs HTTP in production (which the prior check rejects), we don't pile on with a cookie error too.

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/cvert-ops/ -run TestValidateConfig -v`
Expected: ALL validateConfig tests pass (both new and existing).

**Step 5: Commit**

```
fix: enforce COOKIE_SECURE=true for HTTPS in production

Adds startup validation that COOKIE_SECURE must be true when
EXTERNAL_URL uses HTTPS outside development mode. Prevents session
hijacking from forgotten config. Fixes health review finding #12.
```

---

## Task 1.4: Fix worker pool context cancellation (Finding 13)

**Finding:** Worker pool passes cancellable context to job handlers — in-flight jobs fail during shutdown.

**Files:**
- Modify: `internal/worker/pool.go` (~line 142)
- Test: Existing worker tests should still pass

**Step 1: Read the file**

Read `internal/worker/pool.go`. Find the goroutine in the polling loop (~line 139):
```go
go func() {
    defer inflight.Done()
    defer func() { <-sem }()
    p.processOne(ctx, queue)
}()
```

**Step 2: Change to WithoutCancel**

Replace `p.processOne(ctx, queue)` with:
```go
p.processOne(context.WithoutCancel(ctx), queue)
```

This matches the pattern already used in `internal/notify/worker.go:139`.

**IMPORTANT:** Do NOT add `context` to imports if it's already imported. Check the import block first.

**Step 3: Run tests**

Run: `go test ./internal/worker/ -v -count=1`
Expected: All tests pass.

**Step 4: Commit**

```
fix: use WithoutCancel for worker pool job context

In-flight jobs now get a context that survives shutdown signal,
matching the notification worker pattern. Jobs complete gracefully
instead of failing with context.Canceled. Fixes finding #13.
```

---

## Task 1.5: Remove dead readTx method (Finding 26)

**Finding:** `Evaluator.readTx()` is defined but never called. Dead code.

**Files:**
- Modify: `internal/alert/evaluator.go` (~lines 605-615)

**Step 1: Read the file**

Read `internal/alert/evaluator.go` and confirm `readTx` is never called. Search for `.readTx(` in the file — should have zero callers.

**Step 2: Delete the method**

Remove the entire `readTx` method (the function, its comment, and its body). Should be approximately lines 605-615:
```go
// readTx opens a read-only database/sql transaction and calls fn. The transaction
// is always rolled back at the end — writes (if any) are discarded. Use for
// dry-run and other read-only evaluation paths that must not touch alert_events.
func (e *Evaluator) readTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := e.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin read tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	return fn(tx)
}
```

**Step 3: Verify it compiles and tests pass**

Run: `go build ./internal/alert/ && go test ./internal/alert/ -v -count=1`
Expected: Clean build and all tests pass.

**Step 4: Commit**

```
chore: remove unused readTx method from alert evaluator

Dead code — never called. DryRun uses bypassTx instead.
Fixes health review finding #26.
```

---

## Task 1.6: Fix misleading GetCVEDetail comment (Finding 40)

**Finding:** Comment says "parallel queries" but code is sequential. Also claims `(nil, nil, nil, nil, nil)` return but actually returns `(nil, nil, nil, nil, err)`.

**Files:**
- Modify: `internal/store/cve.go` (~line 30)

**Step 1: Read the file**

Read `internal/store/cve.go` and find the `GetCVEDetail` function comment.

**Step 2: Fix the comment**

Replace the existing comment with one that accurately describes the current behavior:

```go
// GetCVEDetail fetches the canonical CVE row plus all child tables (references,
// affected packages, affected CPEs). Returns (nil, nil, nil, nil, nil) when
// the CVE does not exist; returns (nil, nil, nil, nil, err) on query failure.
```

Remove "in parallel" — the code is sequential. Fix the nil return documentation.

**DO NOT** change the code to actually be parallel. That's a separate optimization. Just fix the comment.

**Step 3: Verify it compiles**

Run: `go build ./internal/store/`
Expected: Clean build.

**Step 4: Commit**

```
fix: correct misleading GetCVEDetail comment

Comment claimed parallel queries and wrong nil return signature.
Code is sequential and returns err on failure. Fixes finding #40.
```

---

## Task 1.7: Fix test with no assertion (Finding 41)

**Finding:** `TestExecuteDSLQuery_EmptyConditions` logs both outcomes but never asserts.

**Files:**
- Modify: `internal/store/dsl_executor_test.go` (~lines 132-148)

**Step 1: Read the file**

Read `internal/store/dsl_executor_test.go` around line 132. The current test:
```go
_, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
if err == nil {
    t.Log("Compile accepted empty conditions — NL search handler must handle this case")
} else {
    t.Log("Compile rejected empty conditions — NL search handler must handle this case")
}
```

**Step 2: Determine the expected behavior**

First, check what `dsl.Compile` actually does with empty conditions. Read `internal/alert/dsl/compiler.go` and find the Compile function. Look for how it handles empty conditions. Based on the test comment "The DSL compiler rejects rules where all conditions are regex with no watchlist IDs", empty conditions should probably be rejected.

Run the test once to see which branch executes:
```
go test ./internal/store/ -run TestExecuteDSLQuery_EmptyConditions -v -count=1
```

**Step 3: Add the assertion**

Based on what the compiler actually does, add the appropriate assertion. If Compile rejects empty conditions (returns error):
```go
_, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
if err == nil {
    t.Fatal("expected Compile to reject empty conditions")
}
```

If Compile accepts empty conditions (returns nil error):
```go
compiled, err := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
if err != nil {
    t.Fatalf("Compile should accept empty conditions: %v", err)
}
// Verify the compiled rule produces a valid (empty) result
if compiled == nil {
    t.Fatal("compiled rule should not be nil")
}
```

**IMPORTANT:** Pick ONE behavior and assert it. The whole point is that this test must be able to fail.

**Step 4: Run the test**

Run: `go test ./internal/store/ -run TestExecuteDSLQuery_EmptyConditions -v -count=1`
Expected: PASS with the assertion actually verifying behavior.

**Step 5: Commit**

```
fix: add assertion to TestExecuteDSLQuery_EmptyConditions

Test previously logged both outcomes without asserting either.
Now verifies the compiler's actual behavior. Fixes finding #41.
```

---

## Task 1.8: Fix store tests discarding setup errors (Finding 37)

**Finding:** Store tests use `org1, _ := s.CreateOrg(ctx, ...)` discarding setup errors.

**Files:**
- Modify: `internal/store/store_test.go`

**Step 1: Read the file**

Read `internal/store/store_test.go` and find ALL instances of discarded errors in test setup. Look for patterns like:
- `org1, _ := s.CreateOrg(...)`
- `u1, _ := s.CreateUser(...)`
- `_ = s.CreateOrgMember(...)`

**Step 2: Replace each discarded error with require**

For each instance, replace `_` with a named error and add `require.NoError`:

```go
// Before:
org1, _ := s.CreateOrg(ctx, "OrgTxOrg1")

// After:
org1, err := s.CreateOrg(ctx, "OrgTxOrg1")
require.NoError(t, err)
```

For calls that only return error:
```go
// Before:
_ = s.CreateOrgMember(ctx, org1.ID, u1.ID, "member")

// After:
err = s.CreateOrgMember(ctx, org1.ID, u1.ID, "member")
require.NoError(t, err)
```

**IMPORTANT:** Check if `require` is already imported (from `github.com/stretchr/testify/require`). If not, check what assertion library the file uses. If it uses stdlib only, use:
```go
if err != nil {
    t.Fatalf("setup: CreateOrg: %v", err)
}
```

Match the file's existing test style.

**Step 3: Run tests**

Run: `go test ./internal/store/ -v -count=1 -timeout 120s`
Expected: All tests pass (if the test DB is available). If tests are skipped due to no DB, that's fine — verify the code compiles: `go build ./internal/store/`

**Step 4: Commit**

```
fix: check setup errors in store tests instead of discarding

Replace blank _ error returns with require.NoError (or t.Fatalf) so
infrastructure failures surface clearly. Fixes finding #37.
```

---

## Task 1.9: Fix DownloadToTemp test package state mutation (Finding 42)

**Finding:** Test mutates package-level `MaxDownloadSize`, preventing parallel execution.

**Files:**
- Modify: `internal/feed/util.go` (~line 70) — make MaxDownloadSize a function parameter or use a different pattern
- Modify: `internal/feed/util_test.go` (~line 326)

**Step 1: Read both files**

Read `internal/feed/util.go` to understand how `MaxDownloadSize` is used in `DownloadToTemp`. Read `internal/feed/util_test.go` to see the test.

**Step 2: Evaluate the fix**

The cleanest fix depends on how `MaxDownloadSize` is used. Two options:

**Option A (preferred if MaxDownloadSize is only used in DownloadToTemp):** Add an optional parameter or use a config pattern. But this changes the API surface — check all callers first.

**Option B (minimal, safe):** Keep the package var but add `t.Setenv`-style isolation. Since the test already correctly avoids `t.Parallel()` and uses `t.Cleanup`, the current approach is actually safe for sequential execution. The finding's concern is about *future* parallelization.

The safest minimal fix: add a comment explaining why `t.Parallel()` is omitted, and ensure the test uses `t.Cleanup` (which it already does). If you want to go further, refactor `DownloadToTemp` to accept a max size parameter.

**Check how many callers DownloadToTemp has** before deciding. If it's only called in 2-3 places, adding a parameter is fine. If it's called everywhere, keep the package var.

**Step 3: Implement the chosen fix**

If adding a parameter, update `DownloadToTemp` signature to accept `maxSize int64` and update all callers to pass `MaxDownloadSize`. Then the test can pass its own value without mutating global state, and add `t.Parallel()`.

If keeping the package var, just ensure the test is clearly documented:
```go
func TestDownloadToTemp_SizeLimit(t *testing.T) {
	// Not parallel: mutates package-level MaxDownloadSize.
	// See finding #42 — would need a parameter refactor to parallelize.
```

**Step 4: Run tests**

Run: `go test ./internal/feed/ -v -count=1`
Expected: All tests pass.

**Step 5: Commit**

```
fix: make DownloadToTemp size limit testable without global mutation

[Description depends on which option was chosen]
Fixes health review finding #42.
```

---

## Task 1.10: Validate InCISAKEV boolean query parameter (Finding 35)

**Finding:** `?in_cisa_kev=yes` silently treated as false. No validation.

**Files:**
- Modify: `internal/api/cves.go` (~line 263)
- Test: `internal/api/cves_test.go` (if it exists) or verify via build

**Step 1: Read the file**

Read `internal/api/cves.go` and find the InCISAKEV handling. Current code:
```go
if i.InCISAKEV != "" {
    b := strings.EqualFold(i.InCISAKEV, "true")
    i.inCISAKEVBool = &b
}
```

**Step 2: Determine if this is a huma handler or chi handler**

This is in `cves.go` which uses huma. Check how the query parameter is defined in the huma input struct. If it's defined as a `string` field with a huma tag, we can add validation.

**Step 3: Add validation**

Replace the current code with:
```go
if i.InCISAKEV != "" {
    switch strings.ToLower(i.InCISAKEV) {
    case "true":
        b := true
        i.inCISAKEVBool = &b
    case "false":
        b := false
        i.inCISAKEVBool = &b
    default:
        return nil, huma.Error400BadRequest("in_cisa_kev must be 'true' or 'false'")
    }
}
```

**IMPORTANT:** Check the handler's return signature to make sure returning an error this way is correct for the huma handler pattern used here. Look at how other validation errors are returned in the same handler.

**Step 4: Run tests**

Run: `go test ./internal/api/ -run TestCVE -v -count=1` (or whatever test pattern exists for CVE endpoints)
Expected: Existing tests pass. No test should have been passing `?in_cisa_kev=yes`.

**Step 5: Commit**

```
fix: validate in_cisa_kev query parameter accepts only true/false

Returns 400 for invalid boolean values instead of silently treating
them as false. Fixes health review finding #35.
```

---

## Task 1.11: Add sqlc rename for Cfe → CVE type (Finding 27)

**Finding:** sqlc inflects `cves` table name to `Cfe` — confusing for contributors.

**Files:**
- Modify: `sqlc.yaml`
- Regenerate: `sqlc generate`
- Modify: All files that reference `generated.Cfe` (will need find-and-replace)

**⚠️ SUBAGENT WARNING:** This task has a large blast radius. Every file that imports `generated.Cfe` will need to be updated. Do a thorough search before committing.

**Step 1: Read sqlc.yaml**

Read `sqlc.yaml` and understand the current structure.

**Step 2: Add rename directive**

Add a `rename` section to the sqlc config. The exact syntax depends on the sqlc version. For sqlc v2:

```yaml
sql:
  - engine: "postgresql"
    queries: "internal/store/queries/"
    schema: "migrations/"
    gen:
      go:
        package: "store"
        out: "internal/store/generated"
        rename:
          cfe: CVE
          cves: CVEs
        overrides:
          # ... existing overrides ...
```

**IMPORTANT:** Check the sqlc docs for the exact rename syntax for v2. The `rename` key maps the *generated* Go name to the desired name. You may need:
```yaml
rename:
  cfe: "CVE"
```
or it might need to be under `go:` directly. Read the sqlc config reference.

**Step 3: Regenerate**

Run: `sqlc generate`
Expected: `internal/store/generated/models.go` now has `type CVE struct` instead of `type Cfe struct`.

**Step 4: Update all references**

Search the entire codebase for `generated.Cfe` and replace with `generated.CVE`. Also search for `[]generated.Cfe` and `*generated.Cfe`.

Run: `grep -r "generated\.Cfe" --include="*.go" -l` to find all files.

**Step 5: Verify**

Run: `go build ./...`
Expected: Clean build.

Run: `go test ./internal/store/ -count=1 -timeout 120s`
Expected: Tests pass.

**Step 6: Commit**

```
chore: rename sqlc-generated Cfe type to CVE

Adds rename directive to sqlc.yaml so the cves table generates
as CVE instead of the confusing Cfe inflection. Updates all
references across the codebase. Fixes finding #27.
```

---

## Task 1.12: Deduplicate toNullString helpers (Finding 28)

**Finding:** Three packages have their own `toNullString` / `nullString` implementations.

**Files:**
- Create: `internal/dbutil/null.go`
- Modify: `internal/merge/pipeline.go` (~line 298)
- Modify: `internal/store/ai.go` (~line 239)
- Modify: `internal/store/watchlist.go` (~line 311)

**Step 1: Read all three implementations**

Read the helpers in all three files. Note the differences:
- `merge/pipeline.go:298`: `toNullString(s string) sql.NullString` — value-based
- `store/ai.go:240`: `toNullString(v string) sql.NullString` — identical to above
- `store/watchlist.go:312`: `nullString(s *string) sql.NullString` — pointer-based

Also note `merge/pipeline.go` has additional helpers: `toNullStringPtr`, `toNullFloat64`, `toNullTimePtr`, `toNullRawMessage`, `derefString`. And `store/ai.go` has `toNullInt32`.

**Step 2: Create shared package**

Create `internal/dbutil/null.go`:

```go
// ABOUTME: Shared database/sql nullable type conversion helpers.
// ABOUTME: Eliminates duplication across store, merge, and other packages.
package dbutil

import (
	"database/sql"
)

// NullString converts a string to sql.NullString; empty string maps to NULL.
func NullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// NullStringPtr converts a *string to sql.NullString; nil maps to NULL.
func NullStringPtr(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}
```

**IMPORTANT:** Only extract the helpers that are actually duplicated (the two `toNullString` variants). Do NOT move `toNullFloat64`, `toNullTimePtr`, etc. — those are only used in one package and moving them gains nothing. YAGNI.

**Step 3: Update callers**

In `internal/merge/pipeline.go`:
- Replace calls to `toNullString(x)` with `dbutil.NullString(x)`
- Replace calls to `toNullStringPtr(x)` with `dbutil.NullStringPtr(x)`
- Delete the local `toNullString` and `toNullStringPtr` functions
- Keep `toNullFloat64`, `toNullTimePtr`, `toNullRawMessage`, `derefString` — they're unique to this package

In `internal/store/ai.go`:
- Replace calls to `toNullString(x)` with `dbutil.NullString(x)`
- Delete the local `toNullString` function
- Keep `toNullInt32` — unique to this file

In `internal/store/watchlist.go`:
- Replace calls to `nullString(x)` with `dbutil.NullStringPtr(x)`
- Delete the local `nullString` function

**Step 4: Verify**

Run: `go build ./...`
Expected: Clean build.

Run: `go test ./internal/merge/ ./internal/store/ -count=1 -timeout 120s`
Expected: Tests pass.

**Step 5: Commit**

```
refactor: extract shared NullString helpers to internal/dbutil

Consolidates three identical toNullString/nullString implementations
from merge, store/ai, and store/watchlist into dbutil.NullString and
dbutil.NullStringPtr. Fixes health review finding #28.
```

---

# Phase 2: Critical Fixes

## Phase 2A: RLS Security Fix (Finding 2)

---

## Task 2A.1: Enable the restricted database role for the app service

**Finding:** The app connects as the database superuser, completely bypassing RLS.

**Files:**
- Modify: `docker/init.sql` (~line 19)
- Modify: `docker/compose.yml` (~lines 136-137)
- Modify: `.env` or `.env.example` (if it exists — add APP_DB_PASSWORD)

**⚠️ SUBAGENT WARNING:** This is a security-critical change. Do NOT modify the migrate service's connection — it must remain as superuser to run DDL. Only change the app service.

**Step 1: Read the files**

Read `docker/init.sql` and `docker/compose.yml` to understand the current setup.

**Step 2: Uncomment and set the app role password in init.sql**

Find the commented-out line (~line 19):
```sql
-- ALTER ROLE cvert_ops_app WITH PASSWORD 'changeme';
```

Replace with:
```sql
ALTER ROLE cvert_ops_app WITH PASSWORD :'app_password';
```

Wait — this uses psql variable interpolation which may not work in init scripts. Instead, use a fixed default for dev:
```sql
ALTER ROLE cvert_ops_app WITH LOGIN PASSWORD 'cvert_ops_app_dev';
```

Also verify that `cvert_ops_app` has been granted the necessary permissions. Check the existing GRANT statements in init.sql — the role needs:
- `USAGE` on the schema
- `SELECT, INSERT, UPDATE, DELETE` on all tables
- `USAGE, SELECT` on all sequences
- These GRANTs must be set as DEFAULT PRIVILEGES so new migration-created tables are also accessible

**Step 3: Update compose.yml app service DATABASE_URL**

Find the app service's DATABASE_URL (~line 136). Change from:
```yaml
DATABASE_URL: "postgresql://${POSTGRES_USER:-cvert_ops}:${POSTGRES_PASSWORD}@postgres:5432/..."
```
to:
```yaml
DATABASE_URL: "postgresql://cvert_ops_app:${APP_DB_PASSWORD:-cvert_ops_app_dev}@postgres:5432/..."
```

**CRITICAL:** Do NOT change the migrate service's DATABASE_URL. It must remain as the superuser to execute DDL (CREATE TABLE, ALTER TABLE, etc.).

**Step 4: Test locally**

```bash
docker compose -f docker/compose.yml --env-file .env down -v
docker compose -f docker/compose.yml --env-file .env up -d
# Wait for Postgres to initialize
go run ./cmd/cvert-ops migrate
go run ./cmd/cvert-ops serve
```

Verify the app starts and can query the database. If you get permission errors, the GRANT statements in init.sql need to be expanded.

**Step 5: Commit**

```
security: connect app as restricted cvert_ops_app role, not superuser

Enables the RLS defense-in-depth layer by having the application
connect as cvert_ops_app (NOBYPASSRLS) instead of the database
superuser. Migration service retains superuser for DDL operations.
Fixes health review finding #2.
```

---

## Task 2A.2: Write an integration test proving RLS blocks cross-tenant access

**Files:**
- Create: `internal/store/rls_test.go`

**Step 1: Write the test**

This test must prove that when `app.org_id` is set to Org A, a query against Org B's data returns zero rows (not an error — RLS silently filters).

```go
func TestRLS_CrossTenantBlocked(t *testing.T) {
	// Skip if no test DB
	s := testutil.NewTestStore(t) // or whatever the test helper is

	ctx := context.Background()

	// Create two orgs
	org1, err := s.CreateOrg(ctx, "RLS Test Org 1")
	require.NoError(t, err)
	org2, err := s.CreateOrg(ctx, "RLS Test Org 2")
	require.NoError(t, err)

	// Create a watchlist in org1 (using org1's transaction context)
	// ... create via store method that uses withOrgTx ...

	// Query org2's watchlists — should return empty, not org1's data
	// ... query via store method with org2's ID ...
	// assert len(result) == 0
}
```

**IMPORTANT:** This test must use the actual store methods (not raw SQL) to prove the full RLS path works. Read existing store test patterns in `internal/store/` to match the helper setup.

**Step 2: Run test**

Run: `go test ./internal/store/ -run TestRLS -v -count=1`
Expected: PASS — RLS should already be working at the application level (the store always sets `app.org_id`). This test documents that guarantee.

**Step 3: Commit**

```
test: add RLS cross-tenant isolation integration test

Proves that org-scoped queries with one org's context cannot see
another org's data. Complements finding #2 RLS fix.
```

---

## Phase 2B: Alert Evaluator Refactoring (Findings 20, 21, 30)

These tasks clean up the evaluator internals BEFORE wiring it into the runtime (Phase 2C).

---

## Task 2B.1: Extract shared post-filter logic (Finding 20)

**Finding:** `applyPostFilters` in evaluator.go and `applyDSLPostFilters` in dsl_executor.go are 98% identical.

**⚠️ Phase 8B interaction:** Phase 8B Observe may have added metric instrumentation near `applyPostFilters` in the evaluator. After extracting the shared function, verify that any metric calls still fire correctly. If 8B instruments at the call site (not inside the function), no change is needed. If 8B instruments inside `applyPostFilters`, move the instrumentation to the new shared function or the call site.

**Files:**
- Create: `internal/alert/dsl/postfilter.go`
- Modify: `internal/alert/evaluator.go` (~lines 525-576)
- Modify: `internal/store/dsl_executor.go` (~lines 235-283)

**Step 1: Read both implementations**

Read the two functions side by side. The only difference is the input type and the field accessor:
- Evaluator: `[]cveSummary` with `c.CVEID` and `c.Description`
- DSL executor: `[]generated.Cfe` with `c.CveID` and `c.DescriptionPrimary.String`

**Step 2: Write the failing test first**

Create a test in `internal/alert/dsl/postfilter_test.go` that tests the generic filter function with simple string-based targets:

```go
func TestApplyPostFilters(t *testing.T) {
	// Test AND logic: all filters must match
	// Test OR logic: any filter can match
	// Test negate
	// Test cve_id field targeting
	// Test description field targeting (default)
	// Test empty filter list returns all candidates
}
```

**Step 3: Implement the generic filter**

In `internal/alert/dsl/postfilter.go`, create a generic function:

```go
// PostFilterTarget provides field values for post-filter matching.
type PostFilterTarget interface {
	PostFilterField(field string) string
}

// ApplyPostFilters filters candidates using regex post-filters with AND/OR logic.
func ApplyPostFilters[T PostFilterTarget](candidates []T, filters []PostFilter, logic Logic) []T {
	if len(filters) == 0 {
		return candidates
	}
	var matched []T
	for _, c := range candidates {
		if matchesPostFilters(c, filters, logic) {
			matched = append(matched, c)
		}
	}
	return matched
}

func matchesPostFilters[T PostFilterTarget](c T, filters []PostFilter, logic Logic) bool {
	for _, f := range filters {
		ok := f.Pattern.MatchString(c.PostFilterField(f.Field))
		if f.Negate {
			ok = !ok
		}
		if logic == LogicOr && ok {
			return true
		}
		if logic == LogicAnd && !ok {
			return false
		}
	}
	return logic == LogicAnd // AND: all passed; OR: none matched
}
```

**Step 4: Add PostFilterTarget implementations**

In `internal/alert/evaluator.go`, add to `cveSummary`:
```go
func (c cveSummary) PostFilterField(field string) string {
	if field == "cve_id" {
		return c.CVEID
	}
	return c.Description
}
```

In `internal/store/dsl_executor.go`, add a wrapper or implement on a local type that wraps `generated.Cfe`.

**Step 5: Replace both implementations**

Replace `applyPostFilters` in evaluator.go with a call to `dsl.ApplyPostFilters`.
Replace `applyDSLPostFilters` in dsl_executor.go with a call to `dsl.ApplyPostFilters`.
Delete both old implementations and their helper functions.

**Step 6: Run tests**

Run: `go test ./internal/alert/... ./internal/store/ -count=1 -timeout 120s`
Expected: All tests pass.

**Step 7: Commit**

```
refactor: extract shared post-filter logic to dsl.ApplyPostFilters

Eliminates duplicate regex filter implementations between the alert
evaluator and DSL executor. Both now call a single generic function.
Fixes health review finding #20.
```

---

## Task 2B.2: Merge queryCandidates and queryCandidatesAll (Finding 21)

**Finding:** Two ~90-line methods differ only by an optional `WHERE cve_id = ANY(?)` clause.

**⚠️ Phase 8B interaction:** Same as Task 2B.1 — check if 8B Observe added metric instrumentation in either `queryCandidates` or `queryCandidatesAll`. After merging, ensure metrics are preserved in the unified method.

**Files:**
- Modify: `internal/alert/evaluator.go` (~lines 425-523)

**Step 1: Read both methods**

Confirm they're identical except for the candidate ID filter.

**Step 2: Merge into one method**

Replace both with a single method:
```go
// queryCandidates runs the compiled SQL query against CVEs. If candidateIDs is
// non-nil, only those CVE IDs are considered; otherwise all CVEs are scanned.
// Returns (matches, capExceeded, error).
func (e *Evaluator) queryCandidates(ctx context.Context, tx *sql.Tx, compiled *dsl.CompiledRule, candidateIDs []string) ([]cveSummary, bool, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	combined := sq.And{
		compiled.SQL,
		sq.Expr("lower(cves.status) NOT IN ('rejected', 'withdrawn')"),
	}
	if len(candidateIDs) > 0 {
		combined = append(combined, sq.Expr("cves.cve_id = ANY(?)", pq.Array(candidateIDs)))
	}
	// ... rest of the shared implementation ...
}
```

**Step 3: Update all callers**

Find where `queryCandidatesAll` was called (should be in `DryRun` and possibly `EvaluateBatch`/`EvaluateEPSS`). Replace with `queryCandidates(ctx, tx, compiled, nil)`.

Find where `queryCandidates` was called with explicit IDs. It should already work with the new signature.

Delete the old `queryCandidatesAll` method entirely.

**Step 4: Run tests**

Run: `go test ./internal/alert/ -v -count=1`
Expected: All tests pass.

**Step 5: Commit**

```
refactor: merge queryCandidates and queryCandidatesAll

Consolidates two near-identical ~90-line methods into one with an
optional candidateIDs parameter. nil = scan all CVEs.
Fixes health review finding #21.
```

---

## Phase 2C: Wire Alert Evaluation into Runtime (Finding 1)

**This is the most critical finding — the product's core feature is dead code.**

---

## Task 2C.1: Register batch and EPSS evaluation as scheduled worker jobs

**Finding:** `EvaluateBatch` and `EvaluateEPSS` are never called. No scheduler entries exist for them.

**Files:**
- Modify: `internal/ingest/scheduler.go` — add schedule entries for alert evaluation
- Modify: `cmd/cvert-ops/main.go` — register worker handlers for the new job types

**⚠️ SUBAGENT WARNING:** Read the existing scheduler and worker registration patterns carefully. The scheduler enqueues jobs into the `job_queue` table; the worker pool picks them up. You need BOTH: a scheduler entry to periodically enqueue, AND a worker handler to execute.

**Step 1: Read existing patterns**

Read `internal/ingest/scheduler.go` to understand how `feed_ingest` jobs are scheduled. Read `cmd/cvert-ops/main.go` to see how worker handlers are registered (look for `workerPool.Register`).

**Step 2: Write a test for the new handler**

In `cmd/cvert-ops/` or a new test file, write a test that verifies the batch alert handler calls `EvaluateBatch` when invoked by the worker pool. This may require a test double for the evaluator.

**Step 3: Add scheduler entries**

In the scheduler's default schedule (or wherever feed schedules are defined), add entries for:
- `alert_batch` — runs every 1-2 minutes (same cadence as feed ingest)
- `alert_epss` — runs every 24 hours (EPSS updates daily)
- `alert_zombie_sweep` — runs every 5 minutes (cleanup stuck activations)

**Step 4: Register worker handlers in main.go**

In both `runServe` and `runWorker`, register handlers:
```go
workerPool.Register("alert_batch", func(ctx context.Context, _ json.RawMessage) error {
    return alertEval.EvaluateBatch(ctx)
})
workerPool.Register("alert_epss", func(ctx context.Context, _ json.RawMessage) error {
    return alertEval.EvaluateEPSS(ctx)
})
workerPool.Register("alert_zombie_sweep", func(ctx context.Context, _ json.RawMessage) error {
    return alertEval.SweepZombieActivations(ctx)
})
```

**IMPORTANT:** Check the worker handler signature — it might be `func(ctx, payload) error` or similar. Match the existing pattern exactly.

**Step 5: Run tests**

Run: `go build ./cmd/cvert-ops/ && go test ./internal/ingest/ -count=1`
Expected: Builds clean. Existing tests pass.

**Step 6: Commit**

```
feat: wire alert batch, EPSS, and zombie sweep into worker scheduler

Registers EvaluateBatch, EvaluateEPSS, and SweepZombieActivations
as scheduled worker jobs. Batch runs every 2 minutes, EPSS daily,
zombie sweep every 5 minutes. Fixes finding #1 (partial — realtime
path in next commit).
```

---

## Task 2C.2: Wire EvaluateRealtime as post-merge hook

**Finding:** When a CVE's material_hash changes after merge, EvaluateRealtime should fire.

**Files:**
- Modify: `internal/ingest/handler.go` — call EvaluateRealtime after successful merge
- OR: Modify `internal/merge/pipeline.go` — add a post-merge callback

**⚠️ SUBAGENT WARNING:** The realtime evaluation must happen AFTER the merge transaction commits (the CVE data must be visible to the evaluator's separate transaction). Do NOT call EvaluateRealtime inside the merge transaction.

**Step 1: Read the merge and ingest flow**

Read `internal/ingest/handler.go` to understand the flow:
1. Adapter fetches patches
2. For each patch, `mergeFn` is called
3. If merge succeeds and material_hash changed, we need to trigger realtime evaluation

Read `internal/merge/pipeline.go` to understand what `Ingest` returns — does it indicate whether material_hash changed?

**Step 2: Determine the integration point**

If `merge.Ingest` returns whether the material_hash changed (or the CVE ID of modified CVEs), the handler can collect those IDs and call `EvaluateRealtime` after the loop.

If `merge.Ingest` doesn't return this information, you may need to modify it to return a result struct:
```go
type IngestResult struct {
    MaterialHashChanged bool
}
```

**Step 3: Wire the call**

In the ingest handler, after each successful merge where material_hash changed:
```go
if result.MaterialHashChanged {
    if err := alertEval.EvaluateRealtime(ctx, patch.CVEID); err != nil {
        log.Error("realtime alert evaluation failed", "cve_id", patch.CVEID, "error", err)
        // Don't fail the ingest — alert evaluation failure shouldn't block feed ingestion
    }
}
```

**IMPORTANT:** Alert evaluation failures must NOT fail the feed ingest. Log the error and continue. Feed data integrity is more important than alert timeliness.

**Step 4: Write a test**

Test that the ingest handler calls EvaluateRealtime when material_hash changes and does NOT call it when it doesn't change.

**Step 5: Run tests**

Run: `go test ./internal/ingest/ -v -count=1`
Expected: All tests pass.

**Step 6: Commit**

```
feat: trigger realtime alert evaluation on material_hash change

After a successful CVE merge where material_hash changed, the ingest
handler calls EvaluateRealtime for that CVE ID. Evaluation failures
are logged but don't block ingestion. Completes finding #1.
```

---

# Phase 3: Chi→Huma Migration (Outlined)

**Findings addressed:** 6, 7, 8, 9, 31, 32, 33, 34, 43

**This phase needs its own detailed plan.** It's the largest single body of work and affects every org-scoped endpoint. Key decisions to make before writing the detailed plan:

### Migration strategy

1. **One handler file at a time.** Each file (watchlists.go, channels.go, etc.) is a self-contained migration unit. Complete one, verify it works (build + test + frontend smoke test), commit, then move to the next.

2. **Consistent response shapes.** All list endpoints migrate from bare arrays to `{"items": [...], "next_cursor": "..."}` simultaneously with the huma migration. This is a breaking frontend change — the frontend must be updated for each migrated endpoint.

3. **Standardize pagination.** As each endpoint migrates, adopt the standard cursor pattern: `?cursor=` with base64 JSON `{"d":"...","id":"..."}`. Document the pattern once, apply everywhere.

4. **Frontend updates are part of each handler migration.** Don't migrate all handlers and then fix the frontend. Each handler migration includes updating the corresponding Pinia store/composable to use the typed openapi-fetch client instead of orgFetch.

### Subagent risks for this phase

- **RBAC middleware composition:** Chi handlers currently use `r.With(requireRole("admin"))` inline. Huma uses middleware differently — need to figure out the huma-compatible RBAC pattern ONCE and document it as the reference.
- **OrgID extraction:** Chi handlers use `chi.URLParam(r, "org_id")`. Huma extracts from path params in the input struct. Every handler migration must change this.
- **Request body parsing:** Chi handlers manually decode JSON. Huma does automatic validation from struct tags. The migration changes validation behavior — some currently-accepted inputs may be rejected.
- **Error codes:** Migrated handlers will return RFC 9457 errors (good), but also need consistent status codes (400 vs 422 — decide once, apply everywhere).
- **Frontend breakage:** Each migrated endpoint changes the response shape. The frontend MUST be updated in the same commit or the app breaks.

### Recommended handler migration order

1. **Groups** (simplest, fewest endpoints, low traffic)
2. **Saved searches** (similar simplicity)
3. **API keys** (simple CRUD)
4. **Channels** (medium complexity)
5. **Watchlists** (medium complexity, has pagination)
6. **Alert rules** (complex, has activation flow)
7. **Deliveries** (has broken cursor — fix during migration)
8. **Reports** (has scheduled delivery)
9. **Orgs** (has bootstrap, tier limits)
10. **Members/Invitations** (tied to org management)
11. **Audit log** (read-only, simple)
12. **Admin endpoints** (added by Phase 8C Operate — org/user/feed/delivery/system admin)
13. **Feeds admin** (added by Phase 8C Operate — pause/resume/logs)

### Reference pattern

Write one complete before/after migration (Groups) with:
- Full huma operation registration
- Huma input/output structs with validation tags
- RBAC middleware in huma context
- Standard pagination cursor
- Standard error responses
- Frontend store update

Then every subsequent migration follows this reference.

---

# Phase 4: Ops Hardening (Reduced Scope)

**Findings addressed:** 14, 44

Tasks 4A (health/readiness), 4B (metrics), and 4C (runServe/runWorker dedup) have been removed or moved:
- **4A/4B:** Resolved by Phase 8B Observe and 8C Operate (merged before this plan executes).
- **4C:** Moved to Phase 6 — Phase 8 adds significant code to both runServe/runWorker, making the refactoring more valuable but also more complex post-merge.

### Task 4D: Notification worker semaphore eviction (Finding 14)

- Add a periodic cleanup goroutine that removes semaphores not used in the last 10 minutes
- Track last-used timestamp per entry
- Small change, low risk

### Task 4E: Configurable statement timeout (Finding 44)

- Allow per-operation timeout override via context
- Or add a separate config for "long operations" timeout
- Applied to activation scans, bulk DSL queries, merge operations

---

# Phase 5: Test Quality (Outlined)

**Findings addressed:** 22, 23, 24, 36

### Task 5A: Feed adapter golden file tests (Finding 23)

- Capture real responses from NVD, GHSA, OSV, KEV, EPSS APIs
- Save as `internal/feed/<adapter>/testdata/<feed>_response.json`
- Write tests that parse the golden file and verify the produced `CanonicalPatch` output
- This catches upstream API format changes

### Task 5B: Ingest handler integration test (Finding 22)

- Write one test that uses the real merge function and a test database
- Verifies data actually reaches the DB after handler processing
- Replaces or supplements the mock-based tests

### Task 5C: Email testcontainer test (Finding 24)

- Use Inbucket testcontainer (pattern from recent commit f253dc2)
- Replace Mailpit skip-if-unavailable with testcontainer startup
- Update header injection test to query Inbucket API and verify Bcc was stripped

### Task 5D: Advisory lock concurrency test (Finding 36)

- Use two goroutines that attempt concurrent merge of the same CVE ID
- Verify both complete without data corruption
- Use `pg_advisory_xact_lock` visibility to prove serialization

---

# Phase 6: Architecture (Outlined — Defer)

**Findings addressed:** 15, 16, 17, 19, 25, 39

These are structural improvements that benefit from the earlier phases being stable. Phase 8 merge makes some of these more impactful (more code to factor out) but also more complex.

### Task 6A: Replace Set*Deps with options struct (Finding 15, partial)

- Replace `SetAlertDeps`, `SetAIDeps`, `SetAuditDeps` with a single `ServerDeps` struct passed to `NewServer`
- Validates all required deps at construction time
- Eliminates temporal coupling
- **Post-Phase 8 note:** Phase 8C Operate adds more dependencies (doctor, admin routes). Include these in the options struct.

### Task 6B: Unify or instrument notification worker (Finding 16)

- Either migrate notification delivery to the generic worker pool
- Or add equivalent health check + metrics to the notification worker
- **Post-Phase 8 note:** Phase 8B Observe already adds notification delivery metrics. The remaining gap is health check integration — the notification worker should report readiness to the `/readyz` endpoint added by Phase 8C.

### Task 6C: Extract shared app setup from runServe/runWorker (Finding 17)

- Create `buildApp() (*App, error)` that returns a struct with all wired dependencies
- `runServe` calls `buildApp()` then adds HTTP server
- `runWorker` calls `buildApp()` then runs worker pool directly
- **Post-Phase 8 note:** Previously Task 4C. Moved here because Phase 8B/8C/8D all add code to both functions (metrics port, auto-migrate, generic feed loading), making the duplication worse but the refactoring scope larger. Best done after Phase 3 (chi→huma) is also complete so the API server setup is stable.

### Task 6D: ~~Implement import-bulk for NVD~~ — INVALIDATED (Finding 19)

**Finding 19 is invalid.** NVD does not offer bulk download files. Their [developer documentation](https://nvd.nist.gov/developers/start-here) explicitly recommends iterative API calls with `startIndex` pagination for initial data population. The existing `import-bulk` command accepts a local file, which is valid for offline/airgapped scenarios, but there are no NVD bulk archives to feed it.

No action needed. If initial population performance becomes a concern, the NVD feed adapter's normal sync (with parallelized paginated API calls) is the correct approach — not a separate bulk import path.

### Task 6E: Extract MergeStore interface (Finding 25)

- Define a `MergeStore` interface in `internal/merge/` with the methods the pipeline actually calls
- `*store.Store` already implements these methods
- Enables future testing with fake store

### Task 6F: Refactor BootstrapFirstUserOrg to use withBypassTx (Finding 39)

- Restructure to use the defer-based transaction helper
- Move advisory lock logic into the callback
- Reduces error-prone manual rollback paths

---

## Appendix: Finding → Task Cross-Reference

| Finding | Description | Task | Phase | Notes |
|---------|-------------|------|-------|-------|
| 1 | Alert paths not wired | 2C.1, 2C.2 | 2C | 8B Observe alert metrics activate once wired |
| 2 | RLS bypass | 2A.1, 2A.2 | 2A | 8C/8E doctor checks validate the fix |
| 3 | No health check | — | — | **RESOLVED by Phase 8C Operate** |
| 4 | Server.Close not called | 1.1 | 1 | |
| 5 | sql.DB not closed | 1.2 | 1 | |
| 6 | Inconsistent error format | Phase 3 | 3 | Include 8C admin endpoints |
| 7 | Inconsistent list shapes | Phase 3 | 3 | |
| 8 | Dual API client | Phase 3 | 3 | |
| 9 | Inconsistent pagination | Phase 3 | 3 | |
| 10 | No metrics | — | — | **RESOLVED by Phase 8B Observe** |
| 11 | Registration mode default | — | — | **RESOLVED** (already correct) |
| 12 | Cookie secure validation | 1.3 | 1 | |
| 13 | Worker context cancellation | 1.4 | 1 | |
| 14 | Semaphore map unbounded | 4D | 4 | |
| 15 | API monolith | 6A | 6 | Include 8C deps in options struct |
| 16 | Dual worker systems | 6B | 6 | 8B adds notify metrics; readiness gap remains |
| 17 | runServe/runWorker duplication | 6C | 6 | Moved from Phase 4; worse post-8 but more complete |
| 18 | CVE endpoints unauthenticated | — | — | Tracked separately |
| 19 | import-bulk stub | ~~6D~~ | — | **INVALIDATED** — NVD has no bulk download files; API pagination is the correct approach |
| 20 | Duplicated post-filters | 2B.1 | 2B | May shift 8B metric instrumentation points |
| 21 | queryCandidates duplication | 2B.2 | 2B | May shift 8B metric instrumentation points |
| 22 | Ingest handler mock tests | 5B | 5 | |
| 23 | No golden file tests | 5A | 5 | Also applies to 8D generic adapter |
| 24 | Email test skips | 5C | 5 | |
| 25 | Store concrete struct | 6E | 6 | |
| 26 | Dead readTx method | 1.5 | 1 | |
| 27 | sqlc Cfe type name | 1.11 | 1 | |
| 28 | Duplicated toNullString | 1.12 | 1 | |
| 29 | SMTP error string matching | — | — | Low priority, monitor |
| 30 | Evaluator mixes DB patterns | 2B | 2B | Addressed implicitly by 2B.1/2B.2 |
| 31 | No Location header on 201 | Phase 3 | 3 | |
| 32 | PATCH non-pointer fields | Phase 3 | 3 | |
| 33 | Inconsistent validation codes | Phase 3 | 3 | |
| 34 | Tier limit 403 | Phase 3 | 3 | |
| 35 | InCISAKEV boolean filter | 1.10 | 1 | |
| 36 | Advisory lock test | 5D | 5 | |
| 37 | Store tests discard errors | 1.8 | 1 | |
| 38 | No readiness probe | — | — | **RESOLVED by Phase 8C Operate** |
| 39 | Bootstrap manual tx | 6F | 6 | |
| 40 | Misleading comment | 1.6 | 1 | |
| 41 | Test with no assertion | 1.7 | 1 | |
| 42 | Test mutates package state | 1.9 | 1 | |
| 43 | Delivery cursor unusable | Phase 3 | 3 | |
| 44 | Statement timeout | 4E | 4 | |
| 45 | Schema version manual sync | — | — | Reduced impact by 8C auto-migrate |
