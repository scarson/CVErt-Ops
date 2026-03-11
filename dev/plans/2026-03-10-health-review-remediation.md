# Health Review Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address all 45 findings from the 2026-03-10 project health review, organized into 6 phases by dependency and risk.

**Architecture:** Findings are grouped by root cause and dependency order. All 6 phases are fully detailed with exact code, files, test commands, and commit messages.

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
	tdb := testutil.NewTestDB(t)

	ctx := context.Background()

	// Create two orgs
	org1, err := tdb.CreateOrg(ctx, "RLS Test Org 1")
	require.NoError(t, err)
	org2, err := tdb.CreateOrg(ctx, "RLS Test Org 2")
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
- DSL executor: `[]generated.CVE` with `c.CveID` and `c.DescriptionPrimary.String` (type was renamed from `Cfe` to `CVE` by Task 1.11)

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

In `internal/store/dsl_executor.go`, add a wrapper or implement on a local type that wraps `generated.CVE` (renamed from `Cfe` by Task 1.11).

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

# Phase 3: Chi→Huma Migration

**Findings addressed:** 6, 7, 8, 9, 31, 32, 33, 34, 43

This is the largest single body of work. It migrates all chi-registered org-scoped handlers to huma, which simultaneously fixes:
- Inconsistent error formats (Finding 6: text/plain → RFC 9457)
- Inconsistent list shapes (Finding 7: bare arrays → `{"items": [...]}`)
- Dual API client (Finding 8: orgFetch eliminated, typed client for everything)
- Inconsistent pagination (Finding 9: one `?cursor=` pattern everywhere)
- Missing Location headers (Finding 31: huma can set these automatically)
- Non-pointer PATCH fields (Finding 32: pointer types in input structs)
- Inconsistent validation codes (Finding 33: huma standardizes to 422)
- Tier limit 403 (Finding 34: distinct error type in RFC 9457 body)
- Broken delivery cursor (Finding 43: standardized cursor encoding)

---

## Key Decisions (Locked In — Not Negotiable)

These decisions apply to ALL handler migrations. Do NOT deviate per-handler.

### 1. RBAC Pattern

Chi middleware continues to run before huma handlers (chi is the underlying router). The existing `RequireOrgRole` middleware is unchanged — it validates org membership and injects `ctxOrgID` and `ctxRole` into the request context.

Huma handlers access the org ID via the Input struct's path param (`OrgID uuid.UUID \`path:"org_id"\``), which huma parses automatically. The middleware-validated value and the huma-parsed value are the same (both come from the URL). Use `input.OrgID` in handler bodies.

If a handler needs the caller's role (e.g., to check admin), read from context:
```go
role := ctx.Value(ctxRole).(Role)
```

**Do NOT rewrite the RBAC middleware.** It works. Leave it as chi middleware.

### 2. Route Registration

Huma operations are registered inside a `registerXxxRoutes(api huma.API, s *store.Store)` function per handler file, following the existing `registerCVERoutes` and `registerAuthRoutes` pattern. These are called from `NewServer` after `humachi.New(apiRouter, humaConfig)`.

RBAC enforcement moves from `r.With(srv.RequireOrgRole(RoleAdmin))` to the huma `Operation.Middlewares` field. Example:
```go
huma.Register(api, huma.Operation{
	OperationID: "create-group",
	Method:      http.MethodPost,
	Path:        "/orgs/{org_id}/groups",
	Tags:        []string{"Groups"},
	Middlewares: huma.Middlewares(srv.RequireOrgRole(RoleAdmin)),
}, createGroupHandler(s))
```

**⚠️ Critical:** Verify that `huma.Operation.Middlewares` accepts chi-style middleware (`func(http.Handler) http.Handler`). If huma has a different middleware type, read the huma docs for the adapter. The `humachi` adapter should bridge the types.

**⚠️ Critical:** Org-level middleware (`RequireOrgRole(RoleViewer)`, `tierMiddleware`, `orgRateLimitMiddleware`) currently applies to all sub-routes of `/{org_id}` via `r.Use()`. When migrating to huma, these must be applied per-operation or via a shared middleware group. Read how `humachi` handles route-level middleware.

### 3. Error Status Codes

| Scenario | Status Code | Huma Function |
|----------|-------------|---------------|
| Malformed request (bad JSON, invalid UUID) | 400 | `huma.Error400BadRequest` |
| Validation failure (name required, too long) | 422 | `huma.Error422UnprocessableEntity` |
| Authentication required | 401 | `huma.Error401Unauthorized` |
| Insufficient RBAC role | 403 | `huma.Error403Forbidden` |
| Tier limit exceeded | 403 | Custom: use `huma.NewError(403, "tier limit exceeded")` with `type: "urn:cvert-ops:error:tier-limit-exceeded"` |
| Not found | 404 | `huma.Error404NotFound` |
| Rate limited | 429 | `huma.Error429TooManyRequests` |
| Internal error | 500 | Return `fmt.Errorf(...)` (huma auto-converts to 500) |

**Tier limits vs RBAC:** Both return 403 but the tier limit error includes `"type": "urn:cvert-ops:error:tier-limit-exceeded"` in the RFC 9457 body. Frontend checks `error.type` to show "upgrade" CTA vs "insufficient permissions" message.

**⚠️ Important:** Huma auto-validates input structs. If a required field is missing, huma returns 422 automatically — you don't need to write manual validation for required fields. Only add custom validation for business rules (e.g., field length, format, cross-field constraints).

### 4. List Response Shape

ALL list endpoints return:
```json
{"items": [...], "next_cursor": "..."}
```

Huma output struct pattern:
```go
type ListGroupsOutput struct {
	Body struct {
		Items      []GroupItem `json:"items"`
		NextCursor string      `json:"next_cursor,omitempty"`
	}
}
```

For currently-unpaginated lists (groups, members, api-keys), add pagination with:
- Default limit: 25
- Max limit: 100
- Cursor: opaque base64 JSON (see next section)
- If the current data volume is small enough that pagination is unnecessary, still use the `{"items": [...]}` wrapper but omit `next_cursor`.

### 5. Pagination Cursor Standard

All paginated endpoints use the CVE cursor pattern:
```
?cursor=<base64url-raw JSON>
```

Cursor JSON structure:
```json
{"d": "<sort_value>", "id": "<uuid>"}
```

Where `d` is the sort column value (e.g., `created_at` timestamp) and `id` is the UUID tiebreaker. Encoding uses `base64.RawURLEncoding` (no padding).

For endpoints that are currently unpaginated but have small datasets, pagination can be deferred — just wrap in `{"items": [...]}` and omit `next_cursor`. Add a TODO comment noting pagination is needed when the dataset grows.

### 6. PATCH with Pointer Types

PATCH input structs use pointer fields for all optional updates:
```go
type UpdateGroupInput struct {
	OrgID   uuid.UUID `path:"org_id"`
	GroupID uuid.UUID `path:"group_id"`
	Body    struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
}
```

`nil` = field not provided (don't update). Empty string pointer = set to empty string. This allows clients to clear optional fields.

### 7. Location Header on 201

Huma supports `Header` fields in output structs:
```go
type CreateGroupOutput struct {
	Header struct {
		Location string `header:"Location"`
	}
	Body GroupItem
}
```

Set Location to the resource URL: `/api/v1/orgs/{org_id}/groups/{id}`

### 8. Frontend Migration Pattern

Each handler migration includes updating the corresponding frontend store/composable. The pattern:

**Before (chi):**
```typescript
const resp = await orgFetch(`/orgs/${orgId}/groups`)
const data = await resp.json() as GroupEntry[]
```

**After (huma — typed client):**
```typescript
const { data, error } = await client.GET('/orgs/{org_id}/groups', {
  params: { path: { org_id: orgId } }
})
// data.items is typed automatically from the OpenAPI schema
```

After migrating ALL handlers, `orgFetch.ts` should have zero callers and can be deleted.

---

## Task 3.0: Reference Migration — Groups (DO THIS FIRST)

**This is the reference implementation. All subsequent migrations copy this pattern.** Take extra care to get it right — every subsequent handler follows this exact structure.

**Files:**
- Rewrite: `internal/api/groups.go` (chi handlers → huma handlers)
- Modify: `internal/api/server.go` (change route registration)
- Create or modify: `web/src/stores/groups.ts` or equivalent (switch to typed client)
- Test: existing group tests + manual frontend smoke test

**Step 1: Read reference code**

Read these files to understand both patterns:
- `internal/api/groups.go` — the chi handlers to migrate (8 handlers, 315 lines)
- `internal/api/cves.go` — the existing huma handler pattern to follow
- `internal/api/server.go` lines ~195-205 — how huma API is created and routes registered
- `internal/api/server.go` lines ~397-411 — current chi route registration for groups

**Step 2: Define huma input/output structs**

Replace the chi-style request/response structs with huma input/output structs:

```go
// ── Input structs ─────────────────────────────────────────────────────────────

type CreateGroupInput struct {
	OrgID uuid.UUID `path:"org_id" doc:"Organization ID"`
	Body  struct {
		Name        string `json:"name" minLength:"1" doc:"Group name (required)"`
		Description string `json:"description,omitempty" doc:"Optional description"`
	}
}

type ListGroupsInput struct {
	OrgID uuid.UUID `path:"org_id" doc:"Organization ID"`
}

type GetGroupInput struct {
	OrgID   uuid.UUID `path:"org_id" doc:"Organization ID"`
	GroupID uuid.UUID `path:"group_id" doc:"Group ID"`
}

type UpdateGroupInput struct {
	OrgID   uuid.UUID `path:"org_id" doc:"Organization ID"`
	GroupID uuid.UUID `path:"group_id" doc:"Group ID"`
	Body    struct {
		Name        *string `json:"name,omitempty" doc:"Group name"`
		Description *string `json:"description,omitempty" doc:"Group description"`
	}
}

type DeleteGroupInput struct {
	OrgID   uuid.UUID `path:"org_id" doc:"Organization ID"`
	GroupID uuid.UUID `path:"group_id" doc:"Group ID"`
}

// ── Output structs ────────────────────────────────────────────────────────────

type GroupItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

type CreateGroupOutput struct {
	Header struct {
		Location string `header:"Location"`
	}
	Body GroupItem
}

type ListGroupsOutput struct {
	Body struct {
		Items []GroupItem `json:"items"`
	}
}

type GetGroupOutput struct {
	Body GroupItem
}

type UpdateGroupOutput struct {
	Body GroupItem
}
```

**⚠️ Important:** `minLength:"1"` on the Name field makes huma auto-reject empty names with a 422. This replaces the manual `if req.Name == ""` check. Verify huma supports `minLength` validation on string fields — read the huma docs.

**⚠️ Important — PATCH pointer types (Finding 32):** `UpdateGroupInput.Body` uses `*string` for both fields. This is the fix for Finding 32. The store's `UpdateGroup` method may need updating to accept pointer types and only update non-nil fields. Read the store method before changing the handler.

**Step 3: Write huma handler functions**

Huma handlers are closures (not Server methods) that capture dependencies:

```go
func createGroupHandler(s *store.Store) func(context.Context, *CreateGroupInput) (*CreateGroupOutput, error) {
	return func(ctx context.Context, input *CreateGroupInput) (*CreateGroupOutput, error) {
		group, err := s.CreateGroup(ctx, input.OrgID, input.Body.Name, input.Body.Description)
		if err != nil {
			slog.ErrorContext(ctx, "create group", "error", err)
			return nil, fmt.Errorf("create group: %w", err)
		}
		item := GroupItem{
			ID:          group.ID.String(),
			Name:        group.Name,
			Description: group.Description,
			CreatedAt:   group.CreatedAt.Format(time.RFC3339),
		}
		return &CreateGroupOutput{
			Header: struct{ Location string }{
				Location: fmt.Sprintf("/api/v1/orgs/%s/groups/%s", input.OrgID, group.ID),
			},
			Body: item,
		}, nil
	}
}

func listGroupsHandler(s *store.Store) func(context.Context, *ListGroupsInput) (*ListGroupsOutput, error) {
	return func(ctx context.Context, input *ListGroupsInput) (*ListGroupsOutput, error) {
		rows, err := s.ListOrgGroups(ctx, input.OrgID)
		if err != nil {
			slog.ErrorContext(ctx, "list groups", "error", err)
			return nil, fmt.Errorf("list groups: %w", err)
		}
		items := make([]GroupItem, 0, len(rows))
		for _, g := range rows {
			items = append(items, GroupItem{
				ID:          g.ID.String(),
				Name:        g.Name,
				Description: g.Description,
				CreatedAt:   g.CreatedAt.Format(time.RFC3339),
			})
		}
		return &ListGroupsOutput{Body: struct {
			Items []GroupItem `json:"items"`
		}{Items: items}}, nil
	}
}
```

Follow this pattern for all 8 handlers (create, list, get, update, delete, listMembers, addMember, removeMember).

**⚠️ Important — not found handling:** In the chi version, `getGroupHandler` checks `if group == nil` and returns 404. In huma, return `huma.Error404NotFound("group not found")`. Read the store method to understand how it signals "not found" — it may return `nil, nil` or a specific error.

**⚠️ Important — no-content responses:** For DELETE and add-member (which return 204), huma needs an empty output. Check huma docs for how to return 204 — it may be returning `nil, nil` or a specific empty output struct. The existing codebase's auth handlers may have an example.

**Step 4: Register huma routes**

Create a `registerGroupRoutes` function:

```go
func registerGroupRoutes(api huma.API, srv *Server, s *store.Store) {
	orgViewer := huma.Middlewares(
		srv.RequireOrgRole(RoleViewer),
		srv.tierMiddleware,
		srv.orgRateLimitMiddleware,
	)
	orgAdmin := huma.Middlewares(
		srv.RequireOrgRole(RoleAdmin),
		srv.tierMiddleware,
		srv.orgRateLimitMiddleware,
	)

	huma.Register(api, huma.Operation{
		OperationID: "list-groups",
		Method:      http.MethodGet,
		Path:        "/orgs/{org_id}/groups",
		Tags:        []string{"Groups"},
		Middlewares: orgViewer,
	}, listGroupsHandler(s))

	huma.Register(api, huma.Operation{
		OperationID: "create-group",
		Method:      http.MethodPost,
		Path:        "/orgs/{org_id}/groups",
		Tags:        []string{"Groups"},
		Middlewares: orgAdmin,
	}, createGroupHandler(s))

	// ... register all 8 operations
}
```

**⚠️ Critical — middleware type compatibility:** Verify that `huma.Middlewares()` accepts chi-style middleware functions (`func(http.Handler) http.Handler`). If it doesn't, read huma's middleware documentation for the correct way to apply chi middleware to huma operations. The `humachi` adapter may provide a bridge function.

**⚠️ Critical — route path:** Huma operations use full paths from the API root. The current chi routes are nested under `/orgs/{org_id}` with parent middleware. In huma, each operation declares its full path and its own middleware. Don't accidentally lose the org-level middleware (tier, rate limit) when migrating.

**Step 5: Remove chi route registrations**

In `server.go`, remove the chi route block for groups (lines ~397-411). Replace with a call to `registerGroupRoutes(api, srv, srv.store)` alongside the existing `registerCVERoutes` and `registerAuthRoutes` calls.

**Step 6: Update frontend**

Find the frontend file(s) that call group endpoints via `orgFetch`. Replace with typed `client` calls:

```typescript
// Before:
const resp = await orgFetch(`/orgs/${orgId}/groups`)
const groups = await resp.json() as GroupEntry[]

// After:
const { data, error } = await client.GET('/orgs/{org_id}/groups', {
  params: { path: { org_id: orgId } }
})
const groups = data?.items  // typed from OpenAPI schema
```

**⚠️ Important:** The response shape changes from a bare array to `{"items": [...]}`. The frontend MUST be updated in the same commit or the app breaks.

**⚠️ Important:** After this migration, regenerate the OpenAPI TypeScript types so the typed client knows about the new group endpoints. The build step may do this automatically — check `web/package.json` scripts.

**Step 7: Verify**

Run: `go build ./...`
Run: `golangci-lint run`
Run: `go test ./internal/api/ -v -count=1 -run TestGroup`
Run: `cd web && npm run type-check`
Run: `cd web && npm run lint`
Expected: All pass.

**Step 8: Manual smoke test** (if dev environment is available)

Start the backend and frontend. Navigate to a page that shows groups. Verify:
- Groups list loads
- Creating a group works
- Editing a group works
- Deleting a group works
- Error messages show RFC 9457 format in browser dev tools

**Step 9: Commit**

```
feat: migrate groups handlers from chi to huma

Migrates all 8 group endpoints to huma with RFC 9457 errors,
{"items": [...]} list response shape, pointer PATCH fields,
and Location header on 201. Updates frontend to use the typed
openapi-fetch client. Reference migration for all subsequent
handler files. Addresses findings #6, #7, #31, #32, #33.
```

---

## Tasks 3.1–3.12: Subsequent Handler Migrations

Each migration follows the Groups reference pattern (Task 3.0) exactly. The handler-specific details below note what's different or needs extra attention.

**Migration order:** Execute in this order. Each migration is one commit. Each includes the frontend update.

**Commit message pattern for all 3.x tasks:**
```
feat: migrate <handler-name> handlers from chi to huma

Migrates <handler-name> endpoints to huma with RFC 9457 errors,
{"items": [...]} list response shape, pointer PATCH fields,
and Location header on 201. Updates frontend to use the typed
openapi-fetch client. Addresses findings #6, #7, #31, #32, #33.
```
Replace `<handler-name>` with the resource name (e.g., "saved searches", "API keys"). Add finding-specific notes if the task fixes additional findings (e.g., Task 3.6 also fixes Finding 43, Task 3.8 also fixes Finding 34).

**Steps for each task (follow the Task 3.0 reference pattern exactly):**
1. Read the handler file + `server.go` route registration + frontend store
2. Define huma input/output structs (use pointer types for PATCH body fields)
3. Write huma handler closures (match `createGroupHandler` pattern)
4. Create `registerXxxRoutes` function with per-operation middleware
5. Remove chi route registration from `server.go`, add `registerXxxRoutes` call
6. Update frontend store to use typed `client.GET`/`client.POST`/etc.
7. Verify: `go build ./...`, `golangci-lint run`, `go test ./internal/api/ -v -count=1`, `cd web && npm run type-check`
8. Commit with the pattern above

### Task 3.1: Saved Searches

**File:** `internal/api/saved_searches.go`
**Endpoints:** CRUD (create, list, get, update, delete)
**Special:** Currently not paginated. Wrap in `{"items": [...]}`. Add pagination later if needed.
**Frontend:** Find saved search store/composable, switch to typed client.

### Task 3.2: API Keys

**File:** `internal/api/apikeys.go`
**Endpoints:** Create, list, revoke
**Special:** Create returns the raw API key value — only time it's visible. Ensure the response body includes the key. List returns masked keys only.
**Frontend:** Find API key management store, switch to typed client.

### Task 3.3: Channels

**File:** `internal/api/channels.go`
**Endpoints:** CRUD + test-send
**Special:** Test-send endpoint triggers an outbound HTTP call (webhook). Ensure the huma handler doesn't hold a response timeout during the outbound call — apply `http.TimeoutHandler` if needed.
**Frontend:** Find channel store, switch to typed client.

### Task 3.4: Watchlists

**File:** `internal/api/watchlists.go`
**Endpoints:** CRUD + items (add/remove/list)
**Special:** Already has pagination — migrate to the standard cursor pattern. Currently uses `?after=` with `base64.URLEncoding` of `time|uuid`. Change to `?cursor=` with `base64.RawURLEncoding` of `{"d":"...","id":"..."}`.
**Frontend:** Update pagination logic to use the new cursor format.

### Task 3.5: Alert Rules

**File:** `internal/api/alert_rules.go`
**Endpoints:** CRUD + activation
**Special:**
- Create returns 202 (activation is async) — handle this in huma's operation registration (`DefaultStatus: 202`)
- Activation flow: handler inserts rule with `status='activating'`, enqueues scan job
- Currently has hardcoded `limit=20` with no client-controllable page size — add standard pagination
**Frontend:** Update alert rules store. The 202 response may need special handling.

### Task 3.6: Deliveries

**File:** `internal/api/deliveries.go`
**Endpoints:** List + retry
**Special:**
- **Finding 43 fix:** The current cursor uses `<RFC3339Nano>/<uuid>` in `next_cursor` but expects `after_created_at` + `after_id` as separate params. Migrate to the standard single `?cursor=` param with base64 JSON encoding. This is a **breaking cursor change** — any stored cursors become invalid.
- The delivery retry endpoint sends outbound HTTP — same timeout consideration as channels.
**Commit addendum:** Add "Fixes finding #43 (broken delivery cursor)." to the commit message.
**Frontend:** Update delivery list pagination to use the new cursor format.

### Task 3.7: Reports

**File:** `internal/api/reports.go`
**Endpoints:** CRUD + schedule management
**Special:** Has scheduled delivery fields — ensure date/time parsing works with huma's automatic input parsing.
**Frontend:** Update report store.

### Task 3.8: Orgs

**File:** `internal/api/orgs.go`
**Endpoints:** Create, get, update
**Special:**
- **Finding 34 fix:** Tier limit violations currently return 403. Change to 403 with `type: "urn:cvert-ops:error:tier-limit-exceeded"` in the error body. This applies here and to all other endpoints with tier checks.
- Bootstrap logic has special auth handling — read carefully before migrating.
**Commit addendum:** Add "Fixes finding #34 (tier limit error type)." to the commit message.
**Frontend:** Update org store.

### Task 3.9: Members and Invitations

**File:** `internal/api/orgs.go` (members and invitations are in the same file as orgs, not separate files)
**Endpoints:** List/update/remove members, create/list/delete invitations
**Special:** Currently returns bare arrays. Wrap in `{"items": [...]}`. The member and invitation handlers live in `orgs.go` alongside the org CRUD handlers migrated in Task 3.8 — migrate them in the same file.
**Frontend:** Update members and invitations stores.

### Task 3.10: Audit Log

**File:** `internal/api/audit_log.go`
**Endpoints:** List (read-only)
**Special:** Simple migration. May already have pagination — standardize cursor format.
**Frontend:** Update audit log store.

### Task 3.11: Admin Endpoints

**Files:** `internal/api/admin_orgs.go`, `admin_users.go`, `admin_deliveries.go`, `admin_system.go`, `admin_version.go`, `admin_doctor.go` (added by Phase 8C Operate). Also `admin_helpers.go` (shared admin utilities — migrate if it contains handlers, skip if it's just helpers).
**Endpoints:** Org admin, user admin, delivery admin, system admin, doctor checks
**Special:** These use `RequireSiteAdmin` middleware, not `RequireOrgRole`. Ensure the huma migration preserves this distinction. No org context — different middleware chain.
**⚠️ Important:** Verify these files exist before starting. Read each file to determine which ones contain HTTP handlers (need migration) vs. just helper functions (skip).
**Frontend:** Admin UI may or may not exist yet. If it does, update it. If not, this task is Go-only.

### Task 3.12: Feeds Admin

**File:** `internal/api/admin_feeds.go` (expected from Phase 8C Operate)
**Endpoints:** Pause/resume/logs for feeds
**Special:** Same admin middleware as Task 3.11.
**⚠️ Important:** This file may not exist. As of the latest check, Phase 8C created `admin_deliveries.go`, `admin_doctor.go`, `admin_helpers.go`, `admin_orgs.go`, `admin_system.go`, `admin_users.go`, `admin_version.go` — but NOT `admin_feeds.go`. If it doesn't exist, skip this task and report to lead.
**Frontend:** Same as Task 3.11.

---

## Post-Migration Cleanup (after all handlers migrated)

1. **Delete `orgFetch.ts`** — should have zero callers. Verify with `grep -r "orgFetch" web/src/`.
2. **Delete `writeJSON` helper** — chi handlers used it; huma doesn't need it. Verify no remaining callers.
3. **Remove chi route blocks** — all org-scoped routes should be huma-registered. The chi router remains as the underlying transport but only for static routes (SPA fallback) and middleware application.
4. **Regenerate OpenAPI types** — run the TypeScript type generation to pick up all new endpoints.
5. **Run full test suite:** `go test ./...` + `cd web && npm run test:unit && npm run type-check && npm run lint`

**Commit:**
```
chore: remove orgFetch and writeJSON after huma migration

All org-scoped handlers now use huma. Remove the untyped orgFetch
wrapper and the chi writeJSON helper. Regenerate OpenAPI types.
```

---

# Phase 4: Ops Hardening (Reduced Scope)

**Findings addressed:** 14, 44

Tasks 4A (health/readiness), 4B (metrics), and 4C (runServe/runWorker dedup) have been removed or moved:
- **4A/4B:** Resolved by Phase 8B Observe and 8C Operate (merged before this plan executes).
- **4C:** Moved to Phase 6 — Phase 8 adds significant code to both runServe/runWorker, making the refactoring more valuable but also more complex post-merge.

---

## Task 4D: Notification worker semaphore eviction (Finding 14)

**Finding:** `internal/notify/worker.go` creates a per-org semaphore channel in `semaphore()` (line ~356) but never removes entries. Over the process lifetime, every org that ever receives a notification gets a permanent map entry.

**Files:**
- Modify: `internal/notify/worker.go`
- Test: `internal/notify/worker_test.go` (add eviction test)

**Step 1: Read the file**

Read `internal/notify/worker.go`. Find:
- The `Worker` struct (line ~35-46), specifically the `sems map[uuid.UUID]chan struct{}` and `semsMu sync.Mutex` fields
- The `NewWorker` constructor (line ~49-62) where the map is initialized
- The `semaphore()` method (line ~356-363) that creates entries
- The `Start()` method (line ~71-99) event loop with existing tickers

**Step 2: Add last-used tracking**

Add a `semsLastUsed map[uuid.UUID]time.Time` field to the Worker struct alongside the existing `sems` map. Initialize it in `NewWorker` the same way `sems` is initialized:

```go
// In Worker struct, next to sems:
semsLastUsed map[uuid.UUID]time.Time // last access time per semaphore

// In NewWorker, next to sems initialization:
semsLastUsed: make(map[uuid.UUID]time.Time),
```

**Step 3: Update semaphore() to record access time**

Modify the `semaphore()` method to record `time.Now()` on every call. The method already holds `semsMu` — add the timestamp update inside the lock:

```go
func (w *Worker) semaphore(orgID uuid.UUID) chan struct{} {
	w.semsMu.Lock()
	defer w.semsMu.Unlock()
	if _, ok := w.sems[orgID]; !ok {
		w.sems[orgID] = make(chan struct{}, w.cfg.MaxConcurrentPerOrg)
	}
	w.semsLastUsed[orgID] = time.Now()
	return w.sems[orgID]
}
```

**Step 4: Add eviction method**

Add a method that removes semaphores not used within a threshold. Only evict a semaphore if its channel is empty (no in-flight deliveries):

```go
const semaphoreEvictionAge = 10 * time.Minute

func (w *Worker) evictStaleSemaphores() {
	w.semsMu.Lock()
	defer w.semsMu.Unlock()
	cutoff := time.Now().Add(-semaphoreEvictionAge)
	for orgID, lastUsed := range w.semsLastUsed {
		if lastUsed.Before(cutoff) && len(w.sems[orgID]) == 0 {
			delete(w.sems, orgID)
			delete(w.semsLastUsed, orgID)
		}
	}
}
```

**⚠️ Critical:** Only evict when `len(w.sems[orgID]) == 0`. A non-empty channel means deliveries are in flight — evicting would cause goroutines to read/write a channel that's no longer tracked, and a new `semaphore()` call would create a different channel, breaking the concurrency bound.

**Step 5: Wire eviction into the Start() event loop**

In the `Start()` method, add an eviction ticker alongside the existing tickers. Use `time.NewTicker` (NOT `time.After` — see `dev/implementation-pitfalls.md` timer leak pitfall).

Find the existing ticker declarations in `Start()`. Add:
```go
evictTicker := time.NewTicker(semaphoreEvictionAge)
defer evictTicker.Stop()
```

Add a case to the select loop:
```go
case <-evictTicker.C:
	w.evictStaleSemaphores()
```

**Step 6: Write a test (TDD — write before implementation if not yet done)**

Add tests in `internal/notify/worker_test.go`:

**Test 1: Stale semaphore is evicted**
1. Create a Worker with `MaxConcurrentPerOrg: 1` (minimal config needed to construct)
2. Call `semaphore(orgID)` to create an entry
3. Verify the entry exists: `len(w.sems) == 1`
4. Manually set `w.semsLastUsed[orgID]` to `time.Now().Add(-15 * time.Minute)` (past the threshold)
5. Call `w.evictStaleSemaphores()`
6. Verify: `len(w.sems) == 0`

**Test 2: In-flight semaphore is NOT evicted**
1. Call `semaphore(orgID)` to create an entry
2. Write to the channel: `w.sems[orgID] <- struct{}{}` (simulates in-flight delivery)
3. Set lastUsed to 15 minutes ago
4. Call `w.evictStaleSemaphores()`
5. Verify: `len(w.sems) == 1` (entry preserved)

**⚠️ Agent note:** To access `sems`, `semsLastUsed`, and `evictStaleSemaphores()` from the test, the test must be in package `notify` (not `notify_test`). Check whether the existing test file uses internal or external package naming and match it.

**Step 7: Run tests**

Run: `go test ./internal/notify/ -v -count=1 -run TestEvict`
Run: `go build ./...`
Expected: All pass.

**Step 8: Commit**

```
fix: evict stale per-org semaphores from notification worker

The semaphore map in the notification delivery worker grows without
bound as orgs receive notifications. Add last-used tracking and a
periodic cleanup that removes semaphores idle for 10+ minutes,
but only if no deliveries are in flight. Addresses finding #14.
```

---

## Task 4E: Configurable long-operation statement timeout (Finding 44)

**Finding:** `DB_STATEMENT_TIMEOUT_MS` is globally set to 14s via `RuntimeParams["statement_timeout"]` in `cmd/cvert-ops/main.go` (line ~609). This applies per-statement to every query on every connection. Some operations (activation scans, complex DSL queries) may legitimately exceed 14 seconds when scanning the full CVE corpus.

**Approach:** Add a configurable long-operation timeout and a `SET LOCAL statement_timeout` helper that overrides the per-connection default within a transaction. `SET LOCAL` resets automatically when the transaction ends.

**Files:**
- Modify: `internal/config/config.go` (add config field)
- Modify: `internal/config/config_test.go` (add default test)
- Create: `internal/store/timeout.go` (helper function)
- Modify: `internal/alert/evaluator.go` (apply to activation scan)
- Test: `internal/store/timeout_test.go`

**Step 1: Add config field**

Read `internal/config/config.go`. Find `DBStatementTimeoutMS` (line ~22). Add `DBLongStatementTimeoutMS` immediately after it:

```go
DBLongStatementTimeoutMS int `env:"DB_LONG_STATEMENT_TIMEOUT_MS" envDefault:"120000"`
```

**Step 2: Update config test**

Read `internal/config/config_test.go`. Find the defaults table test (line ~109 has `DBStatementTimeoutMS`). Add a row:

```go
{"DBLongStatementTimeoutMS", cfg.DBLongStatementTimeoutMS, 120000},
```

**Step 3: Create the helper**

Create `internal/store/timeout.go`:

```go
// ABOUTME: Transaction-scoped statement timeout override for long-running operations.
// ABOUTME: Use SetStatementTimeout within a transaction to override the connection-level default.
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SetStatementTimeout overrides the connection-level statement_timeout for the
// current transaction. The timeout resets automatically when the transaction
// ends. Use for operations expected to exceed the default 14s timeout
// (activation scans, complex DSL queries).
func SetStatementTimeout(ctx context.Context, tx *sql.Tx, ms int) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", ms))
	return err
}
```

**⚠️ Constraint:** `SET LOCAL` only works inside a transaction. This helper takes `*sql.Tx`, not a bare connection. A version that takes a bare connection would use `SET` (session-level), which would persist on the pooled connection and affect all subsequent queries — never do this.

**Step 4: Apply to activation scan**

Read `internal/alert/evaluator.go`. Find the activation scan method — it scans all CVEs matching a newly created rule. This is the primary operation that may exceed 14s (scanning 250k+ CVEs with regex conditions).

At the start of the activation scan's transaction, call:
```go
if err := store.SetStatementTimeout(ctx, tx, cfg.DBLongStatementTimeoutMS); err != nil {
	return fmt.Errorf("set long statement timeout: %w", err)
}
```

**⚠️ Important:** Read the evaluator code carefully to find:
1. The exact method name for activation scans
2. How it obtains its transaction (it may use a store transaction helper)
3. Where `cfg` is accessible (the evaluator may need the long timeout value passed at construction or as a parameter)

If the evaluator doesn't have direct access to `*sql.Tx` (e.g., it uses a store method that wraps the transaction), you may need to add the timeout call inside the store method instead. Follow the existing transaction pattern — don't restructure.

**Step 5: Write a test**

Create `internal/store/timeout_test.go`. Test that `SetStatementTimeout` correctly overrides the timeout within a transaction:

```go
func TestSetStatementTimeout_CancelsSlowQuery(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	// Use tdb.DB().BeginTx to get a raw *sql.Tx — the store's transaction
	// helpers (withBypassTx, withOrgTx) are unexported and take
	// func(*generated.Queries), not func(*sql.Tx).
	tx, err := tdb.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback() //nolint:errcheck

	// Set a very short timeout (1ms)
	require.NoError(t, store.SetStatementTimeout(ctx, tx, 1))

	// This 1-second sleep should be cancelled by the 1ms timeout
	_, err = tx.ExecContext(ctx, "SELECT pg_sleep(1)")
	require.Error(t, err)
	require.Contains(t, err.Error(), "canceling statement due to statement timeout")
}
```

**Step 6: Run tests**

Run: `go test ./internal/store/ -v -count=1 -run TestSetStatementTimeout`
Run: `go test ./internal/config/ -v -count=1`
Run: `go build ./...`
Expected: All pass.

**Step 7: Commit**

```
feat: add configurable long-operation statement timeout

Add DB_LONG_STATEMENT_TIMEOUT_MS config (default 120s) and a
store.SetStatementTimeout helper that overrides the per-connection
14s timeout within a transaction using SET LOCAL. Applied to
activation scans which may query the full CVE corpus.
Addresses finding #44.
```

---

# Phase 5: Test Quality

**Findings addressed:** 22, 23, 24, 36

---

## Task 5A: Feed adapter golden file tests (Finding 23)

**Superseded by dedicated plan:** `dev/plans/2026-03-11-test-fixture-corpus.md`

That plan covers the full scope: capture tool, CVE selection agent, fixture extraction, golden file tests for all 8 adapters (NVD, GHSA, KEV, MITRE, OSV, EPSS, MSRC, Red Hat), URL-rewrite transport infrastructure, and a `SeedCorpus` integration helper. Execute that plan instead of implementing this task directly.

**Do NOT implement this task from this plan.** The fixture corpus plan has 6 review rounds of refinement and is authoritative.

---

## Task 5B: Ingest handler integration test (Finding 22)

**Finding:** `internal/ingest/handler_test.go` tests use `mockMerge` and `mockAdapter` — all assertions verify mock call counts and arguments, never that data actually reaches the database. A bug in the handler→merge→DB data flow would go undetected.

**Files:**
- Create: `internal/ingest/handler_integration_test.go`
- Read (reference, do not modify): `internal/ingest/handler.go` (injection points)
- Read (reference, do not modify): `internal/ingest/handler_test.go` (existing mock patterns)
- Read (reference, do not modify): `internal/merge/pipeline_integration_test.go` (TestDB usage)

**Step 1: Understand the injection points**

Read `internal/ingest/handler.go`. The key types and functions:

- `Payload` struct — JSON payload passed to the handler. Read its fields (at minimum it has `FeedName string`). Do NOT guess field names.
- `HandlerStore` interface (line ~26-30) — sync state persistence. `*store.Store` satisfies this.
- `MergeFunc` type (line ~33) — `func(ctx, *store.Store, feed.CanonicalPatch, string) error`
- `HandlerWithFactory` (line ~43-45) — accepts `*store.Store`, `*http.Client`, `MergeFunc`, `AdapterFactory`
- `handlerWithStore` (line ~49) — internal implementation. Passes `st` for both `syncSt` and `mergeSt`.

The integration test should use:
- Real `*store.Store` (via `testutil.NewTestDB`) for both sync state and merge
- Real `merge.Ingest` as the merge function
- A test adapter that returns known `CanonicalPatch` data (we're testing handler→merge→DB, not HTTP parsing)

**Step 2: Write the test adapter**

Create a minimal adapter that returns one patch, then signals last page:

```go
type singlePatchAdapter struct {
	patch  feed.CanonicalPatch
	called bool
}

func (a *singlePatchAdapter) Fetch(ctx context.Context, cursor json.RawMessage) (*feed.FetchResult, error) {
	if a.called {
		return &feed.FetchResult{LastPage: true}, nil
	}
	a.called = true
	return &feed.FetchResult{
		Patches:  []feed.CanonicalPatch{a.patch},
		Cursor:   json.RawMessage(`{"done":true}`),
		LastPage: true,
	}, nil
}
```

**⚠️ Critical:** Read `internal/feed/types.go` to verify the exact `CanonicalPatch` field names and `FetchResult` field names. The struct above is illustrative. Use the actual field names from the codebase.

**Step 3: Write the integration test**

```go
func TestHandler_Integration_DataReachesDB(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	testPatch := feed.CanonicalPatch{
		CVEID:       "CVE-2024-99999",
		Description: "Test vulnerability for integration test",
		Severity:    "HIGH",
		SourceURL:   "https://example.com/CVE-2024-99999",
	}

	adapter := &singlePatchAdapter{patch: testPatch}
	factory := func(name string, client *http.Client) (feed.Adapter, error) {
		return adapter, nil
	}

	handler := ingest.HandlerWithFactory(tdb.Store, nil, merge.Ingest, factory)

	payload, err := json.Marshal(ingest.Payload{FeedName: "test-integration"})
	require.NoError(t, err)

	err = handler(ctx, payload)
	require.NoError(t, err)

	// Verify data reached the database — the CVE should exist
	// Read the store code to find the correct method: GetCVE, GetCVEByID, etc.
	cve, err := tdb.GetCVE(ctx, "CVE-2024-99999")
	require.NoError(t, err)
	require.Equal(t, "CVE-2024-99999", cve.CveID)
}
```

**⚠️ Important:** Read the `Payload` struct to verify field names. It may be `FeedName`, `Feed`, `Name`, or something else.

**⚠️ Important:** Read the store to find the correct CVE query method. It may be `GetCVE(ctx, cveID)` or `GetCVEByID(ctx, cveID)` or accessed via the sqlc-generated queries. Check `internal/store/generated/` or search for existing test patterns in `internal/merge/pipeline_integration_test.go`.

**⚠️ Important:** The `AdapterFactory` type signature may differ from `func(name string, client *http.Client) (feed.Adapter, error)`. Read `internal/ingest/handler.go` for the exact type definition.

**⚠️ Important:** Passing `nil` for `*http.Client` is safe only if the test adapter doesn't use it. Verify by reading `HandlerWithFactory` — if it wraps the client or passes it to the factory, `nil` may cause a panic. If so, pass `http.DefaultClient`.

**Step 4: Run tests**

Run: `go test ./internal/ingest/ -v -count=1 -run TestHandler_Integration`
Expected: Test passes, proving data flows from handler through merge to database.

**Step 5: Commit**

```
test: add ingest handler integration test with real merge and DB

Supplements the existing mock-based handler tests with an
integration test that uses real merge.Ingest and a real Postgres
testcontainer. Verifies the full handler→merge→DB data path
that mock tests cannot validate. Addresses finding #22.
```

---

## Task 5C: Email testcontainer with header injection verification (Finding 24)

**Finding:** `internal/notify/email_test.go` skips tests when Mailpit is unavailable (line ~25-27). The header injection test (`TestEmailSend_SubjectHeaderInjection`, line ~64-81) is security-critical but effectively unrun in CI. Even when it runs, it doesn't verify the injected header was actually stripped from the delivered message.

**Files:**
- Modify: `internal/testutil/smtp.go` (add web API URL to TestSMTP)
- Modify: `internal/notify/email_test.go` (replace skip with testcontainer, add header verification)

**Step 1: Extend TestSMTP with web API URL**

Read `internal/testutil/smtp.go`. The existing `TestSMTP` struct has `Host` and `Port`. Add `WebURL string` for querying the Inbucket REST API:

```go
type TestSMTP struct {
	Host   string
	Port   int
	WebURL string // Inbucket REST API base URL for message inspection
}
```

In `NewTestSMTP`, after getting the SMTP connection, also get the web interface URL. The inbucket testcontainer module exposes this — read the module source or docs to find the exact method. It is likely one of:
- `ctr.WebInterface(ctx)` → returns `string, error`
- `ctr.WebAddress(ctx)` → returns `string, error`
- `ctr.MappedPort(ctx, "9000/tcp")` → returns the mapped port

**⚠️ Critical:** Do NOT guess the method name. Read the `testcontainers-go/modules/inbucket` package to find the correct method for the web API URL. The SMTP connection method is `SmtpConnection(ctx)` — there should be an analogous method for the web interface.

Store the result:
```go
webURL, err := ctr.WebInterface(ctx) // verify method name
if err != nil {
	t.Fatalf("get inbucket web interface: %v", err)
}
return &TestSMTP{Host: host, Port: port, WebURL: webURL}
```

**⚠️ Note:** The web URL may or may not include the scheme (`http://`). If it returns just `host:port`, prepend `http://`. Read the return value documentation.

**Step 2: Replace skip logic with testcontainer**

Read `internal/notify/email_test.go`. The current pattern:
```go
// Lines 25-27 (approximate):
conn, err := net.DialTimeout("tcp", "localhost:1025", time.Second)
if err != nil {
	t.Skip("Mailpit not available")
}
conn.Close()
```

Replace this with:
```go
smtp := testutil.NewTestSMTP(t)
cfg := notify.SmtpConfig{
	Host: smtp.Host,
	Port: smtp.Port,
	From: "test@example.com",
}
```

Apply this change to ALL test functions in the file that use the skip pattern. Each test should call `testutil.NewTestSMTP(t)` — or better, if multiple tests share setup, use a `TestMain` or helper function that creates one container per test file.

**⚠️ Performance consideration:** Starting a Docker container per test function is slow. If the file has multiple test functions, consider creating the container once with a helper:
```go
func setupSMTP(t *testing.T) (*testutil.TestSMTP, notify.SmtpConfig) {
	t.Helper()
	smtp := testutil.NewTestSMTP(t)
	return smtp, notify.SmtpConfig{Host: smtp.Host, Port: smtp.Port, From: "test@example.com"}
}
```
Each test calls this independently — testcontainers-go reuses containers within the same test binary run if configured, but verify this behavior.

**Step 3: Add header injection verification**

The existing `TestEmailSend_SubjectHeaderInjection` test sends an email with `\r\nBcc: attacker@evil.com` injected in the subject. Currently it only checks that `EmailSend` returns no error. Add verification that the delivered message does NOT contain the injected Bcc header.

After sending the email, query the Inbucket REST API:

```go
// Wait briefly for message delivery
time.Sleep(500 * time.Millisecond)

// List messages in the recipient's mailbox
// Inbucket mailbox name = local part of recipient email (before @)
listURL := fmt.Sprintf("%s/api/v1/mailbox/recipient", smtp.WebURL)
resp, err := http.Get(listURL)
require.NoError(t, err)
defer resp.Body.Close()

var messages []struct {
	ID string `json:"id"`
}
require.NoError(t, json.NewDecoder(resp.Body).Decode(&messages))
require.Len(t, messages, 1, "expected exactly one delivered message")

// Fetch full message with headers
msgURL := fmt.Sprintf("%s/api/v1/mailbox/recipient/%s", smtp.WebURL, messages[0].ID)
msgResp, err := http.Get(msgURL)
require.NoError(t, err)
defer msgResp.Body.Close()

var msg struct {
	Header map[string][]string `json:"header"`
}
require.NoError(t, json.NewDecoder(msgResp.Body).Decode(&msg))

// Verify the injected Bcc header was stripped
_, hasBcc := msg.Header["Bcc"]
require.False(t, hasBcc, "injected Bcc header must not appear in delivered message")
```

**⚠️ Important:** Read the existing test to find the actual recipient email address used. The mailbox name in the Inbucket API is the local part (before `@`). If the test sends to `user@example.com`, the mailbox is `user`.

**⚠️ Important:** The Inbucket REST API response format shown above is illustrative. Read the Inbucket API docs (https://github.com/inbucket/inbucket/wiki/REST-API) or inspect the response manually to verify the actual JSON structure. Key things to verify:
- List endpoint response format (is it a bare array or wrapped in an object?)
- Individual message response format (where are headers located?)
- Whether the header field is `"header"` or `"headers"` or nested differently

**⚠️ Important:** The `time.Sleep(500ms)` is a pragmatic delay for SMTP delivery. If this proves flaky, use a polling loop with a timeout instead. But start with the simple approach.

**Step 4: Run tests**

Run: `go test ./internal/notify/ -v -count=1 -run TestEmailSend`
Expected: All email tests pass, including the header injection test with actual header verification.

**Step 5: Commit**

```
test: replace Mailpit skip with Inbucket testcontainer and verify header stripping

Email tests now always run using an Inbucket testcontainer instead of
skipping when Mailpit is unavailable. The header injection test now
queries the Inbucket REST API to verify the Bcc header was actually
stripped from the delivered message. Addresses finding #24.
```

---

## Task 5D: Advisory lock concurrency test (Finding 36)

**Finding:** `internal/merge/pipeline_integration_test.go` has `TestIngest_AdvisoryLockAcquired` (line ~544-583) which only tests that `CVEAdvisoryKey` is deterministic and that a single Ingest succeeds. It does NOT verify that the advisory lock serializes concurrent merges.

**Files:**
- Modify: `internal/merge/pipeline_integration_test.go` (add concurrent test)

**Step 1: Read the existing test**

Read `internal/merge/pipeline_integration_test.go`. Find `TestIngest_AdvisoryLockAcquired` and understand the test setup: how it creates `testutil.NewTestDB`, constructs patches, and calls `merge.Ingest`.

Also read the `CanonicalPatch` struct in `internal/feed/types.go` to verify field names.

**Step 2: Write the concurrency test**

Add `TestIngest_AdvisoryLock_SerializesConcurrentMerges` after the existing lock test:

```go
func TestIngest_AdvisoryLock_SerializesConcurrentMerges(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	cveID := "CVE-2024-LOCK-TEST"

	// Two different source patches for the same CVE
	patch1 := feed.CanonicalPatch{
		CVEID:       cveID,
		Description: "Description from source A",
		Severity:    "HIGH",
		SourceURL:   "https://source-a.example.com",
	}
	patch2 := feed.CanonicalPatch{
		CVEID:       cveID,
		Description: "Description from source B",
		Severity:    "CRITICAL",
		SourceURL:   "https://source-b.example.com",
	}

	// Run two merges concurrently — they contend on the same advisory lock
	errs := make(chan error, 2)
	go func() { errs <- merge.Ingest(ctx, tdb.Store, patch1, "source-a") }()
	go func() { errs <- merge.Ingest(ctx, tdb.Store, patch2, "source-b") }()

	// Both must complete without error (no deadlock, no data corruption)
	for i := 0; i < 2; i++ {
		require.NoError(t, <-errs)
	}

	// Verify the CVE exists with data from both sources
	// The merge pipeline re-reads all cve_sources and resolves from scratch,
	// so the final state reflects both source contributions.
	// Use the correct store method — read existing tests for the pattern.
}
```

**⚠️ Critical:** Read `internal/feed/types.go` to verify `CanonicalPatch` field names. The struct above is illustrative.

**⚠️ Critical:** After verifying both merges succeed, also verify both source rows were persisted. Read the existing integration tests to find how to query `cve_sources` — it may be via a sqlc-generated method like `GetAllCVESources(ctx, cveID)`. The exact verification depends on what methods are available. At minimum, verify the CVE exists. Ideally, also verify two distinct source rows.

**⚠️ Important:** This test proves serialization by showing that:
1. Both concurrent merges complete without error (no deadlock)
2. Both sources persist (no data loss from concurrent writes)
3. The CVE's final state is consistent (not corrupted)

It does NOT need to prove ordering (which merge runs first is nondeterministic) or measure timing. The advisory lock guarantees serialization — the test just verifies the system handles concurrent contention correctly.

**Step 3: Run tests**

Run: `go test ./internal/merge/ -v -count=1 -run TestIngest_AdvisoryLock_Serializes`
Expected: Test passes.

**Step 4: Commit**

```
test: add concurrent advisory lock merge test

Two goroutines merge different source patches for the same CVE ID
concurrently. Verifies both complete without error and both sources
persist, proving the advisory lock serializes concurrent merges
without deadlock or data corruption. Addresses finding #36.
```

---

# Phase 6: Architecture

**Findings addressed:** 15, 16, 17, 19, 25, 39

**Dependency note:** Task 6C (extract shared app setup) depends on Phase 3 completing — it's deferred. All other tasks are independent of each other and of earlier phases.

---

## Task 6A: Replace Set*Deps with ServerDeps options struct (Finding 15)

**Finding:** `internal/api/server.go` has three setter methods (`SetAlertDeps`, `SetAIDeps`, `SetAuditDeps`) that must be called after `NewServer` in the correct order. This temporal coupling means wrong ordering or missing calls produce nil-pointer panics at runtime, not compile time.

**Files:**
- Modify: `internal/api/server.go` (add ServerDeps, modify NewServer, delete setters)
- Modify: `cmd/cvert-ops/main.go` (update both runServe and runWorker)
- Test: compile-time verification via `go build ./...`

**Step 1: Read the files**

Read `internal/api/server.go`. Find:
- The `Server` struct (line ~35-55) — note the fields set by the three setters:
  - `alertCache *alert.RuleCache` and `alertEvaluator *alert.Evaluator` (set by `SetAlertDeps`, line ~425-430)
  - `llm ai.LLMClient` (set by `SetAIDeps`, line ~432-436)
  - `auditWriter *audit.Writer` (set by `SetAuditDeps`, line ~438-441)
- `NewServer` constructor (line ~59-128) — note which fields it already sets during construction

Read `cmd/cvert-ops/main.go`. Find where the setters are called in:
- `runServe` (line ~196: `SetAlertDeps`, line ~199-200: `SetAIDeps`, and `SetAuditDeps` nearby)
- `runWorker` (find the equivalent calls — runWorker may call a subset)

**Step 2: Define ServerDeps struct**

Add near the `Server` struct definition:

```go
// ServerDeps holds optional dependencies injected at construction time.
// Fields may be nil if the feature is disabled (e.g., LLM client when
// AI enrichment is off).
type ServerDeps struct {
	AlertCache     *alert.RuleCache
	AlertEvaluator *alert.Evaluator
	LLM            ai.LLMClient
	AuditWriter    *audit.Writer
}
```

**⚠️ Post-Phase 8 note:** Phase 8C Operate may have added additional dependencies (doctor, admin routes). Read the current `Server` struct and all `Set*` methods to capture ALL post-construction dependencies, not just the original three. If Phase 8C added more setters or direct field assignments in main.go, include those in `ServerDeps` too.

**Step 3: Modify NewServer to accept ServerDeps**

Change the `NewServer` signature. The current signature is approximately:
```go
func NewServer(st *store.Store, cfg *config.Config) (*Server, error)
```

Change to:
```go
func NewServer(st *store.Store, cfg *config.Config, deps ServerDeps) (*Server, error)
```

Inside the constructor, assign the deps fields alongside existing field initialization:
```go
srv := &Server{
	// ... existing fields ...
	alertCache:     deps.AlertCache,
	alertEvaluator: deps.AlertEvaluator,
	llm:            deps.LLM,
	auditWriter:    deps.AuditWriter,
}
```

**⚠️ Critical:** Read the full `NewServer` body before modifying. Don't duplicate initialization for fields already set during construction. The deps replace ONLY the fields that were previously set by the setter methods.

**Step 4: Delete the setter methods**

Delete `SetAlertDeps`, `SetAIDeps`, `SetAuditDeps` entirely. Do NOT comment them out, leave stubs, or add deprecation notes.

**Step 5: Update callers in main.go**

In `runServe`, replace the setter calls with a `ServerDeps` literal passed to `NewServer`:

```go
apiSrv, err := api.NewServer(st, cfg, api.ServerDeps{
	AlertCache:     alertCache,
	AlertEvaluator: alertEval,
	LLM:            llm,        // may be nil if AI is disabled
	AuditWriter:    auditWriter,
})
```

Do the same in `runWorker`. Read the existing code to determine which deps are available in worker mode — `runWorker` may not create an LLM client or audit writer. Pass nil for unavailable deps.

**⚠️ Important:** Search the entire codebase for calls to `SetAlertDeps`, `SetAIDeps`, `SetAuditDeps` — there may be callers in test files too. Update or remove all of them.

**Step 6: Verify**

Run: `go build ./...` (the compiler catches any callers still using deleted setters)
Run: `golangci-lint run`
Run: `go test ./internal/api/ -v -count=1`
Expected: All pass.

**Step 7: Commit**

```
refactor: replace Set*Deps with ServerDeps constructor parameter

Replaces temporal coupling (SetAlertDeps, SetAIDeps, SetAuditDeps
called post-construction) with a single ServerDeps struct passed to
NewServer. Dependencies are wired at construction time — missing
calls cause compile errors, not runtime nil-pointer panics.
Addresses finding #15.
```

---

## Task 6B: Add health reporting to notification worker (Finding 16)

**Finding:** The notification worker (`internal/notify/worker.go`) operates independently from the generic worker pool. Phase 8B Observe added delivery metrics, but the worker has no health reporting — if it stops claiming or gets stuck, there's no visibility via the `/readyz` endpoint.

**Files:**
- Modify: `internal/notify/worker.go` (add health tracking + Healthy method)
- Modify: `cmd/cvert-ops/main.go` (wire Healthy into readiness endpoint)
- Test: `internal/notify/worker_test.go`

**Step 1: Understand the existing health pattern**

Search for the readiness endpoint added by Phase 8C. Look in:
- `internal/api/` for a `/readyz` or `/healthz` handler
- `cmd/cvert-ops/main.go` for readiness check registration

Understand what interface or callback the readiness endpoint expects. It likely aggregates multiple component health checks. Match whatever pattern already exists — do NOT invent a new one.

**⚠️ Critical:** The readiness check pattern is the single most important thing to read before writing any code. If the agent doesn't match the existing pattern, the health check won't be wired correctly.

**Step 2: Add health state tracking**

In the `Worker` struct, add an atomic value to track the last successful claim loop tick:

```go
lastClaimAt atomic.Value // stores time.Time — last successful claim loop iteration
```

In the `Start()` method's event loop, after each claim iteration (whether or not jobs were found), store the current time:

```go
w.lastClaimAt.Store(time.Now())
```

Find the exact location in `Start()` — it's inside the select loop, in the claim ticker case. The claim loop running at all (even finding zero jobs) means the worker is healthy.

**Step 3: Add Healthy method**

```go
// Healthy reports whether the delivery worker's claim loop is running.
// Returns false if the loop hasn't ticked within 2× the claim interval.
func (w *Worker) Healthy() bool {
	v := w.lastClaimAt.Load()
	if v == nil {
		return false
	}
	lastTick := v.(time.Time)
	// Use the claim ticker interval — read the Start() method to find
	// the exact duration used for the claim ticker.
	return time.Since(lastTick) < 2*claimInterval
}
```

**⚠️ Important:** Read `Start()` to find the claim ticker's interval. It may be a config field (`w.cfg.ClaimInterval` or similar) or a constant. Use whatever the existing code uses — don't hardcode a duration.

**Step 4: Wire into readiness endpoint**

In `cmd/cvert-ops/main.go`, find where readiness checks are registered. Add the notification worker's `Healthy()` method as an additional check.

The exact wiring depends on Phase 8C's implementation. Possible patterns:
- A `[]func() bool` slice passed to the readiness handler
- A `HealthChecker` interface that the worker can implement
- Direct registration on an `api.Server` method

Match the existing pattern. Do NOT restructure the readiness endpoint.

**Step 5: Write a test**

Test `Healthy()` in isolation:
1. Create a Worker (minimal config)
2. Assert `Healthy()` returns `false` (never started)
3. Manually `w.lastClaimAt.Store(time.Now())`
4. Assert `Healthy()` returns `true`
5. `w.lastClaimAt.Store(time.Now().Add(-1 * time.Hour))`
6. Assert `Healthy()` returns `false` (stale)

**Step 6: Run tests**

Run: `go test ./internal/notify/ -v -count=1 -run TestWorker_Healthy`
Run: `go build ./...`
Expected: All pass.

**Step 7: Commit**

```
feat: add health reporting to notification delivery worker

The delivery worker now tracks its last claim loop tick and exposes
a Healthy() method. Wired into the /readyz endpoint so the readiness
probe detects a stuck delivery worker. Addresses finding #16.
```

---

## Task 6C: Extract shared app setup from runServe/runWorker (Finding 17)

**DEFERRED — depends on Phase 3 completing.**

Phase 3 (chi→huma migration) will restructure how the HTTP server is initialized. Extracting `buildApp()` before that migration would require rework afterward. Additionally, Phase 8B/8C/8D all added code to both functions, making the duplication worse but the refactoring scope larger.

Execute this task only after Phase 3 is complete and stable. The approach:
- Create `buildApp() (*App, error)` that returns a struct with all wired dependencies
- `runServe` calls `buildApp()` then adds HTTP server
- `runWorker` calls `buildApp()` then runs worker pool directly

**No action needed now.**

---

## Task 6D: ~~Implement import-bulk for NVD~~ — INVALIDATED (Finding 19)

**Finding 19 is invalid.** NVD does not offer bulk download files. Their [developer documentation](https://nvd.nist.gov/developers/start-here) explicitly recommends iterative API calls with `startIndex` pagination for initial data population. The existing `import-bulk` command accepts a local file, which is valid for offline/airgapped scenarios, but there are no NVD bulk archives to feed it.

No action needed. If initial population performance becomes a concern, the NVD feed adapter's normal sync (with parallelized paginated API calls) is the correct approach — not a separate bulk import path.

---

## Task 6E: Extract MergeStore interface (Finding 25)

**Finding:** `internal/merge.Ingest` takes `*store.Store` (concrete struct). The merge pipeline calls `s.Pool()` and `s.DB()` directly. This tight coupling means merge tests always require a real Postgres database.

**Files:**
- Create: `internal/merge/store.go` (interface definition)
- Modify: `internal/merge/pipeline.go` (change parameter type)
- Modify: `internal/ingest/handler.go` (update MergeFunc type if it references `*store.Store`)
- Verify: `cmd/cvert-ops/main.go` (callers pass `*store.Store` which satisfies the interface implicitly)

**Step 1: Catalog store method calls in the merge pipeline**

Read `internal/merge/pipeline.go` thoroughly. Find EVERY method called on the `s` parameter (currently typed `*store.Store`). Based on earlier analysis, Ingest calls:
- `s.Pool()` — to begin a pgx transaction
- `s.DB()` — for `database/sql` operations

But there may be other calls. Read the entire function and note every `s.` call.

**⚠️ Critical:** Do NOT create the interface from assumptions. Read every line of `Ingest` (and any helper functions it calls that receive `s`). If Ingest passes `s` to other functions, trace those too.

**Step 2: Define the interface**

Create `internal/merge/store.go`:

```go
// ABOUTME: Interface for the store dependency used by the merge pipeline.
// ABOUTME: Decouples merge from the concrete store.Store for testability.
package merge

import (
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store defines the database access the merge pipeline requires.
// *store.Store satisfies this interface implicitly.
type Store interface {
	Pool() *pgxpool.Pool
	DB() *sql.DB
}
```

**⚠️ Adjust based on Step 1:** If the pipeline calls additional methods on `s` beyond `Pool()` and `DB()`, add them to the interface. The interface must include exactly the methods that are called — no more, no less.

**⚠️ Naming:** The interface is `merge.Store`, not `merge.MergeStore` (the package name provides context, so `merge.MergeStore` stutters).

**Step 3: Update Ingest signature**

In `internal/merge/pipeline.go`, change:
```go
func Ingest(ctx context.Context, s *store.Store, patch feed.CanonicalPatch, sourceName string) error
```
to:
```go
func Ingest(ctx context.Context, s Store, patch feed.CanonicalPatch, sourceName string) error
```

Remove the `store` package import if it's no longer needed (it likely is still needed for `store.Store` references in sqlc-generated queries — check carefully).

**Step 4: Update MergeFunc type if needed**

Read `internal/ingest/handler.go`. The `MergeFunc` type (line ~33) references `*store.Store`:
```go
type MergeFunc func(ctx context.Context, s *store.Store, patch feed.CanonicalPatch, sourceName string) error
```

This must change to match the new signature:
```go
type MergeFunc func(ctx context.Context, s merge.Store, patch feed.CanonicalPatch, sourceName string) error
```

**⚠️ Watch for circular imports:** `ingest` already imports `merge` (it calls `merge.Ingest`). Changing `MergeFunc` to reference `merge.Store` should work since `merge.Store` is in the `merge` package. But verify there are no import cycles.

**⚠️ Alternative:** If changing `MergeFunc` causes import issues, leave it as `*store.Store` — the concrete type satisfies the interface, so `merge.Ingest` can still be passed as a `MergeFunc`. The interface change in `pipeline.go` is the primary value.

**Step 5: Verify**

Run: `go build ./...` (compiler verifies `*store.Store` satisfies `merge.Store`)
Run: `go test ./internal/merge/ -v -count=1`
Run: `go test ./internal/ingest/ -v -count=1`
Expected: All pass with zero behavior changes.

**Step 6: Commit**

```
refactor: extract merge.Store interface from concrete store dependency

Defines a merge.Store interface with the methods the merge pipeline
actually calls. *store.Store satisfies it implicitly. Enables future
testing with fake stores. Addresses finding #25.
```

---

## Task 6F: Refactor BootstrapFirstUserOrg to use withBypassRawTx (Finding 39)

**Finding:** `internal/store/org.go` `BootstrapFirstUserOrg` (line ~66-123) manually manages transaction begin/rollback/commit with 6 explicit rollback calls and a manual panic recovery. The rest of the store uses bypass transaction helpers which handle this via defer.

**Files:**
- Modify: `internal/store/org.go`
- Test: existing bootstrap tests should pass unchanged

**Step 1: Read both patterns**

Read `internal/store/org.go` lines 66-123. Understand the full flow:
1. `s.db.BeginTx(ctx, nil)` — manual transaction start
2. `SET LOCAL app.bypass_rls = 'on'` — bypass RLS
3. `pg_advisory_xact_lock(bootstrapLockKey)` — serialize concurrent attempts
4. `SELECT COUNT(*) FROM users` — check if first user
5. Early return with rollback if `count != 1`
6. `CreateOrg` + `CreateOrgMember` via sqlc
7. `tx.Commit()`
8. Six explicit `tx.Rollback()` calls on error paths
9. Manual `recover()` with rollback in defer

Read `internal/store/store.go` to understand the bypass transaction helpers. There are TWO:
- `withBypassTx(ctx, fn func(*generated.Queries) error)` — callback receives sqlc Queries
- `withBypassRawTx(ctx, fn func(*sql.Tx) error)` — callback receives raw `*sql.Tx`

Bootstrap needs raw SQL (advisory lock, COUNT) AND sqlc queries (CreateOrg, CreateOrgMember). Use `withBypassRawTx` and create sqlc queries inside the callback via `s.q.WithTx(tx)`.

Both helpers handle panics via `recover()` + rollback in defer — the manual recover in the existing Bootstrap code is redundant.

**Step 2: Refactor**

Replace the manual transaction management with `withBypassRawTx`:

```go
func (s *Store) BootstrapFirstUserOrg(ctx context.Context, ownerID uuid.UUID, orgName string) (*generated.Organization, error) {
	var org *generated.Organization
	err := s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
		// Advisory lock serializes concurrent first-user bootstrap attempts.
		const bootstrapLockKey = 0x435654626F6F74
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", bootstrapLockKey); err != nil {
			return fmt.Errorf("bootstrap advisory lock: %w", err)
		}

		var count int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		if count != 1 {
			return nil // not the first user — no org to create
		}

		q := s.q.WithTx(tx)
		created, err := q.CreateOrg(ctx, orgName)
		if err != nil {
			return fmt.Errorf("create bootstrap org: %w", err)
		}
		if err := q.CreateOrgMember(ctx, generated.CreateOrgMemberParams{
			OrgID:  created.ID,
			UserID: ownerID,
			Role:   "owner",
		}); err != nil {
			return fmt.Errorf("create bootstrap owner: %w", err)
		}

		org = &created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return org, nil
}
```

**⚠️ Critical detail — early return semantics:** When `count != 1`, the callback returns `nil` (no error). This causes `withBypassRawTx` to COMMIT the transaction (containing only the advisory lock and a SELECT). The original code did `tx.Rollback()` for this case. Both are functionally equivalent for a read-only transaction — commit and rollback have the same effect when no writes occurred.

**⚠️ Critical detail — closure capture:** The `org` variable is declared outside the callback and assigned inside it. This is the standard pattern for returning values from `withBypassRawTx` callbacks. The callback communicates success via the closure; it communicates failure via the error return.

**Step 3: Run tests**

Run: `go test ./internal/store/ -v -count=1 -run TestBootstrap`
Run: `go build ./...`
Expected: All existing tests pass unchanged. The behavior is identical — only the transaction management pattern changed.

**Step 4: Commit**

```
refactor: use withBypassRawTx in BootstrapFirstUserOrg

Replaces 6 manual rollback calls and a manual panic recovery with
the defer-based withBypassRawTx callback pattern used by all other
store methods. Behavior is unchanged — the advisory lock, user
count check, and org creation logic are preserved.
Addresses finding #39.
```

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
| 23 | No golden file tests | 5A | 5 | **Superseded** by `dev/plans/2026-03-11-test-fixture-corpus.md`; also applies to 8D generic adapter |
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
