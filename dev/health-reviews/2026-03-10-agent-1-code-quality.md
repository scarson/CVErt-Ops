# Agent 1: Code Quality & Go Idiom
**Date:** 2026-03-10
**Scope:** Full review

---

### [MAJOR] Duplicated post-filter logic between evaluator and store

**Evidence:** `internal/alert/evaluator.go:527-576` (`applyPostFilters` + `postFilterTarget`) and `internal/store/dsl_executor.go:237-283` (`applyDSLPostFilters` + `dslPostFilterTarget`)

**Problem:** Two nearly identical implementations of regex-based post-filter application exist. Both iterate candidates, apply PostFilter patterns with AND/OR logic and negate support, and dispatch on `f.Field`. The evaluator version operates on `cveSummary`, the store version on `generated.Cfe`. The logic is structurally identical with only the input type differing. The evaluator version could have been parameterized or the filter matching extracted to a shared function.

**Risk:** When filter logic needs to change (e.g., adding a new field, fixing an edge case in OR/negate interaction), one copy gets updated and the other does not, producing inconsistent behavior between alert evaluation and saved-search execution.

---

### [MAJOR] Duplicated `toNullString` helper across packages

**Evidence:** `internal/merge/pipeline.go:298` defines `toNullString`, `toNullStringPtr`, `toNullFloat64`, `toNullTimePtr`, `derefString`. `internal/store/ai.go:240` defines its own `toNullString`. `internal/store/watchlist.go:312` defines `nullString` (same function, different name).

**Problem:** Three separate package-private implementations of `sql.NullString` conversion. These are small functions, but there are five helpers in pipeline.go alone, duplicated partially in two other files. A shared `internal/dbutil` or similar package would eliminate this.

**Risk:** Low individually, but the pattern signals that shared utilities are being re-invented per-package rather than extracted, which will compound as the codebase grows.

---

### [MAJOR] Dead code: `readTx` method defined but never called

**Evidence:** `internal/alert/evaluator.go:608-615` defines `readTx`. Grep for `.readTx(` across all non-test files returns zero results.

**Problem:** `readTx` is a method on `Evaluator` that opens a read-only transaction but is never called anywhere. The `DryRun` method (which seems like the intended user) calls `bypassTx` instead. This is dead code that misleads readers about the evaluator's transaction model.

**Risk:** A contributor might use `readTx` thinking it's the intended read path, not realizing it lacks RLS bypass and would fail for queries touching org-scoped tables.

---

### [MAJOR] `queryCandidates` and `queryCandidatesAll` are near-duplicates

**Evidence:** `internal/alert/evaluator.go:428-473` and `internal/alert/evaluator.go:478-523`

**Problem:** These two methods are structurally identical: same SELECT, same FROM, same join loop, same LIMIT, same scan loop. The only difference is that `queryCandidates` adds `cves.cve_id = ANY(?)` to the WHERE clause while `queryCandidatesAll` does not. This is ~90 lines of duplicated code that could be a single method with an optional `candidateIDs` parameter (nil = no ID filter).

**Risk:** A bug fix or column change in one method is easily missed in the other. Adding a new selected column requires changes in two places that must stay synchronized.

---

### [MINOR] sqlc generates `Cfe` as the Go type name for the `cves` table

**Evidence:** `internal/store/generated/models.go:182` — `type Cfe struct`

**Problem:** sqlc inflected the table name `cves` into `Cfe` (singular of "cves"). This is a confusing name that will trip up every new contributor looking for the CVE type. The generated code is used throughout the codebase (`generated.Cfe`). This could be fixed with a `rename` directive in the sqlc config.

**Risk:** Readability. Every new contributor will spend time figuring out that `Cfe` is the CVE row type. Not a runtime risk, but a meaningful contributor-experience issue for an open-source project.

---

### [MINOR] `EvaluateRealtime`, `EvaluateBatch`, and `EvaluateEPSS` share a duplicated loop pattern

**Evidence:** `internal/alert/evaluator.go:76-102`, `internal/alert/evaluator.go:106-144`, `internal/alert/evaluator.go:148-186`

**Problem:** All three public evaluation methods share the same structural pattern: list rules, iterate rules, compile each, call `evaluateRule`, optionally write a run row. The bodies differ only in: (1) which rules are listed, (2) how candidates are sourced, (3) the path name string, and (4) whether a run row is always written or only on match. A single parameterized evaluation loop could capture all three with a strategy struct.

**Risk:** The current approach is not buggy, but as evaluation paths diverge (e.g., adding metrics, changing run-row policy), the three copies will drift. This is borderline between "reasonable repetition" and "should be refactored."

---

### [MINOR] SMTP permanent error detection relies on string matching against error messages

**Evidence:** `internal/notify/worker.go:317-324`

**Problem:** `isPermanentDeliveryError` scans `err.Error()` for string prefixes like `"550 "`, `"551 "`, etc. This is fragile -- it depends on the exact formatting of errors from the `go-mail` library. If the library changes error formatting, wraps errors differently, or the SMTP server returns multi-line responses, permanent errors could be misclassified as transient and retried indefinitely.

**Risk:** Wasted delivery retries on permanent failures (exhausted mailbox, relay denied), which could hit rate limits with SMTP providers and delay legitimate retries.

---

### [MINOR] `Evaluator` mixes `*sql.DB` stdlib and `store.AlertRuleStore` interface for DB access

**Evidence:** `internal/alert/evaluator.go:44-49` -- `Evaluator` holds both `db *sql.DB` (for raw queries) and `rules store.AlertRuleStore` (for typed store methods). The raw `db` is used for cursor management, zombie sweeps, and candidate queries, while `rules` is used for everything else.

**Problem:** The evaluator bypasses the store's transaction helpers (which enforce RLS) for its raw queries, duplicating the `SET LOCAL app.bypass_rls = 'on'` pattern in its own `bypassTx` method. This creates two independent implementations of the bypass transaction pattern that must be kept in sync. If the RLS bypass mechanism changes (e.g., different GUC variable name), the evaluator's copy would be missed.

**Risk:** Inconsistent RLS bypass behavior if the store's transaction helpers are updated without updating the evaluator's copy.

---

### [MINOR] `BootstrapFirstUserOrg` uses manual transaction management instead of `withBypassTx`

**Evidence:** `internal/store/org.go:66-123`

**Problem:** This method manually opens a transaction, sets bypass_rls, runs queries, and handles commit/rollback -- the same pattern that `withBypassTx` encapsulates. The reason is that it also needs an advisory lock and custom serialization logic. But the manual error handling (explicit `_ = tx.Rollback()` on every error path) is more error-prone than a `defer`-based approach. Line 72-77 has a `recover` that re-panics but only after rollback, while the rest of the error paths do `_ = tx.Rollback(); return nil, fmt.Errorf(...)` without a deferred rollback.

**Risk:** A future code path added between `BeginTx` and the `defer` could leak an uncommitted transaction on error. The mixed transaction management styles make this function harder to audit.
