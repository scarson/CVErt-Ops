# Agent 1: Code Quality & Go Idiom
**Date:** 2026-03-18 03:08
**Scope:** Full review

---

### [MAJOR] JWT parse functions are near-identical copies with no shared logic

**Evidence:** internal/auth/jwt.go -- ParseAccessToken (lines 50-78), ParseRefreshToken (lines 118-146), ParsePendingToken (lines 190-218), ParseEnrollmentToken (lines 253-281)

**Problem:** All four parse functions implement the same dual-key rotation logic: try active secret, check for ErrTokenSignatureInvalid, retry with previous secret. The bodies are structurally identical -- only the claims type and the error prefix string differ. This is ~120 lines of copy-pasted logic. Any bug fix or behavioral change must be applied four times.

**Risk:** A future security-relevant change (e.g., adding audit logging on fallback key usage) will be applied to some parse functions but missed in others. This is a realistic maintenance hazard for a security-critical code path.

---

### [MAJOR] Three alert evaluation paths duplicate the rule-iteration-and-metrics pattern

**Evidence:** internal/alert/evaluator.go -- EvaluateRealtime (lines 88-120), EvaluateBatch (lines 124-169), EvaluateEPSS (lines 173-218)

**Problem:** All three methods follow the same structural pattern: read cursor, get candidate IDs, list rules, iterate rules calling loadAndCompileRule + evaluateRule, accumulate metrics, write run rows. The batch and EPSS paths are nearly line-for-line identical (the only differences are the cursor name, the rule-listing method, and the metrics label).

**Risk:** Behavioral changes to the evaluation loop must be applied in three places. EvaluateBatch and EvaluateEPSS could share an evaluateBatchPath helper that handles the cursor-iterate-metrics pattern, reducing ~100 lines to ~30.

---

### [MAJOR] store.UpsertDelivery hand-rolls a bypass transaction instead of using withBypassRawTx

**Evidence:** internal/store/notification_delivery.go:39-52

**Problem:** UpsertDelivery manually opens a transaction, calls SET LOCAL app.bypass_rls, executes raw SQL, and commits -- exactly what withBypassRawTx does. But it bypasses the transaction helper, skipping the panic-recovery defer that withBypassTx and withBypassRawTx both include. A panic inside the raw SQL path would leak the transaction without rollback.

**Risk:** Inconsistency in transaction management. The missing panic recovery is a real correctness gap, however unlikely the trigger.

---

### [MINOR] alert.Evaluator.bypassTx duplicates store.withBypassRawTx logic

**Evidence:** internal/alert/evaluator.go:544-562 vs internal/store/store.go:73-93

**Problem:** The evaluator has its own bypassTx method that does the same begin-tx / SET LOCAL bypass_rls / fn(tx) / commit pattern as store.withBypassRawTx, plus an optional statement-timeout override. This creates a second transaction management code path that must be kept in sync.

**Risk:** Low -- but the duplication is a maintenance concern if transaction management conventions change.

---

### [MINOR] NullString empty-string maps to NULL, conflating empty string with absent value

**Evidence:** internal/dbutil/null.go:10-12 -- NullString returns {Valid: false} for empty input

**Problem:** Code that calls dbutil.NullString(someField) cannot store an intentionally empty string in the database. The merge pipeline at internal/merge/pipeline.go:160 calls dbutil.NullString(resolved.Status) -- if a source explicitly sets status to empty string, it will be stored as NULL.

**Risk:** Subtle data loss at the merge layer. A source that explicitly clears a field to empty string is indistinguishable from one that never provided the field.

---

### [MINOR] ingest.Handler has four factory-function variants that differ only by parameter combinations

**Evidence:** internal/ingest/handler.go:50-70 -- Handler, HandlerWithFactory, HandlerWithAlerts, HandlerWithFactoryAndAlerts

**Problem:** These four functions are a combinatorial explosion of two boolean features (custom adapter factory, alert evaluation). All four delegate to handlerWithStore with different nil/non-nil argument combinations.

**Risk:** Adding a third optional capability would require 8 functions. An options struct would scale better.

---

### [MINOR] applyNVDCVSS has three copy-pasted blocks for v3.1, v3.0, and v4.0 metric extraction

**Evidence:** internal/feed/nvd/adapter.go:517-560

**Problem:** The three blocks each call pickPreferred, extract BaseScore/VectorString/BaseSeverity, apply strings.Clone, and assign to the patch. The only differences are which metric slice is read and which patch fields are written.

**Risk:** Duplication increases the chance of a subtle inconsistency (e.g., forgetting strings.Clone in one branch, or different nil-check semantics for severity).

---

### [MINOR] merge.Ingest at 294 lines is a God Function with 10 sequential steps

**Evidence:** internal/merge/pipeline.go:38-294

**Problem:** Ingest handles advisory locking, PK migration, source upsert, raw payload insert, source resolution, hash computation, CVE upsert, tombstoning, child table updates, vendor enrichment, EPSS staging, and FTS indexing -- all in a single function. It is difficult to test individual steps in isolation.

**Risk:** Moderate -- the function is readable because it is sequential, but a bug in step 8 requires setting up steps 1-7 first for any test. Breaking it into step functions would improve testability.

---

### [MINOR] Server struct has 20+ fields making constructor and dependency injection unwieldy

**Evidence:** internal/api/server.go:50-75

**Problem:** The Server struct carries every dependency the HTTP layer needs -- store, config, OAuth providers, rate limiters, caches, alert evaluator, AI client, audit writer, event writer, lockout manager, etc. It is a megastruct that suggests the HTTP layer is doing too much.

**Risk:** Manageable today, but will continue to grow. Grouping related fields into sub-structs would make the struct scannable.

---

### [MINOR] Chi handlers and huma handlers use different error response patterns in the same API

**Evidence:** Chi handlers (e.g., internal/api/orgs.go:52-53) use writeProblem/writeProblemWithErrors. Huma handlers (e.g., internal/api/auth.go:129) use huma.Error403Forbidden/huma.Error500InternalServerError.

**Problem:** The API has two parallel error-response mechanisms. Error-handling conventions must be implemented twice.

**Risk:** Inconsistencies in error response shape between chi-routed and huma-routed endpoints.

---

### [MINOR] Store methods for simple single-query reads wrap in withBypassTx unnecessarily

**Evidence:** internal/store/auth.go:191-202 (IsSiteAdmin), internal/store/auth.go:207-218 (IsUserEnabled), internal/store/auth.go:236-251 (GetUserAuthStatus), and many more in internal/store/mfa.go (30 total occurrences)

**Problem:** Many store methods that perform a single read query are wrapped in withBypassTx, which opens a transaction, sets app.bypass_rls, runs the query, and commits. For a read-only single-statement operation, the transaction overhead (BEGIN + SET LOCAL + COMMIT = 3 round trips) is unnecessary.

**Risk:** Performance -- every auth middleware check (which runs on every request) pays for three extra database round trips. At scale, this triples connection pressure on auth-path queries.

---

### [MINOR] time.Now() calls are scattered throughout business logic, making time-dependent code untestable

**Evidence:** internal/alert/evaluator.go:89,130,179, internal/notify/worker.go:75,98, internal/merge/pipeline.go:163

**Problem:** Direct time.Now() calls prevent deterministic testing. The evaluator batch/EPSS paths compute batchTime using time.Now().UTC() for the cursor. The merge pipeline writes time.Now().UTC() as the canonical modification time.

**Risk:** Test fragility -- tests must use time ranges or approximate assertions. A clock interface injected at construction would enable precise assertions.

---

### [MINOR] isPermanentDeliveryError uses string matching on error messages for SMTP code detection

**Evidence:** internal/notify/worker.go:349-365

**Problem:** The function checks for SMTP 5xx codes by doing strings.Contains on the error message string. This depends on the exact formatting of go-mail library error messages.

**Risk:** False positives (URL containing a 5xx code string causes premature exhaustion) or false negatives (library format change causes retries of permanent failures). A type assertion on the underlying SMTP error type would be more robust.
