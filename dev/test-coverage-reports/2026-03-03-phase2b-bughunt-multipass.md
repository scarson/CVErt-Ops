# Bug Hunt Report — Phase 2b (Multi-Pass)

**Date:** 2026-03-03
**Method:** Multi-pass (5 passes: contract violations, cross-sibling patterns, failure modes, concurrency, error propagation)

## Scope
- `internal/alert/dsl/field.go` — field registry
- `internal/alert/dsl/parser.go` — DSL parser
- `internal/alert/dsl/validator.go` — semantic validation
- `internal/alert/dsl/compiler.go` — DSL-to-SQL compilation
- `internal/alert/dsl/accessor.go` — CVE field accessors
- `internal/alert/dsl/types.go` — IR types
- `internal/alert/evaluator.go` — evaluation paths (realtime, batch, EPSS, activation)
- `internal/alert/cache.go` — compiled rule cache
- `internal/store/watchlist.go` — watchlist store
- `internal/store/alert_rule.go` — alert rule/event store
- `internal/store/alert_rule_channel.go` — rule↔channel bindings
- `internal/store/dsl_executor.go` — DSL query execution with pagination
- `internal/api/watchlists.go` — watchlist HTTP handlers
- `internal/api/alert_rules.go` — alert rule HTTP handlers
- `internal/api/alert_events.go` — alert event HTTP handler

All five passes performed. Test files excluded.

## Summary

| ID | Title | Severity | Pass |
|----|-------|----------|------|
| BH-Q-1 | numericSQL float parse — undefined evaluation order | significant | 1 |
| BH-Q-2 | createAlertRuleHandler returns 201 instead of 202 | minor | 1 |
| BH-Q-3 | Activation job never enqueued — rules stuck in "activating" | critical* | 1 |
| BH-Q-4 | EvaluateActivation overwrites concurrent status changes | significant | 1 |
| BH-Q-5 | deleteWatchlistItemHandler returns 204 for non-existent items | minor | 2 |
| BH-Q-6 | Worker event methods use withOrgTx instead of withBypassTx | minor | 2 |
| BH-Q-7 | SweepZombieActivations TOCTOU race | significant | 3 |

\*BH-Q-3 is critical if truly missing; may be implemented in out-of-scope code (see caveat).

4 design concerns documented (DC-1 through DC-4).

---

## Bugs

### BH-Q-1: numericSQL float parse closure returns value before Unmarshal runs
**Location:** internal/alert/dsl/compiler.go:142-145
**Severity:** significant
**Evidence:** The float parsing closure is:
```go
func(raw json.RawMessage) (interface{}, error) {
    var v float64
    return v, json.Unmarshal(raw, &v)
}
```
Per Go spec §Order of evaluation: "the order of [function call] events compared to the evaluation … of [other operands] is not specified." The read of `v` and the call to `json.Unmarshal(raw, &v)` have **undefined relative evaluation order**. If the compiler reads `v` before calling `json.Unmarshal`, the returned `interface{}` holds `float64(0)` — not the parsed value.

Compare with the correct pattern used for `kindTime` at compiler.go:147-153, which properly separates the unmarshal from the return:
```go
var s string
if err := json.Unmarshal(raw, &s); err != nil {
    return nil, err
}
return time.Parse(time.RFC3339, s)
```
**Impact:** If the undefined evaluation order resolves unfavorably, ALL numeric DSL conditions (`cvss_v3_score`, `cvss_v4_score`, `epss_score`) would compare against 0 instead of the user-specified threshold. Conditions like `epss_score > 0.5` would become `epss_score > 0`. Even if the current gc compiler happens to evaluate correctly, this is relying on undefined behavior and could break on a compiler update or when using gccgo.
**Found in:** Pass 1 — Contract Violations

---

### BH-Q-2: createAlertRuleHandler always returns 201, never 202
**Location:** internal/api/alert_rules.go:262
**Severity:** minor
**Evidence:** The handler comment at line 161 says: "Returns 201 for draft rules, 202 for rules entering activation scan." The architecture spec (CLAUDE.md) says: "handler inserts rule with `status='activating'`, enqueues scan job, returns 202 immediately."

But the handler always returns `http.StatusCreated` (201):
```go
writeJSON(w, http.StatusCreated, entry) // line 262 — always 201
```
When `req.Enabled` is true, `status` is set to `"activating"` (line 240) but the response code is still 201.
**Impact:** API clients that check for 202 to know an activation scan was queued will not get the expected signal. The response body is correct (status field shows "activating"), so the functional impact is limited to clients relying on HTTP status code semantics.
**Found in:** Pass 1 — Contract Violations

---

### BH-Q-3: Activation job never enqueued — rules stuck in "activating" forever
**Location:** internal/api/alert_rules.go:240-271 (create), internal/api/alert_rules.go:459-505 (update)
**Severity:** critical
**Evidence:** Per CLAUDE.md architecture: "New rule activation: handler inserts rule with `status='activating'`, enqueues scan job, returns 202 immediately — never runs the scan inline."

The `createAlertRuleHandler` sets `status = "activating"` at line 240, creates the rule at line 245, and returns at line 262 — but **never enqueues a job** in `job_queue` with queue `"alert_activation"`.

Similarly, `updateAlertRuleHandler` transitions rules to `"activating"` (lines 471, 479) but never enqueues a job.

The evaluator expects jobs in the `alert_activation` queue (evaluator.go:25-26, referenced in SweepZombieActivations at line 263). Without a job, `EvaluateActivation` is never called.

**Caveat:** The job enqueue might be implemented in a file outside this bug hunt's scope (e.g., a server wiring file, a DB trigger, or a worker poller). But within the scoped handler code, the documented contract is not fulfilled.
**Impact:** If the enqueue is truly missing, every rule created with `enabled: true` (or re-enabled via PATCH) enters "activating" status and never transitions to "active". The rule never fires alerts. The SweepZombieActivations won't catch this because no job exists in the queue to be detected as a zombie.
**Found in:** Pass 1 — Contract Violations (also Pass 2 — float/time sibling inconsistency)

---

### BH-Q-4: EvaluateActivation overwrites concurrent status changes
**Location:** internal/alert/evaluator.go:242
**Severity:** significant
**Evidence:** After the activation scan completes, `EvaluateActivation` unconditionally sets status to "active":
```go
return e.rules.SetAlertRuleStatus(ctx, orgID, ruleID, "active") // line 242
```
`SetAlertRuleStatus` (store/alert_rule.go:166) updates unconditionally — no `WHERE status = 'activating'` guard.

If the user disables the rule (PATCH with `enabled: false`, setting status to "disabled") while the activation scan is running, the scan completion overwrites it back to "active".
**Impact:** User intent is silently overridden. A rule the user explicitly disabled continues to fire alerts. The window is the duration of the activation scan, which iterates the full CVE corpus in 1,000-row pages — potentially minutes for large corpora.
**Found in:** Pass 1 — Contract Violations

---

### BH-Q-5: deleteWatchlistItemHandler returns 204 for non-existent items
**Location:** internal/api/watchlists.go:589-614
**Severity:** minor
**Evidence:** All other delete handlers in this scope follow the pattern: fetch-before-delete → 404 if not found → delete → audit log → 204.

| Handler | Fetch first? | 404 on missing? | Audit log? |
|---------|-------------|-----------------|------------|
| `deleteWatchlistHandler` (line 423) | yes (line 437) | yes (line 444) | yes (line 453) |
| `deleteAlertRuleHandler` (line 522) | yes (line 535) | yes (line 542) | yes (line 554) |
| `deleteWatchlistItemHandler` (line 589) | no | no | no |

`deleteWatchlistItemHandler` calls `srv.store.DeleteWatchlistItem` directly. The soft-delete UPDATE affects 0 rows on a non-existent item and returns no error. The handler returns 204 regardless.
**Impact:** Clients deleting an already-deleted or non-existent item receive 204 (success) instead of 404. Minor inconsistency with the API's behavior for other resource types.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### BH-Q-6: Worker-called event methods use withOrgTx instead of withBypassTx
**Location:** internal/store/alert_rule.go:257, 283, 296
**Severity:** minor
**Evidence:** Within `alert_rule.go`, methods called exclusively from the evaluator worker use two different transaction helpers:

**Correctly use `withBypassTx`** (worker pattern):
- `InsertAlertRuleRun` (line 225)
- `UpdateAlertRuleRun` (line 242)
- `ListActiveRulesForEvaluation` (line 369)
- `ListActiveRulesForEPSS` (line 380)

**Deviate to `withOrgTx`** (API handler pattern):
- `InsertAlertEvent` (line 257)
- `GetUnresolvedAlertEventCVEs` (line 283)
- `ResolveAlertEvent` (line 296)

Per CLAUDE.md architecture: "`withOrgTx` / `withOrgRawTx` — API handler org-scoped queries" and "`WorkerTx` — background workers only."

The methods are functionally correct (they pass `orgID` and RLS still works), but they deviate from the architectural convention. The evaluator knows the correct `orgID` for each rule, so `withOrgTx` works. However, the pattern inconsistency makes the code harder to audit for RLS correctness — a reviewer might assume these methods are only called from handlers.
**Impact:** No immediate correctness issue. Architectural consistency concern — future audits of "which methods are worker-callable" will produce incorrect results if relying on transaction helper choice as a signal.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

---

### BH-Q-7: SweepZombieActivations unconditional status update causes TOCTOU race
**Location:** internal/alert/evaluator.go:282-289
**Severity:** significant
**Evidence:** `SweepZombieActivations` queries for jobs stuck in "running" for 15+ minutes, then unconditionally updates the rule status and job status:
```go
// line 282: unconditional — no WHERE status = 'activating' guard
e.rules.SetAlertRuleStatus(ctx, z.OrgID, z.RuleID, "error")

// line 285-289: unconditional — no WHERE status = 'running' guard
e.db.ExecContext(ctx,
    `UPDATE job_queue SET status = 'failed', finished_at = now() WHERE id = $1`,
    z.JobID)
```
Between the zombie query (line 255-263) and the status updates (line 282-289), the activation could complete successfully:
1. Sweep queries zombie jobs at T=0 → finds job J (running for 16 minutes)
2. `EvaluateActivation` completes at T=1 → sets rule to "active", job to "complete"
3. Sweep sets rule to "error" and job to "failed" at T=2 → overwrites correct state

The `SetAlertRuleStatus` store method (alert_rule.go:166) wraps a sqlc-generated query that updates unconditionally (no status precondition).
**Impact:** A slow-but-successful activation scan is incorrectly marked as failed. The user must re-enable the rule to trigger another activation. Low probability (requires completion during the sweep's iteration loop), but the consequence is rule downtime.
**Found in:** Pass 3 — Failure Mode Reasoning

---

## Design Concerns

### DC-1: Batch/EPSS cursor advances even when all rules fail compilation
**Location:** evaluator.go:143, evaluator.go:185
Both `EvaluateBatch` and `EvaluateEPSS` advance the cursor unconditionally after iterating rules. If every rule fails to compile (e.g., schema drift), the candidate CVEs are permanently skipped for those rules. The alternative (don't advance) risks stuck batches on persistently failing rules. This is a conscious trade-off, but a counter/alert on "all rules failed this batch" would make the trade-off visible.

### DC-2: Resolution detection only fires for CVEs in the current evaluation window
**Location:** evaluator.go:374-413
Resolution (marking previously-matched CVEs as no longer matching) only runs for CVEs in `candidateIDs`. If a rule's DSL changes but CVEs that no longer match weren't recently modified, they won't appear in any evaluation window and their events remain in "matched" state. The activation scan runs with `suppressResolution=true` (line 225), so re-activation doesn't resolve stale events either. Eventually, only CVE modification triggers resolution — there's no periodic "full reconciliation" pass.

### DC-3: PostFilter regex hardcoded to description field
**Location:** evaluator.go:528, compiler.go:38-48
The compiler emits a `PostFilter` for any `regex` op condition (line 38-48) without recording which field it applies to. The evaluator's `applyPostFilters` always matches against `c.Description` (line 528). This works because only `description_primary` supports `regex` in the current field registry. But if a future field type adds regex support, PostFilters would silently match against the wrong field. The `PostFilter` struct (types.go:48-51) has no field reference.

### DC-4: EvaluateRealtime swallows all errors and returns nil
**Location:** evaluator.go:76-102
`EvaluateRealtime` logs individual rule failures but always returns `nil`. The worker calling this function cannot distinguish between "success, no matches" and "every rule failed." Individual failures ARE recorded in `alert_rule_runs` rows, so observability exists via the database, but the worker process itself has no error signal for monitoring/alerting on systemic evaluation failures.
