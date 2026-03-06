# Bug Hunt Report — Phase 2b (Exploratory)

**Date:** 2026-03-03
**Variant:** BH-R (Exploratory — depth-first from high-risk code)
**Scope:** Alert DSL (compiler, validator, parser, field registry, types, accessor), alert evaluator + cache, watchlist store, alert rule store + channel bindings, DSL executor, API handlers (watchlists, alert rules, alert events)

## Scope

Files analyzed (deeply explored):
- `internal/alert/evaluator.go` — orchestration: realtime/batch/EPSS/activation paths, resolution detection, DryRun
- `internal/alert/dsl/compiler.go` — DSL→SQL compilation, PostFilter extraction, watchlist subquery
- `internal/store/dsl_executor.go` — compiled DSL execution with keyset pagination
- `internal/api/alert_rules.go` — CRUD handlers, DSL validation, state machine, cache eviction
- `internal/api/watchlists.go` — watchlist + item CRUD, cursor pagination
- `internal/store/alert_rule.go` — alert rule store (incl. event/run management)
- `internal/store/queries/alert_rules.sql` — raw sqlc queries (confirmed dsl_version behavior)

Files read (lower risk, no new bugs found):
- `internal/alert/dsl/parser.go`, `validator.go`, `field.go`, `types.go`, `accessor.go` — DSL IR, validation, field registry
- `internal/alert/cache.go` — thread-safe rule cache
- `internal/store/watchlist.go` — watchlist store CRUD
- `internal/store/alert_rule_channel.go` — rule↔channel join table
- `internal/api/alert_events.go` — read-only event listing
- `internal/store/jobs.go` — job queue (followed activation enqueue thread)
- `migrations/000014_create_watchlists.up.sql` — RLS policy (confirmed DryRun bug)

**Strategy:** Started at the evaluator (highest-risk orchestration). Followed the DryRun→readTx→RLS thread to the migration SQL to confirm the watchlist RLS bug. Then traced the update handler's state machine through cache eviction and the sqlc UPDATE query to confirm dsl_version is never incremented. Cross-referenced Phase 3a and Phase 4 bug reports to avoid duplicate findings.

## Bugs

### 1. DryRun uses readTx without RLS context — watchlist-scoped rules silently return 0 matches

**Location:** `internal/alert/evaluator.go:313-316`
**Severity:** significant
**Evidence:**

The DryRun evaluation path uses `readTx` (read-only transaction) to query candidates:

```go
if err := e.readTx(ctx, func(tx *sql.Tx) error {
    var err error
    candidates, partial, err = e.queryCandidatesAll(ctx, tx, compiled)
    return err
}); err != nil {
```

`readTx` opens a plain read-only transaction without setting either `app.org_id` or `app.bypass_rls`:

```go
func (e *Evaluator) readTx(ctx context.Context, fn func(*sql.Tx) error) error {
    tx, err := e.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
    // ... no SET LOCAL app.org_id or app.bypass_rls
    return fn(tx)
}
```

When the compiled rule includes a watchlist condition (via `watchlistExpr`), the SQL contains an EXISTS subquery on `watchlist_items`. The `watchlist_items` table has RLS enforced (migration 000014):

```sql
CREATE POLICY org_isolation ON watchlist_items
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
```

With neither setting configured, the policy evaluates to `(NULL = 'on') OR (org_id = NULL::uuid)` → `false`. All `watchlist_items` rows are filtered out, making the EXISTS subquery always return false.

Compare with the non-DryRun evaluation path, which correctly uses `bypassTx`:

```go
if err := e.bypassTx(ctx, func(tx *sql.Tx) error {
    var err error
    candidates, partial, err = e.queryCandidates(ctx, tx, compiled, candidateIDs)
    return err
}); err != nil {
```

`bypassTx` sets `SET LOCAL app.bypass_rls = 'on'`, allowing the watchlist subquery to see all rows.

**Impact:** DryRun for any rule with watchlist IDs assigned always reports 0 matches, regardless of the actual CVE corpus. The API handler returns 200 OK with `{"match_count": 0}` — a silent failure with no error. Users testing their rules before activation see no matches and may assume the rule is wrong.

### 2. Missing cache eviction when DSL changes from error/disabled state — stale compiled rule used

**Location:** `internal/api/alert_rules.go:463-481`, `internal/store/queries/alert_rules.sql:21-32`
**Severity:** significant
**Evidence:**

The update handler's state machine sets `needsCacheEvict = true` only for the "active" case:

```go
switch current.Status {
case "activating":
    // ...
case "active":
    if hasDSLChange {
        newStatus = "activating"
        needsCacheEvict = true  // ← only set here
    }
case "error", "draft", "disabled":
    if req.Enabled != nil && *req.Enabled {
        newStatus = "activating"
        // needsCacheEvict NOT set
    }
}
```

The `UpdateAlertRule` SQL query (confirmed in `alert_rules.sql:17-32`) does **not** increment `dsl_version`:

```sql
UPDATE alert_rules
SET name = $3, logic = $4, conditions = $5, watchlist_ids = $6,
    has_epss_condition = $7, is_epss_only = $8,
    fire_on_non_material_changes = $9, status = $10,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
```

No `dsl_version = dsl_version + 1`. The cache key is `(ruleID, dslVersion)`, and dsl_version is always 1 (set at creation, never incremented). Cache correctness depends entirely on explicit eviction.

For the "error" and "disabled" cases with a DSL change + re-enable:
1. Rule was previously active → compiled and cached as `(ruleID, 1)`
2. Rule went to "error" or was disabled → cache entry remains
3. User PATCHes with new conditions + `enabled: true`
4. Handler writes new conditions to DB, sets status = "activating"
5. Cache is **not** evicted
6. Activation scan calls `loadAndCompileRule` → cache hit for `(ruleID, 1)` → returns OLD compiled rule
7. Activation runs with the old DSL, not the new one

**Impact:** When a previously active rule in error/disabled state gets DSL changes and is re-enabled, the activation scan (if it were wired — see known bug) would evaluate against the old DSL conditions, not the updated ones. Alert events would be created based on wrong criteria.

### 3. Create handler always returns 201, never 202 for activating rules

**Location:** `internal/api/alert_rules.go:262`
**Severity:** minor
**Evidence:**

The handler's docstring states "Returns 201 for draft rules, 202 for rules entering activation scan" but the code always returns 201:

```go
entry := alertRuleToEntry(*row)
writeJSON(w, http.StatusCreated, entry) // always 201
```

Per PLAN.md: "handler inserts rule with `status='activating'`, enqueues scan job, returns 202 immediately." The status code should be `http.StatusAccepted` (202) when `status == "activating"` to signal that the rule is not yet active and an async operation is in progress.

**Impact:** API consumers cannot distinguish between a rule that was created as a draft (immediately usable after enabling) and a rule that was created with activation pending. The 201 response implies the resource is complete, but an activating rule is not yet ready to evaluate.

## Design Concerns

### EvaluateActivation doesn't verify rule status before running

**Location:** `internal/alert/evaluator.go:191-243`

`EvaluateActivation` reads the rule at the start:

```go
rule, err := e.rules.GetAlertRule(ctx, orgID, ruleID)
```

But it never checks that the rule's status is still "activating" before proceeding. If the user disables the rule (PATCH with `enabled: false` → status "disabled") while an activation scan is running, the scan continues to completion and then sets the rule back to "active":

```go
return e.rules.SetAlertRuleStatus(ctx, orgID, ruleID, "active")
```

This would override the user's explicit disable. The sweeper (`SweepZombieActivations`) handles the reverse case (stuck activations), but there's no guard against completed scans overriding a concurrent status change.

### Resolution detection scope is limited to the current candidate set

**Location:** `internal/alert/evaluator.go:400-413`

Resolution only marks a CVE as "no longer matching" if it's in the current `candidateIDs` set AND doesn't match. CVEs that were previously matched but aren't in the current candidate set (e.g., not modified since the last batch cursor) are never resolved. This is correct by design (you can only resolve what you've re-evaluated), but it means resolution is eventually consistent — a rule change that should un-match existing CVEs won't resolve them until each CVE's `date_modified_canonical` is updated by a feed sync.

## Previously Identified Bugs (cross-referenced)

The following bugs in this scope were already identified by Phase 3a and Phase 4 bug hunts:

1. **Float parse `return v, json.Unmarshal(raw, &v)` returns 0.0** — `compiler.go:142-145` — critical (Phase 4 holistic, Phase 4 exploratory)
2. **PostFilter regex conditions use AND semantics regardless of rule logic** — `evaluator.go:520-542`, `compiler.go:38-49` — significant (Phase 4 holistic)
3. **ExecuteDSLQuery silently drops regex PostFilters** — `dsl_executor.go:118-194` — significant (Phase 4 exploratory)
4. **Activation pipeline not wired: rules stuck in 'activating' forever** — `alert_rules.go:240-262`, `alert_rules.go:459-492` — significant (Phase 3a exploratory, Phase 3a holistic)
