# Bug Hunt Report — Phase 2b: Watchlists / Alert DSL / Evaluator (Holistic)

## Scope

15 source files analyzed:

- `internal/alert/dsl/` — field.go, parser.go, validator.go, compiler.go, accessor.go, types.go
- `internal/alert/` — evaluator.go, cache.go
- `internal/store/` — watchlist.go, alert_rule.go, alert_rule_channel.go, dsl_executor.go
- `internal/api/` — watchlists.go, alert_rules.go, alert_events.go

**Approach:** Read all 15 source files, then traced the full lifecycle: DSL parse → validate → compile → SQL generation → candidate query → PostFilter → event insert → resolution detection → cursor advance. Cross-referenced field registry, compiler, and evaluator for consistency. Verified transaction helper usage against documented conventions. Checked cursor encoding for URL safety.

Note: 8 of these files overlap with Phase 3a/4 scope. Re-finds of previously reported bugs are expected and noted.

## Bugs

### 1. Float value always compiled as 0 in DSL compiler

**Location:** [compiler.go:142-145](internal/alert/dsl/compiler.go#L142-L145)
**Severity:** critical
**Previously found:** Phase 3a holistic, Phase 4 holistic, Phase 4 multipass, Phase 4 exploratory

**Evidence:**

```go
case kindFloat:
    return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
        var v float64
        return v, json.Unmarshal(raw, &v)
    })
```

The Go specification states that the evaluation order of non-function-call operands relative to function calls in a return statement is "not specified" (§Order of evaluation). With the gc compiler's left-to-right evaluation, `v` is read (as 0.0, the zero value) *before* `json.Unmarshal` writes the parsed value into `v`. The returned `interface{}` always contains 0.0.

Compare with the `kindTime` handler immediately below (lines 147-153), which correctly unmarshals first, checks the error, then returns the parsed value.

**Impact:** Every float DSL condition (`cvss_v3_score`, `cvss_v4_score`, `epss_score`) compiles to a comparison against 0 instead of the user-specified value. A rule like `epss_score gte 0.5` becomes `epss_score >= 0`, matching nearly every CVE with an EPSS score. `cvss_v3_score lt 4.0` becomes `cvss_v3_score < 0`, matching almost nothing. Affects all evaluation paths (realtime, batch, EPSS, activation, dry-run) and `ExecuteDSLQuery`.

---

### 2. Activation scan job never enqueued

**Location:** [alert_rules.go:240-262](internal/api/alert_rules.go#L240-L262) (create), [alert_rules.go:459-481](internal/api/alert_rules.go#L459-L481) (update)
**Severity:** significant
**Previously found:** Phase 3a holistic, Phase 3a exploratory, Phase 3a multipass

**Evidence:** `createAlertRuleHandler` sets `status = "activating"` when `req.Enabled == true` (line 240-243) but:
1. Never enqueues a job into `job_queue` with queue `alert_activation`
2. Always returns 201 (`StatusCreated`) instead of 202 (`StatusAccepted`)

Same issue in `updateAlertRuleHandler` — transitions to "activating" on DSL changes to active rules (line 471) or when enabling draft/disabled/error rules (line 479), but never enqueues.

A grep for `alert_activation` across the entire codebase finds it only in `evaluator.go` (constant + zombie sweeper), `evaluator_test.go`, and documentation. No code enqueues activation jobs. No worker handler registers for the `alert_activation` queue.

The CLAUDE.md architecture section explicitly states: "handler inserts rule with `status='activating'`, enqueues scan job, returns 202 immediately — never runs the scan inline."

**Impact:** Rules created with `enabled=true` or re-activated via PATCH enter "activating" status and stay there permanently. The zombie sweeper (`SweepZombieActivations`) only catches jobs stuck in `job_queue` with status "running" — since no job is ever enqueued, the sweeper doesn't apply. Rules are stuck forever. The handler also returns 201 instead of the 202 specified in PLAN.md §10.

---

### 3. ExecuteDSLQuery silently returns empty results for watchlist-scoped rules

**Location:** [dsl_executor.go:118-194](internal/store/dsl_executor.go#L118-L194)
**Severity:** significant

**Evidence:** `ExecuteDSLQuery` queries `s.db` directly (line 160) without any transaction wrapper:

```go
rows, err := s.db.QueryContext(ctx, query, args...)
```

When the compiled rule includes watchlist conditions, the SQL contains an EXISTS subquery on `watchlist_items` (compiler.go:116-136). The `watchlist_items` table is org-scoped with RLS policies. Without `SET LOCAL app.org_id` or `SET LOCAL app.bypass_rls = 'on'`, the RLS fail-closed design evaluates `current_setting('app.org_id', true)::uuid = org_id` as `NULL = org_id → NULL → false`, returning zero rows from the subquery.

The compiler's watchlist subquery does include an explicit `wi.org_id = ?` filter (compiler.go:119), but RLS policies are applied *on top of* explicit WHERE clauses. Without setting the session variable, RLS blocks all access regardless of the explicit filter.

Compare with the evaluator's `queryCandidates` (evaluator.go:361-367) which correctly uses `bypassTx` to set `bypass_rls = 'on'`.

**Impact:** Any use of `ExecuteDSLQuery` with a watchlist-scoped compiled rule (NL search, saved search execution per the ABOUTME) silently returns zero matches for the watchlist condition. The overall query may still return results from other conditions (in OR logic), but AND-combined watchlist conditions would produce empty results.

---

### 4. base64.StdEncoding cursor corrupted by URL query parameter parsing

**Location:** [watchlists.go:90-93](internal/api/watchlists.go#L90-L93)
**Severity:** minor

**Evidence:**

```go
func encodeTimeCursor(t time.Time, id uuid.UUID) string {
    raw := t.UTC().Format(time.RFC3339Nano) + "|" + id.String()
    return base64.StdEncoding.EncodeToString([]byte(raw))
}
```

`base64.StdEncoding` uses `+` and `/` characters. When the cursor is passed as a URL query parameter (`?after=...`), Go's `r.URL.Query().Get("after")` uses `url.ParseQuery` which follows `application/x-www-form-urlencoded` rules: `+` is decoded as a space character. If the base64 cursor contains `+`, it is silently corrupted to a space, and `base64.StdEncoding.DecodeString` fails.

The error is silently swallowed in all callers (watchlists.go:294, alert_rules.go:317, alert_events.go:69, audit_log.go:118):

```go
if c := r.URL.Query().Get("after"); c != "" {
    t, id, err := decodeTimeCursor(c)
    if err == nil {
        afterTime = &t
        afterID = &id
    }
}
```

On decode failure, `afterTime` and `afterID` remain nil, and the query returns the first page instead of the requested page.

`dsl_executor.go` correctly uses `base64.URLEncoding` (line 92) which substitutes `-` and `_` for `+` and `/`. The inconsistency confirms this is unintentional.

**Impact:** Pagination across watchlists, alert rules, alert events, and audit logs intermittently breaks when the cursor happens to base64-encode with a `+`. The user sees the first page repeated instead of the next page. The probability depends on the timestamp/UUID bytes — roughly 1 in 4 cursors contain at least one `+`.

---

### 5. Duplicate watchlist IDs in alert rule creation silently rejected

**Location:** [watchlist.go:288-304](internal/store/watchlist.go#L288-L304)
**Severity:** minor

**Evidence:**

```go
func (s *Store) ValidateWatchlistsOwnership(ctx context.Context, orgID uuid.UUID, ids []uuid.UUID) (bool, error) {
    // ...
    count, err = q.CountOwnedWatchlistsByIDs(ctx, ...)
    // ...
    return count == int64(len(ids)), nil
}
```

`CountOwnedWatchlistsByIDs` uses `WHERE id = ANY($1)` which de-duplicates array values. If `ids` contains duplicates (e.g., `[uuid1, uuid1, uuid2]`), `count = 2` but `len(ids) = 3`, so the method returns `false`.

The caller `parseWatchlistUUIDs` (alert_rules.go:146-156) converts string UUIDs to `uuid.UUID` without deduplication. A user sending `"watchlist_ids": ["same-uuid", "same-uuid"]` gets a confusing "one or more watchlist_ids not found in this org" error.

**Impact:** Users who accidentally include duplicate watchlist IDs in alert rule create/update receive a misleading error message. Low practical severity — duplicates are uncommon and the error is non-destructive.

## Design Concerns

1. **PostFilter lacks field reference** — `PostFilter` (types.go:48-51) stores only the regex pattern, not which field it applies to. The evaluator applies all PostFilters against `c.Description` (evaluator.go:528). This is correct by construction in MVP (only `description_primary` supports regex via `textOps` in field.go:36), but adding regex support to another field would silently apply the regex against the wrong column with no compile-time or runtime error.

2. **Batch/EPSS cursor advances despite individual rule errors** — `EvaluateBatch` (evaluator.go:143) and `EvaluateEPSS` (evaluator.go:185) always advance the cursor, even when individual rules fail compilation or evaluation. CVEs that failed evaluation for temporarily-errored rules won't be re-processed in the next batch. This is a reasonable trade-off (prevents infinite retries for permanently broken rules) but means transient errors can cause missed alerts.

3. **dsl_version never incremented on DSL updates** — `UpdateAlertRuleParams` (alert_rule.go:37-46) doesn't include `DslVersion`. The field stays at 1 from creation. The in-process cache eviction (alert_rules.go:503-505) compensates for this in a single-node deployment, but if the system ever runs multiple nodes with shared cache invalidation keyed on dsl_version, stale rules would be served. Also undermines dsl_version's semantic meaning as a change counter.

4. **Regex case sensitivity not communicated to users** — The DSL evaluator lowercases `description_primary` for PostFilter matching (accessor.go:41), but the regex pattern is compiled as-is (compiler.go:43). Users writing `"regex": "CVE-2024"` will match, but `"regex": "ERROR"` won't (lowered to "error" in the description but pattern stays uppercase). The validator doesn't warn about uppercase characters in regex patterns. Users must use `(?i)` for case-insensitive matching or write lowercase patterns.
