# Phase 2b Design: Watchlists + Alert DSL

**Date:** 2026-02-27
**Status:** Approved — ready for implementation
**References:** PLAN.md §9, §10, Appendix A; implementation-pitfalls.md

---

## Scope

Full watchlist management + alert DSL evaluator (realtime + batch + EPSS evaluation paths,
writing `alert_events`). Notification delivery is Phase 3. Deferred out of scope:
`cve_annotations`, `saved_searches`.

## Implementation Approach

Bottom-up: migrations → store layer → DSL compiler → evaluator workers → HTTP handlers.
Each layer is TDD'd in isolation before the next is built.

---

## Section 1: Schema

### Migrations

| Migration | Contents |
|---|---|
| 000013 | `watchlists`, `watchlist_items` |
| 000014 | `alert_rules` |
| 000015 | `alert_rule_runs`, `alert_events` |

### Key Design Decisions

**`watchlist_items` — type-discriminated with partial unique indexes:**
```sql
CREATE TYPE watchlist_item_type AS ENUM ('package', 'cpe');

CREATE TABLE watchlist_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    watchlist_id  UUID NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL,    -- denormalized for RLS
    item_type     watchlist_item_type NOT NULL,
    -- package fields
    ecosystem     TEXT,
    package_name  TEXT,
    namespace     TEXT,
    -- cpe fields
    cpe_normalized TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ NULL
);

-- Partial unique indexes (allow reuse after soft-delete)
CREATE UNIQUE INDEX CONCURRENTLY watchlist_items_pkg_uq
    ON watchlist_items (watchlist_id, ecosystem, package_name)
    WHERE item_type = 'package' AND deleted_at IS NULL;

CREATE UNIQUE INDEX CONCURRENTLY watchlist_items_cpe_uq
    ON watchlist_items (watchlist_id, cpe_normalized)
    WHERE item_type = 'cpe' AND deleted_at IS NULL;
```

**`alert_rules.watchlist_ids uuid[]`:** No FK on arrays — app-layer validation validates
ownership at save time. At evaluation time, deleted watchlist IDs silently match nothing
(`wi.deleted_at IS NULL` in EXISTS subquery).

**`alert_rules` — extra columns beyond Appendix A:**
- `has_epss_condition BOOL NOT NULL DEFAULT false` — set by compiler at save time
- `is_epss_only BOOL NOT NULL DEFAULT false` — set by compiler at save time
- `status TEXT NOT NULL` — `draft | activating | active | error | disabled`

**`alert_events` — extra column beyond Appendix A:**
- `suppress_delivery BOOL NOT NULL DEFAULT false` — set to `true` by activation scan;
  Phase 3 delivery worker skips these rows (establishes dedup baseline without firing)

**`alert_events` UNIQUE constraint:**
```sql
UNIQUE(org_id, rule_id, cve_id, material_hash)
```
All inserts use `ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING RETURNING id`.
Fan-out only if `RETURNING id` yields a row.

**Evaluator cursors:** Stored in existing `feed_sync_state` table:
- `feed_name = 'alert:batch'` — batch evaluator cursor
- `feed_name = 'alert:epss'` — EPSS evaluator cursor

**job_queue dependency:** Realtime alert jobs use:
```sql
INSERT INTO job_queue (queue, lock_key, payload, status)
VALUES ('alert:realtime', 'alert:realtime:' || $cve_id, ..., 'pending')
ON CONFLICT (lock_key) WHERE status IN ('pending', 'running') DO NOTHING
```
**Verify that migration 000001 includes** `CREATE UNIQUE INDEX CONCURRENTLY job_queue_lock_key_active ON job_queue(lock_key) WHERE status IN ('pending', 'running')`. Add it if missing.

---

## Section 2: DSL Compiler

**Package:** `internal/alert/dsl/`

### Files

```
internal/alert/dsl/
  types.go       — IR types: Rule, Condition, CompiledRule, PostFilter, ValidationError
  field.go       — field registry: name → (kind, SQLExpr, validOps, nullable, enumValues)
  parser.go      — JSON → Rule (dsl_version check, structural validation)
  validator.go   — semantic validation; returns []ValidationError
  compiler.go    — Rule + watchlistIDs → CompiledRule (squirrel expressions)
  accessor.go    — nil-safe CVE field accessors for regex post-filter
```

### IR Types

```go
// Rule — top-level DSL IR. dsl_version lives on the DB row, not here.
type Rule struct {
    Logic      Logic       `json:"logic"`       // "and" | "or"
    Conditions []Condition `json:"conditions"`
}

type Logic string
const (
    LogicAnd Logic = "and"
    LogicOr  Logic = "or"
)

// Condition — one filter clause. Value deferred to field-type-aware compiler.
type Condition struct {
    Field string          `json:"field"`
    Op    string          `json:"operator"`
    Value json.RawMessage `json:"value"`
}

// CompiledRule — output of Compile; ready for the evaluator.
type CompiledRule struct {
    RuleID      uuid.UUID
    DSLVersion  int
    SQL         squirrel.Sqlizer // WHERE predicate only; no LIMIT, no FROM
    PostFilters []PostFilter     // Go-side regex filters (description_primary only, MVP)
    IsEPSSOnly  bool             // all conditions reference epss_score
    HasEPSS     bool             // any condition references epss_score
}

// PostFilter — in-process regex filter applied to SQL result set candidates.
// Field is always description_primary in MVP.
type PostFilter struct {
    Negate  bool
    Pattern *regexp.Regexp
}

// ValidationError — one validation problem; multiple returned at once.
type ValidationError struct {
    Index    int    // condition index; -1 for rule-level errors
    Field    string
    Message  string
    Severity string // "error" (blocks save) | "warning" (advisory)
}
```

### Field Registry

```go
type fieldKind int
const (
    kindString   fieldKind = iota // eq/neq/in/not_in
    kindEnum                      // eq/neq/in/not_in; validated against enumValues
    kindFloat                     // numeric ops
    kindTime                      // numeric ops; value parsed as RFC 3339
    kindBool                      // eq only
    kindStrArray                  // contains_any / contains_all
    kindText                      // contains/starts_with/ends_with/regex
    kindAffected                  // EXISTS subquery on cve_affected_packages; no regex
)

var severityEnum = []string{"critical", "high", "medium", "low", "none"}
var ecosystemEnum = []string{
    "npm", "pypi", "maven", "go", "cargo", "rubygems", "nuget",
    "hex", "pub", "swift", "cocoapods", "packagist",
}

var numericOps = []string{"gt", "gte", "lt", "lte", "eq", "neq"}
var setOps     = []string{"eq", "neq", "in", "not_in"}
var arrayOps   = []string{"contains_any", "contains_all"}
// textOps for kindText includes regex; kindAffected excludes regex (MVP)
var textOps         = []string{"contains", "starts_with", "ends_with", "regex"}
var textOpsNoRegex  = []string{"contains", "starts_with", "ends_with"}

var fields = map[string]fieldSpec{
    "cve_id":                   {kindString,   "cves.cve_id",                  setOps,        false, nil},
    "severity":                 {kindEnum,     "cves.severity",                setOps,        false, severityEnum},
    "cvss_v3_score":            {kindFloat,    "cves.cvss_v3_score",           numericOps,    true,  nil},
    "cvss_v4_score":            {kindFloat,    "cves.cvss_v4_score",           numericOps,    true,  nil},
    "epss_score":               {kindFloat,    "cves.epss_score",              numericOps,    true,  nil},
    "date_published":           {kindTime,     "cves.date_published",          numericOps,    true,  nil},
    "date_modified_source_max": {kindTime,     "cves.date_modified_source_max",numericOps,    false, nil},
    "cwe_ids":                  {kindStrArray, "cves.cwe_ids",                 arrayOps,      false, nil},
    "in_cisa_kev":              {kindBool,     "cves.in_cisa_kev",             []string{"eq"},false, nil},
    "exploit_available":        {kindBool,     "cves.exploit_available",       []string{"eq"},false, nil},
    "affected.ecosystem":       {kindAffected, "",                             setOps,        false, ecosystemEnum},
    "affected.package":         {kindAffected, "",                             textOpsNoRegex,false, nil},
    "description_primary":      {kindText,     "cves.description_primary",     textOps,       false, nil},
}
```

### Parse → Validate → Compile Pipeline

**`Parse(data []byte) (Rule, error)`**
- Unmarshal JSON → `Rule`
- Check `logic` ∈ {"and", "or"}
- Check `len(conditions) > 0`
- No semantic checks — those are in Validate

**`Validate(r Rule, hasWatchlists bool) []ValidationError`**

Per-condition checks:
- Field exists in registry
- Op is valid for the field's kind
- Value parseable to the field's type (float64, RFC 3339 time, bool, []string)
- Enum values in field's `enumValues` list

Regex-specific:
- `regexp.Compile` succeeds
- `len(pattern) <= 256`
- At least one selective non-regex condition exists OR `hasWatchlists = true`
  - Selective = severity condition, `in_cisa_kev eq true`, date window, affected.ecosystem/package
  - Fail with `severity:"error"` if neither

Advisory warnings (severity "warning", do not block save):
- `contains` pattern with < 3 chars (trigram index won't help)

Also computes:
- `isEPSSOnly = all conditions reference epss_score`
- `hasEPSS = any condition references epss_score`

**`Compile(r Rule, ruleID uuid.UUID, dslVersion int, orgID uuid.UUID, watchlistIDs []uuid.UUID) (*CompiledRule, error)`**

Loops over conditions building squirrel predicates. Regex conditions are extracted
to `PostFilters`, not compiled to SQL. Combines predicates with `squirrel.And{}` or
`squirrel.Or{}` based on `r.Logic`. Appends watchlist EXISTS subquery as additional AND
when `len(watchlistIDs) > 0`.

### Squirrel Expression Mapping

| Condition | SQL output |
|---|---|
| `cvss_v3_score gte 7.0` | `squirrel.GtOrEq{"cves.cvss_v3_score": 7.0}` |
| `severity in [high, critical]` | `squirrel.Eq{"cves.severity": []string{...}}` |
| `in_cisa_kev eq true` | `squirrel.Eq{"cves.in_cisa_kev": true}` |
| `cwe_ids contains_any [CWE-79]` | `squirrel.Expr("cves.cwe_ids && ?", pq.Array(vals))` |
| `cwe_ids contains_all [CWE-79]` | `squirrel.Expr("cves.cwe_ids @> ?", pq.Array(vals))` |
| `description_primary contains "apache"` | `squirrel.ILike{"cves.description_primary": "%apache%"}` |
| `description_primary starts_with "linux"` | `squirrel.ILike{...: "linux%"}` (lowercased) |
| `affected.ecosystem eq npm` | EXISTS subquery (see below) |
| `description_primary regex ".*rce.*"` | PostFilter only — not in SQL |

### Relational Field Strategy: EXISTS Subqueries

Both `affected.*` conditions and the watchlist pre-filter use EXISTS subqueries, not JOINs.
This prevents row multiplication (a CVE can have many affected packages) and composes
cleanly as `squirrel.Expr`.

Column names always use the unaliased `cves.` prefix — consistent with `FROM cves` (no alias)
in all query contexts including resolution detection subqueries.

**`affected.ecosystem eq npm`:**
```sql
EXISTS (
    SELECT 1 FROM cve_affected_packages cap
    WHERE cap.cve_id = cves.cve_id
      AND lower(cap.ecosystem) = lower($1)
)
```

**`affected.package contains "express"`:**
```sql
EXISTS (
    SELECT 1 FROM cve_affected_packages cap
    WHERE cap.cve_id = cves.cve_id
      AND lower(cap.package_name) ILIKE $1
)
```

**Watchlist pre-filter** (appended as AND when watchlistIDs non-empty):
```sql
EXISTS (
    SELECT 1 FROM watchlist_items wi
    WHERE wi.watchlist_id = ANY($1::uuid[])
      AND wi.org_id       = $2              -- explicit tenant isolation (workerTx bypasses RLS)
      AND wi.deleted_at IS NULL
      AND (
          (wi.item_type = 'package' AND EXISTS (
              SELECT 1 FROM cve_affected_packages cap
              WHERE cap.cve_id = cves.cve_id
                AND lower(cap.ecosystem)    = lower(wi.ecosystem)
                AND lower(cap.package_name) = lower(wi.package_name)
          ))
          OR
          (wi.item_type = 'cpe' AND EXISTS (
              SELECT 1 FROM cve_affected_cpes cac
              WHERE cac.cve_id      = cves.cve_id
                AND cac.cpe_normalized LIKE (wi.cpe_normalized || '%')
          ))
      )
)
```

### Regex Guardrails

Regex conditions become `PostFilters` only. The candidate cap (5,000) is enforced by the
evaluator (not the compiler) via `LIMIT 5001`. If `len(results) > 5000`: mark run
`status=partial`, emit metric, return without firing alerts (fail-closed).

Compiled `*regexp.Regexp` objects are cached in the evaluator's `RuleCache` (see §3).

### Nil-Safe Accessors (accessor.go)

Used in regex post-filter loop to safely dereference optional CVE fields:

```go
func CVSSV3Score(c *store.CVE) float64 {
    if c == nil || c.CvssV3Score == nil { return 0 }
    return *c.CvssV3Score
}

func EPSSScore(c *store.CVE) float64 {
    if c == nil || c.EpssScore == nil { return 0 }
    return float64(*c.EpssScore)
}

func DescriptionPrimary(c *store.CVE) string {
    if c == nil { return "" }
    return strings.ToLower(c.DescriptionPrimary)
}
```

---

## Section 3: Alert Evaluator

### Package

```
internal/alert/
  evaluator.go   — three evaluation paths + activation scan + zombie sweeper
  cache.go       — CompiledRule cache (sync.RWMutex, keyed by rule_id+dsl_version)
```

### Evaluator Struct

```go
type Evaluator struct {
    db    *pgxpool.Pool
    cache *RuleCache
    log   *slog.Logger
}

func (e *Evaluator) EvaluateRealtime(ctx context.Context, cveID string) error
func (e *Evaluator) EvaluateBatch(ctx context.Context) error
func (e *Evaluator) EvaluateEPSS(ctx context.Context) error
func (e *Evaluator) EvaluateActivation(ctx context.Context, ruleID uuid.UUID, orgID uuid.UUID) error
func (e *Evaluator) SweepZombieActivations(ctx context.Context) error
```

### RuleCache

```go
type RuleCache struct {
    mu    sync.RWMutex
    rules map[cacheKey]*dsl.CompiledRule
}
type cacheKey struct {
    ruleID     uuid.UUID
    dslVersion int
}

func (c *RuleCache) Get(ruleID uuid.UUID, dslVersion int) (*dsl.CompiledRule, bool)
func (c *RuleCache) Set(key cacheKey, rule *dsl.CompiledRule)
func (c *RuleCache) Evict(ruleID uuid.UUID) // called by handler on rule update/delete
```

Cache is local to the process. Entries evicted on rule update/delete. No TTL.

### Merge Pipeline → Realtime Trigger (Transactional Outbox)

The merge pipeline inserts a job in the **same transaction** as the CVE write, only when
`material_hash` changed:

```go
// In merge transaction after CVE upsert
_, err = tx.Exec(ctx, `
    INSERT INTO job_queue (queue, lock_key, payload, status)
    VALUES ('alert:realtime', 'alert:realtime:' || $1,
            jsonb_build_object('cve_id', $1), 'pending')
    ON CONFLICT (lock_key) WHERE status IN ('pending', 'running') DO NOTHING
`, cveID)
```

Dedup semantics: rapid multi-source updates to the same CVE produce one job. The job
evaluates the final committed state. Batch evaluator is the durability backstop.
The merge package imports only the job_queue table — no import of `internal/alert`.

### Three Evaluation Paths

| Path | Queue | Cursor | Rules evaluated |
|---|---|---|---|
| Realtime | `alert:realtime` | N/A (single CVE) | `status='active' AND is_epss_only=false` |
| Batch | periodic, every 5 min | `feed_sync_state` row `alert:batch` | `status='active' AND is_epss_only=false` |
| EPSS | daily | `feed_sync_state` row `alert:epss` | `status='active' AND has_epss_condition=true` |

### Per-Rule Evaluation Loop (shared across paths)

For each active rule evaluated against a candidate CVE set:

```
1. Load/compile rule from cache (cache miss → compile from DB)
2. Build query:
   SELECT cve_id FROM cves
   WHERE <dsl_sql>
     AND status NOT IN ('rejected', 'withdrawn')
     AND cve_id = ANY($candidate_ids)   -- realtime: [$cveID]; batch: all changed since cursor
   LIMIT 5001                            -- cap enforcement (evaluator adds this, not compiler)
3. If len(results) > 5000:
   → INSERT alert_rule_run(status='partial', ...)
   → emit metric alert_eval_partial_total{rule_id=...}
   → RETURN (fail-closed, no alerts)
4. Apply PostFilters (regex on description_primary) → matched_cves
5. For each matched CVE:
   INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state=true,
                              first_fired_at=now(), last_fired_at=now(), times_fired=1,
                              suppress_delivery=$suppress)
   ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING RETURNING id
   → fan-out (Phase 3) only if id returned
6. Resolution detection (see below)
7. INSERT alert_rule_run(status='complete', candidates_evaluated, matches_found, ...)
```

`$suppress = true` during activation scans; `false` for all other paths.

**Batch cursor timing:** Captured at job start (before any queries), advanced only after
all rules successfully evaluated. CVEs modified during the batch run are caught by the
next batch.

### Resolution Detection

After evaluating a rule over changed CVEs, identify CVEs that previously matched but now
fail the DSL:

```sql
SELECT ae.cve_id
FROM alert_events ae
WHERE ae.rule_id        = $1
  AND ae.org_id         = $2
  AND ae.last_match_state = true
  AND EXISTS (
      SELECT 1 FROM cves
      WHERE cves.cve_id = ae.cve_id
        AND cves.date_modified_canonical > $cursor   -- or cves.cve_id = $cveID for realtime
        AND cves.status NOT IN ('rejected', 'withdrawn')
        AND NOT (<dsl_conditions>)   -- cves.* prefix works with unaliased FROM cves
  )
```

For each resolved CVE:
```sql
UPDATE alert_events SET last_match_state = false
WHERE rule_id = $1 AND org_id = $2 AND cve_id = $3
```

Phase 3 will enqueue a resolution notification here.

**EPSS re-escalation limitation:** EPSS changes do not affect `material_hash`. If a CVE
resolves (EPSS drops below threshold) and later re-escalates via EPSS alone, the
`ON CONFLICT DO NOTHING` will suppress re-firing (same material_hash). Per PLAN §10.4,
this is intentional: "A rule fires again only if material_hash changes."

### Activation Scan

Handler (202 response path):
```
1. INSERT alert_rules with status='activating'   ─┐
2. INSERT job_queue (queue='alert_activation',    ─┘ same transaction
       lock_key='alert:activation:<rule_id>',
       payload={rule_id, org_id})
3. Return 201 { id, status: "activating" }
```

Worker job (`EvaluateActivation`) — keyset pagination, 1,000-row batches:
```go
var lastID string
for {
    batch := SELECT cve_id, ... FROM cves
             WHERE cve_id > $lastID
               AND status NOT IN ('rejected', 'withdrawn')
             ORDER BY cve_id ASC LIMIT 1000
    if len(batch) == 0 { break }
    evaluateAndRecord(batch, rule, orgID, suppressDelivery=true)
    lastID = batch[len(batch)-1].CVEID
}
UPDATE alert_rules SET status='active' WHERE id=$ruleID AND org_id=$orgID
```

The activation scan writes `alert_events` with `suppress_delivery=true` to establish the
dedup baseline. Outbound notifications are not sent for these rows (Phase 3 delivery
skips `suppress_delivery=true` rows).

### Zombie Recovery

`SweepZombieActivations` runs every 5 minutes as a goroutine started by the `worker`
subcommand:

```sql
SELECT jq.id, jq.payload->>'rule_id' AS rule_id
FROM job_queue jq
WHERE jq.queue      = 'alert_activation'
  AND jq.status     = 'running'
  AND jq.locked_at  < now() - interval '15 minutes'
```

For each zombie job:
1. `UPDATE alert_rules SET status='error' WHERE id=$rule_id`
2. `UPDATE job_queue SET status='failed' WHERE id=$job_id`
3. Log + emit metric `alert_activation_zombie_total`

**Does NOT auto-retry** — marks error, user retries via PATCH. Auto-retry risks infinite
loop if the rule itself causes the crash.

### alert_rule_runs Write Policy

| Path | Write a run row when |
|---|---|
| Batch | Always (one row per rule per batch window) |
| EPSS | Always (one row per rule per EPSS run) |
| Realtime | Only on match (matches_found > 0) or error |
| Activation | One row tracking full scan (start → complete or error) |

---

## Section 4: HTTP API Surface

All paths under `/api/v1/orgs/{org_id}/`. Auth: all write ops require `member` role;
reads require `viewer`.

### Watchlist CRUD

| Method | Path | Response |
|---|---|---|
| `POST` | `/watchlists` | 201 |
| `GET` | `/watchlists` | 200 (keyset paginated, cursor on created_at DESC, id DESC) |
| `GET` | `/watchlists/{id}` | 200 (includes item_count via COUNT) |
| `PATCH` | `/watchlists/{id}` | 200 |
| `DELETE` | `/watchlists/{id}` | 204 |
| `POST` | `/watchlists/{id}/items` | 201 |
| `GET` | `/watchlists/{id}/items` | 200 (paginated; `?item_type=package\|cpe`) |
| `DELETE` | `/watchlists/{id}/items/{item_id}` | 204 |

**Create body:**
```json
{ "name": "string (≤255)", "description": "string?", "group_id": "uuid?" }
```
Name unique among non-deleted watchlists in org (partial unique index) → 409 on conflict.

**PATCH body** — all pointer types:
```json
{ "name": "*string?", "description": "*string?", "group_id": "*uuid?" }
```
`"group_id": null` in JSON → sets group_id to null (remove from group).
Omitting `group_id` → no change.

**Add item body:**
```json
// package
{ "item_type": "package", "ecosystem": "npm", "package_name": "express (≤255)", "namespace": "string? (≤255)" }
// cpe
{ "item_type": "cpe", "cpe_normalized": "cpe:2.3:... (≤512)" }
```
- `ecosystem` must be in whitelist: npm, pypi, maven, go, cargo, rubygems, nuget, hex, pub,
  swift, cocoapods, packagist → 422 if unknown
- CPE must match `^cpe:2\.3:` prefix → 422 if malformed
- Duplicate item → 409

**Deleted watchlist behavior:** When a watchlist is deleted, alert rules that reference its
ID continue to compile. The deleted watchlist contributes no CVE matches (`wi.deleted_at IS NULL`
in EXISTS subquery). No cascade to alert rules on watchlist delete.

### Alert Rule CRUD

| Method | Path | Response |
|---|---|---|
| `POST` | `/alert-rules/validate` | 200 (register BEFORE `/{id}` routes) |
| `POST` | `/alert-rules` | 201 |
| `GET` | `/alert-rules` | 200 (paginated; `?status=`) |
| `GET` | `/alert-rules/{id}` | 200 (includes full conditions) |
| `PATCH` | `/alert-rules/{id}` | 200 or see PATCH logic |
| `DELETE` | `/alert-rules/{id}` | 204 |
| `GET` | `/alert-rules/{id}/runs` | 200 (paginated, cursor on started_at DESC, id DESC) |
| `POST` | `/alert-rules/{id}/dry-run` | 200 |

**Create body:**
```json
{
  "name": "string (≤255)",
  "logic": "and | or",
  "conditions": [...],              // max 50
  "watchlist_ids": ["uuid", ...],   // max 10; all must belong to this org
  "enabled": true,
  "fire_on_non_material_changes": false
}
```

**Create logic:**
```
1. Validate DSL (compile + validate) → 422 on error
2. Validate watchlist_ids: all UUIDs belong to this org, deleted_at IS NULL → 422 if not
3. In single transaction:
   a. INSERT alert_rules (status = enabled ? 'activating' : 'draft',
                          has_epss_condition, is_epss_only from compiled rule)
   b. If enabled: INSERT job_queue (activation scan)
4. Evict rule from cache (defensive — new rule, but good habit)
5. Return 201 { id, status: "draft" | "activating" }
```

Always 201 (resource created). Status field communicates activation state.

**PATCH body** — all pointer types:
```json
{
  "name": "*string?",
  "logic": "*string?",
  "conditions": "*[]Condition?",
  "watchlist_ids": "*[]UUID?",      // [] means clear bindings; null means no change
  "enabled": "*bool?",
  "fire_on_non_material_changes": "*bool?"
}
```

**PATCH state machine:**

| Current status | PATCH action | Result |
|---|---|---|
| `activating` | DSL/watchlist change | **409 Conflict** — wait for scan to complete |
| `activating` | name/enabled change only | 200, update field only |
| `error\|draft\|disabled` | `enabled=true` | Re-activate: status='activating', enqueue scan, 200 |
| `active` | DSL/watchlist change | Re-activate: evict cache, status='activating', enqueue scan, 200 |
| `active` | name/fire_on_non_material change | 200, update field, no re-activation |

On DSL change: old `alert_events` rows are retained (§21 audit log). New activation scan
adds new baseline rows with `suppress_delivery=true`. Stale dedup is a known limitation.

**DELETE:** Sets `deleted_at`. Calls `cache.Evict(ruleID)`. `alert_events` rows retained.

**Response fields:**
- List (`GET /alert-rules`): `id, name, status, logic, watchlist_ids, has_epss_condition, is_epss_only, fire_on_non_material_changes, created_at, updated_at`
- Detail (`GET /alert-rules/{id}`): above + full `conditions` array + `last_run_at`

**Field asymmetry:** Input accepts `enabled: bool` (simple toggle); output returns
`status: string` (full state machine). This is intentional — document in API spec.

### Validate Endpoint

```
POST /api/v1/orgs/{org_id}/alert-rules/validate
Body: { "logic": "...", "conditions": [...], "watchlist_ids": ["uuid?"] }
```

Response always **200** (even when invalid — it's a successful validation response):
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    { "index": 0, "field": "description_primary",
      "message": "pattern shorter than 3 chars — trigram index won't help",
      "severity": "warning" }
  ],
  "is_epss_only": false,
  "has_epss_condition": false
}
```

Does not validate watchlist_ids ownership (pure in-memory operation, no DB queries).
Passes `hasWatchlists = len(watchlist_ids) > 0` to the DSL validator for regex guardrail.

**Routing note:** Register `/alert-rules/validate` before `/alert-rules/{id}` routes in chi.

### Dry-Run Endpoint

```
POST /api/v1/orgs/{org_id}/alert-rules/{id}/dry-run
```

Response 200:
```json
{
  "match_count": 47,
  "candidates_evaluated": 1250,
  "partial": false,
  "elapsed_ms": 234,
  "sample_cves": [{ "cve_id": "CVE-2024-...", "severity": "critical" }]
}
```

**Implementation — rollback transaction (per PLAN §10.6):**
```go
tx, _ := db.Begin(ctx)
defer tx.Rollback(ctx)  // always rollback; never commit

results, meta := evaluator.RunDryRun(ctx, tx, rule, orgID)
// Rollback called by defer — zero state persisted
```

Uses same evaluation code path as real evaluation. Rollback is defense-in-depth against
accidental alert_events writes. Apply `http.TimeoutHandler` with 30s to this handler.

### Alert Events List

```
GET /api/v1/orgs/{org_id}/alert-events
?rule_id=uuid
&cve_id=string
&last_match_state=bool
&since=RFC3339              -- filters first_fired_at >= since
&after=cursor              -- keyset cursor
&limit=int                 -- default 20, max 100
```

Keyset pagination on `(first_fired_at DESC, id DESC)`.

Response:
```json
{
  "events": [{
    "id": "uuid",
    "rule_id": "uuid",
    "cve_id": "CVE-...",
    "material_hash": "abc123",
    "last_match_state": true,
    "first_fired_at": "...",
    "last_fired_at": "...",
    "times_fired": 3,
    "suppress_delivery": false
  }],
  "next_cursor": "..."
}
```

### Handler Dependencies

```go
type WatchlistHandler struct {
    store store.WatchlistStore
    log   *slog.Logger
}

type AlertRuleHandler struct {
    store     store.AlertRuleStore
    evaluator *alert.Evaluator  // for dry-run
    queue     worker.Enqueuer   // for activation job enqueue
    cache     *alert.RuleCache  // for eviction on save/delete
    log       *slog.Logger
}
```

---

## Appendix: Test Inventory

The tests listed below are a **starting point**. During implementation, additional test
cases will emerge — implement those too. The goal is comprehensive behavioral coverage,
not just the cases listed here.

### DSL Compiler

| Scenario | Expected outcome |
|---|---|
| Unknown field name | `ValidationError{severity: "error"}` |
| Invalid op for field kind (`cwe_ids gt 5`) | `ValidationError{severity: "error"}` |
| Regex, no selective prefilter, no watchlists | `ValidationError{severity: "error"}` |
| Regex, no selective prefilter, but watchlists present | valid |
| Regex pattern > 256 chars | `ValidationError{severity: "error"}` |
| Invalid regex syntax | `ValidationError{severity: "error"}` |
| `contains` pattern < 3 chars | `ValidationError{severity: "warning"}` (not error) |
| Empty conditions array | `ValidationError{severity: "error"}` |
| `severity eq "unknown_value"` | `ValidationError{severity: "error"}` |
| `date_published gt "not-a-date"` | `ValidationError{severity: "error"}` |
| `cvss_v3_score gte 7.0` | compiles to `squirrel.GtOrEq{"cves.cvss_v3_score": 7.0}` |
| `severity in ["high", "critical"]` | compiles to `squirrel.Eq{"cves.severity": [...]}` |
| `description_primary contains "apache"` | compiles to `squirrel.ILike{...: "%apache%"}` |
| `description_primary starts_with "Linux"` | compiles to ILIKE `"linux%"` (lowercased) |
| `description_primary regex ".*rce.*"` | PostFilter only — SQL predicate is empty/other |
| `affected.ecosystem eq npm` | compiles to EXISTS subquery on cve_affected_packages |
| Watchlist IDs provided | EXISTS subquery includes `wi.org_id = $orgID` |
| All conditions reference `epss_score` | `CompiledRule.IsEPSSOnly = true` |
| Any condition references `epss_score` | `CompiledRule.HasEPSS = true` |
| `affected.package regex ".*"` | `ValidationError` (regex not supported for kindAffected) |

### Alert Evaluator

| Scenario | Expected outcome |
|---|---|
| CVE matches rule | `alert_events` row inserted, RETURNING id non-empty |
| CVE does not match rule | no `alert_events` row |
| CVE with nil CVSS vs `cvss_v3_score gte 7.0` | no match (nil-safe accessor returns 0) |
| Same rule + CVE evaluated twice | second insert is DO NOTHING; no duplicate |
| Candidate count > 5000 | `alert_rule_run.status = "partial"`, zero alert_events inserted |
| Regex PostFilter: CVE description matches | match recorded |
| Regex PostFilter: CVE description does not match | no match |
| CVE previously matched (`last_match_state=true`), now fails DSL | `last_match_state = false` |
| EPSS-only re-escalation after resolution (same material_hash) | no re-alert (known limitation) |
| Activation scan on 2,500-row corpus (1,000-row pages) | all CVEs evaluated, no skips |
| Activation scan inserts | `suppress_delivery = true` on all rows |
| Activation scan completion | `alert_rules.status = 'active'` |
| Zombie job > 15 min | `alert_rules.status = 'error'`, run marked failed |
| Zombie sweeper does not auto-retry | rule stays 'error' until user PATCH |
| Realtime job dedup: two rapid CVE updates | one realtime job, not two |
| Rejected CVE update triggers realtime | rule `NOT IN ('rejected','withdrawn')` → no alert |
| Batch cursor not advanced on mid-run crash | re-processes from old cursor on restart |

### HTTP Handlers

| Scenario | Expected outcome |
|---|---|
| `POST /alert-rules` with enabled=true | 201, status='activating', job in job_queue |
| `POST /alert-rules` with enabled=false | 201, status='draft', no job enqueued |
| `POST /alert-rules` with invalid DSL | 422, no rule row, no job row |
| `POST /alert-rules` with foreign watchlist_id | 422, no rule created |
| `PATCH /alert-rules/{id}` on activating rule + DSL change | 409 |
| `PATCH /alert-rules/{id}` enabled=true on error-state rule | 200, status='activating', job enqueued |
| `PATCH /alert-rules/{id}` name change on active rule | 200, status stays 'active' |
| `DELETE /alert-rules/{id}` | cache evicted, deleted_at set, alert_events retained |
| `POST /alert-rules/validate` with invalid DSL | 200, `valid=false`, non-empty errors |
| `POST /alert-rules/validate` with warning-only | 200, `valid=true`, non-empty warnings |
| `POST /alert-rules/{id}/dry-run` | 200, zero rows in alert_events after call |
| `POST /alert-rules/{id}/dry-run` times out | 408 via TimeoutHandler |
| `GET /alert-events?rule_id=X` | only events for rule X |
| `GET /alert-events?last_match_state=false` | only resolution events |
| `POST /watchlists/{id}/items` with unknown ecosystem | 422 |
| `POST /watchlists/{id}/items` with malformed CPE | 422 |
| `POST /watchlists/{id}/items` duplicate | 409 |
| Viewer role on write endpoint | 403 |
| Wrong org_id in path | 403 or 404 (depending on membership check) |
