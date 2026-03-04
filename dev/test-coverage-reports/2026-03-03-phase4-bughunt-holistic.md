# Bug Hunt Report — Phase 4 (BH-J Holistic)

## Scope

Analyzed 20 source files across Phase 4 (AI/NL search, alert DSL, saved searches, quota management):

- `internal/ai/` — LLMClient interface, Gemini adapter, mock, quota resolution, sanitizer, schema
- `internal/alert/dsl/` — field registry, types, compiler, validator
- `internal/alert/evaluator.go` — realtime/batch/EPSS/activation evaluation paths
- `internal/store/dsl_executor.go` — DSL query execution with keyset pagination
- `internal/api/ai.go` — NL search and summarize HTTP handlers
- `internal/api/saved_searches.go` — saved search CRUD and execution
- `internal/api/server.go` — handler wiring and server construction
- `internal/store/ai.go` — quota tracking, caching, request logging store methods
- `internal/store/saved_search.go` — saved search store CRUD
- `cmd/cvert-ops/quota.go` — CLI quota override management
- `cmd/cvert-ops/main.go` — binary entrypoint, serve/worker/migrate commands
- `internal/config/config.go` — environment config
- `internal/metrics/ai.go` — Prometheus metrics for AI features

Read every source file in full, then analyzed cross-cutting correctness.

## Bugs

### 1. Float DSL conditions always compare against 0.0 — parse function returns value before Unmarshal writes it

**Location:** [compiler.go:142-145](internal/alert/dsl/compiler.go#L142-L145)
**Severity:** critical

**Evidence:**

```go
case kindFloat:
    return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
        var v float64
        return v, json.Unmarshal(raw, &v)
    })
```

In Go, `return v, json.Unmarshal(raw, &v)` evaluates the expressions left-to-right. The variable `v` is read (0.0 — the float64 zero value) and boxed to `interface{}` *before* `json.Unmarshal` is called. When Unmarshal writes the parsed value into `v` via pointer, the return value has already captured the pre-modification zero. The returned `interface{}` always contains `0.0`.

Compare with the correct `kindTime` implementation directly below (lines 147-153):

```go
case kindTime:
    return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
        var s string
        if err := json.Unmarshal(raw, &s); err != nil {
            return nil, err
        }
        return time.Parse(time.RFC3339, s)
    })
```

The time path correctly calls Unmarshal first, checks the error, then returns the parsed value. The float path does not follow this pattern.

**Impact:** Every float DSL condition (`cvss_v3_score`, `cvss_v4_score`, `epss_score`) compiles to a comparison against 0.0 instead of the user-specified value. A rule like `cvss_v3_score gte 9.0` becomes `cvss_v3_score >= 0.0`, matching nearly every CVE with a CVSS score. Affects all consumers of `dsl.Compile`:

- Alert evaluation (realtime, batch, EPSS, activation) — over-alerting on every rule with float conditions
- NL search — LLM-generated float conditions return wrong results
- Saved search execution — stored float queries return wrong results
- Dry-run — inflated match counts

The validator (`validator.go:121-124`) correctly parses the float value (using a separate `json.Unmarshal` + error check), so validation passes — the bug only manifests at compile time.

**Fix:** Split the Unmarshal and return:

```go
case kindFloat:
    return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
        var v float64
        if err := json.Unmarshal(raw, &v); err != nil {
            return nil, err
        }
        return v, nil
    })
```

### 2. PostFilter regex conditions use AND semantics regardless of rule logic — OR rules with regex produce wrong results

**Location:** [evaluator.go:520-542](internal/alert/evaluator.go#L520-L542) and [compiler.go:38-49](internal/alert/dsl/compiler.go#L38-L49)
**Severity:** significant

**Evidence:**

The compiler extracts `regex` conditions as PostFilters (Go-side regex matching) and keeps other conditions as SQL predicates. When the rule logic is OR, the SQL predicates are combined with `sq.Or{...}` (correct), but PostFilters are applied afterwards with AND semantics in `applyPostFilters`:

```go
// compiler.go:38-49 — regex conditions bypass SQL, become PostFilters
if c.Op == "regex" {
    // ...
    postFilters = append(postFilters, PostFilter{Negate: false, Pattern: re})
    continue
}
sqlParts = append(sqlParts, sqlizer)
```

```go
// evaluator.go:525-536 — PostFilters always use AND
for _, f := range filters {
    ok := f.Pattern.MatchString(c.Description)
    if f.Negate {
        ok = !ok
    }
    if !ok {
        pass = false
        break
    }
}
```

For a rule with `logic: "or"` and conditions `[severity eq "critical", description_primary regex "overflow"]`:

- **Expected:** CVEs where severity = critical **OR** description matches "overflow"
- **Actual:** CVEs where severity = critical **AND** description matches "overflow"

The SQL query returns candidates matching any SQL condition (OR), then PostFilters further restrict to only candidates also matching all regex patterns (AND). The PostFilters contradict the rule's OR semantics.

**Impact:** Alert rules and search queries with `logic: "or"` that mix SQL conditions with regex conditions will return fewer results than intended. Rules with `logic: "and"` are unaffected (AND + AND = correct). Pure-SQL rules (no regex) are unaffected.

## Design Concerns

### Regex PostFilter operates on lowered text without user-facing documentation

**Location:** [evaluator.go:432-433](internal/alert/evaluator.go#L432-L433)

The candidate query selects `COALESCE(lower(cves.description_primary), '')`, so all PostFilter regex matching runs against lowered text. User-supplied regex patterns are compiled as-is (case-sensitive). A regex like `CVE|CRITICAL` would never match because the text is lowered. This isn't a bug (the system is internally consistent), but users creating regex patterns need to know to use lowercase or `(?i)` flags. The system prompt for NL search doesn't mention this, and there's no validation warning when a regex pattern contains uppercase characters.

### Quota counter incremented before limit check — denied requests inflate the count

**Location:** [ai.go:115-131](internal/api/ai.go#L115-L131)

`IncrementAIUsage` is called before comparing against `dailyLimit`. If the quota is exceeded, the counter has already been incremented. Denied requests inflate the daily counter above the limit. This doesn't affect quota enforcement (exactly N requests per day are allowed), but the `ai_daily_usage.request_count` value exceeds the actual number of LLM calls made. Could confuse usage reporting.