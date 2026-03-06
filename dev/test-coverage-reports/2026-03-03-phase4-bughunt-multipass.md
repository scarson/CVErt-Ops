# Bug Hunt Report — BH-K: Multi-Pass (Phase 4)

**Date:** 2026-03-03
**Variant:** Multi-pass (5 focused analysis passes)
**Scope:** Phase 4 — AI features, alert DSL, saved searches, quota management

## Scope

### Files analyzed (21 files)
- `internal/ai/ai.go` — LLMClient interface and types
- `internal/ai/gemini.go` — Gemini adapter
- `internal/ai/mock.go` — Mock LLM client
- `internal/ai/quota.go` — Quota resolution logic
- `internal/ai/sanitize.go` — Prompt injection sanitizer
- `internal/ai/schema.go` — DSL schema description generator
- `internal/alert/dsl/field.go` — DSL field registry
- `internal/alert/dsl/types.go` — DSL IR types
- `internal/alert/dsl/compiler.go` — DSL → SQL compiler
- `internal/alert/dsl/validator.go` — DSL semantic validation
- `internal/alert/dsl/parser.go` — DSL JSON parser
- `internal/alert/evaluator.go` — Alert evaluation (realtime, batch, EPSS, activation)
- `internal/store/dsl_executor.go` — DSL query executor with pagination
- `internal/api/ai.go` — AI HTTP handlers (NL search, summarize)
- `internal/api/saved_searches.go` — Saved search CRUD + execution handlers
- `internal/api/server.go` — Server struct, constructor, route wiring
- `internal/store/ai.go` — AI quota/cache/log store methods
- `internal/store/saved_search.go` — Saved search store methods
- `cmd/cvert-ops/quota.go` — CLI quota management
- `cmd/cvert-ops/main.go` — Binary entry point, serve/worker/migrate
- `internal/config/config.go` — Environment configuration
- `internal/metrics/ai.go` — Prometheus AI metrics

### Passes performed
1. Contract Violations
2. Cross-Sibling Pattern Violations
3. Failure Mode Reasoning
4. Concurrency Reasoning
5. Error Propagation

---

## Bugs

### Float parse lambda in DSL compiler always returns zero

**Location:** `internal/alert/dsl/compiler.go:142-145`
**Severity:** critical
**Found in:** Pass 1 — Contract Violations

**Evidence:**

The `kindFloat` case in `conditionToSQL` passes this lambda to `numericSQL`:

```go
case kindFloat:
    return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
        var v float64
        return v, json.Unmarshal(raw, &v)
    })
```

In Go, `return v, json.Unmarshal(raw, &v)` evaluates `v` (reading 0.0, the zero value) **before** `json.Unmarshal` modifies it. The Go specification states that the order of variable reads vs function calls in a return statement is unspecified, but in practice (gc compiler) the left operand `v` is read first. Either way, this code at best depends on unspecified behavior, and with current compilers returns `(0.0, nil)` regardless of the input JSON.

Compare with the `kindTime` lambda (compiler.go:147-153), which does it correctly:

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

And the validator (validator.go:121-124) correctly unmarshals into a separate step — the parse succeeds, so validation passes, but compilation produces the wrong value.

**Impact:**

Every DSL rule with a float condition (`cvss_v3_score`, `cvss_v4_score`, `epss_score`) compiles to a comparison against **0** instead of the user-specified value.

- `{"field": "cvss_v3_score", "operator": "gte", "value": 7.0}` → `cves.cvss_v3_score >= 0` (should be `>= 7.0`)
- Alert rules with CVSS/EPSS thresholds match far more CVEs than intended
- NL search queries involving numeric thresholds return incorrect results
- Saved searches with float conditions execute incorrectly
- EPSS evaluation path fires on nearly all CVEs with any EPSS score

This affects all three alert evaluation paths (realtime, batch, EPSS), NL search, saved search execution, dry-run, and activation scan.

**Fix:**

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

---

## Design Concerns

### Batch cursor advances past failed evaluations

In `EvaluateBatch` (evaluator.go:106-144), the cursor is always advanced to `batchTime` at the end of the function, even when individual rule evaluations fail. If `evaluateRule` returns an error for a particular rule (e.g., transient DB error during `InsertAlertEvent`), the error is logged but the loop continues. The CVEs from that batch will not be re-evaluated for the failed rule on the next batch run.

This is likely an intentional design choice (advancing the cursor prevents infinite reprocessing), but it means transient failures can cause permanent event gaps for individual rules. A more resilient approach would track per-rule cursors or re-enqueue failed rules, but this would add significant complexity.

### Quota counter drifts on denial

In `nlSearchHandler` and `summarizeHandler`, the quota counter is incremented *before* checking whether the new count exceeds the limit. On denial, the counter is not decremented. This causes the counter to drift above the limit over the course of a day. This has no practical impact (any value > limit produces the same "denied" result, and counters reset daily), but it means the counter does not accurately reflect actual usage.