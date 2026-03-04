# Bug Hunt Report — Phase 4 (Exploratory)

**Date:** 2026-03-03
**Variant:** BH-L (Exploratory — depth-first from high-risk code)
**Scope:** AI features (NL search, summarization, Gemini client, quota), DSL compiler/validator/evaluator, saved searches, DSL executor

## Scope

Files analyzed (deeply explored):
- `internal/alert/dsl/compiler.go` — DSL compilation, high-risk: SQL generation, PostFilter creation
- `internal/alert/evaluator.go` — alert evaluation paths, high-risk: multi-step query + insert + resolution
- `internal/store/dsl_executor.go` — DSL query execution, high-risk: shared by NL search + saved searches
- `internal/api/ai.go` — NL search + summarize handlers, high-risk: quota, caching, DSL compilation/execution
- `internal/api/saved_searches.go` — saved search CRUD + execute, high-risk: RBAC + DSL execution
- `internal/ai/gemini.go` — Gemini adapter, moderate risk: external API
- `internal/ai/quota.go` — quota resolution, low risk: simple logic
- `internal/ai/sanitize.go` — LLM input sanitization, moderate risk: security boundary

Files read but not deeply explored (lower risk):
- `internal/alert/dsl/types.go`, `field.go`, `validator.go` — DSL IR, field registry, validation
- `internal/store/ai.go`, `saved_search.go` — store methods (straightforward CRUD wrappers)
- `internal/ai/ai.go`, `mock.go`, `schema.go` — interface, mock, prompt generation
- `cmd/cvert-ops/quota.go` — CLI quota management
- `internal/config/config.go` — config fields
- `internal/metrics/ai.go` — Prometheus counters
- `internal/api/server.go` — route registration (spot-checked)

**Strategy:** Started with the evaluator (orchestrates multi-step flows) and DSL compiler (generates SQL). Followed the PostFilter thread from compiler → evaluator (works correctly) → ExecuteDSLQuery (drops PostFilters). Then traced the NL search and saved search handlers end-to-end. Checked quota increment-then-check flow, cache hit/miss paths, tier resolver injection, and sanitization.

## Bugs

### 1. ExecuteDSLQuery silently drops regex PostFilters

**Location:** `internal/store/dsl_executor.go:118-194`
**Severity:** significant
**Evidence:**

The DSL compiler (`compiler.go:38-49`) converts `regex` conditions into `PostFilter` objects (in-memory regex matchers) rather than SQL predicates, because PostgreSQL regex matching on large text columns is expensive. The alert evaluator correctly applies these PostFilters after the SQL query (`evaluator.go:372`):

```go
matched := applyPostFilters(candidates, compiled.PostFilters)
```

However, `ExecuteDSLQuery` — the query execution path used by NL search and saved search execution — only applies `compiled.SQL` and `compiled.Joins` (lines 131-134). It never calls `applyPostFilters` or any equivalent:

```go
// Line 132: applies SQL predicate
if compiled.SQL != nil {
    sb = sb.Where(compiled.SQL)
}
// ... but PostFilters are never applied to the results
```

Callers that hit this path:
- `internal/api/ai.go:194` — NL search handler
- `internal/api/saved_searches.go:436` — saved search execute handler

Neither caller applies PostFilters after receiving results from `ExecuteDSLQuery`.

**Impact:** If the LLM generates a DSL rule with a `description_primary` regex condition (the schema description instructs it that `regex` is a valid operator), or if a user creates a saved search with a regex condition, the regex filter is silently ignored. Results include CVEs that should have been filtered out by the regex. The `interpreted_query` JSON response shows the regex condition, making the behavior misleading — the user sees the regex in the interpreted query but the results don't reflect it.

The alert evaluation path (realtime, batch, EPSS, activation) is NOT affected — `evaluateRule` correctly applies PostFilters.

## Design Concerns

### PostFilter.Negate is unreachable

`PostFilter` has a `Negate bool` field (`types.go:49`) and `applyPostFilters` handles negation (`evaluator.go:529-531`), but no code path ever creates a PostFilter with `Negate: true`. The compiler always sets `Negate: false` (`compiler.go:47`). The DSL has no `not_regex` or negated regex operator. The negation handling is dead code.

This isn't a bug today, but if a `not_regex` operator is added in the future, someone might assume the plumbing already works end-to-end. It does in the evaluator, but not in `ExecuteDSLQuery` (see Bug #1).

### Float parser uses `return v, json.Unmarshal(raw, &v)` pattern

The float64 parse closure in `compiler.go:142-145` uses:

```go
func(raw json.RawMessage) (interface{}, error) {
    var v float64
    return v, json.Unmarshal(raw, &v)
}
```

This pattern reads `v` and calls `json.Unmarshal(raw, &v)` in the same return statement. The Go spec does not guarantee the order of variable reads relative to function calls in return statements ("the order of those events compared to the evaluation and indexing of x and the evaluation of y is not specified" — Go spec). Tests confirm this works correctly with the current gc compiler (TestCompile_FloatGTE, TestCompile_FloatEq, TestCompile_FloatValueIsParameterized all pass with correct values in args), but the code relies on unspecified behavior.

The time parser (`compiler.go:147-153`) does NOT have this issue — it calls `json.Unmarshal` first, then passes the result to `time.Parse` as a function argument, which is guaranteed to be evaluated before the function call.

A safer pattern would be:
```go
func(raw json.RawMessage) (interface{}, error) {
    var v float64
    if err := json.Unmarshal(raw, &v); err != nil {
        return nil, err
    }
    return v, nil
}
```