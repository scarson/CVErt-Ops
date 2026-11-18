# A regex rule without a watchlist needs a condition that narrows its candidates

## What was built

| Feature | Files | Description |
|---|---|---|
| Narrowing check | `internal/alert/dsl/validator.go` (`narrowingOps`, `narrowsCandidates`, `msgRegexNeedsNarrowing`) | The regex guardrail counts a condition only if its field and operator narrow the SQL candidates: `severity`, `affected.ecosystem`, `affected.cpe_product` with `eq`/`in`; `in_cisa_kev eq true`; dates with `gt`/`gte`/`eq`; any `affected.package` condition; `fts_query`. Before, any condition on a selective field counted, including `in_cisa_kev eq false`, `severity neq low` and `affected.ecosystem not_in`. |
| Message | same | Names the conditions that count. |
| Docs | `PLAN.md` §10.2 | One paragraph under the selective-constraint list. |
| Tests | `internal/alert/dsl/regex_rules_test.go` | `TestValidate_RegexNeedsANarrowingCondition`: 17 conditions beside a regex, with and without a watchlist. |

## Key decisions

- **Conditions under `or` need nothing here.** PR 247 refuses an `or` rule that combines regex with other conditions, so the only `or` regex rule left is all-regex, which the check already sends to a watchlist.
- **Validate only.** `Compile` keeps its check that some condition is not a regex. A stored rule that passed the old check still compiles and evaluates correctly; its prefilter is wider, and the candidate cap and chunking bound the cost.
- Found by the MATCH-2 `/plan-check` (product-match-rules plan, Discoveries).

## Quality checks

- The new test failed first on the 8 non-narrowing conditions, then passed; `go test ./internal/alert/dsl/`: pass.
- `go test ./internal/api/ -run 'AlertRule|Validate|Regex'`: pass.
