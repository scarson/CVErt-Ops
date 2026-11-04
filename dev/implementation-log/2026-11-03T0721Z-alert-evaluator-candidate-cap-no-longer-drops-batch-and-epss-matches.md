# Alert Evaluator — Candidate Cap No Longer Drops Batch and EPSS Matches

> **Date:** 2026-11-03
> **Branch:** `fix/alert-candidate-cap-batch`
> **Source:** investigation of whether batch/EPSS evaluation loses matches when a rule hits the 5,000-row candidate cap

## What was built

| Part | Files | Description |
|---|---|---|
| Chunked evaluation | `internal/alert/evaluator.go` | `evaluateRuleInChunks` runs `evaluateRule` over the run's changed CVE IDs in chunks of at most `candidateCap` IDs; `evaluateBatchPath` calls it for both the batch and EPSS paths. One run row per rule per run, with summed counts |
| Spec | `PLAN.md` §10.2 | The cap bounds a single prefilter query; batch and EPSS evaluate in chunks; dry-run keeps the fail-closed cap |

## Key implementation decisions

- **Chunk instead of holding the cursor or adding a per-rule cursor**: a rule that overflows the cap on one run overflows on every later run, so holding the global cursor would stall every rule, and a per-rule cursor would still never let the broad rule fire. Chunking produces a complete evaluation, which is what the fail-closed rule protects. Activation already pages the corpus the same way.
- **Chunk size is `candidateCap`**: the prefilter returns at most one row per candidate ID (the only DSL join is the 1:1 `cve_search_index`), so a chunk of that size cannot overflow. If a later join breaks that, the chunk returns partial and the run is recorded as partial rather than silently dropping CVEs.

## Gotchas discovered

- **The EPSS path had no fallback**: realtime evaluation covers most batch-path changes, but EPSS score changes do not alter `material_hash` and never trigger realtime evaluation. The daily EPSS update touches most of the corpus, so a rule such as `epss_score >= 0.1` was partial on every run and never fired.
- **A rule error still advances the cursor**: a statement timeout or other error on one rule loses that run's CVEs for that rule. Not addressed here.
- **PLAN §10.2's partial metric and log entry are not emitted**: after this change only dry-run can return partial, and it reports `Partial` to the caller.

## Quality checks

- **golangci-lint:** 0 issues on `internal/alert`
- **New tests:** `TestEvaluateBatch_RuleMatchingMoreThanCandidateCap`, `TestEvaluateEPSS_RuleMatchingMoreThanCandidateCap` (5,100 matching CVEs; failed with 0 events before the fix)
