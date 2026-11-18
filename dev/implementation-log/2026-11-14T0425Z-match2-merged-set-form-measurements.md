# MATCH-2: measurements of the limit rule as two set conditions

## What was built

| Feature | Files | Description |
|---|---|---|
| Merged-form measurement | `internal/alert/kept_ingest_measure_test.go` | `TestKeptIngestMergedForms` (build tag `keptingest`, read-only): the limit rule's 50 products as one `affected.cpe_product in` and its 50 packages as one `affected.package in`, under `or`, with JIT on and off. Results appended to `dev/plans/2026-11-13-product-match-rules-measurements.md`. |

## Key decisions

- Evidence for the Phase 4 gate decision only; no remedy is implemented until Sam chooses. In this form batch passes (1.7 s, 0.51 s with JIT off), dry-run still fails (shared-memory error, or 8.0 s for products alone, 3.9 s with JIT off), and realtime still fails on planning (10.7 ms).

## Quality checks

- `go vet -tags keptingest ./internal/alert/`: clean. Build-tagged, so the normal suite never runs it.
