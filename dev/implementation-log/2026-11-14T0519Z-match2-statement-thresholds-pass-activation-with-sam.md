# MATCH-2: re-measured after parallel query off and one package branch per or rule

## What was built

| Feature | Files | Description |
|---|---|---|
| Re-measurement | `dev/plans/2026-11-13-product-match-rules-measurements.md` | Every Phase 4 row after `9d58ee1`, an interleaved comparison for M7d, and the M8 full activation on the disposable copy. |
| Design amendment | `dev/plans/2026-11-13-product-match-rules-design.md` section 17 | The query shape Sam chose at the gate, why, and the result; section 5 points to it. |
| Harness | `internal/alert/kept_ingest_measure_test.go` | `TestKeptIngestContainsInterleaved`; build tag `keptingest`, read-only. |

## Key decisions

- Every statement threshold passes at the original limits. M8 does not: 12 min 5 s against 7 minutes, of which about 8 minutes is 200,252 one-transaction event inserts. That cost follows the number of matching CVEs and applies equally to a broad scalar rule (`severity in [critical, high]` matches 182,637 CVEs), so it goes to Sam rather than to another query change.
- M7d is decided on five interleaved runs per form (3,324 ms against 3,330 ms), because single triples flipped by a few percent.

## Quality checks

- `go vet -tags keptingest ./internal/alert/`: clean; golangci-lint v2.15.0 with `--build-tags keptingest`: 0 issues.
