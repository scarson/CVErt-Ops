# MATCH-2 measurements on the kept ingest: the limit-rule gate fails

## What was built

| Feature | Files | Description |
|---|---|---|
| Measurement harness | `internal/alert/kept_ingest_measure_test.go` | Build tag `keptingest`. Read-only connection (checked), `BEGIN READ ONLY` per statement, credentials from their own variables and never in a URL; connect errors report only the error class and host:port (a sentinel test checks this). Runs `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` three times on statements built by `candidateQuery` and by a rebuild of `ExecuteDSLQuery`'s page; walks the corpus as `EvaluateActivation` does for M8's read-only estimate; `TestKeptIngestLimitSweep` measures smaller limits and serial execution. |
| M8 activation on a copy | `internal/alert/kept_ingest_activation_test.go` | Migrates a disposable restored copy, creates an organisation and the limit rule with status `activating`, and times `EvaluateActivation`. Refuses to run unless `KEPT_INGEST_COPY_CONFIRM` names the copy. |
| Results | `dev/plans/2026-11-13-product-match-rules-measurements.md` | Method, inputs, the design section 13 table, M8, the sweep, and the failing rows. |

## Key decisions

- **The gate failed, so Phase 4 is deferred** (plan Task 4.3). Single-product, package-with-ecosystem and saved-search statements pass with wide margins (realtime under 1 ms, batch under 70 ms, Node dry-run 3.5 ms). The 50-product/100-condition limit rule under `or` fails realtime (23.3 ms against 5 ms, mostly planning), dry-run and batch (shared-memory error at 64 MB `/dev/shm`; 27.6 s and 17.7 s serially), and the full activation (shared-memory error on page 1). 50 products under `or` fail dry-run at 16.2 s.
- **No remedy was implemented.** Sam chooses; the plan forbids building one first.
- **The kept ingest was only read.** M8's full activation ran on a disposable copy restored from the kept backup, which Sam approved; the copy stays for re-measurement and Task 5.5.

## Gotchas discovered

- **Docker's default 64 MB `/dev/shm` breaks large parallel hashes** with `could not resize shared memory segment ... No space left on device`. No compose file in `docker/` sets `shm_size`. Raised with Sam separately; not part of this change.
- **Package conditions with no ecosystem dominate the cost.** The most common package names are Linux kernel flavours on 19,399 to 131,545 rows each, so each such set is large; 5 products and 5 such packages already take 3.5 s dry-run.
- **`tar` on Windows reads `C:` in a path as a remote host;** pass `--force-local`.

## Quality checks

- `go vet -tags keptingest ./internal/alert/`: clean.
- golangci-lint v2.15.0 with `--build-tags keptingest` on `./internal/alert/`: 0 issues (two inline `gosec` suppressions with reasons: a fake sentinel credential, and SQL built from `ecosystem.FoldedNameSQL`'s fixed text).
- The harness is excluded from the normal suite by its build tag.
