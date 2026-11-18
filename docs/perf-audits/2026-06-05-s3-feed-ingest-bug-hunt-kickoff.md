# Bug-hunt kickoff — suspected bugs from the 2026-06-05 S3 feed-ingest performance audit

Run: `bug-hunt-cycle` with the scope below.

**Scope:** `internal/feed/epss/adapter.go`, `internal/feed/osv/adapter.go`, `internal/feed/nvd/adapter.go`,
and the ingest loop `internal/ingest/handler.go`. These surfaced incidentally during the S3 performance
audit and were NOT investigated as bugs.

**Seed findings (verify, don't trust — surfaced during a perf audit, not confirmed):**
- **EPSS partial run persisted as complete** — `internal/feed/epss/adapter.go:202-232`. If the ~250k-row
  serial apply loop exceeds the 10-min `maxJobDuration`, `ctx` cancels, every remaining row's
  `applyRowFn` errors → logged-and-`continue`d, then `Apply` returns a fresh next cursor as if the run
  succeeded — recording a partial run as complete and skipping re-download via the `score_date`
  short-circuit. (Co-located with perf finding P1; the EPSS batching fix will touch this code.)
- **Pre-merge hash read races the merge** — `internal/ingest/handler.go:167`. The pre-merge
  `GetCVEMaterialHash` is an autocommit read *outside* the per-CVE advisory-locked merge tx, so the
  change-detection compare can race a concurrent writer. (Resolved by perf finding P4, which removes
  both reads in favor of a merge-returned change signal.)
- **OSV `isAdvisoryEntry` overly permissive** — `internal/feed/osv/adapter.go`. Buffers ZIP entries it
  later discards (wasted work; check whether any non-advisory entries are mis-accepted).
- **NVD swallows `RawPayload` marshal errors** — `internal/feed/nvd/adapter.go:398-415`. Marshal error is
  ignored; a record could persist with an empty/!partial raw payload silently.
- **`resolve` silently drops a source on malformed `normalized_json`** — `internal/merge/resolve.go:90-94`.
  `continue` with no log/metric — a corrupt source row vanishes from the canonical merge invisibly.

These were noticed while auditing performance and were NOT investigated. Treat them as leads for the
hunters, not confirmed bugs.
