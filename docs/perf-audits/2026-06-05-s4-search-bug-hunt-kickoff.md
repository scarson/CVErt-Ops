# Bug-hunt kickoff — suspected bugs from the 2026-06-05 S4 search/read performance audit

Run: `bug-hunt-cycle` with the scope below.

**Scope:** `internal/api/cves.go`, `internal/store/cve.go`, `internal/store/dsl_executor.go`,
`cmd/cvert-ops/main.go` (server wiring). Surfaced incidentally during the S4 performance audit.

**Seed findings (verify, don't trust):**
- **`http.TimeoutHandler` claimed but absent** — `cmd/cvert-ops/main.go:306` comment says `WriteTimeout`
  is "applied per-handler via http.TimeoutHandler", but no `http.TimeoutHandler` exists anywhere in
  `internal/api`. Missing protection + false comment. (Also perf finding P14; plan-compliance gap vs
  CLAUDE.md's HTTP-server requirement.)
- **(verify intent) EPSS range COALESCE sentinels** — `internal/store/cve.go:186-192`. `COALESCE(epss_score,
  -1) >= min` / `COALESCE(epss_score, 2) <= max` **exclude** NULL-EPSS rows when a filter is set, but the
  comment says COALESCE "guards against NULL rows being dropped." The behavior (exclude NULL-EPSS from an
  EPSS filter) is probably correct; the comment is likely wrong. Confirm intent, fix the comment or the code.
- **Three non-interchangeable cursor base64 codecs** — `internal/store/dsl_executor.go:93,102` uses padded
  `base64.URLEncoding` for the saved-search cursor while API-layer codecs use `RawURLEncoding`. A cursor
  minted on one path may fail to decode on another. Verify cross-path cursor interchange.

These were noticed while auditing performance and were NOT investigated. Treat as leads, not confirmed bugs.
