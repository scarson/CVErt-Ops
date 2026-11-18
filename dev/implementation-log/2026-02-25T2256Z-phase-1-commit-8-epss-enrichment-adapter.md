# Phase 1 — Commit 8: EPSS Enrichment Adapter

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/epss/adapter.go`, `internal/feed/epss/adapter_test.go`

## Files created

| File | Purpose |
|---|---|
| `internal/feed/epss/adapter.go` | EPSS enrichment adapter: gzip CSV streaming, line-1 comment parsing, two-statement IS DISTINCT FROM pattern with per-CVE advisory lock |
| `internal/feed/epss/adapter_test.go` | Unit tests for parseLine1, score_date RFC3339 format verification, null byte stripping, rate limiter non-nil |

## Implementation decisions / discoveries

**Does NOT implement `feed.Adapter`** — EPSS is an enrichment adapter, not a CVE source. It exposes `Apply(ctx, *store.Store, cursorJSON) (cursorJSON, error)` and writes directly to the DB via the two-statement pattern (PLAN.md §5.3).

**Domain change** — Canonical URL is `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`. The old domain `epss.cyentia.com` redirects HTTP 301 to this domain. Verified via `curl` on 2026-02-25.

**`score_date` is RFC3339, not a plain date** — Line 1 of the CSV is `#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z`. The `score_date` field contains a full RFC3339 timestamp (including time component), not a plain `YYYY-MM-DD` date. Training data had this wrong. Verified live. Uses `feed.ParseTime()` multi-layout parser.

**`bufio.Reader` for line 1, `encoding/csv` for the rest** — `bufio.NewReader(gz).ReadString('\n')` reads the non-CSV comment line. The same `bufio.Reader` is passed to `csv.NewReader`, which picks up from line 2 onward. First `cr.Read()` discards the CSV header line 2. `cr.ReuseRecord = true` avoids one allocation per row; CVE ID cloned via `strings.Clone` before next read.

**Two-statement pattern, advisory lock** — Per PLAN.md §5.3 and pitfall §2.8:
- Per-row transaction begins → `pg_advisory_xact_lock(merge.CVEAdvisoryKey(cveID))` (same key as merge pipeline, prevents TOCTOU race)
- Statement 1 (`UpdateCVEEPSS`): `UPDATE cves SET epss_score=... WHERE ... IS DISTINCT FROM ...` — no-op if unchanged
- Statement 2 (`UpsertEPSSStaging`): `INSERT INTO epss_staging WHERE NOT EXISTS (SELECT 1 FROM cves ...)` — only writes if CVE not yet in corpus
- Both statements run unconditionally; `RowsAffected` never inspected

**Short-circuit cursor check** — If `cursor.score_date` date (UTC) matches today's UTC date, skip the download. File is published once daily; the 24h rate limiter is a second guard.

**Model version warning** — `slog.WarnContext` when `model_version` changes between runs — all ~250k scores shift non-incrementally and analysts may want to know why alert thresholds behave differently.

**research-findings directory moved** — User moved `docs/research-findings/` to `dev/research-findings/` (end-user docs vs developer reference). Git history records the move.

## Quality check results

**pitfall-check:** No issues found.
**golangci-lint:** 0 issues.
**go test:** All tests pass (`ok github.com/scarson/cvert-ops/internal/feed/epss`).
**build:** `go build ./internal/feed/epss/...` clean.

## Open items carried forward

- [x] Commit 9: CVE search + detail API (`internal/api/cves.go`) — see below
