# Phase 1 — Commit 5: NVD Feed Adapter

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/nvd/adapter.go`

## Files created

| File | Purpose |
|---|---|
| `internal/feed/nvd/adapter.go` | NVD API 2.0 adapter: dynamic rate limiting, 120-day window chunking, 15-min overlap, per-page resumable cursor, streaming JSON parser, CVSS v3.1/v3.0/v4.0, CWE extraction, CPE deduplication |

## Implementation decisions / discoveries

**Dynamic rate limiting from NVD_API_KEY env var** — Rate limit determined at `New()` time by checking `os.Getenv("NVD_API_KEY")`. With key: 50 req/30s → `rate.Every(600ms)`; without: 5 req/30s → `rate.Every(6s)`.

**`"apiKey"` header casing** — NVD API 2.0 requires exactly `apiKey` (lowercase `a`). Go's `http.Header.Set` canonicalizes header names, which would change this to `Apikey`. Added `//nolint:canonicalheader` comment. NVD's server is case-sensitive on this header.

**Timestamp params via `url.Values` + `Z` suffix** — Query parameters via `req.URL.Query()` → `q.Set(...)` → `req.URL.RawQuery = q.Encode()`. Format `"2006-01-02T15:04:05.000Z"` uses the `Z` UTC suffix to avoid the `+00:00` form entirely (no `%2B` encoding needed).

**Cursor embeds window position + page offset** — `Cursor{WindowStart, WindowEnd, StartIndex}` persists both the date-range position and intra-window page offset. Partial failures mid-window resume from the exact page.

**120-day window + 15-minute overlap** — `windowMax = 120 * 24 * time.Hour`. After a window is exhausted, the next starts at `cur.WindowEnd - 15 minutes`. `computeNextCursor` returns nil when all available data is fetched.

**Response `timestamp` field for clock-skew safety** — NVD API 2.0 returns `timestamp` in the response body. Used as `effectiveNow` instead of `time.Now()` to avoid Docker container clock skew. Fallback chain: response body timestamp → HTTP `Date` header → `time.Now()`.

**`zeroValueCursor()` for full-history backfill** — Nil/empty cursor triggers full history backfill from `nvdEpoch = "2002-01-01"`.

**Streaming parse via Token()/More()** — `parseNVDResponse` navigates the top-level JSON object, processing the `"vulnerabilities"` array one record at a time. NVD pages can be >5 MB.

**NVD source preference for CVSS** — `pickPreferred(entries)` returns the `nvd@nist.gov`-sourced entry if present, else first entry.

**Attribution TODO** — Package comment includes `TODO(attribution): NVD notice required in UI per NVD ToU`. Phase 6+ frontend item per PLAN.md §3.2.

## Quality check results

**pitfall-check:** No issues found.
**golangci-lint:** 0 issues.
**build:** `go build ./internal/feed/nvd/...` clean.

## Open items carried forward

- [ ] Commit 6: OSV adapter (`internal/feed/osv/adapter.go`) — ZIP streaming, alias resolution, late-binding PK migration, withdrawn tombstoning
- [ ] Phase 6+: Add NVD attribution notice to UI per NVD ToU
