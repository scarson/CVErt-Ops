# Phase 10 — Test Fixture Corpus + MSRC/GHSA Adapter Fixes

> **Date:** 2026-03-19 to 2026-04-05
> **Commits:** `95fde73`..`7f113fc` on `phase10/test-fixture-corpus` (merged to dev)
> **Plan:** `dev/plans/2026-03-15-phase10-test-fixture-corpus-plan.md`, `dev/plans/2026-03-19-phase10-msrc-csaf-fix-plan.md`

## What was built

| Feature | Files | Description |
|---|---|---|
| Feed capture CLI | `dev/cmd/capture-feeds/main.go`, `internal/feed/recording.go` | Recording HTTP transport + CLI to snapshot all 8 feed APIs to `.data/feed-snapshots/` |
| Fixture extraction tool | `dev/cmd/extract-fixtures/main.go` | Extracts curated CVE subsets from bulk captures into `testdata/golden/` per adapter |
| Golden file test helpers | `internal/testutil/golden.go`, `internal/testutil/rewrite.go` | `NewGoldenServer` (serves fixture dirs) + `NewURLRewriteTransport` (redirects adapter URLs to test servers) |
| Golden file tests (7 adapters) | `internal/feed/{nvd,kev,ghsa,mitre,osv,msrc,redhat}/golden_test.go` | Real captured API responses served via httptest; catches upstream schema drift |
| EPSS golden file test | `internal/feed/epss/golden_test.go` | Seeds NVD CVEs via merge pipeline, applies EPSS scores, verifies DB values (testcontainer) |
| SeedCorpus helper | `internal/testutil/seedcorpus.go`, `seedcorpus_test.go` | Runs all 8 adapters against golden fixtures through merge pipeline into test DB; 65 CVEs from 8 feeds |
| MSRC adapter rewrite | `internal/feed/msrc/adapter.go` | Fixed broken `/csaf/{id}` endpoint → real CSAF 2.0 static files via `changes.csv` discovery at `msrc.microsoft.com/csaf/advisories/` |
| GHSA references fix | `internal/feed/ghsa/adapter.go` | `references` field is `[]string` (bare URLs), not `[]ghsaReference` objects; was silently dropping 100% of advisories |

## Key implementation decisions

- **MSRC: CSAF static files over CVRF API** — Microsoft publishes CSAF 2.0 files at `msrc.microsoft.com/csaf/advisories/` with `changes.csv` for incremental sync. The API's `/cvrf/v3.0/csaf/{id}` endpoint never existed; `/cvrf/{id}` returns CVRF format (different schema). CSAF files use the existing `csaf.Parse()` — no parser changes needed.
- **Import cycle avoidance** — `testutil/seedcorpus.go` imports adapter packages. Internal adapter tests (`package msrc`) cannot import `testutil` without a cycle. Solution: local `redirectTransport` in internal tests; external test packages (`package msrc_test`) use `testutil.NewURLRewriteTransport`.
- **SeedCorpus uses `minFeeds` threshold** — allows individual feed failures (GHSA was broken until the reference fix) without blocking the entire test.
- **CVE-2026-3909 replaced with CVE-2026-32194** — original manifest CVE had no CSAF file in Microsoft's distribution; replacement provides equivalent coverage.

## Gotchas discovered

- **MSRC adapter was always broken against real data** — 8 hand-crafted unit tests passed, but the `/csaf/{id}` endpoint never existed on the real API. The adapter only worked against synthetic test fixtures. Golden file tests exist specifically to catch this class of bug.
- **GHSA `references` is `[]string` not `[]object`** — GitHub REST API returns bare URL strings, not `{"url": "..."}` objects. Every advisory failed unmarshal, silently dropping 100% of records. Another case where unit tests with hand-crafted fixtures masked a real integration failure.
- **Docker Desktop pause after WSL reinstall** — testcontainers fail with "No such container" when Docker Engine is paused. Restart Docker Desktop (not just Resume) after WSL changes.

## Quality checks

- **go build ./...:** Clean (backend packages; `web/dist/` absent in worktree — expected)
- **Tests:** 12/12 packages pass — `internal/feed/...` (11 packages) + `internal/testutil/...` (1 package, includes SeedCorpus with 65 CVEs from 8 feeds)
- **Code review:** MSRC adapter rewrite reviewed via spec compliance + code quality subagents; GHSA fix reviewed manually
- **New tests:** 7 golden file tests, 1 EPSS golden test (testcontainer), 1 SeedCorpus integration test, `TestParseChangesCSV`, 4 MSRC Fetch tests rewritten
