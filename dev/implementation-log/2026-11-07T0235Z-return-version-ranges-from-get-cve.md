# Return version ranges from GET /cves/{id}

## What was built

- `GET /api/v1/cves/{cve_id}` returns `affected_cpe_matches` (NVD ranges, `vulnerable` rows only) and `cna_affected` (CNA products and versions). Both serialize as `[]` when empty.
- `store.GetCVEVersionRanges` reads both tables. `GetCVEDetail` is unchanged rather than growing to seven return values.
- `openapi.json` and `web/src/lib/api/schema.d.ts` regenerated. The SPA does not display the new fields yet.

## Key decisions

- `affected_cpes` keeps its contents and gains an OpenAPI description saying it includes platforms NVD marks not vulnerable and pointing at `affected_cpe_matches`. Filtering it would hide the CPE that made a watchlist item match.
- `affected_cpe_matches` has no `vulnerable` field, because the read returns only `true` rows.

## Quality checks

- `go test ./internal/api/ -run 'TestGetCVE|TestOpenAPI'` with real golden records for the Node.js range (`23.0.0` up to `24.22.1`), a firmware CVE with a `vulnerable: false` hardware CPE, and a fastify CVE NVD has not analysed: pass.
- Live run, throwaway test: real NVD API, 595 real patches through the adapter and merge, then `GET` on `CVE-2026-56847` returned its three Node.js ranges.
- `npm run type-check` in `web`: pass after adding the new required fields to one test fixture.
