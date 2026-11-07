# Read CNA data from NVD's relay

## What was built

- The NVD adapter reads `cve.affected[]` and keeps the element whose `source` is the CVE's `sourceIdentifier`, which is the CNA's own data. Other elements come from other organisations and are skipped.
- `feed.ParseCNAAffected` is shared by the MITRE and NVD adapters.
- `merge.resolve` takes CNA entries from one source, MITRE first and then NVD, and removes repeats within it.
- Fixes from an independent review:
  - An entry whose `versions` do not decode also loses its `defaultStatus`, because the status alone would call an affected product unaffected.
  - Malformed product data no longer costs the whole CVE in either adapter.
  - The warnings carry the CVE ID.
  - `GetCVECNAAffected` orders by content, so its order does not change between merges.
  - OpenAPI descriptions no longer imply an empty list means no data exists upstream.

## Key decisions

- **The MITRE feed cannot deliver this data as it stands, so NVD does.** All 420,477 CVE entries in the real cvelistV5 ZIP carry one timestamp, the commit time, so the `FileHeader.Modified` filter skips nothing once upstream has a new commit. The whole archive is one page, which needs about 9 hours at the measured 13 merges per second against a 10-minute job limit, so the run fails and the cursor stays put. By reading the code, a MITRE run reaches roughly the first 8,000 records in archive order, which are the oldest CVEs. This was not confirmed against a running deployment.
- **Why NVD's copy is safe to use:** in 262 of 262 real records with `cve.affected[]`, from 2019, 2021, 2023 and 2026, the CNA's element was identical to the MITRE `containers.cna.affected[]` on all stored fields. The 3 of 265 records without the array were all `Rejected`. `TestGoldenNVDRelayMatchesMITRERecord` pins this for the fixtures.
- **One source rather than a union,** so that an entry the CNA has edited is not stored twice while one copy lags.
- ADP product data, such as CISA's, is not stored. Neither is `cpes` from `affected[]`: adding those to `AffectedCPEs` would move `material_hash`.

## How existing CVEs get filled

A CVE gets ranges and CNA data the next time its NVD or MITRE record is ingested. To fill the whole corpus, clear the NVD cursor:

```sql
UPDATE feed_sync_state SET cursor_json = NULL WHERE feed_name = 'nvd';
```

The NVD feed pages and continues across job limits, so this walk finishes. Hashes do not move, so no alerts fire. NVD's incremental updates wait until the walk ends, and each record adds a `cve_raw_payloads` row until 90-day retention removes it. Do not clear the `mitre` cursor: it would not help, for the reason above.

## Gotchas

- NVD `negate: true` is not decoded. It appeared on 0 of 2,784 configuration nodes across real samples from 2019 to 2026, and on 0 in the golden page, so no handling was added.

## Quality checks

- `go test ./internal/merge/ ./internal/feed/ ./internal/feed/nvd/ ./internal/feed/mitre/`: pass, with the golden hash pins unedited.
- Real archive, re-run through the shared parser: 420,475 records, 0 errors, and the same counts as the first run.
- Live run, throwaway test: real NVD API, 76 patches, all 76 with CNA data. `GET` on `CVE-2026-107832`, status `Awaiting Analysis`, returned the fastify entry from the NVD record alone.
- `go test ./internal/api/ -run 'TestGetCVE|TestOpenAPI'`, `golangci-lint run` and `npm run type-check`: pass.
