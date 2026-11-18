# Pin material_hash for the golden corpus

## What was built

- `internal/merge/material_hash_golden_test.go` seeds every adapter's golden fixtures through the real merge pipeline and compares each CVE's stored `material_hash` with `internal/merge/testdata/golden_material_hashes.json` (68 CVEs).
- Three real records added to the NVD golden page and the MITRE golden ZIP, captured 2026-11-06:
  - `CVE-2026-56847`: Node.js fixed on three branches under one criteria string, using `versionEndIncluding`.
  - `CVE-2026-111497`: Node.js and Brotli under repeated criteria strings, using `versionEndExcluding` (`23.0.0` up to `24.22.1`).
  - `CVE-2026-107832`: fastify, NVD status `Awaiting Analysis` with no `configurations`, so CNA data is all there is.

## Key decisions

- The pins were captured by running the code at `af664e3` against these fixtures, and are committed before any change to adapters or merge. Storing version ranges must leave them untouched, so the commit order is part of the evidence.
- The test seeds through `testutil.SeedCorpus`, so it covers multi-source merges and not only single-source hashing.
- The test has no update mode. A hash change fires an alert for every matching rule on next merge, so moving a pin should be a visible edit.

## Gotchas

- `SeedCorpus` calls `t.Setenv`, so tests using it cannot call `t.Parallel`.
- The NVD golden page is served once: the adapter stops after the first page when `totalResults` is reached, so a second page file would not be read. The new records were appended to `page-001.json` and its counts updated.
- Real NVD responses now carry a `cve.affected[]` array that relays CNA data (100 of 100 recent records; 0 of the 26 records captured in March 2026). The adapter ignores it.

## Quality checks

- `go test ./internal/merge/ -run TestMaterialHash_GoldenCorpusMatchesPins`: pass.
- `go test ./internal/feed/nvd/ ./internal/feed/mitre/ -run Golden`: pass.
