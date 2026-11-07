# Store NVD CPE ranges and CNA affected entries

## What was built

- Migration `000052`: `cve_cpe_matches` (one row per distinct NVD `cpeMatch`, with the four range fields and `vulnerable`) and `cve_cna_affected` (one row per distinct CNA `affected[]` entry, with `versions` as JSONB).
- `feed.CPEMatch`, `feed.CNAAffected`, `feed.CNAVersion`, `feed.CNAVersionChange`, and the `cpe_matches` and `cna_affected` fields on `CanonicalPatch`.
- The NVD adapter emits a `CPEMatch` for every entry. The MITRE adapter emits a `CNAAffected` for every CNA `affected[]` entry.
- `merge.resolve` unions both across sources, removing exact repeats. `merge.Ingest` deletes and re-inserts both tables. Both are in the rename and delete lists of the late-binding CVE ID move.

## Key decisions

- **Separate table, `cve_affected_cpes` unchanged.** That table holds one row per CPE string, including `vulnerable: false` platforms. It feeds `material_hash`, so the adapter still emits the same list and no hash moves. Ranges are not hash inputs: a range change on its own does not fire alerts or bump `date_modified_canonical`. Whether it should is a separate decision.
- **CPE watchlist items keep matching `vulnerable: false` CPEs.** NVD marks hardware `vulnerable: false` when the flaw is in its firmware (`CVE-2017-12542`). Excluding those rows would silently stop alerts for a watched device. The cost is noise: a Windows item matches an application CVE that names Windows as its platform (`CVE-2026-3909`). `internal/alert/watchlist_cpe_test.go` pins this.
- **Deferred FK on both tables.** The rename path updates children before `cves`, so an immediate FK would fail. `cve_references`, `cve_affected_packages` and `cve_affected_cpes` have no FK, so a child table missing from the hand-written list orphans rows silently. With this FK the rename fails at commit instead.
- **No unique index.** CVE 5 allows `product` up to 2048 and `version` up to 1024 characters, and the btree row limit is about 2700 bytes, so one oversized CNA value would fail the merge of its CVE. Rows are rewritten under the per-CVE advisory lock and `resolve` removes repeats.
- **`versions` stays raw during decode**, so a malformed `versions` costs that entry's versions and not the whole CVE record.
- **Stored beyond the listed fields:** `packageName`, `collectionURL` and `versions[].changes`. In the 2026-11-06 archive, 1,066 entries are identified only by package, and 15,332 version elements carry `changes` (for example a backported fix inside a range), so a reader without them gets wrong answers. Adding them later would need another full re-sync.

## Gotchas

- `cve_raw_payloads` cannot fill existing NVD data: the adapter re-marshals its own types into that payload, and those types had no range fields. MITRE payloads are complete but retained for 90 days. For how existing CVEs fill, see the entry "Read CNA data from NVD's relay".
- The comment in the MITRE adapter calling `versions` polymorphic does not match the current corpus: every one of 1,366,778 version elements has string fields.
- A fresh worktree needs `web/dist` copied in before `internal/api` compiles, and `TESTCONTAINERS_RYUK_DISABLED=true` while other sessions use Docker.

## Quality checks

- Real archive (720 MB, 420,475 records): the adapter parsed all with 0 errors. 1,091 records, including the 40 largest (up to 9,197 version elements), merged with and without ranges: 0 hash changes.
- `go test ./internal/merge/`, `./internal/feed/nvd/`, `./internal/feed/mitre/`, `./internal/feed/`: pass, including the golden hash pins committed before this change.
- `go test ./internal/alert/ -run TestEvaluatorRealtime_CPEWatchlist`: pass.
- `golangci-lint run` on the changed packages: 0 issues.
