# Integration tests for CPE product rules

## What was built

MATCH-2 plan Task 3.3 (design sections 3.5, 5.1, 5.2, 12 and 15.2). New `internal/alert/product_match_test.go`:

- `TestProductMatch_RuleConditions`: a hand-built corpus ingested through `merge.Ingest` (CNA entries as MITRE records, CPE matches and affected CPEs as NVD records). Each rule runs through realtime and through an activation scan, with the rule's status asserted before and after, and events checked on every corpus CVE. `nodejs:node.js` matches the CNA rows `Node.js` / `Node.js` and `The Node.js Project` / `Node.js` and NVD vulnerable rows under both CPE spellings, and not a CVE whose only Node row is `vulnerable: false` or a rejected CVE with a matching CNA row. `microsoft:.net` matches `.NET 9.0 runtime` and `.NET FrameworkExtensions`, not `.NET Framework 4.8` or `OpenAPI.NET`; `in [microsoft:.net, microsoft:.net_framework]` also matches `Microsoft` / `.NET Framework`.
- `TestProductMatch_FullNameRecheck`: `dsl.ProductSetSQL` with a 257-character vendor against two CNA rows whose vendors share the first 256 characters; only the row with the full vendor matches.
- `TestProductMatch_ParityWithIsOtherProduct`: for every other product of `microsoft:.net`, `microsoft:.net_core` and `openssl:openssl`, followed by `a`, `7`, a space, nothing and `é`, the database's answer to `dsl.OtherProductSQL` equals `check.IsOtherProduct`. The statement is built entirely by squirrel. The test also checks `IsOtherProduct` against the ASCII boundary rule, so the comparison cannot pass with both sides always false.
- `TestProductMatch_SeededCorpus`: on `testutil.SeedCorpus`, after asserting CVE-2026-107832's stored severity is `LOW` and it has no CPE match row, `{fastify:fastify, severity in [critical, high, medium, low]}` matches it and the rule without `low` does not; `nodejs:node.js` matches exactly CVE-2026-111497 and CVE-2026-56847; `google:brotli` matches exactly CVE-2026-111497.
- `TestProductMatch_SameAnswerOnEveryPath`: for each rule, `store.ExecuteDSLQuery` paged to the end returns the CVEs an activation scan writes events for, and `DryRun`'s `MatchCount` equals their number.
- `TestProductMatch_AcceptanceCNAThenNVD`: `testutil.GoldenPatch(t, "nvd", "CVE-2026-56847")` (CNA `nodejs` / `node`), moved to an unused ID with its CPE data cleared and severity `HIGH`, fires `{nodejs:node.js, severity in [critical, high]}` on realtime; an NVD patch adding a vulnerable `nodejs:node.js` match and affected CPE changes `material_hash`, and realtime writes a second event at the new hash.

## Key decisions

- **An extra rule in the every-path set.** The plan's `{ecosystem eq npm, package eq fastify}` matches nothing in the seeded corpus (fastify is there only as a CNA product), so it is kept and pinned as empty, and `{ecosystem eq npm, package eq jspdf}` (CVE-2026-31938) is added so the correlated package set is compared on a match. Every other rule must match at least one CVE.
- **Exact sets on the seeded corpus** for `nodejs:node.js` and `google:brotli`, not only membership.
- The seeded and acceptance tests do not call `t.Parallel()`: the NVD golden fixtures call `t.Setenv`.

## Gotchas

- Falsification probe, run once: with `lower(a.vendor) = ?` removed from the exact-name term in `internal/alert/dsl/sets.go`, `TestProductMatch_FullNameRecheck` failed with both CVEs matched; restored with the Edit tool, and `git diff` showed no change to the file.

## Quality checks

- `go test ./internal/alert/... -count=1 -run 'Product|Package|Parity|EveryPath'`: pass (67 tests and subtests); no error-level log lines.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
