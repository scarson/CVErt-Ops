# Vendor Feed Adapters — MSRC + Red Hat

> **Date:** 2026-03-05 to 2026-03-06
> **Commits:** `d42674e`..`9499ef2` on `feature/vendor-feed-adapters`, merged to `dev`

## What was built

| Feature | Files | Description |
|---|---|---|
| CSAF 2.0 parser | `internal/feed/csaf/parser.go` | Shared OASIS CSAF 2.0 JSON parser — extracts CVE IDs, CVSS vectors/scores, CWEs, remediation URLs. Designed for reuse by MSRC now and CISA ICS-CERT later |
| MSRC adapter | `internal/feed/msrc/adapter.go` | Fetches CSAF 2.0 advisories from `api.msrc.microsoft.com`. Two-phase: queries `/updates` for modified advisory IDs, then fetches each CSAF document. Rate limited (2 req/s) |
| Red Hat adapter | `internal/feed/redhat/adapter.go` | Two-phase from Red Hat Security Data API: paginated CVE list, then individual detail requests. Rate limited (5 req/s) |
| Vendor enrichment schema | `migrations/000029_vendor_enrichment.{up,down}.sql` | `cve_vendor_enrichment` table with `(cve_id, source_name)` unique constraint, vendor severity/fix state, JSONB enrichment blob |
| Merge pipeline vendor step | `internal/merge/pipeline.go` | Vendor enrichment upsert when `CanonicalPatch.VendorEnrichment` is non-nil |
| KEV vendor enrichment | `internal/feed/kev/adapter.go` | Backfilled `VendorEnrichment` population for KEV adapter |

## Key implementation decisions

- **Shared CSAF parser** — CSAF 2.0 is an OASIS standard used by multiple vendors. Reusable `csaf` package avoids future duplication
- **Two-phase fetch pattern** — list modified IDs first, then fetch details. Enables per-CVE cursor granularity and crash recovery
- **`VendorEnrichment` as separate table** — vendor data is heterogeneous across sources. JSONB blob with extracted scalar columns for common filter dimensions
- **`slices.Concat` for priority list** — bug hunt found `append(globalPriority, ...)` was mutating the global slice's backing array
- **OData datetime validation** via regex in MSRC adapter — prevents injection into `$filter` query parameter

## Bug hunt findings (all fixed)

- Red Hat adapter never advanced cursor on last page (full re-sync every run)
- KEV enrichment fields not null-byte stripped
- MSRC silently dropped CVSS 0.0 scores
- Red Hat/MSRC response bodies not drained (broke connection reuse)
- Global priority slice mutation via `append` in merge resolver

## Tests added

| Test file | Coverage |
|---|---|
| `internal/feed/csaf/parser_test.go` | Multi-vulnerability documents, missing fields, empty input |
| `internal/feed/msrc/adapter_test.go` | Pagination, CVSS 0.0 preservation, rate limiting, cursor persistence |
| `internal/feed/redhat/adapter_test.go` | Pagination, cursor advancement, detail fetch errors, null-byte stripping |
| `internal/merge/resolve_test.go` (additions) | MSRC/Red Hat priority ordering, mutation protection |
