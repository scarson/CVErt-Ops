# Digest Total Count — CVEs Beyond the 500-Row Limit Are Reported

> **Date:** 2026-11-03
> **Branch:** `fix/digest-truncation`
> **Source:** follow-up to the digest re-scan window: a digest with more than 500 matching CVEs dropped the rest with no trace

## What was built

| Part | Files | Description |
|---|---|---|
| Query | `internal/store/queries/cves.sql` | `DigestCVEs` returns `count(*) OVER () AS total_count`, the match count before `LIMIT 500` |
| Worker | `internal/notify/digest.go` | Digest payload is `digestPayload`, `{"total_count": N, "cves": [...]}`. `digestTemplateData` lists the first 25 CVEs and takes the email's total from `total_count` |
| Delivery | `internal/notify/worker.go` | `deliverEmail` decodes the payload per kind: alerts stay arrays, digests are objects |
| Docs | `PLAN.md` §12.1, `dev/implementation-pitfalls.md` NOTIFY-23 | Payload shape and the rule that renderers take N from `total_count` |

## Key implementation decisions

- **Report the total, keep the cap**: carrying the overflow into later digests would need a cursor that is not ordered by timestamp, would delay low-severity CVEs by days after a burst, and would grow `rescan_sent_cves` without bound. Removing the cap would let a burst produce multi-megabyte payloads.
- **Window function, not a second `COUNT(*)` query**: one predicate and one snapshot, so the total cannot disagree with the rows. The cost is that Postgres buffers every matching row before the top-500 sort.
- **No decoder for the old array form**: digest deliveries still pending at deploy fail to decode, retry and are exhausted. The project has no release yet.
- **The "view all" link still opens the CVErt Ops root**: the SPA CVE search cannot filter by modification date, so a link scoped to the digest window needs frontend work.

## Gotchas discovered

- **The re-scan window hid the bug in a first test version**: with the CVEs stamped within 2 minutes of the run, the second run's re-scan window picked up the dropped CVE and the test passed on `dev`.
- **`TestWorker_EmailDigestBranch` cannot detect a payload decode failure**: it uses an unreachable SMTP host, and a decode error leaves the row in the same state (pending, one attempt). The email-side logic is covered by the `digestTemplateData` unit test instead.

## Quality checks

- **golangci-lint:** 0 issues on `internal/notify`, `internal/store`
- **Break-test:** with `total_count` set from the payload length, `TestWorker_Digest_MoreCVEsThanQueryLimit` fails (`total_count = 500, want 501`)
- **New tests:** `TestWorker_Digest_MoreCVEsThanQueryLimit` (failed on `dev`: low-severity CVE in no digest), `TestDigestCVEs_TotalCountBeyondLimit`, `TestDigestTemplateData`; `total_count` assertion added to `TestWorker_DigestPipeline_EndToEnd`
- **Tests run:** full `internal/notify` package; `internal/store` tests matching `TestDigestCVEs|TestAdvanceReport|TestInsertDigestDelivery`
