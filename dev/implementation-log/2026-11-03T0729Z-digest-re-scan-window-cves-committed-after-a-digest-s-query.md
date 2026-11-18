# Digest Re-scan Window — CVEs Committed After a Digest's Query

> **Date:** 2026-11-03
> **Commit:** `3a4331a` on `fix/digest-window-gap`
> **Source:** follow-up to the alert evaluator cursor re-scan window, which covers the same flaw in the batch and EPSS evaluators

## What was built

| Part | Files | Description |
|---|---|---|
| Schema | `migrations/000048_scheduled_report_rescan_sent_cves.*.sql` | `scheduled_reports.rescan_sent_cves JSONB NOT NULL DEFAULT '[]'`, CHECK that it is an array |
| Queries | `internal/store/queries/cves.sql`, `scheduled_reports.sql` | `DigestCVEs` returns `date_modified_canonical` and leaves out the `(cve_id, date_modified_canonical)` pairs in a JSONB argument. `AdvanceReport` writes the list with the cursor |
| Store | `internal/store/notification_delivery.go`, `scheduled_report.go` | `DigestSentCVE`, new `sent` parameters on `DigestCVEs` and `AdvanceReport` (nil stores `[]`) |
| Worker | `internal/notify/digest.go` | Cursor read before the query, scan from `digestRescanWindow` (2 minutes) before `last_run_at`, `sentInRescanWindow` keeps sent versions the next scan reaches |
| Docs | `dev/implementation-pitfalls.md` NOTIFY-21, `PLAN.md` §12.1 | Digest re-scan window rule |

## Key implementation decisions

- **Overlap plus a sent-version list, not overlap alone**: digests have no `alert_events` uniqueness, so a plain overlap repeats CVEs across digests.
- **Key is `(cve_id, date_modified_canonical)`, not `material_hash`**: a CVE that changes and changes back gets its old hash again under a new timestamp and must appear again.
- **Exclusion in SQL before `LIMIT 500`**: filtering in Go after the limit would shrink a full digest below 500 while eligible CVEs exist.
- **Previous entries still inside the window are carried over**, so the list stays correct if two runs fall within the window of each other.
- **A malformed list is logged and treated as empty**, so it costs repeats in one digest rather than stopping the report.

## Gotchas discovered

- **DB-16 hit again**: a semicolon in the new migration's comment broke every integration test with `migration failed in line 0`.
- **A pending digest delivery blocks the next digest for the same report and channel**: `InsertDigestDelivery` is `ON CONFLICT (report_id, channel_id) WHERE status = 'pending' DO NOTHING`. Multi-run digest tests must complete the first delivery (`completeDigestDeliveries`), or the second run's insert is a no-op and the test fails for the wrong reason. In production this also drops a digest's CVEs while the previous digest is still retrying; not addressed here.

## Quality checks

- **golangci-lint:** 0 issues on `internal/notify`, `internal/store`
- **Break-tests:** both new notify tests fail on `dev` (late CVE in 0 digests, re-modified CVE missed); `TestWorker_Digest_RescanWindowSkipsSentVersions` fails with the sent-version exclusion disabled (unchanged CVE in 2 digests)
- **New tests:** `TestWorker_Digest_IncludesCVECommittedAfterQuery`, `TestWorker_Digest_RescanWindowSkipsSentVersions`, `TestDigestCVEs_ExcludesSentVersions`, `TestAdvanceReport_NilSentStoresEmptyArray`, `TestSentInRescanWindow` (fails with the carry-over loop removed), `TestSentInRescanWindow_NothingSent`; sent-list assertion added to `TestAdvanceReport`
