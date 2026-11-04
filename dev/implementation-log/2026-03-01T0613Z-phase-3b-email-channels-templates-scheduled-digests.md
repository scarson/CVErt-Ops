# Phase 3b — Email Channels, Templates, Scheduled Digests

> **Dates:** 2026-02-28 – 2026-03-01
> **Branch:** `dev`
> **Commits:** `79a4b1c`–`1742e5f` (migrations), `200d227`–`567bbc7` (store), `d3e0628`–`6dcb71f` (notify), `8219f16`–`e377437` (api), `47ee37b` (wiring), `978a1eb` (quality fixes), `770f3c2` (test coverage), `b36723c` (pitfalls)
> **Deliverables:** Migrations 000018–000019, email delivery, HTML/text templates, digest runner, scheduled report CRUD, report-channel bindings

## Files created / modified

| File | Purpose |
|---|---|
| `migrations/000018_create_scheduled_reports.{up,down}.sql` | `scheduled_reports` (soft-delete, RLS) + `report_channels` join table |
| `migrations/000019_phase3b_channel_delivery_alterations.{up,down}.sql` | `notification_channels`: nullable `signing_secret`, `'email'` type. `notification_deliveries`: `kind` discriminator, nullable `rule_id`, `report_id` FK, compound check constraint |
| `internal/notify/email.go` | `EmailSend()` via `go-mail` dial-per-send, BCC all recipients, header injection defense |
| `internal/notify/template.go` | `CVESummary`, `AlertTemplateData`, `DigestTemplateData` structs; `snapshotsToCVESummaries()` with 280-char truncation |
| `internal/notify/render.go` | `RenderAlert()`, `RenderDigest()` — templates from `embed.FS`, per-file parse (no `{{define}}` collision), `funcMap` with `deref`/`pct`/`sevColor` |
| `internal/notify/digest.go` | `runDigest()`, `executeDigestReport()`, `ComputeNextRunAt()`, DST-safe `advanceNextRunAt` via `AddDate(0,0,1)` |
| `templates/email_{alert,digest}.{html,txt}.tmpl` | Four HTML/text template files for alert and digest emails |
| `internal/api/reports.go` | Scheduled digest report CRUD + channel bindings |
| `internal/api/channels.go` | Email channel validation, signing secret guards |
| `internal/store/scheduled_report.go` | Report CRUD, `ClaimDueReports`, `DigestCVEs`, `AdvanceReport` |
| `internal/store/report_channel.go` | Report-channel bindings, unified channel deletion guard |

## Key implementation decisions

**Delivery-time rendering.** Payload stored as structured JSON; templates applied at delivery time. Template updates apply to pending deliveries.

**`AddDate(0,0,1)` for DST correctness.** `Add(24*time.Hour)` drifts ±1h across DST boundaries.

**Missed-run catch-up.** Single delivery covering the full gap; skip ahead to next future slot. No flood of one-per-missed-interval.

**SMTP 5xx is permanent.** `isPermanentSMTPError` string-matches codes 550–555 (go-mail doesn't expose typed SMTP codes). Permanent failures exhaust immediately; 4xx uses existing exponential backoff.

**`deliver_kind_fk_check` compound CHECK.** Enforces `(kind='alert' AND rule_id NOT NULL AND report_id IS NULL) OR (kind='digest' AND rule_id IS NULL AND report_id IS NOT NULL)` — belt-and-suspenders against app-layer bugs.

**Template namespace isolation.** Each template file parsed into its own `*template.Template` instance — `{{define "body"}}` in alert doesn't shadow `{{define "body"}}` in digest.

**Digest truncation at 25 CVEs.** Cap summaries at 25 with `Truncated` flag and `TotalCount` for "N of M shown" footer.

## Gotchas discovered

- **Subject sanitization applied in two places** — `sanitizeSubject()` in `render.go` and `strings.NewReplacer` in `EmailSend()`. Render is primary defense; EmailSend is belt-and-suspenders.
- **Existing `nc_webhook_url` CHECK is already email-safe** — `type != 'webhook' OR jsonb_exists(config, 'url')` evaluates TRUE for email rows without modification.
- **Migration ordering is load-bearing** — 000018 must run before 000019 (`report_id` FK depends on `scheduled_reports` table).
- **Debounce index recreation** — new kind-aware indexes created CONCURRENTLY before dropping old ones (no unprotected window).

## Deferred items

- Watchlist-scoped digest filtering (schema column present, implementation deferred)
- AI executive summary in digests (`ai_summary` field plumbed, no LLM call yet)
- Weekly/custom recurrence (daily hardcoded; trivial to extend)
- Email bounce processing
- Custom user-provided templates (Enterprise feature)

## Quality check results

**pitfall-check:** Clean after fixes.
**plan-check (§11, §12, §16):** Found missing SSRF check in PATCH, `send_on_empty` default, digest truncation. All fixed in `978a1eb`.
**security-review:** Clean.
**Test coverage audit:** Found 20+ gaps, all addressed in `770f3c2` — store (DigestCVEs, InsertDigestDelivery, etc.), pure functions (isPermanentSMTPError 11-case, advanceNextRunAt), API (PATCH SSRF 5 cases, PATCH email 3 cases, DELETE 409 report-bound), worker integration (email digest delivery).
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.
