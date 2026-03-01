# Phase 3b: Email Channels, Templates, Digests — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add email notification channels, HTML email templates, and scheduled daily digest reports to the existing webhook delivery pipeline.

**Architecture:** Extend the notification worker with a channel-type switch (webhook → Send(), email → RenderTemplate() + EmailSend()). Digest reports use a new `scheduled_reports` table with timezone-aware `next_run_at` polling via a new ticker in the worker's select loop. Email delivery uses `wneessen/go-mail/v2`.

**Tech Stack:** Go 1.26, PostgreSQL 15+, `wneessen/go-mail/v2` (SMTP), `html/template` + `text/template` (rendering), `embed.FS` (template files).

**Design doc:** `dev/plans/2026-02-28-phase-3b-email-templates-digests-design.md`

**Reference files for patterns:**
- Store methods: `internal/store/notification_channel.go` (withOrgTx, withBypassTx, error handling)
- API handlers: `internal/api/channels.go` (validation, writeJSON, orgID extraction)
- API CRUD: `internal/api/alert_rules.go` (full CRUD + binding pattern)
- Worker: `internal/notify/worker.go` (Start loop, deliver, type-switch point)
- Queries: `internal/store/queries/notification_channels.sql`, `notification_deliveries.sql`, `alert_rule_channels.sql`
- Migration: `migrations/000017_create_notification_tables.up.sql` (RLS, grants, indexes, autovacuum)
- Wiring: `cmd/cvert-ops/main.go` lines 126–141 (worker construction)
- Config: `internal/config/config.go` (SMTP fields at lines 56–62, EXTERNAL_URL at line 32)

---

## Task 1: Migration — `scheduled_reports` and `report_channels` Tables

**Files:**
- Create: `migrations/000018_create_scheduled_reports.up.sql`
- Create: `migrations/000018_create_scheduled_reports.down.sql`

**Step 1: Write the up migration**

```sql
-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

-- ── scheduled_reports ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL CHECK (char_length(name) <= 255),
    scheduled_time      TIME        NOT NULL,
    timezone            TEXT        NOT NULL DEFAULT 'UTC' CHECK (char_length(timezone) <= 40),
    next_run_at         TIMESTAMPTZ NOT NULL,
    last_run_at         TIMESTAMPTZ NULL,
    severity_threshold  TEXT        NULL CHECK (severity_threshold IN ('critical','high','medium','low')),
    watchlist_ids       UUID[]      NULL,
    send_on_empty       BOOLEAN     NOT NULL DEFAULT TRUE,
    ai_summary          BOOLEAN     NOT NULL DEFAULT FALSE,
    status              TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused')),
    deleted_at          TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scheduled_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scheduled_reports
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Soft-delete entity: no DELETE grant.
GRANT SELECT, INSERT, UPDATE ON scheduled_reports TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS scheduled_reports_org_id_idx
    ON scheduled_reports (org_id);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scheduled_reports_name_uq
    ON scheduled_reports (org_id, name) WHERE deleted_at IS NULL;

-- Scheduler poll: find due reports.
CREATE INDEX CONCURRENTLY IF NOT EXISTS scheduled_reports_next_run_idx
    ON scheduled_reports (next_run_at)
    WHERE status = 'active' AND deleted_at IS NULL;

-- ── report_channels (M:M binding) ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS report_channels (
    report_id  UUID        NOT NULL REFERENCES scheduled_reports(id) ON DELETE CASCADE,
    channel_id UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    org_id     UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, channel_id)
);

ALTER TABLE report_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON report_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Hard-delete join table: no UPDATE grant.
GRANT SELECT, INSERT, DELETE ON report_channels TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS report_channels_org_id_idx
    ON report_channels (org_id);

-- Channel deletion pre-flight: "which reports reference this channel?"
CREATE INDEX CONCURRENTLY IF NOT EXISTS report_channels_channel_id_idx
    ON report_channels (channel_id);
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS report_channels_channel_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS report_channels_org_id_idx;
DROP TABLE IF EXISTS report_channels;

DROP INDEX CONCURRENTLY IF EXISTS scheduled_reports_next_run_idx;
DROP INDEX CONCURRENTLY IF EXISTS scheduled_reports_name_uq;
DROP INDEX CONCURRENTLY IF EXISTS scheduled_reports_org_id_idx;
DROP TABLE IF EXISTS scheduled_reports;
```

**Step 3: Run the migration and verify**

```bash
go run ./cmd/cvert-ops migrate
```

Expected: migration 000018 applied successfully.

**Step 4: Commit**

```bash
git add migrations/000018_create_scheduled_reports.up.sql migrations/000018_create_scheduled_reports.down.sql
git commit -m "feat(migrations): create scheduled_reports and report_channels tables (000018)"
```

---

## Task 2: Migration — Alter `notification_channels` and `notification_deliveries`

**Files:**
- Create: `migrations/000019_phase3b_channel_delivery_alterations.up.sql`
- Create: `migrations/000019_phase3b_channel_delivery_alterations.down.sql`

**Step 1: Write the up migration**

This migration:
- Makes `signing_secret` nullable (email channels don't need HMAC signing)
- Extends `type` CHECK to include `'email'`
- Adds `kind` column to `notification_deliveries` with discriminator
- Makes `rule_id` nullable (digest deliveries have `report_id` instead)
- Adds `report_id` FK to `scheduled_reports`
- Recreates debounce unique indexes with kind-awareness

```sql
-- migrate:no-transaction
-- Index operations use CONCURRENTLY.

-- ── notification_channels alterations ──────────────────────────────────────────

-- Email channels don't need signing secrets.
ALTER TABLE notification_channels ALTER COLUMN signing_secret DROP NOT NULL;

-- Extend channel type to include 'email'.
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook', 'email'));

-- Email channels store {"recipients": [...]} — webhook URL check is type-specific.
-- The existing nc_webhook_url CHECK already handles this correctly:
-- "type != 'webhook' OR jsonb_exists(config, 'url')" evaluates TRUE for email channels.

-- ── notification_deliveries alterations ────────────────────────────────────────

-- Add delivery kind discriminator.
ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'alert'
    CHECK (kind IN ('alert', 'digest'));

-- Make rule_id nullable: digest deliveries have report_id instead.
ALTER TABLE notification_deliveries ALTER COLUMN rule_id DROP NOT NULL;

-- Add report_id FK for digest deliveries.
ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS report_id UUID NULL REFERENCES scheduled_reports(id) ON DELETE CASCADE;

-- Exactly one of rule_id or report_id must be set, matching kind.
ALTER TABLE notification_deliveries
    ADD CONSTRAINT delivery_kind_fk_check CHECK (
        (kind = 'alert'  AND rule_id IS NOT NULL AND report_id IS NULL) OR
        (kind = 'digest' AND rule_id IS NULL     AND report_id IS NOT NULL)
    );

-- Recreate debounce indexes: create new ones first (no unprotected window).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_pending_alert
    ON notification_deliveries (rule_id, channel_id)
    WHERE status = 'pending' AND kind = 'alert';

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_pending_digest
    ON notification_deliveries (report_id, channel_id)
    WHERE status = 'pending' AND kind = 'digest';

-- Drop old debounce index (superseded by kind-aware ones above).
DROP INDEX CONCURRENTLY IF EXISTS uq_notification_deliveries_pending;

-- Index for delivery history queries filtered by report.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_report_id_idx
    ON notification_deliveries (report_id);
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_report_id_idx;

-- Restore original debounce index.
-- Safe: all existing rows with kind='alert' have non-null rule_id.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_notification_deliveries_pending
    ON notification_deliveries (rule_id, channel_id) WHERE status = 'pending';

DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_pending_digest;
DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_pending_alert;

ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS delivery_kind_fk_check;
ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS report_id;
ALTER TABLE notification_deliveries ALTER COLUMN rule_id SET NOT NULL;
ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS kind;

ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook'));
ALTER TABLE notification_channels ALTER COLUMN signing_secret SET NOT NULL;
```

**Step 3: Run migration**

```bash
go run ./cmd/cvert-ops migrate
```

**Step 4: Regenerate sqlc**

```bash
sqlc generate
```

Expected: regeneration succeeds. The generated code in `internal/store/generated/` will now reflect nullable `signing_secret`, new `kind` and `report_id` columns.

**Step 5: Fix compilation errors from nullable signing_secret**

The `signing_secret` column change from `NOT NULL` to nullable will change the generated type from `string` to `sql.NullString`. Update all store methods and callers:

- `internal/store/notification_channel.go`: `CreateNotificationChannel` — pass `sql.NullString` for signing_secret
- `internal/notify/worker.go` line 143: `ch.SigningSecret` → `ch.SigningSecret.String` (already uses `.String` pattern for secondary)

Run:
```bash
go build ./...
```
Expected: compiles without errors.

**Step 6: Fix any broken tests**

```bash
go test ./internal/store/... ./internal/notify/... ./internal/api/...
```
Expected: all tests pass (may need to update test fixtures that create channels with signing secrets).

**Step 7: Commit**

```bash
git add migrations/000019_phase3b_channel_delivery_alterations.up.sql \
       migrations/000019_phase3b_channel_delivery_alterations.down.sql \
       internal/store/generated/ \
       internal/store/notification_channel.go \
       internal/notify/worker.go
git commit -m "feat(migrations): email channel type + delivery kind discriminator (000019)"
```

---

## Task 3: sqlc Queries and Store Methods for `scheduled_reports`

**Files:**
- Create: `internal/store/queries/scheduled_reports.sql`
- Create: `internal/store/scheduled_report.go`
- Test: `internal/store/scheduled_report_test.go`

**Step 1: Write sqlc queries**

Create `internal/store/queries/scheduled_reports.sql`:

```sql
-- ABOUTME: sqlc queries for scheduled_reports digest configuration CRUD.
-- ABOUTME: Runner ops (claim, advance) use bypass-RLS; API ops use org-scoped tx.

-- name: CreateScheduledReport :one
INSERT INTO scheduled_reports (
    org_id, name, scheduled_time, timezone, next_run_at,
    severity_threshold, watchlist_ids, send_on_empty, ai_summary, status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetScheduledReport :one
SELECT * FROM scheduled_reports
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: ListScheduledReports :many
SELECT * FROM scheduled_reports
WHERE org_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC;

-- name: UpdateScheduledReport :one
UPDATE scheduled_reports
SET name               = $3,
    scheduled_time     = $4,
    timezone           = $5,
    next_run_at        = $6,
    severity_threshold = $7,
    watchlist_ids      = $8,
    send_on_empty      = $9,
    ai_summary         = $10,
    status             = $11,
    updated_at         = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteScheduledReport :exec
UPDATE scheduled_reports
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: ClaimDueReports :many
-- Digest runner: claim up to $1 reports that are due for execution.
SELECT * FROM scheduled_reports
WHERE status = 'active'
  AND next_run_at <= now()
  AND deleted_at IS NULL
ORDER BY next_run_at
LIMIT $1
FOR UPDATE SKIP LOCKED;

-- name: AdvanceReport :exec
-- After a digest run: update last_run_at and next_run_at.
UPDATE scheduled_reports
SET last_run_at = $2,
    next_run_at = $3,
    updated_at  = now()
WHERE id = $1;

-- name: GetAlertRuleName :one
-- Lightweight lookup for template rendering — rule name only.
SELECT name FROM alert_rules WHERE id = $1 LIMIT 1;
```

**Step 2: Regenerate sqlc**

```bash
sqlc generate
```

**Step 3: Write store methods**

Create `internal/store/scheduled_report.go`. Follow the patterns in `notification_channel.go`:
- CRUD methods use `s.withOrgTx(ctx, orgID, ...)`
- `ClaimDueReports` uses `s.withBypassTx(ctx, ...)` (worker context)
- `AdvanceReport` uses `s.withBypassTx(ctx, ...)`
- `GetAlertRuleName` uses `s.withBypassTx(ctx, ...)` (worker context, no org scope)
- Get returns `(*Row, error)` with `sql.ErrNoRows → nil`
- List returns `([]Row, error)`
- All errors wrapped with `fmt.Errorf`

```go
// ABOUTME: Store methods for scheduled_reports digest configuration CRUD.
// ABOUTME: Runner ops (ClaimDueReports, AdvanceReport) use withBypassTx; API ops use withOrgTx.
```

Include:
- `CreateScheduledReport(ctx, orgID, params) (*Row, error)`
- `GetScheduledReport(ctx, orgID, id) (*Row, error)`
- `ListScheduledReports(ctx, orgID) ([]Row, error)`
- `UpdateScheduledReport(ctx, orgID, id, params) (*Row, error)`
- `SoftDeleteScheduledReport(ctx, orgID, id) error`
- `ClaimDueReports(ctx, limit int) ([]Row, error)` — bypass RLS
- `AdvanceReport(ctx, id, lastRunAt, nextRunAt time.Time) error` — bypass RLS
- `GetAlertRuleName(ctx, ruleID) (string, error)` — bypass RLS, returns "" on ErrNoRows

**Step 4: Write tests**

Create `internal/store/scheduled_report_test.go`:
- `TestCreateScheduledReport` — create and verify fields
- `TestGetScheduledReport_NotFound` — returns nil
- `TestListScheduledReports` — returns correct order
- `TestSoftDeleteScheduledReport` — soft-deleted reports excluded from get/list
- `TestClaimDueReports` — only claims active, non-deleted, due reports
- `TestAdvanceReport` — updates last_run_at and next_run_at

Use the existing `testutil.NewTestDB(t)` helper for real database tests.

**Step 5: Run tests**

```bash
go test ./internal/store/... -run TestScheduledReport -v
```

**Step 6: Commit**

```bash
git add internal/store/queries/scheduled_reports.sql internal/store/scheduled_report.go \
       internal/store/scheduled_report_test.go internal/store/generated/
git commit -m "feat(store): scheduled_reports CRUD + runner queries"
```

---

## Task 4: sqlc Queries and Store Methods for `report_channels`

**Files:**
- Create: `internal/store/queries/report_channels.sql`
- Create: `internal/store/report_channel.go`
- Modify: `internal/store/notification_channel.go` — update channel deletion guard
- Test: `internal/store/report_channel_test.go`

**Step 1: Write sqlc queries**

Create `internal/store/queries/report_channels.sql`:

```sql
-- ABOUTME: sqlc queries for report ↔ notification channel M:M bindings.
-- ABOUTME: Hard-delete join table; mirrors alert_rule_channels pattern.

-- name: BindChannelToReport :exec
INSERT INTO report_channels (report_id, channel_id, org_id)
VALUES ($1, $2, $3)
ON CONFLICT (report_id, channel_id) DO NOTHING;

-- name: UnbindChannelFromReport :exec
DELETE FROM report_channels
WHERE report_id = $1 AND channel_id = $2 AND org_id = $3;

-- name: ListChannelsForReport :many
SELECT nc.id, nc.org_id, nc.name, nc.type, nc.config, nc.created_at, nc.updated_at
FROM report_channels rc
JOIN notification_channels nc ON nc.id = rc.channel_id
WHERE rc.report_id = $1 AND rc.org_id = $2
  AND nc.deleted_at IS NULL
ORDER BY rc.created_at;

-- name: ListActiveChannelsForDigest :many
-- Used by digest runner: fetches channel config + secrets for delivery creation.
SELECT nc.id, nc.type, nc.config, nc.signing_secret, nc.signing_secret_secondary
FROM report_channels rc
JOIN notification_channels nc ON nc.id = rc.channel_id
WHERE rc.report_id = $1 AND rc.org_id = $2
  AND nc.deleted_at IS NULL;

-- name: ReportChannelBindingExists :one
SELECT EXISTS(
    SELECT 1 FROM report_channels
    WHERE report_id = $1 AND channel_id = $2 AND org_id = $3
) AS exists;

-- name: ChannelHasActiveBoundReports :one
-- Pre-flight check before channel soft-delete.
SELECT EXISTS(
    SELECT 1
    FROM report_channels rc
    JOIN scheduled_reports sr ON sr.id = rc.report_id
    WHERE rc.channel_id = $1
      AND sr.org_id = $2
      AND sr.status = 'active'
      AND sr.deleted_at IS NULL
) AS has_active_reports;
```

**Step 2: Regenerate sqlc and write store methods**

```bash
sqlc generate
```

Create `internal/store/report_channel.go` — follow `internal/store/alert_rule_channel.go` pattern:
- `BindChannelToReport(ctx, orgID, reportID, channelID) error` — withOrgTx
- `UnbindChannelFromReport(ctx, orgID, reportID, channelID) error` — withOrgTx
- `ListChannelsForReport(ctx, orgID, reportID) ([]Row, error)` — withOrgTx
- `ListActiveChannelsForDigest(ctx, orgID, reportID) ([]Row, error)` — withBypassTx (worker context)
- `ReportChannelBindingExists(ctx, orgID, reportID, channelID) (bool, error)` — withOrgTx
- `ChannelHasActiveBoundReports(ctx, orgID, channelID) (bool, error)` — withOrgTx

**Step 3: Update channel deletion guard**

Modify `internal/store/notification_channel.go` — add `ChannelHasActiveBindings` that checks both tables:

```go
// ChannelHasActiveBindings returns true if the channel is bound to any active
// alert rule OR active digest report. Used as pre-flight check before soft-delete.
func (s *Store) ChannelHasActiveBindings(ctx context.Context, orgID, channelID uuid.UUID) (bool, error) {
    hasRules, err := s.ChannelHasActiveBoundRules(ctx, orgID, channelID)
    if err != nil {
        return false, err
    }
    if hasRules {
        return true, nil
    }
    return s.ChannelHasActiveBoundReports(ctx, orgID, channelID)
}
```

**Step 4: Update `deleteChannelHandler` in `internal/api/channels.go`**

Replace `srv.store.ChannelHasActiveBoundRules(...)` with `srv.store.ChannelHasActiveBindings(...)`. Update error message to "channel has active bound rules or reports".

**Step 5: Write tests, run, commit**

```bash
go test ./internal/store/... -run TestReportChannel -v
go test ./internal/api/... -run TestDeleteChannel -v
git add internal/store/queries/report_channels.sql internal/store/report_channel.go \
       internal/store/report_channel_test.go internal/store/notification_channel.go \
       internal/api/channels.go internal/store/generated/
git commit -m "feat(store): report_channels bindings + unified channel deletion guard"
```

---

## Task 5: go-mail Dependency + EmailSend Function

**Files:**
- Create: `internal/notify/email.go`
- Test: `internal/notify/email_test.go`

**Step 1: Add go-mail dependency**

```bash
go get github.com/wneessen/go-mail/v2
```

**Step 2: Write EmailSend tests**

Create `internal/notify/email_test.go`. Test against Mailpit (already in docker-compose on port 1025):

```go
func TestEmailSend_BasicDelivery(t *testing.T) {
    // Use Mailpit on localhost:1025 (docker-compose dev services).
    // Test sends an email and verifies no error returned.
    cfg := notify.SmtpConfig{
        Host: "localhost",
        Port: 1025,
        From: "test@cvert-ops.local",
    }
    err := notify.EmailSend(context.Background(), cfg,
        []string{"recipient@example.com"},
        "Test Subject",
        "<h1>HTML Body</h1>",
        "Text Body",
    )
    // If Mailpit not running, skip rather than fail.
    if err != nil {
        t.Skipf("SMTP not available (Mailpit required): %v", err)
    }
}
```

Also test:
- `TestEmailSend_EmptyRecipients` — returns error
- `TestEmailSend_InvalidHost` — returns error (connection refused)

**Step 3: Write SmtpConfig and EmailSend**

Create `internal/notify/email.go`:

```go
// ABOUTME: SMTP email delivery using go-mail. Dial-per-send for sporadic alert traffic.
// ABOUTME: BCC all recipients in a single email. Retry = retry all recipients.
package notify

import (
    "context"
    "errors"
    "fmt"
    "strings"

    "github.com/wneessen/go-mail/v2"
)

// SmtpConfig holds SMTP connection parameters sourced from global env vars.
type SmtpConfig struct {
    Host     string
    Port     int
    From     string
    Username string
    Password string
    TLS      bool
}

// EmailSend sends an HTML+plaintext multipart email to all recipients via BCC.
// Uses DialAndSend (dial-per-send) — no persistent SMTP connection.
func EmailSend(ctx context.Context, cfg SmtpConfig, recipients []string, subject, htmlBody, textBody string) error {
    if len(recipients) == 0 {
        return errors.New("email send: no recipients")
    }

    // Strip CR/LF from subject to prevent header injection.
    subject = strings.NewReplacer("\r", "", "\n", "").Replace(subject)

    m := mail.NewMsg()
    if err := m.FromFormat("CVErt Ops", cfg.From); err != nil {
        return fmt.Errorf("email send: set from: %w", err)
    }
    if err := m.Bcc(recipients...); err != nil {
        return fmt.Errorf("email send: set bcc: %w", err)
    }
    m.Subject(subject)
    m.SetBodyString(mail.TypeTextPlain, textBody)
    m.AddAlternativeString(mail.TypeTextHTML, htmlBody)

    opts := []mail.Option{
        mail.WithPort(cfg.Port),
    }
    if cfg.Username != "" {
        opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain))
        opts = append(opts, mail.WithUsername(cfg.Username))
        opts = append(opts, mail.WithPassword(cfg.Password))
    }
    if cfg.TLS {
        opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
    } else {
        opts = append(opts, mail.WithTLSPolicy(mail.TLSOpportunistic))
    }

    c, err := mail.NewClient(cfg.Host, opts...)
    if err != nil {
        return fmt.Errorf("email send: create client: %w", err)
    }
    if err := c.DialAndSendWithContext(ctx, m); err != nil {
        return fmt.Errorf("email send: %w", err)
    }
    return nil
}
```

**Step 4: Run tests**

```bash
go test ./internal/notify/... -run TestEmailSend -v
```

**Step 5: Commit**

```bash
git add internal/notify/email.go internal/notify/email_test.go go.mod go.sum
git commit -m "feat(notify): EmailSend with go-mail/v2 SMTP delivery"
```

---

## Task 6: Template System — Embed, Data Structs, Rendering

**Files:**
- Create: `templates/email_alert.html.tmpl`
- Create: `templates/email_alert.txt.tmpl`
- Create: `templates/email_digest.html.tmpl`
- Create: `templates/email_digest.txt.tmpl`
- Create: `internal/notify/template.go`
- Create: `internal/notify/render.go`
- Test: `internal/notify/render_test.go`

**Step 1: Create template data structs**

Create `internal/notify/template.go`:

```go
// ABOUTME: Template data structs for alert and digest email rendering.
// ABOUTME: CVESummary is converted from cveSnapshot at render time with nil-safe accessors.
package notify

// CVESummary is the template-ready representation of a CVE for email rendering.
type CVESummary struct {
    CVEID        string
    Severity     string
    CVSSV3Score  *float64
    CVSSV4Score  *float64
    EPSSScore    *float64
    Description  string
    ExploitAvail bool
    InCISAKEV    bool
    DetailURL    string
}

// AlertTemplateData is the context passed to alert email templates.
type AlertTemplateData struct {
    RuleName    string
    RuleID      string
    CVEs        []CVESummary
    CVErtOpsURL string
}

// DigestTemplateData is the context passed to digest email templates.
type DigestTemplateData struct {
    OrgName     string
    ReportName  string
    Date        string
    CVEs        []CVESummary
    TotalCount  int
    Truncated   bool
    ViewAllURL  string
    AISummary   string
    CVErtOpsURL string
}

// snapshotsToCVESummaries converts delivery payload snapshots to template-ready summaries.
// Truncates descriptions to 280 chars and constructs detail URLs.
func snapshotsToCVESummaries(snaps []cveSnapshot, baseURL string) []CVESummary {
    out := make([]CVESummary, len(snaps))
    for i, s := range snaps {
        sev := ""
        if s.Severity != nil {
            sev = *s.Severity
        }
        desc := s.Description
        if len(desc) > 280 {
            desc = desc[:277] + "..."
        }
        var detailURL string
        if baseURL != "" {
            detailURL = baseURL + "/cves/" + s.CVEID
        }
        out[i] = CVESummary{
            CVEID:        s.CVEID,
            Severity:     sev,
            CVSSV3Score:  s.CVSSV3Score,
            CVSSV4Score:  s.CVSSV4Score,
            EPSSScore:    s.EPSSScore,
            Description:  desc,
            ExploitAvail: s.ExploitAvail,
            InCISAKEV:    s.InCISAKEV,
            DetailURL:    detailURL,
        }
    }
    return out
}
```

**Step 2: Create template files**

Create all four template files in `templates/`. Each file uses `{{define "subject"}}` and `{{define "body"}}` blocks. The HTML templates use fixed-width table layout (600px), inline CSS, severity color badges.

**`templates/email_alert.html.tmpl`:** Alert notification with CVE table (severity badge, CVSS score, EPSS, description, KEV/exploit indicators, detail link). Subject: `[CVErt Ops] Alert: {{.RuleName}} — {{len .CVEs}} CVE(s)`.

**`templates/email_alert.txt.tmpl`:** Plaintext version of the same.

**`templates/email_digest.html.tmpl`:** Daily digest with "N of M shown" footer, heartbeat message when empty, AI summary placeholder. Subject: `[CVErt Ops] Daily Digest — {{.Date}} — {{.TotalCount}} CVE(s)`.

**`templates/email_digest.txt.tmpl`:** Plaintext version.

Delete `templates/.gitkeep` once template files exist.

**Step 3: Write render functions**

Create `internal/notify/render.go`:

```go
// ABOUTME: Template rendering for alert and digest notification emails.
// ABOUTME: Templates parsed once at init from embedded FS; rendered per delivery.
package notify

import (
    "bytes"
    "embed"
    "fmt"
    htmltpl "html/template"
    "strings"
    texttpl "text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// Parsed templates — one per file to avoid {{define}} namespace collisions.
var (
    alertHTML  *htmltpl.Template
    alertText  *texttpl.Template
    digestHTML *htmltpl.Template
    digestText *texttpl.Template
)

func init() {
    alertHTML = htmltpl.Must(htmltpl.ParseFS(templateFS, "templates/email_alert.html.tmpl"))
    alertText = texttpl.Must(texttpl.ParseFS(templateFS, "templates/email_alert.txt.tmpl"))
    digestHTML = htmltpl.Must(htmltpl.ParseFS(templateFS, "templates/email_digest.html.tmpl"))
    digestText = texttpl.Must(texttpl.ParseFS(templateFS, "templates/email_digest.txt.tmpl"))
}

// RenderAlert renders an alert notification email. Returns subject, HTML body, and plaintext body.
func RenderAlert(data AlertTemplateData) (string, string, string, error) {
    return renderPair(alertHTML, alertText, data)
}

// RenderDigest renders a digest email. Returns subject, HTML body, and plaintext body.
func RenderDigest(data DigestTemplateData) (string, string, string, error) {
    return renderPair(digestHTML, digestText, data)
}

func renderPair(html *htmltpl.Template, text *texttpl.Template, data any) (string, string, string, error) {
    // Render subject from the text template's "subject" block.
    var subjectBuf bytes.Buffer
    if err := text.ExecuteTemplate(&subjectBuf, "subject", data); err != nil {
        return "", "", "", fmt.Errorf("render subject: %w", err)
    }
    subject := sanitizeSubject(subjectBuf.String())

    // Render HTML body.
    var htmlBuf bytes.Buffer
    if err := html.ExecuteTemplate(&htmlBuf, "body", data); err != nil {
        return "", "", "", fmt.Errorf("render html: %w", err)
    }

    // Render text body.
    var textBuf bytes.Buffer
    if err := text.ExecuteTemplate(&textBuf, "body", data); err != nil {
        return "", "", "", fmt.Errorf("render text: %w", err)
    }

    return subject, htmlBuf.String(), textBuf.String(), nil
}

// sanitizeSubject strips CR/LF to prevent email header injection.
func sanitizeSubject(s string) string {
    s = strings.TrimSpace(s)
    return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
```

**Important:** The `//go:embed` directive path is relative to the file's package directory. Since `render.go` is in `internal/notify/` but templates are in `templates/` at the project root, the embed path won't work. Two options:

1. Move template files to `internal/notify/templates/` (simplest — keeps embed path relative).
2. Create a thin `templates/embed.go` that exports the FS and import it.

**Use option 1:** Place template files in `internal/notify/templates/` and use `//go:embed templates/*.tmpl`.

**Step 4: Write render tests**

Create `internal/notify/render_test.go`:
- `TestRenderAlert_BasicOutput` — verify subject contains rule name, HTML contains CVE IDs
- `TestRenderAlert_EmptyCVEs` — verify no crash on empty list
- `TestRenderDigest_TruncationFooter` — set TotalCount > 25, Truncated=true, verify footer
- `TestRenderDigest_Heartbeat` — empty CVEs, verify heartbeat message
- `TestRenderDigest_AISummaryPlumbing` — non-empty AISummary renders in output
- `TestSanitizeSubject` — strips `\r\n` from subject

**Step 5: Run tests, commit**

```bash
go test ./internal/notify/... -run TestRender -v
git add internal/notify/templates/ internal/notify/template.go internal/notify/render.go \
       internal/notify/render_test.go
git commit -m "feat(notify): email template system with alert and digest rendering"
```

---

## Task 7: Worker Email Integration — Type-Switch in deliver()

**Files:**
- Modify: `internal/notify/worker.go`
- Modify: `internal/notify/worker_test.go`

**Step 1: Extend Worker struct**

Add `smtpCfg SmtpConfig` and `externalURL string` fields to the `Worker` struct. Update `NewWorker` to accept them:

```go
type Worker struct {
    store       *store.Store
    client      *http.Client
    cfg         WorkerConfig
    smtpCfg     SmtpConfig     // SMTP delivery config
    externalURL string         // base URL for deep links in templates
    log         *slog.Logger
    sems        map[uuid.UUID]chan struct{}
    semsMu      sync.Mutex
    wg          sync.WaitGroup
    dispatcher  *Dispatcher
}

func NewWorker(st *store.Store, client *http.Client, cfg WorkerConfig, smtpCfg SmtpConfig, externalURL string) *Worker {
    // ... existing code, add smtpCfg and externalURL fields
}
```

**Step 2: Add kind column to ClaimedDelivery**

The `ClaimPendingDeliveries` sqlc query needs to return `kind` and `report_id`. Update the query in `notification_deliveries.sql`:

```sql
-- name: ClaimPendingDeliveries :many
SELECT id, org_id, rule_id, channel_id, kind, report_id, attempt_count, payload
FROM notification_deliveries
WHERE status = 'pending' AND send_after <= now()
ORDER BY send_after
LIMIT $1
FOR UPDATE SKIP LOCKED;
```

Regenerate sqlc. Update the `ClaimedDelivery` type alias.

**Step 3: Implement type-switch in deliver()**

Modify `worker.go` `deliver()` method:

```go
func (w *Worker) deliver(ctx context.Context, row store.ClaimedDelivery) {
    ch, err := w.store.GetNotificationChannelForDelivery(ctx, row.ChannelID)
    if err != nil || ch == nil {
        // ... existing error handling
        return
    }

    var sendErr error
    switch ch.Type {
    case "webhook":
        sendErr = w.deliverWebhook(ctx, row, ch)
    case "email":
        sendErr = w.deliverEmail(ctx, row, ch)
    default:
        w.exhaust(ctx, row.ID, fmt.Sprintf("unsupported channel type: %s", ch.Type))
        return
    }

    // ... existing retry/exhaust logic unchanged
}

func (w *Worker) deliverWebhook(ctx context.Context, row store.ClaimedDelivery, ch *store.ChannelForDelivery) error {
    // Existing webhook delivery code extracted from deliver()
    // Add X-CVErtOps-Kind header based on row.Kind
}

func (w *Worker) deliverEmail(ctx context.Context, row store.ClaimedDelivery, ch *store.ChannelForDelivery) error {
    // 1. Parse channel config for recipients
    // 2. Deserialize payload into []cveSnapshot
    // 3. Convert to []CVESummary
    // 4. Switch on row.Kind:
    //    "alert": look up rule name, RenderAlert(), EmailSend()
    //    "digest": look up report name + org name, RenderDigest(), EmailSend()
    // 5. Return error (nil on success)
}
```

**Step 4: Handle SMTP error classification**

In the retry/exhaust logic, check if the error is a permanent SMTP failure (5xx):

```go
// After sendErr is set:
if sendErr != nil && ch.Type == "email" {
    if isPermanentSMTPError(sendErr) {
        w.exhaust(ctx, row.ID, sendErr.Error())
        return
    }
}
// ... existing retry logic
```

Implement `isPermanentSMTPError` checking go-mail's typed errors for 5xx status codes.

**Step 5: Write tests**

Add to `internal/notify/worker_test.go`:
- `TestDeliver_EmailChannel` — mock SMTP (use httptest-style or Mailpit), verify email rendered and sent
- `TestDeliver_WebhookKindHeader` — verify `X-CVErtOps-Kind` header is set on webhook deliveries
- `TestDeliver_UnknownChannelType` — verify exhaust called

**Step 6: Run tests, commit**

```bash
go test ./internal/notify/... -v
git add internal/notify/worker.go internal/notify/worker_test.go \
       internal/store/queries/notification_deliveries.sql internal/store/generated/
git commit -m "feat(notify): worker type-switch for email delivery with template rendering"
```

---

## Task 8: Channel CRUD Updates for Email Type

**Files:**
- Modify: `internal/api/channels.go`
- Modify: `internal/store/notification_channel.go`
- Test: `internal/api/channels_test.go`

**Step 1: Add email config validation**

Add to `internal/api/channels.go`, in `createChannelHandler`, after the webhook validation block:

```go
if req.Type == "email" {
    recipients, err := validateEmailConfig(req.Config)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnprocessableEntity)
        return
    }
    _ = recipients
}
```

Write `validateEmailConfig`:

```go
// validateEmailConfig validates email channel config:
// - recipients must be non-empty, max 50, valid RFC 5322 addresses, no duplicates.
func validateEmailConfig(config json.RawMessage) ([]string, error) {
    var cfg struct {
        Recipients []string `json:"recipients"`
    }
    if err := json.Unmarshal(config, &cfg); err != nil {
        return nil, errors.New("email config must include a recipients array")
    }
    if len(cfg.Recipients) == 0 {
        return nil, errors.New("email config must include at least one recipient")
    }
    if len(cfg.Recipients) > 50 {
        return nil, errors.New("email config must not exceed 50 recipients")
    }
    seen := make(map[string]bool, len(cfg.Recipients))
    for _, r := range cfg.Recipients {
        addr, err := mail.ParseAddress(r)
        if err != nil {
            return nil, fmt.Errorf("invalid email recipient %q: %w", r, err)
        }
        normalized := strings.ToLower(addr.Address)
        if seen[normalized] {
            return nil, fmt.Errorf("duplicate email recipient: %s", normalized)
        }
        seen[normalized] = true
    }
    return cfg.Recipients, nil
}
```

**Step 2: Update CreateNotificationChannel for email channels**

Email channels don't get a signing secret. Modify `internal/store/notification_channel.go`:

```go
func (s *Store) CreateNotificationChannel(ctx context.Context, orgID uuid.UUID, name, chanType string, config json.RawMessage) (*Row, string, error) {
    var secret string
    var signingSecretParam sql.NullString
    if chanType == "webhook" {
        var err error
        secret, err = generateSigningSecret()
        if err != nil {
            return nil, "", err
        }
        signingSecretParam = sql.NullString{String: secret, Valid: true}
    }
    // ... pass signingSecretParam to sqlc
}
```

**Step 3: Guard rotate-secret and clear-secondary**

In `rotateSecretHandler` and `clearSecondarySecretHandler`, add a channel type check after fetching:

```go
// After fetching the channel:
ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
if ch.Type != "webhook" {
    http.Error(w, "signing secret operations are only available for webhook channels", http.StatusUnprocessableEntity)
    return
}
```

**Step 4: Update patchChannelHandler for email config**

In the PATCH handler, add email config re-validation when config is updated and channel type is "email" (mirror the webhook URL re-validation pattern).

**Step 5: Add valid channel type validation**

In `createChannelHandler`, after defaulting type to "webhook", validate:

```go
if req.Type != "webhook" && req.Type != "email" {
    http.Error(w, "type must be 'webhook' or 'email'", http.StatusUnprocessableEntity)
    return
}
```

**Step 6: Write tests**

Add to `internal/api/channels_test.go`:
- `TestCreateChannel_EmailType` — valid email config, 201, no signing_secret in response
- `TestCreateChannel_EmailInvalidRecipients` — empty, invalid addresses, >50, duplicates → 422
- `TestCreateChannel_InvalidType` — type="slack" → 422
- `TestRotateSecret_EmailChannel_Rejected` — 422
- `TestClearSecondary_EmailChannel_Rejected` — 422

**Step 7: Run tests, commit**

```bash
go test ./internal/api/... -run TestChannel -v
git add internal/api/channels.go internal/api/channels_test.go \
       internal/store/notification_channel.go
git commit -m "feat(api): email channel validation, signing secret guards"
```

---

## Task 9: Digest Insert Delivery + Severity Expansion

**Files:**
- Create: `internal/notify/digest.go`
- Test: `internal/notify/digest_test.go`

**Step 1: Write severity expansion helper**

```go
// ABOUTME: Digest runner: claims due reports, queries matching CVEs, fans out to channels.
// ABOUTME: Runs as a synchronous ticker in the worker select loop — all DB, no outbound HTTP.
package notify

// severityRank maps severity strings to numeric rank for threshold expansion.
var severityRank = map[string]int{
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
}

// expandSeverityThreshold returns all severities at or above the given threshold.
// Returns nil if threshold is empty (all severities).
func expandSeverityThreshold(threshold string) []string {
    if threshold == "" {
        return nil
    }
    minRank := severityRank[threshold]
    var result []string
    for sev, rank := range severityRank {
        if rank >= minRank {
            result = append(result, sev)
        }
    }
    return result
}
```

**Step 2: Write next_run_at calculation helpers**

```go
// computeNextRunAt calculates the next occurrence of scheduledTime in the given
// timezone that is strictly after now. Returns UTC.
func computeNextRunAt(scheduledTime time.Time, timezone string) (time.Time, error) {
    loc, err := time.LoadLocation(timezone)
    if err != nil {
        return time.Time{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
    }
    now := time.Now().In(loc)
    candidate := time.Date(now.Year(), now.Month(), now.Day(),
        scheduledTime.Hour(), scheduledTime.Minute(), scheduledTime.Second(), 0, loc)
    if !candidate.After(now) {
        candidate = candidate.AddDate(0, 0, 1)
    }
    return candidate.UTC(), nil
}

// advanceNextRunAt advances next_run_at by one day in the report's timezone.
// Uses AddDate for DST correctness — never adds 24*time.Hour.
func advanceNextRunAt(currentNextRun time.Time, timezone string) (time.Time, error) {
    loc, err := time.LoadLocation(timezone)
    if err != nil {
        return time.Time{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
    }
    inTZ := currentNextRun.In(loc)
    next := inTZ.AddDate(0, 0, 1)
    return next.UTC(), nil
}
```

**Step 3: Write the digest insert delivery SQL**

Add to `internal/store/queries/notification_deliveries.sql`:

```sql
-- name: InsertDigestDelivery :exec
-- Digest runner: insert a digest delivery for a report+channel.
-- ON CONFLICT DO NOTHING: safety net against double-dispatch.
INSERT INTO notification_deliveries (org_id, report_id, channel_id, kind, payload, send_after)
VALUES ($1, $2, $3, 'digest', $4, now())
ON CONFLICT (report_id, channel_id) WHERE status = 'pending' AND kind = 'digest'
DO NOTHING;
```

Regenerate sqlc and add the store method.

**Step 4: Write digest CVE query**

Add to `internal/store/queries/cves.sql` (or a new `digest.sql`):

```sql
-- name: DigestCVEs :many
-- Fetch CVEs modified since $1, optionally filtered by severity.
-- Sort: severity desc (critical > high > medium > low), CVSS v3 tiebreaker.
SELECT cve_id, severity, cvss_v3_score, cvss_v4_score, epss_score,
       description_primary, exploit_available, in_cisa_kev
FROM cves
WHERE date_modified_canonical > $1
  AND status NOT IN ('rejected', 'withdrawn')
  AND ($2::text[] IS NULL OR severity = ANY($2::text[]))
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        ELSE 5
    END,
    cvss_v3_score DESC NULLS LAST
LIMIT 500;
```

**Step 5: Write digest runner method**

```go
func (w *Worker) runDigest(ctx context.Context) {
    reports, err := w.store.ClaimDueReports(ctx, 10)
    if err != nil {
        w.log.Error("claim due reports", "err", err)
        return
    }
    for _, report := range reports {
        if err := w.executeDigestReport(ctx, report); err != nil {
            w.log.Error("execute digest report", "report_id", report.ID, "err", err)
        }
    }
}
```

`executeDigestReport` does:
1. Compute since-time: `COALESCE(last_run_at, created_at)`
2. Expand severity threshold
3. Query CVEs
4. Build `[]cveSnapshot` payload
5. List active channels for digest
6. Insert delivery row per channel (or heartbeat if empty + send_on_empty)
7. Advance report: set `last_run_at = now()`, advance `next_run_at`
8. Handle missed-run catch-up: if `next_run_at < now() - 2h`, log and skip-advance to next future time

**Step 6: Write tests**

- `TestExpandSeverityThreshold` — "high" → {"critical","high"}, "" → nil, "low" → all four
- `TestComputeNextRunAt` — verify future time, DST boundary
- `TestAdvanceNextRunAt` — verify DST-correct advancement

**Step 7: Run tests, commit**

```bash
go test ./internal/notify/... -run "TestExpand|TestCompute|TestAdvance" -v
git add internal/notify/digest.go internal/notify/digest_test.go \
       internal/store/queries/notification_deliveries.sql \
       internal/store/queries/cves.sql internal/store/generated/
git commit -m "feat(notify): digest runner with severity expansion and DST-safe scheduling"
```

---

## Task 10: Digest Report API Handlers

**Files:**
- Create: `internal/api/reports.go`
- Test: `internal/api/reports_test.go`
- Modify: `internal/api/server.go` — add routes

**Step 1: Write request/response types**

Follow `channels.go` pattern:

```go
// ABOUTME: HTTP handlers for scheduled digest report CRUD and channel bindings.
// ABOUTME: Mirrors the alert-rules + channels handler patterns.
package api

type createReportBody struct {
    Name              string    `json:"name"`
    ScheduledTime     string    `json:"scheduled_time"`     // "HH:MM" or "HH:MM:SS"
    Timezone          string    `json:"timezone"`            // IANA timezone
    SeverityThreshold *string   `json:"severity_threshold"`  // null = all
    WatchlistIDs      []string  `json:"watchlist_ids"`       // null = all
    SendOnEmpty       *bool     `json:"send_on_empty"`
    AISummary         *bool     `json:"ai_summary"`
}

type patchReportBody struct {
    Name              *string   `json:"name"`
    ScheduledTime     *string   `json:"scheduled_time"`
    Timezone          *string   `json:"timezone"`
    SeverityThreshold *string   `json:"severity_threshold"`
    WatchlistIDs      *[]string `json:"watchlist_ids"`
    SendOnEmpty       *bool     `json:"send_on_empty"`
    AISummary         *bool     `json:"ai_summary"`
    Status            *string   `json:"status"`
}

type reportEntry struct {
    ID                string   `json:"id"`
    OrgID             string   `json:"org_id"`
    Name              string   `json:"name"`
    ScheduledTime     string   `json:"scheduled_time"`
    Timezone          string   `json:"timezone"`
    NextRunAt         string   `json:"next_run_at"`
    LastRunAt         *string  `json:"last_run_at"`
    SeverityThreshold *string  `json:"severity_threshold"`
    WatchlistIDs      []string `json:"watchlist_ids"`
    SendOnEmpty       bool     `json:"send_on_empty"`
    AISummary         bool     `json:"ai_summary"`
    Status            string   `json:"status"`
    CreatedAt         string   `json:"created_at"`
    UpdatedAt         string   `json:"updated_at"`
}
```

**Step 2: Write handlers**

Implement following channels.go/alert_rules.go patterns:

- `createReportHandler` — validate name, timezone (`time.LoadLocation`), parse scheduled_time, compute `next_run_at` via `computeNextRunAt()`, validate severity_threshold, store. Return 201.
- `getReportHandler` — standard get with 404 on nil.
- `listReportsHandler` — list all active reports for org.
- `patchReportHandler` — pointer-typed partial update. Recalculate `next_run_at` if `scheduled_time`, `timezone`, or `status` changes (un-pause → recalculate). Validate changed fields.
- `deleteReportHandler` — soft-delete.
- `bindChannelToReportHandler` — idempotent PUT, 204.
- `unbindChannelFromReportHandler` — DELETE, 204.
- `listReportChannelsHandler` — GET, list bound channels.

**Step 3: Register routes**

Add to `internal/api/server.go`, inside the org-scoped route group (after channels routes):

```go
r.Route("/reports", func(r chi.Router) {
    r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listReportsHandler)
    r.With(srv.RequireOrgRole(RoleMember)).Post("/", srv.createReportHandler)
    r.Route("/{id}", func(r chi.Router) {
        r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.getReportHandler)
        r.With(srv.RequireOrgRole(RoleMember)).Patch("/", srv.patchReportHandler)
        r.With(srv.RequireOrgRole(RoleMember)).Delete("/", srv.deleteReportHandler)
        r.Route("/channels", func(r chi.Router) {
            r.With(srv.RequireOrgRole(RoleViewer)).Get("/", srv.listReportChannelsHandler)
            r.With(srv.RequireOrgRole(RoleMember)).Put("/{channel_id}", srv.bindChannelToReportHandler)
            r.With(srv.RequireOrgRole(RoleMember)).Delete("/{channel_id}", srv.unbindChannelFromReportHandler)
        })
    })
})
```

**Step 4: Write tests**

Create `internal/api/reports_test.go`:
- `TestCreateReport_Valid` — valid input, 201, response includes next_run_at
- `TestCreateReport_InvalidTimezone` — 422
- `TestCreateReport_MissingName` — 422
- `TestCreateReport_InvalidSeverityThreshold` — 422
- `TestGetReport_NotFound` — 404
- `TestListReports` — returns list
- `TestPatchReport_UpdateSchedule` — changed scheduled_time recalculates next_run_at
- `TestPatchReport_Unpause` — status paused→active recalculates next_run_at
- `TestDeleteReport` — 204, no longer in list
- `TestBindChannelToReport` — 204, appears in list
- `TestUnbindChannelFromReport` — 204, removed from list

**Step 5: Run tests, commit**

```bash
go test ./internal/api/... -run TestReport -v
git add internal/api/reports.go internal/api/reports_test.go internal/api/server.go
git commit -m "feat(api): digest report CRUD and channel binding handlers"
```

---

## Task 11: Wire Everything Together

**Files:**
- Modify: `cmd/cvert-ops/main.go` — pass SMTP config, external URL to worker
- Modify: `internal/notify/worker.go` — add digest ticker to Start()
- Modify: `cmd/cvert-ops/main.go` — update `expectedSchemaVersion`

**Step 1: Update NewWorker call in main.go**

```go
smtpCfg := notify.SmtpConfig{
    Host:     cfg.SMTPHost,
    Port:     cfg.SMTPPort,
    From:     cfg.SMTPFrom,
    Username: cfg.SMTPUsername,
    Password: cfg.SMTPPassword,
    TLS:      cfg.SMTPTLS,
}
deliveryWorker := notify.NewWorker(st, deliveryClient, notify.WorkerConfig{
    ClaimBatchSize:      cfg.NotifyClaimBatchSize,
    MaxAttempts:         cfg.NotifyMaxAttempts,
    BackoffBaseSeconds:  cfg.NotifyBackoffBaseSeconds,
    MaxConcurrentPerOrg: cfg.NotifyMaxConcurrentPerOrg,
}, smtpCfg, cfg.ExternalURL)
```

**Step 2: Add digest ticker to worker Start()**

```go
func (w *Worker) Start(ctx context.Context) {
    claimTicker := time.NewTicker(5 * time.Second)
    stuckTicker := time.NewTicker(60 * time.Second)
    recoveryTicker := time.NewTicker(5 * time.Minute)
    digestTicker := time.NewTicker(60 * time.Second)  // new
    defer claimTicker.Stop()
    defer stuckTicker.Stop()
    defer recoveryTicker.Stop()
    defer digestTicker.Stop()  // new

    for {
        select {
        case <-ctx.Done():
            w.wg.Wait()
            return
        case <-claimTicker.C:
            w.runClaim(ctx)
        case <-stuckTicker.C:
            w.runStuckReset(ctx)
        case <-recoveryTicker.C:
            w.runRecovery(ctx)
        case <-digestTicker.C:  // new
            w.runDigest(ctx)
        }
    }
}
```

**Step 3: Update expectedSchemaVersion**

In `cmd/cvert-ops/main.go`, update:

```go
const expectedSchemaVersion = 19  // was 17
```

**Step 4: Verify full build**

```bash
go build ./...
```

**Step 5: Run full test suite**

```bash
go test ./...
```

**Step 6: Run linter**

```bash
golangci-lint run
```

**Step 7: Commit**

```bash
git add cmd/cvert-ops/main.go internal/notify/worker.go
git commit -m "feat(notify): wire SMTP config, external URL, and digest ticker into worker"
```

---

## Task 12: Final Quality Checks

**Step 1: Run /pitfall-check on `internal/notify/`**

Check for:
- `defer` inside loops
- `time.After` in loops (should be `NewTicker`)
- Open DB transaction during outbound HTTP
- `errgroup` instead of `sync.WaitGroup` for fan-out

**Step 2: Run /schema-review on migrations 000018 and 000019**

Check for:
- RLS completeness
- Correct grants per table type
- Index coverage
- FK constraints

**Step 3: Run /security-review on `internal/api/channels.go`, `internal/api/reports.go`**

Check for:
- Input validation completeness
- Tenant isolation
- Email header injection defense

**Step 4: Run /plan-check against PLAN.md §11.4 and §12**

Verify all MUST items are satisfied.

**Step 5: Final commit if any fixes**

```bash
git add -A && git commit -m "fix(notify): quality-check fixes from pitfall/plan/security review"
```
