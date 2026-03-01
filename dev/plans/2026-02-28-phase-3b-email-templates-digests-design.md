# Phase 3b: Email Channels, Notification Templates, Scheduled Digests

**Goal:** Add email as a notification channel type, introduce a template rendering pipeline for email delivery, and build a scheduled daily digest system.

**Architecture:** Extend the existing delivery worker with a channel-type switch (webhook vs email) and a kind switch (alert vs digest) for template selection. Email rendering uses embedded Go templates. Digest scheduling uses a new `scheduled_reports` table with timezone-aware `next_run_at` polling. SMTP delivery via `wneessen/go-mail/v2`.

**Tech Stack additions:** `github.com/wneessen/go-mail/v2` (SMTP client with MIME multipart, STARTTLS, modern auth).

**Depends on:** Phase 3a (webhook delivery pipeline, channel CRUD, delivery worker).

---

## 1. Email Channel Type

### Schema Changes

- `ALTER COLUMN signing_secret DROP NOT NULL` on `notification_channels`. Email channels store NULL; webhook channels keep their secrets. (`signing_secret_secondary` is already nullable.)
- Extend type CHECK: `type IN ('webhook', 'email')`.
- Email channel config schema: `{"recipients": ["alice@acme.com", "bob@acme.com"]}`.

### Validation

- Email channels: `recipients` must be non-empty array, each validated via `net/mail.ParseAddress()`, max 50 per channel, no duplicates.
- No signing secret generated for email channels (columns stay NULL).
- `rotate-secret` and `clear-secondary` endpoints return 422 for non-webhook channel types.

### SMTP Delivery (`internal/notify/email.go`)

- `EmailSend(ctx, smtpCfg SmtpConfig, recipients []string, subject, htmlBody, textBody) error`
- Uses `wneessen/go-mail/v2` with `DialAndSend()` — dial per delivery, no persistent connection. Sporadic alert emails don't benefit from persistent SMTP connections.
- All recipients in single email via BCC. Retry = retry all recipients.
- `SmtpConfig` struct populated from global env vars (`SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`).

### SMTP Error Classification

- 4xx (transient — greylisting, rate limit, temp failure): retry with existing exponential backoff.
- 5xx (permanent — invalid recipient, rejected sender, auth failure): exhaust immediately with SMTP error in `last_error`. Admin can fix config and replay from DLQ.
- go-mail exposes SMTP status codes via typed errors.

### Worker Integration

- `deliver()` gains a channel-type switch: `"webhook"` → existing `Send()` path, `"email"` → render template + `EmailSend()`.
- Template rendering happens at delivery time (not dispatch time). Payload stays as structured JSON in the DB.
- `signing_secret` column becomes `sql.NullString` in sqlc — webhook path updated to use `.String`.
- New `X-CVErtOps-Kind: alert|digest` header on webhook deliveries so consumers can distinguish delivery kinds without payload format changes.

---

## 2. Template System

### Architecture

- Templates embedded in `templates/` via `embed.FS`, parsed once at package init.
- Each template file parsed independently into its own `*template.Template` instance — prevents `{{define}}` namespace collisions across files.
- HTML templates parsed with `html/template` (auto-escaped). Plaintext parsed with `text/template`. Never use `template.HTML` with feed-sourced or user-sourced data.
- Each file contains `{{define "subject"}}...{{end}}` and `{{define "body"}}...{{end}}` blocks.

### Template Files (MVP)

| File | Purpose |
|------|---------|
| `templates/email_alert.html.tmpl` | Alert email HTML body + subject |
| `templates/email_alert.txt.tmpl` | Alert email plaintext fallback + subject |
| `templates/email_digest.html.tmpl` | Digest email HTML body + subject |
| `templates/email_digest.txt.tmpl` | Digest email plaintext fallback + subject |

### Template Data Structs (`internal/notify/template.go`)

```go
type AlertTemplateData struct {
    RuleName    string       // looked up at render time from delivery's rule_id
    RuleID      string
    CVEs        []CVESummary // deserialized from delivery payload
    CVErtOpsURL string       // from EXTERNAL_URL config; may be empty
}

type DigestTemplateData struct {
    OrgName     string
    ReportName  string
    Date        string       // formatted in report's timezone
    CVEs        []CVESummary // sorted severity desc, capped at 25
    TotalCount  int          // pre-truncation count
    Truncated   bool         // true when TotalCount > 25
    ViewAllURL  string       // omitted if EXTERNAL_URL not configured
    AISummary   string       // plumbing — empty string until AI gateway
    CVErtOpsURL string
}

type CVESummary struct {
    CVEID        string
    Severity     string   // empty string if source was nil
    CVSSV3Score  *float64
    CVSSV4Score  *float64
    EPSSScore    *float64
    Description  string   // truncated to 280 chars at conversion time
    ExploitAvail bool
    InCISAKEV    bool
    DetailURL    string   // constructed at render time; empty if no EXTERNAL_URL
}
```

### Rendering (`internal/notify/render.go`)

- `RenderAlert(data AlertTemplateData) (subject, html, text string, err error)`
- `RenderDigest(data DigestTemplateData) (subject, html, text string, err error)`
- Both strip `\r` and `\n` from rendered subjects (email header injection defense).
- `cveSnapshot → CVESummary` converter: handles nil pointer fields, constructs `DetailURL`, truncates `Description` to 280 chars.
- Templates handle missing `CVErtOpsURL` gracefully — deep links omitted, not rendered as broken URLs.

### Email HTML Style

- Fixed-width table layout (600px max). All CSS inline — Gmail strips `<style>` tags.
- No external assets, no images.
- Severity badges with white text: Critical (#d32f2f), High (#f57c00), Medium (#ffa000), Low (#1976d2).

### Delivery Kind Discriminator (Schema)

- `ADD COLUMN kind TEXT NOT NULL DEFAULT 'alert' CHECK (kind IN ('alert', 'digest'))` on `notification_deliveries`.
- `ALTER COLUMN rule_id DROP NOT NULL`.
- `ADD COLUMN report_id UUID NULL REFERENCES scheduled_reports(id) ON DELETE CASCADE`.
- CHECK constraint: `(kind = 'alert' AND rule_id IS NOT NULL) OR (kind = 'digest' AND report_id IS NOT NULL)`.
- Migration ordering: `scheduled_reports` table created before `notification_deliveries` is altered.
- Both alert and digest payloads use the same `[]cveSnapshot` JSON array format.
- Debounce indexes updated:
  - Drop: `UNIQUE (rule_id, channel_id) WHERE status = 'pending'`
  - Create: `UNIQUE (rule_id, channel_id) WHERE status = 'pending' AND kind = 'alert'`
  - Create: `UNIQUE (report_id, channel_id) WHERE status = 'pending' AND kind = 'digest'`
  - Create new indexes before dropping old one (no unprotected window).
  - All index operations use `CONCURRENTLY`; migration file needs `-- migrate:no-transaction`.
- Add `(report_id)` BTREE index for delivery history queries.

### Webhook Passthrough

Webhook channels continue receiving raw JSON payload (`[]cveSnapshot` array) for both alert and digest deliveries — no template rendering. `X-CVErtOps-Kind` header distinguishes the two.

### Worker Switch Logic

```
channel.Type == "webhook":
    → Send(raw payload)  // kind-agnostic

channel.Type == "email":
    kind == "alert"  → RenderAlert() → EmailSend()
    kind == "digest" → RenderDigest() → EmailSend()
```

---

## 3. Scheduled Digest Reports

### Schema — `scheduled_reports` (soft-delete, org-scoped)

| Column | Type | Notes |
|--------|------|-------|
| `id` | `UUID PK` | |
| `org_id` | `UUID NOT NULL` | RLS-scoped |
| `name` | `TEXT NOT NULL` | User-facing label |
| `scheduled_time` | `TIME NOT NULL` | Wall-clock (e.g., `09:00:00`) |
| `timezone` | `TEXT NOT NULL DEFAULT 'UTC'` | IANA name, validated via `time.LoadLocation` at create/update. Max 40 chars. |
| `next_run_at` | `TIMESTAMPTZ NOT NULL` | Precomputed UTC — what the scheduler polls |
| `last_run_at` | `TIMESTAMPTZ NULL` | NULL until first successful run |
| `severity_threshold` | `TEXT NULL CHECK (severity_threshold IN ('critical','high','medium','low'))` | NULL = all severities. Threshold = "this and above." |
| `watchlist_ids` | `UUID[] NULL` | No FK (array). NULL = all CVEs. Non-empty = filter by these. Reject empty arrays at API layer. App-layer validation only. |
| `send_on_empty` | `BOOLEAN NOT NULL DEFAULT TRUE` | Heartbeat delivery when no CVEs match |
| `ai_summary` | `BOOLEAN NOT NULL DEFAULT FALSE` | Plumbing — no-op until AI gateway |
| `status` | `TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused'))` | |
| `deleted_at` | `TIMESTAMPTZ NULL` | Soft-delete |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |

Daily recurrence only (hardcoded). No `recurrence` column for now — trivial migration to add when weekly is needed.

Per-org admin-configured. Per-user opt-in is additive later via a `digest_subscriptions` join table — no schema changes to `scheduled_reports` required.

**RLS:** ENABLE + FORCE, dual-escape policy.
**Grants:** `SELECT, INSERT, UPDATE` (soft-delete, no DELETE).
**Indexes:**
- `(org_id)` BTREE
- `UNIQUE (org_id, name) WHERE deleted_at IS NULL` (partial)
- `(next_run_at) WHERE status = 'active' AND deleted_at IS NULL` (scheduler poll)

### `report_channels` Join Table

Same pattern as `alert_rule_channels`:
- `(report_id UUID, channel_id UUID, org_id UUID, created_at TIMESTAMPTZ)`
- PK: `(report_id, channel_id)`
- `report_id` FK → `scheduled_reports(id) ON DELETE CASCADE`
- `channel_id` FK → `notification_channels(id) ON DELETE RESTRICT`
- Denormalized `org_id` for RLS
- RLS, GRANT `SELECT, INSERT, DELETE` (hard-delete)
- Indexes: `(org_id)`, `(channel_id)` (pre-flight for channel deletion)

### Channel Deletion Guard

`deleteChannelHandler` must check both `alert_rule_channels` AND `report_channels` before allowing channel deletion. Return 409 if the channel is bound to any active alert rule or digest report.

### Digest Runner (`internal/notify/digest.go`)

New 60s ticker in worker's `Start()` select loop. Runs synchronously (all DB work, no outbound HTTP).

Each tick:
1. Claim due reports: `SELECT ... FROM scheduled_reports WHERE status = 'active' AND next_run_at <= now() AND deleted_at IS NULL FOR UPDATE SKIP LOCKED LIMIT 10`
2. Per claimed report (single transaction):
   a. Query CVEs: `date_modified_canonical > COALESCE(last_run_at, created_at)`, filtered by severity threshold expansion (`'high'` → `{'critical','high'}`)
   b. Watchlist filtering: **deferred** — severity-only for initial implementation. `watchlist_ids` column present in schema but unused until affected-products matching infrastructure is available.
   c. Sort by severity desc, CVSS v3 desc as tiebreaker
   d. Build `[]cveSnapshot` payload (full set — truncation at render time)
   e. For each bound channel (via `ListActiveChannelsForDigest`): `INSERT INTO notification_deliveries (kind='digest', report_id=...) ON CONFLICT DO NOTHING` (safety net, not debounce)
   f. If no CVEs match and `send_on_empty = true`: insert delivery with empty CVE array (heartbeat)
   g. Update `last_run_at = now()`
   h. Advance `next_run_at` (DST-correct):
      ```go
      loc, _ := time.LoadLocation(report.Timezone)
      prev := report.NextRunAt.In(loc)
      next := prev.AddDate(0, 0, 1)
      report.NextRunAt = next.UTC()
      ```
      Never `prev.Add(24 * time.Hour)` — drifts ±1 hour across DST boundaries.
3. Commit transaction.
4. Worker's claim ticker picks up the new delivery rows on the next cycle (≤5s latency).

### Missed-Run Catch-Up

If `next_run_at < now() - 2 hours`:
- Deliver single catch-up digest covering `COALESCE(last_run_at, created_at)` to `now()`.
- Advance `next_run_at` to next future occurrence (skip all missed intervals).
- Log catch-up event with number of skipped runs.
- Do NOT deliver one digest per missed interval.

### `next_run_at` Calculation

On create, un-pause, or PATCH when `scheduled_time`/`timezone` changes:

```go
loc, _ := time.LoadLocation(timezone)
now := time.Now().In(loc)
candidate := time.Date(now.Year(), now.Month(), now.Day(),
    schedHour, schedMin, 0, 0, loc)
if !candidate.After(now) {
    candidate = candidate.AddDate(0, 0, 1) // tomorrow
}
nextRunAt = candidate.UTC()
```

### API Endpoints (admin+)

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/orgs/{org_id}/reports` | POST | Create report. Validate timezone. Compute initial `next_run_at`. Return in response. |
| `/orgs/{org_id}/reports` | GET | List active reports (no pagination — low cardinality). |
| `/orgs/{org_id}/reports/{id}` | GET | Detail including `next_run_at`, `last_run_at`. |
| `/orgs/{org_id}/reports/{id}` | PATCH | Pointer fields. Recalculates `next_run_at` if `scheduled_time`, `timezone`, or `status` changes. |
| `/orgs/{org_id}/reports/{id}` | DELETE | Soft-delete. |
| `/orgs/{org_id}/reports/{id}/channels/{channel_id}` | PUT | Bind channel (idempotent, 204). |
| `/orgs/{org_id}/reports/{id}/channels/{channel_id}` | DELETE | Unbind channel (204 or 404). |
| `/orgs/{org_id}/reports/{id}/channels` | GET | List bound channels. |

---

## 4. Operational Concerns

### Config

- `EXTERNAL_URL` env var needed for template deep links. Templates handle missing value gracefully (links omitted, not broken).
- SMTP config already exists in `internal/config/config.go`: `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`.

### Dependency

`github.com/wneessen/go-mail/v2` — actively maintained (v0.7.2, Sep 2025), minimal deps, MIME multipart, STARTTLS, modern auth.

### Out of Scope (Phase 3b)

- **Slack channels** — future phase
- **Custom user-provided templates** — P1/Enterprise feature
- **Watchlist-scoped digest filtering** — `watchlist_ids` column present but unused; depends on affected-products matching infrastructure
- **AI executive summary execution** — `ai_summary` field plumbed through; LLM call deferred to AI gateway phase
- **Email bounce-back processing** — requires inbound mail handler or SMTP provider webhook
- **Per-user digest subscriptions** — additive later via `digest_subscriptions` join table
- **Weekly/custom digest recurrence** — additive later via `recurrence` column + CHECK extension

---

## 5. Migration Summary

All schema changes in dependency order:

1. **Create `scheduled_reports`** — new table with RLS, grants, indexes
2. **Create `report_channels`** — new join table with RLS, grants, indexes
3. **Alter `notification_channels`** — `signing_secret` DROP NOT NULL, extend type CHECK to include `'email'`
4. **Alter `notification_deliveries`** — add `kind`, make `rule_id` nullable, add `report_id` FK, add CHECK constraint, recreate debounce indexes (CONCURRENTLY, `-- migrate:no-transaction`), add `(report_id)` index

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| SMTP library | `wneessen/go-mail/v2` | Active, MIME multipart, minimal deps |
| SMTP connection | Dial-per-send | Sporadic sends; persistent connections go stale |
| Email recipients | In channel config JSONB | Consistent with webhook model (one channel = one destination) |
| Recipient delivery | BCC all, retry all | Matches webhook model; split per-recipient later if needed |
| Template rendering | Delivery time | Single source of truth; template updates apply to pending deliveries |
| Worker dispatch | Type-switch in deliver() | Simple; extract Sender interface when third type arrives |
| Signing secret | Nullable column | Clean semantics; email channels don't need HMAC |
| Digest ownership | Per-org, admin-configured | User opt-in additive later |
| Digest recurrence | Daily only (hardcoded) | YAGNI; weekly is a trivial addition |
| AI summary | Plumbing only | Field in payload, empty until AI gateway |
| Webhook payload format | Unchanged (bare array) | Non-breaking; `X-CVErtOps-Kind` header for kind distinction |
| Watchlist digest filtering | Deferred | Schema column present; implementation depends on affected-products matching |
