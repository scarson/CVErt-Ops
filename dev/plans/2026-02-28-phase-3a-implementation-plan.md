# Phase 3a — Notification Delivery (Webhook) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement end-to-end webhook notification delivery: channel CRUD, rule–channel
binding, evaluator fanout, delivery worker with debounce/retry/per-org semaphore,
HMAC signing, DLQ replay, secret rotation, and orphaned-event recovery.

**Architecture:** Approach A — injected `Dispatcher` interface. The evaluator calls
`dispatcher.Fanout()` after each new `alert_event` auto-commits. Fanout creates/updates
a `notification_deliveries` row per channel (debounce upsert). A separate delivery
worker polls that table, claims rows with `FOR UPDATE SKIP LOCKED`, executes outbound
HTTP, and updates status in a new transaction.

**Tech Stack:** Go stdlib `database/sql`, sqlc-generated queries in
`internal/store/generated/`, squirrel for dynamic queries, `doyensec/safeurl` for SSRF-
safe HTTP, `crypto/hmac`+`crypto/sha256` for webhook signing, huma+chi for HTTP handlers.

**Design doc:** `dev/plans/2026-02-28-phase-3a-notification-delivery-design.md`

---

## Key facts before you start

- sqlc config: `sqlc.yaml` — queries in `internal/store/queries/`, generated output in
  `internal/store/generated/` (package `store`). Run `sqlc generate` after every `.sql` change.
- `evaluateRule()` calls `InsertAlertEvent` **outside** any transaction — it auto-commits.
  `bypassTx` only wraps `queryCandidates`. Fanout fires after the auto-commit, no
  transaction coordination needed.
- `Store` methods live in `internal/store/*.go`. They call `generated.New(db)` or use
  `s.withOrgTx` / `s.withBypassTx` helpers. Follow the pattern in `watchlist.go`.
- `internal/store/generated/` is regenerated — never edit it directly.
- Test DB: look at existing `*_test.go` files in `internal/store/` for the test DB
  setup pattern (typically `testDB(t)` or similar helper).
- golangci-lint must be clean before each commit: `golangci-lint run ./...`
- safeurl is not yet in go.mod; Task 6 adds it.

---

## Task 1: Migration 000017 — notification tables

**Files:**
- Create: `migrations/000017_create_notification_tables.up.sql`
- Create: `migrations/000017_create_notification_tables.down.sql`

**Step 1: Write the up migration**

```sql
-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

CREATE TABLE IF NOT EXISTS notification_channels (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                   UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                     TEXT        NOT NULL CHECK (char_length(name) <= 255),
    type                     TEXT        NOT NULL CHECK (type IN ('webhook')),
    config                   JSONB       NOT NULL DEFAULT '{}',
    CONSTRAINT nc_webhook_url CHECK (type != 'webhook' OR config ? 'url'),
    -- Server-generated 256-bit random secret. Never returned in GET responses.
    signing_secret           TEXT        NOT NULL,
    -- Populated during rotation; cleared after grace period via clear-secondary endpoint.
    signing_secret_secondary TEXT        NULL,
    deleted_at               TIMESTAMPTZ NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON notification_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Soft-delete: no DELETE grant.
GRANT SELECT, INSERT, UPDATE ON notification_channels TO cvert_ops_app;

-- alert_rule_channels: M:M binding of alert rules to notification channels.
-- Hard-delete: bindings have no independent identity.
-- org_id denormalized for RLS (no FK — established pattern; see watchlist_items).
-- rule_id CASCADE: binding deleted when rule is deleted.
-- channel_id RESTRICT: last-resort guard against hard-deleting a soft-delete entity.
CREATE TABLE IF NOT EXISTS alert_rule_channels (
    rule_id    UUID        NOT NULL REFERENCES alert_rules(id)            ON DELETE CASCADE,
    channel_id UUID        NOT NULL REFERENCES notification_channels(id)  ON DELETE RESTRICT,
    org_id     UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, channel_id)
);

ALTER TABLE alert_rule_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rule_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON alert_rule_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Hard-delete join table: no UPDATE grant.
GRANT SELECT, INSERT, DELETE ON alert_rule_channels TO cvert_ops_app;

-- notification_deliveries: delivery job queue.
-- Debounce: one pending row per (rule, channel); CVE snapshots accumulate in payload.
-- rule_id has no FK: historical reference; alert_rules uses soft-delete.
-- Retention: 90 days per §21.2.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID        NOT NULL,
    -- No FK: historical reference preserved after rule soft-deletion.
    rule_id           UUID        NOT NULL,
    channel_id        UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    status            TEXT        NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','processing','succeeded','failed','cancelled')),
    attempt_count     INT         NOT NULL DEFAULT 0,
    -- JSONB array of CVE snapshots accumulated during the debounce window.
    payload           JSONB       NOT NULL DEFAULT '[]',
    -- Dual-purpose: debounce window end and retry backoff next-attempt time.
    send_after        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_attempted_at TIMESTAMPTZ NULL,
    delivered_at      TIMESTAMPTZ NULL,
    last_error        TEXT        NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON notification_deliveries
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- DELETE included: retention job hard-deletes rows older than 90 days (§21.2).
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_deliveries TO cvert_ops_app;

-- High-churn: INSERT + 2 UPDATEs (claim → processing → succeeded/failed) per delivery.
ALTER TABLE notification_deliveries SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 70
);

-- ── notification_channels indexes ────────────────────────────────────────────

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_channels_org_id_idx
    ON notification_channels (org_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_channels_active_idx
    ON notification_channels (org_id) WHERE deleted_at IS NULL;

-- Partial unique: name unique among live channels in an org.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS notification_channels_name_uq
    ON notification_channels (org_id, name) WHERE deleted_at IS NULL;

-- ── alert_rule_channels indexes ──────────────────────────────────────────────

CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_channels_org_id_idx
    ON alert_rule_channels (org_id);

-- Channel deletion pre-flight: "which rules reference this channel?"
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_channels_channel_id_idx
    ON alert_rule_channels (channel_id);

-- ── notification_deliveries indexes ──────────────────────────────────────────

-- At most one pending delivery per (rule, channel). Debounce ON CONFLICT target.
-- Deviation from PLAN.md per-event idempotency key: debounce groups N events into
-- one row, making a per-event key incorrect.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_notification_deliveries_pending
    ON notification_deliveries (rule_id, channel_id) WHERE status = 'pending';

-- Delivery worker claim query.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_claim_idx
    ON notification_deliveries (send_after) WHERE status = 'pending';

-- Per-org concurrency cap: count in-flight deliveries per org.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_processing_idx
    ON notification_deliveries (org_id) WHERE status = 'processing';

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_org_id_idx
    ON notification_deliveries (org_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_channel_id_idx
    ON notification_deliveries (channel_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_rule_id_idx
    ON notification_deliveries (rule_id);

-- §21.3 explicit requirement: retention cleanup batches by created_at.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_created_at_idx
    ON notification_deliveries (created_at);
```

**Step 2: Write the down migration**

```sql
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS alert_rule_channels;
DROP TABLE IF EXISTS notification_channels;
```

**Step 3: Run migration**

```bash
migrate -path migrations -database "$DATABASE_URL" up
```

Expected: `000017/up` runs without error. Verify:
```bash
psql "$DATABASE_URL" -c "\dt notification_*" -c "\dt alert_rule_channels"
```

**Step 4: Commit**

```bash
git add migrations/000017_create_notification_tables.up.sql \
        migrations/000017_create_notification_tables.down.sql
git commit -m "feat(migrations): Phase 3a schema — notification_channels, alert_rule_channels, notification_deliveries (000017)"
```

---

## Task 2: Config — add missing notify env vars

**Files:**
- Modify: `internal/config/config.go` (Notifications section, around line 72)

The config already has `NotifyMaxConcurrentPerOrg`, `NotifyDebounceSeconds`,
`WebhookSecretGraceHours`. Add three more:

**Step 1: Add fields**

In the `// ── Notifications ──` section, after `WebhookSecretGraceHours`, add:

```go
NotifyClaimBatchSize      int `env:"NOTIFY_CLAIM_BATCH_SIZE"       envDefault:"50"`
NotifyMaxAttempts         int `env:"NOTIFY_MAX_ATTEMPTS"           envDefault:"4"`
NotifyBackoffBaseSeconds  int `env:"NOTIFY_BACKOFF_BASE_SECONDS"   envDefault:"30"`
```

**Step 2: Verify compilation**

```bash
go build ./...
```

Expected: compiles cleanly.

**Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add NOTIFY_CLAIM_BATCH_SIZE, NOTIFY_MAX_ATTEMPTS, NOTIFY_BACKOFF_BASE_SECONDS"
```

---

## Task 3: Store queries — notification_channels

**Files:**
- Create: `internal/store/queries/notification_channels.sql`
- Modify: `internal/store/generated/` (regenerated by sqlc — do not edit)
- Create: `internal/store/notification_channel.go`

**Step 1: Write SQL query file**

```sql
-- ABOUTME: sqlc queries for notification channel CRUD.
-- ABOUTME: Secrets (signing_secret) are excluded from most queries; use GetChannelForDelivery.

-- name: CreateNotificationChannel :one
INSERT INTO notification_channels (org_id, name, type, config, signing_secret)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, org_id, name, type, config, deleted_at, created_at, updated_at;

-- name: GetNotificationChannel :one
SELECT id, org_id, name, type, config, deleted_at, created_at, updated_at
FROM notification_channels
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: GetNotificationChannelForDelivery :one
-- Includes signing secrets — used by delivery worker only; never exposed via API.
SELECT id, org_id, type, config, signing_secret, signing_secret_secondary
FROM notification_channels
WHERE id = $1 AND deleted_at IS NULL
LIMIT 1;

-- name: ListNotificationChannels :many
SELECT id, org_id, name, type, config, deleted_at, created_at, updated_at
FROM notification_channels
WHERE org_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC;

-- name: UpdateNotificationChannel :one
-- Full replacement of mutable fields. Handler reads existing record and applies
-- pointer-typed patch fields before calling this.
UPDATE notification_channels
SET name       = $3,
    config     = $4,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING id, org_id, name, type, config, deleted_at, created_at, updated_at;

-- name: SoftDeleteNotificationChannel :exec
UPDATE notification_channels
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: RotateSigningSecret :one
-- Atomically moves primary → secondary, sets new primary.
UPDATE notification_channels
SET signing_secret_secondary = signing_secret,
    signing_secret           = $3,
    updated_at               = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING signing_secret;

-- name: ClearSecondarySecret :exec
UPDATE notification_channels
SET signing_secret_secondary = NULL, updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: ChannelHasActiveBoundRules :one
-- Pre-flight check before soft-delete. Active = not draft/disabled/deleted.
SELECT EXISTS(
    SELECT 1
    FROM alert_rule_channels arc
    JOIN alert_rules ar ON ar.id = arc.rule_id
    WHERE arc.channel_id = $1
      AND ar.org_id = $2
      AND ar.status NOT IN ('draft', 'disabled', 'deleted')
      AND ar.deleted_at IS NULL
) AS has_active_rules;
```

**Step 2: Regenerate sqlc**

```bash
sqlc generate
```

Expected: `internal/store/generated/notification_channels.sql.go` created, no errors.

**Step 3: Write store wrapper**

Create `internal/store/notification_channel.go`:

```go
// ABOUTME: Store methods for notification channel CRUD.
// ABOUTME: Wraps sqlc-generated queries; excludes secrets from API-facing responses.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store/generated"
)

// ChannelRow is the API-safe view of a notification_channels row (no secrets).
type ChannelRow = generated.CreateNotificationChannelRow

// ChannelDeliveryRow includes secrets for the delivery worker.
type ChannelDeliveryRow = generated.GetNotificationChannelForDeliveryRow

// generateSigningSecret returns 32 cryptographically random bytes as a hex string.
func generateSigningSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate signing secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateNotificationChannel inserts a new channel with a server-generated signing secret.
// Returns the row (no secrets) and the raw signing secret (shown once to the caller).
func (s *Store) CreateNotificationChannel(
	ctx context.Context,
	orgID uuid.UUID,
	name, channelType string,
	config json.RawMessage,
) (ChannelRow, string, error) {
	secret, err := generateSigningSecret()
	if err != nil {
		return ChannelRow{}, "", err
	}
	var row ChannelRow
	err = s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var e error
		row, e = q.CreateNotificationChannel(ctx, generated.CreateNotificationChannelParams{
			OrgID:         orgID,
			Name:          name,
			Type:          channelType,
			Config:        config,
			SigningSecret: secret,
		})
		return e
	})
	return row, secret, err
}

// GetNotificationChannel fetches a channel by id + org (no secrets).
func (s *Store) GetNotificationChannel(ctx context.Context, id, orgID uuid.UUID) (ChannelRow, error) {
	var row ChannelRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var e error
		// GetNotificationChannel returns the same columns as Create minus the secret.
		// Use a type alias if sqlc generates separate row types; otherwise cast.
		ch, e := q.GetNotificationChannel(ctx, generated.GetNotificationChannelParams{
			ID:    id,
			OrgID: orgID,
		})
		if e != nil {
			return e
		}
		row = ChannelRow{
			ID: ch.ID, OrgID: ch.OrgID, Name: ch.Name, Type: ch.Type,
			Config: ch.Config, DeletedAt: ch.DeletedAt, CreatedAt: ch.CreatedAt, UpdatedAt: ch.UpdatedAt,
		}
		return nil
	})
	return row, err
}

// GetNotificationChannelForDelivery fetches a channel with secrets (delivery worker only).
func (s *Store) GetNotificationChannelForDelivery(ctx context.Context, id uuid.UUID) (ChannelDeliveryRow, error) {
	var row ChannelDeliveryRow
	// Uses bypass tx: delivery worker is cross-tenant.
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var e error
		row, e = q.GetNotificationChannelForDelivery(ctx, id)
		return e
	})
	return row, err
}

// ListNotificationChannels returns all live channels for an org.
func (s *Store) ListNotificationChannels(ctx context.Context, orgID uuid.UUID) ([]generated.ListNotificationChannelsRow, error) {
	var rows []generated.ListNotificationChannelsRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var e error
		rows, e = q.ListNotificationChannels(ctx, orgID)
		return e
	})
	return rows, err
}

// UpdateNotificationChannel patches name and/or config. Caller passes existing values for unpatched fields.
func (s *Store) UpdateNotificationChannel(ctx context.Context, id, orgID uuid.UUID, name string, config json.RawMessage) (generated.UpdateNotificationChannelRow, error) {
	var row generated.UpdateNotificationChannelRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var e error
		row, e = q.UpdateNotificationChannel(ctx, generated.UpdateNotificationChannelParams{
			ID: id, OrgID: orgID, Name: name, Config: config,
		})
		return e
	})
	return row, err
}

// SoftDeleteNotificationChannel marks a channel as deleted.
func (s *Store) SoftDeleteNotificationChannel(ctx context.Context, id, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.SoftDeleteNotificationChannel(ctx, generated.SoftDeleteNotificationChannelParams{ID: id, OrgID: orgID})
	})
}

// RotateSigningSecret moves primary secret to secondary and sets a new primary.
// Returns the new primary secret (shown once to the caller).
func (s *Store) RotateSigningSecret(ctx context.Context, id, orgID uuid.UUID) (string, error) {
	newSecret, err := generateSigningSecret()
	if err != nil {
		return "", err
	}
	err = s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		_, e := q.RotateSigningSecret(ctx, generated.RotateSigningSecretParams{
			ID: id, OrgID: orgID, SigningSecret: newSecret,
		})
		return e
	})
	return newSecret, err
}

// ClearSecondarySecret nulls out the secondary signing secret.
func (s *Store) ClearSecondarySecret(ctx context.Context, id, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.ClearSecondarySecret(ctx, generated.ClearSecondarySecretParams{ID: id, OrgID: orgID})
	})
}

// ChannelHasActiveBoundRules returns true if any active alert rules reference this channel.
func (s *Store) ChannelHasActiveBoundRules(ctx context.Context, channelID, orgID uuid.UUID) (bool, error) {
	var has bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, e := q.ChannelHasActiveBoundRules(ctx, generated.ChannelHasActiveBoundRulesParams{
			ChannelID: channelID, OrgID: orgID,
		})
		if e != nil {
			return e
		}
		has = row.HasActiveRules
		return nil
	})
	return has, err
}
```

**Step 4: Build**

```bash
go build ./...
```

Expected: compiles. Fix any sqlc type mismatches (the generated row struct field names
may differ — check `internal/store/generated/notification_channels.sql.go` for exact names).

**Step 5: Commit**

```bash
git add internal/store/queries/notification_channels.sql \
        internal/store/generated/ \
        internal/store/notification_channel.go
git commit -m "feat(store): notification_channels queries + store methods"
```

---

## Task 4: Store queries — alert_rule_channels

**Files:**
- Create: `internal/store/queries/alert_rule_channels.sql`
- Modify: `internal/store/generated/` (sqlc regenerate)
- Create: `internal/store/alert_rule_channel.go`

**Step 1: Write SQL**

```sql
-- ABOUTME: sqlc queries for alert rule ↔ notification channel M:M bindings.

-- name: BindChannelToRule :exec
INSERT INTO alert_rule_channels (rule_id, channel_id, org_id)
VALUES ($1, $2, $3)
ON CONFLICT (rule_id, channel_id) DO NOTHING;

-- name: UnbindChannelFromRule :exec
DELETE FROM alert_rule_channels
WHERE rule_id = $1 AND channel_id = $2 AND org_id = $3;

-- name: ListChannelsForRule :many
SELECT nc.id, nc.org_id, nc.name, nc.type, nc.config, nc.created_at, nc.updated_at
FROM alert_rule_channels arc
JOIN notification_channels nc ON nc.id = arc.channel_id
WHERE arc.rule_id = $1 AND arc.org_id = $2
  AND nc.deleted_at IS NULL
ORDER BY arc.created_at;

-- name: ListActiveChannelsForFanout :many
-- Used by Dispatcher.Fanout: fetches channel config + secrets for delivery row creation.
SELECT nc.id, nc.type, nc.config, nc.signing_secret, nc.signing_secret_secondary
FROM alert_rule_channels arc
JOIN notification_channels nc ON nc.id = arc.channel_id
WHERE arc.rule_id = $1 AND arc.org_id = $2
  AND nc.deleted_at IS NULL;

-- name: ChannelRuleBindingExists :one
SELECT EXISTS(
    SELECT 1 FROM alert_rule_channels
    WHERE rule_id = $1 AND channel_id = $2 AND org_id = $3
) AS exists;
```

**Step 2: Regenerate sqlc**

```bash
sqlc generate
```

**Step 3: Write store wrapper**

Create `internal/store/alert_rule_channel.go`:

```go
// ABOUTME: Store methods for alert rule ↔ notification channel bindings.
// ABOUTME: Hard-delete join table; no soft-delete.
package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store/generated"
)

func (s *Store) BindChannelToRule(ctx context.Context, ruleID, channelID, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.BindChannelToRule(ctx, generated.BindChannelToRuleParams{
			RuleID: ruleID, ChannelID: channelID, OrgID: orgID,
		})
	})
}

func (s *Store) UnbindChannelFromRule(ctx context.Context, ruleID, channelID, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UnbindChannelFromRule(ctx, generated.UnbindChannelFromRuleParams{
			RuleID: ruleID, ChannelID: channelID, OrgID: orgID,
		})
	})
}

func (s *Store) ListChannelsForRule(ctx context.Context, ruleID, orgID uuid.UUID) ([]generated.ListChannelsForRuleRow, error) {
	var rows []generated.ListChannelsForRuleRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var e error
		rows, e = q.ListChannelsForRule(ctx, generated.ListChannelsForRuleParams{
			RuleID: ruleID, OrgID: orgID,
		})
		return e
	})
	return rows, err
}

func (s *Store) ListActiveChannelsForFanout(ctx context.Context, ruleID, orgID uuid.UUID) ([]generated.ListActiveChannelsForFanoutRow, error) {
	var rows []generated.ListActiveChannelsForFanoutRow
	// Fanout runs in the evaluator's worker context — no org tx needed; bypass RLS.
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var e error
		rows, e = q.ListActiveChannelsForFanout(ctx, generated.ListActiveChannelsForFanoutParams{
			RuleID: ruleID, OrgID: orgID,
		})
		return e
	})
	return rows, err
}

func (s *Store) ChannelRuleBindingExists(ctx context.Context, ruleID, channelID, orgID uuid.UUID) (bool, error) {
	var exists bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, e := q.ChannelRuleBindingExists(ctx, generated.ChannelRuleBindingExistsParams{
			RuleID: ruleID, ChannelID: channelID, OrgID: orgID,
		})
		if e != nil {
			return e
		}
		exists = row.Exists
		return nil
	})
	return exists, err
}
```

**Step 4: Build + commit**

```bash
go build ./...
git add internal/store/queries/alert_rule_channels.sql \
        internal/store/generated/ \
        internal/store/alert_rule_channel.go
git commit -m "feat(store): alert_rule_channels queries + store methods"
```

---

## Task 5: Store queries — notification_deliveries

**Files:**
- Create: `internal/store/queries/notification_deliveries.sql`
- Modify: `internal/store/generated/` (sqlc regenerate)
- Create: `internal/store/notification_delivery.go`

**Step 1: Write SQL**

```sql
-- ABOUTME: sqlc queries for the notification_deliveries delivery job queue.
-- ABOUTME: Claim uses FOR UPDATE SKIP LOCKED; debounce uses ON CONFLICT partial index.

-- name: UpsertDelivery :exec
-- Debounce: creates a pending delivery row or appends CVE snapshot to existing one.
-- ON CONFLICT targets the partial unique index (rule_id, channel_id) WHERE status='pending'.
INSERT INTO notification_deliveries (org_id, rule_id, channel_id, payload, send_after)
VALUES ($1, $2, $3, jsonb_build_array($4::jsonb), now() + ($5 * interval '1 second'))
ON CONFLICT (rule_id, channel_id) WHERE status = 'pending'
DO UPDATE SET
    payload    = notification_deliveries.payload || jsonb_build_array($4::jsonb),
    send_after = now() + ($5 * interval '1 second'),
    updated_at = now();

-- name: ClaimPendingDeliveries :many
SELECT id, org_id, rule_id, channel_id, attempt_count, payload
FROM notification_deliveries
WHERE status = 'pending' AND send_after <= now()
ORDER BY send_after
LIMIT $1
FOR UPDATE SKIP LOCKED;

-- name: MarkDeliveriesProcessing :exec
UPDATE notification_deliveries
SET status = 'processing', last_attempted_at = now(), updated_at = now()
WHERE id = ANY($1::uuid[]);

-- name: CompleteDelivery :exec
UPDATE notification_deliveries
SET status = 'succeeded', delivered_at = now(), updated_at = now()
WHERE id = $1;

-- name: RetryDelivery :exec
-- Sets status back to pending with incremented attempt_count and backoff send_after.
UPDATE notification_deliveries
SET status        = 'pending',
    attempt_count = attempt_count + 1,
    send_after    = now() + ($2 * interval '1 second'),
    last_error    = $3,
    updated_at    = now()
WHERE id = $1;

-- name: ExhaustDelivery :exec
-- Max attempts reached — move to permanent failure.
UPDATE notification_deliveries
SET status        = 'failed',
    attempt_count = attempt_count + 1,
    last_error    = $2,
    updated_at    = now()
WHERE id = $1;

-- name: ResetStuckDeliveries :exec
-- Recovery: reset processing rows that haven't been updated in $1 seconds.
UPDATE notification_deliveries
SET status = 'pending', send_after = now(), updated_at = now()
WHERE status = 'processing'
  AND updated_at < now() - ($1 * interval '1 second');

-- name: OrphanedAlertEvents :many
-- Recovery scan: alert_events with no corresponding delivery rows.
SELECT ae.org_id, ae.rule_id, ae.cve_id
FROM alert_events ae
WHERE ae.suppress_delivery = false
  AND ae.last_match_state  = true
  AND ae.first_fired_at < now() - interval '5 minutes'
  AND NOT EXISTS (
      SELECT 1
      FROM notification_deliveries nd
      WHERE nd.rule_id  = ae.rule_id
        AND nd.org_id   = ae.org_id
        AND nd.status   IN ('pending', 'processing', 'succeeded')
        AND nd.created_at >= ae.first_fired_at - interval '1 minute'
  )
LIMIT $1;

-- name: ListDeliveries :many
SELECT id, org_id, rule_id, channel_id, status, attempt_count,
       send_after, last_attempted_at, delivered_at, last_error, created_at, updated_at
FROM notification_deliveries
WHERE org_id = $1
  AND ($2::uuid IS NULL OR rule_id   = $2)
  AND ($3::uuid IS NULL OR channel_id = $3)
  AND ($4::text IS NULL OR status    = $4)
  AND (created_at < $5 OR (created_at = $5 AND id < $6))
ORDER BY created_at DESC, id DESC
LIMIT $7;

-- name: GetDelivery :one
SELECT id, org_id, rule_id, channel_id, status, attempt_count, payload,
       send_after, last_attempted_at, delivered_at, last_error, created_at, updated_at
FROM notification_deliveries
WHERE id = $1 AND org_id = $2
LIMIT 1;

-- name: ReplayDelivery :exec
UPDATE notification_deliveries
SET status        = 'pending',
    attempt_count = 0,
    send_after    = now(),
    last_error    = NULL,
    updated_at    = now()
WHERE id = $1 AND org_id = $2
  AND status IN ('failed', 'cancelled');
```

**Step 2: Regenerate + write wrapper**

```bash
sqlc generate
```

Create `internal/store/notification_delivery.go`:

```go
// ABOUTME: Store methods for the notification_deliveries delivery job queue.
// ABOUTME: Claim uses FOR UPDATE SKIP LOCKED; delivery worker uses withBypassTx.
package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store/generated"
)

// ClaimedDelivery is returned by ClaimPendingDeliveries.
type ClaimedDelivery = generated.ClaimPendingDeliveriesRow

// UpsertDelivery creates or debounce-updates a pending delivery row.
// payload is a JSON object (one CVE snapshot); debounceSeconds is the window duration.
func (s *Store) UpsertDelivery(ctx context.Context, orgID, ruleID, channelID uuid.UUID, payload []byte, debounceSeconds int) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpsertDelivery(ctx, generated.UpsertDeliveryParams{
			OrgID:     orgID,
			RuleID:    ruleID,
			ChannelID: channelID,
			Column4:   payload, // jsonb payload snapshot
			Column5:   int32(debounceSeconds),
		})
	})
}

// ClaimPendingDeliveries claims up to limit pending rows ready to send.
func (s *Store) ClaimPendingDeliveries(ctx context.Context, limit int) ([]ClaimedDelivery, error) {
	var rows []ClaimedDelivery
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var e error
		rows, e = q.ClaimPendingDeliveries(ctx, int32(limit))
		return e
	})
	return rows, err
}

// MarkDeliveriesProcessing bulk-updates claimed rows to status=processing.
func (s *Store) MarkDeliveriesProcessing(ctx context.Context, ids []uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.MarkDeliveriesProcessing(ctx, ids)
	})
}

// CompleteDelivery marks a delivery succeeded.
func (s *Store) CompleteDelivery(ctx context.Context, id uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.CompleteDelivery(ctx, id)
	})
}

// RetryDelivery re-queues a failed delivery with backoff.
func (s *Store) RetryDelivery(ctx context.Context, id uuid.UUID, backoffSeconds int, lastError string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.RetryDelivery(ctx, generated.RetryDeliveryParams{
			ID: id, Column2: int32(backoffSeconds), LastError: &lastError,
		})
	})
}

// ExhaustDelivery permanently fails a delivery (max attempts reached).
func (s *Store) ExhaustDelivery(ctx context.Context, id uuid.UUID, lastError string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.ExhaustDelivery(ctx, generated.ExhaustDeliveryParams{ID: id, LastError: &lastError})
	})
}

// ResetStuckDeliveries resets processing rows not updated within stuckThreshold.
func (s *Store) ResetStuckDeliveries(ctx context.Context, stuckThreshold time.Duration) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.ResetStuckDeliveries(ctx, int32(stuckThreshold.Seconds()))
	})
}

// OrphanedAlertEvents returns alert events with no corresponding delivery rows.
func (s *Store) OrphanedAlertEvents(ctx context.Context, limit int) ([]generated.OrphanedAlertEventsRow, error) {
	var rows []generated.OrphanedAlertEventsRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var e error
		rows, e = q.OrphanedAlertEvents(ctx, int32(limit))
		return e
	})
	return rows, err
}

// ListDeliveries returns paginated deliveries for an org with optional filters.
func (s *Store) ListDeliveries(ctx context.Context, orgID uuid.UUID, ruleID, channelID uuid.NullUUID, status *string, cursorTime time.Time, cursorID uuid.UUID, limit int) ([]generated.ListDeliveriesRow, error) {
	var rows []generated.ListDeliveriesRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var statusArg *string
		if status != nil {
			statusArg = status
		}
		var e error
		rows, e = q.ListDeliveries(ctx, generated.ListDeliveriesParams{
			OrgID: orgID, Column2: ruleID, Column3: channelID,
			Column4: statusArg, Column5: cursorTime, Column6: cursorID, Limit: int32(limit),
		})
		return e
	})
	return rows, err
}

// GetDelivery fetches a single delivery by id + org.
func (s *Store) GetDelivery(ctx context.Context, id, orgID uuid.UUID) (generated.GetDeliveryRow, error) {
	var row generated.GetDeliveryRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var e error
		row, e = q.GetDelivery(ctx, generated.GetDeliveryParams{ID: id, OrgID: orgID})
		return e
	})
	return row, err
}

// ReplayDelivery resets a failed/cancelled delivery for re-delivery.
func (s *Store) ReplayDelivery(ctx context.Context, id, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.ReplayDelivery(ctx, generated.ReplayDeliveryParams{ID: id, OrgID: orgID})
	})
}
```

**Step 3: Build + commit**

```bash
go build ./...
git add internal/store/queries/notification_deliveries.sql \
        internal/store/generated/ \
        internal/store/notification_delivery.go
git commit -m "feat(store): notification_deliveries queries + store methods"
```

> **Note:** sqlc may generate parameter struct field names like `Column4`, `Column5` for
> untyped positional params. Check `internal/store/generated/notification_deliveries.sql.go`
> for exact names and update the wrapper accordingly. If sqlc can't handle the partial
> index conflict target in `UpsertDelivery`, split it into a SELECT + conditional INSERT/UPDATE
> in the store method using raw SQL via `s.db.ExecContext`.

---

## Task 6: Add safeurl dependency + webhook.Send() (TDD)

**Files:**
- Create: `internal/notify/webhook.go`
- Create: `internal/notify/webhook_test.go`

**Step 1: Add safeurl**

```bash
go get github.com/doyensec/safeurl
```

Verify it appears in `go.mod`.

**Step 2: Write the failing test**

```go
// ABOUTME: Tests for outbound webhook delivery: HMAC signing, body discard, redirect rejection.
package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/notify"
)

func buildTestClient() *http.Client {
	// In tests use a plain http.Client (safeurl blocks private IPs used by httptest).
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestSend_HMACHeadersCorrect(t *testing.T) {
	var gotTS, gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTS = r.Header.Get("X-CVErt-Timestamp")
		gotSig = r.Header.Get("X-CVErtOps-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := []byte(`[{"cve_id":"CVE-2024-1234","severity":"CRITICAL"}]`)
	secret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex chars = 32 bytes

	err := notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL:           srv.URL,
		SigningSecret: secret,
	}, payload)
	require.NoError(t, err)

	require.NotEmpty(t, gotTS)
	tsInt, err := strconv.ParseInt(gotTS, 10, 64)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), tsInt, 5)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(gotTS + "." + string(payload)))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expected, gotSig)
}

func TestSend_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL: srv.URL, SigningSecret: "x",
	}, []byte(`[]`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestSend_DeniedHeaderStripped(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("Host") // always set by net/http from URL; custom Host override rejected
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_ = notify.Send(context.Background(), buildTestClient(), notify.WebhookConfig{
		URL:           srv.URL,
		SigningSecret: "x",
		CustomHeaders: map[string]string{"Host": "evil.internal", "X-Custom": "ok"},
	}, []byte(`[]`))
	// The Host header must match the server URL, not the injected value.
	assert.NotEqual(t, "evil.internal", gotHost)
}

func TestSend_RedirectRejected(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer inner.Close()

	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, inner.URL, http.StatusFound) //nolint:staticcheck
	}))
	defer outer.Close()

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	err := notify.Send(context.Background(), client, notify.WebhookConfig{
		URL: outer.URL, SigningSecret: "x",
	}, []byte(`[]`))
	// Non-2xx (302) → error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
}
```

**Step 3: Run — verify fails**

```bash
go test ./internal/notify/... -run TestSend -v
```

Expected: compile error (package doesn't exist yet).

**Step 4: Implement webhook.go**

```go
// ABOUTME: Outbound webhook delivery: HMAC signing, safeurl client, response body discard.
// ABOUTME: Send is a pure function; the http.Client is injected (constructed once at worker startup).
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookConfig holds the delivery-time view of a notification_channels row for a webhook channel.
type WebhookConfig struct {
	URL           string
	SigningSecret string
	CustomHeaders map[string]string // applied after denylist filtering
}

// deniedHeaders are custom header keys that callers must not override.
var deniedHeaders = map[string]bool{
	"host": true, "content-type": true, "content-length": true,
	"transfer-encoding": true, "connection": true,
	"x-cvert-timestamp": true, "x-cvertos-signature": true,
}

// Send posts payload to the webhook URL, signs with HMAC-SHA256, and discards the response body.
// The caller constructs client once at startup (safeurl-wrapped, redirect-disabled, 10s timeout).
func Send(ctx context.Context, client *http.Client, cfg WebhookConfig, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply custom headers, skipping denied keys.
	for k, v := range cfg.CustomHeaders {
		if !deniedHeaders[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}

	// HMAC-SHA256 over "timestamp.body" with primary signing secret.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(cfg.SigningSecret))
	mac.Write([]byte(ts + "." + string(payload)))
	req.Header.Set("X-CVErt-Timestamp", ts)
	req.Header.Set("X-CVErtOps-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST %s: %w", cfg.URL, err)
	}
	defer resp.Body.Close()
	// Must read and discard response body for HTTP/1.1 connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s: HTTP %d", cfg.URL, resp.StatusCode)
	}
	return nil
}

// BuildSafeClient constructs the production safeurl-wrapped HTTP client.
// Called once at worker startup; passed to Send for each delivery.
func BuildSafeClient() (*http.Client, error) {
	// Import github.com/doyensec/safeurl for the actual production client.
	// safeurl blocks RFC 1918 ranges and DNS rebinding by default.
	cfg := safeurl.GetConfigBuilder().
		SetAllowedPorts([]int{80, 443}).
		Build()
	client, err := safeurl.Client(cfg)
	if err != nil {
		return nil, fmt.Errorf("build safe HTTP client: %w", err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// Note: safeurl wraps Transport; set MaxConnsPerHost on the underlying transport.
	if t, ok := client.Transport.(*http.Transport); ok {
		t.MaxConnsPerHost = 50
	}
	return client, nil
}
```

> **Note:** The safeurl API may differ from the above snippet. Check the package docs
> at `github.com/doyensec/safeurl` after `go get`. Adjust `BuildSafeClient` to match
> the actual API. The import is `"github.com/doyensec/safeurl"`.

**Step 5: Run — verify passes**

```bash
go test ./internal/notify/... -run TestSend -v
```

Expected: all 4 tests pass.

**Step 6: Lint + commit**

```bash
golangci-lint run ./internal/notify/...
git add internal/notify/webhook.go internal/notify/webhook_test.go
git commit -m "feat(notify): webhook.Send with HMAC signing, denylist, redirect rejection"
```

---

## Task 7: Dispatcher.Fanout() (TDD)

**Files:**
- Create: `internal/notify/dispatcher.go`
- Create: `internal/notify/dispatcher_test.go`

**Step 1: Write the failing test**

```go
// ABOUTME: Tests for Dispatcher.Fanout: debounce upsert, no-op when no channels bound.
package notify_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/notify"
	// Use your existing test DB helper — check internal/store/*_test.go for the pattern.
)

func TestFanout_NoChannels_NoOp(t *testing.T) {
	// A rule with no bound channels: Fanout must return nil and create 0 delivery rows.
	ctx := context.Background()
	db := testDB(t) // existing test helper from internal/store
	st := store.New(db)
	org := createTestOrg(t, st)
	rule := createTestRule(t, st, org.ID)

	d := notify.NewDispatcher(st, 120)
	err := d.Fanout(ctx, org.ID, rule.ID, "CVE-2024-1234")
	require.NoError(t, err)

	deliveries, err := st.ListDeliveries(ctx, org.ID, uuid.NullUUID{}, uuid.NullUUID{}, nil,
		time.Now().Add(time.Hour), uuid.Nil, 10)
	require.NoError(t, err)
	assert.Empty(t, deliveries)
}

func TestFanout_SingleChannel_CreatesDeliveryRow(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	st := store.New(db)
	org := createTestOrg(t, st)
	rule := createTestRule(t, st, org.ID)
	ch := createTestChannel(t, st, org.ID)
	require.NoError(t, st.BindChannelToRule(ctx, rule.ID, ch.ID, org.ID))

	d := notify.NewDispatcher(st, 120)
	err := d.Fanout(ctx, org.ID, rule.ID, "CVE-2024-1234")
	require.NoError(t, err)

	deliveries, err := st.ListDeliveries(ctx, org.ID, uuid.NullUUID{}, uuid.NullUUID{}, nil,
		time.Now().Add(time.Hour), uuid.Nil, 10)
	require.NoError(t, err)
	require.Len(t, deliveries, 1)
	assert.Equal(t, "pending", deliveries[0].Status)

	var payload []map[string]any
	require.NoError(t, json.Unmarshal(deliveries[0].Payload, &payload)) // check if field exists
	// payload is generated from actual CVE — may be empty if CVE doesn't exist in test DB.
	// Just verify the row was created with the right channel.
	assert.Equal(t, ch.ID, deliveries[0].ChannelID)
}

func TestFanout_Debounce_AppendsToExistingRow(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	st := store.New(db)
	org := createTestOrg(t, st)
	rule := createTestRule(t, st, org.ID)
	ch := createTestChannel(t, st, org.ID)
	require.NoError(t, st.BindChannelToRule(ctx, rule.ID, ch.ID, org.ID))

	d := notify.NewDispatcher(st, 120)

	// First fanout: creates row.
	require.NoError(t, d.Fanout(ctx, org.ID, rule.ID, "CVE-2024-0001"))
	// Second fanout within debounce window: appends to same row.
	require.NoError(t, d.Fanout(ctx, org.ID, rule.ID, "CVE-2024-0002"))

	deliveries, err := st.ListDeliveries(ctx, org.ID, uuid.NullUUID{}, uuid.NullUUID{}, nil,
		time.Now().Add(time.Hour), uuid.Nil, 10)
	require.NoError(t, err)
	// Must be ONE row, not two.
	require.Len(t, deliveries, 1)
}
```

**Step 2: Run — verify fails**

```bash
go test ./internal/notify/... -run TestFanout -v
```

Expected: compile error (`notify.NewDispatcher` not defined).

**Step 3: Implement dispatcher.go**

```go
// ABOUTME: Dispatcher creates notification_deliveries rows after alert_events are committed.
// ABOUTME: Fanout queries bound channels and does a debounce upsert per channel.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

// cveSnapshot is the payload stored in notification_deliveries for one matched CVE.
type cveSnapshot struct {
	CVEИД         string   `json:"cve_id"`
	Severity      *string  `json:"severity,omitempty"`
	CVSSV3Score   *float64 `json:"cvss_v3_score,omitempty"`
	CVSSV4Score   *float64 `json:"cvss_v4_score,omitempty"`
	EPSSScore     *float64 `json:"epss_score,omitempty"`
	Description   string   `json:"description_primary,omitempty"`
	ExploitAvail  bool     `json:"exploit_available"`
	InCISAKEV     bool     `json:"in_cisa_kev"`
}

// Dispatcher creates notification delivery rows after new alert events are committed.
type Dispatcher struct {
	store           *store.Store
	debounceSeconds int
	log             *slog.Logger
}

// NewDispatcher creates a Dispatcher. debounceSeconds is the debounce window duration.
func NewDispatcher(st *store.Store, debounceSeconds int) *Dispatcher {
	return &Dispatcher{store: st, debounceSeconds: debounceSeconds, log: slog.Default()}
}

// Fanout creates or updates a pending notification_deliveries row for each channel
// bound to the rule. Called by the evaluator after a new alert_event auto-commits.
// Returns nil if no channels are bound — not an error.
func (d *Dispatcher) Fanout(ctx context.Context, orgID, ruleID uuid.UUID, cveID string) error {
	channels, err := d.store.ListActiveChannelsForFanout(ctx, ruleID, orgID)
	if err != nil {
		return fmt.Errorf("fanout list channels: %w", err)
	}
	if len(channels) == 0 {
		return nil
	}

	snapshot, err := d.buildSnapshot(ctx, cveID)
	if err != nil {
		// Log but don't fail fanout — delivery row created with partial snapshot.
		d.log.Warn("fanout: CVE snapshot incomplete", "cve_id", cveID, "err", err)
		snapshot = &cveSnapshot{CVEИД: cveID}
	}

	payload, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("fanout marshal snapshot: %w", err)
	}

	for _, ch := range channels {
		if err := d.store.UpsertDelivery(ctx, orgID, ruleID, ch.ID, payload, d.debounceSeconds); err != nil {
			// Log per-channel errors; don't abort remaining channels.
			d.log.Error("fanout upsert delivery", "channel_id", ch.ID, "err", err)
		}
	}
	return nil
}

// buildSnapshot queries the CVE and affected packages to build the delivery payload.
func (d *Dispatcher) buildSnapshot(ctx context.Context, cveID string) (*cveSnapshot, error) {
	cve, err := d.store.GetCVESnapshot(ctx, cveID) // implement in store/cve.go if not present
	if err != nil {
		return nil, err
	}
	desc := cve.DescriptionPrimary
	if len(desc) > 280 {
		desc = desc[:280]
	}
	return &cveSnapshot{
		CVEИД:        cveID,
		Severity:     cve.Severity,
		CVSSV3Score:  cve.CvssV3Score,
		ExploitAvail: cve.ExploitAvailable,
		InCISAKEV:    cve.InCisaKev,
		Description:  desc,
	}, nil
}
```

> **Note:** `store.GetCVESnapshot` may not exist yet. Add a minimal SQL query to
> `internal/store/queries/cves.sql`:
> ```sql
> -- name: GetCVESnapshot :one
> SELECT cve_id, severity, cvss_v3_score, cvss_v4_score, epss_score,
>        description_primary, exploit_available, in_cisa_kev
> FROM cves WHERE cve_id = $1 LIMIT 1;
> ```
> Run `sqlc generate`, add a `GetCVESnapshot` wrapper to `internal/store/cve.go`.

**Step 4: Run — verify passes**

```bash
go test ./internal/notify/... -run TestFanout -v
```

**Step 5: Lint + commit**

```bash
golangci-lint run ./internal/notify/...
git add internal/notify/dispatcher.go internal/notify/dispatcher_test.go \
        internal/store/queries/cves.sql internal/store/generated/ internal/store/cve.go
git commit -m "feat(notify): Dispatcher.Fanout with debounce upsert"
```

---

## Task 8: Evaluator integration — inject Dispatcher, call Fanout (TDD)

**Files:**
- Modify: `internal/alert/evaluator.go`
- Modify: `internal/alert/evaluator_test.go`

**Step 1: Write the failing test**

In `internal/alert/evaluator_test.go`, add:

```go
type mockDispatcher struct {
	calls []struct{ orgID, ruleID uuid.UUID; cveID string }
	mu    sync.Mutex
}

func (m *mockDispatcher) Fanout(_ context.Context, orgID, ruleID uuid.UUID, cveID string) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.calls = append(m.calls, struct{ orgID, ruleID uuid.UUID; cveID string }{orgID, ruleID, cveID})
	return nil
}

func TestEvaluateRealtime_FanoutCalledForNewEvent(t *testing.T) {
	// Setup: org, rule with one matching CVE, non-suppressed.
	// ... (use existing test helpers in evaluator_test.go)
	d := &mockDispatcher{}
	e := alert.New(db, rules, cache, slog.Default())
	e.SetDispatcher(d)

	err := e.EvaluateRealtime(ctx, cveID, orgID)
	require.NoError(t, err)

	d.mu.Lock(); defer d.mu.Unlock()
	require.Len(t, d.calls, 1)
	assert.Equal(t, cveID, d.calls[0].cveID)
}

func TestEvaluateRealtime_FanoutNotCalledForSuppressedEvent(t *testing.T) {
	// Rules in 'activating' state use suppressDelivery=true.
	d := &mockDispatcher{}
	e := alert.New(db, rules, cache, slog.Default())
	e.SetDispatcher(d)

	// Create rule in 'activating' state and run EvaluateActivation.
	err := e.EvaluateActivation(ctx, ruleID, orgID)
	require.NoError(t, err)
	assert.Empty(t, d.calls) // suppressed — no Fanout call.
}
```

**Step 2: Run — verify fails**

```bash
go test ./internal/alert/... -run TestEvaluateRealtime_Fanout -v
```

Expected: compile error (`e.SetDispatcher` not defined).

**Step 3: Modify evaluator.go**

3a. Add the `Dispatcher` interface and field to `Evaluator`:

```go
// Dispatcher dispatches notification delivery for newly created alert events.
// Implemented by internal/notify.Dispatcher; nil disables delivery (tests, startup).
type Dispatcher interface {
	Fanout(ctx context.Context, orgID, ruleID uuid.UUID, cveID string) error
}

type Evaluator struct {
	db         *sql.DB
	rules      store.AlertRuleStore
	cache      *RuleCache
	log        *slog.Logger
	dispatcher Dispatcher // nil = delivery disabled
}

// SetDispatcher injects the notification dispatcher.
func (e *Evaluator) SetDispatcher(d Dispatcher) { e.dispatcher = d }
```

3b. In `evaluateRule()`, capture the returned event ID and call Fanout:

```go
// Replace the existing InsertAlertEvent call:
for _, m := range matched {
	matchedIDs[m.CVEID] = true
	eventID, err := e.rules.InsertAlertEvent(ctx, orgID, compiled.RuleID, m.CVEID, m.MaterialHash, suppressDelivery)
	if err != nil {
		return len(matched), false, len(candidateIDs), fmt.Errorf("insert alert event %s: %w", m.CVEID, err)
	}
	if e.dispatcher != nil && !suppressDelivery && eventID != uuid.Nil {
		if fErr := e.dispatcher.Fanout(ctx, orgID, compiled.RuleID, m.CVEID); fErr != nil {
			e.log.Error("fanout notification", "rule_id", compiled.RuleID, "cve_id", m.CVEID, "err", fErr)
			// Do not return: alert_event is committed; log and continue.
		}
	}
}
```

**Step 4: Run — verify passes**

```bash
go test ./internal/alert/... -v
```

Expected: all evaluator tests pass including new Fanout tests.

**Step 5: Lint + commit**

```bash
golangci-lint run ./internal/alert/...
git add internal/alert/evaluator.go internal/alert/evaluator_test.go
git commit -m "feat(alert): inject Dispatcher, call Fanout after alert_event commit"
```

---

## Task 9: Delivery worker — claim loop + per-org semaphore (TDD)

**Files:**
- Create: `internal/notify/worker.go`
- Create: `internal/notify/worker_test.go`

**Step 1: Write the failing tests**

```go
// ABOUTME: Tests for the delivery worker: claim, retry, exhaustion, per-org semaphore.
package notify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/notify"
)

func TestWorker_ClaimsAndDeliversPendingRow(t *testing.T) {
	// Setup: insert a pending delivery row for a webhook channel.
	// Start a test HTTP server to receive the webhook.
	// Run one claim tick.
	// Assert: delivery row status = 'succeeded'; webhook server received the call.
	var received bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db := testDB(t)
	st := store.New(db)
	org := createTestOrg(t, st)
	rule := createTestRule(t, st, org.ID)
	ch := createTestChannelWithURL(t, st, org.ID, srv.URL)
	require.NoError(t, st.UpsertDelivery(context.Background(), org.ID, rule.ID, ch.ID,
		[]byte(`{"cve_id":"CVE-2024-1"}`), 0)) // debounce=0 → send immediately

	w := notify.NewWorker(st, &http.Client{Timeout: 5 * time.Second}, notify.WorkerConfig{
		ClaimBatchSize: 10, MaxAttempts: 4, BackoffBaseSeconds: 30, MaxConcurrentPerOrg: 5,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	w.RunOnce(ctx) // run one claim tick (test helper — not used in production)

	assert.True(t, received, "webhook server should have received the delivery")
	// Check DB: delivery status = succeeded
	deliveries, _ := st.ListDeliveries(ctx, org.ID, uuid.NullUUID{}, uuid.NullUUID{}, nil,
		time.Now().Add(time.Hour), uuid.Nil, 10)
	require.Len(t, deliveries, 1)
	assert.Equal(t, "succeeded", deliveries[0].Status)
}

func TestWorker_RetryOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	db := testDB(t)
	st := store.New(db)
	org, rule, ch := setupOrgRuleChannel(t, st, srv.URL)
	require.NoError(t, st.UpsertDelivery(context.Background(), org.ID, rule.ID, ch.ID,
		[]byte(`{"cve_id":"CVE-2024-2"}`), 0))

	w := notify.NewWorker(st, &http.Client{Timeout: 2 * time.Second}, notify.WorkerConfig{
		ClaimBatchSize: 10, MaxAttempts: 4, BackoffBaseSeconds: 1, MaxConcurrentPerOrg: 5,
	})
	w.RunOnce(context.Background())

	deliveries, _ := st.ListDeliveries(context.Background(), org.ID, uuid.NullUUID{}, uuid.NullUUID{}, nil,
		time.Now().Add(time.Hour), uuid.Nil, 10)
	require.Len(t, deliveries, 1)
	assert.Equal(t, "pending", deliveries[0].Status, "should be re-queued for retry")
	assert.Equal(t, int32(1), deliveries[0].AttemptCount)
}

func TestWorker_ExhaustsAfterMaxAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	db := testDB(t)
	st := store.New(db)
	org, rule, ch := setupOrgRuleChannel(t, st, srv.URL)

	// Pre-seed with attempt_count = maxAttempts-1 so next failure exhausts it.
	// Insert via raw SQL or store helper; adjust as needed.
	require.NoError(t, st.UpsertDelivery(context.Background(), org.ID, rule.ID, ch.ID,
		[]byte(`{"cve_id":"CVE-2024-3"}`), 0))
	// Manually set attempt_count = 3 (maxAttempts-1=3 means next fail = exhausted at 4).
	_, err := st.DB().ExecContext(context.Background(),
		`UPDATE notification_deliveries SET attempt_count = 3 WHERE channel_id = $1`, ch.ID)
	require.NoError(t, err)

	w := notify.NewWorker(st, &http.Client{Timeout: 2 * time.Second}, notify.WorkerConfig{
		ClaimBatchSize: 10, MaxAttempts: 4, BackoffBaseSeconds: 1, MaxConcurrentPerOrg: 5,
	})
	w.RunOnce(context.Background())

	deliveries, _ := st.ListDeliveries(context.Background(), org.ID, uuid.NullUUID{}, uuid.NullUUID{}, nil,
		time.Now().Add(time.Hour), uuid.Nil, 10)
	require.Len(t, deliveries, 1)
	assert.Equal(t, "failed", deliveries[0].Status)
}
```

**Step 2: Run — verify fails**

```bash
go test ./internal/notify/... -run TestWorker -v
```

Expected: compile error.

**Step 3: Implement worker.go**

```go
// ABOUTME: Delivery worker: polls notification_deliveries, claims rows, executes webhooks.
// ABOUTME: Per-org semaphore caps concurrent deliveries. sync.WaitGroup for graceful shutdown.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

// WorkerConfig holds delivery worker tuning parameters (sourced from config.Config).
type WorkerConfig struct {
	ClaimBatchSize      int
	MaxAttempts         int
	BackoffBaseSeconds  int
	MaxConcurrentPerOrg int
	StuckThreshold      time.Duration // default 2 minutes
}

// Worker polls notification_deliveries and executes outbound HTTP webhook deliveries.
type Worker struct {
	store   *store.Store
	client  *http.Client
	cfg     WorkerConfig
	log     *slog.Logger
	sems    map[uuid.UUID]chan struct{} // per-org semaphores, lazy-init
	semsMu  sync.Mutex
	wg      sync.WaitGroup
	// dispatcher is used by the recovery ticker to re-fanout orphaned events.
	dispatcher *Dispatcher
}

// NewWorker creates a Worker. client should be the production safeurl client.
func NewWorker(st *store.Store, client *http.Client, cfg WorkerConfig) *Worker {
	if cfg.StuckThreshold == 0 {
		cfg.StuckThreshold = 2 * time.Minute
	}
	return &Worker{store: st, client: client, cfg: cfg, log: slog.Default(), sems: make(map[uuid.UUID]chan struct{})}
}

// SetDispatcher injects the Dispatcher used by the recovery ticker.
func (w *Worker) SetDispatcher(d *Dispatcher) { w.dispatcher = d }

// Start runs the worker until ctx is cancelled.
func (w *Worker) Start(ctx context.Context) {
	claimTicker    := time.NewTicker(5 * time.Second)
	stuckTicker    := time.NewTicker(60 * time.Second)
	recoveryTicker := time.NewTicker(5 * time.Minute)
	defer claimTicker.Stop()
	defer stuckTicker.Stop()
	defer recoveryTicker.Stop()

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
		}
	}
}

// RunOnce executes one claim tick — used in tests only.
func (w *Worker) RunOnce(ctx context.Context) {
	w.runClaim(ctx)
	w.wg.Wait()
}

func (w *Worker) runClaim(ctx context.Context) {
	rows, err := w.store.ClaimPendingDeliveries(ctx, w.cfg.ClaimBatchSize)
	if err != nil {
		w.log.Error("claim pending deliveries", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	if err := w.store.MarkDeliveriesProcessing(ctx, ids); err != nil {
		w.log.Error("mark deliveries processing", "err", err)
		return
	}

	for _, row := range rows {
		row := row
		sem := w.semaphore(row.OrgID)
		sem <- struct{}{} // acquire slot (blocks if org at cap)
		w.wg.Add(1)
		go func() {
			defer func() { <-sem }()
			defer w.wg.Done()
			w.deliver(ctx, row)
		}()
	}
}

func (w *Worker) deliver(ctx context.Context, row store.ClaimedDelivery) {
	ch, err := w.store.GetNotificationChannelForDelivery(ctx, row.ChannelID)
	if err != nil {
		w.log.Error("get channel for delivery", "channel_id", row.ChannelID, "err", err)
		w.exhaust(ctx, row.ID, fmt.Sprintf("channel lookup failed: %v", err))
		return
	}

	var config struct {
		URL           string            `json:"url"`
		CustomHeaders map[string]string `json:"custom_headers"`
	}
	_ = json.Unmarshal(ch.Config, &config) //nolint:errcheck

	sendErr := Send(ctx, w.client, WebhookConfig{
		URL:           config.URL,
		SigningSecret: ch.SigningSecret,
		CustomHeaders: config.CustomHeaders,
	}, row.Payload)

	if sendErr == nil {
		if err := w.store.CompleteDelivery(ctx, row.ID); err != nil {
			w.log.Error("complete delivery", "id", row.ID, "err", err)
		}
		return
	}

	w.log.Warn("delivery failed", "id", row.ID, "err", sendErr, "attempt", row.AttemptCount+1)
	nextAttempt := int(row.AttemptCount) + 1
	if nextAttempt >= w.cfg.MaxAttempts {
		w.exhaust(ctx, row.ID, sendErr.Error())
		return
	}

	backoff := w.backoffSeconds(nextAttempt)
	if err := w.store.RetryDelivery(ctx, row.ID, backoff, sendErr.Error()); err != nil {
		w.log.Error("retry delivery", "id", row.ID, "err", err)
	}
}

func (w *Worker) exhaust(ctx context.Context, id uuid.UUID, lastError string) {
	if err := w.store.ExhaustDelivery(ctx, id, lastError); err != nil {
		w.log.Error("exhaust delivery", "id", id, "err", err)
	}
}

func (w *Worker) backoffSeconds(attempt int) int {
	base := float64(w.cfg.BackoffBaseSeconds)
	delay := base * math.Pow(2, float64(attempt-1))
	jitter := 0.5 + rand.Float64() // [0.5, 1.5)
	return int(delay * jitter)
}

func (w *Worker) semaphore(orgID uuid.UUID) chan struct{} {
	w.semsMu.Lock()
	defer w.semsMu.Unlock()
	if _, ok := w.sems[orgID]; !ok {
		w.sems[orgID] = make(chan struct{}, w.cfg.MaxConcurrentPerOrg)
	}
	return w.sems[orgID]
}

func (w *Worker) runStuckReset(ctx context.Context) {
	if err := w.store.ResetStuckDeliveries(ctx, w.cfg.StuckThreshold); err != nil {
		w.log.Error("reset stuck deliveries", "err", err)
	}
}

func (w *Worker) runRecovery(ctx context.Context) {
	if w.dispatcher == nil {
		return
	}
	rows, err := w.store.OrphanedAlertEvents(ctx, 100)
	if err != nil {
		w.log.Error("orphaned event scan", "err", err)
		return
	}
	for _, row := range rows {
		if err := w.dispatcher.Fanout(ctx, row.OrgID, row.RuleID, row.CveID); err != nil {
			w.log.Error("recovery fanout", "rule_id", row.RuleID, "cve_id", row.CveID, "err", err)
		}
	}
}

// json import needed in deliver()
import "encoding/json"
```

**Step 4: Run — verify passes**

```bash
go test ./internal/notify/... -run TestWorker -v
```

**Step 5: Lint + commit**

```bash
golangci-lint run ./internal/notify/...
git add internal/notify/worker.go internal/notify/worker_test.go
git commit -m "feat(notify): delivery worker — claim loop, retry/backoff, per-org semaphore, orphaned recovery"
```

---

## Task 10: API — channel CRUD handlers (TDD)

**Files:**
- Create: `internal/api/channels.go`
- Create: `internal/api/channels_test.go`
- Modify: `internal/api/server.go` (register routes)

**Step 1: Write failing tests for key behaviors**

```go
// ABOUTME: Tests for notification channel HTTP handlers: CRUD, secret rotation.
package api_test

func TestCreateChannel_SigningSecretReturnedOnce(t *testing.T) {
	// POST /orgs/{org_id}/channels → 201; response includes signing_secret.
	// GET same channel → signing_secret absent.
}

func TestCreateChannel_URLRequired(t *testing.T) {
	// POST with config missing "url" key → 422 validation error.
}

func TestGetChannel_NoSecretsInResponse(t *testing.T) {
	// GET /orgs/{org_id}/channels/{id} → signing_secret and signing_secret_secondary absent.
}

func TestPatchChannel_PartialUpdate(t *testing.T) {
	// PATCH with only {"name": "new-name"} → name updated, config unchanged.
}

func TestDeleteChannel_409IfActiveRuleBound(t *testing.T) {
	// Bind channel to active rule → DELETE → 409.
	// Soft-delete: channel still in DB with deleted_at set.
}

func TestDeleteChannel_SoftDeleteSucceeds(t *testing.T) {
	// No active rules bound → DELETE → 204; channel has deleted_at set.
}

func TestRotateSecret_NewPrimaryReturned(t *testing.T) {
	// POST rotate-secret → new signing_secret in response; old one in secondary.
}
```

**Step 2: Run — verify fails** (package not found)

**Step 3: Implement `internal/api/channels.go`**

Follow the exact patterns from `internal/api/alert_rules.go`:
- Use `huma.Register(api, huma.Operation{...}, handler)`
- Org ID from URL path, validated against JWT claims in `RequireOrgRole`
- PATCH request struct: all fields pointer types (`*string`, `*WebhookConfig`)
- Two output structs: `ChannelCreateOutput` (includes `SigningSecret string`) and `ChannelOutput` (omits it)
- Validate webhook URL via safeurl at create and update time: attempt `http.NewRequest` with the URL; if safeurl rejects it, return 422
- `DELETE` pre-flight: call `s.store.ChannelHasActiveBoundRules(ctx, channelID, orgID)`; if true, return 409

**Step 4: Register routes in server.go**

In the `r.Route("/orgs", ...)` block, add alongside existing alert-rules routes:
```go
registerChannelRoutes(api, srv)
```

**Step 5: Run — verify passes**

```bash
go test ./internal/api/... -run TestCreateChannel -run TestDeleteChannel -run TestRotateSecret -v
```

**Step 6: Lint + commit**

```bash
golangci-lint run ./internal/api/...
git add internal/api/channels.go internal/api/channels_test.go internal/api/server.go
git commit -m "feat(api): notification channel CRUD handlers"
```

---

## Task 11: API — rule-channel binding handlers (TDD)

**Files:**
- Modify: `internal/api/alert_rules.go`
- Modify: `internal/api/alert_rules_test.go`

**Step 1: Write failing tests**

```go
func TestBindChannelToRule_Idempotent(t *testing.T) {
	// PUT /orgs/{org_id}/alert-rules/{rule_id}/channels/{channel_id} twice → both 204.
}

func TestBindChannelToRule_CrossOrgChannelRejected(t *testing.T) {
	// Channel belongs to org2, rule to org1 → 404.
}

func TestUnbindChannelFromRule_204(t *testing.T) {
	// DELETE binding → 204.
}

func TestUnbindChannelFromRule_404(t *testing.T) {
	// DELETE non-existent binding → 404.
}

func TestListChannelsForRule(t *testing.T) {
	// Bind 2 channels → GET list returns both; soft-deleted channel excluded.
}
```

**Step 2: Implement in alert_rules.go**

Add three handlers at the bottom of `internal/api/alert_rules.go`:
- `listRuleChannels` — calls `s.store.ListChannelsForRule`
- `bindRuleChannel` — validates channel is in same org (`s.store.GetNotificationChannel`), calls `s.store.BindChannelToRule`, returns 204
- `unbindRuleChannel` — calls `s.store.UnbindChannelFromRule`; if 0 rows affected, return 404

Register in `registerAlertRuleRoutes` (already called from server.go):
```go
huma.Register(api, huma.Operation{Method: "GET",    Path: "/orgs/{org_id}/alert-rules/{rule_id}/channels"}, srv.listRuleChannels)
huma.Register(api, huma.Operation{Method: "PUT",    Path: "/orgs/{org_id}/alert-rules/{rule_id}/channels/{channel_id}"}, srv.bindRuleChannel)
huma.Register(api, huma.Operation{Method: "DELETE", Path: "/orgs/{org_id}/alert-rules/{rule_id}/channels/{channel_id}"}, srv.unbindRuleChannel)
```

**Step 3: Run + lint + commit**

```bash
go test ./internal/api/... -run TestBindChannel -run TestUnbindChannel -run TestListChannels -v
golangci-lint run ./internal/api/...
git add internal/api/alert_rules.go internal/api/alert_rules_test.go
git commit -m "feat(api): rule-channel binding endpoints (PUT/DELETE/GET)"
```

---

## Task 12: API — delivery list, detail, replay (TDD)

**Files:**
- Create: `internal/api/deliveries.go`
- Create: `internal/api/deliveries_test.go`
- Modify: `internal/api/server.go` (register routes)

**Step 1: Write failing tests**

```go
func TestListDeliveries_FilterByStatus(t *testing.T) {
	// Insert 2 deliveries: one succeeded, one failed.
	// GET ?status=succeeded → returns only the succeeded one.
}

func TestGetDelivery_IncludesLastError(t *testing.T) {
	// Delivery with last_error set → error visible in GET response.
}

func TestReplayDelivery_ResetsAttemptCount(t *testing.T) {
	// Failed delivery → POST replay → attempt_count=0, status=pending, last_error null.
}

func TestReplayDelivery_RateLimited(t *testing.T) {
	// Make 10 replay calls → 11th returns 429.
}

func TestReplayDelivery_NonAdminRejected(t *testing.T) {
	// Viewer role → POST replay → 403.
}
```

**Step 2: Implement `internal/api/deliveries.go`**

- `listDeliveries`: parse `rule_id`, `channel_id`, `status` query params; parse keyset cursor from `after_created_at` + `after_id`; call `s.store.ListDeliveries`
- `getDelivery`: call `s.store.GetDelivery`; 404 if not found
- `replayDelivery`:
  - Require `RequireOrgRole(RoleAdmin)` (admin+)
  - Rate limit: in-memory `sync.Map` keyed by orgID to `*replayBucket{count int, reset time.Time}`. If `bucket.count >= 10` and `time.Now().Before(bucket.reset)` → return 429. Otherwise increment.
  - Call `s.store.ReplayDelivery`; return 204

**Step 3: Run + lint + commit**

```bash
go test ./internal/api/... -run TestListDeliveries -run TestGetDelivery -run TestReplayDelivery -v
golangci-lint run ./internal/api/...
git add internal/api/deliveries.go internal/api/deliveries_test.go internal/api/server.go
git commit -m "feat(api): delivery list/detail/replay endpoints"
```

---

## Task 13: Wire up — inject Dispatcher into Evaluator, start delivery Worker

**Files:**
- Modify: `cmd/cvert-ops/serve.go` (or wherever the server is set up — check `cmd/cvert-ops/`)
- Modify: `cmd/cvert-ops/worker.go` (or the worker cobra command)

**Step 1: Find the right files**

```bash
ls cmd/cvert-ops/
```

Identify the `serve` and `worker` cobra command files.

**Step 2: In the `serve` command — inject Dispatcher into Evaluator**

```go
dispatcher := notify.NewDispatcher(st, cfg.NotifyDebounceSeconds)
evaluator.SetDispatcher(dispatcher)
```

This goes after the `Evaluator` is constructed and before the server starts.

**Step 3: In the `worker` command — start delivery Worker**

```go
safeClient, err := notify.BuildSafeClient()
if err != nil {
    log.Fatalf("build safe HTTP client: %v", err)
}

dispatcher := notify.NewDispatcher(st, cfg.NotifyDebounceSeconds)
deliveryWorker := notify.NewWorker(st, safeClient, notify.WorkerConfig{
    ClaimBatchSize:      cfg.NotifyClaimBatchSize,
    MaxAttempts:         cfg.NotifyMaxAttempts,
    BackoffBaseSeconds:  cfg.NotifyBackoffBaseSeconds,
    MaxConcurrentPerOrg: cfg.NotifyMaxConcurrentPerOrg,
})
deliveryWorker.SetDispatcher(dispatcher)

g.Go(func() error {
    deliveryWorker.Start(ctx)
    return nil
})
```

Add this alongside the existing worker goroutines (look for the `errgroup` or similar pattern).

**Step 4: Build**

```bash
go build ./...
```

Fix any wiring issues.

**Step 5: Commit**

```bash
git add cmd/cvert-ops/
git commit -m "feat(cmd): wire Dispatcher into Evaluator, start delivery Worker"
```

---

## Task 14: Quality checks — pitfall-check, plan-check, security-review, full suite

**Step 1: pitfall-check**

Run `/pitfall-check` on the new packages. Target: `internal/notify/`, `internal/api/channels.go`, `internal/api/deliveries.go`. Key items to verify:
- No `defer` inside loops in `worker.go`
- No `time.After` in the ticker loop (using `time.NewTicker` ✓)
- No `errgroup` in fan-out (using `sync.WaitGroup` ✓)
- No open DB tx during outbound HTTP (`MarkDeliveriesProcessing` commits before `deliver()` goroutines ✓)
- `doyensec/safeurl` used for production client ✓
- `ctx.WithoutCancel` not needed — worker goroutines use the worker's context, not an HTTP handler context ✓

**Step 2: plan-check**

Run `/plan-check` targeting §11. Verify PLAN.md §11.2 and §11.3 requirements are satisfied.

**Step 3: security-review**

Run `/security-review` targeting `internal/notify/` and `internal/api/channels.go`. Key items:
- `signing_secret` never returned in GET responses ✓
- `custom_headers` Host override blocked ✓
- Webhook URL validated via safeurl at registration time ✓
- No open tx during outbound HTTP ✓

**Step 4: Full test suite**

```bash
go test ./... -count=1
```

Expected: all tests pass, no failures.

**Step 5: Lint**

```bash
golangci-lint run ./...
```

Expected: 0 issues.

**Step 6: Final commit**

```bash
git add -p  # review any remaining changes
git commit -m "feat(notify): Phase 3a complete — webhook delivery, worker, HMAC signing, replay"
```

---

## Appendix: Helper patterns

**testDB(t)** — look at `internal/store/watchlist_test.go` for the existing test database
setup helper. Use the same pattern for notify tests.

**createTestOrg/createTestRule/createTestChannel** — add to a `internal/notify/testhelpers_test.go`
file (or reuse from `internal/api/testhelpers_test.go` if one exists).

**sqlc parameter name ambiguity** — when sqlc generates `Column4`, `Column5` for untyped
params, check the generated struct in `internal/store/generated/` and update wrapper calls.
If a query is too complex for sqlc, write it as raw SQL in the store wrapper using
`s.DB().ExecContext` or `s.DB().QueryContext`.
