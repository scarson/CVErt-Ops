# Phase 3a Design: Notification Delivery (Webhook)

Date: 2026-02-28
Status: Approved
Scope: Webhook channel delivery only. Email = Phase 3b. Slack = future.

---

## Scope

Phase 3a implements the full notification delivery pipeline for webhook channels:
channel CRUD, rule–channel binding, fanout from the alert evaluator, delivery worker
(claim → HTTP → status update), HMAC signing, retry with full jitter, debounce
window, per-org concurrency cap, DLQ replay, secret rotation, and orphaned-event
recovery. No email or Slack in this phase.

---

## Schema (migration 000017)

Three new tables. Full DDL below is the canonical reference for the migration.

### `notification_channels` (soft-delete)

```sql
CREATE TABLE IF NOT EXISTS notification_channels (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                   UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                     TEXT        NOT NULL CHECK (char_length(name) <= 255),
    type                     TEXT        NOT NULL CHECK (type IN ('webhook')),
    config                   JSONB       NOT NULL DEFAULT '{}',
    CONSTRAINT nc_webhook_url CHECK (type != 'webhook' OR config ? 'url'),
    signing_secret           TEXT        NOT NULL,   -- server-generated; never returned in GET
    signing_secret_secondary TEXT        NULL,        -- populated during rotation only
    deleted_at               TIMESTAMPTZ NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

RLS: ENABLE + FORCE + dual-escape policy (bypass_rls OR org_id match).
Grant: `SELECT, INSERT, UPDATE` (soft-delete — no DELETE).
Indexes: `org_id`, `(org_id) WHERE deleted_at IS NULL`, `UNIQUE (org_id, name) WHERE deleted_at IS NULL`.

### `alert_rule_channels` (hard-delete M:M join)

```sql
CREATE TABLE IF NOT EXISTS alert_rule_channels (
    rule_id    UUID        NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    org_id     UUID        NOT NULL,   -- denormalized for RLS; no FK (established pattern)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, channel_id)
);
```

RLS: ENABLE + FORCE + dual-escape policy.
Grant: `SELECT, INSERT, DELETE` (no UPDATE — bindings are create/delete only).
Indexes: `org_id`, `channel_id` (pre-flight check for channel deletion).

### `notification_deliveries` (delivery queue, 90-day retention per §21.2)

```sql
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID        NOT NULL,
    rule_id           UUID        NOT NULL,   -- no FK: historical reference; alert_rules soft-deletes
    channel_id        UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    status            TEXT        NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','processing','succeeded','failed','cancelled')),
    attempt_count     INT         NOT NULL DEFAULT 0,
    payload           JSONB       NOT NULL DEFAULT '[]',   -- CVE snapshots accumulated during debounce
    send_after        TIMESTAMPTZ NOT NULL DEFAULT now(),  -- debounce window end / retry backoff time
    last_attempted_at TIMESTAMPTZ NULL,
    delivered_at      TIMESTAMPTZ NULL,
    last_error        TEXT        NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

RLS: ENABLE + FORCE + dual-escape policy.
Grant: `SELECT, INSERT, UPDATE, DELETE` (DELETE for 90-day retention cleanup).
Autovacuum: `scale_factor=0.01, cost_delay=2, fillfactor=70` (high-churn: 2 UPDATEs per delivery).

Indexes:
- `UNIQUE (rule_id, channel_id) WHERE status = 'pending'` — debounce dedup; ON CONFLICT target
- `(send_after) WHERE status = 'pending'` — delivery worker claim query
- `(org_id) WHERE status = 'processing'` — per-org concurrency cap count
- `org_id`, `channel_id`, `rule_id` — history queries
- `created_at` — §21.3 explicit requirement for 90-day retention batch cleanup

**Deviation from PLAN.md**: PLAN.md specifies a per-event idempotency key
`sha256(org_id + event_id + channel_id)`. The debounce design groups N events into one
delivery row (appending CVE snapshots to the payload array), making a per-event key
incorrect. The partial unique index on `(rule_id, channel_id) WHERE status = 'pending'`
provides equivalent deduplication with correct debounce semantics.

---

## Architecture

### Approach: Injected Dispatcher (Approach A)

The evaluator writes `alert_events` inside a `bypassTx`. After that transaction
commits, the evaluator calls `dispatcher.Fanout()` in a new `withOrgTx`. The two-
transaction gap means an alert_event can exist without delivery rows if Fanout fails;
the orphaned-event recovery scan corrects this within 5 minutes.

### Package layout

```
internal/notify/
├── dispatcher.go    # types (Channel, DeliveryRow), Dispatcher interface, Fanout() impl
├── worker.go        # Worker struct — claim/stuck/recovery tickers, shutdown drain
└── webhook.go       # stateless Send() function
```

---

## Components

### Dispatcher interface

```go
type Dispatcher interface {
    Fanout(ctx context.Context, orgID, ruleID uuid.UUID, cveID string) error
}
```

**Evaluator integration**: `evaluateRule()` gains an additional return value
`[]fanoutTarget{{OrgID, RuleID, CveID}}` for newly created non-suppressed events.
The callers (`EvaluateBatch`, `EvaluateRealtime`, `EvaluateEPSS`) commit the
`bypassTx`, then iterate the slice and call `e.dispatcher.Fanout()` for each target.
If `e.dispatcher == nil`, the loop is skipped — no change to existing test coverage.

**Fanout flow** (single `withOrgTx`):
1. Query bound active channels via `alert_rule_channels` JOIN `notification_channels WHERE deleted_at IS NULL`.
2. If no channels: return nil immediately.
3. Query CVE snapshot from `cves` (global table, no RLS) + up to 10 rows from `cve_affected_packages`. Truncate `description_primary` to 280 chars.
4. For each channel, debounce upsert:

```sql
INSERT INTO notification_deliveries (org_id, rule_id, channel_id, payload, send_after)
VALUES ($1, $2, $3, jsonb_build_array($snapshot), now() + $debounce)
ON CONFLICT (rule_id, channel_id) WHERE status = 'pending'
DO UPDATE SET
    payload    = notification_deliveries.payload || jsonb_build_array($snapshot),
    send_after = now() + $debounce,
    updated_at = now()
```

`$debounce` from env var `NOTIFY_DEBOUNCE_SECONDS` (default 120).

**Known edge case**: concurrent evaluation paths racing on the same `(rule_id,
channel_id)` can produce a duplicate CVE snapshot in the payload array. The ON
CONFLICT handles the race at DB level; receivers should deduplicate by `cve_id`.

### Delivery Worker

`Worker` struct holds: DB pool, `Dispatcher` (for recovery), shared safeurl HTTP client
(constructed once at startup), per-org semaphore map.

**Three tickers, one select loop:**

| Ticker | Interval | Responsibility |
|--------|----------|----------------|
| `claimTicker` | 5s | Claim and dispatch pending deliveries |
| `stuckTicker` | 60s | Reset crashed-worker `processing` rows |
| `recoveryTicker` | 5m | Orphaned-event recovery scan |

**Claim loop**:
1. `SELECT ... WHERE status='pending' AND send_after <= now() LIMIT $batchSize FOR UPDATE SKIP LOCKED`
2. `UPDATE SET status='processing', last_attempted_at=now()` — do NOT increment `attempt_count` here; increment only on confirmed failure.
3. `COMMIT` — release DB connection before HTTP.
4. For each row: acquire per-org semaphore slot, `wg.Add(1)`, spawn goroutine.
5. `wg.Wait()` only on shutdown — not between ticks.

**Per-delivery goroutine**:
```
acquire org semaphore slot
defer release slot; defer wg.Done()

err := webhook.Send(ctx, client, channel, delivery.Payload)

BEGIN new tx
  if err == nil:
      UPDATE status='succeeded', delivered_at=now()
  else if attempt_count+1 < maxAttempts:
      UPDATE status='pending', attempt_count=attempt_count+1,
             send_after=now()+backoff(attempt_count+1), last_error=$err
  else:
      UPDATE status='failed', attempt_count=attempt_count+1, last_error=$err
COMMIT
```

**Backoff**: `delay = 30s × 2^attempt × jitter`, `jitter ∈ [0.5, 1.5]`.
`maxAttempts = 4` (3 retries). Max delay ≈ 6 min.

**Per-org semaphore**: `map[uuid.UUID]chan struct{}` with lazy init under `sync.Mutex`.
Size from `NOTIFY_MAX_CONCURRENT_PER_ORG` (default 5).

**Stuck row reset** (stuckTicker):
```sql
UPDATE notification_deliveries
SET status='pending', send_after=now(), updated_at=now()
WHERE status='processing' AND updated_at < now() - interval '2 minutes'
```
Does not touch `attempt_count` — the attempt was never actually delivered.

**Orphaned event recovery** (recoveryTicker):
```sql
SELECT ae.org_id, ae.rule_id, ae.cve_id
FROM alert_events ae
WHERE ae.suppress_delivery = false
  AND ae.last_match_state = true
  AND ae.first_fired_at < now() - interval '5 minutes'
  AND NOT EXISTS (
      SELECT 1 FROM notification_deliveries nd
      WHERE nd.rule_id = ae.rule_id AND nd.org_id = ae.org_id
        AND nd.status IN ('pending','processing','succeeded')
        AND nd.created_at >= ae.first_fired_at - interval '1 minute'
  )
LIMIT 100
```
For each result: `dispatcher.Fanout(ctx, row.OrgID, row.RuleID, row.CveID)`.
The debounce upsert is idempotent — existing pending rows are extended harmlessly.

**Known limitation**: the EXISTS check operates at `(rule_id, org_id)` granularity,
not per-CVE. A delivery for a different CVE from the same rule within the window
would cause a genuinely orphaned event to be missed. Acceptable for MVP given the
millisecond-wide two-transaction gap.

**Graceful shutdown**: stop all tickers, `wg.Wait()` to drain in-flight goroutines.

### Webhook Sender

```go
func Send(ctx context.Context, client *http.Client, ch Channel, payload []byte) error
```

The safeurl client is constructed once at Worker startup:
- `Timeout: 10 * time.Second`
- `MaxConnsPerHost: 50`
- `CheckRedirect: func(...) error { return http.ErrUseLastResponse }` — redirect disabled

Steps:
1. Build POST request with `Content-Type: application/json`.
2. Apply `ch.CustomHeaders`; deny: `Host`, `Content-Type`, `Content-Length`,
   `Transfer-Encoding`, `Connection`, `X-CVErt-Timestamp`, `X-CVErtOps-Signature`.
3. HMAC with primary secret only (secondary is receiver-side fallback — sender never sends it):
```go
ts := strconv.FormatInt(time.Now().Unix(), 10)
mac := hmac.New(sha256.New, []byte(ch.SigningSecret))
mac.Write([]byte(ts + "." + string(payload)))
req.Header.Set("X-CVErt-Timestamp", ts)
req.Header.Set("X-CVErtOps-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
```
4. Execute. `defer resp.Body.Close()`.
5. `io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))` — mandatory for connection reuse.
6. Non-2xx → `fmt.Errorf("webhook %s: HTTP %d", ch.URL, resp.StatusCode)`.

---

## API Endpoints

### Channels (`internal/api/channels.go`)

| Method | Path | RBAC | Notes |
|--------|------|------|-------|
| POST | `/orgs/{org_id}/channels` | admin+ | Server generates `signing_secret`; returned once in `ChannelCreateOutput` |
| GET | `/orgs/{org_id}/channels` | member+ | Returns `ChannelOutput` (no secrets) |
| GET | `/orgs/{org_id}/channels/{id}` | member+ | Returns `ChannelOutput` (no secrets) |
| PATCH | `/orgs/{org_id}/channels/{id}` | admin+ | `*string Name`, `*WebhookConfig Config`; `type` immutable; URL re-validated via safeurl |
| DELETE | `/orgs/{org_id}/channels/{id}` | admin+ | 409 if active rules bound (`status NOT IN ('draft','disabled','deleted')`); soft-delete |
| POST | `/orgs/{org_id}/channels/{id}/rotate-secret` | owner | Moves primary→secondary, generates new primary; returns new primary once |
| POST | `/orgs/{org_id}/channels/{id}/clear-secondary` | owner | Sets `signing_secret_secondary = NULL` |

Two output types: `ChannelCreateOutput` (includes `signing_secret`) and `ChannelOutput`
(omits both secrets). All PATCH optional fields are pointer types.

### Rule–channel binding (additions to `internal/api/alert_rules.go`)

| Method | Path | RBAC | Notes |
|--------|------|------|-------|
| GET | `/orgs/{org_id}/alert-rules/{rule_id}/channels` | member+ | Lists bound active channels |
| PUT | `/orgs/{org_id}/alert-rules/{rule_id}/channels/{channel_id}` | admin+ | Idempotent; validates channel belongs to org and `deleted_at IS NULL`; 204 |
| DELETE | `/orgs/{org_id}/alert-rules/{rule_id}/channels/{channel_id}` | admin+ | Hard-delete binding row; 204 or 404 |

### Deliveries (`internal/api/deliveries.go`)

| Method | Path | RBAC | Notes |
|--------|------|------|-------|
| GET | `/orgs/{org_id}/deliveries` | member+ | Filter: `rule_id`, `channel_id`, `status`; keyset on `(created_at DESC, id DESC)` |
| GET | `/orgs/{org_id}/deliveries/{id}` | member+ | Full detail including `last_error`, `attempt_count` |
| POST | `/orgs/{org_id}/deliveries/{id}/replay` | admin+ | Resets `attempt_count=0`, `status='pending'`, `send_after=now()`, `last_error=NULL`; rate-limited 10/org/hour via in-memory token bucket (`sync.Map`) — resets on restart, acceptable for self-hosted MVP |

---

## TDD Order

1. Schema + migrations (sqlc generate, verify types compile)
2. Store layer: channel CRUD, binding CRUD, delivery claim/update queries
3. `webhook.Send()` — mock httptest.Server, verify HMAC headers, body discard, redirect rejection
4. `Dispatcher.Fanout()` — real DB (testcontainers or test DB), verify debounce upsert,
   ON CONFLICT behavior, no-channels no-op
5. Evaluator integration — inject mock Dispatcher, verify Fanout called after bypassTx commit,
   not called for suppressed events
6. Delivery worker — mock webhook server, verify claim→send→update flow, retry backoff,
   stuck-row reset, per-org semaphore cap
7. HTTP handlers — channel CRUD, binding, delivery list/replay, secret rotation

---

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `NOTIFY_DEBOUNCE_SECONDS` | `120` | Debounce window duration |
| `NOTIFY_MAX_CONCURRENT_PER_ORG` | `5` | Per-org delivery goroutine cap |
| `NOTIFY_CLAIM_BATCH_SIZE` | `50` | Rows claimed per delivery worker tick |
| `NOTIFY_MAX_ATTEMPTS` | `4` | Total attempts (1 initial + 3 retries) |
| `NOTIFY_BACKOFF_BASE_SECONDS` | `30` | Exponential backoff base delay |
| `WEBHOOK_SECRET_GRACE_HOURS` | `24` | Grace period before secondary secret should be cleared |
