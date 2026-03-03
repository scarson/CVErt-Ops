# Phase 3a Test Coverage Review — Notification Delivery (Webhook)

**Date:** 2026-03-03
**Scope:** Phase 3a commits `2633286..83d0cf1` + `1c9712e`
**Reviewer:** Claude (test-coverage-review skill)

## Scope

Phase 3a: Notification Delivery (Webhook) — channel CRUD, rule–channel binding, evaluator
fanout, delivery worker with debounce/retry/per-org semaphore, HMAC signing, DLQ replay,
secret rotation, and orphaned-event recovery.

**Files reviewed across 4 areas:**

- **Store:** `internal/store/notification_channel.go`, `internal/store/alert_rule_channel.go`, `internal/store/notification_delivery.go` + test files
- **Notify:** `internal/notify/webhook.go`, `internal/notify/dispatcher.go`, `internal/notify/worker.go`, `internal/notify/client.go` + test files
- **Alert integration:** `internal/alert/evaluator.go` (Dispatcher-related paths) + test file
- **API:** `internal/api/channels.go`, `internal/api/deliveries.go`, binding handlers in `internal/api/alert_rules.go` + test files

---

## Security-Critical Gaps

### S1. SSRF protection has zero test coverage

- `internal/notify/client.go:15-27` — `BuildSafeClient()` is never used in any test. All webhook tests use `plainHTTPClient()`. No test proves that the production client blocks `127.0.0.1`, `10.0.0.0/8`, `169.254.0.0/16`, etc.
- `internal/notify/webhook.go:69` — Same root cause: the safeurl SSRF guard is never exercised.

### S2. Signing secret end-to-end plumbing untested

- `internal/notify/worker.go:201-202` — No test creates a channel with a known signing secret, delivers a webhook, and validates the HMAC on the receiving end uses that specific DB-stored secret. The HMAC math is tested in isolation, but the plumbing from DB → worker → webhook.Send is not.

### S3. Cross-org isolation — systematic gap in store layer

13 store functions lack cross-org isolation tests. Only `GetNotificationChannel` and `ListChannelsForRule` have them. Missing for:

| Function | File:Line | Risk |
|----------|-----------|------|
| `ListNotificationChannels` | `notification_channel.go:129-140` | Data leak |
| `UpdateNotificationChannel` | `notification_channel.go:144-163` | Cross-org modification |
| `SoftDeleteNotificationChannel` | `notification_channel.go:166-176` | Cross-org deletion (silent success) |
| `RotateSigningSecret` | `notification_channel.go:181-203` | **Destroys another tenant's secret** |
| `ClearSecondarySecret` | `notification_channel.go:206-216` | Cross-org secret manipulation |
| `ChannelHasActiveBoundRules` | `notification_channel.go:220-234` | Incorrect deletion guard |
| `BindChannelToRule` | `alert_rule_channel.go:24-35` | Cross-org binding |
| `UnbindChannelFromRule` | `alert_rule_channel.go:38-49` | Cross-org unbind |
| `ListActiveChannelsForFanout` | `alert_rule_channel.go:72-86` | Uses bypassTx; org filtering only in SQL WHERE |
| `ChannelRuleBindingExists` | `alert_rule_channel.go:90-105` | Cross-org visibility |
| `ListDeliveries` | `notification_delivery.go:151-170` | Data leak |
| `GetDelivery` | `notification_delivery.go:173-190` | Data leak |
| `ReplayDelivery` | `notification_delivery.go:194-205` | Cross-org replay |

### S4. Signing secret leak surface — LIST and PATCH responses

- `internal/api/channels.go` list handler (lines 211-236) — no assertion that LIST response omits `signing_secret`
- `internal/api/channels.go` patch handler (lines 315-323) — no assertion that PATCH response omits `signing_secret` (higher risk — returns full channel object)

### S5. `GetNotificationChannelForDelivery` bypass behavior untested

- `internal/store/notification_channel.go:111-125` — Uses `withBypassTx` (no orgID filter). No test verifies this can retrieve without supplying orgID, confirming bypass works as designed vs. accidental exposure.

### S6. Header denylist case sensitivity

- `internal/notify/webhook.go:50` — `strings.ToLower` is probably correct but only tested with canonical casing. No test with `HoSt`, `CONTENT-TYPE`, or mixed-case injection attempts.

---

## Correctness Gaps

### Entire functions untested

| Function | File:Lines | Impact |
|----------|-----------|--------|
| `EvaluateEPSS()` | `evaluator.go:148-186` | Daily EPSS-specific evaluation path — zero test coverage |
| `DryRun()` | `evaluator.go:297-341` | Powers the dry-run API endpoint — zero test coverage |

### `buildSnapshot` always returns minimal snapshots

- `internal/notify/dispatcher.go:79-117` — Dispatcher tests don't insert CVEs into the `cves` table, so `GetCVESnapshot` always returns nil. The full snapshot path (lines 95-116) with nullable field handling is never exercised. The webhook payload in production will look completely different from what tests exercise.

### Delivery state-machine holes

- `internal/store/notification_delivery.go` — `MarkDeliveriesProcessing`, `CompleteDelivery`, `RetryDelivery`, `ExhaustDelivery` have **no SQL status guards**. No test proves behavior when called from wrong status (e.g., completing a "failed" delivery, retrying a "succeeded" one).
- `RetryDelivery` (lines 92-104) — `backoffSeconds` → `send_after` timing never verified. Empty `lastError` path untested.
- `ReplayDelivery` (lines 194-205) — Replay from non-failed/cancelled status is a no-op (SQL guard exists), but no test proves this.

### Worker paths with zero coverage

| Path | File:Lines | Impact |
|------|-----------|--------|
| `runStuckReset` | `worker.go:318-322` | Stuck delivery reset never tested |
| `runRecovery` | `worker.go:324-338` | Orphaned event recovery never tested |
| `backoffSeconds` | `worker.go:302-307` | Exponential backoff + jitter is a pure function with no unit test |
| Graceful shutdown | `worker.go:82-84` | `Start` → ctx cancel → `wg.Wait` never tested |

### `OrphanedAlertEvents` filter conditions under-tested

- `internal/store/notification_delivery.go:135-146` — The SQL has 4 independent filters (`suppress_delivery`, `last_match_state`, `first_fired_at` threshold, `NOT EXISTS`). Only `NOT EXISTS` is tested. If the others were inverted, no test would catch it.

### Multi-channel fanout

- `internal/notify/dispatcher.go:62-71` — No test binds 2+ channels to a rule and verifies each gets a delivery row. Per-channel failure isolation (log and continue) also untested.

### Fanout error propagation

- `internal/alert/evaluator.go:393-396` — When `Fanout()` returns error, evaluator logs and continues. No test verifies this. If someone changed it to `return err`, subsequent event processing would abort.

### `applyPostFilters` negated filter

- `internal/alert/evaluator.go:529-531` — `f.Negate` path untested.

### API handler input validation gaps

- **Delivery pagination:** no tests for cursor params, `NextCursor` generation, limit clamping (>200), or limit < 1 rejection
- **`validateEmailConfig` >50 recipients cap** — untested
- **PATCH channel not-found** after concurrent delete (line 311-314)
- **Replay non-existent delivery ID** — behavior undefined/untested

### Non-webhook channel type path

- `internal/store/notification_channel.go:59-60` — `CreateNotificationChannel` with `chanType != "webhook"` (email): no test verifies empty secret and NULL `signing_secret` in DB.

### Store not-found / soft-deleted path gaps

Multiple functions return `(nil, nil)` on `sql.ErrNoRows` but this contract is only tested for some:
- `GetNotificationChannelForDelivery` — untested for nonexistent and soft-deleted IDs
- `UpdateNotificationChannel` — untested for nonexistent and soft-deleted
- `RotateSigningSecret` — untested for nonexistent and soft-deleted
- `SoftDeleteNotificationChannel` — idempotent delete (already deleted) untested

### Store query logic gaps

- `ChannelHasActiveBoundRules` — Only "active" status tested; `draft`, `disabled`, and soft-deleted rule exclusion unverified
- `ClaimPendingDeliveries` — `FOR UPDATE SKIP LOCKED` concurrent safety untested
- `ListDeliveries` — `ruleID` and `channelID` filter paths untested; keyset pagination with real cursor untested
- `ResetStuckDeliveries` — no test proves recently-updated processing rows survive reset

---

## Nice-to-Have Gaps

~30+ gaps across DB error wrapping (`withOrgTx` callback errors), `generateSigningSecret` / `rand.Read` failure, empty-slice edge cases, ordering assertions, and unlikely runtime errors. Not individually enumerated — see per-function tables below.

---

## Per-File Detailed Tables

### `internal/store/notification_channel.go`

#### `generateSigningSecret()` (lines 47-53)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: generates 32-byte hex secret | 48-52 | Covered (integration) | — |
| Error: `rand.Read` fails | 49-51 | GAP | nice-to-have |

#### `CreateNotificationChannel()` (lines 58-85)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `chanType == "webhook"`: generates secret | 61-68 | Covered (integration) | — |
| `chanType != "webhook"` (email): no secret | 59-60 | GAP | correctness |
| `generateSigningSecret()` error | 63-65 | GAP | nice-to-have |
| `withOrgTx` success → row returned | 69-84 | Covered (integration) | — |
| `withOrgTx` error → wrapped error | 81-83 | GAP | nice-to-have |
| RLS: channel created with correct orgID | 70-79 | Covered | — |

#### `GetNotificationChannel()` (lines 89-106)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: row found | 92-103 | Covered (integration) | — |
| `sql.ErrNoRows`: not found → (nil, nil) | 96-98 | Covered (integration) | — |
| Wrong orgID → (nil, nil) | 96-98 | Covered (integration) | — |
| Non-ErrNoRows DB error | 99-101 | GAP | nice-to-have |

#### `GetNotificationChannelForDelivery()` (lines 111-125)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: row with secrets returned | 113-122 | Covered (integration) | — |
| Not found → (nil, nil) | 115-117 | GAP | correctness |
| Soft-deleted → (nil, nil) | 115-117 | GAP | correctness |
| Non-ErrNoRows DB error | 118-120 | GAP | nice-to-have |
| Uses `withBypassTx` — security correctness | 113 | GAP | security-critical |

#### `ListNotificationChannels()` (lines 129-140)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: returns non-deleted channels | 131-135 | Covered (integration) | — |
| Excludes soft-deleted | 131-135 | Covered (integration) | — |
| Cross-org isolation | 131-135 | GAP | security-critical |
| Empty org → empty slice | 131-135 | GAP | nice-to-have |
| DB error | 136-138 | GAP | nice-to-have |

#### `UpdateNotificationChannel()` (lines 144-163)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: update succeeds | 146-160 | Covered (integration) | — |
| Not found → (nil, nil) | 153-155 | GAP | correctness |
| Soft-deleted → (nil, nil) | 153-155 | GAP | correctness |
| Wrong org → (nil, nil) | 153-155 | GAP | security-critical |
| Non-ErrNoRows DB error | 156-158 | GAP | nice-to-have |

#### `SoftDeleteNotificationChannel()` (lines 166-176)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: sets deleted_at | 167-175 | Covered (integration) | — |
| Idempotent (already deleted) | 168-171 | GAP | correctness |
| Wrong org → silent no-op | 168-171 | GAP | security-critical |
| DB error | 171-173 | GAP | nice-to-have |

#### `RotateSigningSecret()` (lines 181-203)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: primary → secondary, new primary | 187-200 | Covered (integration) | — |
| `generateSigningSecret()` error | 182-184 | GAP | nice-to-have |
| Not found → ("", nil) | 193-195 | GAP | correctness |
| Soft-deleted → ("", nil) | 193-195 | GAP | correctness |
| Wrong org → ("", nil) | 193-195 | GAP | security-critical |
| Non-ErrNoRows DB error | 196-198 | GAP | nice-to-have |

#### `ClearSecondarySecret()` (lines 206-216)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: clears secondary | 207-215 | Covered (integration) | — |
| Not found/soft-deleted | 208-211 | GAP | correctness |
| Wrong org → silent no-op | 208-211 | GAP | security-critical |
| DB error | 211-213 | GAP | nice-to-have |

#### `ChannelHasActiveBoundRules()` (lines 220-234)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| No active rules → false | 222-229 | Covered (integration) | — |
| Active rule → true | 222-229 | Covered (integration) | — |
| Draft rule → false | SQL L65 | GAP | correctness |
| Disabled rule → false | SQL L65 | GAP | correctness |
| Soft-deleted rule → false | SQL L66 | GAP | correctness |
| Cross-org → false | 222-229 | GAP | security-critical |
| DB error | 230-232 | GAP | nice-to-have |

### `internal/store/alert_rule_channel.go`

#### `BindChannelToRule()` (lines 24-35)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: inserts binding | 25-34 | Covered (integration) | — |
| Idempotent: ON CONFLICT DO NOTHING | SQL L7 | Covered (integration) | — |
| Cross-org bind | 25-34 | GAP | security-critical |
| FK violation (bad IDs) | 25-34 | GAP | correctness |
| DB error | 30-32 | GAP | nice-to-have |

#### `UnbindChannelFromRule()` (lines 38-49)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: deletes binding | 39-48 | Covered (integration) | — |
| No-op (never bound) | 39-48 | GAP | correctness |
| Cross-org unbind | 39-48 | GAP | security-critical |
| DB error | 43-45 | GAP | nice-to-have |

#### `ListChannelsForRule()` (lines 53-67)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: returns bound non-deleted | 55-62 | Covered (integration) | — |
| Excludes soft-deleted | SQL L18 | Covered (integration) | — |
| Cross-org isolation | 55-62 | Covered (integration) | — |
| Empty result | 55-62 | Covered (integration) | — |
| DB error | 63-65 | GAP | nice-to-have |

#### `ListActiveChannelsForFanout()` (lines 72-86)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: returns config + secrets | 74-81 | Covered (integration) | — |
| Excludes soft-deleted | SQL L27 | Covered (integration) | — |
| Cross-org (bypassTx, org in SQL) | 74-81 | GAP | security-critical |
| DB error | 82-84 | GAP | nice-to-have |

#### `ChannelRuleBindingExists()` (lines 90-105)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Not bound → false | 92-99 | Covered (integration) | — |
| Bound → true | 92-99 | Covered (integration) | — |
| Cross-org → false | 92-99 | GAP | security-critical |
| DB error | 101-103 | GAP | nice-to-have |

### `internal/store/notification_delivery.go`

#### `UpsertDelivery()` (lines 38-51)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: creates pending row | 39-50 | Covered (integration) | — |
| Debounce: ON CONFLICT appends | SQL L27-31 | Covered (integration) | — |
| Debounce resets `send_after` timing | SQL L30 | GAP | correctness |
| `BeginTx` / SET LOCAL / ExecContext / Commit errors | 39-50 | GAP | nice-to-have |

#### `ClaimPendingDeliveries()` (lines 55-66)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: claims ready rows | 57-61 | Covered (integration) | — |
| Skips `send_after > now()` | SQL L7 | Covered (integration) | — |
| `FOR UPDATE SKIP LOCKED` concurrent safety | SQL L10 | GAP | correctness |
| Empty result | 57-61 | Covered (integration) | — |
| DB error | 62-64 | GAP | nice-to-have |

#### `MarkDeliveriesProcessing()` (lines 69-77)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: pending → processing | 70-72 | Covered (integration) | — |
| No status guard — marks any status | SQL L14-15 | GAP | correctness |
| Empty `ids` slice | 70-72 | GAP | nice-to-have |
| DB error | 73-75 | GAP | nice-to-have |

#### `CompleteDelivery()` (lines 80-88)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: sets succeeded + delivered_at | 81-83 | Covered (integration) | — |
| Non-existent ID: 0 rows, no error | 81-83 | GAP | correctness |
| No status guard | SQL L17-19 | GAP | correctness |
| DB error | 84-86 | GAP | nice-to-have |

#### `RetryDelivery()` (lines 92-104)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: resets to pending, increments attempt | 93-99 | Covered (integration) | — |
| `lastError != ""` → NullString{Valid: true} | 97 | Covered | — |
| `lastError == ""` → NullString{Valid: false} | 97 | GAP | correctness |
| No status guard | SQL L25-30 | GAP | correctness |
| `backoffSeconds` → `send_after` timing | SQL L27 | GAP | correctness |
| DB error | 100-102 | GAP | nice-to-have |

#### `ExhaustDelivery()` (lines 107-118)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: sets failed, increments attempt | 108-114 | Covered (integration) | — |
| `lastError != ""` → Valid | 113 | Covered | — |
| `lastError == ""` → NULL | 113 | GAP | nice-to-have |
| No status guard | SQL L33-39 | GAP | correctness |
| DB error | 114-116 | GAP | nice-to-have |

#### `ResetStuckDeliveries()` (lines 122-131)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: resets stuck processing rows | 124-126 | Covered (integration) | — |
| Recent processing rows survive reset | 124-126 | GAP | correctness |
| DB error | 127-129 | GAP | nice-to-have |

#### `OrphanedAlertEvents()` (lines 135-146)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: finds events with no delivery | 137-141 | Covered (integration) | — |
| Events with delivery excluded | SQL L55-62 | Covered (integration) | — |
| `suppress_delivery = true` excluded | SQL L52 | GAP | correctness |
| `last_match_state = false` excluded | SQL L53 | GAP | correctness |
| `first_fired_at` within threshold excluded | SQL L54 | GAP | correctness |
| Failed delivery → event still orphaned? | SQL L60 | GAP | correctness |
| DB error | 142-144 | GAP | nice-to-have |

#### `ListDeliveries()` (lines 151-170)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Status filter | 153-163 | Covered (integration) | — |
| No status filter (all) | 153-163 | Covered (integration) | — |
| RuleID filter | SQL L70 | GAP | correctness |
| ChannelID filter | SQL L71 | GAP | correctness |
| Keyset pagination cursor | SQL L73 | GAP | correctness |
| Cross-org isolation | 153 | GAP | security-critical |
| DB error | 166-168 | GAP | nice-to-have |

#### `GetDelivery()` (lines 173-190)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: row found | 175-187 | Covered (integration) | — |
| Not found → (nil, nil) | 180-182 | Covered (integration) | — |
| Cross-org → (nil, nil) | 180-182 | GAP | security-critical |
| Non-ErrNoRows DB error | 183-185 | GAP | nice-to-have |

#### `ReplayDelivery()` (lines 194-205)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: failed → pending, attempt=0 | 195-200 | Covered (integration) | — |
| Replay from non-failed/cancelled → no-op | SQL L100 | GAP | correctness |
| Cross-org → no-op | 195-200 | GAP | security-critical |
| Nonexistent ID → no-op | 195-200 | GAP | correctness |
| DB error | 201-203 | GAP | nice-to-have |

#### `InsertDigestDelivery()` (lines 209-218)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Happy: inserts digest row | 210-217 | Covered (integration) | — |
| Idempotent: ON CONFLICT DO NOTHING | SQL L89-90 | Covered (integration) | — |
| DB error (FK violation) | 210-217 | GAP | nice-to-have |

#### `DigestCVEs()` (lines 225-239)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| No severity filter → all | 227-234 | Covered (integration) | — |
| Severity filter | 227-234 | Covered (integration) | — |
| Old CVEs excluded | 227-234 | Covered (integration) | — |
| Empty result | 227-234 | GAP | nice-to-have |
| DB error | 235-237 | GAP | nice-to-have |

### `internal/notify/webhook.go`

#### `Send()` (lines 41-81)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Content-Type set to application/json | 46 | Covered | — |
| Custom header denied (case-insensitive) | 50 | Covered | — |
| Denied header mixed case (`HoSt`, `CONTENT-TYPE`) | 50 | GAP | security-critical |
| Allowed custom header passes through | 49-53 | GAP | correctness |
| HMAC-SHA256 primary signature | 56-60 | Covered | — |
| Secondary signature present | 63-67 | Covered | — |
| Secondary signature absent | 63 | Covered | — |
| `client.Do` network error | 69-71 | GAP | correctness |
| Non-2xx → error | 77-79 | Covered | — |
| 2xx → nil | 80 | Covered | — |
| Redirect (302) → error | 77-79 | Covered | — |
| Context cancellation | 42 | GAP | correctness |
| Empty/nil payload HMAC | 42 | GAP | correctness |
| SSRF via safeurl (production client) | 69 | GAP | security-critical |
| `http.NewRequestWithContext` error | 42-44 | GAP | nice-to-have |
| Response body discard | 73-75 | GAP | nice-to-have |

### `internal/notify/dispatcher.go`

#### `Fanout()` (lines 46-75)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `ListActiveChannelsForFanout` error | 47-49 | GAP | correctness |
| 0 channels → early return | 51-53 | Covered | — |
| Single channel → delivery row created | 62-71 | Covered | — |
| Per-channel `UpsertDelivery` failure (continue) | 63-71 | GAP | correctness |
| Multiple channels (2+) → delivery per channel | 62-71 | GAP | correctness |
| Debounce: second fanout appends | 62-71 | Covered | — |
| `json.Marshal` failure | 57-59 | GAP | nice-to-have |

#### `buildSnapshot()` (lines 79-117)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `GetCVESnapshot` error → minimal snapshot | 81-87 | GAP | correctness |
| `GetCVESnapshot` nil → minimal snapshot | 88-93 | GAP | correctness |
| Full snapshot (all nullable populated) | 95-116 | GAP | correctness |
| Partial snapshot (some nullable nil) | 100-114 | GAP | correctness |

### `internal/notify/worker.go`

#### `runClaim()` (lines 110-140)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `ClaimPendingDeliveries` error | 111-114 | GAP | correctness |
| 0 claimed rows → early return | 116-118 | GAP | nice-to-have |
| `MarkDeliveriesProcessing` fails | 124-127 | GAP | correctness |
| Semaphore blocking at capacity | 132 | GAP | correctness |

#### `deliver()` (lines 142-190)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Channel lookup DB error → exhausts | 143-151 | GAP | correctness |
| Channel nil → exhausts | 144,150 | Covered | — |
| Webhook type → deliverWebhook | 156-157 | Covered | — |
| Email type → deliverEmail | 158-159 | Covered | — |
| Unknown type → exhausts | 160-162 | Covered | — |
| Send success + CompleteDelivery success | 165-169 | Covered | — |
| Send success + CompleteDelivery fails | 166-168 | GAP | correctness |
| SMTP 5xx → exhaust immediately | 173-177 | GAP | correctness |
| Fail + retries remaining → retry | 179-189 | Covered | — |
| Fail + max attempts → exhaust | 181-183 | Covered | — |
| `RetryDelivery` DB failure | 187-189 | GAP | correctness |

#### `deliverWebhook()` (lines 192-205)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| `json.Unmarshal` config fails | 197 | GAP | correctness |
| Happy path | 199-204 | Covered | — |
| Signing secret plumbing from DB to HMAC | 201-202 | GAP | security-critical |

#### `deliverEmail()` (lines 207-278)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Email config unmarshal fails | 212-213 | GAP | correctness |
| Empty recipients | 215-217 | GAP | correctness |
| Payload unmarshal fails | 221-223 | GAP | correctness |
| Alert kind: rule lookup fails | 234-236 | GAP | correctness |
| Digest kind: >25 CVEs truncation | 256-259 | GAP | correctness |
| Unknown kind → error | 270-271 | GAP | correctness |
| Render fails | 273-275 | GAP | nice-to-have |
| Email send success end-to-end | 277 | GAP | correctness |

#### Other worker functions

| Function | Lines | Test Status | Severity |
|----------|-------|-------------|----------|
| `backoffSeconds` | 302-307 | GAP — pure function, no unit test | correctness |
| `semaphore` mutex correctness | 309-316 | GAP — no concurrent test | correctness |
| `runStuckReset` | 318-322 | GAP — entire function untested | correctness |
| `runRecovery` | 324-338 | GAP — entire function untested | correctness |
| Graceful shutdown (`Start`) | 82-84 | GAP — ctx cancel + wg.Wait | correctness |

### `internal/notify/client.go`

#### `BuildSafeClient()` (lines 15-27)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| safeurl config (timeout, redirect) | 16-21 | GAP | correctness |
| `MaxConnsPerHost` set to 50 | 22-25 | GAP | nice-to-have |
| Transport type assertion fails silently | 23-25 | GAP | correctness |
| SSRF blocking of private IPs | (safeurl) | GAP | security-critical |

### `internal/alert/evaluator.go` — Dispatcher Integration

#### `evaluateRule()` — Fanout paths (lines 351-416)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Fanout called when new event + dispatcher set | 392 | Covered | — |
| Fanout NOT called when `suppressDelivery=true` | 392 | Covered | — |
| Fanout NOT called when `eventID == uuid.Nil` (dedup) | 392 | Covered | — |
| Fanout NOT called when `dispatcher == nil` | 392 | Covered | — |
| **Fanout error → logged, NOT returned** | 393-396 | GAP | correctness |
| `applyPostFilters` negated filter | 529-531 | GAP | correctness |

#### `EvaluateEPSS()` (lines 148-186)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| All paths | 148-186 | **ENTIRE FUNCTION UNTESTED** | correctness |

#### `DryRun()` (lines 297-341)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| All paths | 297-341 | **ENTIRE FUNCTION UNTESTED** | correctness |

### `internal/api/channels.go`

#### `createChannelHandler()` (lines 67-175)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Missing orgID → 400 | 68-72 | GAP | security-critical |
| Invalid type → 422 | 86-89 | Covered | — |
| Webhook missing url → 422 | 118-122 | Covered | — |
| Webhook SSRF blocked → 422 | 123-127 | Covered | — |
| Email invalid recipients → 422 | 129-134 | Covered | — |
| Webhook → signing_secret in response | 152-156 | Covered | — |
| Email → no signing_secret | 157-159 | Covered | — |
| Empty name → 422 | 79-82 | GAP | correctness |
| Missing type → default webhook | 83-85 | GAP | correctness |
| Tier gating (free tier → 403 for email) | 98-109 | GAP | correctness |
| Invalid config JSON → 422 | 113-117 | GAP | correctness |

#### `patchChannelHandler()` (lines 240-334)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Partial update (name only) | 275-278 | Covered | — |
| Config SSRF re-validation | 280-294 | Covered | — |
| Email config re-validation | 296-301 | Covered | — |
| **PATCH response omits signing_secret** | 315-323 | GAP | security-critical |
| Not found → 404 | 265-268 | GAP | correctness |
| Concurrent delete → 404 | 311-314 | GAP | correctness |

#### `listChannelsHandler()` (lines 211-236)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Success → items array | 222-236 | Covered | — |
| **LIST response omits signing_secret** | 222-236 | GAP | security-critical |
| Empty list → 200 with empty items | — | GAP | correctness |

#### `deleteChannelHandler()` (lines 338-388)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Active rule bindings → 409 | 368-371 | Covered | — |
| Active report bindings → 409 | 368-371 | Covered | — |
| Success → 204 | 387 | Covered | — |
| Not found → 404 | 357-360 | GAP | correctness |

#### `rotateSecretHandler()` (lines 392-426)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Email channel → 422 | 414-417 | Covered | — |
| Success → 200 with new secret | 425 | Covered | — |
| Not found → 404 | 410-413 | GAP | correctness |

#### `clearSecondarySecretHandler()` (lines 430-463)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Email channel → 422 | 452-455 | Covered | — |
| Success → 204 | 462 | Covered | — |
| Not found → 404 | 448-451 | GAP | correctness |

#### `validateEmailConfig()` (lines 483-509)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Invalid JSON → error | 487-489 | Covered | — |
| Empty recipients → error | 490-492 | Covered | — |
| >50 recipients → error | 493-495 | GAP | correctness |
| Invalid RFC 5322 → error | 498-501 | Covered | — |
| Duplicate → error | 503-505 | Covered | — |
| Success | 508 | Covered | — |

### `internal/api/channels.go` — Rule-Channel Binding Handlers

#### `bindRuleChannelHandler()` (lines 697-732)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Cross-org channel → 404 | 721-724 | Covered | — |
| Idempotent bind → 204 | 731 | Covered | — |
| Invalid rule/channel UUID → 400 | 703-711 | GAP | correctness |

#### `unbindRuleChannelHandler()` (lines 736-771)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Not found → 404 | 760-763 | Covered | — |
| Success → 204 | 770 | Covered | — |
| Invalid rule/channel UUID → 400 | 741-750 | GAP | correctness |

### `internal/api/deliveries.go`

#### `listDeliveriesHandler()` (lines 96-210)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Status filter | 162-209 | Covered | — |
| Invalid rule_id/channel_id UUID → 400 | 107-124 | GAP | correctness |
| Limit < 1 → 400 | 132 | GAP | correctness |
| Limit > 200 → clamped | 136-138 | GAP | correctness |
| Cursor params | 147-155 | GAP | correctness |
| NextCursor generation | 202-207 | GAP | correctness |
| Filter by rule_id | 106-114 | GAP | correctness |
| Filter by channel_id | 116-124 | GAP | correctness |
| Null optional field formatting | 183-199 | GAP | correctness |

#### `getDeliveryHandler()` (lines 214-271)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Not found → 404 | 233-236 | Covered | — |
| Found → 200 | 237-271 | Covered | — |
| Invalid UUID → 400 | 221-225 | GAP | correctness |
| Null field formatting | 250-265 | GAP | correctness |

#### `replayDeliveryHandler()` (lines 275-300)

| Code Path | Line | Test Status | Severity |
|-----------|------|-------------|----------|
| Rate limited → 429 | 288-290 | Covered | — |
| Success → 204 | 299 | Covered | — |
| Invalid UUID → 400 | 282-286 | GAP | correctness |
| Non-existent ID behavior | 292-297 | GAP | correctness |
| Store error → 500 | 292-297 | GAP | correctness |

---

## Cross-Cutting Observations

### 1. Cross-org isolation is the single biggest systematic blind spot

The project's dual-layer isolation (parameter + RLS) is architecturally sound, but tests only verify the happy path with correct org. If a SQL query accidentally dropped the `org_id` filter, no test would catch it. This is especially dangerous for destructive operations (`SoftDelete`, `RotateSigningSecret`) where a cross-org attack succeeds silently.

### 2. RBAC not tested at endpoint level

Route registration shows correct role assignments, but there are zero tests verifying a viewer gets 403 on create, or a member gets 403 on replay. Relies entirely on middleware tests elsewhere.

### 3. Tests use `plainHTTPClient` — bypasses all production safety

Every webhook test creates its own HTTP client without safeurl. The production `BuildSafeClient` with SSRF blocking, redirect disabling, and connection limits is never exercised. A regression in `BuildSafeClient` configuration would be invisible.

### 4. `buildSnapshot` is always minimal in dispatcher tests

No CVE data inserted in `cves` table → every Fanout test gets the fallback minimal snapshot → the webhook payload in production will look completely different from what tests exercise.

### 5. Worker ticker paths untested vs `RunOnce` pattern

All worker tests use `RunOnce` (claim loop only). `runStuckReset` and `runRecovery` ticker paths have zero coverage. These are important operational paths — stuck delivery reset prevents "processing" rows from being permanently stuck, and orphaned recovery prevents alert events from never generating notifications.

### 6. Delivery state transitions lack SQL guards

`MarkDeliveriesProcessing`, `CompleteDelivery`, `RetryDelivery`, `ExhaustDelivery` accept any current status. Whether this is intentional (idempotent) or a bug (missing WHERE guard), no test documents the behavior either way.

### 7. Fanout timing is architecturally correct but fragile

The Fanout call at evaluator.go:393 occurs after `InsertAlertEvent` returns (which commits via `withOrgTx`). A test that explicitly verifies Fanout is called after the event is queryable in the DB would guard against future refactoring.

### 8. `evaluateRule` only tested through realtime path

The inner `evaluateRule` function is called by all four evaluation paths (realtime, batch, EPSS, activation). Its Dispatcher integration is only tested through the realtime path. If any other path accidentally passed wrong flags (e.g., forgetting `suppressDelivery=true` in activation), it would not be caught.

---

## Recommended Priority

### Must fix (security-critical):

1. Add at least one cross-org test per store function that takes `orgID` — especially `SoftDelete`, `RotateSigningSecret`, and `BindChannelToRule`
2. Add SSRF integration test using `BuildSafeClient` → verify private IP blocked
3. Assert signing secret absent in LIST and PATCH responses
4. Test signing secret plumbing from DB → HMAC end-to-end

### Should fix (high-value correctness):

5. Test `EvaluateEPSS()` and `DryRun()` — entire eval paths with zero coverage
6. Test `buildSnapshot` with actual CVE data in `cves` table
7. Test `runStuckReset` and `runRecovery` worker paths
8. Test delivery state transition guards (or add SQL WHERE guards if missing)
9. Test `OrphanedAlertEvents` individual filter conditions
10. Test multi-channel fanout + per-channel failure isolation

---

## Gap Count Summary

| Severity | Count |
|----------|-------|
| Security-critical | ~19 individual gaps across 6 categories |
| Correctness | ~55 individual gaps |
| Nice-to-have | ~30 individual gaps |