# Pitfall Audit: Notification & Alert Evaluation

**Date:** 2026-03-18
**Auditor:** audit-notify agent (Explore)
**Scope:** 21 pitfalls across alert evaluation, notification delivery, webhook, worker pool
**Code paths:** `internal/alert/*`, `internal/notify/*`, `internal/worker/*`, `internal/api/alert_rules.go`, `internal/api/channels.go`

---

## Summary Table

| ID | Title | Status | Evidence |
|---|---|---|---|
| 4.1 | Activation Scan Sends Historical Notifications | VALIDATED | `evaluator.go:257` suppressDelivery=true |
| 4.2 | EPSS Blind Zones (threshold-gated hash) | VALIDATED | `evaluator.go:171-218` separate EvaluateEPSS path + date_epss_updated cursor |
| 4.3 | token_version Global Logout | OUT OF SCOPE | Auth subsystem pitfall |
| 4.4 | Activation Scan Synchronous | VALIDATED | `alert_rules.go:277` returns 202; worker runs async |
| 4.5 | Dry-Run Commits to alert_events | VALIDATED | `evaluator.go:334-380` read-only path, no INSERT |
| 4.6 | Zombie "Activating" Rules | VALIDATED | `evaluator.go:284-332` SweepZombieActivations every 5min |
| 4.7 | Activation Scan OOM | VALIDATED | `evaluator.go:247,606-624` keyset pagination, batch=1000 |
| 4.8 | Deleted Channel Breaks Rules | VALIDATED | `channels.go:366` ChannelHasActiveBindings → 409 |
| 4.9 | Webhook Tarpitting | VALIDATED | `client.go:17` SetTimeout(10s) + context timeout |
| 4.10 | DB Pool Starvation (tx during HTTP) | VALIDATED | `worker.go:179-242` 3-phase: DB → HTTP → DB |
| 4.11 | LLM Prompt Injection | OUT OF SCOPE | AI subsystem pitfall |
| 4.12 | Rejected/Withdrawn CVE Alert Storm | VALIDATED | `evaluator.go:467` status NOT IN filter on all paths |
| 4.13 | Webhook Ephemeral Port Exhaustion | VALIDATED | `client.go:23-25` MaxConnsPerHost=50 |
| 4.14 | Fan-Out Return on First Failure | VALIDATED | `dispatcher.go:62-72` continue on failure, no early return |
| 6.4 | errgroup Cancels Siblings | VALIDATED | `worker.go:46` sync.WaitGroup, not errgroup |
| 9.3 | alert_events UNIQUE Constraint | VALIDATED | `migrations/000016:53` + ON CONFLICT DO NOTHING RETURNING id |
| 9.4 | Notification Debounce | VALIDATED | `notification_delivery.go:25-32` partial unique index + payload append |
| 9.5 | Slack Block Kit > 50 blocks | UNIMPLEMENTED | No Slack integration — email and webhook only |
| 9.6 | Webhook Response Body Not Read | VALIDATED | `webhook.go:75` io.Copy(io.Discard, io.LimitReader(4096)) |
| 9.7 | Channel Hard-Deleted | VALIDATED | `migrations/000017:15` deleted_at column, soft-delete only |
| 9.8 | Thundering Herd on Retry | VALIDATED | `worker.go:373-378` full jitter: 0.5 + rand.Float64() |

**Totals:** 18 VALIDATED, 1 UNIMPLEMENTED (Slack not integrated), 2 OUT OF SCOPE (auth/AI)

---

## Detailed Findings

### 4.1 Activation Scan Sends Historical Notifications
**Status:** VALIDATED
**Evidence:** `evaluator.go:257` passes suppressDelivery=true; `evaluator.go:429-438` skips dispatcher.Fanout when suppressed
**All instances checked:** Activation path only — realtime/batch/EPSS paths use suppressDelivery=false
**Notes:** suppress_delivery flag stored in alert_events and used by recovery scan.

### 4.2 EPSS Blind Zones
**Status:** VALIDATED
**Evidence:** `evaluator.go:171-218` (EvaluateEPSS), `evaluator.go:585-602` (getCVEsEPSSUpdatedSince uses date_epss_updated)
**Notes:** EPSS tracked via separate cursor. EPSS-only rules evaluated only on EPSS score changes.

### 4.4 Activation Scan Synchronous
**Status:** VALIDATED
**Evidence:** `alert_rules.go:253-256` (status='activating'), `alert_rules.go:277-282` (returns 202), `alert_rules.go:820-829` (enqueueActivation)
**Notes:** Handler returns 202 immediately. Worker runs activation asynchronously.

### 4.5 Dry-Run Commits to alert_events
**Status:** VALIDATED
**Evidence:** `evaluator.go:334-380` — DryRun queries candidates and applies post-filters but does NOT write alert_events
**Notes:** Read-only path. Transaction committed but no persistence of matches.

### 4.6 Zombie "Activating" Rules
**Status:** VALIDATED
**Evidence:** `evaluator.go:284-332` (SweepZombieActivations), worker ticker every 5 min
**Notes:** Detects stuck activation jobs (locked_at < now() - 15min), transitions to 'error' status.

### 4.7 Activation Scan OOM
**Status:** VALIDATED
**Evidence:** `evaluator.go:247` (main loop), `evaluator.go:606-624` (getCVEsBatch with keyset pagination, LIMIT 1000)
**Notes:** Batch size constant: activationBatch=1000. Per-iteration memory bounded.

### 4.8 Deleted Channel Breaks Rules
**Status:** VALIDATED
**Evidence:** `channels.go:340-392` (deleteChannelHandler), `channels.go:366-375` (ChannelHasActiveBindings → 409)
**Notes:** Pre-flight check. Only calls SoftDeleteNotificationChannel if no active bindings.

### 4.9 Webhook Tarpitting
**Status:** VALIDATED
**Evidence:** `client.go:15-27` (BuildSafeClient), `client.go:17` (SetTimeout 10s)
**Notes:** Client-level 10s timeout + per-request context timeout from worker.

### 4.10 DB Pool Starvation
**Status:** VALIDATED
**Evidence:** `worker.go:179-242` — 3 phases: (1) channel lookup DB, (2) webhook/email send no-DB, (3) status update DB
**Notes:** No DB transaction held during HTTP call. Each phase uses separate DB interactions.

### 4.12 Rejected/Withdrawn CVE Alert Storm
**Status:** VALIDATED
**Evidence:** `evaluator.go:467` — `lower(cves.status) NOT IN ('rejected', 'withdrawn')`
**All instances checked:** realtime (467), batch (573,577), EPSS (594,599), activation (614,620) — all filtered
**Notes:** Comprehensive coverage across all evaluation paths.

### 4.13 Webhook Ephemeral Port Exhaustion
**Status:** VALIDATED
**Evidence:** `client.go:23-25` — MaxConnsPerHost=50
**Notes:** Both per-org semaphore (worker.go:43) and per-host cap implemented.

### 4.14 Fan-Out Return on First Failure
**Status:** VALIDATED
**Evidence:** `dispatcher.go:62-72` — loop continues on per-channel failure, no early return
**Notes:** UpsertDelivery failures logged but don't abort fan-out.

### 6.4 errgroup Cancels Siblings
**Status:** VALIDATED
**Evidence:** `worker.go:46` — sync.WaitGroup, not errgroup
**Notes:** Independent goroutine tracking. No context cancellation across deliveries.

### 9.3 alert_events UNIQUE
**Status:** VALIDATED
**Evidence:** `migrations/000016:53` — `UNIQUE (org_id, rule_id, cve_id, material_hash)`, `alert_rules.sql:76-79` — ON CONFLICT DO NOTHING RETURNING id
**Notes:** Exactly-once semantics. Fan-out only fires on actual insert.

### 9.4 Notification Debounce
**Status:** VALIDATED
**Evidence:** `notification_delivery.go:25-32` — upsertDeliverySQL with partial unique index, payload append via jsonb_build_array
**Notes:** Configurable debounce window per (rule, channel). Multiple CVEs accumulate in payload array.

### 9.5 Slack Block Kit > 50 blocks
**Status:** UNIMPLEMENTED
**Evidence:** No Slack channel type in codebase. Only webhook and email supported.
**Notes:** Email truncation at 25 CVEs IS implemented (worker.go:314-315). Slack pitfall becomes relevant when Slack integration is added.

### 9.6 Webhook Response Body Not Read
**Status:** VALIDATED
**Evidence:** `webhook.go:75` — `io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))`
**Notes:** Response body read and discarded (capped 4KB) to enable connection reuse.

### 9.7 Channel Hard-Deleted
**Status:** VALIDATED
**Evidence:** `migrations/000017:15` (deleted_at column), `migrations/000017:32-33` ("Soft-delete: no DELETE grant")
**Notes:** All active lookups filter WHERE deleted_at IS NULL. History preserved.

### 9.8 Thundering Herd on Retry
**Status:** VALIDATED
**Evidence:** `worker.go:373-378` — `jitter := 0.5 + rand.Float64()` applied to exponential backoff
**Notes:** Full jitter spreads retry attempts between 50%-150% of base delay.

---

## New Discoveries

1. **Alert Rule Resolution Detection:** `alert_events` tracks `last_match_state` (BOOLEAN). `ResolveAlertEvent()` marks events as resolved when CVE no longer matches rule. Enables resolution notifications (pitfall 9.2 from Rounds 24-52).

2. **Email Truncation at 25 CVEs:** `worker.go:313-315` caps digest emails at 25 CVEs with "N more" footer. Prevents SMTP relay rejection for large batches.

3. **Orphaned Event Recovery:** `notification_deliveries.sql:48-63` defines recovery scan detecting alert_events without corresponding delivery rows (5+ minutes old). Worker re-fans-out missed deliveries every 5 minutes.

4. **Debounce Partial Unique Index:** Uses `WHERE status = 'pending' AND kind = 'alert'` to allow multiple terminal-state rows per (rule, channel) while enforcing one pending row.

5. **SetAlertRuleStatusIf Atomic:** Status transitions use conditional UPDATE (`WHERE status = $4`) for optimistic concurrency during activation scan. Handles concurrent rule disable gracefully.

---

## Assessment

The notification & alert implementation is **production-ready**. All critical operational pitfalls addressed. The activation scan has 4 layers of protection (async 202, silent mode, pagination, zombie sweeper). Delivery has 3 layers (debounce, per-channel independence, jitter backoff). The only gap is Slack integration (not yet implemented).
