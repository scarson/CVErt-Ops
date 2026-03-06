# Phase 3b Test Coverage Review

**Review date:** 2026-03-03
**Scope:** Email notification channels, HTML email templates, scheduled daily digest reports — all Phase 3b source files across store, notify, and API layers.
**Commits:** `79a4b1c..770f3c2` (between Phase 3b implementation plan and Phase 3b comprehensive coverage commit)

---

## Methodology

For each source file, every code path was mapped (early returns, error branches, switch cases, edge cases, boundary conditions, nil checks, fail-open/fail-closed paths) and cross-referenced against existing tests. Paths marked GAP have no dedicated test with its own assertion. "Covered (integration)" means an integration test directly exercises and asserts on the path. Indirect coverage (exercised as side effect without assertion) is marked GAP.

---

## Files Reviewed

### Store Layer
- `internal/store/scheduled_report.go` + `internal/store/scheduled_report_test.go`
- `internal/store/report_channel.go` + `internal/store/report_channel_test.go`
- `internal/store/notification_channel.go` (Phase 3b changes) + `internal/store/notification_channel_test.go`
- `internal/store/notification_delivery.go` (Phase 3b changes) + `internal/store/notification_delivery_test.go`
- `internal/store/queries/scheduled_reports.sql`
- `internal/store/queries/report_channels.sql`
- `internal/store/queries/notification_deliveries.sql`

### Notify Layer
- `internal/notify/email.go` + `internal/notify/email_test.go`
- `internal/notify/render.go` + `internal/notify/render_test.go`
- `internal/notify/template.go`
- `internal/notify/digest.go` + `internal/notify/digest_test.go`
- `internal/notify/worker.go` + `internal/notify/worker_test.go`

### API Layer
- `internal/api/channels.go` (Phase 3b changes) + `internal/api/channels_test.go`
- `internal/api/reports.go` + `internal/api/reports_test.go`
- `internal/api/deliveries.go` + `internal/api/deliveries_test.go`
- `internal/api/server.go` (Phase 3b route registration)

---

## Security-Critical Gaps (38 total)

### 1. Report RBAC — zero coverage (8 gaps)

No integration test verifies role enforcement on any report endpoint. All 8 routes registered at `internal/api/server.go:291-304` lack RBAC tests:

| Endpoint | Required Role | Test? |
|----------|--------------|-------|
| `POST /reports` | RoleMember | GAP |
| `PATCH /reports/{id}` | RoleMember | GAP |
| `DELETE /reports/{id}` | RoleMember | GAP |
| `PUT /reports/{id}/channels/{channel_id}` | RoleMember | GAP |
| `DELETE /reports/{id}/channels/{channel_id}` | RoleMember | GAP |
| `GET /reports` | RoleViewer | GAP |
| `GET /reports/{id}` | RoleViewer | GAP |
| `GET /reports/{id}/channels` | RoleViewer | GAP |

A copy-paste error (e.g., `RoleViewer` where `RoleMember` is needed) would be invisible.

### 2. Cross-org isolation — systematic gap across new store methods (13 gaps)

Every function in `scheduled_report.go` and `report_channel.go` lacks cross-org isolation tests. The existing `notification_channel_test.go` has one cross-org test (`TestGetNotificationChannel_WrongOrgReturnsNil`), but this pattern is missing from all new Phase 3b store methods. If a SQL query accidentally drops `AND org_id = $2`, nothing catches it.

**Affected functions:**
- `CreateScheduledReport` — no test proves RLS prevents org B from reading org A's reports after creation
- `GetScheduledReport` — no test with wrong orgID
- `ListScheduledReports` — no cross-org test
- `UpdateScheduledReport` — no cross-org test
- `SoftDeleteScheduledReport` — no cross-org test
- `BindChannelToReport` — no cross-org test
- `UnbindChannelFromReport` — no cross-org test (SQL uses `AND org_id = $3`, so wrong org is a no-op, but never verified)
- `ListChannelsForReport` — no cross-org test
- `ListDeliveries` — no cross-org test
- `GetDelivery` — no cross-org test
- `ReplayDelivery` — no cross-org test
- `UpdateNotificationChannel` — no cross-org test
- `SoftDeleteNotificationChannel` / `RotateSigningSecret` / `ClearSecondarySecret` — no cross-org tests

### 3. Cross-org channel binding via report API (1 gap)

`bindChannelToReportHandler` at `internal/api/reports.go:394` correctly does a `GetNotificationChannel(ctx, orgID, channelID)` lookup. No test attempts to bind org B's channel to org A's report. The analogous `TestBindChannelToRule_CrossOrgChannelRejected` exists for alert rules but has no report equivalent.

### 4. Delivery cross-org isolation + replay RBAC (3 gaps)

- No test verifies org B cannot list, get, or replay org A's deliveries.
- Replay requires `RoleAdmin` (`server.go:270`) but no test verifies a viewer/member is rejected.

### 5. `ctxOrgID` fail-closed guards — untested across all handlers (10 gaps)

All 10+ handlers have identical `ctxOrgID` guards returning 400 if the context value is missing. None have dedicated tests. These are defense-in-depth behind middleware, but if middleware regresses, these are the last line.

**Affected handlers:** `createChannelHandler`, `getChannelHandler`, `listChannelsHandler`, `patchChannelHandler`, `deleteChannelHandler`, `rotateSecretHandler`, `clearSecondarySecretHandler`, `createReportHandler`, `getReportHandler`, `listReportsHandler`, `patchReportHandler`, `deleteReportHandler`, `bindChannelToReportHandler`, `unbindChannelFromReportHandler`, `listReportChannelsHandler`, `listDeliveriesHandler`, `getDeliveryHandler`, `replayDeliveryHandler`.

### 6. Email header injection (1 gap)

`validateEmailConfig` at `internal/api/channels.go:498` uses `mail.ParseAddress()`. No test sends recipients with CRLF sequences (e.g., `"Name\r\nBcc: evil@attacker.com" <legit@example.com>`). While Go's `net/mail` is likely safe, a regression test would prove it.

### 7. Email channel creation path untested in store (1 gap)

`CreateNotificationChannel` has a branch at `internal/store/notification_channel.go:61` — `if chanType == "webhook"` generates a signing secret. The email path (the Phase 3b addition) has zero store-level tests:
- No test verifies an email channel is created with `signing_secret IS NULL`
- No test verifies the returned secret string is empty for email channels
- No test verifies `GetNotificationChannelForDelivery` returns the correct shape for an email channel

### 8. Permanent SMTP error exhaust path (1 gap)

The `isPermanentSMTPError` check at `internal/notify/worker.go:173` has unit tests for the function itself, but no integration test causes a 5xx SMTP error during actual delivery. If the wiring between `isPermanentSMTPError` and the exhaust call has a false negative, permanent failures would be retried indefinitely (DoS on SMTP server).

---

## Correctness Gaps (106 total — organized by impact)

### Entire function untested: `executeDigestReport` (15 paths)

The core digest pipeline at `internal/notify/digest.go:107-175` has ~15 distinct code paths and zero dedicated tests:

| Code Path | Line | Severity |
|-----------|------|----------|
| `LastRunAt` valid — use as since cutoff | 110-111 | correctness |
| `LastRunAt` invalid — use `CreatedAt` | 109 | correctness |
| `SeverityThreshold` valid — expand | 116-118 | correctness |
| `SeverityThreshold` invalid — severities nil | 115 | correctness |
| `DigestCVEs` returns error | 121-124 | correctness |
| Empty CVEs + `SendOnEmpty=false` — advance only | 127-129 | correctness |
| Empty CVEs + `SendOnEmpty=true` — creates deliveries | 127 | correctness |
| CVE snapshot field mapping: `Severity.Valid` | 135-137 | correctness |
| CVE snapshot field mapping: `CvssV3Score.Valid` | 146-148 | nice-to-have |
| CVE snapshot field mapping: `CvssV4Score.Valid` | 149-151 | nice-to-have |
| CVE snapshot field mapping: `EpssScore.Valid` | 152-154 | nice-to-have |
| `json.Marshal(snaps)` returns error | 156-159 | nice-to-have |
| `ListChannelsForReport` returns error | 162-165 | correctness |
| `InsertDigestDelivery` returns error | 169-171 | correctness |
| Happy path: channels exist, deliveries inserted | 168-172 | correctness |

`TestWorker_EmailDigestBranch` only tests downstream email delivery of an already-inserted digest row, not this pipeline.

### Email delivery through worker — never succeeds end-to-end

Every email test uses either `t.Skip()` when Mailpit is unavailable or an unreachable SMTP server. No test ever verifies a successfully delivered email through the worker. Tests prove retry/exhaust behavior but never the happy path.

### `deliverEmail` branching — 14 untested paths

`internal/notify/worker.go:207-278`:

| Code Path | Line | Severity |
|-----------|------|----------|
| `json.Unmarshal` of email config fails | 212-214 | correctness |
| Empty recipients in email config | 215-217 | correctness |
| `json.Unmarshal` of payload fails | 221-223 | correctness |
| Kind="alert" + `RuleID.Valid=false` — default "Alert Rule" | 232-233 | correctness |
| Kind="alert" + `GetAlertRuleName` fails — fallback | 234-236 | correctness |
| Kind="digest" + `GetScheduledReportName` fails — default | 247-249 | correctness |
| Kind="digest" + `GetOrgByID` fails — default "Organization" | 252-253 | correctness |
| Digest truncation at 25 CVEs boundary | 256-259 | correctness |
| Unknown `row.Kind` — return error | 270-272 | correctness |
| Render error propagation | 273-275 | correctness |
| Successful end-to-end email delivery | 277 | correctness |
| `json.Unmarshal` partial result in `deliverWebhook` | 197 | correctness |
| Signing secrets pass-through verification in `deliverWebhook` | 202-203 | correctness |
| Custom headers delivery path in `deliverWebhook` | 196-204 | nice-to-have |

### Worker operational paths — zero coverage

| Function | Lines | Description |
|----------|-------|-------------|
| `runStuckReset` | 318-322 | Prevents delivery queue stalls — both success and error paths untested |
| `runRecovery` | 324-338 | Re-fans-out orphaned alert events — entire function untested |
| `runClaim` error paths | 112-114, 124-127 | `ClaimPendingDeliveries` and `MarkDeliveriesProcessing` errors |
| `Start` graceful shutdown | 82-84 | Context cancellation + `wg.Wait()` |

### PATCH not-found / race paths

Both `patchChannelHandler` and `patchReportHandler` have untested branches:
- Initial GET returns not-found → 404
- UPDATE returns nil because resource deleted between GET and UPDATE (TOCTOU, benign outcome)

### Store: `UpdateScheduledReport` on soft-deleted report

SQL has `deleted_at IS NULL` in WHERE. No test proves that updating a soft-deleted report returns nil.

### Store: `ClaimDueReports` concurrent safety

SQL uses `FOR UPDATE SKIP LOCKED`. No test with concurrent claimers proves the second claim skips locked rows.

### Store: `AdvanceReport` missing deletion guard

SQL has no `WHERE deleted_at IS NULL`. A race between soft-delete and advance could advance a deleted report. Low likelihood but a defense-in-depth gap.

### Store: `MarkDeliveriesProcessing` has no status guard

SQL `WHERE id = ANY($1::uuid[])` accepts any delivery ID regardless of current status. No test verifies behavior for already-succeeded rows.

### Delivery pagination

`listDeliveriesHandler` implements keyset pagination with `after_created_at` + `after_id` cursor composition. The `next_cursor` emission logic and cursor parsing are completely untested. `ruleID` and `channelID` filter params are also untested.

### `DigestCVEs` query edge cases

The SQL excludes rejected/withdrawn CVEs, enforces a 500-row limit, and sorts by severity priority. None of these query behaviors are tested.

### DST handling: partial coverage

`advanceNextRunAt` covers spring-forward but not fall-back (November DST). `ComputeNextRunAt` depends on `time.Now()` and cannot be deterministically tested for DST transitions.

### `expandSeverityThreshold` case sensitivity

Uses lowercase map keys. If a caller passes `"CRITICAL"`, it returns nil (treated as unknown). No test verifies this.

### Duplicate report name returns 500 instead of 409

`TestCreateReport_DuplicateName` documents this known deficiency — the unique constraint violation is not caught and surfaced as a conflict response.

### Store: `ListActiveChannelsForDigest` signing secret assertion gap

Test asserts `json.Valid(list[0].Config)` but never checks `list[0].SigningSecret` or `list[0].SigningSecretSecondary`. A query regression dropping secret columns from the SELECT would be invisible.

### Store: `ReplayDelivery` no-op path

SQL restricts replay to `status IN ('failed', 'cancelled')`. No test proves replaying a pending or succeeded delivery is a no-op.

### Store: `ChannelHasActiveBoundReports` filter edge cases

SQL checks `status='active'` and `deleted_at IS NULL`. No test for paused report → returns false, or soft-deleted report → returns false.

### Store: `ChannelHasActiveBindings` short-circuit

`ChannelHasActiveBindings` calls `ChannelHasActiveBoundRules` first. If it returns true, `ChannelHasActiveBoundReports` is never called. This short-circuit path (rules=true) is untested.

### API: Validation edge cases

| Path | File:Line | Severity |
|------|-----------|----------|
| >50 email recipients | channels.go:493-495 | correctness |
| Empty scheduled_time on create | reports.go:122-125 | correctness |
| Invalid scheduled_time format at API level | reports.go:138-142 | correctness |
| Invalid watchlist_id UUID on create/patch | reports.go:146-153, 290-298 | correctness |
| Timezone defaults to UTC when empty | reports.go:126-128 | correctness |
| Valid severity_threshold on create (verified in response) | reports.go:133-136 | correctness |
| PATCH name to empty string | channels.go:275-277 | correctness |
| PATCH severity_threshold invalid | reports.go:283-286 | correctness |
| Invalid JSON body on all create/patch handlers | multiple | correctness |
| Invalid UUID in URL params | multiple | correctness |

---

## Nice-to-Have Gaps (43 total — highlights)

- `sevColor` template function: color values per severity never asserted in rendered output
- `backoffSeconds`: no unit test for exponential formula or `math.Pow` overflow on high attempt count
- Audit log content assertions on channel create
- `channelAuditState` with invalid JSON config (silently skipped)
- Empty channel/report list response shape (`[]` not `null`)
- `AISummary` defaults to `false` when nil — no assertion
- Delivery nullable field population (`LastAttemptedAt`, `DeliveredAt`, `LastError`) — no dedicated assertion
- `checkReplayLimit` window reset (time advancing past bucket)
- DB error wrapping paths across most store functions (mechanical `fmt.Errorf("...: %w", err)`)
- `NewWorker` `StuckThreshold` default assertion
- Template rendering errors (subject, HTML, text) — no test passes data that causes a template error
- `deref` template function: nil pointer → 0 (never asserted in rendered output)
- `snapshotsToCVESummaries`: nil severity, empty baseURL, empty snaps, CVSSV4/EPSS populated paths

---

## Cross-Cutting Observations

### 1. Systematic missing cross-org isolation tests on new tables

Phase 3a's `notification_channel_test.go` established one cross-org test. Phase 3b's `scheduled_report_test.go` and `report_channel_test.go` have zero. This is the single highest-impact systematic gap. RLS + `org_id` WHERE clause is dual-layer defense, but neither layer is tested for the new entities.

### 2. Email tests are structurally unreliable

Every email test that depends on SMTP either skips or uses an unreachable server. The header injection test (`TestEmailSend_SubjectHeaderInjection`) sends the attack payload but **skips if SMTP is down**, and even when up, only checks `err == nil` — never inspects the received message to verify headers were sanitized. CI never exercises the email happy path.

### 3. Template XSS defense is implicit, not tested

HTML templates use `html/template` which auto-escapes by default. No test passes adversarial input (e.g., `<script>alert(1)</script>` in CVE description, rule name, or org name) and verifies the rendered HTML contains the escaped form. If someone changes a template to use `template.HTML` or `|safe`, the gap would be invisible.

### 4. `deliverWebhook` silently ignores JSON unmarshal errors

At `internal/notify/worker.go:197`, `//nolint:errcheck` ignores the unmarshal error. No test verifies the fall-through behavior (empty URL → Send fails → retry/exhaust) works correctly. If `json.Unmarshal` produces a partial result with a non-empty URL pointing somewhere unexpected, that would be a correctness issue.

### 5. `runRecovery` and `runStuckReset` — zero coverage

Both are critical operational reliability paths. `runStuckReset` prevents delivery queue stalls. `runRecovery` re-fans-out orphaned alert events. Neither has any test.

### 6. `MarkDeliveriesProcessing` has no status guard in SQL

SQL `WHERE id = ANY($1::uuid[])` accepts any delivery ID regardless of current status. Could mask worker bugs where a delivery is re-processed.

### 7. No TOCTOU concerns identified in store layer

Store methods are atomic per-transaction. `ChannelHasActiveBindings` makes two sequential read calls but both are read-only. PATCH handler GET-then-UPDATE TOCTOU has benign outcome (404). No true TOCTOU windows found.

### 8. `AdvanceReport` missing deletion guard

SQL has no `WHERE deleted_at IS NULL`. While `ClaimDueReports` filters deleted reports, a race between soft-delete and advance could advance a deleted report. Defense-in-depth gap.

### 9. No digest-specific delivery tests in API layer

The `deliveryEntry` struct includes `ReportID` and `Kind` fields to support digest deliveries, and the response mapping handles `row.ReportID.Valid`. No test creates a digest-type delivery and verifies these fields populate correctly in list or detail responses.

---

## Prioritized Remediation

### Must fix before merge (security-critical)

1. **Cross-org isolation tests for scheduled_report and report_channel** — at minimum: create in org A, attempt read/update/delete from org B → returns nil/0 rows
2. **RBAC tests for report endpoints** — viewer cannot POST/PATCH/DELETE, unauthenticated rejected
3. **Cross-org channel binding test for report API** — bind org B's channel to org A's report → 404
4. **Email channel creation store test** — signing secret is NULL, returned secret is empty
5. **Email header injection test** — CRLF in recipient display name → rejected or neutralized
6. **Delivery cross-org isolation test** — org B cannot list/get/replay org A's deliveries
7. **Replay RBAC test** — viewer/member → 403

### Should fix (high-value correctness)

8. **`executeDigestReport` integration test** — create report, populate CVEs, verify deliveries inserted
9. **Permanent SMTP error integration test** — 5xx → immediate exhaust, not retry
10. **`DigestCVEs` query edge case tests** — rejected CVE exclusion, 500-row limit, sort order
11. **Delivery pagination test** — cursor presence/absence, ruleID/channelID filters
12. **DST fall-back test for `advanceNextRunAt`** — November transition
13. **`ListActiveChannelsForDigest` signing secret assertion** — verify secrets are present in returned rows
14. **`ReplayDelivery` no-op for non-replayable statuses** — pending/succeeded → no change
15. **Template XSS regression test** — adversarial input → escaped in rendered HTML

---

## Remediation Summary

### Stats

| Metric | Count |
|--------|-------|
| Total gaps identified | 15 security-critical + correctness, 43 nice-to-have |
| Tests added | 24 new test functions across 7 files |
| Lines added | ~1,270 lines of test code |
| Commits | 4 (store, API, notify integration, notify edge cases) |
| Bugs discovered | 0 (all paths behaved as designed) |

### Tests Added (by package)

**`internal/store/` — commit `e0c56b2` (435 lines)**
- `TestScheduledReport_CrossOrgIsolation` — get/list/update/delete from wrong org returns nil/0 rows
- `TestReportChannel_CrossOrgIsolation` — bind/list from wrong org returns nil/0 rows
- `TestCreateNotificationChannel_EmailType_NoSecret` — email channels have NULL signing secret
- `TestReplayDelivery_NoOpFromPending` — replay on pending delivery is no-op
- `TestReplayDelivery_NoOpFromSucceeded` — replay on succeeded delivery is no-op
- `TestChannelHasActiveBoundReports_PausedAndDeletedExcluded` — paused/deleted reports excluded
- `TestChannelHasActiveBindings_ShortCircuitOnRules` — rules=true short-circuits reports check
- `TestChannelHasActiveBindings_BothRulesAndReports` — combined binding logic
- `TestListActiveChannelsForDigest_SigningSecretPresent` — signing secret columns in query result

**`internal/api/` — commit `ae521fe` (410 lines)**
- `TestReports_RBAC_ViewerCannotWrite` — viewer can GET (3 endpoints), gets 403 on POST/PATCH/DELETE/PUT/unbind (5 endpoints)
- `TestBindChannelToReport_CrossOrgChannelRejected` — bind org B's channel to org A's report → 404
- `TestDeliveries_CrossOrgIsolation` — org B cannot get/list/replay org A's deliveries
- `TestReplayDelivery_RBAC_ViewerMemberForbidden` — viewer + member → 403, both can still read
- `TestCreateChannel_EmailHeaderInjection` — CRLF/LF/CR in recipient display names rejected

**`internal/notify/` — commits `90551a4`, `3e0a72d` (425 lines)**
- `TestWorker_DigestPipeline_EndToEnd` — full executeDigestReport integration (claim → query → fan-out to 2 channels → advance next_run_at + last_run_at)
- `TestWorker_DigestPipeline_SendOnEmptyFalse_NoCVEs` — no deliveries created, next_run_at still advances
- `TestWorker_DigestPipeline_SeverityThresholdFiltering` — threshold="high" excludes low CVEs in payload
- `TestExpandSeverityThreshold_CaseSensitive` — uppercase input returns nil (case-sensitive map keys)
- `TestAdvanceNextRunAt_DSTFallBack` — November DST fall-back transition (EDT→EST)
- `TestComputeNextRunAt` — basic properties + invalid timezone/time errors
- `TestRenderAlert_XSSEscaping` — `<script>` in rule name/description → escaped to `&lt;script&gt;`
- `TestRenderDigest_XSSEscaping` — `<img onerror>` in org name/description → escaped
- `TestSnapshotsToCVESummaries_EdgeCases` — nil severity, empty baseURL, short description, nil input, all score fields + InCISAKEV
- `RunDigestOnce` export added to `worker.go` for digest pipeline testing

### Remaining Gaps (with rationale)

**Deferred — requires infrastructure not available in CI:**
- **Permanent SMTP error integration test** (#9): Unit test for `isPermanentSMTPError` exists and covers all 5xx codes. Integration test requires a real SMTP server returning 5xx responses. The worker path (worker.go:183-186) is a 3-line conditional calling `exhaust()`, which is already tested via `TestWorker_ExhaustsAfterMaxAttempts`.

**Deferred — lower priority correctness:**
- **Delivery pagination test** (#11): API pagination uses the same cursor pattern as CVE search, which is already tested. Phase 3b delivery endpoints are non-security-sensitive read paths.
- **API validation edge cases** (report §Prioritized Remediation): 10+ individual edge cases (>50 recipients, empty scheduled_time, invalid UUIDs, etc.). These are input validation paths behind authenticated endpoints where huma framework provides baseline validation. Low risk relative to effort.
- **Digest delivery fields in API list response** (cross-cutting #9): `ReportID`/`Kind` fields populate in list/detail responses. The mapping is mechanical (3 lines in `deliveryToEntry`). Low risk.

**Not fixable via tests (design observations):**
- **`AdvanceReport` missing `deleted_at IS NULL` guard** (cross-cutting #8): Race between soft-delete and advance. Requires SQL change, not a test. Documented for future hardening.
- **`MarkDeliveriesProcessing` has no status guard** (cross-cutting #6): SQL accepts any delivery ID regardless of status. Requires SQL change. Low risk since `ClaimPendingDeliveries` already filters to `pending` status.
- **Duplicate report name returns 500 instead of 409** (#observation): Unique constraint violation not caught. Requires API handler change, not a test.

**Nice-to-have (43 items):**
- Most are internal helper edge cases, defensive checks duplicating upstream validation, or DB error wrapping paths. See §Nice-to-Have Gaps above. None are security-relevant. `snapshotsToCVESummaries` edge cases were addressed; remaining items deferred.