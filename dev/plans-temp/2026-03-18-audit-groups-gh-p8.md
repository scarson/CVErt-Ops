# Audit: HR Groups G/H + P8 Batch 1

**Date:** 2026-03-18
**Plans audited:**
- `dev/plans/2026-03-18-health-review-remediation-plan.md` (Groups G, H)
- `dev/plans/2026-03-18-phase8-coverage-remediation-plan.md` (Batch 1, Tasks 1-8)

---

## HR Group G

### Task G2: NullString empty-string behavior
- **Plan says:** Audit callers of `dbutil.NullString`. Determine if any caller intentionally depends on empty-string -> NULL. If change is warranted, rename or add a clearly named alternative. Do NOT change existing behavior without Sam's approval. At minimum, clarify with a doc comment.
- **Code does:** `internal/dbutil/null.go` now has two functions: `NullString` (empty string = NULL, with a clear doc comment explaining this behavior) and `NullStringPtr` (preserves empty strings as distinct from NULL when non-nil). The doc comment on line 9-11 explicitly states: "An empty string is treated as NULL (Valid=false). Use NullStringPtr when empty strings should be preserved as distinct from NULL."
- **Match:** YES
- **Tests:** N/A (no test required; this was a documentation/clarification task)
- **Gaps:** None. The doc comment clearly explains the behavior and directs callers to `NullStringPtr` when empty strings should be preserved.

### Task G3: isPermanentDeliveryError typed SMTP errors
- **Plan says:** Check if go-mail exposes a typed SMTP error with status code. If so, use type assertion instead of string matching. If not, document the limitation and improve string matching.
- **Code does:** `internal/notify/worker.go:351-376` implements a three-tier approach: (1) checks for `permanentDeliveryError` wrapper type, (2) uses go-mail's typed `*mail.SendError` with `IsTemp()` and `ErrorCode()` methods, (3) falls back to string matching for SMTP 5xx codes from non-go-mail sources. The doc comment at line 347-350 explains all three tiers.
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s ./internal/notify/...` -- passes). `TestIsPermanentDeliveryError` in `digest_test.go` covers nil, transient (421), all 5xx codes (550-555), embedded 5xx, random errors, permanentDeliveryError wrapper, and wrapped permanentDeliveryError.
- **Gaps:** The test cases don't include a direct `*mail.SendError` test case (only the string-matching and wrapper paths are tested). This is a minor gap -- testing go-mail's typed error would require constructing a `*mail.SendError` which may require internal go-mail dependencies. The fallback string matching provides coverage for the same error codes.

### Task G4: Cache-Control headers
- **Plan says:** Add middleware that sets `Cache-Control: no-store` on all authenticated responses. Wire it on the org-scoped router. (Note from audit instructions: middleware was moved to global apiRouter level during review.)
- **Code does:** `internal/api/middleware_cache.go` defines `noCacheMiddleware` that sets `Cache-Control: no-store` on all responses. `internal/api/server.go:228` wires it on the `apiRouter` (global API level, not just org routes), applied after CSRF protection and before route registration.
- **Match:** YES
- **Tests:** N/A (middleware is trivial; tested implicitly by all API integration tests that check response headers)
- **Gaps:** None. The middleware is correctly placed at the global apiRouter level, which covers all authenticated endpoints.

### Task G5: testChannelHandler 502 on failure
- **Plan says:** When `resp.Success` is false, return HTTP 502 instead of 200.
- **Code does:** `internal/api/channels.go:521-527` sets `status = http.StatusBadGateway` when `testErr != nil`, then calls `writeJSON(w, status, resp)`.
- **Match:** YES
- **Tests:** PASS. Multiple tests verify this: `channel_test_notification_test.go` asserts `http.StatusBadGateway` at lines 55 and 108, and `channels_test.go:TestTestChannel_EmailNoSMTP` asserts 502 at line 1281.
- **Gaps:** None.

---

## HR Group H

### Task H1: PLAN.md import-bulk description
- **Plan says:** Change the description from "bulk import from NVD/MITRE downloads" to clarify its role as a dev/test seed corpus loader. Specific replacement text provided in plan.
- **Code does:** `PLAN.md` section 17.1 (line 1487) now reads: "The `cvert-ops import-bulk` cobra subcommand loads CVE data from local files (captured feed snapshots, golden test fixtures) into the database. Primary use cases: (1) seeding a development environment from the test fixture corpus (see Phase 10 plan), (2) offline/airgapped deployments where API access is unavailable. NOT the primary mechanism for initial production data population -- use the feed adapters' normal API sync for that." This matches the plan's specified replacement text closely.
- **Match:** YES
- **Tests:** N/A (documentation change)
- **Gaps:** Minor: The CLI subcommands list at line 1562 still says "imports a bulk data file for a given feed source (see section 17.1). Used for initial instance population; exits on completion." The "initial instance population" phrasing could be seen as contradicting the section 17.1 update that says it's NOT the primary mechanism for initial production data population. However, section 17.1 is the authoritative description and the brief mention at 1562 does reference it.

---

## P8 Batch 1

### Task 1: Generic feed cursor pagination bug
- **Plan says:** Add dependent field validation in `Validate()`: cursor type requires `cursor_param` and `cursor_path`; offset type requires `page_param`. Add tests for each case plus a positive test.
- **Code does:** `internal/feed/generic/config.go:128-141` adds a second `switch` block on `c.Pagination.Type` that validates dependent fields exactly as specified. `config_test.go` has four new tests: `TestValidateConfig_CursorPaginationMissingCursorParam` (line 221), `TestValidateConfig_CursorPaginationMissingCursorPath` (line 233), `TestValidateConfig_OffsetPaginationMissingPageParam` (line 245), and `TestValidateConfig_CursorPaginationComplete` (line 257).
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s ./internal/feed/generic/...`)
- **Gaps:** None. All four test cases from the plan are present and the validation logic matches exactly.

### Task 2: Audit logging -- groups handler
- **Plan says:** Add 5 `audit.Entry` calls to groups.go (create, update, delete, add member, remove member). Also add `metrics/audit.go` (AuditWriteFailures counter) and `.Inc()` at error sites in `audit/writer.go`. Add `TestAuditIntegration_Groups`.
- **Code does:**
  - `internal/api/groups.go` has 5 audit calls: create (line 85), update (line 231), delete (line 275), add member (line 365), remove member (line 415). All use correct EntityType ("group" or "group_member") and Action strings matching the plan. State capture includes OldState/NewState as specified.
  - `internal/metrics/audit.go` defines `AuditWriteFailures` counter with the exact metric name and help text from the plan.
  - `internal/audit/writer.go` imports metrics and calls `.Inc()` at both error sites (marshal failure line 67, insert failure line 73).
  - `TestAuditIntegration_Groups` exists at `audit_integration_test.go:633`.
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s -run TestAuditIntegration_Groups ./internal/api/...`)
- **Gaps:** None. All 5 audit calls present. Prometheus counter and writer integration implemented as specified.

### Task 3: Audit logging -- ingest handler
- **Plan says:** Add audit.Entry call after the processing loop completes. Include source_name, patch_count, accepted, rejected in NewState.
- **Code does:** `internal/api/ingest.go:165-171` has the audit call with Action "create", EntityType "ingest", and NewState map containing all four specified fields. The `Success` field is set to `resp.Accepted > 0` which is a sensible addition beyond the plan spec.
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s -run TestAuditIntegration_Ingest ./internal/api/...`)
- **Gaps:** None.

### Task 4: Skip webhook HMAC when secret empty + HR F3
- **Plan says:** Guard HMAC block on `cfg.SigningSecret != ""`. Add test for empty secret (no headers) and non-empty secret (headers present). Also improve BuildSafeClient test assertions (HR F3).
- **Code does:** `internal/notify/webhook.go:57-70` wraps the entire HMAC block in `if cfg.SigningSecret != ""`. `webhook_test.go` has:
  - `TestSend_EmptySecret_NoSignatureHeaders` (line 212): verifies no signature or timestamp headers with empty secret.
  - `TestSend_NonEmptySecret_SignatureHeadersPresent` (line 231): positive test verifying headers are present with non-empty secret.
  - `TestBuildSafeClient_BlocksPrivateIPs` (line 252): tests SSRF blocking.
  - `TestBuildSafeClient_ReturnsValidClient` (line 270): verifies timeout, redirect policy, and MaxConnsPerHost.
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s -run "TestWebhook|TestSend_EmptySecret|TestSend_NonEmptySecret|TestBuildSafeClient" ./internal/notify/...`)
- **Gaps:** None. Both the empty-secret guard and BuildSafeClient assertion improvements are in place.

### Task 5: Lockout fail-open regression test
- **Plan says:** Create a `failingLockoutStore` mock that returns errors from `GetLoginLockoutState`. Test that `Check()` returns `allowed=true` (fail-open behavior).
- **Code does:** `internal/api/lockout_test.go:227-257` has `failingLockoutStore` type (all methods return `fmt.Errorf("simulated DB failure")`) and `TestDBLockout_FailOpenOnDBError` that asserts `allowed == true` and `retryAfter == 0`. Includes the regression comment: "Regression: lockout must fail open on DB errors -- rate limiter is secondary defense."
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s -run TestDBLockout_FailOpen ./internal/api/...`)
- **Gaps:** None. Implementation matches plan spec precisely.

### Task 6: Wrap feed client in SafeURL + body limit
- **Plan says:** Create `internal/feed/client.go` with `BuildFeedClient` function. Transport composition: safeurl (inner) -> maxBodyTransport (outer). Use `limitedReadCloser` (NOT `io.NopCloser`). `cmd/cvert-ops/main.go` uses `BuildFeedClient` for both `feedClient` and `epssClient`. Default body limit 512 MB.
- **Code does:**
  - `internal/feed/client.go` has `BuildFeedClient(timeout, maxBodyBytes)` with `DefaultMaxBodyBytes = 512 << 20` (512 MiB).
  - Transport composition is correct: `safeurl.Client(cfg).Client` gets the inner client, then its transport is wrapped with `&maxBodyTransport{inner: inner.Transport, maxBytes: maxBodyBytes}`.
  - `limitedReadCloser` preserves original body's `Close` via embedded `io.Reader` (LimitReader) and `io.Closer` (original body).
  - `cmd/cvert-ops/main.go:178` and `main.go:190` both use `feed.BuildFeedClient` for `feedClient` (5min timeout) and `epssClient` (300s timeout).
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s ./internal/feed/...`). Tests include: `TestBuildFeedClient_BlocksPrivateIPs`, `TestBuildFeedClient_Timeout`, `TestBuildFeedClient_DefaultBodyLimit`, `TestBuildFeedClient_CustomBodyLimit`, `TestMaxBodyTransport_LimitsResponseBody`.
- **Gaps:** None. All plan requirements met including transport composition order, limitedReadCloser pattern, and main.go wiring.

### Task 7: Audit logging -- reports handler
- **Plan says:** Add 5 audit.Entry calls to reports.go (create, patch, delete, bind channel, unbind channel). Add `TestAuditIntegration_Reports`.
- **Code does:** `internal/api/reports.go` has 5 audit calls:
  - create (line 178): Action "create", EntityType "report"
  - update/patch (line 361): Action "update", EntityType "report", includes OldState and NewState
  - delete (line 400): Action "delete", EntityType "report", includes OldState
  - bind (line 459): Action "bind", EntityType "report_channel_binding"
  - unbind (line 493): Action "unbind", EntityType "report_channel_binding"
  - `TestAuditIntegration_Reports` exists at `audit_integration_test.go:772`.
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s -run TestAuditIntegration_Reports ./internal/api/...`)
- **Gaps:** None. All 5 operations covered with correct EntityType and Action values matching the plan.

### Task 8: Audit logging -- API keys handler
- **Plan says:** Add audit.Entry calls for create and revoke. NewState for create must NOT include raw API key value or hash. Include only: key ID, name, permissions, expiry. Add `TestAuditIntegration_APIKeys`.
- **Code does:** `internal/api/apikeys.go` has 2 audit calls:
  - create (line 149): Action "create", EntityType "api_key", NewState contains `name`, `role`, `expires_at` -- no raw key or hash. (Note: plan says "permissions" but implementation uses "role" which is the actual field name in the codebase.)
  - revoke (line 246): Action "revoke", EntityType "api_key", no NewState (correct for revoke).
  - `TestAuditIntegration_APIKeys` exists at `audit_integration_test.go:863`.
- **Match:** YES
- **Tests:** PASS (`go test -count=1 -timeout=120s -run TestAuditIntegration_APIKeys ./internal/api/...`)
- **Gaps:** None. Security-critical requirement (no raw key in audit state) is satisfied.

---

## Summary

| Task | Match | Tests | Gaps |
|------|-------|-------|------|
| G2: NullString | YES | N/A | None |
| G3: isPermanentDeliveryError | YES | PASS | Minor: no direct `*mail.SendError` test case |
| G4: Cache-Control | YES | N/A | None |
| G5: testChannel 502 | YES | PASS | None |
| H1: PLAN.md import-bulk | YES | N/A | Minor: line 1562 brief mention not updated |
| P8-1: Cursor pagination | YES | PASS | None |
| P8-2: Groups audit | YES | PASS | None |
| P8-3: Ingest audit | YES | PASS | None |
| P8-4: Webhook HMAC skip | YES | PASS | None |
| P8-5: Lockout fail-open | YES | PASS | None |
| P8-6: Feed SafeURL + body limit | YES | PASS | None |
| P8-7: Reports audit | YES | PASS | None |
| P8-8: API keys audit | YES | PASS | None |

**Overall: 13/13 tasks match plan spec. All tests pass. 2 minor gaps identified (neither is a blocker).**
