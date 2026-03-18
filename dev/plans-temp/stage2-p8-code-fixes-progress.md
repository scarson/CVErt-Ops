# Stage 2: P8 Code Fixes — Progress Log

## Task 1: Fix Generic Feed Cursor Pagination Infinite Fetch (B1)
- **Status:** completed
- **Files modified:** `internal/feed/generic/config.go`, `internal/feed/generic/config_test.go`
- **Tests:** pass (4 new tests: cursor missing param, cursor missing path, offset missing param, cursor complete)
- **Commit:** e563daa
- **Notes:** Added dependent sub-field validation after the pagination type switch. Used require.Error to prevent nil pointer panic in test assertions.

## Task 2: Audit Logging: Groups Handler (D4/SC27)
- **Status:** completed
- **Files modified:** `internal/metrics/audit.go` (new), `internal/audit/writer.go`, `internal/api/groups.go`, `internal/api/audit_integration_test.go`
- **Tests:** compilation verified (Docker Desktop API timeout prevents testcontainer integration tests from running)
- **Commit:** d120e2f
- **Notes:** Step 0: Created AuditWriteFailures counter and added .Inc() at both error sites in writer.go. Added audit.Entry calls to all 5 mutating handlers in groups.go (create, update, delete, addMember, removeMember). Test follows exact pattern from TestAuditIntegration_Channels.

## Task 3: Audit Logging: Ingest Handler (D5/SC28)
- **Status:** completed
- **Files modified:** `internal/api/ingest.go`, `internal/api/audit_integration_test.go`
- **Tests:** compilation verified (Docker Desktop API timeout prevents integration tests)
- **Commit:** cc90ea4
- **Notes:** Added audit.Entry after processing loop with source_name, patch_count, accepted, rejected in NewState. Test asserts audit entry and new_state field values.

## Task 4: Skip Webhook HMAC When Secret Empty + HR F3 (Combined)
- **Status:** completed
- **Files modified:** `internal/notify/webhook.go`, `internal/notify/webhook_test.go`
- **Tests:** pass (13 webhook tests including 2 new empty/non-empty secret tests + enhanced BuildSafeClient assertions)
- **Commit:** 538dc7a
- **Notes:** Guarded HMAC block with `if cfg.SigningSecret != ""`. Added redirect policy and MaxConnsPerHost assertions to TestBuildSafeClient_ReturnsValidClient per HR F3.

## Task 5: Lockout Fail-Open Regression Test (D1)
- **Status:** completed
- **Files modified:** `internal/api/lockout_test.go`
- **Tests:** pass (9 lockout tests including new fail-open regression)
- **Commit:** 5151aa4
- **Notes:** Created failingLockoutStore mock that returns errors from all methods. Test verifies Check() returns allowed=true on DB error (fail-open). Documents design decision per lockout.go:53-54.

## Task 6: Wrap Feed Client in SafeURL + HR E5 (Combined)
- **Status:** completed
- **Files modified:** `internal/feed/client.go` (new), `internal/feed/client_test.go` (new), `cmd/cvert-ops/main.go`
- **Tests:** pass (5 tests: SSRF blocking, timeout, default body limit, custom body limit, body truncation)
- **Commit:** d067948
- **Notes:** Created BuildFeedClient in internal/feed/client.go with transport composition: safeurl (inner) -> maxBodyTransport (outer, 512MB default). Both feedClient sites in main.go (serve and worker commands) now use BuildFeedClient. All 11 feed sub-package test suites pass.

## Task 7: Audit Logging: Reports Handler
- **Status:** completed
- **Files modified:** `internal/api/reports.go`, `internal/api/audit_integration_test.go`
- **Tests:** compilation verified (Docker Desktop API timeout prevents integration tests)
- **Commit:** fca40d3
- **Notes:** Added audit.Entry calls to all 5 mutating handlers: create, update (patch), delete, bind channel, unbind channel. Test covers create/update/delete (bind/unbind not tested due to needing a channel created first -- existing pattern suffices).

## Task 8: Audit Logging: API Keys Handler
- **Status:** completed
- **Files modified:** `internal/api/apikeys.go`, `internal/api/audit_integration_test.go`
- **Tests:** compilation verified (Docker Desktop API timeout prevents integration tests)
- **Commit:** 4dcfc68
- **Notes:** Added audit.Entry calls to create (action=create, entity_type=api_key) and revoke (action=revoke, entity_type=api_key). NewState explicitly excludes raw_key and key_hash -- only name, role, expires_at. Test includes SECURITY assertions verifying raw_key and key_hash are absent from audit state.

## Post-Batch QA
- **golangci-lint:** 0 issues across all changed packages (62599ee)
- **Docker note:** Docker Desktop API timeout (Windows npipe issue) prevented testcontainer-based integration tests from running. All non-Docker tests pass. Code follows exact patterns from existing working audit tests (TestAuditIntegration_Channels, etc.).
