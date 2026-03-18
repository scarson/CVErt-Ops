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
- **Commit:** pending
- **Notes:** Step 0: Created AuditWriteFailures counter and added .Inc() at both error sites in writer.go. Added audit.Entry calls to all 5 mutating handlers in groups.go (create, update, delete, addMember, removeMember). Test follows exact pattern from TestAuditIntegration_Channels.

## Task 3: Audit Logging: Ingest Handler (D5/SC28)
- **Status:** completed
- **Files modified:** `internal/api/ingest.go`, `internal/api/audit_integration_test.go`
- **Tests:** compilation verified (Docker Desktop API timeout prevents integration tests)
- **Commit:** pending
- **Notes:** Added audit.Entry after processing loop with source_name, patch_count, accepted, rejected in NewState. Test asserts audit entry and new_state field values.

## Task 4: Skip Webhook HMAC When Secret Empty + HR F3 (Combined)
- **Status:** completed
- **Files modified:** `internal/notify/webhook.go`, `internal/notify/webhook_test.go`
- **Tests:** pass (13 webhook tests including 2 new empty/non-empty secret tests + enhanced BuildSafeClient assertions)
- **Commit:** pending
- **Notes:** Guarded HMAC block with `if cfg.SigningSecret != ""`. Added redirect policy and MaxConnsPerHost assertions to TestBuildSafeClient_ReturnsValidClient per HR F3.

## Task 5: Lockout Fail-Open Regression Test (D1)
- **Status:** completed
- **Files modified:** `internal/api/lockout_test.go`
- **Tests:** pass (9 lockout tests including new fail-open regression)
- **Commit:** pending
- **Notes:** Created failingLockoutStore mock that returns errors from all methods. Test verifies Check() returns allowed=true on DB error (fail-open). Documents design decision per lockout.go:53-54.

## Task 6: Wrap Feed Client in SafeURL + HR E5 (Combined)
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**

## Task 7: Audit Logging: Reports Handler
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**

## Task 8: Audit Logging: API Keys Handler
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**
