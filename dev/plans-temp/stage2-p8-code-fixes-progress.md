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
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**

## Task 4: Skip Webhook HMAC When Secret Empty + HR F3 (Combined)
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**

## Task 5: Lockout Fail-Open Regression Test (D1)
- **Status:** pending
- **Files modified:** (pending)
- **Tests:** pending
- **Commit:** pending
- **Notes:**

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
