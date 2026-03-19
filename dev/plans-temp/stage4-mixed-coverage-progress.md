# Stage 4: Mixed Coverage Progress

## Status: In Progress

### Step 1: HR F1 — Fix discarded test errors
- **Status:** Complete
- **Description:** Fixed 384+ discarded store method errors across 27 test files
- **Approach:** Created `MustCreateOrg`, `MustCreateUser`, `MustCreateGroup`, `MustGetCVE` helpers on `testutil.TestDB` for the 3 most common patterns (333 occurrences), then fixed remaining 51 manually with inline error checks
- **Files modified:** `internal/testutil/must.go` (new), 27 `*_test.go` files across store, api, notify, merge, retention, cmd packages

### Step 2: P8 Task 9 — Admin config secret redaction test
- **Status:** Complete
- **Description:** Added tests for `adminConfigHandler` secret redaction and `redactSecret` function
- **Tests:** 4 tests: secrets redacted to "***", empty secrets stay empty, non-admin gets 403, unit test for redactSecret
- **Files:** `internal/api/admin_system_test.go` (new)

### Step 3: P8 Task 10 — Admin user management tests
- **Status:** Complete
- **Description:** Added tests for all 5 admin user handlers
- **Tests:** 7 tests: list pagination, disable success, self-disable prevention, enable after disable, reset-password, site admin auth enforcement (all 5 endpoints)
- **Files:** `internal/api/admin_users_test.go` (new)

### Step 4: P8 Task 11 — Admin audit log + deliveries tests
- **Status:** Complete
- **Description:** Added tests for admin audit log and deliveries list endpoints
- **Tests:** 5 tests: audit log list, filter by entity_type, auth enforcement, deliveries list, deliveries auth enforcement
- **Files:** `internal/api/admin_system_test.go` (appended)
