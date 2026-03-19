# Stage 4: Mixed Coverage Progress

## Status: In Progress

### Step 1: HR F1 — Fix discarded test errors
- **Status:** Complete
- **Description:** Fixed 384+ discarded store method errors across 27 test files
- **Approach:** Created `MustCreateOrg`, `MustCreateUser`, `MustCreateGroup`, `MustGetCVE` helpers on `testutil.TestDB` for the 3 most common patterns (333 occurrences), then fixed remaining 51 manually with inline error checks
- **Files modified:** `internal/testutil/must.go` (new), 27 `*_test.go` files across store, api, notify, merge, retention, cmd packages
