# Agent 3: Test Quality
**Date:** 2026-03-18 03:08
**Scope:** Full review

Packages reviewed: store, auth, feed, alert, api, merge, notify, testutil. Read 25+ test files across 8 packages.

---

### [MAJOR] No feed adapter integration tests verifying parse-to-store pipeline

**Evidence:** `internal/feed/nvd/adapter_test.go`, `internal/feed/ghsa/adapter_test.go`, `internal/feed/kev/adapter_test.go`, and all other adapter test files test only pure parsing/conversion functions using httptest servers with canned responses. No test verifies the full path: adapter.Fetch() -> CanonicalPatch -> merge.Ingest() -> database.
**Problem:** The adapter tests validate that JSON is parsed correctly into CanonicalPatch structs, but never verify that those patches produce correct database state when passed through the merge pipeline. The merge pipeline integration tests (`pipeline_integration_test.go`) construct CanonicalPatch structs manually, so any field mapping mistake in an adapter (e.g., wrong field name, missing pointer dereference, incorrect type conversion) would be invisible to both test suites.
**Risk:** A feed adapter could produce a structurally valid CanonicalPatch with incorrect field mappings (e.g., swapping CVSSv3 and CVSSv4 vectors, losing CWE IDs during conversion) and no test would catch it. This is the most critical gap for a vulnerability intelligence product.

### [MAJOR] TestOrgTx_CommitsOnSuccess does not verify commit persistence

**Evidence:** `internal/store/store_test.go:80-98` - `TestOrgTx_CommitsOnSuccess`
**Problem:** The test opens an OrgTx, executes `SELECT 1` inside it, and asserts no error. It never verifies that a real write inside the transaction was actually persisted after the function returns. The comment says "Insert a row within OrgTx -- it should persist after commit" but the code only runs a SELECT.
**Risk:** The OrgTx commit path could silently swallow commits (e.g., calling Rollback instead of Commit) and this test would still pass. The `TestOrgTx_RollsBackOnError` test properly verifies rollback by checking that rows were NOT persisted, but the commit test lacks the symmetric verification.

### [MAJOR] Alert evaluator tests rely on raw SQL seeding that bypasses merge pipeline

**Evidence:** `internal/alert/evaluator_test.go:67-104` - `createTestOrg` and `insertCVE` helpers insert directly via `db.ExecContext` with raw SQL, bypassing the store layer and merge pipeline.
**Problem:** The evaluator integration tests seed CVE data by inserting directly into the `cves` table via raw SQL. This bypasses the merge pipeline material_hash computation, FTS index update, and child table population. The tests manually provide material_hash values as simple strings like `"hash-batch-1"`. If the evaluator SQL queries evolve to join against child tables (e.g., cve_affected_packages for watchlist matching) or rely on FTS index presence, these tests would still pass with their manually seeded data while production would fail.
**Risk:** The evaluator could have bugs in queries that join against child tables or depend on data that only the merge pipeline produces, and these tests would not catch them.

### [MAJOR] No tests for API key timing-attack resistance

**Evidence:** `internal/auth/apikey_test.go` - tests cover generation, hashing, and uniqueness only. `internal/api/middleware_auth_test.go:154-228` - tests API key auth with valid/invalid keys.
**Problem:** The CLAUDE.md specifies "API key comparison: `subtle.ConstantTimeCompare` -- never `==` or `bytes.Equal`". No test verifies that the comparison is constant-time. The middleware tests only check that valid keys return 200 and invalid keys return 401. A regression from `subtle.ConstantTimeCompare` to `==` would pass all existing tests.
**Risk:** A timing side-channel attack on API key validation could allow key extraction. This is documented as a critical security requirement but has no test enforcement.

### [MAJOR] Webhook test bypasses safeurl entirely for functional tests

**Evidence:** `internal/notify/webhook_test.go:23-31` - `buildTestClient()` and `internal/notify/worker_test.go:23-29` - `plainHTTPClient()` both construct plain `http.Client` instances that bypass safeurl.
**Problem:** All webhook delivery tests use a plain http.Client because safeurl blocks 127.0.0.1 (httptest servers). This means the full delivery path -- from delivery row claim through webhook POST -- is never tested with the production safeurl client. The only safeurl test (`TestBuildSafeClient_BlocksPrivateIPs`) verifies that the safeurl client blocks private IPs but does not test a successful delivery through it.
**Risk:** Bugs in safeurl integration (e.g., incorrect configuration, wrong timeout, missing redirect policy on the real client) would not be caught. The production code path uses a different HTTP client than all tests exercise.

### [MINOR] RuleCache test uses nil compiled rule, not a real one

**Evidence:** `internal/alert/evaluator_test.go:37` - `cache.Set(ruleID, 1, nil)`
**Problem:** The cache test stores nil as the compiled rule value. This tests the cache key/version mechanics but not whether a real compiled rule survives storage and retrieval.
**Risk:** Low -- the cache currently stores pointers directly in a map. But the test gives false confidence about cache ability to store and retrieve real compiled rules.

### [MINOR] TestHashPasswordOWASPParameters is brittle -- coupled to exact parameter string

**Evidence:** `internal/auth/hash_test.go:62-74`
**Problem:** The test asserts that the hash output contains the exact string `$argon2id$v=19$m=19456,t=2,p=1$`. If OWASP recommendations change and the parameters are updated, this test fails even though the security posture improved.
**Risk:** Minor -- updating parameters is intentional and the test failure would be expected. But the test name suggests it is verifying OWASP compliance, not pinning exact values.

### [MINOR] TestSend_DeniedHeaderStripped ignores Send() return value

**Evidence:** `internal/notify/webhook_test.go:89` - `_ = notify.Send(...)`
**Problem:** The test discards the error from `notify.Send()`. If Send fails, the test would still pass because the `assert.Equal` calls compare against zero-value strings, potentially masking the real failure mode.
**Risk:** If the test httptest server fails to start or respond, the test passes vacuously rather than reporting the infrastructure failure.

### [MINOR] No concurrency tests for RuleCache

**Evidence:** `internal/alert/evaluator_test.go:27-52` - `TestRuleCache_GetSetEvict` runs single-threaded only.
**Problem:** The RuleCache is used from concurrent goroutines (evaluator runs in worker pool), but no test exercises concurrent Get/Set/Evict operations to verify thread safety.
**Risk:** A concurrency bug in the cache (data race, lost updates, panics) would only surface under production load.

### [MINOR] TestIngest_AdvisoryLockAcquired does not actually verify lock acquisition

**Evidence:** `internal/merge/pipeline_integration_test.go:546-583`
**Problem:** The test simply calls Ingest and verifies the CVE was written. It adds no verification beyond what other Ingest tests already provide. The concurrent write test (`TestIngest_ConcurrentWriteSerializesCorrectly`) is the real verification of locking behavior.
**Risk:** The advisory lock could be removed from Ingest and this test would still pass.

### [MINOR] Several store test helpers silently discard errors from CreateOrg/CreateUser

**Evidence:** Pattern across multiple files, e.g., `internal/store/alert_rule_test.go:39` - `org, _ := s.CreateOrg(ctx, "AROrg1")`, `internal/notify/dispatcher_test.go:32` - `org, _ := s.CreateOrg(ctx, "FanoutNoChOrg")`
**Problem:** Many test setup calls discard the error from CreateOrg and CreateUser using `_ =`. If the test database is in an unexpected state, these calls would silently fail with a nil org/user, and the actual test would fail with an unhelpful nil pointer dereference.
**Risk:** When tests fail due to infrastructure issues, the root cause is obscured by nil pointer panics deep in test logic.

### [MINOR] TestBuildSafeClient_ReturnsValidClient only checks timeout

**Evidence:** `internal/notify/webhook_test.go:230-235`
**Problem:** The test verifies that `BuildSafeClient` returns a non-nil client with a 10-second timeout. It does not verify that the client has redirect following disabled or that `MaxConnsPerHost` is set to 50, both of which are documented requirements.
**Risk:** The redirect and connection pool settings could be removed from `BuildSafeClient` without test failure.

### [MINOR] No test for EPSS adapter two-statement pattern

**Evidence:** `internal/feed/epss/adapter_test.go` exists but does not verify both Statement 1 (update existing CVE) and Statement 2 (insert to epss_staging for non-existent CVE).
**Problem:** The EPSS adapter has a critical two-statement write pattern: one statement updates `cves.epss_score` if the CVE exists, the other inserts into `epss_staging` if it does not. These must be tested as an integrated unit with a real database.
**Risk:** If the EPSS adapter incorrectly handles the case where a CVE does not exist yet, EPSS scores for newly published CVEs would be silently lost.

### [MINOR] No negative test for pending token accepted as access token

**Evidence:** `internal/auth/jwt_test.go` and `internal/api/middleware_auth_test.go`
**Problem:** No test verifies that a pending token (which has a different typ claim) is rejected when presented as an access token, or vice versa. The middleware tests use only access tokens.
**Risk:** If `ParseAccessToken` does not check the token type, a pending MFA token could be used to authenticate as a fully-authenticated user, bypassing MFA entirely.
