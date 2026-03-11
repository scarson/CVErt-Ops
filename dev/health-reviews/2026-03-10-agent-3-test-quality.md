# Agent 3: Test Quality
**Date:** 2026-03-10
**Scope:** Full review

---

### [MAJOR] Ingest handler tests verify mock behavior, not real merge logic

**Evidence:** `internal/ingest/handler_test.go` lines 22-68 use `mockMerge` to record calls. All assertions verify mock call counts and arguments, never that data is correctly persisted.

**Problem:** The integration between handler, real adapters, and real merge pipeline is untested end-to-end. A bug in how the handler transforms patches or handles partial failures during merge would not be caught.

**Risk:** Data-flow bugs from adapter response through merge to database could ship undetected.

**Suggested approach:** Add at least one integration test that uses a real merge function and real DB, verifying data persistence end-to-end.

---

### [MAJOR] No feed adapter tests with real upstream response shapes (golden files)

**Evidence:** All adapter tests use `httptest.NewServer` with handcrafted JSON. No golden-file tests with captured real responses.

**Problem:** Hand-maintained fixtures may drift from actual upstream API response formats. If NVD changes their JSON schema, the adapter silently produces wrong patches and tests still pass.

**Risk:** Feed ingestion silently producing empty or malformed patches after upstream API changes, with no test breakage.

**Suggested approach:** Capture real responses from each feed API and add golden-file parse tests that verify the adapter produces expected `CanonicalPatch` output.

---

### [MAJOR] Email notification tests skip when SMTP unavailable — security-critical header injection test is effectively unrun

**Evidence:** `internal/notify/email_test.go:25-27` skips if Mailpit not running. The header injection test (line 70-81) is security-critical but will skip in any CI without Mailpit.

**Problem:** The project already uses testcontainers for Postgres — the same pattern should apply to SMTP. The `TestEmailSend_SubjectHeaderInjection` test never verifies the injection was actually stripped, even when Mailpit is available.

**Risk:** A regression in email header injection protection goes undetected in CI.

**Suggested approach:** Use an Inbucket testcontainer (already added per recent commit `f253dc2`). Update the injection test to query the SMTP server and verify the `Bcc` header was stripped.

---

### [MINOR] Advisory lock test does not actually verify lock acquisition

**Evidence:** `internal/merge/pipeline_integration_test.go:546-583` — test comment admits the limitation. Only checks that `CVEAdvisoryKey` is deterministic, not that the lock was acquired.

**Problem:** Misleading test name gives false confidence. If lock acquisition code were removed, this test still passes.

**Risk:** Regression in advisory locking would not be caught by this named test.

---

### [MINOR] Several store tests silently discard setup errors

**Evidence:** Pattern across `internal/store/store_test.go` — `org1, _ := s.CreateOrg(ctx, ...)`, `user1, _ := s.CreateUser(ctx, ...)`.

**Problem:** If setup fails (migration issue, constraint violation), tests proceed with zero-value UUIDs and produce confusing assertion failures.

**Risk:** Root cause of infrastructure failures is obscured.

---

### [MINOR] `TestExecuteDSLQuery_EmptyConditions` has no assertion — cannot fail

**Evidence:** `internal/store/dsl_executor_test.go:132-148` — logs both outcomes, never asserts.

**Problem:** Both success and failure are logged with `t.Log`. Test always passes.

**Risk:** Behavior change on empty conditions is never caught.

---

### [MINOR] `DownloadToTemp_SizeLimit` test mutates package-level state

**Evidence:** `internal/feed/util_test.go:326-346` — modifies package-level `MaxDownloadSize`, not safe with parallel tests.

**Problem:** Race window if other tests call `DownloadToTemp` concurrently.

**Risk:** Intermittent CI failures; blocks safe parallelization of the feed package tests.
