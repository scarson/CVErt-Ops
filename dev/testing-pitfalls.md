# Testing Pitfalls

High-level test scenario checklist. Use this when reviewing test coverage for any feature — these are the categories of bugs that slip through when tests only verify the happy path.

## 1. Concurrency & TOCTOU

- [ ] **Multi-step flows under concurrent access:** If a flow reads state then writes state (check-then-act), test two goroutines racing through the same flow simultaneously. Use a barrier pattern (`ready := make(chan struct{})` + `close(ready)`) to ensure goroutines hit the critical section at the same time — `sync.WaitGroup` alone doesn't guarantee simultaneous execution.
- [ ] **Token/code consumption:** Any "use once" token (reset, verification, invitation) must be tested with two concurrent consumers. Exactly one should succeed.
- [ ] **Rate limit bypass under concurrency:** Count-then-insert rate limits can be bypassed by concurrent requests that all read the same count before any insert. Test with burst requests.
- [ ] **Bootstrap/initialization races:** First-user, first-org, or any "only if none exist" flow must be tested with concurrent attempts. Exactly one should win.
- [ ] **Idempotent operations under concurrency:** If an operation should be idempotent (e.g., accepting an invitation twice), test concurrent execution — the second attempt should not produce a 500 from a constraint violation.

## 2. Negative Property Testing

- [ ] **Cleanup and eviction:** If code accumulates state (maps, caches, queues), test that stale entries are eventually cleaned up. Don't just test "it works" — test "it doesn't leak."
- [ ] **Case sensitivity:** If a string key is used for identity (email, username), test that case variations are treated consistently. `Admin@Example.com` and `admin@example.com` should be the same identity.
- [ ] **Bounded growth:** For any in-memory data structure that grows with external input, test that it has a maximum size or eviction policy. Simulate 1000+ entries and verify memory is bounded.
- [ ] **Resource release on panic:** If a resource (semaphore, lock, file handle) is acquired, test that it's released even if the protected code panics. Prefer `defer` over explicit release.

## 3. Error Path Differentiation

- [ ] **Information leakage via error codes:** If a handler must return the same status code regardless of whether a resource exists (anti-enumeration), test that ALL error paths — including DB errors on post-lookup queries — return the same status. A 500 on a query that only runs for existing users leaks user existence.
- [ ] **Error swallowing:** If code silently returns on error (`if err != nil { return }`), test that the error is at minimum logged. Silent swallowing hides bugs.
- [ ] **Partial failure in multi-step flows:** If a flow commits step 1 (e.g., creates a user) then fails on step 2 (e.g., creates an org), test that step 1's result is still usable. The user shouldn't be in a broken state.

## 4. Validation Symmetry

- [ ] **Create vs Update/PATCH:** If a create handler validates a field (e.g., rejects empty names), the corresponding PATCH/update handler MUST apply the same validation. Test PATCH with every invalid input that create rejects.
- [ ] **Whitespace-only strings:** `""` and `"   "` are both "empty" from a business perspective. If a handler rejects empty strings, test that it also rejects whitespace-only strings. Use `strings.TrimSpace()` before checking.
- [ ] **Zero-value vs absent in PATCH:** For pointer-based optional fields (`*string`, `*bool`), test that sending an explicit zero value (empty string, false) is handled correctly — not silently ignored by `omitempty`.

## 5. Boundary & Configuration Validation

- [ ] **Dangerous config combinations:** If two config values interact (e.g., CORS wildcard + credentials), test that dangerous combinations are rejected at startup — not silently accepted.
- [ ] **Missing config for optional features:** If a feature depends on external config (SMTP host, API key), test what happens when the config is absent. The error message should name the missing config — not produce a cryptic connection failure.
- [ ] **Rate limit accounting:** If registration or another flow creates a resource (e.g., a verification token), and a rate limit counts those resources, the test must account for the implicitly-created resource. A limit of 3 with 1 implicit creation means 2 explicit attempts before the limit.

## 6. Data Lifecycle

- [ ] **Soft-delete filtering:** Every query that lists or counts resources must be tested after a soft-delete. If `deleted_at IS NULL` is missing, soft-deleted records leak into results.
- [ ] **Expired record handling:** Queries filtered by `expires_at > now()` should be tested with expired records present — verify they're excluded, and verify cleanup jobs remove them.
- [ ] **Duplicate detection:** If a resource should be unique within a scope (e.g., one pending invitation per email per org), test that creating a duplicate is rejected — not silently accepted.

## 7. Transaction & Store Conventions

- [ ] **Transaction helper compliance:** Every store method must use the appropriate transaction helper (`withOrgTx`, `withBypassTx`, `WorkerTx`). Direct `s.q` access bypasses RLS setup and will break if RLS is later added to the table. Verify with code inspection.
- [ ] **Audit trail completeness:** If similar operations (create/update/delete channel) have audit logging, verify that ALL operations in the same category (create/cancel/resend invitation) also have audit logging. Missing audit entries are hard to catch with automated tests — use code inspection.

## 8. External Dependency Failure

- [ ] **SMTP/webhook failure reporting:** If a handler sends an email or webhook, test the failure path. Does it claim success when the send failed? Does it surface the error to the user (for authenticated endpoints) or silently log it (for unauthenticated anti-enumeration endpoints)?
- [ ] **Sync vs async send implications:** If an email is sent synchronously, the handler can report failure. If async, it can't. Test that the chosen approach matches the error-reporting contract. Don't make a send async if the API promises to report delivery status.
