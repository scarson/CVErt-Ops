# Testing Pitfalls

Test scenario checklist for reviewing coverage of any feature. Every item on this list exists because it catches bugs that have occurred in real codebases. Items marked with **🔥 Found in bug hunts** were discovered in *this* codebase specifically. Unmarked items are equally important — they represent bugs we haven't made *yet*. Do not deprioritize an item because it lacks a marker.

---

## 1. Concurrency & TOCTOU

- [ ] **Multi-step flows under concurrent access:** When a flow reads state then writes state (check-then-act), test two goroutines racing through the same flow simultaneously. Use a barrier pattern (`ready := make(chan struct{})` + `close(ready)`) to ensure goroutines hit the critical section at the same time — `sync.WaitGroup` alone doesn't guarantee simultaneous execution.
- [ ] **Token/code consumption:** Any "use once" token (reset, verification, invitation) must be tested with two concurrent consumers. Exactly one must succeed. **🔥 Found in bug hunts:** password reset token consumed across separate transactions allowed concurrent resets.
- [ ] **Rate limit bypass under concurrency:** Count-then-insert rate limits can be bypassed by concurrent requests that all read the same count before any insert. Test with burst requests. **🔥 Found in bug hunts:** concurrent forgot-password requests exceeded per-user rate limit.
- [ ] **Bootstrap/initialization races:** First-user, first-org, or any "only if none exist" flow must be tested with concurrent attempts. Exactly one must win. **🔥 Found in bug hunts:** first-user bootstrap race in invite-only mode.
- [ ] **Idempotent operations under concurrency:** When an operation should be idempotent (e.g., accepting an invitation twice), test concurrent execution — the second attempt must not produce a 500 from a constraint violation. **🔥 Found in bug hunts:** concurrent invitation accept hit constraint violation.
- [ ] **Job deduplication under concurrent triggers:** When both a scheduler tick and an API trigger can enqueue the same job type, test that concurrent triggers produce exactly one running job — not two. **🔥 Found in bug hunts:** job queue TOCTOU allowed duplicate feed runs.

## 2. Negative Property Testing

- [ ] **Cleanup and eviction:** When code accumulates state (maps, caches, queues), test that stale entries are eventually cleaned up. Don't just test "it works" — test "it doesn't leak." **🔥 Found in bug hunts:** lockout map grew without bound — no eviction ever triggered.
- [ ] **Case sensitivity:** When a string key is used for identity (email, username), test that case variations are treated consistently. `Admin@Example.com` and `admin@example.com` must be the same identity. **🔥 Found in bug hunts:** login lockout bypassed via email case variation.
- [ ] **Bounded growth:** For any in-memory data structure that grows with external input, test that it has a maximum size or eviction policy. Simulate 1000+ entries and verify memory is bounded.
- [ ] **Resource release on panic:** When a resource (semaphore, lock, file handle) is acquired, test that it's released even if the protected code panics. Prefer `defer` over explicit release. **🔥 Found in bug hunts:** argon2 semaphore not released on panic.
- [ ] **Stream error recovery:** When a streaming parser (e.g., `json.Decoder`) hits a malformed record and `continue`s to the next iteration, test that subsequent valid records still parse correctly. A `continue` after a partial read can leave the decoder in a corrupted state — the next `Decode()` call reads garbage. **🔥 Found in bug hunts:** streaming JSON `continue` after error corrupted decoder state.

## 3. Error Path Differentiation

Silent error swallowing is the #1 bug category in this codebase — 26% of all bug hunt findings. Every error path must be tested explicitly.

- [ ] **Information leakage via error codes:** When a handler must return the same status code regardless of whether a resource exists (anti-enumeration), test that ALL error paths — including DB errors on post-lookup queries — return the same status. A 500 on a query that only runs for existing users leaks user existence. **🔥 Found in bug hunts:** `GetPasswordResetTokenByHash` error leaked user existence.
- [ ] **Error swallowing in Go:** When code silently returns on error (`if err != nil { return }`), test that the error is at minimum logged. Silent `return` hides bugs. **🔥 Found in bug hunts:** sync state persistence errors silently discarded; fetch log errors silently discarded; `resendVerificationHandler` claimed "sent" when SMTP failed.
- [ ] **Partial failure in multi-step flows:** When a flow commits step 1 (e.g., creates a user) then fails on step 2 (e.g., creates an org), test that step 1's result is still usable. The user must not be in a broken state. **🔥 Found in bug hunts:** orphaned tokens created when email delivery failed during registration.
- [ ] **Silent success on missing resources:** When a DELETE or cancel operation targets a non-existent resource, test that it returns 404 — not 204. A silent 204 hides bugs in the caller. **🔥 Found in bug hunts:** `cancelInvitationHandler` returned silent success on 404.
- [ ] **Error propagation across layers:** When a store method returns an error, trace it through the handler to the HTTP response. Test that the handler doesn't discard the error and return 200. Inject DB errors via test fixtures and verify the HTTP status reflects the failure.

## 4. Validation Symmetry

- [ ] **Create vs Update/PATCH:** When a create handler validates a field (e.g., rejects empty names), the corresponding PATCH/update handler MUST apply the same validation. When testing PATCH, test every invalid input that create rejects — without exception. **🔥 Found in bug hunts:** PATCH channel allowed empty/whitespace names; org create/update allowed whitespace-only names.
- [ ] **Whitespace-only strings:** `""` and `"   "` are both "empty" from a business perspective. When a handler rejects empty strings, test that it also rejects whitespace-only strings. Use `strings.TrimSpace()` before checking.
- [ ] **Zero-value vs absent in PATCH:** For pointer-based optional fields (`*string`, `*bool`), test that sending an explicit zero value (empty string, false) is handled correctly — not silently ignored by `omitempty`.
- [ ] **Falsy-value data preservation:** When mapping external data to internal structs, test that legitimate zero values (CVSS score of 0.0, empty string that means "no value" vs missing field) are preserved — not dropped by truthiness checks. **🔥 Found in bug hunts:** CVSS 0.0 scores dropped as falsy in GHSA, MSRC, and OSV adapters — this bug recurred three separate times.

## 5. Boundary & Configuration Validation

- [ ] **Dangerous config combinations:** When two config values interact (e.g., CORS wildcard + credentials), test that dangerous combinations are rejected at startup — not silently accepted.
- [ ] **Missing config for optional features:** When a feature depends on external config (SMTP host, API key), test what happens when the config is absent. The error message must name the missing config — not produce a cryptic connection failure.
- [ ] **Rate limit accounting:** When a flow implicitly creates a counted resource (e.g., registration creates a verification token), and a rate limit counts those resources, the test must account for the implicitly-created resource. A limit of 3 with 1 implicit creation means 2 explicit attempts before the limit.
- [ ] **Schema version drift:** When the application checks schema version at startup, test that the expected version constant matches the latest migration. A stale constant produces spurious warnings on every boot. **🔥 Found in bug hunts:** `expectedSchemaVersion` was stale — startup always warned.

## 6. Data Lifecycle

- [ ] **Soft-delete filtering:** Every query that lists or counts resources must be tested after a soft-delete. If `deleted_at IS NULL` is missing, soft-deleted records leak into results.
- [ ] **Expired record handling:** Queries filtered by `expires_at > now()` must be tested with expired records present — verify they're excluded, and verify cleanup jobs remove them.
- [ ] **Duplicate detection:** When a resource should be unique within a scope (e.g., one pending invitation per email per org), test that creating a duplicate is rejected — not silently accepted. **🔥 Found in bug hunts:** `createInvitationHandler` allowed duplicate pending invitations.

## 7. Transaction & Store Conventions

- [ ] **Transaction helper compliance:** Every store method must use the appropriate transaction helper (`withOrgTx`, `withBypassTx`, `WorkerTx`). Direct `s.q` or `s.db` access bypasses RLS setup. Verify with code inspection — grep for `s.db.QueryContext` and `s.db.ExecContext` in org-scoped methods. **🔥 Found in bug hunts:** `CountUsers`, `CreateUser`, `GetOrgByID`, and `UpdatePasswordHash` all bypassed transaction helpers.
- [ ] **Audit trail completeness:** When similar operations (create/update/delete channel) have audit logging, verify that ALL operations in the same category (create/cancel/resend invitation) also have audit logging. Missing audit entries are hard to catch with automated tests — use code inspection.

## 8. External Dependency Failure

- [ ] **SMTP/webhook failure reporting:** When a handler sends an email or webhook, test the failure path. Does it claim success when the send failed? Does it surface the error to the user (for authenticated endpoints) or silently log it (for unauthenticated anti-enumeration endpoints)? **🔥 Found in bug hunts:** `resendVerificationHandler` claimed "sent" when SMTP failed.
- [ ] **Sync vs async send implications:** When an email is sent synchronously, the handler can report failure. When async, it can't. Test that the chosen approach matches the error-reporting contract. Don't make a send async if the API promises to report delivery status. **🔥 Found in bug hunts:** verification email sent synchronously blocked the registration endpoint under SMTP latency.
- [ ] **No open DB transaction during external I/O:** When code makes an outbound HTTP call (webhook, feed fetch), verify that no database transaction is held open during the call. The pattern is: claim job → commit → call external service → update status in new transaction. Holding a transaction open during a slow HTTP call exhausts the connection pool.

## 9. Feed Data Quality & Cursor Lifecycle

Feed adapters process untrusted external data. Every adapter test suite must cover these scenarios — upstream feeds are inconsistent, sparse, and periodically non-spec-compliant.

- [ ] **Null byte sanitization:** Test that null bytes (`\x00`) in feed data are stripped before reaching Postgres. Postgres text columns reject null bytes — an unsanitized field causes the entire upsert to fail. Test with a fixture containing `\x00` in description, required action, or any free-text field.
- [ ] **Falsy-value preservation:** Test that CVSS 0.0, empty strings, and other legitimate zero values are persisted — not dropped by Go truthiness checks (`if score != 0`). This is the single most recurring adapter bug. **🔥 Found in bug hunts:** CVSS 0.0 dropped in GHSA, MSRC, and OSV adapters — three independent occurrences.
- [ ] **Sparse field handling:** A CVE without a CVSS score, without references, or without a description is normal — not an error. Test that the adapter and merge pipeline handle nil/missing fields gracefully without panicking or skipping the record.
- [ ] **Wire format assumptions:** Never assume the upstream response is a top-level JSON array. Test the actual envelope structure. Use `curl | jq 'keys'` on the real API before writing fixtures. **🔥 Found in implementation-pitfalls:** multiple adapters assumed wrong top-level structure.
- [ ] **Timestamp format tolerance:** External feeds use inconsistent timestamp formats. Test with RFC3339, RFC3339Nano, date-only strings, and timezone-offset variants. A parser that hard-fails on a non-standard timestamp loses the entire CVE.
- [ ] **Cursor advancement after success:** After a successful fetch-and-merge cycle, test that the cursor has advanced in the database. A feed that fetches successfully but doesn't persist its cursor will re-process the same data on every run. **🔥 Found in bug hunts:** Red Hat adapter never advanced `AfterDate` cursor; feed sync cursor not persisted after successful fetch.
- [ ] **Cursor state on final page:** Test that the cursor after processing the last page represents "caught up" — not the penultimate page's marker. **🔥 Found in bug hunts:** NVD cursor regressed on final page.
- [ ] **Crash recovery — no re-processing:** Simulate a crash mid-pagination (process N of M pages, then restart). Verify that already-processed pages are not re-merged. When an adapter fetches all pages internally before checkpointing, every crash re-processes everything. **🔥 Found in bug hunts:** GHSA fetched all pages internally with no mid-pagination checkpoint.
- [ ] **Fetch duration tracking:** Verify that fetch log entries record accurate start/end timestamps with non-zero duration. **🔥 Found in bug hunts:** `InsertFeedFetchLog` discarded `started_at` and `ended_at`.

## 10. RLS & Tenant Isolation Verification

RLS bugs are invisible in tests that use the superuser connection. Every org-scoped store method needs a test through the restricted connection.

- [ ] **Dual-connection testing:** When testing any org-scoped store method, query through `db.AppStore` (the `NOBYPASSRLS` connection) — not `db.Store` (superuser). Tests that only use the superuser connection cannot detect RLS policy bugs. **🔥 Found in implementation-pitfalls §2.14:** four broken list methods passed all tests because the superuser connection returned all rows regardless of `app.org_id`.
- [ ] **Cross-tenant visibility assertion:** For every org-scoped list/get operation, create data in Org A and Org B via the superuser connection, then query via `AppStore` scoped to Org A. Org B's data must not appear. This is the minimum viable RLS test.
- [ ] **Child table isolation:** RLS on a parent table does NOT protect child tables. When a child table has `org_id`, it must have its own RLS policy and its own cross-tenant test. When a child table lacks `org_id`, that is a schema bug — flag it.
- [ ] **Worker vs API transaction helpers:** `WorkerTx` bypasses RLS (for background jobs that need cross-tenant access). `withOrgTx` enforces it (for API handlers). Test that API handler code paths never use `WorkerTx` — grep for `WorkerTx` in `internal/api/` as a code review step. **🔥 Found in implementation-pitfalls §4.6:** worker transaction helpers called from API handlers allowed cross-tenant data access.

## 11. Security Enforcement Testing

Building a security mechanism is not enough — test that the mechanism actually fires. Every security check needs at least one test that proves rejection works.

- [ ] **RBAC matrix coverage:** For every protected endpoint, test with every role (owner, admin, member, viewer, unauthenticated). An endpoint that only tests the happy-path role doesn't prove the others are rejected. **🔥 Found in bug hunts:** admin feed endpoints lacked role-based auth — any authenticated user could trigger feed syncs.
- [ ] **JWT algorithm confusion:** Test that a JWT signed with `alg: "none"` is rejected. Test that a JWT signed with an unexpected algorithm (e.g., RS256 when the server expects HS256) is rejected. `WithValidMethods` must be present and tested.
- [ ] **Anti-enumeration timing:** When a handler must not reveal whether a resource exists (forgot-password, login), test that response times for existing and non-existing targets are statistically indistinguishable. A constant-time comparison on the secret is necessary but not sufficient — a DB query that only runs for existing users creates a timing side-channel.
- [ ] **Authorization parity across auth flows:** When a behavior exists in one auth flow (native register creates a default org), verify it exists in ALL auth flows (GitHub OAuth, Google OIDC). Maintain a checklist of "things that happen on first registration" and test each flow against it. **🔥 Found in implementation-pitfalls §8.3:** OAuth and native registration produced different post-registration states.
- [ ] **Security check enforcement across similar endpoints:** When adding a security check to one handler, grep for all handlers that perform the same kind of operation and verify they have the same check. Role assignment isn't just `updateMemberRole` — it's also invitations, OAuth account linking, and admin overrides. **🔥 Found in implementation-pitfalls §8.1.**
- [ ] **Webhook SSRF protection:** When testing webhook delivery, test with internal/private IP targets (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`). The `safeurl` client must reject them. Test with DNS rebinding (a hostname that resolves to a private IP).
- [ ] **Constant-time secret comparison:** Any comparison of secrets (API key hashes, HMAC signatures, CSRF tokens) must use `subtle.ConstantTimeCompare` or `hmac.Equal` — never `==` or `bytes.Equal`. Verify via code inspection.

## 12. Frontend State & Error Handling

Empty `catch {}` blocks and stale state on navigation are the two most common frontend bug categories. 13 frontend bugs were found in bug hunts — the majority were silent failures that rendered blank pages.

- [ ] **Error states, not blank pages:** When a network request fails, the component must render an error message — never a blank page or an empty list that looks like "no results." Test every `fetch`/`GET` call with a mocked network error and assert that an error element is visible. **🔥 Found in bug hunts:** `WatchlistDetailView` rendered blank page on network error; `GroupMembersDialog` showed "empty state" instead of error message; `fetchItems()` had no catch block.
- [ ] **Mutation error feedback:** When a POST/PUT/DELETE fails, the user must see feedback. Test every mutation call with a mocked failure and assert visible error feedback. **🔥 Found in bug hunts:** `MembersView.cancelInvitation()` silently failed; multiple dialogs swallowed mutation errors.
- [ ] **Stale data on route param change:** When a view fetches data based on a route param (e.g., `/cves/:id`), test that navigating to a different param triggers a new fetch — not a stale render of the previous data. Use Vue's `watch` on the route param or `onBeforeRouteUpdate`. **🔥 Found in bug hunts:** `CveDetailView` showed wrong CVE after param change.
- [ ] **Org switch cache invalidation:** When the user switches organizations, every org-scoped data cache must be invalidated and refetched. Test by switching orgs and asserting that list data reflects the new org — not stale data from the previous org. **🔥 Found in bug hunts:** org switch didn't refetch data — showed cross-org data.
- [ ] **Auth token refresh deduplication:** When multiple concurrent requests receive 401s, exactly one refresh request must fire — not one per failed request. Test with two parallel requests that both trigger 401, assert a single refresh call. **🔥 Found in bug hunts:** dual independent `refreshPromise` in API client and org fetch module.
- [ ] **Request body on retry:** When a middleware retries a failed request (e.g., after token refresh), test that the original request body is re-sent. A `fetch()` body is a stream — once consumed, it's gone. The retry must use a cloned or buffered body. **🔥 Found in bug hunts:** refresh middleware retry used consumed `fetch()` body.
- [ ] **Non-2xx success responses:** When an endpoint intentionally returns non-2xx status codes with valid response bodies (e.g., 503 for health checks, 207 for multi-status), test that the frontend correctly parses the response body — not just checks `resp.ok`. A `fetch` response with `ok === false` still carries a valid JSON body that must be read. **🔥 Found in bug hunts:** `AdminSystemView` doctor check used `resp.ok` to gate JSON parsing, silently discarding 503 responses — the exact case where the doctor results are most needed.

## 13. Feature Flag & Admin Column Enforcement

When a migration adds admin-managed columns (disable flags, forced-reset flags, pause states), the feature is incomplete until the enforcement code reads them. These bugs are invisible in integration tests that only exercise the admin write path.

- [ ] **Admin flag enforcement at all entry points:** When a migration adds a boolean/timestamp flag (e.g., `disabled_at`, `force_password_reset`, `paused_at`), trace every code path that the flag should gate. Login handlers, refresh handlers, scheduler loops, and manual trigger endpoints all need to check the flag — not just the middleware that runs on authenticated API calls. **🔥 Found in bug hunts:** `disabled_at` not checked in login handler (only in auth middleware); `force_password_reset` not checked anywhere; `paused_at` not checked by scheduler or manual trigger endpoint.
- [ ] **In-memory vs DB state consistency:** When both in-memory state (rate limiters, lockout managers) and DB columns exist for the same concept, test that: (1) DB state survives restarts, (2) admin "clear" operations actually affect the enforcement mechanism, (3) multi-instance deployments share state. **🔥 Found in bug hunts:** in-memory lockout manager and DB `locked_at`/`failed_login_count` columns were completely disconnected — admin "unlock" cleared DB columns the login flow never wrote.
- [ ] **Registry completeness for extensible systems:** When a system supports both built-in items and user-configured items (e.g., built-in feeds + generic YAML feeds), test that management endpoints (list, trigger, pause, resume) work for BOTH categories — not just the hardcoded built-in list. **🔥 Found in bug hunts:** admin feed list/trigger/pause/resume endpoints only accepted built-in feed names; generic feeds were invisible and unmanageable.

## 14. Background Worker & Job Lifecycle

Workers operate outside the request-response cycle with different failure modes: no caller to report errors to, no request context for scoping, and crash recovery depends on database state.

- [ ] **Claim-commit-call-update pattern:** When a worker delivers to an external service (webhook, email), verify this exact sequence: (1) claim job in DB, (2) commit the claim transaction, (3) make the external HTTP call, (4) update job status in a new transaction. Any test that mocks the external call while a DB transaction is open is testing the wrong thing.
- [ ] **Stale job recovery:** Simulate a worker crash by claiming a job and not completing it. Verify that the recovery sweep picks it up after the stale threshold and re-enqueues it.
- [ ] **Goroutine shutdown path:** Every `go func() { for { ... } }()` must have a corresponding `Stop()` method and a `done` channel. In tests, every server or worker that spawns goroutines must have `t.Cleanup(srv.Close)`. A test that passes but leaks goroutines is a test that hides bugs. **🔥 Found in implementation-pitfalls §8.5.**
- [ ] **Large corpus pagination:** When a worker processes the full CVE corpus (activation scans, batch evaluation, search index rebuilds), test that it paginates — not loads everything into memory. Mock a corpus of 10,000+ records and verify memory stays bounded.
- [ ] **Fan-out error independence:** When delivering notifications to multiple channels, test that a failure on one channel does not cancel or skip the others. The pattern is `sync.WaitGroup` with independent error recording per channel — never `errgroup` (which cancels siblings on first error).
- [ ] **Prometheus counter race safety:** When workers update Prometheus counters, test with `-race` enabled and multiple concurrent worker goroutines. Counter init and increment must be goroutine-safe. **🔥 Found in bug hunts:** scheduler Prometheus counters had data race on init.
- [ ] **Scheduler respects pause/disable flags:** When a scheduler checks whether to enqueue a job, test that it reads and respects all relevant state flags (paused, disabled, suspended) — not just timing-based checks (interval, backoff). **🔥 Found in bug hunts:** feed scheduler checked backoff and interval but ignored `paused_at` flag entirely.
