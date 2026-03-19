# Section 5: Notification & Alert Evaluation

**Reader context:** "I'm working on alerts, delivery, or webhooks"

---

### NOTIFY-1 New-Rule Activation Scan Sends Outbound Notifications for Historical Data

**The Flaw:** Section 10.3 specified that the new-rule activation scan "fires alerts for existing matches" so users don't miss CVEs that existed before the rule was created.

**Why It Matters:** A moderately broad rule (`cvss_v3_score >= 9.0 AND affected.ecosystem = "npm"`) could match 5,000+ historical CVEs in the corpus. Firing outbound notifications for all of them would:
- Trigger immediate permanent API bans from Slack (which enforces a 1 msg/sec webhook rate limit)
- Suspend the account from email providers (SendGrid, SES, Postmark) for spam-like behavior
- Flood the user's inbox or channel with thousands of notifications for CVEs that may be years old

**The Fix:** The activation scan runs in **silent mode**. It writes matching CVEs to the `alert_events` table (establishing the dedup baseline, making historical matches visible in the UI history API) but does NOT enqueue outbound notification deliveries. External notifications only fire for new data changes that occur after the rule was created.

**The Lesson:** Historical backfill and live alerting have fundamentally different semantics. Any system that sends external notifications for historical data risks violating third-party API rate limits and flooding users. "Populate the dedup table" and "send a notification" must be decoupled. Silent writes to the dedup table serve both purposes: they prevent future duplicate alerts AND make history visible in the UI — without triggering external delivery.

---

### NOTIFY-2 EPSS Blind Zones from Threshold-Gated Material Hash Inclusion (Multi-Round Iteration)

**The Flaw (4 iterations):** The initial design included `epss_score` in `material_hash`. To avoid daily hash churn from minor score fluctuations, a ±threshold dedup gate was added. The "documented limitation" was accepted as a tradeoff.

**Why It Matters:** Any threshold gate creates a "blind zone" where a user-defined threshold can be crossed silently:
- Rule: `epss_score > 0.90`
- Score drifts: 0.85 → 0.94 (delta 0.09, below any reasonable ±0.1 gate)
- Hash doesn't change → alert never fires → user never learns their CVE crossed their explicit threshold

For a security alerting product, a user-defined threshold must be honored exactly. The ±0.1 "documented limitation" is not an acceptable tradeoff — it is a correctness failure. The fact that this went through four rounds of iterative "fixes" before being correctly resolved illustrates that incremental patches to a flawed approach rarely fix the underlying problem.

**The Fix:** Remove `epss_score` from `material_hash` entirely. Track EPSS updates separately via `date_epss_updated` (timestamptz, set only when the score actually changes — see DB-1). A dedicated daily EPSS rule evaluator uses `date_epss_updated > last_cursor` to find CVEs with new data and evaluates only rules containing `epss_score` conditions.

**The Lesson:** "Document the limitation" is not an acceptable resolution for a correctness failure in a security alerting system. When multiple iterations of a fix still have a fundamental blind zone, abandon the approach and redesign — don't patch the latest iteration. The correct fix here was to separate EPSS tracking from the `material_hash` mechanism entirely.

---

### NOTIFY-3 Activation Scan Executed Synchronously in HTTP Handler

**The Flaw:** Section 10.3 said the activation scan is "enqueued as a job" but never specified the HTTP handler behavior: what status code to return, whether the rule has an `activating` state, or that the handler must return before the scan completes.

**Why It Matters:** "Enqueued as a job" is ambiguous. An AI implementing `POST /api/v1/orgs/{org_id}/alert-rules` would plausibly interpret this as: save the rule, run the scan inline, return 201 Created after the scan completes — because that's the simplest implementation that satisfies "the scan runs when a rule is saved." A full-corpus DSL evaluation against 250,000+ CVEs takes multiple seconds to minutes of CPU time. Synchronous execution means:
- The HTTP request hangs past any standard load balancer timeout (30–60 seconds), dropping the connection
- Multiple concurrent rule creations consume unbounded API server goroutines and memory
- An attacker can trivially DOS the application by repeatedly `POST`ing alert rules to trigger expensive synchronous scans

**The Fix:** The HTTP handler must:
1. Insert the rule with `status = 'activating'`
2. Enqueue the scan as a background job with `lock_key = 'alert_activation:<rule_id>'`
3. Return `202 Accepted` (or `201 Created` with `status: "activating"`) **immediately**

The worker runs the scan asynchronously using `workerTx`, writes to `alert_events`, and transitions the rule to `status = 'active'`. The `alert_rules.status` field has valid values: `draft` | `activating` | `active` | `error` | `disabled`.

**The Lesson:** "Enqueued as a job" in a PRD is ambiguous about the HTTP response behavior. Any spec that mandates background work must also explicitly state: what HTTP status the handler returns, what intermediate state the resource has during processing, and how the client polls for completion. Without these, the "obvious" implementation is synchronous.

---

### NOTIFY-4 Dry-Run Commits to `alert_events` — Permanent Dedup Baseline Corruption

**The Flaw:** The dry-run endpoint was specified to "run the rule without firing alerts" but the implementation detail — must not persist to `alert_events` — was not stated.

**Why It Matters:** If the dry-run evaluation path reuses the standard alert evaluation function without modification, it will INSERT matching CVEs into `alert_events` (the dedup table). When the real batch evaluator runs later, it sees those CVEs as "already alerted" and silently suppresses them permanently. The user's dry-run poisons their own alert baseline for every CVE the dry-run matched. Alerts are silently missing; the user has no idea why.

**The Fix:** The dry-run handler must execute the full evaluation pipeline inside a transaction that unconditionally calls `ROLLBACK` at the end (never `COMMIT`), OR use a read-only evaluation code path that returns matched CVEs directly without touching `alert_events` at all.

**The Lesson:** "Without firing alerts" must be translated into an explicit implementation contract: no `alert_events` inserts, no notification fan-out, reads only. Any reuse of the standard evaluation path requires deliberate modification (explicit read-only flag, or transaction rollback) — the default behavior is to persist, not to skip persistence.

---

### NOTIFY-5 Zombie "Activating" Rules After Worker Crash

**The Flaw:** The activation scan was correctly moved to a background worker, but no recovery mechanism was specified for when the worker dies mid-scan.

**Why It Matters:** In containerized environments, workers are subject to OOM-kills, crashes, and routine deployment restarts. If the worker dies while processing an activation scan, the rule remains permanently in `status = 'activating'` — it never fires alerts, users cannot tell if it's broken or still running, and there's no recovery path without direct DB intervention.

**The Fix:** A periodic sweeper goroutine (runs every 5 minutes) identifies `job_queue` rows where `queue = 'alert_activation'`, `status = 'running'`, and `locked_at < now() - interval '15 minutes'`. For each zombie, it transitions the alert rule to `status = 'error'` and re-enqueues the activation scan job. Users can retry by PATCHing the rule.

**The Lesson:** Any background state machine needs a recovery path for crash-in-progress scenarios. `status = 'activating'` is a transient state that must have a reachable next state even if the worker responsible never completes. Design state machines with explicit timeout/recovery transitions, not just happy-path transitions.

---

### NOTIFY-6 Activation Scan OOM from Naive Full-Corpus Load

**The Flaw:** The activation scan was specified as "evaluate against the historical corpus" without prescribing how to read the data.

**Why It Matters:** `SELECT * FROM cves` or loading CVEs into a `[]CVE` slice allocates memory for 250,000+ records simultaneously. On constrained containers (homelab Raspberry Pi, default Docker resource limits), this OOM-kills the worker, crashes the scan, and leaves the rule in a zombie state (see NOTIFY-5). Even without OOM, the query holds a large result set in the DB connection buffer.

**The Fix:** Activation scans must use keyset pagination in 1,000-row batches: `WHERE cve_id > $last_id AND status != 'rejected' ORDER BY cve_id ASC LIMIT 1000`. Per-iteration memory is bounded regardless of corpus size.

**The Lesson:** Any worker that processes the full CVE corpus must paginate — not load. This applies to: activation scans, batch alert evaluation, search index rebuilds, and retention cleanup. Assume corpus size is unbounded; design accordingly.

---

### NOTIFY-7 Deleted Notification Channel Silently Breaks Active Alert Rules

**The Flaw:** The `DELETE /channels/{id}` endpoint was not specified to check for active alert rule dependencies before proceeding.

**Why It Matters:** If a user deletes a Slack channel that an active alert rule routes to, the alert rule continues to fire internally, attempts delivery to the deleted channel UUID, permanently fails in the dead-letter queue, and silently stops alerting — with no error surfaced to the user. The user assumes they're still receiving alerts.

**The Fix:** `DELETE /channels/{id}` must check whether any active alert rules (`status NOT IN ('draft', 'disabled')`) reference this channel. If found, return `409 Conflict` with the conflicting rule IDs and names. Users must reassign rules before the channel can be deleted.

**The Lesson:** Resource deletion in a system with referential relationships requires application-level pre-flight checks when cascading is the wrong behavior and silent failure is worse. `ON DELETE CASCADE` (deletes the rules) and `ON DELETE RESTRICT` (foreign key error) are both wrong here — the user needs a clear error message explaining what depends on the channel.

---

### NOTIFY-8 Webhook Tarpitting Freezes Delivery Worker Pool

**The Flaw:** No explicit HTTP client timeout was specified for outbound webhook delivery.

**Why It Matters:** A "tarpit" server accepts TCP connections but trickles the response at 1 byte per minute. Go's default `http.Client` has no timeout — it waits indefinitely. With a per-org concurrency cap of 5, just 5 tarpit webhooks permanently freeze all outbound delivery for that org and consume worker goroutines globally. Legitimate alerts for other orgs are unaffected only because of the per-org cap; but the affected org's alerts are permanently backlogged.

**The Fix:** The webhook HTTP client must be configured with `Timeout: 10 * time.Second`. The per-request context must also carry a `context.WithTimeout(ctx, 10*time.Second)`. Both are required: the client timeout covers transport-level hangs; the context timeout covers application-level slow responses.

**The Lesson:** Never use an `http.Client` without a `Timeout` for any external call. "The endpoint is controlled by the user" is not a sufficient reason to omit timeouts — that endpoint may be misconfigured, slow, or deliberately hostile.

---

### NOTIFY-9 Database Connection Pool Starvation from Webhook HTTP Hold

**The Flaw:** The initial webhook delivery design held an open database transaction during the outbound HTTP call.

**Why It Matters:** A standard naive pattern: `BEGIN → claim job → make HTTP webhook call (up to 10s) → update status → COMMIT`. With 20 concurrent webhook deliveries each waiting 10 seconds for a response, 20 database connections are held idle for 10+ seconds. A small Postgres pool (default 25 connections) is nearly exhausted. The primary HTTP API starves: user requests that need a DB connection queue behind the webhook deliveries.

**The Fix:** Split the delivery into three phases, releasing the connection between the expensive I/O:
1. `BEGIN` → claim job, mark `status = 'processing'` → `COMMIT` (release connection)
2. Execute outbound HTTP call (no DB connection held)
3. `BEGIN` → update final `status`, increment `attempt_count` → `COMMIT`

**The Lesson:** Long-running external I/O (HTTP calls, file writes, external service polling) must never hold open database connections. Commit early to release connections, then reacquire after the I/O completes. This pattern applies anywhere the gap between DB operations is filled with slow external work.

---

### NOTIFY-10 Rejected/Withdrawn CVE False Alert Storm

**The Flaw:** The alert evaluation engine evaluated all CVEs without filtering by status, including rejected ones.

**Why It Matters:** When NVD or MITRE rejects a CVE, they update its description to `** REJECT **...` and strip CVSS scores — this triggers a `material_hash` change. Alert rules that previously matched the CVE re-fire, paging security analysts for a CVE that no longer exists as a real vulnerability. Repeated false pages cause immediate alert fatigue and product abandonment.

**The Fix:** All alert evaluation passes (realtime, batch, EPSS-specific, activation scan) must add `AND cves.status != 'rejected'` to their queries. Status `withdrawn` (where applicable per feed) must also be excluded.

**The Lesson:** Alert evaluation must be status-aware. Not all CVE record updates represent genuine new threat intelligence; a status change to `rejected` is the opposite. Any alert system that fires on every `material_hash` change without checking status will spam analysts with rejections.

---

### NOTIFY-11 Webhook Fan-Out Exhausts OS Ephemeral Ports

**The Flaw:** No `MaxConnsPerHost` constraint was specified on the `http.Transport` underlying the webhook delivery client.

**Why It Matters:** During a high-impact vulnerability event (e.g., Log4Shell), every org with matching alert rules fires notifications simultaneously. If 400 orgs each have 5 webhook channels pointing to `hooks.slack.com`, the notification worker attempts ~2,000 simultaneous TCP connections to the same host. Each consumes one OS ephemeral port (Linux range: ~32k–60k). Exhausting the range produces `connect: cannot assign requested address` errors — all webhook delivery silently fails for the duration of the event, with no obvious error in application-level logs. The failure looks like network problems, not a resource exhaustion issue.

**The Fix:** Set `MaxConnsPerHost` on the transport backing the webhook HTTP client:
```go
transport := &http.Transport{
    MaxConnsPerHost: 50, // cap connections to any single webhook host
}
```
`MaxConnsPerHost: 50` means at most 50 simultaneous TCP connections to `hooks.slack.com` (or any other single host) regardless of how many orgs are targeting it. The Go default is `0` (unlimited). This is distinct from the per-org delivery concurrency cap (§11.2), which bounds in-flight deliveries per org; `MaxConnsPerHost` bounds connections at the OS TCP layer across all orgs and all deliveries.

**The Lesson:** Ephemeral port exhaustion is invisible at the application layer — it looks like every outbound connection fails simultaneously. Any service that makes large fan-out HTTP calls (notifications, webhooks, aggregation) must bound the total outbound connection count at the transport layer. The per-org cap limits business-logic concurrency; `MaxConnsPerHost` prevents OS-level resource exhaustion. Both are required.

---

### NOTIFY-12 Fan-Out Delivery Loop Returns on First Channel Failure — All Subsequent Alerts Suppressed

**The Flaw:** The notification fan-out loop was not specified to use per-channel error isolation. An AI implementation naturally writes: `for _, ch := range channels { if err := sendNotification(ch); err != nil { return err } }`.

**Why It Matters:** When an alert rule fires and matches a CVE, the system fans out to all bound notification channels (Slack, email, webhook). If Channel 2 (a webhook) is temporarily unreachable and `sendNotification` returns an error, the `return err` exits the loop. Channels 3, 4, and 5 never receive the alert. The user's Slack and email channels are silently skipped. The user configured these channels as redundant delivery paths for a critical security alert — they don't know any of them succeeded or failed until they check the delivery log. In a security product, "one broken webhook silently suppresses all other delivery paths" is a correctness failure, not a configuration issue.

**The Fix:** Each `notification_deliveries` row is an independent job. The delivery worker MUST `continue` the loop on per-channel failures — never `return err` for outbound HTTP failures:
```go
for _, delivery := range pendingDeliveries {
    if err := attemptDelivery(ctx, delivery); err != nil {
        slog.Error("delivery failed", "delivery_id", delivery.ID, "channel_id", delivery.ChannelID, "error", err)
        markDeliveryFailed(ctx, delivery.ID, err.Error()) // mark only this row
        continue // proceed to next channel — never return here
    }
    markDeliverySucceeded(ctx, delivery.ID)
}
```
The parent job returns an error (and retries) only when a database transaction itself fails — not because an outbound HTTP request failed.

**The Lesson:** Fan-out reliability requires explicit per-element isolation. The `return err` on a loop body is the natural Go error-handling idiom for sequential pipelines where any failure should abort processing. For fan-out delivery to independent endpoints, this idiom is wrong. The correct model is: process all elements, accumulate per-element results, log failures, and never use one element's failure to short-circuit others. This distinction — "pipeline abort" vs "independent fan-out" — must be explicit in any spec that involves notification delivery.

---

### NOTIFY-13 `errgroup.WithContext` Fan-Out Cancels All Siblings on First Failure

**The Flaw:** `errgroup.WithContext` creates a derived context that is cancelled when any goroutine returns an error. In a notification fan-out scenario, this means one channel's failure cancels the contexts of all other in-flight deliveries.

**Why It Matters:** In a 3-channel fan-out where Channel B fails: Channel A (already sent) and Channel C (not yet sent) both get their contexts cancelled. The parent job is retried — re-sending to Channel A (duplicate delivery) and attempting Channel C again (which may fail again if the cancellation masked a transient issue vs. the actual error). The result is duplicate notifications on successful channels and potentially permanent suppression of the failed channel's siblings.

This is distinct from NOTIFY-12 (sequential `return err`): even when fan-out is correctly parallelized with goroutines, `errgroup` introduces the same cross-channel failure coupling through context cancellation rather than loop exit.

**The Fix:** Use `sync.WaitGroup` with independent per-goroutine error recording. Each goroutine writes its own result (success or failure) to the corresponding `notification_deliveries` row. No shared context cancellation between channels. The parent function waits for all goroutines to complete, then reports aggregate results.

```go
var wg sync.WaitGroup
for _, delivery := range pendingDeliveries {
    wg.Add(1)
    go func(d Delivery) {
        defer wg.Done()
        if err := attemptDelivery(ctx, d); err != nil {
            slog.Error("delivery failed", "delivery_id", d.ID, "error", err)
            markDeliveryFailed(ctx, d.ID, err.Error())
            return
        }
        markDeliverySucceeded(ctx, d.ID)
    }(delivery)
}
wg.Wait()
```

**The Lesson:** `errgroup` is the correct tool for pipelines where any failure should abort all work (e.g., fetching required data from multiple sources). It is the wrong tool for fan-out to independent endpoints where each delivery has independent success/failure semantics. The context cancellation behavior — which is `errgroup`'s primary feature — becomes the failure mode in fan-out scenarios.

---

### NOTIFY-14 `alert_events` Lacks UNIQUE Constraint — Concurrent Evaluators Produce Duplicate Alerts

Concurrent evaluators (realtime triggered by CVE upsert, batch evaluator running on schedule) can both evaluate the same CVE against the same rule at the same time. Without a constraint, both INSERT into `alert_events`, producing duplicate alert entries and duplicate notification fan-outs.

**Fix:** `UNIQUE(org_id, rule_id, cve_id, material_hash)` on `alert_events`. All inserts use `ON CONFLICT DO NOTHING RETURNING id`. Fan-out only fires when the `RETURNING` clause actually returns a row (meaning the insert succeeded, not a conflict). This makes concurrent evaluation idempotent — the second evaluator's insert is a no-op.

---

### NOTIFY-15 Notification Fan-Out Is Not Debounced — Burst CVEs Produce Burst Messages

A batch evaluator cycle that matches 200 CVEs against a single rule produces 200 individual notification deliveries. Slack rate limits at 1 msg/sec; 200 messages take over 3 minutes and risk throttling or bans.

**Fix:** 2-minute debounce window per `(rule_id, channel_id)` via a partial unique index on pending deliveries. Multiple CVEs matching within the window accumulate in the delivery payload array. One grouped message is sent containing all matched CVEs. This converts N individual deliveries into one batched delivery per debounce window.

---

### NOTIFY-16 Large Notification Payloads Exceed Channel Limits

Grouped notifications (see NOTIFY-15) can produce payloads that exceed channel-specific size limits. Slack Block Kit rejects messages over 50 blocks with `400 invalid_blocks`, silently dropping the entire batch. Email providers reject messages over typical size limits.

**Fix:** Truncate notification payloads at channel-appropriate limits. Email: cap at 25 CVEs with a "N more — view in dashboard" footer (implemented). Slack: chunk at 20 CVEs per message, delivered sequentially (not yet integrated — Slack support is future work). Webhook: no truncation needed (consumers control their own parsing).

---

### NOTIFY-17 Webhook Response Body Not Read — HTTP/1.1 Keep-Alive Broken

After making a webhook HTTP call, if `resp.Body` is closed without reading, the underlying TCP connection cannot be reused for HTTP/1.1 keep-alive. Every webhook delivery opens a new TCP+TLS connection, adding ~100ms+ latency per call and consuming ephemeral ports faster.

**Fix:** After every webhook call, drain the response body before closing:
```go
defer resp.Body.Close()
io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
```
The `LimitReader` prevents a malicious server from forcing unbounded memory allocation via a large response body.

---

### NOTIFY-18 Notification Channels Must Be Soft-Deleted

Hard-deleting a `notification_channels` row orphans all `notification_deliveries` FK references, breaking delivery history queries and audit trails. Users lose visibility into past delivery attempts for channels that were later removed.

**Fix:** Soft-delete: `UPDATE notification_channels SET deleted_at = now()` instead of `DELETE`. Active channel queries filter with `WHERE deleted_at IS NULL`. Delivery history queries join without the filter, preserving the full audit trail. See also NOTIFY-7 for the pre-flight dependency check before any deletion.

---

### NOTIFY-19 Thundering Herd on Retry — All Failed Retries Wake Simultaneously

When a webhook endpoint goes down, all deliveries targeting it fail and are scheduled for retry. If retry delay is computed as a fixed value (e.g., `next_run_at = now() + 30s`), all failed deliveries wake at the same instant, overwhelming the recovering endpoint and likely causing another round of failures.

**Fix:** Apply full jitter to retry delays: `next_run_at = now() + delay * (0.5 + rand.Float64())`. This spreads retry attempts across a time window equal to the base delay, preventing synchronized retry storms. Combined with exponential backoff on successive attempts, this gives recovering endpoints time to stabilize.

---

### See Also
- Webhook SSRF and redirect bypass: see AUTH-17
- DB transaction during external I/O: see testing-pitfalls.md §8
- Fan-out delivery testing: see testing-pitfalls.md §14

---

### Review Checklist

- [ ] Activation scan runs in silent mode (writes `alert_events` but does NOT enqueue notification deliveries)?
- [ ] Activation scan is async (`status = 'activating'`, background job, handler returns 202)?
- [ ] Activation scan paginates in 1,000-row batches (keyset pagination, not full-corpus load)?
- [ ] Zombie rule sweeper runs periodically (detects `activating` + stale `locked_at`, transitions to `error`)?
- [ ] All evaluation passes filter `cves.status NOT IN ('rejected', 'withdrawn')`?
- [ ] Fan-out uses `sync.WaitGroup` with independent per-channel error recording (not `errgroup`)?
- [ ] Delivery loop uses `continue` on per-channel HTTP failures (never `return err`)?
- [ ] DB transaction committed BEFORE outbound webhook HTTP call (three-phase: claim → HTTP → update)?
- [ ] Webhook HTTP client has `Timeout: 10s` and `MaxConnsPerHost: 50`?
- [ ] Webhook response body drained: `io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))`?
- [ ] Notification debounce window per `(rule_id, channel_id)` batches CVEs into grouped delivery?
- [ ] Notification channels soft-deleted (`deleted_at` column), not hard-deleted?
- [ ] Retry delay uses full jitter to prevent thundering herd?
- [ ] Dry-run evaluation does NOT persist to `alert_events` (read-only path or explicit ROLLBACK)?
- [ ] `alert_events` UNIQUE on `(org_id, rule_id, cve_id, material_hash)` with `ON CONFLICT DO NOTHING RETURNING id`?
