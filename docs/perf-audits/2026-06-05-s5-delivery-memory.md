# S5 — Async delivery & per-request overhead — memory & allocation lane

ABOUTME: Memory/allocation perf audit of notify/worker/secure delivery path + rate-limit/event hot paths.
ABOUTME: Lane focus — per-event allocation × fan-out width, unbounded retention (rate-limiter/event-buffer eviction).

Scope read (actual source): `internal/notify/{dispatcher,worker,webhook,digest,template,render,client}.go`,
`internal/worker/{pool,job}.go`, `internal/secure/{ratelimit,writer,events,syslog}.go`,
`internal/store/{notification_delivery,notification_channel,jobs,report_channel,security_events}.go`,
`internal/api/{deliveries,channels,ratelimit,scim_ratelimit,lockout,admin_security_events,admin_deliveries}.go`,
and the fan-out caller in `internal/alert/evaluator.go`.

The two retention vectors the lane brief flagged as priorities — the rate-limiter maps and the
security-event async buffer — are both **already bounded** in this codebase (TTL eviction loops and a
fixed semaphore with drop-on-full backpressure, respectively). The real allocation cost lives in the
fan-out loop and the webhook signer. Findings below in rank order.

---

### [MAJOR] Per-matched-CVE snapshot fetch + re-marshal in the activation/batch fan-out loop

**Location:** `internal/alert/evaluator.go:434-446` (loop) → `internal/notify/dispatcher.go:46-75` (`Fanout`),
`dispatcher.go:79-117` (`buildSnapshot` → `GetCVESnapshot`), `dispatcher.go:57` (`json.Marshal`).

**Problem:** `Dispatcher.Fanout` operates on a single CVE. The evaluator calls it once **per matched
CVE** inside `evaluateRule`'s insert loop. Each call independently (a) runs a `GetCVESnapshot` DB
round-trip, (b) `json.Marshal`s an 8-field `cveSnapshot` into a fresh `[]byte`, and (c) loops calling
`UpsertDelivery` (one bypass-RLS transaction per bound channel). For an activation scan — which by
design can match up to the candidate cap (5,000 CVEs, per CLAUDE.md alert-evaluation notes) — across
M bound channels this is N snapshot queries + N marshals + N×M upsert transactions, with N up to 5,000.
The snapshot struct, the marshaled payload, and the channel slice from `ListActiveChannelsForFanout`
are all re-allocated on every one of the N iterations. The `ListActiveChannelsForFanout` query is also
re-issued per CVE even though the channel set for a given `(rule, org)` is identical across every CVE
in the same scan.

**Impact:** Reachability: activation scan (new-rule insert) and the batch evaluator both walk this loop;
realtime upsert hits it with N=1 (cheap). Frequency: every rule activation and every batch tick with
matches. Per-occurrence: O(N) allocations for snapshots + payloads + O(N) channel-list slices, plus
O(N) snapshot queries and one repeated channel-list query per CVE that could be hoisted to one per scan.
At N=5,000 / M=3 that is ~5,000 marshals and ~5,000 redundant channel-list queries whose result never
changes within the scan. Aggregate allocation and round-trip cost dominate the activation path far more
than any single outbound webhook send. This is the highest-volume allocation site in the lane.

**Confidence:** Strong-static — the per-CVE call structure is explicit in `evaluator.go:441` and
`Fanout` re-fetches/re-marshals/re-lists on every entry.

**Effort:** Contained — a batch fan-out entry point (`Fanout(ctx, orgID, ruleID, cveIDs []string)`) that
lists channels once, fetches snapshots in one `WHERE cve_id = ANY($1)` query, and marshals per-CVE,
threaded through the one evaluator caller. Signature change is local to dispatcher + evaluator.

**Verification plan:** Count `GetCVESnapshot` calls and `json.Marshal` invocations across one activation
scan with N matches — current = N, batched = 1 query + N marshals (or 1 if payloads stay per-CVE) and 1
channel-list query vs N. Correctness guard: existing `dispatcher_test.go` fan-out tests plus an
evaluator activation test asserting one delivery row per `(cve, channel)` with unchanged payload bytes —
the per-CVE debounce upsert semantics (`uq_deliveries_pending_alert`) must be preserved exactly.

---

### [MINOR] Webhook HMAC signing copies the whole payload via string concatenation per signature

**Location:** `internal/notify/webhook.go:60` and `:67` — `mac.Write([]byte(ts + "." + string(payload)))`.

**Problem:** Signing builds `ts + "." + string(payload)` which (1) converts `payload []byte` to a string
(copy), (2) concatenates into a new string (second copy of the whole payload), then (3) converts back to
`[]byte` for `mac.Write` (third copy). When a secondary signing secret is configured (rotation grace
period), the entire concat is done a second time at `:67`, for ~6 full payload copies per delivery.
`hmac.Hash` is an `io.Writer`; the timestamp and body can be written in two `mac.Write` calls with zero
intermediate allocation. Digest payloads carry up to 25 CVE snapshots, so the payload is not trivially
small.

**Impact:** Reachability: every signed webhook delivery (the common case — webhook channels get a
signing secret at creation). Frequency: once per delivery attempt, ×retries. Per-occurrence: 2–3 full
payload-sized allocations (×2 with a secondary secret). Bounded per delivery but on the steady-state
outbound path; constant-factor garbage on every webhook send.

**Confidence:** Strong-static — the allocation chain is visible in the literal expression.

**Effort:** Localized — replace each concat with `mac.Write([]byte(ts)); mac.Write([]byte{'.'});
mac.Write(payload)` (or write `ts` + `.` via a small stack buffer). One function.

**Verification plan:** The HMAC output must be byte-identical (same preimage `ts + "." + body`), so
existing webhook signature tests pin correctness. Allocation argument: 3→~1 small allocations per
signature, payload no longer copied. Confirm with an allocs/op micro-benchmark over `Send` on a
representative digest payload.

---

### [MINOR] Replay rate-limiter `sync.Map` grows unbounded — never evicts per-org buckets

**Location:** `internal/api/deliveries.go:27` (`var replayBuckets sync.Map`), `:33-52` (`checkReplayLimit`).

**Problem:** Unlike the IP/SCIM/security-event limiters (all of which run TTL eviction loops),
`replayBuckets` is a package-level `sync.Map` that gains one `*replayBucket` per distinct org that ever
calls the replay endpoint and never removes them. The window is reset in place but the map entry lives
for process lifetime. This is a slow leak keyed by org cardinality.

**Impact:** Reachability: replay endpoint (admin-gated, low call volume). Frequency: one map entry per
org that ever replays — bounded by total org count, which for a self-hosted/multi-tenant instance is
small-to-moderate and grows monotonically, not per-request. Per-occurrence cost is a single small
struct. Genuinely minor leak; flagged for parity with the other limiters and because it is the one
unbounded retention site in the lane (the brief's named priority), but the bound is org-count, not
request-rate.

**Confidence:** Strong-static — no delete path exists for `replayBuckets`.

**Effort:** Localized — either add a `lastSeen`-based sweep like `ipRateLimiter.cleanupLoop`, or move
the limiter onto `Server` with a stop-driven evictor. Localized but touches lifecycle wiring if moved
off the package var.

**Verification plan:** Assert map size stays bounded after exercising replay across K orgs then idling
past TTL. Correctness guard: existing replay rate-limit tests (10/hour/org window) must still pass.

---

## Non-findings examined (explicitly NOT problems)

- **Security-event async writer buffer (`internal/secure/writer.go`).** No unbounded queue: it uses a
  fixed `sem chan struct{}` of `writerConcurrency = 50` and **drops** events when full (`:83-91`,
  `SecurityEventsDropped`). That is bounded backpressure, not retention growth. `Details map[string]any`
  is marshaled once per event in `InsertSecurityEvent` — no fan-out multiplier. Not a finding.
- **IP / SCIM rate-limiter maps (`api/ratelimit.go`, `api/scim_ratelimit.go`) and the security-event
  `eventRateLimiter` (`secure/ratelimit.go`).** All three run `cleanupLoop`/`evictLoop` TTL eviction.
  Bounded. The per-request `Allow` path allocates only a map probe + (on first-seen) one `rate.Limiter`
  or `bucket`; no per-request payload allocation. Not a finding.
- **Per-org delivery semaphores (`notify/worker.go:391-413`).** `evictStaleSemaphores` reaps idle
  per-org channels on a 10-minute ticker. Bounded. Not a finding.
- **Worker fan-out goroutine launch (`worker.go:167-177`).** One goroutine per claimed row, capped by
  `ClaimBatchSize` and the per-org semaphore; `row := row` copy is a small struct. No large intermediate
  slice. Not a finding.
- **`ClaimPendingDeliveries` ids slice (`store/notification_delivery.go:61-64`).** `make([]uuid.UUID,
  len(result))` is bounded by claim batch size; necessary for the `MarkDeliveriesProcessing` bulk update.
  Not a finding.
- **`renderPair` template buffers (`notify/render.go:137-158`).** Three `bytes.Buffer`s per email render;
  email delivery is comparatively rare and the buffers are bounded by template size. Not worth a
  readability-costing `sync.Pool` at this volume. Not a finding.
- **Webhook response discard (`webhook.go:78`).** `io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))`
  caps body buffering at 4 KiB and enables connection reuse. Correct. Not a finding.
- **`snapshotsToCVESummaries` (`notify/template.go:41-68`).** Pre-sized `make([]CVESummary, len(snaps))`,
  description sliced not copied. Email-path only. Fine.

---

## Suspected Bugs (for follow-up)

None.
