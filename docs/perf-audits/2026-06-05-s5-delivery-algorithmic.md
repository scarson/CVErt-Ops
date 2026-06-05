# S5 — Async delivery & per-request overhead — `algorithmic` lane

ABOUTME: Performance audit of notify/worker/secure for algorithmic complexity & data-structure cost.
ABOUTME: Lane = algorithmic; tier = REDUCED, WARM. No runtime profiling available (no Measured claims).

Scope read: `internal/notify/**` (dispatcher, worker, webhook, email, render, template, digest, client),
`internal/worker/**` (pool, job), `internal/secure/**` (writer, ratelimit, events, syslog), and the
backing store methods (`notification_channel`, `notification_delivery`, `jobs`, `security_events`,
`alert_rule_channels`, `cves` snapshot) plus API hot-path files (`ratelimit`, `scim_ratelimit`,
`lockout`, `admin_deliveries`).

Frequency anchors used throughout:
- **Realtime fanout**: `EvaluateRealtime` runs all active rules across all orgs against one CVE per
  upsert; every matching rule calls `Dispatcher.Fanout(orgID, ruleID, cveID)`
  (`internal/alert/evaluator.go:103,441`).
- **Batch fanout**: `EvaluateBatch` (`evaluator.go:208`, `suppressDelivery=false`) calls `Fanout`
  once per matched CVE per rule across the whole modified-since window — the high-volume path.
- **Delivery worker**: claim tick every 5 s, one goroutine per claimed delivery row
  (`internal/notify/worker.go:152`).
- **API rate limit / security events**: per request / per security-relevant action.

---

### [MAJOR] `Fanout` re-fetches the identical CVE snapshot once per matching rule during realtime evaluation
**Location:** `internal/notify/dispatcher.go:46-117` (`Fanout` → `buildSnapshot` → `GetCVESnapshot`), driven by `internal/alert/evaluator.go:88-115,441`
**Problem:** `EvaluateRealtime` evaluates a single CVE against *every* active rule across *every*
org. Each rule that matches calls `Fanout(orgID, ruleID, cveID)`, and `Fanout` unconditionally calls
`buildSnapshot(cveID)` → `GetCVESnapshot(cveID)` — a fresh DB round-trip — *and* re-marshals the same
`cveSnapshot` to JSON (`dispatcher.go:55-60`). The `cveID` is constant for the whole realtime call,
so for a CVE that matches M rules (a new critical/KEV entry can match many watchlist rules across
tenants) the worker issues M identical single-row `SELECT ... FROM cves WHERE cve_id=$1` queries and
M identical `json.Marshal` calls inside one upsert-triggered evaluation. The snapshot is org- and
rule-independent; only the `UpsertDelivery` write is per-channel.
**Impact:** Reachable on the realtime hot path (fires on every CVE upsert whose `material_hash`
changed). Per-occurrence: M redundant DB round-trips + M JSON marshals where 1 would do; M scales
with rule fan-out for popular CVEs (the exact CVEs that matter most). DB round-trip latency, not query
cost, dominates — `GetCVESnapshot` is a single-row PK lookup, so this is pure round-trip amplification
on the path users feel ("how fast did my alert fire"). Constant-factor-per-rule win on a frequent path.
**Confidence:** Strong-static — the call graph (`EvaluateRealtime` loop → `Fanout` → `buildSnapshot`)
and the constant `cveID` are visible in source.
**Effort:** Contained — hoist snapshot building out of `Fanout` into the evaluator loop (build once
per `cveID` per evaluation pass, pass the marshaled `payload []byte` into `Fanout`), or add a tiny
per-call snapshot cache. Touches the `Dispatcher.Fanout` signature and its two callers
(`evaluator.go`, `worker.go runRecovery`). The mock dispatcher in `evaluator_test.go` also moves.
**Verification plan:** Argument: count `GetCVESnapshot`/`json.Marshal` invocations per
`EvaluateRealtime` call — current = (rules matched), target = 1. Add a counting fake store in an
evaluator test that asserts exactly one snapshot fetch when one CVE matches N rules. Correctness
guard: existing `TestEvaluateRealtime_FanoutCalledForNewEvent` /
`TestEvaluateRealtime_FanoutNotCalledForDuplicateEvent` must stay green (same delivery rows written).

---

### [MAJOR] `Fanout` re-queries the per-rule channel list and re-builds the snapshot per matched CVE in batch evaluation
**Location:** `internal/notify/dispatcher.go:46-60` (`ListActiveChannelsForFanout` + `buildSnapshot` inside `Fanout`), driven by `internal/alert/evaluator.go:208,432-446`
**Problem:** In `EvaluateBatch`, a single rule is evaluated against the entire modified-since window
and `Fanout` is invoked once per matched CVE (`evaluator.go:441`, inside the `for _, m := range
matched` loop). For one rule, `(ruleID, orgID)` is fixed across all its matches, yet every `Fanout`
call re-runs `ListActiveChannelsForFanout(ruleID, orgID)` — a two-table JOIN
(`alert_rule_channels ⋈ notification_channels`, `alert_rule_channels.sql:21-27`) — *and* builds a
fresh snapshot + JSON for that match's CVE. So a rule matching K CVEs issues K channel-list JOIN
queries that all return the same channel set, plus K snapshot fetches. The channel list is invariant
for the rule; only the payload and the `UpsertDelivery` write legitimately vary per CVE.
**Impact:** Reachable on the periodic batch evaluator. Per-occurrence: K redundant channel-list JOIN
queries per rule where 1 suffices (K = matches in the window; large after a bulk feed import or a
broad rule). The JOIN is heavier than a PK lookup, so each redundant call costs more than the
snapshot one. Aggregate: (rules × matches-per-rule) extra JOINs per batch cycle.
**Impact:** Aggregates with the realtime finding above — same `Fanout` body, both call sites.
**Confidence:** Strong-static — loop structure and the invariant `(ruleID, orgID)` are visible.
**Effort:** Contained — fetch the channel list once per rule (in `evaluateRule`, before the match
loop) and pass channels + a per-CVE payload into a slimmed `Fanout` (or a new
`FanoutToChannels`). Same signature change as the finding above; do both together.
**Verification plan:** Argument: channel-list queries per rule-batch = 1 instead of K. Counting fake
store asserting one `ListActiveChannelsForFanout` per rule when K CVEs match. Correctness guard:
delivery rows per (rule, channel, CVE) unchanged — assert `UpsertDelivery` still called K×channels.

---

### [MINOR] Webhook signing concatenates the full payload into a new string per delivery (and twice during key rotation)
**Location:** `internal/notify/webhook.go:60,67` — `mac.Write([]byte(ts + "." + string(payload)))`
**Problem:** `string(payload)` copies the whole `[]byte` body to a string, then `ts + "." + string`
allocates a second full-size string, then `[]byte(...)` copies it back to bytes — three allocations
sized to the payload, just to feed HMAC. During the rotation grace period this happens twice
(primary + secondary secret, lines 60 and 67), each rebuilding the same concatenation independently.
`hmac.Hash` is an `io.Writer`: writing `ts`, ".", then `payload` directly avoids all three copies.
**Impact:** Per delivery (every webhook send). Payloads are debounced arrays of CVE snapshots, so
they can be multi-KB; cost scales with payload size × (1 or 2 signatures). Constant-factor allocation
win on a per-delivery path — modest individually, but it is the per-delivery serialization hot spot
and the GC pressure is avoidable.
**Confidence:** Strong-static — the conversions are explicit in source.
**Effort:** Localized — write `[]byte(ts)`, `[]byte(".")`, `payload` to the `mac` in sequence
(optionally pre-format `ts` once and reuse the bytes for both MACs). One function.
**Verification plan:** Argument: allocations per signed delivery drop from ~3 (×2 in rotation) to ~1
small `ts` buffer. `go test -benchmem` on a `Send` microbench, or `-gcflags=-m` to confirm the
concatenation no longer escapes. Correctness guard: a test that pins the exact HMAC hex for a known
`(secret, ts, payload)` triple — signature bytes must be byte-identical before/after.

---

### [MINOR] Per-IP / per-org rate limiters serialize every check through one global mutex
**Location:** `internal/api/ratelimit.go:45-55` (`ipRateLimiter.Allow`), `internal/api/scim_ratelimit.go:48-59` (`scimRateLimiter.Allow`), same shape in `internal/secure/ratelimit.go:50-79`
**Problem:** Each limiter guards its whole `map[string]*rate.Limiter` with a single `sync.Mutex`
taken on *every* `Allow` call, including the common path where the entry already exists and only
`limiter.Allow()` (itself internally synchronized) + a `lastSeen` timestamp write are needed. Under
concurrent request load all callers contend on one lock for a map read that could be lock-free or
sharded. The map+lock combo also carries the per-entry overhead the Go pack flags (a `map[string]*T`
of limiters per IP).
**Impact:** The auth/SCIM limiters are *not* on the every-request path — `authRateLimit` wraps only
auth endpoints and `scimRateLimit` only SCIM — so contention is bounded by those endpoints' QPS, not
total API QPS. The `secure` event limiter is hit per security-relevant action (also bounded). This is
therefore a constant-factor contention concern on medium-frequency paths, not a global bottleneck —
ranked MINOR for that reason. (The prompt's "rate-limit check runs on EVERY API request" was not
borne out by the middleware wiring; recorded under Suspected Bugs as a scope note, not a defect.)
**Confidence:** Strong-static for the single-lock structure; Heuristic that contention is material at
current load (no profile).
**Effort:** Contained — shard the map by key hash, or switch to `sync.Map` for the read-mostly
lookup with the per-entry `*rate.Limiter` doing its own locking. Touches each limiter independently.
**Verification plan:** Argument: lock-hold time per `Allow` drops to the (rare) miss path; hot path
becomes a sharded/`sync.Map` read. `go test -bench` with parallel goroutines (`b.RunParallel`) on
`Allow` comparing mutex vs sharded. Correctness guard: existing limiter tests (window reset, burst,
eviction) stay green; add a race-detector run (`-race`) over concurrent `Allow`.

---

### [MINOR] Security-event writer spawns a goroutine and a separate DB transaction per event
**Location:** `internal/secure/writer.go:71-136` (`Write` → `go func(){ ... InsertSecurityEvent ... }`)
**Problem:** Every accepted security event acquires a semaphore slot, launches a goroutine, and runs
its own `InsertSecurityEvent` (one tx, one round-trip). During an event burst — a brute-force login
storm, a credential-stuffing run, an SCIM rate-limit flood — this is one goroutine + one INSERT
round-trip per event up to `writerConcurrency=50`, with the rate limiter shedding the rest. No
batching: 50 near-simultaneous failed logins from distinct IPs (distinct rate-limit keys) become 50
concurrent single-row INSERTs. A bounded channel feeding a batch INSERT (`COPY`/multi-row VALUES)
would collapse a burst into a few multi-row writes.
**Impact:** Reachable only under event bursts (the rate limiter caps steady state). Per-occurrence:
N single-row INSERT round-trips + N goroutine spawns where a batch would do O(N/batch). Because the
limiter already sheds floods per (type, IP), aggregate exposure is bounded — MINOR. Worth noting as
a structural item if security-event volume grows (e.g., many distinct IPs defeating the per-IP key).
**Confidence:** Strong-static for the per-event goroutine+tx structure; Heuristic on burst frequency.
**Effort:** Contained — introduce a buffered channel + a batching drainer doing multi-row inserts;
changes `writer.go` and adds a batch store method. Only worth it if event volume is shown to matter.
**Verification plan:** Argument: INSERT round-trips per burst of N events drop from N to ⌈N/batch⌉.
Bench feeding N events and counting store calls via a fake. Correctness guard: every non-rate-limited
event still persists exactly once; drop-on-capacity semantics preserved (assert dropped counter).

---

## Summary (rank · title · location)

1. **MAJOR** — Realtime `Fanout` re-fetches identical CVE snapshot per matching rule — `internal/notify/dispatcher.go:55` (driver `internal/alert/evaluator.go:103,441`)
2. **MAJOR** — Batch `Fanout` re-queries invariant per-rule channel list + snapshot per matched CVE — `internal/notify/dispatcher.go:47-55` (driver `internal/alert/evaluator.go:208,441`)
3. **MINOR** — Webhook HMAC rebuilds full `ts+"."+payload` string per delivery (×2 in rotation) — `internal/notify/webhook.go:60,67`
4. **MINOR** — Rate limiters serialize every check through one global mutex — `internal/api/ratelimit.go:45`, `internal/api/scim_ratelimit.go:48`, `internal/secure/ratelimit.go:50`
5. **MINOR** — Security-event writer: goroutine + separate tx per event, no batching — `internal/secure/writer.go:71`

The two MAJOR findings share the same `Fanout` body and should be fixed together: pass a
pre-built channel list and a pre-marshaled per-CVE payload into `Fanout`, eliminating both the
redundant snapshot fetch (realtime, same CVE across rules) and the redundant channel-list JOIN
(batch, same rule across CVEs).

## Suspected Bugs (for follow-up)

- **Scope mismatch (not a defect):** The lane brief states "rate-limit check runs on EVERY API
  request." In the read source, `authRateLimit` (`internal/api/ratelimit.go:81`) is applied only to
  auth endpoints and `scimRateLimit` only to SCIM endpoints — there is no global per-request limiter
  middleware in these files. This lowers the rate-limiter contention finding to MINOR. Flagging so a
  reviewer can confirm there is no separately-wired global limiter elsewhere (e.g., a chi
  `Use(...)` in server setup) that would raise the frequency — `internal/api/ratelimit.go:81-96`.
- `internal/notify/worker.go:250` — `deliverWebhook` ignores the `json.Unmarshal` error on
  `ch.Config` (documented `//nolint`: bad JSON → empty URL → Send fails → retry/exhaust). Not a
  performance issue; noted only because it sits on the delivery path.
