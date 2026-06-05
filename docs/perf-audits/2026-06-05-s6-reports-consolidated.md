---
run_schema_version: 1
run_id: 2026-06-05-s6-reports
date: 2026-06-05T02:35:00Z
scope: "S6 — Reports / AI / retention (internal/{ai,retention}/**, scheduled_report/ai/retention stores + handlers, notify/digest)"
methodology: { skill: performance-audit-cycle, plugin_version: "superpowers-plus@0.2.0 (vendored; version per source repo)" }
dispatch: { model_requested: "opus (latest; Claude Code Agent tool)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack:
  - { ecosystem: go, framework: "google.golang.org/genai (Gemini)", version: "1.52.1" }
  - { ecosystem: go, framework: "stdlib+pgx", version: "go1.26.2 / pgx5.9.2" }
currency_briefs: [ { framework: go, researched_on: null, status: "version-index go.md (covered_through 1.24); genai third-party — n/a" } ]
lanes_run: [algorithmic, memory, data-access, concurrency]
lanes_skipped: { idiom-currency: "REDUCED tier", cost-map: "REDUCED tier", payload-startup: "n/a", dynamic: "no runtime locally" }
finding_counts: { by_impact: { critical: 0, major: 4, minor: 7 }, by_lane: { algorithmic: 1, memory: 3, data-access: 4, concurrency: 4 }, suspected_bugs: 2 }
regression: { prev_run_id: null, new: 11, persisting: 0, resolved: 0 }
---

# Performance Audit (consolidated + validated) — S6 Reports / AI / retention

**Scope:** internal/{ai,retention}/**, scheduled-report/ai/retention stores + handlers, notify/digest. **Tier:** REDUCED. **Verification:** static-only. **Regression:** 11 new.

**This is a low-finding slice, and that is the calibration working.** Both hypothesized criticals were
**refuted from source**: the AI cache is DB-backed (`ai_cache`) with TTL eviction (not an unbounded
in-process map); report digest generation is `LIMIT 500` (not whole-corpus materialization). **Honest
non-findings (verified):** retention DELETEs are textbook bounded-batch `WITH doomed (… ORDER BY ts LIMIT
batch) DELETE USING` with only an `int64` counter accumulated in Go (no ID-list materialization); AI quota
is a per-org atomic UPSERT (not a global lock); no DB transaction is held across the external Gemini call
(claim→commit→call→new-tx); prompt sanitization uses package-scope compiled regexes + a pre-sized
`strings.Builder`; tier-gated retention groups orgs into one batched DELETE per window. No CRITICAL.

## Major Findings

### P1. `ai_usage_counters` retention DELETE seq-scans + sorts the whole table every batch (no index on its filter column)
**Lane:** data-access  **Location:** `internal/store/queries/retention.sql:68-76` + `migrations/000020_create_ai_quota_tables.up.sql`
**Fingerprint:** `data-access:retention.sql:ai_usage-no-date-index`  **Status:** new
**Problem:** The `WHERE date < cutoff ORDER BY date` retention predicate has no usable index — the PK leads with `org_id` and the only other index is `(org_id)`. It is the **one** retention table with no index on its filter column, so each batch seq-scans + sorts the whole table. **Confidence:** Strong-static  **Effort:** Localized — add a `(date)` (or `(date, org_id)`) index.
**Verification plan:** EXPLAIN the retention DELETE (Index Scan vs Seq Scan+Sort); guard = same rows deleted.

### P2. A cache-miss AI call fans out into ~6 single-statement transactions, and two writes hit the same usage-counter row in different transactions
**Lane:** data-access  **Location:** `internal/api/ai.go:107-168,284-356` + `internal/store/ai.go` + tx helpers `internal/store/store.go:48,126`
**Fingerprint:** `data-access:api/ai.go:per-call-tx-fanout`  **Status:** new
**Problem:** Each store call is its own `BEGIN`/`SET LOCAL`/`COMMIT` (~24 round-trips/call under simple protocol), and `IncrementAIUsage` + `UpdateAIUsageTokens` touch the **same** hot quota row in two separate transactions (2 dead tuples/call → bloat on the hottest quota row). **Confidence:** Strong-static  **Effort:** Contained — batch the post-LLM writes (usage increment + token update + request log + cache insert) into one transaction; merge the two usage-counter writes into one statement.
**Verification plan:** round-trip + dead-tuple argument; guard = quota accounting unchanged (per-org totals correct under concurrency).

### P3. Digest generation runs inline on the worker select-loop goroutine, serializing delivery dispatch
**Lane:** concurrency  **Location:** `internal/notify/worker.go:105-106` → `internal/notify/digest.go:87-98`
**Fingerprint:** `concurrency:notify/worker.go:digest-inline-on-loop`  **Status:** new
**Problem:** `runDigest` executes directly in the worker `select` loop, so a multi-report batch of serial DB round-trips blocks the latency-sensitive `claimTicker` delivery dispatch (and can flip `Healthy()` false). **Confidence:** Strong-static  **Effort:** Contained — run digest generation off the select loop (its own goroutine/worker). **Forward risk:** if AI summaries are later wired into digests (see SB1), this loop would issue **blocking network calls** — design the fan-out off the loop now.
**Verification plan:** argument that the claim ticker is not blocked by digest work; guard = digests still generated on schedule.

### P4. Independent per-report digest generation runs strictly sequentially
**Lane:** concurrency  **Location:** `internal/notify/digest.go:93-97`
**Fingerprint:** `concurrency:notify/digest.go:serial-per-report`  **Status:** new
**Problem:** Claimed reports are provably independent (distinct orgs, idempotent inserts, read-only shared corpus) yet generate one-at-a-time; batch latency is the sum, not the max, of per-report I/O. **Confidence:** Strong-static  **Effort:** Contained — bounded `errgroup` over the claimed batch (cap to DB-pool headroom). **Guard:** per-report idempotency already holds; size the limit under the 25-conn pool.
**Verification plan:** latency argument (Σ → max); guard = identical digests, race-free.

## Minor Findings
- **P5** `data-access:notify/digest.go:DigestCVEs:whole-corpus-rescan` — `digest.go:107-175`, `cves.sql:166-184`: every due report re-scans the corpus (sargable range, but a non-indexed `CASE severity` sort), and reports clustering at common times (09:00 UTC) run N near-identical scans differing only in `since`. Bounded by `LIMIT 500` + a 10-report claim cap. **Also a scoping bug — see SB2.** Contained.
- **P6** `data-access:retention.sql:org-scoped-single-col-index` — `retention.sql:20-34`: org-scoped retention DELETEs (`alert_events`, `notification_deliveries`) sort across orgs on a single-column date index, while `audit_log` already has the better `(org_id, created_at)` composite. Localized (add composite indexes for parity).
- **P7** `memory:notify/digest.go:payload-per-channel` — `digest.go:156-172`, `notification_delivery.go:201-212`: the up-to-500-CVE digest JSON blob is persisted + wire-shipped once **per channel** (shared Go buffer, no heap copy, but DB/wire amplification). Localized. (Relates to S5-P1's fan-out shape.)
- **P8** `concurrency:ai/gemini.go:init-mutex-dial` — `gemini.go:40-57`: lazy client init holds a process-wide mutex across a 10s network dial; cold-start/post-failure only. Localized.
- **P9** `concurrency:ai/gemini.go:fixed-init-timeout` — `gemini.go:46`: client init uses a fixed 10s timeout independent of the caller deadline (cancel still propagates — not a leak). Localized.
- **P10** `memory:api/ai.go:sprintf-hex-cachekey` — `api/ai.go:97,277`: `fmt.Sprintf("%x", sha256.Sum256(...))` for the cache key on a quota-gated path; `hex.EncodeToString` is the free, byte-identical swap. Localized.
- **P11** `memory:ai/gemini.go:bytes-string-copy` — `gemini.go:114,133`: `genai.Text(string(inputJSON))` forces a `[]byte→string` copy; small (one CVE), vendor API takes a string — documented, lowest priority (grouped minor).

## Measurability
Retention pass duration, AI-call round-trip count, and digest-batch latency are all observable with
counters. Recommend a retention-DELETE-duration metric to confirm P1.

## Suspected Bugs (for follow-up — NOT addressed here)
> Kickoff: `docs/perf-audits/2026-06-05-s6-reports-bug-hunt-kickoff.md`.
- **SB1. `report.AiSummary` flag is never honored** — the LLM summarizer is not wired into the digest/render
  path; the flag is stored and round-tripped but **dead** (`internal/notify/digest.go` render path). A
  functional gap; also a forward perf risk (P3) if later wired naively.
- **SB2. Digest reports ignore `watchlist_ids` entirely** — `internal/notify/digest.go:107-175` → `DigestCVEs`
  applies no watchlist/org narrowing, so a scheduled digest scans the **whole corpus** regardless of the
  report's watchlist scoping. Potential correctness/scoping bug with direct user impact (users may receive
  unscoped digests). Verify intended scoping; this is the priority item.

---
**Disposition:** all 11 findings default to **FIX**. No severity/effort deferral. The two refuted criticals
are recorded as scope-brief corrections (calibration working). 2 suspected bugs handed off (SB2 is a
user-facing scoping bug worth priority).
