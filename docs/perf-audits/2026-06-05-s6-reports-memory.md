# S6 — Reports / AI / retention — memory & allocation lane

ABOUTME: Memory/allocation perf audit of the reports-generation, AI-orchestration, and retention paths.
ABOUTME: Lane slug: reports-memory (S6, reduced/warm). No runtime profiling available — static reasoning only.

## Scope examined

- `internal/ai/{ai,gemini,sanitize}.go` — LLM orchestration boundary (quota/cache/sanitize).
- `internal/retention/runner.go` + `internal/store/retention.go` — batch DELETE cleanup.
- `internal/store/{scheduled_report,ai}.go` — report-config CRUD + AI cache/quota/log store methods.
- `internal/api/{reports,ai}.go` — report CRUD handlers + NL-search/summarize handlers.
- `internal/notify/digest.go` (the actual report *generation* path — corpus aggregation lives here, not in `api/reports.go`) and `internal/store/queries/cves.sql:DigestCVEs`.

## Headline: the lane's two hypothesized criticals do NOT hold

The dispatch lens flagged "AI response cache without eviction (unbounded growth keyed by prompt hash)" and "report generation materializing the whole corpus into memory." Reading the actual code, both are already defended:

- **AI cache is DB-backed, not an in-process map.** `GetAICache`/`PutAICache` (`internal/store/ai.go:175-209`) read/write the Postgres `ai_cache` table (org-scoped). There is no Go-resident cache map keyed by prompt hash anywhere in the AI path. Eviction exists: `CleanupAICacheBatch` (`internal/store/retention.go:154-169`) is driven each retention pass by the runner (`runner.go:84-86`) using a TTL cutoff and bounded `LIMIT batchSize` DELETE loop. No unbounded growth.
- **Digest CVE query is `LIMIT 500`.** `DigestCVEs` (`internal/store/queries/cves.sql:166-184`) caps the result set at 500 rows. The report generator (`digest.go:121`) therefore materializes at most 500 8-field snapshot structs, not the whole corpus. Bounded.

So there is no CRITICAL in this lane. The remaining findings are MINOR and design remarks.

---

## Findings

### [MINOR] Digest payload buffer is re-persisted in full to `notification_deliveries` once per channel
**Location:** `internal/notify/digest.go:156-172` (`executeDigestReport`); `internal/store/notification_delivery.go:201-212` (`InsertDigestDelivery`)
**Problem:** The digest builds one `payload []byte` (a JSON array of up to 500 `cveSnapshot` objects) once, then loops over the report's channels calling `InsertDigestDelivery(...payload)` per channel. The Go buffer is *shared* by reference (good — no in-process copy), but each insert writes the **entire** payload as a separate `notification_deliveries.payload` row. With C channels bound to a report, the same up-to-500-CVE JSON blob is stored C times and re-shipped over the pgx wire C times. This is DB storage + wire amplification, not heap amplification.
**Impact:** Reachability: every scheduled digest run that has matches. Frequency: once per report per schedule tick (low — daily-ish per report). Per-occurrence cost: payload size (≤500 CVEs × ~5 small fields, realistically single-digit to low-tens of KB) × C channels written and round-tripped. Aggregate cost is small because digests are infrequent and C is typically 1–3. Genuinely MINOR; noted because it's the only payload-duplication in the path.
**Confidence:** Strong-static — loop structure and per-row storage are explicit.
**Effort:** Cross-cutting to fix "properly" (normalize payload into one row + a join table of channel targets), and that change is disproportionate to the bounded cost. Not recommended. Recording only.
**Verification plan:** Count `InsertDigestDelivery` calls = `len(channels)`; each receives the same `payload`. Storage scales as `O(payloadBytes × channels)`. Correctness guard: `internal/notify/worker_test.go` digest delivery tests pin one delivery row per channel with identical payload — any de-dup refactor must keep per-channel `X-CVErtOps-Kind`/signing behavior intact.

### [MINOR] `genai.Text(string(inputJSON))` forces a defensive copy of the marshaled summary input
**Location:** `internal/ai/gemini.go:114,133` (`Summarize`)
**Problem:** `Summarize` does `json.Marshal(input)` → `[]byte`, then `genai.Text(string(inputJSON))` which converts the byte slice to a `string` (one copy) before wrapping it in a `genai.Part`. For NL-search (`gemini.go:80`) the prompt is already a `string` so no extra copy. The summary input is small (one CVE's sanitized fields), so the copy is a few hundred bytes to low-KB.
**Impact:** Reachability: every cache-miss summarize call. Frequency: quota-gated, low. Per-occurrence cost: one `[]byte→string` allocation of the marshaled input (small). Trivial in absolute terms; listed only for completeness of the allocation inventory.
**Confidence:** Strong-static.
**Effort:** Localized but not worth doing — the `genai` API takes the value by `string`, and the input is small; eliminating the copy would require an API the vendor doesn't expose.
**Verification plan:** `string(inputJSON)` is a documented Go copy. No behavior change available without vendor API support; nothing to guard.

### [MINOR] Per-AI-request `fmt.Sprintf("%x", sha256.Sum256(...))` for the cache/input hash
**Location:** `internal/api/ai.go:97` (NL search), `internal/api/ai.go:277` (summarize)
**Problem:** The cache key hash is hex-encoded via `fmt.Sprintf("%x", ...)`, which routes a 32-byte array through reflection-based formatting and allocates an intermediate. `hex.EncodeToString(h[:])` is the direct, allocation-lean equivalent and avoids the `fmt` machinery.
**Impact:** Reachability: every AI request (both features). Frequency: quota-gated, so bounded and low. Per-occurrence cost: one `fmt` formatting pass + small alloc, once per request, off the LLM-latency critical path (the request is dominated by a network round-trip to Gemini). Effectively negligible relative to the surrounding work — MINOR bordering on non-finding, but it's a clean, free win.
**Confidence:** Strong-static.
**Effort:** Localized — swap to `encoding/hex`. Low-effort.
**Verification plan:** `hex.EncodeToString(sum[:])` produces byte-identical lowercase output to `fmt.Sprintf("%x", sum)` for a `[32]byte`, so cache keys stay stable (no cache-wide miss storm). Guard: existing AI cache hit/miss tests pin key stability.

---

## Things checked and found clean (no finding)

- **Retention deletes are set-based and batched.** Every `Cleanup*` store method (`internal/store/retention.go`) calls a sqlc query with `Cutoff` + `BatchSize`, and `cleanupTable` (`runner.go:169-200`) loops until a batch returns 0 rows or the deadline passes. No ID list is loaded into memory to delete — the DELETE is `... WHERE <ts> < cutoff LIMIT batchSize` server-side. This is exactly the recommended pattern; the lane's "retention loading large ID lists" hypothesis does not apply.
- **`ListAllOrgs`** (`internal/store/queries/org.sql:102-104`) materializes all orgs, but only 3 small columns (id, tier, overrides), once per retention pass, bounded by tenant count. `groupByRetentionDays` then passes whole org-ID slices into the grouped `Cleanup*` calls — UUIDs are 16 bytes and this is the only way to express a grouped multi-org DELETE. Not a finding.
- **`Sanitize`** (`internal/ai/sanitize.go`) already uses `strings.Builder` with `b.Grow(len(s))` — single-pass, pre-sized, no quadratic concatenation.
- **Report CRUD handlers** (`internal/api/reports.go`) are bounded list/get/patch operations over a per-org report config table; `make([]reportEntry, len(rows))` is correctly pre-sized. No corpus materialization here — report *generation* is in `notify/digest.go`.
- **Digest snapshot build** (`digest.go:133-155`) pre-sizes `make([]cveSnapshot, len(cves))` and marshals once — no per-channel re-marshal (the marshal is outside the channel loop).

## Suspected Bugs (for follow-up)

None.
