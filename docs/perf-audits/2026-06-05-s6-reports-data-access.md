# S6 Reports / AI / Retention — data-access lane

ABOUTME: Performance audit (data-access & I/O lane) of the S6 slice — scheduled
ABOUTME: digest reports, AI cache/quota/logging, and retention batch deletes.

Auditor lane: **data access & I/O**. Scope read in full: `internal/ai/**`,
`internal/retention/**`, `internal/store/{ai,scheduled_report,notification_delivery}.go`,
`internal/notify/digest.go`, `internal/api/{reports,ai}.go`, and the SQL pack
(`store/queries/{ai_cache,ai_usage,ai_request_log,scheduled_reports,retention}.sql`,
`store/queries/cves.sql` DigestCVEs) plus relevant DDL in `migrations/`.

No runtime profiling available (Docker/testcontainers absent) — all confidences are
Strong-static or Heuristic, never Measured.

---

## Hot-path map (where the I/O actually is)

- **Reports**: there is no `internal/report/` package. Digest report *generation* lives in
  `internal/notify/digest.go`. `runDigest` claims ≤10 due reports per worker tick
  (`ClaimDueReports`, `FOR UPDATE SKIP LOCKED`) and calls `executeDigestReport` per report.
  Each report runs one `DigestCVEs` query — a **corpus-wide** scan of `cves`
  (`cves.sql:166`), bounded `LIMIT 500`, sorted by a `CASE severity` expression.
- **AI call**: each NL-search / summarize request is a chain of *independent* store calls,
  each its own `withOrgTx`/`withBypassTx` transaction (`store.go:48`, `:126`) =
  `BEGIN` + `SET LOCAL` + query + `COMMIT`. Under `QueryExecModeSimpleProtocol` (no prepared
  statements) every statement in that sequence is its own network round-trip.
- **Retention**: `internal/retention/runner.go` runs bounded-batch `DELETE`s
  (`retention.sql`) — CTE `SELECT … ORDER BY <date> LIMIT batch` + `DELETE … USING doomed`.
  The batching shape is correct; the question is whether each table's retention date column
  is indexed.

---

## Findings

### MAJOR — `ai_usage_counters` retention DELETE has no index on its filter column; every batch seq-scans + sorts the whole table
**Location:** `internal/store/queries/retention.sql:68-76` (`CleanupAIUsageCounters`);
DDL `migrations/000020_create_ai_quota_tables.up.sql:6-31`.
**Problem:** The cleanup filters `WHERE date < @cutoff::date ORDER BY date LIMIT batch`.
The table's only indexes are the PK `(org_id, feature, date)` and
`ai_usage_counters_org_id_idx (org_id)`. A predicate/sort on the leading-bare `date` column
can use **neither** — the PK leads with `org_id`, so `date` is not a usable prefix. Postgres
must `Seq Scan` the entire table and `Sort` it on every batch iteration, and the runner loops
until 0 rows deleted, so it re-scans + re-sorts each pass. Every other retention table
(`ai_request_log.created_at`, `ai_cache.expires_at`, `security_events.created_at`,
`cve_raw_payloads.ingested_at`, `feed_fetch_log.started_at`, `refresh_tokens(user_id,expires_at)`,
`audit_log(org_id,created_at)`, `alert_events.first_fired_at`,
`notification_deliveries.created_at`, `job_queue` cleanup idx) **does** have an index serving its
retention predicate — this is the one gap.
**Impact:** Reachable on every retention pass (daily). Per pass: O(rows) seq scan + O(rows·log
rows) sort, repeated per batch until drained. Row count grows as `n_orgs × 2 features × n_days_retained`;
on a multi-tenant SaaS that is the largest of the AI tables and the only one without index support.
Cost per batch is full-table, not batch-bounded — the worst shape in the retention set.
**Confidence:** Strong-static (DDL shows no index on `date`; query filters/sorts on `date`).
**Effort:** Localized — add `CREATE INDEX CONCURRENTLY ai_usage_counters_date_idx ON ai_usage_counters (date)`
in a new migration. (Equivalently, a BRIN on `date` given the append-by-day shape.)
**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` the CTE before/after — expect Seq Scan +
Sort to become Index Scan with no Sort node and `Rows Removed by Filter` → 0. Correctness guard:
`retention/runner_test.go` AI-usage cleanup assertions on rows-deleted-per-cutoff must stay green.

### MAJOR — Cache-miss AI request fans out into ~6 separate single-statement transactions; two writes hit the same `ai_usage_counters` row in different transactions
**Location:** `internal/api/ai.go:107-168` (nlSearch), `:284-356` (summarize);
helpers `internal/store/ai.go` (`GetAICache`, `IncrementAIUsage`, `GetAIQuotaOverride`,
`UpdateAIUsageTokens`, `PutAICache`, `InsertAIRequestLog`); tx helpers `store.go:48,126`.
**Problem:** A cache-miss NL-search executes, in order, six store calls — `GetAICache`,
`IncrementAIUsage`, `GetAIQuotaOverride` (via `resolveAIQuotaLimit`), `UpdateAIUsageTokens`,
`PutAICache`, `InsertAIRequestLog` — each opening its own transaction
(`BEGIN`/`SET LOCAL`/query/`COMMIT`). With simple-protocol pgx that is ~4 round-trips apiece,
~24 round-trips per cache-miss call (summarize adds `GetCVE`). Notably `IncrementAIUsage`
(UPSERT, `ai_usage.sql:4`) and `UpdateAIUsageTokens` (UPDATE, `:16`) touch the **same**
`(org_id, feature, CURRENT_DATE)` row in two separate transactions, doubling the write
round-trips and the row-version churn (each UPDATE is an MVCC dead tuple) on the single
hottest quota row per org/day.
**Impact:** Reachable on every uncached AI call (cache hit path is lean: `GetAICache` +
`InsertAIRequestLog` = 2 tx). The LLM network call dominates *latency*, so this is not a
user-latency emergency — but it is real connection-pool occupancy and write amplification on a
hot row (two dead tuples per call on `ai_usage_counters`, plus `IncrementAIUsage` already
churns it once). At AI-feature scale the round-trip count and the per-call dead-tuple rate are
the cost. Token counts genuinely aren't known until the LLM returns, so increment-then-update
can't be fully collapsed, but `UpdateAIUsageTokens` can be merged into `PutAICache`'s
transaction (both post-LLM writes) — and the override read can be folded into the increment.
**Confidence:** Strong-static (each helper is its own `withOrgTx`; tx helpers confirm
per-call BEGIN/SET LOCAL/COMMIT).
**Effort:** Contained — batch the post-LLM writes (`UpdateAIUsageTokens` + `PutAICache`,
optionally `+ InsertAIRequestLog`) into one org-tx; fold the override lookup into the increment
UPSERT's `RETURNING`. Touches `store/ai.go` + the two `ai.go` handlers.
**Verification plan:** Count transactions per request path (static) before/after; confirm the
hot-row UPDATE count per call drops from 2 tx to 1. Correctness guard: `api/ai_test.go`
quota-enforcement + token-accounting assertions and `store/ai_test.go` usage-counter tests
stay green; quota decrement-on-LLM-failure path must still run in isolation.

### MINOR — Every digest report re-scans the whole corpus; reports sharing a (since, severity) window do redundant identical scans, and the report's `watchlist_ids` never narrow the scan
**Location:** `internal/notify/digest.go:107-175` (`executeDigestReport`),
`internal/store/queries/cves.sql:166-184` (`DigestCVEs`).
**Problem:** `DigestCVEs(since, severities)` scans `cves` on
`date_modified_canonical > since` (served by `cves_date_modified_canonical_idx`,
`migrations/000002:45`) but applies **no org/watchlist filter** — it returns up to 500
corpus-wide rows. `executeDigestReport` passes only `since` + expanded severity; the report's
`WatchlistIDs` are loaded but never used to scope the query. Two consequences: (1) the scan is
broader than the report needs (full corpus rather than watchlist-matching CVEs), and (2) when
several reports across orgs share the same `since`/severity window in one tick, each runs an
independent, near-identical scan + `CASE severity` sort — N scans where the corpus slice could
be fetched once and fanned out. The `CASE severity` sort is not index-orderable, so each call
also pays a sort (bounded by `LIMIT 500`).
**Impact:** Reachable per due report per tick (≤10/tick). Per occurrence: one index-range scan
(sargable, good) + a non-indexed sort of the matched set, capped at 500 rows — bounded, so the
absolute cost is modest. The redundancy (N reports → N identical scans) and the unfiltered
breadth are the real waste; both grow with report count. Lower rank because `LIMIT 500` caps
the per-scan blast radius and the sort input.
**Confidence:** Heuristic for the redundancy (depends on how many reports share a window per
tick); Strong-static that watchlist scoping is absent from the query.
**Effort:** Contained — to dedup, group claimed reports by `(since-bucket, severities)` and
share one `DigestCVEs` result; to scope, push watchlist membership into the query (join the
watchlist CVE set). The watchlist gap is also a suspected correctness bug (below) — fixing it
*reduces* rows scanned/returned, so it doubles as the perf fix.
**Verification plan:** `EXPLAIN (ANALYZE)` confirms the range scan + sort shape; count
`DigestCVEs` invocations per tick before/after dedup. Correctness guard: `notify/digest_test.go`
and `store/notification_delivery_test.go` DigestCVEs ordering/filter tests stay green; add a
test that a report with `watchlist_ids` excludes non-watchlist CVEs once scoping lands.

### MINOR — Org-scoped retention DELETEs (`alert_events`, `notification_deliveries`) sort across orgs on a single-column date index
**Location:** `retention.sql:20-34` (`CleanupAlertEvents`, `CleanupNotificationDeliveries`);
indexes `migrations/000016:90` `alert_events (first_fired_at)`,
`migrations/000017:156` `notification_deliveries (created_at)`.
**Problem:** These filter `org_id = ANY(@org_ids) AND <date> < cutoff ORDER BY <date> LIMIT batch`.
The date index is single-column, so Postgres scans it in date order and filters `org_id = ANY`
post-fetch (`Rows Removed by Filter` for orgs not in the batch's group). With retention grouped
by window, `org_ids` is usually most/all orgs, so the filter discards little — the single-column
date index is close to optimal here and the `ORDER BY <date>` is satisfied directly by the index
(no extra sort). `audit_log` already has the better `(org_id, created_at)` composite
(`migrations/000027:19`); the asymmetry is only a mild concern when a window group is a small org
subset.
**Impact:** Reachable per retention pass; bounded by `LIMIT batch` per iteration. The date index
makes the predicate sargable and the order free — cost is the post-fetch `org_id` filter on rows
outside the group. Minor because grouping usually makes the group ≈ all orgs.
**Confidence:** Strong-static on the index shapes; Heuristic on the filter-discard magnitude
(depends on per-window org distribution).
**Effort:** Localized — optional composite `(org_id, first_fired_at)` /
`(org_id, created_at)` if profiling shows large `Rows Removed by Filter`; weigh the added
write cost on these high-churn tables before adding.
**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` the CTE with a small `org_ids` array vs all
orgs; only add the composite if `Rows Removed by Filter` is large. Correctness guard: retention
tests for org-scoped tables stay green.

---

## Things checked and found OK (so they aren't re-flagged)

- **Retention batch shape**: every cleanup uses `CTE SELECT … ORDER BY <col> LIMIT batch` +
  `DELETE … USING doomed`, looped with a deadline and a 0-row break (`runner.go:169-200`). This
  is the correct bounded-batch pattern — bounded lock duration, no million-row single DELETE,
  no `OFFSET`. No finding.
- **AI cache lookup/upsert**: `GetAICache` filters the full key `(org_id, feature,
  prompt_version, input_hash)` + `expires_at > now()`, served by unique
  `ai_cache_lookup_idx` (`migrations/000020`-era `migrations/.../ai_cache` `ai_cache_lookup_idx`).
  `PutAICache` is `ON CONFLICT … DO UPDATE … WHERE … IS DISTINCT FROM` — avoids no-op writes
  (no dead tuple when unchanged). Good shapes. No finding.
- **`ai_request_log` write**: a single INSERT per AI call (one row, one tx). Indexed on
  `created_at` and `org_id` for retention/queries. Expected per-call cost; not amplified beyond
  the one tx already counted in the AI-fanout finding. No separate finding.
- **`DigestCVEs` range predicate** is sargable on `cves_date_modified_canonical_idx`; the only
  cost is the non-index `CASE severity` sort, capped at `LIMIT 500` (covered in the MINOR above).

---

## Suspected Bugs (for follow-up)

- **Digest reports ignore `watchlist_ids` entirely.** `executeDigestReport`
  (`internal/notify/digest.go:107-175`) loads `report.WatchlistIDs` (the field exists on the row
  and the create/patch API accepts it, `api/reports.go:28,38`) but `DigestCVEs`
  (`store/notification_delivery.go:219`, `cves.sql:166`) is only passed `since` + `severities`.
  A report scoped to specific watchlists therefore digests the **entire corpus** matching its
  severity/since, not just its watchlisted CVEs. Looks like the watchlist filter was specified
  but never wired into the query. In-scope for this lane only insofar as fixing it *narrows*
  every report's scan (see MINOR #3); the behavioral correctness is a follow-up for the owning
  team.
- **`ai_summary` report flag appears unused in the digest path.** `executeDigestReport` builds
  the payload directly from `DigestCVEs` rows and never branches on `report.AiSummary`; no LLM
  summarization call is made in the digest runner. Possibly intentional (AI summary applied at
  render time) but worth confirming — flagging, not chasing.
</content>
</invoke>
