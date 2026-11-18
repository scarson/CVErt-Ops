# S6 Reports / AI / Retention — Algorithmic complexity & data-structures lane

ABOUTME: Performance audit (algorithmic lane) of the reports/AI/retention slice.
ABOUTME: Examines orchestration data structures, batching, and corpus-aggregation complexity — not model latency.

**Scope read:** `internal/ai/{ai,gemini,sanitize,quota,schema}.go`; `internal/retention/runner.go`;
`internal/store/{scheduled_report,ai,retention}.go`; `internal/api/{reports,ai}.go`;
`internal/notify/digest.go` (the actual report-generation path — `internal/report/` is empty, generation
lives in the digest worker); supporting SQL in `internal/store/queries/{retention,ai_cache,cves,scheduled_reports,report_channels}.sql`
and the relevant migrations.

**Lane framing:** AI calls are an external-process boundary; I audited the orchestration (cache-key
structure, quota resolution, prompt-sanitization scan), not model latency. Retention is bounded-batch
DELETE. Reports are scheduled-digest aggregation. I assumed a global corpus of ~250k CVEs and
potentially large `audit_log` / `notification_deliveries` / `alert_events` / `ai_request_log` tables.

---

## Findings

### MINOR — Digest worker re-scans the global CVE corpus once per due report with no window/severity reuse
**Location:** `internal/notify/digest.go:87-98` (`runDigest`) → `:107-124` (`executeDigestReport` → `w.store.DigestCVEs`); SQL `internal/store/queries/cves.sql:166-184`
**Problem:** `runDigest` claims up to 10 due reports per tick and loops, issuing one `DigestCVEs(since, severities)`
query per report. Each query is an independent index-range scan over the shared global `cves` table.
Reports overwhelmingly cluster at round times (09:00 UTC is the obvious default), so a single tick frequently
runs N near-identical scans of the same corpus slice that differ only in the per-report `since` cutoff
(`COALESCE(last_run_at, created_at)`) and severity set. There is no shared materialization of "CVEs modified
since T0" across the batch.
**Impact:** Reachability: digest tick is periodic and unconditional. Frequency: N = number of due reports in
the tick (bounded at 10 by `ClaimDueReports(ctx, 10)`). Per-occurrence cost: each scan is an index-range walk
on `cves_date_modified_canonical_idx` bounded by `LIMIT 500` + an in-SQL CASE sort — *not* a full-table scan,
so the absolute cost is modest. The aggregate cost is N× a bounded index scan, with the redundancy capped at
10/tick. Because the per-report `since` cutoffs genuinely differ, the scans cannot be trivially deduplicated
into one query; the only real win (a single `date_modified_canonical > min(since)` scan filtered in-process per
report) trades a clean SQL boundary for in-Go fan-out filtering. Given the `LIMIT 500` cap and the 10-report
batch ceiling, this is a bounded-n situation, so I rank it MINOR / design-remark rather than a clear win.
**Confidence:** Strong-static (loop structure and per-report query are explicit; index + LIMIT bound the cost).
**Effort:** Contained — would require a batched "fetch corpus window once, partition by report in Go" path in
the digest worker plus a new store method; touches `digest.go` and `store`. Not justified at the current
10-report ceiling.
**Verification plan:** Complexity argument — current cost is `O(R · (log C + 500))` per tick for R due reports
over corpus C; a shared-scan rewrite is `O(log C + W)` where W is the union window size, but only pays off when
R is large and windows overlap heavily, which the 10-cap and distinct cutoffs prevent. Correctness guard:
`TestRunDigest`/`executeDigestReport` tests must continue to assert each report receives exactly the CVEs in its
own `[since, now]` window at its own severity threshold — any shared-scan rewrite must preserve per-report
window isolation.

---

## Items examined and cleared (not findings)

- **AI response cache lookup** (`internal/store/queries/ai_cache.sql:4-7`, `store/ai.go:175`): keyed by a
  composite `(org_id, feature, prompt_version, input_hash)` backed by a **UNIQUE B-tree index**
  (`ai_cache_lookup_idx`, migration 000021). Lookups are O(log n) index probes, not linear scans. The cache key
  is a single `sha256` of the query / `cve_id+material_hash` (`api/ai.go:97,277`) — O(len) once per request, not
  per-iteration. No linear-membership or nested-map antipattern. Clean.

- **Prompt sanitization** (`internal/ai/sanitize.go`): two package-scope `regexp.MustCompile` patterns (compiled
  once, not in a loop) plus a single `strings.Builder` rune loop with `b.Grow(len(s))` pre-sizing. Runs only on
  cache-miss summarize requests over a single CVE description (bounded, small). No O(n²) string building, no
  per-call recompilation. Correctly structured.

- **Schema-description / prompt-version build** (`internal/ai/schema.go`): guarded by `sync.Once`; the sort and
  `strings.Builder` assembly run exactly once per process. `PromptVersion()` returns a memoized hash. No
  per-request recomputation.

- **Retention bounded-batch DELETEs** (`internal/store/queries/retention.sql`): every cleanup uses the correct
  `WITH doomed AS (SELECT id ... ORDER BY ts LIMIT @batch_size) DELETE ... USING doomed` pattern. No large
  in-memory ID list is built in Go — the ID set lives inside one SQL statement and is bounded by `batch_size`.
  The runner loop (`runner.go:169-200`) accumulates only a running `int64` counter, never the deleted rows.
  Deadline + zero-rows break conditions are correct. This is the textbook shape; no algorithmic issue.

- **Tier-gated retention grouping** (`runner.go:113-163`, `groupByRetentionDays`): one pass over all orgs
  building `map[int][]uuid.UUID` (group orgs by retention-days), then one batched DELETE loop per distinct
  window using `org_id = ANY(@org_ids::uuid[])`. This is O(orgs) grouping + O(distinct-windows) delete loops —
  far better than the naive per-org DELETE loop it replaces. `ListAllOrgs` is one query; `Overrides` JSON is
  unmarshalled once per org. Correctly designed. (See suspected design remark below on index support for the
  multi-org ordered DELETE.)

- **Digest payload assembly** (`digest.go:132-159`): `snaps := make([]cveSnapshot, len(cves))` is pre-sized;
  single linear pass; one `json.Marshal`. Channel-insert loop (`:168-172`) is O(channels). No quadratic work.

- **Reports CRUD handlers** (`api/reports.go`): pure per-request CRUD; watchlist-ID parsing loops are over
  user-supplied small arrays. `validSeverityThresholds` is a map lookup. Nothing aggregates the corpus in Go.

---

## Suspected Bugs (for follow-up)

None. (No correctness issues observed in this lane; the one design remark below is a performance note, not a bug.)

### Design remark (performance, not a finding): multi-org ordered retention DELETE index support
The tier-gated DELETEs filter `org_id = ANY(array) AND ts < cutoff ORDER BY ts LIMIT batch`. `alert_events` and
`notification_deliveries` have **separate single-column** indexes on `org_id` and on the timestamp
(`alert_events_first_fired_at_idx`, `notification_deliveries_created_at_idx`), so Postgres can scan the
timestamp index in `ORDER BY` order and recheck `org_id = ANY(...)` per row — acceptable. `audit_log` has a
**composite** `(org_id, created_at)` index (`audit_log_org_created_idx`) but no standalone `created_at` index, so
the cross-org `ORDER BY created_at` cannot be served in index order by that composite for an `ANY(array)` set and
may fall back to a heap scan + sort when the array spans many orgs. This is a data-access concern (index design),
flagged here only because it's adjacent to the grouping logic in this lane; the data-access lane should confirm
the chosen plan. No action recommended from the algorithmic lane.
