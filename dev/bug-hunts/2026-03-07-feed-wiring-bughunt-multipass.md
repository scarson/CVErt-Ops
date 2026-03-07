# Bug Hunt Report — Feed Wiring (Multipass)

**Date:** 2026-03-07
**Branch:** feed-wiring
**Method:** Five-pass multipass analysis (contract, cross-sibling, failure mode, concurrency, error propagation)

## Scope

Packages analyzed (source files only, no tests):

- `internal/ingest/` — handler.go, feeds.go, epss.go, scheduler.go
- `internal/feed/` — interface.go, util.go
- `internal/feed/nvd/` — adapter.go
- `internal/feed/kev/` — adapter.go
- `internal/feed/mitre/` — adapter.go
- `internal/feed/ghsa/` — adapter.go
- `internal/feed/osv/` — adapter.go
- `internal/feed/msrc/` — adapter.go
- `internal/feed/redhat/` — adapter.go
- `internal/feed/epss/` — adapter.go
- `internal/merge/` — pipeline.go, resolve.go, advisory.go, hash.go
- `internal/store/` — feed.go, jobs.go
- `internal/worker/` — pool.go, job.go
- `internal/api/` — feeds.go
- `cmd/cvert-ops/` — main.go (registration wiring)

All five passes were performed.

## Bugs

### 1. InsertFeedFetchLog silently drops StartedAt and EndedAt — all fetch logs show zero duration

**Location:** internal/store/feed.go:78-90, internal/store/queries/feed.sql (InsertFeedFetchLog)
**Severity:** significant
**Found in:** Pass 1 — Contract Violations

**Evidence:** The SQL INSERT for `feed_fetch_log` (generated at `internal/store/generated/feed.sql.go:36-41`) does not include `started_at` in its column list and hardcodes `ended_at` to `now()`:

```sql
INSERT INTO feed_fetch_log (
    feed_name, status, items_fetched, items_upserted,
    cursor_before, cursor_after, error_summary, ended_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
```

The `started_at` column uses `DEFAULT now()` from the schema. The `FeedFetchLog` domain struct has both `StartedAt` and `EndedAt` fields that the handler carefully populates (e.g., `handler.go:136-145` sets `StartedAt: start` and `EndedAt: &now`), but the store method at `feed.go:80-88` never passes these to the generated params.

**Impact:** Every `feed_fetch_log` row has `started_at ≈ ended_at ≈ INSERT time`. Duration is always ~0ms regardless of actual fetch duration. For NVD (multi-page pagination taking minutes), MITRE/OSV (ZIP download + parse), or EPSS (250k row CSV processing), the timing data is meaningless. The admin UI's feed status view (`FeedLogEntry.StartedAt`/`EndedAt` at `api/feeds.go:36-37`) renders these incorrect values. Any SLA monitoring or performance analysis built on these logs would report all fetches as instantaneous.

---

### 2. Sync state and fetch log persistence errors silently discarded on success path

**Location:** internal/ingest/handler.go:157,165 and internal/ingest/epss.go:73,81
**Severity:** significant
**Found in:** Pass 5 — Error Propagation

**Evidence:** Both the feed handler and EPSS handler use `_ =` to discard errors from `UpsertFeedSyncState` and `InsertFeedFetchLog` on the **success** path:

```go
// handler.go:157 (success path)
_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{...})
// handler.go:165
_, _ = st.InsertFeedFetchLog(ctx, store.FeedFetchLog{...})
```

The handler then returns `nil` (success), causing the worker pool to mark the job as `completed`.

**Impact:** If cursor persistence fails after a successful multi-page fetch (e.g., transient DB error, connection pool exhaustion), the cursor is not saved. The job is marked as completed and won't be retried. On the next scheduled run, the feed re-processes from the old cursor — potentially re-downloading and re-merging thousands of CVEs. For NVD initial backfill (250k+ CVEs, hours of work across many windows), this could lose the entire run's progress. The IS DISTINCT FROM guards prevent data corruption but not wasted work.

The failure path (`handler.go:127,136`) also discards these errors, but that's less impactful — the handler is already returning the fetch error. The real risk is the success path, where the handler reports success but the cursor wasn't actually saved.

---

### 3. GHSA adapter fetches all pages internally — no mid-pagination cursor persistence

**Location:** internal/feed/ghsa/adapter.go:115-130
**Severity:** significant
**Found in:** Pass 1 — Contract Violations

**Evidence:** The `Adapter` interface contract at `interface.go:12-13` states: "Fetch returns one page of canonical patches and a cursor for the next page." The GHSA adapter's `Fetch()` violates this by internally looping through ALL GitHub API pages:

```go
for {
    if err := a.rateLimiter.Wait(ctx); err != nil {
        return nil, fmt.Errorf("ghsa: rate limit: %w", err)
    }
    page, nextAfter, err := a.fetchPage(ctx, sinceStr, after)
    if err != nil {
        return nil, err
    }
    patches = append(patches, page...)
    if nextAfter == "" {
        break
    }
    after = nextAfter
}
```

It always returns `LastPage: true` and a single combined result.

**Impact:** Three consequences:
1. **No crash recovery**: If the process crashes on page 50 of 100, all 49 pages of work are lost. The cursor hasn't been persisted mid-run.
2. **Unbounded memory**: All GHSA advisories (~55k+ reviewed advisories, each with description/references/vulnerabilities) accumulate in `[]feed.CanonicalPatch` in memory before any merge processing begins.
3. **All-or-nothing failure**: A single GitHub API error or rate limit on page 50 fails the entire run — the handler has no partial result to persist.

This contrasts with NVD and Red Hat, which correctly return one page per `Fetch()` call, allowing the handler to persist cursor progress between pages.

---

### 4. KEV adapter hard-fails on single malformed record (deviation from sibling pattern)

**Location:** internal/feed/kev/adapter.go:220-223
**Severity:** minor
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

**Evidence:** The KEV parser returns a hard error when a single record fails to decode:

```go
for dec.More() {
    var rec kevRecord
    if err := dec.Decode(&rec); err != nil {
        return nil, "", "", fmt.Errorf("decode record: %w", err)
    }
```

All other adapters with streaming JSON arrays (NVD, GHSA) use `continue` to skip malformed individual records:

```go
// NVD (adapter.go:394-397):
if err := dec.Decode(&wrapper); err != nil {
    continue  // skip malformed records
}
```

**Impact:** If CISA publishes a KEV catalog with a single malformed entry (e.g., a null byte in a string field that breaks JSON parsing), the entire KEV feed is blocked. The adapter retries with exponential backoff, failing each time on the same record. The remaining ~1200 KEV entries are not processed.

This is minor because: (a) CISA's KEV catalog is well-maintained and very rarely has structural issues, (b) a JSON syntax error mid-array would likely break all subsequent decoding regardless of skip-vs-fail behavior. However, `json.UnmarshalTypeError` (Go type mismatch) is recoverable and would benefit from `continue`.

---

## Design Concerns

### Scheduler TOCTOU on job deduplication (benign but worth noting)

The scheduler's `maybeEnqueue` at `scheduler.go:102-113` checks `HasPendingOrRunningJob` then calls `EnqueueJob` non-atomically. A concurrent scheduler tick (in a multi-replica deployment) could pass the check and enqueue a duplicate job. This is safe because: (a) lock keys prevent concurrent execution, (b) feed processing is idempotent via IS DISTINCT FROM guards. No fix needed, but the dedup is advisory rather than strict.

### NVD terminal-page cursor loses one window of progress

When NVD's final page returns `NextCursor = nil`, the handler persists `lastSuccessfulCursor` from the previous page — which points to the START of the last window. On the next scheduled run, that window is re-fetched and re-processed unnecessarily (one redundant API call + IS DISTINCT FROM no-ops). This is the correct safe behavior (no data loss), but every NVD run ends with one wasted re-fetch of the final window.

### DownloadToTemp has no size limit for ZIP archives

`feed.DownloadToTemp` at `util.go:157` uses `io.Copy(f, resp.Body)` with no upper bound. Used by MITRE (~2 GB ZIP) and OSV (~500 MB ZIP), this is intentional for legitimate archives. But a compromised or misconfigured upstream could serve an infinite stream, filling disk. All other feed adapters apply `io.LimitReader` on their responses. A reasonable cap (e.g., 5 GB) would match the safety pattern without breaking legitimate archives.

### EPSS per-row failure blocks entire feed (edge case)

If `applyRow` at `epss/adapter.go:219` encounters a persistent per-row DB error, the entire EPSS feed is blocked. Each retry re-downloads the 15 MB CSV and replays ~250k no-op IS DISTINCT FROM writes before hitting the same failing row. The adapter correctly skips CSV parse errors (line 211-216) but does not skip DB-level errors. DB errors typically indicate broader connectivity issues where failing fast is appropriate, so this is the correct default behavior — but a poison-row scenario (e.g., CVE ID exceeding column width) would require manual intervention.