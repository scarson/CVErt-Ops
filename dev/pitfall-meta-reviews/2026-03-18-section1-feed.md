# Section 1: Feed Adapters & Data Ingestion

> **Reader context:** I'm building or reviewing a feed adapter.
>
> This section covers every known pitfall in feed parsing, upstream API integration, cursor management, and data normalization. Each entry documents a failure mode that was caught during architectural review or implementation — and would have caused production failures if shipped.

---

### FEED-1: JSON Feed Wire Format Assumption

**The Flaw:** The streaming pattern used `Decode(&slice)` or assumed all feeds return top-level JSON arrays. A prescriptive `Token()`+`More()` loop was written as if NVD returned `[{...}, {...}]`.

**Why It Matters:** NVD API 2.0 returns `{"resultsPerPage":2000,"vulnerabilities":[{...}]}` — a top-level JSON object. A loop that tries to read this as a direct array fails immediately or silently produces wrong results. `json.NewDecoder(r).Decode(&bigSlice)` also reads the entire stream into memory before returning — there is no streaming benefit when decoding into a slice. On a 500 MB NVD annual file this OOM-crashes the server.

**The Fix:** Each adapter must use the appropriate wire format pattern:
- **NVD / CISA KEV (JSON object with nested array):** Use `Token()` to navigate to the target key (`"vulnerabilities"`), then enter the `More()` loop on the nested array. Consume both `[` and `]` tokens explicitly.
- **MITRE / OSV bulk (ZIP archives):** Use the temp-file bridging pattern (see FEED-2).
- **`Decode(&slice)` is unconditionally forbidden** for any response or file that could be large.

The correct pattern for a top-level JSON object with a nested array:
```go
dec := json.NewDecoder(resp.Body)
for {
    t, err := dec.Token()
    if err != nil { return err }
    if key, ok := t.(string); ok && key == "vulnerabilities" {
        break
    }
}
if _, err := dec.Token(); err != nil { return err } // consume '['
for dec.More() {
    var record FeedRecord
    if err := dec.Decode(&record); err != nil { return err }
    // process one record at a time
}
if _, err := dec.Token(); err != nil { return err } // consume ']'
```

> **WARNING:** Do NOT use `continue` after a `json.Decoder.Decode()` error. After `Decode` returns an error, the decoder's internal state is undefined. Subsequent calls to `More()` and `Decode()` may skip or garble valid records. Either abort the feed or manually consume tokens to resync.

**The Lesson:** Always verify a feed's actual wire format before writing the parser. Vulnerability feed APIs are rarely top-level JSON arrays. The "obvious" streaming pattern is often wrong. Verify with `curl | jq 'keys'` before writing a single line of adapter code.

---

### FEED-2: archive/zip Requires a Seekable Reader — Cannot Stream Over HTTP

**The Flaw:** The plan said to use `archive/zip` for MITRE (cvelistV5) and OSV bulk archives. The initial prescriptive text didn't address the fundamental interface constraint.

**Why It Matters:** `archive/zip.NewReader` requires `io.ReaderAt` (seekable, random access) plus the total byte count. An HTTP response body is `io.ReadCloser` — a forward-only stream that satisfies neither. The "obvious" fix of `io.ReadAll()` into `*bytes.Reader` would OOM-crash the server on a multi-GB MITRE archive. There is no way to stream a ZIP file directly over HTTP without first materializing it on disk.

**The Fix:** Stream the HTTP body to a temporary disk file first:
```go
f, err := os.CreateTemp("", "cvert-bulk-*.zip")
if err != nil { return err }
defer os.Remove(f.Name())
defer f.Close()
if _, err := io.Copy(f, resp.Body); err != nil { return err }
info, err := f.Stat()
if err != nil { return err }
zr, err := zip.NewReader(f, info.Size()) // os.File implements io.ReaderAt
if err != nil { return err }
for _, entry := range zr.File {
    rc, err := entry.Open()
    if err != nil { return err }
    var record AdvisoryRecord
    if err := json.NewDecoder(rc).Decode(&record); err != nil { rc.Close(); return err }
    rc.Close()
    // process record
}
```
For local file paths (`import-bulk` CLI), skip the temp file — pass the local `os.File` directly to `zip.NewReader`.

**The Lesson:** Go's `archive/zip` and `archive/tar` have different reader interfaces. ZIP requires seekable access to read the central directory at the end of the file. Any code that processes ZIP archives from HTTP must account for this. `io.ReadAll()` for large files is never the answer — always ask "what is the interface this library actually requires?" before writing the integration.

---

### FEED-3: Custom Timestamp Fallback Parser

**The Flaw:** Feed adapters called `time.Parse(time.RFC3339, val)` directly on feed timestamp fields.

**Why It Matters:** Feed timestamps are inconsistent across historical records and sources. Older NVD records, MITRE CVEs, and some GHSA advisories use ISO 8601 variants that violate RFC 3339 (missing timezone `Z`, space instead of `T`, irregular fractional seconds). `time.RFC3339` is strict; on any violation it returns a `*time.ParseError`, which aborts the struct decoding and hard-fails the transaction for that CVE. That CVE becomes a "poison pill" that permanently blocks the sync pipeline on retry.

**The Fix:** Implement a multi-layout fallback parser used for all feed timestamp fields:
```go
var timeLayouts = []string{
    time.RFC3339Nano, time.RFC3339,
    "2006-01-02T15:04:05", "2006-01-02",
}
func parseTime(s string) time.Time {
    for _, layout := range timeLayouts {
        if t, err := time.Parse(layout, s); err == nil { return t }
    }
    return time.Time{} // graceful zero — never panic
}
```

**The Lesson:** Feed data is not spec-compliant. Never use `time.RFC3339` directly on external data. Implement a fallback parser and treat unparseable timestamps as `time.Time{}` (zero value) rather than hard-failing the entire CVE ingestion.

---

### FEED-4: Polymorphic JSON Field Type Variance

**The Flaw:** Feed adapters defined struct fields with fixed Go types for fields that can appear as an object, array, or string across historical records.

**Why It Matters:** A field that is normally `{"description": "X"}` in modern NVD records appeared as `[{"description": "X"}]` in older records. Go's `json.Unmarshal` returns `json.UnmarshalTypeError` when the JSON type doesn't match the Go type. This aborts the entire CVE decode, causing that CVE to be a permanent sync blocker.

**The Fix:** For volatile fields, unmarshal into `json.RawMessage` and dispatch on the first byte:
```go
type ProblemType struct {
    Raw json.RawMessage
}
func (p *ProblemType) UnmarshalJSON(data []byte) error {
    p.Raw = data
    return nil
}
// At use site: if bytes.HasPrefix(p.Raw, []byte("[")) { /* array */ } else { /* object */ }
```

> **Status:** Preventive guidance. Current feeds are spec-compliant and this pattern hasn't been needed yet. Keep in mind for future adapters or when processing historical data.

**The Lesson:** Historical vulnerability feed records do not conform to current schemas. Any struct field that might vary in type across historical and current records must use `json.RawMessage` and runtime type detection. Never assume structural consistency in external feed data.

---

### FEED-5: `defer` Inside a Loop Exhausts File Descriptors — ZIP Archive Iteration

**The Flaw:** The OSV/MITRE ZIP iteration loop used `defer rc.Close()` to close each archive entry's reader.

**Why It Matters:** In Go, `defer` statements are pushed onto a per-function stack and execute only when the **surrounding function returns** — not when the loop iteration ends. The OSV `all.zip` contains 100,000+ individual advisory files. Using `defer rc.Close()` inside the loop body holds all 100,000 file descriptors open simultaneously. The Go runtime hits the OS-level `ulimit -n` (typically 1024 or 65535) within seconds and crashes the worker process with `too many open files`. This is one of the most common and highest-severity Go bugs — the code compiles cleanly, passes code review, and only fails at runtime under production-scale data.

**The Fix:** Use explicit `rc.Close()` at every loop exit path — both error return and normal success. Never use `defer` for resources that must be released per-iteration:
```go
for _, entry := range zr.File {
    rc, err := entry.Open()
    if err != nil { return err }
    var record AdvisoryRecord
    err = json.NewDecoder(rc).Decode(&record)
    rc.Close() // explicit, not defer — releases fd immediately
    if err != nil { return err }
    // process record
}
```
If the inner loop body is complex, extract it into a named helper function and use `defer` inside that function — the defer then fires at the helper's return, releasing the fd after each iteration.

**The Lesson:** `defer` is function-scoped, not block-scoped. Using `defer` for cleanup inside loops is a resource-leak footgun that Go developers encounter repeatedly. The fix is a one-word change (`defer` → explicit call), but requires understanding the exact semantics. For any loop that opens closeable resources (files, network connections, DB rows), always ask: "does this `defer` fire at the end of the loop iteration, or at the end of the function?"

---

### FEED-6: URL Query `+` Is Parsed as Space — Timestamp URL Encoding

**The Flaw:** The NVD adapter constructed query string parameters using string concatenation: `"?lastModStartDate=" + t.Format(time.RFC3339)`.

**Why It Matters:** `time.RFC3339` formatting for a UTC timestamp produces `2026-02-19T12:00:00+00:00`. In HTTP query strings, the `+` character is the URL-encoding of a space character (per the `application/x-www-form-urlencoded` spec). The NVD server receives `lastModStartDate=2026-02-19T12:00:00 00:00` — a malformed timestamp with a literal space — and returns `400 Bad Request`. The NVD incremental sync fails permanently on every run, stopping all CVE updates.

**The Fix:** Always construct URL query parameters using `url.Values`, which percent-encodes `+` as `%2B`:
```go
q := url.Values{}
q.Set("lastModStartDate", startTime.UTC().Format("2006-01-02T15:04:05.000+00:00"))
q.Set("lastModEndDate",   endTime.UTC().Format("2006-01-02T15:04:05.000+00:00"))
req.URL.RawQuery = q.Encode() // '+' → '%2B', space → '%20'
```
Never use string concatenation for URL parameters that may contain `+`, `&`, `=`, `#`, or non-ASCII characters.

**The Lesson:** In HTTP query strings, `+` means space, and `%2B` means `+`. This encoding trap bites any code that uses `time.RFC3339` formatting with timezone offsets in URL parameters. `url.Values` and `url.QueryEscape` exist precisely for this reason. Raw string concatenation into a URL query is always wrong for any value that might contain special characters.

---

### FEED-7: OSV ZIP FileHeader Parsed Without Pre-filter — Entire Archive Re-processed Every Incremental Sync

**The Flaw:** The ZIP iteration loop for OSV/MITRE bulk archives called `entry.Open()` unconditionally for every file in the archive, then checked timestamps inside the parsed JSON to decide whether the record was new.

**Why It Matters:** OSV's `all.zip` and MITRE's `cvelistV5.zip` each contain 100,000+ individual JSON files. `archive/zip.FileHeader.Modified` is available without opening the entry — it is read from the ZIP central directory when `zip.NewReader` loads the archive. For an incremental sync (daily run after initial bulk load), only ~50 files in the archive have changed since yesterday's cursor. Calling `entry.Open()` on all 100,000+ entries and parsing JSON just to find those 50 wastes ~2,000x the necessary I/O and CPU. On a constrained self-hosted machine this can take minutes per sync cycle, holding a database transaction open and blocking other feed updates.

**The Fix:** Check `entry.FileHeader.Modified.After(lastCursor)` **before** calling `entry.Open()`. The central directory contains this metadata at no additional I/O cost:
```go
for _, entry := range zr.File {
    // Skip entries unmodified since last sync without opening them
    if !lastCursor.IsZero() && !entry.FileHeader.Modified.After(lastCursor) {
        continue
    }
    rc, err := entry.Open()
    // ... parse and process
}
```
For a full `import-bulk` run `lastCursor` is the zero `time.Time`, so `lastCursor.IsZero()` is true and the pre-filter is a no-op — all entries are processed.

**The Lesson:** ZIP archives expose file metadata (name, size, modification time, compression method) in the central directory without requiring each entry to be opened. Always check available metadata before performing I/O. For incremental processing of large archives, a single timestamp comparison can eliminate 99.9% of redundant work. Never assume that "checking inside" is the only option when the file system or archive format provides a pre-filter.

---

### FEED-8: strings.Clone Required for Fields Extracted from Large JSON Buffers

Streaming decoders (`json.Decoder`), `gjson`, and `csv.Reader` with `ReuseRecord` share backing byte buffers. When `Decode()` or `gjson.Get()` returns a string field, that string is a sub-slice of the decoder's internal buffer. Storing that string long-term (e.g., in a `CanonicalPatch` that outlives the decode loop) pins the entire backing buffer in memory — the GC cannot reclaim it because a live string reference points into it. For a 200 MB NVD response, a single retained CVE ID string prevents the GC from freeing the full 200 MB.

**Fix:** Call `strings.Clone()` on all string fields before storing them in output structs. The `feed.CloneStrings()` helper handles string slices. The EPSS adapter correctly clones CSV fields. The generic adapter's `mapRecord()` function uses `gjson.Get(raw, path).String()` without cloning — this is the one remaining gap. When writing or reviewing any adapter, ALWAYS clone string fields extracted from shared buffers before returning them.

---

### FEED-9: Bulk Import Is Required — API Polling Cannot Handle Initial Population

**The Flaw:** The initial plan used normal incremental API polling to populate a fresh instance.

**Why It Matters:** NVD API rate limits (5 req/30s with API key, ~2000 results/page) make a from-scratch API sync of the full historical corpus (250k+ CVEs) take many hours under ideal conditions, and any network error or API downtime forces a retry from an earlier cursor. This makes a fresh instance unusable until polling catches up.

**The Fix:** Feeds with bulk archive sources (OSV GCS bucket, MITRE cvelistV5 ZIP) use the `cvert-ops import-bulk` CLI subcommand for initial load through the same merge pipeline as incremental polling. After bulk import, the feed cursor is initialized to a timestamp just before the archive's "as-of" date, and normal incremental polling takes over. **NVD does not offer bulk download files** — their [developer documentation](https://nvd.nist.gov/developers/start-here) recommends iterative API calls with `startIndex` pagination. NVD initial population uses the adapter's normal paginated sync with chunked <=120-day windows (see FEED-10). This is slow but there is no alternative.

> **Status:** CLI stub exists (`cmd/cvert-ops/main.go`), implementation pending.

**The Lesson:** Design the initial data population path explicitly. API rate limits that are tolerable for incremental updates are often prohibitive for full-corpus initial loads. Where bulk archives exist, provide a "bulk load from archive" path separate from the "incremental sync" path, and share the downstream pipeline to avoid divergence. Where they don't (NVD), accept the slow initial sync and design the adapter's cursor chunking to handle it.

---

### FEED-10: NVD API 120-Day Query Window Hard Limit

**The Flaw:** The NVD API 2.0 rejects date-range queries spanning more than 120 days with `403 Forbidden`. This is undocumented in NVD's primary API docs but encountered in production.

**Why It Matters:** After a 5-month shutdown, the adapter constructs a single query spanning 150 days. Every attempt returns `403`. The worker retries the same invalid query indefinitely. NVD sync is permanently broken until a human intervenes.

**The Fix:** The NVD adapter MUST chunk any time range exceeding 120 days into sequential <=120-day windows with separate API requests, iterating until `time.Now()`.

**The Lesson:** Upstream API constraints not in primary documentation will be encountered in production. Build adapters assuming "unusual" date ranges (after shutdown, after bulk import) will occur. The cursor system must accommodate chunked window iteration.

---

### FEED-11: NVD Dual Rate Limits Require Dynamic Configuration

**The Flaw:** NVD enforces 5 req/30s unauthenticated vs 50 req/30s with API key. Neither rate works universally.

**Why It Matters:** (a) Hardcode the fast rate — unauthenticated users get IP-banned during initial backfill. (b) Hardcode the slow rate — API key users wait hours for a minutes-long backfill.

**The Fix:** The NVD adapter configures its rate-limiting ticker at startup based on `NVD_API_KEY` presence: 6-second delay if absent, 0.6-second if present.

**The Lesson:** Dual-rate APIs (unauthenticated/authenticated) require dynamic configuration based on credential presence. Never hardcode either rate.

---

### FEED-12: OSV/GHSA Native IDs as Primary Keys Create Split-Brain Vulnerability Records

**The Flaw:** OSV and GHSA advisories use their own native identifier formats (`GHSA-xxxx-xxxx-xxxx`, `GO-2024-1234`, `PYSEC-2024-12`, etc.). The "obvious" implementation stores these records using the native ID as the `cve_id` primary key.

**Why It Matters:** NVD ingests `CVE-2024-56789` and creates a canonical row keyed on `CVE-2024-56789`. OSV later ingests `GO-2024-1234` (whose `aliases` array contains `"CVE-2024-56789"`) using `GO-2024-1234` as the primary key. The database now has two separate rows for the same vulnerability — one from NVD, one from OSV. The merge pipeline never joins them because it operates on a single `cve_id` primary key. The canonical `cves` row from NVD has no OSV package data, version ranges, or severity scores. Alert rules evaluating the CVE ID find only the NVD row. The OSV row is an orphan that nothing queries. No error — just permanently wrong data.

**The Fix:** OSV and GHSA adapters MUST inspect the `aliases` field of each record before determining the primary key:
```go
func resolveCanonicalID(nativeID string, aliases []string) string {
    cvePattern := regexp.MustCompile(`^CVE-\d{4}-\d+$`)
    for _, alias := range aliases {
        if cvePattern.MatchString(alias) {
            return alias // use CVE ID as canonical primary key
        }
    }
    return nativeID // no CVE alias; store under native ID
}
```
The native ID is stored as `cve_sources.source_id` for provenance tracking.

**The Lesson:** When a system has a canonical primary key (CVE ID) and multiple data sources use different identifier namespaces for the same entity, adapters MUST perform identifier resolution before storage — not after. Storing under the native ID and "resolving later" never gets implemented. The merge pipeline must operate on a single canonical key from the moment of first insert. Alias arrays in feed data exist precisely for this purpose; ignoring them creates permanently fragmented records.

---

### FEED-13: NVD API Key Header Is Case-Sensitive `apiKey`

The NVD API 2.0 requires its API key in a custom HTTP header named `apiKey` — not `Authorization: Bearer`, not `Api-Key`, not `API-KEY`. Go's `net/http` canonicalizes header names by default (`apiKey` becomes `Apikey`), which NVD rejects silently by applying unauthenticated rate limits. Fix: `req.Header.Set("apiKey", key)` with an inline `//nolint:canonicalheader` suppression. Without this, authenticated requests are throttled at the unauthenticated rate with no error message indicating why.

---

### FEED-14: NVD Overlapping Cursor Gap — Eventual Consistency Guard

NVD's backend is eventually consistent. Using the exact `lastModEndDate` from the previous sync as the next `lastModStartDate` can miss CVEs that were committed between the query execution and the cursor snapshot. Fix: `lastModStartDate = last_cursor - 15 minutes`. The 15-minute overlap causes some CVEs to be re-fetched, but the merge pipeline's `material_hash` check makes re-processing idempotent. Without this overlap, CVEs modified during the consistency window are silently lost.

---

### FEED-15: NVD Cursor Upper Bound from Server Time

Using `time.Now()` as the cursor upper bound (`lastModEndDate`) introduces clock skew between the application server and NVD's backend. If the app server's clock is ahead of NVD's, the query window extends past NVD's "now" — future modifications within that window are never re-queried. Fix: extract the `Date` response header from NVD API responses and use it as the cursor upper bound instead of local `time.Now()`. This guarantees the cursor tracks NVD's own clock.

---

### FEED-16: OSV/GHSA Withdrawn Field Must Be Checked

OSV advisories have a `withdrawn` timestamp field; GHSA advisories have `withdrawn_at`. If these fields are non-null, the advisory has been retracted — the vulnerability was a false positive, duplicate, or otherwise invalid. An adapter that ignores these fields keeps withdrawn vulnerabilities live in the corpus, generating false-positive alerts. Fix: check `withdrawn != nil` / `withdrawn_at != null` in the adapter; set `status = "withdrawn"` and `IsWithdrawn = true` on the canonical patch. The merge pipeline tombstones withdrawn CVEs by NULLing scores and CPEs so they fall out of alert evaluation.

---

### FEED-17: Late-Binding Alias Split-Brain — PK Migration Required

**The Flaw:** An OSV/GHSA advisory is initially ingested without a CVE alias — `GHSA-xxxx-xxxx-xxxx` is used as the primary key. Later, MITRE assigns a CVE ID and the advisory's `aliases` array gains `CVE-2026-9999`. The adapter's `resolveCanonicalID()` (FEED-12) handles this correctly for *new* records, but the existing record is already stored under the native PK.

**Why It Matters:** The database now has a `GHSA-xxxx` row (from the first ingest) and the adapter wants to write a `CVE-2026-9999` row (from the update). Without PK migration, one of two things happens: (a) the adapter creates a second row, producing split-brain — two records for the same vulnerability that the merge pipeline never joins, or (b) the adapter matches on the native ID and updates the existing row, but the `cve_id` PK remains `GHSA-xxxx` while every other source uses `CVE-2026-9999` — the merge pipeline cannot correlate cross-source data.

**The Fix:** The adapter MUST detect this case (existing record with native PK, incoming payload has a CVE alias for that native ID) and execute a PK migration atomically. This means renaming the `cve_id` in `cves`, `cve_sources`, `cve_references`, `cve_affected_packages`, `cve_affected_cpes`, `alert_events`, `cve_annotations`, and all other tables that reference the CVE ID. This is a multi-table cascading rename; use a database function or carefully ordered updates to avoid FK violations.

**The Lesson:** Alias resolution at ingest time (FEED-12) prevents split-brain for records that already have a CVE alias. But advisories that *gain* a CVE alias after initial ingest require a PK migration path. Without it, every advisory that predates its CVE assignment is permanently fragmented. This is not an edge case — GHSA advisories routinely gain CVE aliases days or weeks after initial publication.

---

### FEED-18: GHSA Rate Limiting — 1 req/sec with Token Support

GitHub's GraphQL API enforces rate limits per token (5,000 points/hour). The GHSA adapter MUST limit concurrency to 1 concurrent request with a minimum 1-second inter-request delay. On HTTP 429 responses, honor the `Retry-After` header. Without rate limiting, a full GHSA sync during initial backfill exhausts the hourly quota within minutes, and subsequent requests fail for the remainder of the hour.

---

### FEED-19: Internal Pagination Defeats Crash Recovery

**The Flaw:** An adapter loops through all upstream API pages internally and returns `LastPage: true` with all results combined in a single `FetchResult`.

**Why It Matters:** A crash on page 50 of 100 loses all work from pages 1-49 — nothing was persisted. All results accumulate in memory across pages (unbounded growth). A single API error on any page fails the entire run, discarding all successfully-fetched pages.

**The Fix:** Return one page per `Fetch()` call. The ingestion handler persists each page's results and updates the cursor before requesting the next page. If the process crashes, it resumes from the last persisted cursor instead of restarting from scratch.

**The Lesson:** Internal pagination defeats the handler's crash recovery mechanism. When an adapter fetches all pages internally, the handler cannot persist intermediate progress. Always return one logical page per adapter call and let the handler own the persistence lifecycle.

---

### FEED-20: Response Body Must Be Drained After json.Decoder

**The Flaw:** `json.NewDecoder(resp.Body).Decode(&v)` reads only enough bytes to decode one JSON value. The remaining bytes in the response body are left unread.

**Why It Matters:** HTTP/1.1 connection reuse (`keep-alive`) requires the response body to be fully consumed before the connection can be returned to the pool. An undrained body forces `http.Transport` to close the TCP connection and open a new one (with full TCP + TLS handshake) for the next request. For adapters making hundreds of sequential API calls, this turns a pooled-connection workload into a connection-per-request workload — multiplying latency and resource consumption.

**The Fix:** After `Decode`, drain the remaining body before closing:
```go
defer resp.Body.Close()
if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
    return err
}
_, _ = io.Copy(io.Discard, resp.Body)
```

**The Lesson:** `json.Decoder` does not consume the entire response body — it reads only what it needs. Always drain the remainder with `io.Copy(io.Discard, resp.Body)` before `Close()`. This applies to ALL outbound HTTP responses, not just feed adapter calls.

---

### See Also
- Feed adapter data seeded in tests: see testing-pitfalls.md §9 (Feed Data Quality)
- Null byte sanitization in DB layer: see DB-10 (PostgreSQL Null Byte Poisoning)
- Array field sorting for material_hash: see DB-23 (Array Fields Sorted Before Hash)

---

### Review Checklist

When building or reviewing a feed adapter, verify each of the following:

- [ ] **Wire format verified** — checked the actual API response structure with `curl | jq 'keys'` before writing the parser (FEED-1)
- [ ] **No `Decode(&slice)`** — streaming uses `Token()`+`More()` loop, never decodes into a slice (FEED-1)
- [ ] **Decoder errors abort** — no `continue` after `json.Decoder.Decode()` error; decoder state is undefined after error (FEED-1)
- [ ] **ZIP via temp file** — HTTP response bodies streamed to disk before `zip.NewReader`, never `io.ReadAll` (FEED-2)
- [ ] **Timestamp fallback parser** — all feed timestamps parsed via multi-layout fallback, never raw `time.RFC3339` (FEED-3)
- [ ] **No `defer` in loops** — archive iteration uses explicit `Close()` at every exit path (FEED-5)
- [ ] **URL params via `url.Values`** — no string concatenation for query parameters (FEED-6)
- [ ] **ZIP pre-filter** — `FileHeader.Modified.After(lastCursor)` checked before `entry.Open()` (FEED-7)
- [ ] **`strings.Clone` on extracted fields** — all string fields from shared decoder/gjson buffers cloned before storing (FEED-8)
- [ ] **Canonical ID resolution** — OSV/GHSA records use CVE alias as PK when available; native ID stored as `source_id` (FEED-12)
- [ ] **PK migration for late aliases** — adapter detects when existing native-PK record gains a CVE alias and triggers atomic PK rename (FEED-17)
- [ ] **Withdrawn field checked** — `withdrawn` / `withdrawn_at` non-null sets status to "withdrawn" (FEED-16)
- [ ] **NVD API key header** — `req.Header.Set("apiKey", key)` with `//nolint:canonicalheader` (FEED-13)
- [ ] **NVD cursor overlap** — `lastModStartDate = last_cursor - 15 minutes` (FEED-14)
- [ ] **NVD cursor upper bound** — uses `Date` response header, not `time.Now()` (FEED-15)
- [ ] **NVD 120-day chunking** — time ranges exceeding 120 days split into sequential windows (FEED-10)
- [ ] **Rate limiter dynamic** — rate configured based on API key presence (FEED-11)
- [ ] **One page per Fetch()** — adapter returns one logical page; handler persists between pages (FEED-19)
- [ ] **Response body drained** — `io.Copy(io.Discard, resp.Body)` after `json.Decoder` use (FEED-20)
