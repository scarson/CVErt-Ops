---
name: feed-adapter
description: Scaffold a new CVE feed adapter implementing the FeedAdapter interface with all required safety patterns from PLAN.md §3.2. Use when adding a new vulnerability data source.
argument-hint: "<feed-name> (e.g., nvd, osv, ghsa, mitre, kev, epss)"
allowed-tools: Read, Write, Glob, Grep
---

# Feed Adapter Scaffold

Scaffolding a CVErt Ops feed adapter for: **$ARGUMENTS**

## Step 1: Reference existing adapters

Glob `internal/feed/**/*.go` and read 1–2 existing adapters for style and structure conventions. Check `internal/feed/` for shared utilities (null byte stripping, time parsing) already defined.

## Step 2: Determine adapter type

**Standard feed** (NVD, MITRE, GHSA, OSV, KEV): implements `FeedAdapter` → returns `[]CanonicalPatch`
**Enrichment feed** (EPSS only): does NOT implement `FeedAdapter` → returns `[]EnrichmentPatch` with just `{cve_id, epss_score, as_of_date}`

---

## Step 3: Create `internal/feed/<name>/adapter.go`

### Core interface (standard adapters)

```go
type FeedAdapter interface {
    Fetch(ctx context.Context, cursor json.RawMessage) (*FetchResult, error)
}

type FetchResult struct {
    Patches    []CanonicalPatch
    RawPayload json.RawMessage
    SourceMeta SourceMeta
    NextCursor json.RawMessage // nil if no more pages
}
```

---

## Step 4: Required safety patterns — ALL must be present

### 4.1 Null byte stripping (REQUIRED — Postgres rejects \x00)
```go
func stripNullBytes(s string) string {
    return strings.ReplaceAll(s, "\x00", "")
}

func stripNullBytesJSON(b []byte) []byte {
    return bytes.ReplaceAll(b, []byte{0}, []byte{})
}
```
Apply `stripNullBytes` to every extracted string field. Apply `stripNullBytesJSON` to every raw JSON payload before DB write.

### 4.2 Timestamp parsing fallback (REQUIRED — feed timestamps are inconsistent)
```go
var timeLayouts = []string{
    time.RFC3339Nano,
    time.RFC3339,
    "2006-01-02T15:04:05",
    "2006-01-02",
}

func parseTime(s string) time.Time {
    for _, layout := range timeLayouts {
        if t, err := time.Parse(layout, s); err == nil {
            return t
        }
    }
    return time.Time{} // graceful zero — never panic
}
```
Never call `time.Parse(time.RFC3339, val)` directly on feed data.

### 4.3 Polymorphic JSON fields (REQUIRED — feed schemas drift across history)
Fields that may be a string, object, or array in different records must use `json.RawMessage`:
```go
type rawField struct {
    raw json.RawMessage
}

func extractStringFromPolymorphic(raw json.RawMessage) string {
    if len(raw) == 0 { return "" }
    switch raw[0] {
    case '"':
        var s string
        json.Unmarshal(raw, &s)
        return s
    case '[':
        var arr []json.RawMessage
        if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
            return extractStringFromPolymorphic(arr[0])
        }
    case '{':
        var obj struct{ Value string `json:"value"` }
        json.Unmarshal(raw, &obj)
        return obj.Value
    }
    return ""
}
```

### 4.4 String field cloning (REQUIRED — prevents retaining large JSON buffers in GC)
After extracting string fields from a large JSON byte slice:
```go
cveID = strings.Clone(cveID)
description = strings.Clone(description)
```
Apply to all string fields extracted from bulk JSON payloads before the source buffer is discarded.

### 4.5 Per-adapter rate limiter (REQUIRED — not shared globally)
```go
type Adapter struct {
    client      *http.Client
    rateLimiter *rate.Limiter
    // ...
}
```
Configure the limiter based on upstream API constraints. Rate limiters are per-adapter — do not use a single global limiter.

---

## Step 5: Streaming JSON (REQUIRED for large responses)

**Never** `json.Unmarshal(body, &bigSlice)` — buffers entire response.

For feeds with a top-level JSON **object** wrapping an array (NVD, KEV):
```go
dec := json.NewDecoder(resp.Body)
// Navigate to the target array key
for {
    t, err := dec.Token()
    if err != nil { return err }
    if key, ok := t.(string); ok && key == "vulnerabilities" { break } // use actual key name
}
if _, err := dec.Token(); err != nil { return err } // consume opening '['
for dec.More() {
    var record FeedRecord
    if err := dec.Decode(&record); err != nil { return err }
    // process one record
}
if _, err := dec.Token(); err != nil { return err } // consume closing ']'
```

For feeds with **ZIP archives** (MITRE bulk, OSV bulk): stream HTTP body to a temp file first (`os.CreateTemp`), then use `zip.NewReader(f, info.Size())`. Loop over `zr.File` entries with **explicit** `rc.Close()` — NOT `defer rc.Close()` inside the loop (closes all FDs at function return, exhausting ulimit).

---

## Step 6: Feed-specific patterns

### NVD adapter
- **Rate limiting:** 6s/request (no `NVD_API_KEY` env var) or 0.6s (with key). Check at init.
- **Auth header:** `req.Header.Set("apiKey", key)` — case-sensitive lowercase `a`. Not `"ApiKey"` or `"X-API-Key"`.
- **Query params:** Always construct with `url.Values` + `.Encode()`. The `+` in timezone offsets must become `%2B`. Direct string concatenation sends literal `+` → NVD reads as space → 400.
- **Cursor overlap:** `lastModStartDate = last_success_cursor - 15 minutes` to catch eventual-consistency stragglers.
- **Cursor upper bound:** Use the `Date` response header from NVD, not `time.Now()` (clock skew in Docker containers).
- **120-day window limit:** If gap > 120 days, chunk into sequential ≤120-day windows.
- **Per-page cursor:** Save `startIndex` to `feed_sync_state`, not just the date cursor.

### OSV/GHSA adapters
- **Alias resolution (REQUIRED — prevents split-brain records):**
  ```go
  func resolveCanonicalID(nativeID string, aliases []string) string {
      cvePattern := regexp.MustCompile(`^CVE-\d{4}-\d+$`)
      for _, alias := range aliases {
          if cvePattern.MatchString(alias) { return alias }
      }
      return nativeID
  }
  ```
  If a CVE alias is found, use it as `cve_id`. Native ID becomes `source_id` metadata.

- **Withdrawn tombstoning (REQUIRED):** If record has non-null `withdrawn` (OSV) or `withdrawn_at` (GHSA), set `status = 'withdrawn'` AND explicitly NULL out `cvss_v3_score`, `cvss_v4_score`, `cvss_v3_vector`, `cvss_v4_vector`, `epss_score`. A simple partial upsert leaves historical critical scores on retracted advisories.

- **Late-binding PK migration:** Check if an incoming record has a CVE alias but the DB already has it under the native ID. If so, call `store.MigrateCVEPK(ctx, nativeID, canonicalCVEID)` before upserting.

### EPSS adapter
The EPSS adapter uses a two-statement pattern with an advisory lock (see PLAN.md §5.3):

```go
// Acquire advisory lock (same key as merge pipeline)
_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", cveAdvisoryKey("cve:"+cveID))

// Statement 1: update cves if CVE exists AND score changed
// Statement 2: insert to epss_staging if CVE does not exist in cves
// Do NOT inspect RowsAffected — logic is DB-side
```

---

## Step 7: Advisory lock (merge pipeline)

The merge pipeline serializes per CVE ID:
```go
import "hash/fnv"

func cveAdvisoryKey(cveID string) int64 {
    h := fnv.New64a()
    h.Write([]byte("cve:" + cveID)) // domain-prefixed
    return int64(h.Sum64())
}

// In the merge transaction:
_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", cveAdvisoryKey(cveID))
```
Each CVE merge is its own transaction. No multi-CVE batch transaction.

---

## Step 8: Create `internal/feed/<name>/adapter_test.go`

Include tests for:
- Null byte handling (input with `\x00` → stored without it)
- Timestamp parsing edge cases (ISO 8601 without `Z`, date-only)
- Alias resolution (for OSV/GHSA: record with CVE in aliases uses CVE as PK)
- Withdrawn/rejected record handling (scores nulled out)
- Streaming parse (verify only one record in memory at a time — mock small fixture)
- Rate limiter is configured and non-nil

Use recorded HTTP response fixtures, not live API calls.
