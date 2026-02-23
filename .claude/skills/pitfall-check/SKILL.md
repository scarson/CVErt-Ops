---
name: pitfall-check
description: Check Go code against implementation-pitfalls.md to catch documented mistakes before they reach production. Use before committing significant business logic, especially feed adapters, merge pipeline, alert evaluation, or delivery workers.
argument-hint: "[file-path or package path — omit to check files in conversation context]"
allowed-tools: Read, Glob, Grep
---

# Implementation Pitfall Check

Reviewing CVErt Ops code against documented pitfalls.

Target: **$ARGUMENTS** (or the file/code already in conversation context)

## Steps

**1. Load the reference:** Read `implementation-pitfalls.md` — the numbered list and summary tables.

**2. Load the target code:** Read the specified file(s). If given a package path (e.g., `internal/feed/nvd`), glob all `*.go` files in it.

**3. Check each category systematically:**

For each category below, state ✅ (no issues), ❌ (issue found), or N/A (not applicable to this code).

---

### Database / PostgreSQL

- **`defer` inside loops:** Any `defer rc.Close()`, `defer rows.Close()` etc. inside a `for` loop body? `defer` executes at function return, not loop iteration — exhausts file descriptors or DB connections. Look for loops over ZIP entries (`range zr.File`) or DB result rows with defer inside.

- **`time.After` in goroutine loops:** Any `case <-time.After(d):` inside a `for { select { ... } }` loop? Allocates a new Timer per iteration that isn't GC'd until it fires. Use `time.NewTicker` with `defer ticker.Stop()`.

- **Dynamic `IN` clause with positional params:** Any `WHERE col IN ($1, $2, ..., $N)` built by looping? Panics at 65,536 params. Should be `WHERE col = ANY($1::text[])` with a slice parameter.

- **`json.Decode(&slice)` on large feeds:** Any `json.NewDecoder(r).Decode(&bigSlice)`? Buffers the full document in memory. Must use the streaming `Token()` + `More()` loop for large feeds.

- **JSONB upsert TOAST bloat:** Any `ON CONFLICT DO UPDATE SET jsonb_col = EXCLUDED.jsonb_col` without a `WHERE jsonb_col IS DISTINCT FROM EXCLUDED.jsonb_col`? Writes TOAST entry even when content is unchanged.

- **`CREATE INDEX` without `CONCURRENTLY`:** Any bare `CREATE INDEX` in `.sql` files? Takes an exclusive table lock. Must be `CREATE INDEX CONCURRENTLY`.

---

### Feed Adapters

- **Null bytes not stripped:** Any string field written to DB without `strings.ReplaceAll(s, "\x00", "")`? Postgres TEXT/JSONB rejects null bytes.

- **Fixed struct for polymorphic JSON:** Any field decoded directly as `string` or `struct` that might be a string, object, or array in different records? Must use `json.RawMessage` + first-byte dispatch.

- **`time.Parse(time.RFC3339, val)` directly on feed data:** Feed timestamps are inconsistent. Must use the multi-layout fallback parser from PLAN.md §3.2.

- **NVD `apiKey` header casing:** Is it `req.Header.Set("apiKey", key)` (lowercase `a`)? Not `"ApiKey"`, `"API-Key"`, or `"X-API-Key"`. The NVD API is case-sensitive.

- **NVD timestamp query params:** Are timestamp params added via `url.Values.Set()` + `.Encode()`? The `+` in RFC3339 timezone offsets must be percent-encoded (`%2B`). String concatenation sends literal `+` which NVD reads as a space.

- **OSV/GHSA alias resolution:** Is there a `resolveCanonicalID(nativeID, aliases)` call that promotes a CVE ID from aliases to be the primary key? Without this, OSV and NVD records for the same CVE create two separate rows.

- **OSV/GHSA withdrawn tombstoning:** When `withdrawn` or `withdrawn_at` is set, does the adapter NULL out CVSS scores and set `status = 'withdrawn'`? A simple partial upsert preserves historical critical scores on retracted advisories.

- **String field cloning after bulk JSON parse:** Any string field extracted from a large JSON buffer without `strings.Clone(field)`? The extracted string holds a reference to the multi-MB backing array, preventing GC.

---

### Security

- **JWT parser missing `WithValidMethods`:** Any `jwt.ParseWithClaims` or `jwt.Parse` call without `jwt.WithValidMethods([]string{"HS256"})`? Enables algorithm confusion attacks (`alg: none`, RS256→HS256).

- **JWT parser missing `WithExpirationRequired`:** Any JWT parse without `jwt.WithExpirationRequired()`? Accepts tokens with no `exp` claim as permanently valid.

- **API key timing oracle:** Any hash comparison using `==`, `bytes.Equal`, or `strings.Compare`? Must be `subtle.ConstantTimeCompare`. Short-circuit comparison enables timing attacks.

- **Open DB transaction during outbound HTTP:** Any code that holds a `pgx.Tx` open while calling an outbound HTTP endpoint (webhook, Slack)? Holds a Postgres connection for the full 10s timeout duration, exhausting the pool.

- **SSRF — outbound HTTP not wrapped:** Any `http.Client` used for webhook delivery that is NOT a `doyensec/safeurl`-wrapped client? Allows internal network access.

---

### Concurrency

- **`errgroup` for notification fan-out:** Any `g.Go(func() error { return sendToChannel(ch) })` pattern in the notification delivery path? If one channel fails, `errgroup` cancels the context and aborts all sibling sends. Must use `sync.WaitGroup` with independent per-channel error recording.

- **`r.Context()` passed to background goroutine:** Any `go func() { doWork(r.Context()) }()` spawned from an HTTP handler? `r.Context()` is cancelled when the handler returns. Must use `context.WithoutCancel(r.Context())`.

- **`defer` inside long loops (reminder):** See Database section — same risk applies to any loop, not just DB-related ones.

---

### Alert Evaluation

- **Nil dereference on optional CVE fields:** Any direct dereference of `*float64` or `*int` CVE fields (CVSS score, EPSS) without a nil check? Must use nil-safe accessor functions.

- **Regex without SQL prefilter:** Any alert rule using `regex` operator that isn't guarded by at least one SQL-side filter (severity, watchlist, date window, CISA KEV, affected ecosystem)? Regex must be a post-filter on a bounded candidate set.

- **`alert_events` insert without dedup guard:** Any `INSERT INTO alert_events` that doesn't use `ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING RETURNING id`? Concurrent workers fire duplicate notifications.

- **Dry-run path that commits `alert_events`:** Any dry-run code path that doesn't unconditionally ROLLBACK (or use a read-only code path)? A committed dry-run poisons the dedup baseline.

- **Rejected CVE filtering missing:** Any evaluation query missing `AND cves.status NOT IN ('rejected', 'withdrawn')`? Rejected CVEs trigger spurious alerts when NVD strips their scores.

---

### Pagination

- **Missing `cve_id` tiebreaker:** Any `WHERE sort_col < $last_val ORDER BY sort_col DESC` without `cve_id` as a tiebreaker? Feed batch updates create groups of identical timestamps; without a tiebreaker, rows at page boundaries are silently dropped.

- **Nullable sort column without COALESCE:** Any keyset cursor on a nullable column (e.g., `epss_score`, `date_published`) using `WHERE col < $val` without `COALESCE`? `NULL < $val` evaluates to NULL (false) — all NULL rows vanish from pagination.

---

## Output Format

For each ❌:
```
❌ <Category> — <pitfall name>
   File: path/to/file.go:line
   Code: <the problematic snippet>
   Risk: <what goes wrong>
   Fix:  <correct pattern>
```

End with: **Found N issues across M categories.** (or "No issues found.")
