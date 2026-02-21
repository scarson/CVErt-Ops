# CVErt Ops — Implementation Pitfalls & Review Findings

> **Date:** 2026-02-21
> **Source:** 8 rounds of Gemini Pro architectural review of PLAN.md before implementation began
> **Purpose:** Document implementation traps, design flaws, and corrected decisions as a learning artifact for future development and similar projects.

---

## How to Read This Document

This document captures issues caught during pre-implementation architectural review that would have caused production failures, security vulnerabilities, or data correctness bugs if they had shipped. Each finding includes:

- **The Flaw** — what the original design said
- **Why It Matters** — the failure mode if shipped as written
- **The Fix** — what PLAN.md now specifies
- **The Lesson** — the generalizable principle

Issues are organized by category, not by review round.

---

## 1. Go Implementation Traps

### 1.1 JSON Feed Wire Format Assumption

**The Flaw:** The streaming pattern used `Decode(&slice)` or assumed all feeds return top-level JSON arrays. A prescriptive `Token()+More()` loop was written as if NVD returned `[{...}, {...}]`.

**Why It Matters:** NVD API 2.0 returns `{"resultsPerPage":2000,"vulnerabilities":[{...}]}` — a top-level JSON object. A loop that tries to read this as a direct array fails immediately or silently produces wrong results. `json.NewDecoder(r).Decode(&bigSlice)` also reads the entire stream into memory before returning — there is no streaming benefit when decoding into a slice. On a 500 MB NVD annual file this OOM-crashes the server.

**The Fix:** Each adapter must use the appropriate wire format pattern:
- **NVD / CISA KEV (JSON object with nested array):** Use `Token()` to navigate to the target key (`"vulnerabilities"`), then enter the `More()` loop on the nested array. Consume both `[` and `]` tokens explicitly.
- **MITRE / OSV bulk (ZIP archives):** Use the temp-file bridging pattern (see 1.2).
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

**The Lesson:** Always verify a feed's actual wire format before writing the parser. Vulnerability feed APIs are rarely top-level JSON arrays. The "obvious" streaming pattern is often wrong. Verify with `curl | jq 'keys'` before writing a single line of adapter code.

---

### 1.2 archive/zip Requires a Seekable Reader — Cannot Stream Over HTTP

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

### 1.3 GitHub Does Not Support OIDC

**The Flaw:** Section 7.2 specified `coreos/go-oidc/v3` for both GitHub and Google OAuth without distinguishing between them.

**Why It Matters:** GitHub does not implement OpenID Connect. It has no `.well-known/openid-configuration` discovery endpoint. Calling `oidc.NewProvider(ctx, "https://github.com")` returns a 404 immediately, failing at provider initialization before any user interaction occurs. An AI coding assistant given the spec as written would implement a GitHub OIDC flow that fails in every environment at the very first request.

**The Fix:** The implementation is split by provider:

| Provider | Library | Identity extraction |
|---|---|---|
| **Google** | `coreos/go-oidc/v3` (OIDC) | ID token claims: `sub`, `email`, `email_verified` |
| **GitHub** | `golang.org/x/oauth2` only (raw OAuth 2.0) | `GET https://api.github.com/user` (for numeric user ID) + `GET https://api.github.com/user/emails` (for primary verified email) |
| **Future enterprise OIDC** | `coreos/go-oidc/v3` | Configurable discovery URL |

GitHub-specific flow: exchange code for token → call `/user` and `/user/emails` APIs → find the entry with `primary: true, verified: true` → upsert `user_identities`.

**The Lesson:** "OAuth" and "OIDC" are not interchangeable. OIDC adds an ID token and a `.well-known/openid-configuration` discovery endpoint on top of OAuth 2.0. GitHub supports OAuth 2.0 only. Always verify a provider's documentation before choosing a library. Many popular OAuth providers (GitHub, Twitter/X, Stripe) do not implement OIDC.

---

### 1.4 GitHub OAuth Scope Blackhole — `/user/emails` Requires `user:email` Scope

**The Flaw:** Section 7.2 correctly specified calling `https://api.github.com/user/emails` to retrieve the primary verified email after GitHub OAuth, but did not specify which OAuth scope grants that access.

**Why It Matters:** GitHub's default OAuth flow grants read access to public profile data only. The `/user/emails` endpoint requires the `user:email` scope to be explicitly requested. Without it, the endpoint returns an empty array for any GitHub user whose email is set to private — which is the GitHub default setting. This permanently blocks signup for the majority of GitHub users. An AI implementing `oauth2.Config` with standard defaults omits this scope entirely.

**The Fix:** The GitHub `oauth2.Config` must explicitly include `user:email`:
```go
githubOAuthConfig := &oauth2.Config{
    ClientID:     cfg.GitHubClientID,
    ClientSecret: cfg.GitHubClientSecret,
    RedirectURL:  cfg.GitHubCallbackURL,
    Endpoint:     github.Endpoint,
    Scopes:       []string{"user:email"}, // REQUIRED — do not omit
}
```
Note: `read:user` alone is insufficient. `user:email` is the specific scope for `/user/emails` access.

**The Lesson:** OAuth scopes control API access, and provider defaults are never "read everything." Always check the specific endpoint's documentation for required scopes — do not assume the default OAuth grant covers all the API calls you plan to make. For GitHub specifically, `/user/emails` is a separate permission from basic profile access and must be explicitly requested.

---

## 2. Database & Query Pitfalls

### 2.1 EPSS Unconditional UPDATE Writes 250k Dead Tuples Daily

**The Flaw:** Section 5.3 said `epss_score` is "always updated unconditionally on every EPSS adapter run."

**Why It Matters:** The EPSS CSV feed contains ~250,000 rows daily. If the adapter issues `UPDATE cves SET epss_score = $1, date_epss_updated = now() WHERE cve_id = $2` for every row, it writes 250,000 new dead tuples to Postgres via MVCC daily — even when 99% of scores are identical to the stored value. The dedicated EPSS rule evaluator uses `date_epss_updated > last_cursor` to find CVEs with new data; bumping this timestamp for unchanged scores forces it to re-evaluate all 250,000 CVEs against every active alert rule daily, for zero benefit.

**The Fix:** Use `IS DISTINCT FROM` to make the write conditional:
```sql
UPDATE cves
SET epss_score = $1, date_epss_updated = now()
WHERE cve_id = $2 AND epss_score IS DISTINCT FROM $1
```
`IS DISTINCT FROM` is NULL-safe: `NULL IS DISTINCT FROM 0.5` → true (write proceeds); `NULL IS DISTINCT FROM NULL` → false (write suppressed). Only genuinely changed scores write a new tuple.

**The Lesson:** In Postgres, every UPDATE on a row writes a new physical tuple via MVCC — even if the value being set is identical to the current value. For high-frequency enrichment feeds that touch hundreds of thousands of rows daily, always use `WHERE col IS DISTINCT FROM new_value` to suppress no-op writes. This pattern applies to any column used as a cursor for downstream processing.

---

### 2.2 FTS GIN Index Write Churn from High-Frequency Column Updates

**The Flaw:** The initial design put `fts_document tsvector` directly on the `cves` table alongside canonical fields that are updated frequently (timestamps, epss_score).

**Why It Matters:** Postgres MVCC writes a new physical row tuple on every UPDATE to any column. The `cves` table is updated frequently — timestamps on every ingestion, `epss_score` on every daily EPSS run. Every such update forces GIN index maintenance for `fts_document`, even when the text content hasn't changed. GIN indexes are expensive to update. At scale, this becomes significant write amplification on a globally-shared table.

**The Fix:** Isolate `fts_document` in a dedicated 1:1 table `cve_search_index(cve_id text PK REFERENCES cves, fts_document tsvector NOT NULL)`. The merge function only writes to `cve_search_index` when text-contributing fields (description, CWE titles) actually change. Timestamp and score updates to `cves` never touch the GIN index. Search queries use a JOIN.

**The Lesson:** In Postgres, put high-churn columns (timestamps, scores, counters) and expensive-to-index columns (GIN, tsvector, JSONB) in separate tables whenever they live on the same logical entity. Any UPDATE to any column on a row triggers index maintenance for all indexed columns on that row. If a column is indexed but rarely changes, isolating it avoids write amplification from the columns that change constantly.

---

### 2.3 Advisory Lock Hash: Wrong Function + Imprecise Domain Isolation Claim

**The Flaw:** Initial plan used `pg_advisory_xact_lock(hashtext(cve_id))` — a Postgres-internal function — and described domain prefixes as creating "non-overlapping key spaces."

**Two distinct corrections were needed:**

1. **`hashtextextended` / `hashtext` are internal Postgres APIs.** They are partitioning utilities, unavailable or restricted in some managed Postgres environments (RDS, Cloud SQL, etc.). Computing the hash in application code is explicit, testable, and fully portable.

2. **"Non-overlapping key spaces" is mathematically wrong.** Domain prefixes ensure that *identical IDs in different domains* hash to different values (because the inputs differ). They do not create partitioned output spaces — all keys map to the same 64-bit pool. What makes cross-domain collisions negligible is the 64-bit pool size: at 250k+ CVE IDs, the Birthday Paradox probability is effectively zero.

**The Fix:** Compute the advisory lock key in Go with domain-prefixed input:
```go
func advisoryKey(domain, id string) int64 {
    h := fnv.New64a()
    h.Write([]byte(domain + ":" + id))
    return int64(h.Sum64())
}
// Usage: pg_advisory_xact_lock(advisoryKey("cve", cveID))
```

**The Lesson:** Don't rely on database-internal functions for business logic — they are implementation details that may be restricted in managed environments. Compute deterministic hashes in application code. Also: be precise about what domain prefixes actually guarantee. They prevent identical-input cross-domain collisions; they do not create non-overlapping output spaces. Imprecise wording in architectural documents leads to imprecise implementations.

---

### 2.4 RLS `missing_ok` Fail-Closed Blindfolds Background Workers

**The Flaw:** The RLS policy correctly used `current_setting('app.org_id', TRUE)::uuid` with `missing_ok=TRUE`, so unscoped queries (background workers, health checks) return NULL and see 0 rows — intentional fail-closed behavior for API routes.

**Why It Matters:** Background workers (batch alert evaluator, EPSS evaluator, retention cleanup) operate outside any user HTTP session and have no `app.org_id` context. With the fail-closed policy, every worker query returns 0 rows silently: 0 alert rules evaluated, 0 alerts fired, 0 CVEs cleaned up. There is no error — just silent, total inactivity. This failure mode is invisible in logs because the queries succeed; they simply match nothing.

**The Fix:** Add a `app.bypass_rls` session variable to the policy, set only in worker transactions:
```sql
CREATE POLICY org_isolation ON watchlists
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
```
Worker transaction helper (only valid call site):
```go
func workerTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
    tx, _ := pool.Begin(ctx)
    defer tx.Rollback(ctx)
    tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'on'")
    if err := fn(tx); err != nil { return err }
    return tx.Commit(ctx)
}
```
`SET LOCAL` is transaction-scoped; the bypass auto-resets on commit/rollback and cannot leak to subsequent connections. The `WITH CHECK` bypass allows workers to write `alert_events` and `notification_deliveries` on behalf of any org.

**The Lesson:** Any RLS design that is "fail-closed" for unauthenticated queries will also blindfold background processes that legitimately need cross-tenant access. The policy must distinguish between "unauthenticated API caller who should see nothing" and "trusted internal worker who needs to see everything." A transaction-scoped session variable provides this distinction safely; a role-level `BYPASSRLS` attribute is the alternative but is coarser-grained.

---

### 2.5 `RowsAffected == 0` Is Ambiguous After `IS DISTINCT FROM` Guard

**The Flaw:** The EPSS adapter used `IS DISTINCT FROM` in the UPDATE to avoid writing dead tuples for unchanged scores. Go code then checked `RowsAffected() == 0` to decide whether to insert into `epss_staging`.

**Why It Matters:** After adding `IS DISTINCT FROM`, `RowsAffected == 0` has two completely different meanings:
- (A) CVE does not exist in `cves` → score should go to staging
- (B) CVE exists, score unchanged → do nothing

Code implementing `if rowsAffected == 0 { insertIntoStaging() }` inserts 250,000 unchanged EPSS scores into `epss_staging` every day — the exact write amplification the `IS DISTINCT FROM` clause was designed to prevent.

**The Fix:** Never inspect `RowsAffected` for this decision. Instead, run a second SQL statement unconditionally that delegates the existence check entirely to the database:
```sql
-- Statement 1: update if CVE exists AND score changed
UPDATE cves SET epss_score = $1, date_epss_updated = now()
WHERE cve_id = $2 AND epss_score IS DISTINCT FROM $1;

-- Statement 2: insert to staging only if CVE doesn't exist (WHERE NOT EXISTS)
INSERT INTO epss_staging (cve_id, epss_score, as_of_date)
SELECT $2, $1, $3
WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = $2)
ON CONFLICT (cve_id) DO UPDATE
    SET epss_score = EXCLUDED.epss_score,
        as_of_date = EXCLUDED.as_of_date;
```
Both statements run for every CSV row. The database handles all three cases correctly without any Go-side conditional logic.

**The Lesson:** `RowsAffected == 0` is a blunt instrument that becomes ambiguous whenever a WHERE clause can suppress writes for multiple independent reasons. When a SQL guard clause is added (like `IS DISTINCT FROM`), audit all downstream code that branches on `RowsAffected` — the meaning may have changed. Delegating conditional logic to DB-side `WHERE NOT EXISTS` / `ON CONFLICT` / `RETURNING` clauses eliminates ambiguity and reduces round-trips.

---

## 3. Security Vulnerabilities

### 3.1 JWT Algorithm Confusion and `alg: none` Bypass

**The Flaw:** JWT parsing was not explicitly whitelisting the expected signing algorithm.

**Why It Matters:** Permissive JWT parsers enable two critical attacks:
- **Algorithm confusion:** Attacker changes `alg` in the header from RS256 to HS256, then signs with the server's public key used as the HMAC secret. The server verifies the signature — with the wrong key — and accepts the forged token.
- **`alg: none` bypass:** Attacker removes the signature entirely and sets `alg: none`. Naive parsers accept this as a valid unsigned token.

Either attack allows forging arbitrary JWT claims (user ID, org ID, roles) without knowing the signing secret.

**The Fix:**
```go
token, err := jwt.ParseWithClaims(tokenString, &Claims{}, keyFunc,
    jwt.WithValidMethods([]string{"HS256"}),
    jwt.WithExpirationRequired(),
)
```
`WithValidMethods` is mandatory on every parse call, including refresh token validation. `WithExpirationRequired` rejects tokens without an `exp` claim, preventing accidentally-issued non-expiring tokens from remaining permanently valid. The JWT secret must be at minimum 32 cryptographically random bytes, validated at startup.

**The Lesson:** JWT security requires explicit algorithm whitelisting at the parser level. `golang-jwt/jwt/v5` does not enforce this by default. `WithValidMethods` is a non-optional security control. Treat any unguarded `jwt.Parse` or `jwt.ParseWithClaims` call as a critical security bug. Add a static analysis check or linting rule to catch unguarded calls in CI.

---

### 3.2 Argon2id OOM Denial of Service — Concurrency Limiter Required

**The Flaw:** The argon2id configuration was documented (m=19456, t=2, p=1) but no concurrency guard was specified for the login endpoint.

**Why It Matters:** Each argon2id hash operation allocates ~19.5 MB of RAM. Without a concurrency cap, 50 concurrent unauthenticated login requests cause ~975 MB of simultaneous allocation. On the constrained hardware that homelab/self-hosted users run (Raspberry Pi, cheap VPS, shared NAS), this OOM-kills the container. This is a trivially mounted denial-of-service attack requiring no authentication and no special knowledge.

**The Fix:** A global non-blocking semaphore before the hashing function — excess requests are immediately rejected with 503, never queued (see section 3.3 for why blocking is itself a DOS vector):
```go
// Initialized at server startup; configurable via ARGON2_MAX_CONCURRENT (default 5)
var argon2Sem = make(chan struct{}, cfg.Argon2MaxConcurrent)

func acquireArgon2Slot() bool {
    select {
    case argon2Sem <- struct{}{}:
        return true
    default:
        return false // reject immediately — do NOT block
    }
}
```
IP-based rate limiting on the login endpoint is the first line of defense; the semaphore is the backstop that bounds worst-case RAM consumption even if the rate limiter is bypassed.

**The Lesson:** Memory-hard password hashing algorithms are intentionally expensive. The same properties that make them resistant to offline cracking (high memory usage per operation) make them vectors for server-side OOM attacks when called concurrently without a guard. Any time you implement argon2id, bcrypt, or scrypt, add a concurrency limiter. The OWASP parameters are chosen for security, not for handling unbounded concurrent load. See section 3.3 for the critical implementation detail: the semaphore must be non-blocking.

---

### 3.3 Blocking Semaphore Converts OOM-DOS into Connection-Starvation DOS

**The Flaw:** The prescribed argon2id semaphore used a blocking channel send (`sem <- struct{}{}`). The spec text said "excess requests block on the semaphore channel — they do not fail; they queue."

**Why It Matters:** Blocking is not safe. With 1,000 concurrent bad login requests and a semaphore cap of 5:
- 5 goroutines acquire slots and begin hashing
- 995 goroutines block indefinitely on `sem <- struct{}{}`
- Each blocked goroutine holds an open HTTP connection with its associated memory
- This exhausts the server's connection pool and starves all other API endpoints — including endpoints completely unrelated to authentication
- Legitimate users face multi-minute login timeouts while waiting behind the attacker in the queue

The OOM-DOS is fixed but replaced with a connection-starvation Layer 7 DOS of equivalent severity.

**The Fix:** Use a non-blocking `select/default` that immediately rejects requests when all slots are busy:
```go
select {
case argon2Sem <- struct{}{}:
    defer func() { <-argon2Sem }()
default:
    // Return 503 immediately with Retry-After header
    // Never block — blocked goroutines hold HTTP connections
    return huma.Error503ServiceUnavailable("server busy, retry shortly")
}
```
Legitimate users rarely have more than 1–2 simultaneous login attempts. The 503 response with `Retry-After` is the correct signal for a transient capacity constraint.

**The Lesson:** A concurrency gate that blocks rather than rejects converts a resource-exhaustion attack vector into a different resource-exhaustion attack vector. When designing concurrency controls for public-facing endpoints, always prefer fast-fail (reject with 503) over queuing. Queuing is appropriate for internal, bounded workloads — not for endpoints reachable by unauthenticated attackers. The system's overall concurrency is bounded by the connection pool, not by a single endpoint's semaphore.

---

## 4. Operational / UX Footguns

### 4.1 New-Rule Activation Scan Sends Outbound Notifications for Historical Data

**The Flaw:** Section 10.3 specified that the new-rule activation scan "fires alerts for existing matches" so users don't miss CVEs that existed before the rule was created.

**Why It Matters:** A moderately broad rule (`cvss_v3_score >= 9.0 AND affected.ecosystem = "npm"`) could match 5,000+ historical CVEs in the corpus. Firing outbound notifications for all of them would:
- Trigger immediate permanent API bans from Slack (which enforces a 1 msg/sec webhook rate limit)
- Suspend the account from email providers (SendGrid, SES, Postmark) for spam-like behavior
- Flood the user's inbox or channel with thousands of notifications for CVEs that may be years old

**The Fix:** The activation scan runs in **silent mode**. It writes matching CVEs to the `alert_events` table (establishing the dedup baseline, making historical matches visible in the UI history API) but does NOT enqueue outbound notification deliveries. External notifications only fire for new data changes that occur after the rule was created.

**The Lesson:** Historical backfill and live alerting have fundamentally different semantics. Any system that sends external notifications for historical data risks violating third-party API rate limits and flooding users. "Populate the dedup table" and "send a notification" must be decoupled. Silent writes to the dedup table serve both purposes: they prevent future duplicate alerts AND make history visible in the UI — without triggering external delivery.

---

### 4.2 EPSS Blind Zones from Threshold-Gated Material Hash Inclusion (Multi-Round Iteration)

**The Flaw (4 iterations):** The initial design included `epss_score` in `material_hash`. To avoid daily hash churn from minor score fluctuations, a ±threshold dedup gate was added. The "documented limitation" was accepted as a tradeoff.

**Why It Matters:** Any threshold gate creates a "blind zone" where a user-defined threshold can be crossed silently:
- Rule: `epss_score > 0.90`
- Score drifts: 0.85 → 0.94 (delta 0.09, below any reasonable ±0.1 gate)
- Hash doesn't change → alert never fires → user never learns their CVE crossed their explicit threshold

For a security alerting product, a user-defined threshold must be honored exactly. The ±0.1 "documented limitation" is not an acceptable tradeoff — it is a correctness failure. The fact that this went through four rounds of iterative "fixes" before being correctly resolved illustrates that incremental patches to a flawed approach rarely fix the underlying problem.

**The Fix:** Remove `epss_score` from `material_hash` entirely. Track EPSS updates separately via `date_epss_updated` (timestamptz, set only when the score actually changes — see 2.1). A dedicated daily EPSS rule evaluator uses `date_epss_updated > last_cursor` to find CVEs with new data and evaluates only rules containing `epss_score` conditions.

**The Lesson:** "Document the limitation" is not an acceptable resolution for a correctness failure in a security alerting system. When multiple iterations of a fix still have a fundamental blind zone, abandon the approach and redesign — don't patch the latest iteration. The correct fix here was to separate EPSS tracking from the `material_hash` mechanism entirely.

---

### 4.3 token_version Causes Global Logout Across All Devices (Documented Limitation)

**The Flaw:** The `token_version` revocation mechanism was described without explaining its UX scope.

**Why It Matters:** Incrementing `token_version` invalidates all refresh tokens for a user simultaneously — across all devices and sessions. This is appropriate for security events (account compromise, password change, forced logout) but means there is no way to revoke a single session (e.g., "sign out of work laptop, keep phone session active").

**The Resolution:** Explicitly document global logout as the MVP behavior. Incrementing `token_version` is appropriate for the listed security-critical events. Granular single-session revocation is a P1 feature requiring a separate `sessions` or `refresh_tokens` table with per-token JTI tracking and individual revocation records.

**The Lesson:** Token revocation has a spectrum from "revoke all sessions" (simple, one version counter) to "revoke one specific session" (requires per-token tracking). Document which granularity your MVP provides and explicitly flag it as a limitation, not a feature. Users expect "sign out of this device" to not sign them out of everything.

---

## 5. Architectural Decisions Validated Early

### 5.1 RLS Must Be Implemented Alongside Initial Org Table Migrations (Not Deferred)

**The Initial Plan:** Implement Postgres Row Level Security in a future phase after the data model stabilizes.

**Why Deferral Is Dangerous:** All org-scoped tables require `org_id NOT NULL` + `BTREE(org_id)` index whether or not RLS is enabled — the schema is identical. The `SET LOCAL app.org_id = $1` middleware is ~10 lines of Go. Adding RLS policies at table-creation time costs almost nothing. Retrofitting RLS after the application is built requires auditing every query path for implicit cross-org access and re-running the full integration test matrix. A bug in a single application-layer store method can expose cross-tenant data; RLS ensures the database itself rejects the query regardless of application bugs.

**The Decision:** RLS is implemented in Phase 2 alongside org table migrations. `FORCE ROW LEVEL SECURITY` on every org-scoped table; app DB role is `NOBYPASSRLS`. Same codebase, same policies for both self-hosted and SaaS deployments.

**The Lesson:** Security controls that are cheap to add during initial implementation become expensive to retrofit later. "We'll add it later" for defense-in-depth controls almost always means "we won't add it until after a security incident." For multi-tenant products, database-level isolation is not optional.

---

### 5.2 Bulk Import Is Required — API Polling Cannot Handle Initial Population

**The Initial Plan:** Use normal incremental API polling to populate a new instance.

**Why It Fails:** NVD API rate limits (5 req/30s with API key, ~2000 results/page) make a from-scratch API sync of the full historical corpus (250k+ CVEs) take many hours under ideal conditions, and any network error or API downtime forces a retry from an earlier cursor. This makes a new instance unusable until polling catches up. NVD annual archives are hundreds of MB; OSV ecosystem archives are similar.

**The Decision:** Each large feed has a preferred bulk source for initial load (NVD annual JSON archives, OSV GCS bucket, MITRE cvelistV5 ZIP). The `cvert-ops import-bulk` CLI subcommand handles bulk ingestion through the same merge pipeline as incremental polling. After bulk import, the feed cursor is initialized to a timestamp just before the archive's "as-of" date, and normal incremental polling takes over.

**The Lesson:** Design the initial data population path explicitly. API rate limits that are tolerable for incremental updates are often prohibitive for full-corpus initial loads. Every data-intensive service should have a "bulk load from archive" path separate from the "incremental sync" path, and they should share the same downstream pipeline to avoid divergence.

---

## Summary Table

| # | Category | Issue | Severity | Key Fix |
|---|---|---|---|---|
| 1.1 | Go | Feed wire format — JSON object, not top-level array | High | Feed-specific `Token()+More()` navigation; `Decode(&slice)` forbidden |
| 1.2 | Go | `archive/zip` requires `io.ReaderAt`; HTTP body is forward-only | High | `os.CreateTemp()` temp-file bridging pattern |
| 1.3 | Go | GitHub does not support OIDC (no discovery endpoint) | Critical | `go-oidc` for Google only; raw `oauth2` + REST for GitHub |
| 1.4 | Go | GitHub `/user/emails` requires `user:email` OAuth scope | Critical | Add `Scopes: []string{"user:email"}` to GitHub `oauth2.Config` |
| 2.1 | DB | EPSS unconditional UPDATE writes 250k dead tuples daily | High | `IS DISTINCT FROM` guard in UPDATE SQL |
| 2.2 | DB | FTS GIN churn from high-frequency `cves` updates | Medium | Isolate `fts_document` in `cve_search_index` table |
| 2.3 | DB | Advisory lock: internal Postgres hash API + imprecise isolation claim | Medium | FNV-1a in Go; domain prefix corrected to accurate description |
| 2.4 | DB | RLS `missing_ok` fail-closed blindfolds background workers | Critical | `app.bypass_rls` session variable + `workerTx` helper; `SET LOCAL` scoped |
| 2.5 | DB | `RowsAffected == 0` ambiguous after `IS DISTINCT FROM` guard | High | Two-statement pattern; staging insert uses `WHERE NOT EXISTS`; no `RowsAffected` branching |
| 3.1 | Security | JWT algorithm confusion / `alg: none` bypass | Critical | `jwt.WithValidMethods([]string{"HS256"})` + `WithExpirationRequired()` required |
| 3.2 | Security | Argon2id OOM denial of service under concurrent load | Critical | Non-blocking semaphore (default: 5) with immediate 503 on excess |
| 3.3 | Security | Blocking semaphore converts OOM-DOS into connection-starvation DOS | Critical | `select/default` — reject immediately, never block on semaphore send |
| 4.1 | Operational | Activation scan drops thousands of outbound notifications | Critical | Silent mode: write `alert_events`, suppress outbound delivery |
| 4.2 | Operational | EPSS threshold gate creates user-defined threshold blind zones | High | Remove EPSS from `material_hash`; dedicated cursor-based evaluator |
| 4.3 | Operational | `token_version` causes global logout (undocumented scope) | Low | Documented as MVP limitation; P1 = per-JTI `sessions` table |
| 5.1 | Architecture | RLS deferred to "a future phase" | High | RLS in Phase 2 alongside org table migrations; `NOBYPASSRLS` |
| 5.2 | Architecture | Relying on API polling for initial corpus population | High | Bulk import CLI with feed-specific archive sources |

---

## Meta-Observations on the Review Process

Several findings from this review process are worth preserving as patterns:

**Iterative patches rarely fix flawed foundations.** EPSS went through four rounds of iteration (baseline column → NULL arithmetic fix → ±threshold gate → "documented limitation") before the correct solution emerged: remove EPSS from `material_hash` entirely and track it via a separate cursor. Each incremental fix addressed the symptom while preserving the fundamental flaw. When multiple iterations of a fix still produce correctness problems, reconsider the entire approach.

**Wording precision matters when the document is an AI coding spec.** The "non-overlapping key spaces" correction was a wording fix, but it reflected a real conceptual misunderstanding about what domain prefixes guarantee. An AI coding assistant given imprecise architectural documentation produces imprecise implementations. When writing prescriptive architecture documents, be exact about what a mechanism guarantees — not what you hope it achieves.

**Library interface details must be in the spec.** The `archive/zip` and GitHub OIDC issues both stem from correct high-level plans (`use the zip library`, `use the OIDC library`) breaking down at the library interface level. The constraints that experienced developers know from memory (`zip.NewReader` needs seekable; GitHub has no OIDC) are not inferrable from architectural documents. For any non-obvious integration, the spec must include the specific interface pattern, not just the library name.

**Security assumptions deserve adversarial review.** JWT algorithm confusion, Argon2id OOM DOS, and the activation scan spam issue all required asking "what happens if someone deliberately abuses this?" rather than "does this work for normal usage?" Architectural review of security products should include explicit adversarial passes on every external-facing mechanism.
