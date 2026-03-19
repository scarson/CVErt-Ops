# Section 4: API Design & HTTP

> **Reader context:** "I'm writing or reviewing HTTP handlers or middleware"

---

## API-1: `r.Context()` Background Assassination

**The Flaw:** When an HTTP handler dispatches background work (e.g., the activation scan), it passes `r.Context()` to the goroutine: `go runScan(r.Context(), ruleID)`.

**Why It Matters:** The moment the HTTP handler returns its `202 Accepted` response, the Go server automatically cancels `r.Context()`. Any database query, file read, or network call in the background goroutine using this context is immediately aborted. The activation scan dies silently, the rule is stuck in `activating` forever, and no error is surfaced to the user. This failure is non-obvious because the HTTP request appears to succeed.

**The Fix:** Use `context.WithoutCancel(r.Context())` (Go 1.21+) when spawning goroutines from HTTP handlers. This preserves trace IDs and values from the request context but detaches the cancellation signal, allowing the goroutine to outlive the HTTP request. Never pass `r.Context()` directly. Never use `context.Background()` (loses tracing).
```go
bgCtx := context.WithoutCancel(r.Context())
go func() { workerPool.Enqueue(bgCtx, activationScanJob) }()
```

**The Lesson:** HTTP request contexts have a lifetime tied to the request. Any background work that must outlive the response needs a context whose cancellation is decoupled from the HTTP lifecycle. `context.WithoutCancel` is the idiomatic Go 1.21+ answer.

> Note: Worker-side lifecycle management (join points, shutdown coordination) is covered in ARCH section.

---

## API-2: `omitempty` on PATCH Payload Structs Silently Drops Zero-Value Fields

**The Flaw:** PATCH request payload structs used concrete Go types with `omitempty` tags (e.g., `Active bool \`json:"active,omitempty"\``).

**Why It Matters:** Go's `encoding/json` treats `omitempty` as "skip this field if its value equals the zero-value for its type." For `bool`, zero-value is `false`. For `int`, zero-value is `0`. For `string`, zero-value is `""`. When a client sends `{"active": false}` to disable an alert rule, the JSON unmarshaler reads `false`, sees that it equals the `bool` zero-value, applies `omitempty`, and silently ignores the field. The struct field retains its zero-initialized `false` value, but because the field is treated as "not provided," the handler skips the DB update for it. `active` in the database remains `true`. The user cannot disable their alert rule — any number of `PATCH {"active": false}` requests are silently no-ops. This applies equally to `status` integers set to `0`, empty strings, and other zero-valued fields a user might legitimately want to set.

**The Fix:** All PATCH request structs MUST use pointer types for every field:
```go
type PatchAlertRuleRequest struct {
    Active   *bool   `json:"active,omitempty"`   // nil = not provided; &false = explicitly false
    MaxScore *int    `json:"max_score,omitempty"`
    Name     *string `json:"name,omitempty"`
}
```
In the handler, only generate SQL SET clauses for fields where the pointer is non-nil. `huma` handles pointer types correctly in its OpenAPI schema generation (marks them as non-required). This applies to every PATCH endpoint in the API.

**The Lesson:** In Go APIs that use partial updates (PATCH), the distinction between "field not present in request" and "field explicitly set to its zero value" cannot be made with concrete types. Only pointer types (`*bool`, `*int`, `*string`) correctly encode three states: `nil` (absent), `&false` (present, false), `&true` (present, true). Using concrete types with `omitempty` for PATCH payloads is always wrong. When reviewing Go PATCH handlers, if you see `bool` or `int` without a `*`, it's a bug.

---

## API-3: Unbounded Request Body Causes OOM Before Any Validation Runs

**The Flaw:** No HTTP request body size limit was specified for the API server.

**Why It Matters:** Go's `net/http` will faithfully read whatever the client sends. `huma` and `json.Decoder` buffer the body before schema validation. An attacker (or misconfigured client) POST-ing a 5 GB body to `POST /api/v1/orgs/{org_id}/alert-rules` causes the server to allocate 5 GB of heap memory before any handler logic or validation fires. On a homelab server or resource-limited container, this OOM-kills the process. The attack requires no authentication if any public endpoint exists, and no special knowledge — just a large body.

**The Fix:** Register `chi/middleware.RequestSize` globally before any routes:
```go
r.Use(middleware.RequestSize(1 << 20)) // 1 MB global limit
```
This rejects requests with a `Content-Length` header exceeding 1 MB with `413 Request Entity Too Large` before the body is read. The `import-bulk` subcommand is a CLI path that reads local files — not an HTTP endpoint — and is unaffected. Raise the limit only on specific subrouters where larger payloads are legitimately required.

**The Lesson:** Request body size limits are a basic web API hardening requirement — not an optimization. Without them, any endpoint is an OOM vector regardless of authentication. Global middleware registered before all routes is the correct pattern: it applies universally without requiring per-handler awareness. Middleware that enforces size limits early in the stack prevents reading any body content at all.

---

## API-4: Slowloris DOS via Infinite `http.Server` Default Timeouts

**The Flaw:** The API server was initialized with `http.ListenAndServe(addr, handler)` or an `http.Server{}` struct with no timeout fields set.

**Why It Matters:** Go's `net/http.Server` has **infinite timeouts by default**. A Slowloris attack opens thousands of TCP connections and sends exactly 1 byte every few seconds, intentionally never completing the HTTP request headers. Each connection holds an open file descriptor and a goroutine. At 10,000 simultaneous slow connections the server exhausts OS file descriptors and Go goroutine memory — taking the entire API offline. Critically, the attack bypasses every application-level defense:
- `chi/middleware.RequestSize` fires after headers are fully parsed — never reached
- Rate-limiting middleware fires after headers are parsed — never reached
- Chi route matching fires after headers are parsed — never reached

The Slowloris attack requires no authentication, no large payload, no special knowledge — just the ability to open many TCP connections and trickle bytes.

**The Fix:** Always initialize `http.Server` with explicit timeouts:
```go
server := &http.Server{
    Addr:              cfg.ListenAddr,
    Handler:           r,
    ReadHeaderTimeout: 5 * time.Second,   // kills slow-headers attacks
    ReadTimeout:       15 * time.Second,  // kills slow-body attacks
    IdleTimeout:       120 * time.Second, // reclaims idle keep-alive connections
}
```
`ReadHeaderTimeout` is the most critical: it kills connections that never complete their HTTP headers. After 5 seconds with no complete header, Go closes the connection and releases the goroutine. Never use `http.ListenAndServe` in production — it creates a zero-timeout server.

**The Lesson:** Go's `net/http` server is not safe by default. Infinite timeouts are the default because the standard library cannot know what timeout is appropriate for every application. For any internet-facing HTTP server, explicit timeout configuration is mandatory security hardening, not an optimization. The fact that `ReadHeaderTimeout` causes Slowloris connections to be cleaned up *before any application code runs* is precisely what makes it effective where middleware-level defenses fail.

---

## API-5: IP Rate Limiter Global Ban via Reverse Proxy

**The Flaw:** IP-based rate limiting used `r.RemoteAddr` directly, which returns the reverse proxy's internal IP in Docker/Kubernetes.

**Why It Matters:** (a) One user triggers the limit and all users are banned (same proxy IP). (b) Naive fix of trusting `X-Forwarded-For` enables attacker bypass by sending `X-Forwarded-For: 127.0.0.1`.

**The Fix:** chi's `middleware.RealIP` handles `X-Forwarded-For` parsing securely. Register it before any middleware that reads client IP:
```go
r.Use(middleware.RealIP)       // parses XFF, sets r.RemoteAddr
r.Use(clientIPMiddleware)      // reads r.RemoteAddr (already corrected)
r.Use(rateLimitMiddleware)     // uses client IP from context
```

**The Lesson:** IP extraction for rate limiting is a two-step trust decision: (1) is the immediate connection from a trusted proxy? (2) if yes, what IP did the proxy report? Skipping step 1 enables trivial bypass. Using a well-tested library middleware (chi's RealIP) is preferable to a custom implementation for this security-critical parsing.

---

## API-6: Keyset Pagination Without Composite Tie-Breaker Silently Drops Records at Page Boundaries

**The Flaw:** The default pagination was correctly specified with `cve_id` as a tiebreaker, but the "unless otherwise specified" clause left secondary sort orders (e.g., `?sort=date_published`) without a mandatory tiebreaker requirement.

**Why It Matters:** The CVE search endpoint supports `?sort=date_published`. An implementation using `WHERE date_published < $last_date ORDER BY date_published DESC` fails when NVD and MITRE publish hundreds of CVEs in a single batch ingestion run, all with identical `date_published` timestamps (the timestamp is set by the feed, not the ingestion time). A page of 100 results ends at timestamp `T`. There are 47 more CVEs with the same timestamp `T`. The next page query uses `WHERE date_published < T`, which evaluates to strictly less than — skipping all 47 CVEs with `date_published = T`. The API user's pagination loop completes silently, having dropped 47 CVEs from their result set. No error, no warning, no indication of data loss.

**The Fix:** Every keyset pagination query using a non-unique sort column MUST use a composite cursor with the table's unique PK as a mandatory tiebreaker:
```sql
-- Composite cursor: no rows dropped at page boundaries
WHERE (date_published, cve_id) < ($last_date, $last_id)
ORDER BY date_published DESC, cve_id DESC
```
The opaque cursor encodes both values. `cve_id` is globally unique, so this composite is unique and the ordering is fully deterministic.

**The Lesson:** Any sort column that is not globally unique creates page-boundary ambiguity in keyset pagination. Timestamp columns are especially dangerous because feed data is batch-ingested with identical timestamps. The tiebreaker must be globally unique and immutable. Always specify the tiebreaker explicitly in the pagination spec — do not rely on "obvious" implementation choices.

---

## API-7: pgx Named Prepared Statements Crash Under PgBouncer Transaction Pooling

**The Flaw:** pgx v5 (used by pgxpool) defaults to the extended query protocol with named prepared statements. No guidance was given for enterprise deployments with connection poolers.

**Why It Matters:** An enterprise user places PgBouncer in front of Postgres in transaction pooling mode (the standard configuration for handling hundreds of application connections). pgx creates a named prepared statement (`pgx_0`, `pgx_1`, ...) on backend connection A. PgBouncer routes the next query to backend connection B. Postgres B has no record of the prepared statement and returns `ERROR: prepared statement "pgx_0" does not exist`. The error propagates through pgxpool; pgxpool may mark the connection as broken. Under load, this repeats continuously — the API and worker pools experience constant query failures, appearing as database errors or connection resets. The entire application is effectively down under enterprise deployment topology even though Postgres itself is healthy.

**The Fix:** Configure pgxpool to use `QueryExecModeSimpleProtocol` by default:
```go
config, _ := pgxpool.ParseConfig(cfg.DatabaseURL)
config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
pool, _ := pgxpool.NewWithConfig(ctx, config)
```
Simple protocol sends SQL as plain text strings without named prepared statements — fully compatible with all PgBouncer modes, all pooler configurations, and direct Postgres connections. The performance difference at our scale (hundreds of queries/sec, not millions) is negligible. Expose `DB_QUERY_EXEC_MODE` env var so advanced users can opt into extended protocol if connecting directly to Postgres without a pooler.

**The Lesson:** pgx's default query execution mode is optimized for direct-to-Postgres performance with persistent connections. It is fundamentally incompatible with connection poolers operating in transaction pooling mode. This incompatibility is not surfaced in development (single direct connection) but manifests immediately in enterprise deployments. Any Go application using pgx that might be deployed with PgBouncer must configure the query execution mode at initialization time.

---

## API-8: Partial Unique Index Violations Surface as 500, Not 409

**The Flaw:** `CreateScheduledReport` handler inserts a row into `scheduled_reports`, which has a partial unique index `scheduled_reports_name_uq ON (org_id, name) WHERE deleted_at IS NULL`. When a user creates a report with a duplicate name, Postgres rejects the insert with error code `23505` (`unique_violation`). The handler does not catch this and returns 500.

**Why It Matters:** 500 is a server error that implies a bug; 409 is a client error that tells the user "this name is already taken." Every soft-delete entity with a partial unique name index (notification channels, alert rules, watchlists, scheduled reports) has this same gap. Users see "Internal Server Error" for a perfectly recoverable situation.

**The Fix:** In every handler that creates or renames a soft-delete entity, catch the Postgres `unique_violation` error and return 409 Conflict:
```go
var pgErr *pgconn.PgError
if errors.As(err, &pgErr) && pgErr.Code == "23505" {
    return nil, huma.Error409Conflict("a resource with this name already exists")
}
```
This applies to: `CreateNotificationChannel`, `CreateAlertRule`, `CreateWatchlist`, `CreateScheduledReport`, and the corresponding PATCH/rename handlers.

**The Lesson:** When a schema uses partial unique indexes for soft-delete name deduplication, the application layer must translate the DB constraint violation into an appropriate HTTP status. The constraint protects data integrity; the handler must translate that protection into a user-friendly response. Audit all `INSERT` and `UPDATE` paths that touch columns covered by partial unique indexes.

**Known gap (2026-03-18):** Auth paths (registration, OAuth) correctly catch 23505 and return 409. Channel, alert rule, and scheduled report create handlers do NOT — they return 500 on duplicate names. These handlers need the same `pgErrCode(err) == '23505'` check.

---

## API-9: PATCH Endpoints Must Re-Validate the Same Constraints as POST

**The Flaw:** During the test audit, PATCH handlers for channels and reports were tested for SSRF validation (webhook URLs), email config validation (recipient addresses), and timezone validation. These checks were present, but the pattern is easy to miss: a developer implements validation on `POST` (create) and forgets to apply the same checks on `PATCH` (update).

**Why It Matters:** If a webhook channel is created with SSRF validation but can be PATCHed to `http://169.254.169.254/`, the SSRF protection is bypassed. If a report is created with timezone validation but can be PATCHed to `Invalid/Zone`, the digest runner panics on `time.LoadLocation`. Every mutable field that has a validation constraint at creation must have the same constraint on update.

**The Fix:** Extract validation logic into shared functions callable from both create and update handlers:
```go
func validateWebhookURL(url string) error { ... }  // called from POST and PATCH
func validateEmailConfig(cfg EmailConfig) error { ... }  // called from POST and PATCH
```
When adding a new validation to a create handler, immediately grep for the corresponding PATCH handler and apply the same check.

**The Lesson:** POST and PATCH handlers for the same resource must enforce identical validation constraints. When implementing or reviewing a create handler, always check the update handler for parity. A quick audit: for every `validate*` call in a POST handler, verify the same call exists in the corresponding PATCH handler.

Common validation gaps: whitespace-only names (`strings.TrimSpace(name) == ""`) validated on POST but not PATCH; org create/update checking `name == ""` without TrimSpace.

---

## API-10: API Response Contract Consistency Across Endpoints

**The Flaw:** Seven health review findings stemmed from inconsistency across API endpoints that were implemented one at a time over weeks. Each handler was correct in isolation but collectively they presented:
- Two error formats (RFC 9457 JSON from huma routes, plaintext from chi routes)
- Two list response shapes (`{"items": [...], "next_cursor": "..."}` vs bare `[...]` arrays)
- Six different pagination cursor mechanisms (base64 JSON, base64 `time|uuid`, separate params, raw UUID, hardcoded limit, none)
- Inconsistent validation status codes (400 vs 422 for the same "name is required" error)
- Tier limits and RBAC rejections both returning 403

**Why It Matters:** An API consumer's generic error handler, pagination helper, or response parser cannot work across all endpoints. Every new endpoint integration requires discovering which contract variant that endpoint uses. Adding pagination to a bare-array endpoint later is a breaking change. Clients must maintain per-endpoint special cases. This accumulates invisibly: each handler passes its own code review, but the API as a whole becomes unusable for generic client code.

**The Fix:** Before writing any new endpoint handler, **MUST** check the most recent similar endpoint for these contract elements and match them exactly:

| Element | Standard | Check before writing |
|---|---|---|
| Error format | RFC 9457 Problem Details JSON | How do existing handlers in the same router return errors? |
| List response shape | `{"items": [...], "next_cursor": "..."}` | Does any existing list endpoint use a bare array? Don't add another. |
| Pagination cursor | Single opaque `?cursor=` param, base64-encoded JSON | What cursor format do adjacent endpoints use? |
| Validation errors | 422 for validation failures, 400 for parse failures | What status do similar handlers return for "field required"? |
| Quota/tier errors | 429 (not 403) for quota/tier limits; 403 for RBAC only | How does the tier middleware signal "upgrade needed" vs "wrong role"? |

**When to check:** Before writing any new HTTP handler. During code review of any new endpoint. When adding a new list endpoint or a new PATCH endpoint.

**The Lesson:** API consistency is not enforced by any single handler's correctness — it is enforced by checking every new handler against the existing contract. Inconsistency accumulates silently because each handler is reviewed independently. The fix is not architectural (migrating frameworks) — it is procedural: check the contract before writing the handler.

---

## API-11: Admin API Must Discover Resources Dynamically

**The Flaw:** Admin feed management endpoints gate on `IsKnownFeed(feedName)` which is hardcoded to built-in feeds. Generic feeds loaded from YAML config are invisible to admin listing, triggering, and management.

**Why It Matters:** Operators cannot list, trigger, pause, or resume user-configured feeds. An entire category of resources is invisible to the management API.

**The Fix:** Query the source of truth (e.g., `feed_sync_state` table rows or loaded config) instead of iterating a compile-time constant:
```go
// Wrong: hardcoded list excludes user-configured feeds
if !feed.IsKnownFeed(feedName) {
    return nil, huma.Error404NotFound("unknown feed")
}

// Right: query the runtime source of truth
feeds, err := store.ListRegisteredFeeds(ctx)
```

**The Lesson:** When a resource type can be extended by users (config files, plugins, dynamic registration), admin endpoints MUST discover resources from the runtime source of truth — not from a hardcoded list.

---

## Review Checklist

When writing or reviewing HTTP handlers and middleware, verify each item:

- [ ] Background goroutines from handlers use `context.WithoutCancel(r.Context())`, never raw `r.Context()` or `context.Background()` (API-1)
- [ ] PATCH request structs use pointer types (`*bool`, `*string`, `*int`) for ALL optional fields (API-2)
- [ ] `middleware.RequestSize(1 << 20)` registered globally before all routes (API-3)
- [ ] `http.Server` initialized with `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `IdleTimeout: 120s` — never `http.ListenAndServe` (API-4)
- [ ] Keyset pagination uses a composite cursor with a unique tiebreaker column (e.g., `(sort_col, cve_id)`) in both `ORDER BY` and `WHERE` (API-6)
- [ ] Unique constraint violations (`pgconn.PgError` code `23505`) caught and returned as 409 Conflict, not 500 (API-8)
- [ ] PATCH handlers validate every field with the same constraints as the corresponding POST handler (API-9)
- [ ] API contract consistency: error format (RFC 9457), list shape (`{items, next_cursor}`), cursor format (base64 JSON), validation status (422), tier errors (429 not 403) (API-10)
- [ ] Admin/management endpoints discover resources dynamically, not from hardcoded lists (API-11)

---

### See Also
- Background goroutine lifecycle (worker-side): see ARCH-X (Goroutine Lifecycle)
- Security enforcement in auth handlers: see AUTH-3 through AUTH-12
- Validation symmetry testing: see testing-pitfalls.md section 4
- Error path testing: see testing-pitfalls.md section 3
