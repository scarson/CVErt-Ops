# Adversarial design review: API client CLI and MCP server (all eight lenses)

Document reviewed: `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` (558 lines, read in full). Cold read: no `reviews/` content, git history or prior review artifact was opened.

Code was checked in the worktree `C:\Users\Sam\Code\CVErt-Ops\.claude\worktrees\cli-mcp-design-5a3740`. Module sources were read from the local module cache (`go-sdk@v1.8.0`, `chi/v5@v5.5.0`, `oapi-codegen/v2@v2.8.2`). Two probes were run in the session scratchpad; neither touched the repository.

Pitfalls docs: `dev/testing-pitfalls.md` was read in full. `dev/implementation-pitfalls.md` (3,028 lines) was read by its heading index, and these entries in full: ARCH-13, NOTIFY-20, NOTIFY-21, AUTH-20, AUTH-24, ARCH-34, ARCH-40, API-10.

Findings are ranked most severe first. The per-lens lines follow the findings.

---

## Findings

### R1 · failure modes, seams & contracts, unstated assumptions

**Anchor:** section 7.3, "an `HttpRequestDoer` that hands each API request to the server's own router, with: the outer request's context".

**Claim:** As written, the in-process transport cannot route. An inner request that carries the outer request's context and is dispatched to the chi router is routed with the outer request's routing state, and gets 404.

**Evidence:** `chi/v5@v5.5.0/mux.go` lines 70-75: `Mux.ServeHTTP` reads `RouteCtxKey` from the request context and, when one is present, reuses it ("Check if a routing context already exists from a parent router"). `routeHTTP` (lines 460-476) then uses that context's `RoutePath` and `RouteMethod` instead of the inner request's URL and method. The outer request reached its handler through `r.Mount("/api/v1", apiRouter)` (`internal/api/server.go` line 527), so its routing context holds the mounted remainder path and the method `POST`.

Probe run (`scratchpad/chiprobe/main.go`, chi v5.5.0, a root router with a sub-router mounted at `/api/v1`, a `POST /mcp` handler that dispatches `GET /api/v1/whoami` to the root router):

```
strip chi route context=false: depth=1: inner GET /api/v1/whoami -> 404 "404 page not found\n"
strip chi route context=true: depth=1: inner GET /api/v1/whoami -> 200 "whoami handler"
```

The second line overrides `chi.RouteCtxKey` with nil in the inner context. The design states no such step. The same reuse would also append the inner route patterns to the outer routing context, which `httpMetricsMiddleware` reads after the handler returns (`internal/api/metrics_middleware.go` line 43, `chi.RouteContext(r.Context()).RoutePattern()`).

Related gap in the same contract: the outer context also carries the outer auth values (`ctxUserID`, `ctxAPIKeyRole`, `ctxAPIKeyOrgID`, `ctxAPIKeyID`, set in `internal/api/middleware_auth.go` lines 145-148), so "the outer request's `Authorization` header and no other credential" does not hold at the context level until the inner auth middleware overwrites them. Section 7.3 also does not say how the inner request gets both the outer request's cancellation and the per-call 60-second deadline of section 7.8, which belongs to the tool handler's context, not the outer request's.

**Axes:** objective. Remedy determinate in kind (state which context values the inner request keeps and drops; the routing context must be dropped), with a small choice in how.

---

### R2 · seams & contracts, failure modes, simplicity & proportionality, alternatives & rationale

**Anchor:** section 7.2, "A `tools/list` or `server/discover` costs no API request"; section 7.4, "the key's org role is at least member, which `whoami` reports"; section 7.8, "over HTTP, the tools that need the org ask `whoami` once per MCP request"; section 7.3, "the SDK calls `getServer(r)`, and the handler builds an MCP server for that request".

**Claim:** The three statements about `whoami` over HTTP contradict each other once `MCP_WRITE_TOOLS` is not empty, and the SDK's `getServer` contract makes the gap larger. The design does not say where the role comes from at server-build time, what happens when that lookup fails, or how it is charged.

**Evidence:**
- The per-request server is built in `getServer`, before the SDK parses the body, so the write-tool set (which depends on the role) must be known for every MCP request, not only for `tools/list` and not only for "tools that need the org". If the role comes from `whoami`, every MCP request costs a `whoami`, including `tools/list`, `server/discover` and `get_advisory`. That contradicts 7.2 and 7.8.
- `whoami` spends an org rate token (`internal/api/whoami.go` line 82, `allowOrgRequest`). An org-scoped tool call then costs two tokens. On the free tier (60 a minute, burst 10) that is a burst of 5 tool calls.
- `go-sdk@v1.8.0/mcp/streamable.go` calls `getServer(req)` twice on the stateless path: line 349 (protocol-version check, before the method check, so it also runs for `GET` and `DELETE`) and line 400 (`serveStateless`). Work done in `getServer` runs twice unless the design memoizes it per request.
- `getServer` has the signature `func(*http.Request) *Server` (line 231). It cannot return an error. A nil return yields `400 "no server available"` as `text/plain` (lines 401-403). So a `whoami` that returns 429, 403 or 5xx during `getServer` can only become a 400 with no cause, or a server silently built without write tools. The design specifies neither.
- The simpler shape is not weighed. The outer request has already authenticated the key, and its context already holds the org ID, key ID and role cap (`middleware_auth.go` lines 145-148). `internal/api/mcp.go` lives in `internal/api` and could compute the effective role (`describeOrg` in `whoami.go`) and pass org ID and role into `internal/mcpserver` as inputs, the way "the set of write tools to offer" is already an input (section 7.1). That removes the per-request `whoami`, its rate charge and its failure path, and keeps every API call on the full middleware chain.

**Axes:** the contradiction is objective. The remedy is a choice (role from `whoami` with stated cost, caching and failure behaviour; or role and org passed in from the outer request).

---

### R3 · unstated assumptions, downstream readiness, seams & contracts

**Anchor:** section 7.2, "The request log records the MCP method and tool name"; section 9.3, "each tool's API requests appear in the server's request log with the key's ID".

**Claim:** The server has no request log. The logging contract and the test that verifies the section 7.3 guarantee both depend on infrastructure that does not exist and that section 13 does not list as work.

**Evidence:** `internal/api/log_middleware.go` holds only `contextLoggerMiddleware`, which puts a logger enriched with `request_id` into the context; nothing emits a line per request. `internal/api/server.go` registers `middleware.RequestID`, the client-IP middleware, the context logger, `RequestSize` and `Recoverer`, and no `middleware.Logger`. A grep of the non-test files of `internal/api` for `slog.Info`/`slog.Debug` calls that mention request, method, path or status returns nothing. No per-request log line carries a key ID (the only `key_id` log fields are in an error path of `whoami.go` and a security event in `middleware_auth.go`). Section 7.1 gives "the server's own middleware sees every call" as a reason HTTP is primary; today that visibility is the HTTP metrics (by route pattern, without key) and the audit log (writes only).

A second gap in the same sentence: the method and tool name are to be read from the `Mcp-Method` and `Mcp-Name` headers, which only 2026-07-28 clients send. Section 7.2 also says older clients that send `initialize` are served, and section 9.3 tests a 2025-11-25 client. For those requests there is nothing to log.

**Axes:** objective. Remedy is a choice (add a request log as stated server work with its own field rules, or restate the claim and the test in terms of what exists).

---

### R4 · failure modes (security), downstream readiness

**Anchor:** section 7.4, "A write tool is offered only when both hold"; section 9.3, "Tool list by authorization".

**Claim:** The write-tool gate is specified and tested as a property of the tool list, not of the call. With `MCP_WRITE_TOOLS` empty and a member key, the REST API accepts the write, so the only thing that stops `tools/call add_watchlist_item` is that the tool is not registered on the per-request server. The design never states that, and no test calls a write tool that was not offered.

**Evidence:** Section 7.4 uses "offered" throughout. Section 9.3 checks what each key "sees", and that a member key's `add_watchlist_item` succeeds when named. Section 11 says a viewer key "is still offered none and changes nothing", which the API's own 403 guarantees for a viewer but not for a member. Missing cases: member key, `MCP_WRITE_TOOLS` empty, `tools/call` of each write tool by name is refused and writes nothing; member key, one write tool named, the other write tool is refused; the same over stdio without `--enable-write-tool`. Pitfall ARCH-40 (feature flags must be checked at every enforcement point) and ARCH-34 (every security check needs a test that proves it fires) describe this gap.

**Axes:** objective. Remedy determinate (state that unoffered tools are not callable, and add the call-time tests).

---

### R5 · downstream readiness, requirements trace (internal consistency)

**Anchor:** section 12 preamble, "the design text describes the recommended option, and each span a pending item would change says so".

**Claim:** For at least four pending items the design text describes the option that is not recommended, and the recommended option is specified nowhere. A plan author who follows the stated rule ("the plan follows Sam's answer, not the text") has nothing to follow if Sam accepts the recommendations.

**Evidence:**
- Item 7 recommends exit 0 for an empty list and a new code 10 for an invalid rule. Section 5.4's table says 0 requires "at least one item", 3 is "A search or list returned no items", and 8 covers `valid: false`. Code 10 is not in the table. Section 9.2 tests "(3, or 0 under section 12 item 7(a))".
- Item 13: "Recommendation changed: pace long runs only, from `whoami`'s rate". Section 5.5 says "the rules below assume they do not". Pacing has no design: which commands count as long runs beyond the two examples, what fraction of the rate (the "half" in item 13 belongs to the rejected every-request option), how pacing waits count against `--max-wait`, and whether the MCP tools pace.
- Item 11 recommends refusing `items replace --cves` on a mixed watchlist with exit 8, and reporting an existing item as success (`already_present`). Section 5.2 describes neither. The refusal needs reads before the write; the items endpoint has an `item_type` filter (`internal/api/watchlists.go` line 721) that would make it two requests, but the design does not say so. Exit 8 is defined in 5.4 as server rejections; this would be a client-side refusal after requests were sent, which fits neither 8 nor 2 ("no request was sent"). The check-then-`PUT` sequence can also delete an item added in between, the same silent loss the item cites against merging. The output shape for `already_present` (inside `{"added": [...]}` or beside it) is not given.
- Item 8 recommends `CVERT_CA_FILE`. Section 5.1's table has no row for it (errors, exit code, whether it applies to `cvert mcp`).
- Item 14 recommends ARCH-13 cleaning; see R6 for where that code can come from.

**Axes:** objective. Remedy determinate in kind (either make the text describe the recommended options, or correct the preamble and specify each recommended option where it is listed).

---

### R6 · seams & contracts, downstream readiness (pitfalls ARCH-13, AUTH-24)

**Anchor:** section 12 item 14, "apply ARCH-13's cleaning ... to description fields"; section 7.3 item 2, "a package that imported `internal/alert/dsl` or `internal/ai` ... would link store code".

**Claim:** The recommended cleaning lives in a package the design's own import boundary forbids `internal/mcpserver` to import, and the design does not say where the code will come from.

**Evidence:** ARCH-13 names `internal/ai/sanitize.go`, which holds `func Sanitize(s string) string`. `go list -deps ./internal/ai` lists `github.com/scarson/cvert-ops/internal/store/generated`. Section 7.3 item 2 names `internal/ai` as a package the `go list -deps` test must keep out. The design treats the same situation for the DSL field catalog as a decision (item 12, move it to a store-free package) and is silent here. The two available paths are moving `Sanitize` to a store-free package or writing a second copy; pitfall AUTH-24 (security-critical code must not be copy-pasted) argues against the second. Item 14's wording of the cleaning ("keeping link text") matches what `Sanitize` does, so one implementation can serve both.

**Axes:** objective. Remedy is a choice between the two paths.

---

### R7 · unstated assumptions, alternatives & rationale

**Anchor:** section 4.2, "A build-time tool. The generator, pinned with a `tool` directive in `go.mod`, so its version is reviewed like any dependency; its own dependencies are build-time only and never linked into a binary."

**Claim:** The `tool` directive adds the generator's whole module graph to this repository's `go.mod`. The design reviews the generator and two runtime modules, and does not list or status-check the modules the directive brings in. At least two of them fail the age rule the design applies to `uritemplate` and `go-jsonmerge`. The option that avoids this is not mentioned.

**Evidence:** Probe run on a scratch copy of `go.mod` and `go.sum` (`scratchpad/toolprobe`): `go get -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2`, then `diff --strip-trailing-cr go.mod.orig go.mod`. No existing requirement changed version. Fourteen indirect requirements were added (the generator and thirteen modules it needs):

```
github.com/dprotaso/go-yit v0.0.0-20220510233725-9ba8df137936
github.com/getkin/kin-openapi v0.142.0
github.com/go-openapi/jsonpointer v0.23.1
github.com/go-openapi/swag/jsonname v0.26.0
github.com/oapi-codegen/oapi-codegen/v2 v2.8.2
github.com/oasdiff/yaml v0.1.1
github.com/oasdiff/yaml3 v0.0.14
github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
github.com/speakeasy-api/jsonpath v0.6.3
github.com/speakeasy-api/openapi v1.24.0
github.com/vmware-labs/yaml-jsonpath v0.3.2
golang.org/x/mod v0.41.0
golang.org/x/tools v0.51.0
gopkg.in/yaml.v3 v3.0.1
```

(plus the `tool` line itself). `go-yit` is pinned to a 2022-05 commit. `gopkg.in/yaml.v3` is the go-yaml module whose repository was archived in 2025; this repository already uses its successor, `go.yaml.in/yaml/v4`. These modules are not linked into a binary, but the generator executes on developer machines and in CI with repository write access, and the project rule is to verify every new dependency before a plan is final. The design's argument that the generator's advisories "need a hostile spec" covers the generator's input, not the code of its dependencies.

Alternative not recorded: a separate module for the generator (a `tools/go.mod`, or `go tool -modfile`), which keeps these requirements out of the main module's graph and out of what `govulncheck` and dependency scanners attribute to the server.

**Axes:** the measurement is objective. The remedy is a choice (status-check the thirteen modules and accept them, or isolate the generator in its own module).

---

### R8 · downstream readiness, unstated assumptions

**Anchor:** section 4.2, "The tests that keep the MCP tool descriptions complete (section 7.6) iterate over these constants instead of parsing the spec"; section 7.5, "Enumerations are taken from the generated client's constants, so a schema cannot offer a value the API does not accept".

**Claim:** Go cannot iterate over the constants of a type, and the generator emits no value list. Both mechanisms need something the design does not name.

**Evidence:** `oapi-codegen/v2@v2.8.2/pkg/codegen/templates/constants.tmpl` generates, per enum, a `const (...)` block and a `Valid() bool` method with a `switch`. It generates no slice or function that returns the values. A test or schema builder therefore needs one of: a hand-written slice of the constants (which does not fail when the server adds a value, the exact drift sections 7.5, 7.6 and 9.1 exist to catch), parsing `internal/apiclient/gen` with `go/ast`, a custom generator template that emits a value list, or reading `openapi-3.0.json` (which the sentence says it avoids). The fifth bullet of 4.2 ("No hand-maintained conformance table") depends on this as well.

**Axes:** objective. Remedy is a choice among those mechanisms.

---

### R9 · failure modes

**Anchor:** section 5.2, "It stops above 10,000 items with exit 2 and prints nothing"; section 5.3, "`events list` is the exception that keeps a poller's place".

**Claim:** `events list --all` can enter a state it never leaves. The 10,000-item stop was designed for `cves search`, and applied to the poller it discards the cursor. A mid-walk failure has no stated output at all.

**Evidence:** A poller whose backlog exceeds 10,000 events (after an outage, or a new broad rule) runs `events list --after C --all`, gets exit 2 and no output, stores nothing, and gets the same result on every later run. The design gives the stop one rationale ("so `cves search --all` with no filter cannot walk the whole corpus by accident") and applies it to every list command. Separately, section 5.2 does not say what `--all` prints when a page fails mid-walk (429 after the budget, a 5xx, a network error). Section 6 defines partial output for `check` in detail; `--all` has no equivalent. If nothing is printed, a walk that needs more requests than the rate budget allows (item 13 gives 200 requests for a 10,000-item watchlist against a 2-minute budget) restarts from the first page every run and cannot finish. For `events list`, pages already fetched carry a valid cursor that could be printed.

**Axes:** the behaviour follows from the text (objective). Remedy is a choice (exempt `events list` from the stop, print the fetched pages and cursor on stop or failure, or make `--all` unavailable for events).

---

### R10 · failure modes

**Anchor:** section 7.8, "It splits on the candidate-limit 422 as in section 6.2, within the deadline"; "When it passes, the call returns a tool error saying the server is busy and to retry."

**Claim:** A `check_components` call whose 422 splits outlast the 60-second deadline returns "busy, retry" for a failure that will repeat, and the design does not say whether answered sub-batches are returned.

**Evidence:** The candidate-limit 422 depends on the items, not on load (`internal/api/check.go`, `store.ErrCandidateLimit`). The same input splits the same way on a retry, and each sub-request can take up to the server's 30 seconds, so a call that overran once overruns again. The deadline message tells the agent the server is busy. Section 7.7 gives the tool an `unanswered` list "as in section 6.3", which implies partial results exist, while 7.8 says a passed deadline is a tool error. Which of the two applies when some halves were answered is not stated. The time-limit case in the same bullet is handled correctly ("retry with fewer items").

**Axes:** objective ambiguity. Remedy is a choice (return answered items with the rest in `unanswered`, or return an error that says to send fewer items).

---

### R11 · unstated assumptions, simplicity & proportionality

**Anchor:** section 7.7, "Results are compact JSON in the MCP result's structured content, with the same JSON as one text block"; "`check_components`: ... up to 20 advisories ... `matched_ranges` holds up to 5"; "`get_advisory`: ... up to 20 CNA product entries".

**Claim:** Results are capped per list and not in total. The caps the design gives allow results far larger than agent hosts accept, and one list has an uncapped inner list.

**Evidence:**
- `check_components` accepts 1 to 500 items (section 7.4). With 20 advisories per item and 5 ranges per advisory, one result can hold 10,000 advisory objects of thirteen fields each. At a few hundred bytes each that is megabytes, sent twice (structured content and the text block). The design gives no total budget and no paging for this tool.
- `get_advisory` caps CNA product entries at 20, but each entry holds a `versions` list (`CNAVersionResponse` in `internal/api/cves.go`, with nested `changes`) that the design does not cap. CNA records for large projects carry long version lists per product.
- Agent hosts limit tool output. Claude Code's default limit is 25,000 tokens per MCP tool result (`MAX_MCP_OUTPUT_TOKENS`), which is on the order of 100 KB. This figure is from the reviewer's knowledge and was not re-checked in this session; the runner can confirm it in the host's documentation.
- The design also drops the server's `matched_ranges_total` when it cuts ranges to 5, so the agent cannot tell that ranges were omitted, although "Each list carries the number of entries it omitted" is the stated rule for `get_advisory`. And it reuses `advisories_truncated`, which the server sets only above its own limit of 100 (`check.go`, "At most 100"), for the tool's cut at 20 without saying so.

**Axes:** contestable (depends on corpus and host). Remedy is a choice (a total size budget with a stated overflow rule, a lower item limit for the tool, or a summary form).

---

### R12 · failure modes (security)

**Anchor:** section 7.6, "Advisory descriptions and references come from external feeds. `get_advisory` and `search_advisories` say so"; section 12 item 14, "apply ARCH-13's cleaning ... to description fields".

**Claim:** The untrusted-text boundary is drawn around one field, while other feed-authored and member-authored strings reach the agent without cleaning, a length cap or a label.

**Evidence:** Strings the tools return that an outside party writes: CNA `vendor`, `product`, `package_name` and version strings (`get_advisory`); package names and ecosystems in affected ranges (`get_advisory`, `check_components` `matched_ranges`); reference `url` and `tags`, which item 14 leaves "as structured URLs"; CPE strings. Strings another org member writes: rule names (`list_alert_events`, `list_rules`), watchlist names, API key names (`whoami`). Section 5.3 recognises the second group for terminals ("values such as rule names are written by org members") and replaces control characters in table output, but the MCP results get no equivalent. Only `get_advisory` and `search_advisories` carry the untrusted label; `check_components`, `list_alert_events` and `dry_run_rule` results do not. The stated input-schema length limits (section 7.5) apply to inputs only. ARCH-13's lesson is stated per source, not per field: "Any data from external sources ... that flows into an LLM prompt is a potential injection vector."

**Axes:** contestable (how far to go). Remedy is a choice (clean and cap every string field from feeds and members; or clean descriptions only and state the residual risk).

---

### R13 · downstream readiness

**Anchor:** section 7.7, "Per tool:" (five tools listed); section 5.3, table of `--output table` columns (six commands listed).

**Claim:** Several elements a plan needs are absent, so a plan author would have to decide them.

**Evidence:**
1. Result shapes are given for 5 of 12 tools. `whoami`, `list_rules`, `validate_rule`, `list_watchlists`, `list_watchlist_items`, `add_watchlist_item` and `remove_watchlist_item` have none (for example, whether `list_rules` returns each rule's conditions).
2. Table columns are given for 6 commands. `whoami`, `cves sources`, `rules validate`, `rules dry-run`, `watchlists list`, and the three `items` write commands have none, and the design does not say what `--output table` does for them.
3. Section 8.1: "each passes its policy to the wrapper". The policy's fields are not listed (budget, deadline, whether to split on timeout, whether to retry 429).
4. Section 7.3: "The transport accepts only the paths of the generated operations". The generated client exposes no route table, so the source of the allowlist is unstated, as is whether it matches method and path or path only. The 14 generated operations include the whole-list `PUT`, which section 7.4 makes CLI-only.
5. Section 2 and section 13: the four score filters are to be documented in the spec "by another means than a pointer `query:` tag". The means is not named, and it is the first item of the first pull request.
6. `MCP_WRITE_TOOLS` and `--enable-write-tool` with a name that is not a write tool: startup failure or silent ignore is not stated. This is also the behaviour an operator meets after a tool is renamed (R19).
7. `validate_rule` input: section 7.5 requires enumerations to be enumerated and no unlisted properties. The `conditions[]` item schema (field and operator enumerations) needs the DSL catalog, so item 12 gates the schema and not only the description. The design says only the description depends on it.
8. `--all`: the page size the client requests is not stated (the endpoints differ: `/cves` up to 100, watchlist items 50, watchlists 20, rules 20).
9. Section 9.3 "Cancellation" and section 9.4 "Two concurrent tool calls send their requests one after the other" need an observation point in the server. With the 71-record seeded corpus a check finishes in milliseconds, so "closes the request while `check_components` runs" is not reachable without a hook the design does not name.
10. Section 9.2: "the 11th request inside the 10-request burst". Each CLI invocation also spends a `whoami` token (section 10), so the refused request may be the `whoami` and not the command's own request. `testing-pitfalls.md` section 5, "Rate limit accounting", covers this case.
11. Section 5.1 says the client "asks `whoami` once per process". Whether `cves` commands, which need no org, also ask is not stated; it decides whether they spend an org token.
12. Section 7.7: "A field the server can return as null keeps its null". `/cves` omits unknown scores (`omitempty` on `cvss_v3_score`, `epss_score` in `CVEItem`) instead of sending null. Whether the tool then emits null or omits the field is not stated.

Open questions that are marked as open (section 12, the rate-limiter test hook, the `go install` proof, `cacheScope`) are not counted here.

**Axes:** objective. Remedy determinate in kind (state each), with choices inside several.

---

### R14 · seams & contracts, alternatives & rationale (pitfalls NOTIFY-20, NOTIFY-21)

**Anchor:** section 10, FEED-1 row, "Every event must reach a poller exactly once, including an event whose transaction commits after a later event's ... and including a resolved event that is reopened".

**Claim:** The contract with FEED-1 is stated on this design's side only, asks for the harder guarantee, and has no fallback. An interim option that exists today is not mentioned.

**Evidence:**
- No FEED-1 design exists under `dev/plans/` (grep for `FEED-1` matches only this document and unrelated uses). The design does not record that the other session accepted these requirements.
- NOTIFY-20 and NOTIFY-21 record how this codebase solved the late-commit problem twice: an overlap window with idempotent or deduplicated re-processing, not exactly-once ordering. If FEED-1 follows the same pattern, a poller sees some events twice. The client side here has no deduplication and no statement of what a consumer should do with a repeat.
- "Exactly once" and "including a resolved event that is reopened" pull against each other: a reopened event is a second delivery of an event ID already delivered. The output fields in 7.7 (`open`, `first_fired_at`, `last_fired_at`) would let a consumer tell the cases apart, but the design does not say that a repeat ID is expected.
- Section 2 describes the events endpoint as "newest first, 100 a page, with no `limit` parameter" and concludes the commands wait. The endpoint also has a `since` filter and a `cursor` (`internal/api/alert_events.go` lines 130-173: "`?since=` keeps events whose most recent fire is at or after the given time"). A `--since` poll with an overlap would give at-least-once delivery today. The design does not mention `since`, so a reader cannot tell whether it was weighed.

Section 1 defers all of this work until FEED-1 lands, which limits the cost of being wrong.

**Axes:** contestable. Remedy is a choice (state at-least-once with consumer deduplication as the fallback contract; record agreement with FEED-1's owner; or record why `since` was rejected).

---

### R15 · simplicity & proportionality, alternatives & rationale

**Anchor:** section 7.1, "stdio remains for agent hosts that cannot send a header with an HTTP MCP server, and for use against a server that has the endpoint turned off."

**Claim:** Keeping stdio is a decision with a real current cost and no named consumer, and it is not among the section 12 decisions.

**Evidence:** By the design's own account every host the requirement names can use HTTP: section 7.10, "agent hosts that can send a static header (Claude Code and Codex do) can connect"; item 16, "the hosts the requirement names accept a static header". No host that cannot send a header is named. The second reason refers to a switch (`MCP_ENABLED`) this design introduces. The cost is current: one of four pull requests, `cvert mcp` with `--enable-write-tool`, the single-request lane and its cancellation rules (7.8), the startup `whoami` rules (7.9), `CVERT_WEB_URL`, the stdio tests including a child-process test, the MCP half of version skew (5.6), and the MCP SDK and its transitive modules linked into the binary installed on script hosts. The shape already chosen (a tool package built from an API client) makes adding stdio later cheap, so deferring it closes nothing. Item 5 records the case for stdio only; no item records the case for HTTP only. Requirements are unpinned, so the private requirement may ask for stdio; the document does not say so.

**Axes:** contestable. Remedy is a choice (add the decision to section 12 with its case, or name the requirement or host that pays for stdio).

---

### R16 · alternatives & rationale

**Anchor:** section 7.3, "Loopback HTTP to the server's own URL was rejected: it would need the server to know its external URL and trust its own certificate".

**Claim:** The stated reason does not distinguish the options, and it conflicts with section 7.7.

**Evidence:** Section 7.7: "Over HTTP, `<web base>` is the server's configured external URL". `internal/config/config.go` line 32 has `ExternalURL` (`EXTERNAL_URL`, default `http://localhost:8080`), already used for OAuth redirect URLs (`server.go` line 169). The server therefore knows its external URL in both designs. A loopback call would also target the server's own listen address over plain HTTP, which needs neither the external URL nor a certificate. The remaining reason ("double the connections") stands. Related: the default `http://localhost:8080` means MCP result links point at localhost on any deployment that has not set `EXTERNAL_URL`; the design does not mention this.

**Axes:** objective. Remedy determinate (correct the rationale; note the `EXTERNAL_URL` default).

---

### R17 · unstated assumptions

**Anchor:** section 7.8, "Every tool call has a total deadline of 60 seconds"; section 7.2, "Agent hosts send none".

**Claim:** Two assumptions about agent hosts carry the primary transport and are not checked against the hosts the design names.

**Evidence:**
- The deadline exists so that a call "must not stall the agent" and returns an explanation. That works only if the host's own tool timeout is longer than 60 seconds. Codex's per-server `tool_timeout_sec` defaults to 60 seconds as far as the reviewer knows; at equal values the host can time out first and the agent gets the unexplained failure the section is written to prevent. The 60-second figure has no stated derivation. Probe for the runner: read the default MCP tool timeout in the documentation of each named host (Codex `tool_timeout_sec`, Claude Code `MCP_TOOL_TIMEOUT`).
- "A request with any `Origin` header gets 403 ... Agent hosts send none" is asserted without evidence. A host that runs its MCP client in a browser or an Electron renderer sends `Origin`, and would get a 403 with no hint of the cause. Probe for the runner: capture the request headers each named host sends to a test endpoint.

**Axes:** contestable. Remedy is a choice (verify and record; or set the deadline below the lowest host timeout; or state the unsupported host class).

---

### R18 · failure modes

**Anchor:** section 5.5, "retry once, only for `GET`, `PUT` and the check `POST`"; section 12 item 11, "retries after a lost response are the common case for agents".

**Claim:** The idempotency argument is applied to adding an item and not to removing one.

**Evidence:** `DELETE` is idempotent and is not in the retry list; no reason is given. After a lost response, a repeat of `items remove` or `remove_watchlist_item` gets 404, which is exit 8 or a tool error, and `items remove` "Stops at the first failure", leaving later IDs unremoved. Item 11 recommends treating an already-present item as success for exactly this retry case, and says nothing of an already-absent one. The read-only `POST`s (`rules validate`, `dry-run`) are also outside the retry list without a reason.

**Axes:** contestable. Remedy is a choice.

---

### R19 · change & reversibility

**Anchor:** section 5.6, "tool names, input schemas and result fields may change between commits until a release"; section 7.4, "Write tools are named one by one".

**Claim:** Two reversal costs are unstated.

**Evidence:**
- Write-tool names become operator configuration (`MCP_WRITE_TOOLS`, `--enable-write-tool`). Renaming or removing a write tool leaves a stale name in deployed configuration. Whether that fails startup or is ignored is not stated (R13 item 6), so the effect of a rename on existing deployments is unknown.
- The generated client's types and constants are used directly by `cmd/cvert` and `internal/mcpserver` (schemas from constants, result shaping from typed responses). Reversing the generator choice (item 3) would touch every consumer, not only `internal/apiclient`. The design calls the wrapper "thin" and does not state this.

Stated and adequate: no data migration is needed; `MCP_ENABLED=false` is the back-out for the endpoint; output and exit codes carry no compatibility promise; stored-cursor validity is required of FEED-1; version skew is declared undetected.

**Axes:** objective (unstated). Remedy determinate (state them).

---

### R20 · downstream readiness

**Anchor:** section 1, "scoped API keys (AUTH-3 ...)", "FEED-1", "AUTH-5", "AUTH-6"; section 2, "API-1 acceptance run"; section 12 item 13, "AUTH-7".

**Claim:** The requirement IDs collide with pitfall IDs in the repository the plan author is told to check.

**Evidence:** `dev/implementation-pitfalls.md` has entries with the same IDs and unrelated meanings: FEED-1 (JSON feed wire format), FEED-2 (archive/zip needs a seekable reader), AUTH-3 (JWT algorithm confusion), AUTH-5 (blocking semaphore), AUTH-6 (refresh token cloning), AUTH-7 (OAuth login CSRF), API-1 (`r.Context()` in background work). The design also cites pitfalls by the same scheme (NOTIFY-20, ARCH-13). Each requirement ID is glossed on first use, which limits the damage, but later uses are bare (section 10, item 13, item 16 "revisit with AUTH-3"), and the source document is private.

**Axes:** objective. Remedy determinate (qualify the IDs, for example "requirement AUTH-3", or use the gloss at each use).

---

### R0 · requirements trace (standing)

**Requirements completeness unverifiable — unpinned.** The requirements are summarised in section 1 from a private document. Section 12 item 1 says the same. Within the document, the design is consistent with its own summary except for the points in R5, and the narrowing of "no results" (item 7) is declared, not silent.

---

## Checks that found no problem

Recorded so the runner does not repeat them. Section 2's claims about `check.go` (500 items, one slot, 503 with `Retry-After: 1`, typed 422, untyped time-limit 503) match the code, and on the `/check` path no other handler or middleware returns a 503 with a problem body. The check handler tolerates a response writer without deadlines (`http.ErrNotSupported` is ignored), so an in-memory recorder is safe there. `whoami` returns the fields section 10 lists, and `org.role` is the capped effective role. The SDK options named in 7.2 exist with the stated behaviour (`Stateless`, `JSONResponse`, `DisableLocalhostProtection`, `MaxRequestBodyBytes`, 405 for `GET`/`DELETE`, `Mcp-Method`/`Mcp-Name` validation, latest protocol `2026-07-28`). The audit `action` constraint already allows `add` and `remove` (migration 000041). The watchlist item `POST` returns 409 for a duplicate and writes no audit row; the whole-list `PUT` returns `{added, removed, unchanged}`. No OSV ecosystem name in `internal/ecosystem` contains `/`. `go.mod` has no `replace` directive. A session cookie and an API key are distinguishable in the request context (`ctxAPIKeyID`).

---

## Per-lens lines

1. **Requirements trace:** R0 (standing: requirements completeness unverifiable — unpinned), R5.
2. **Simplicity & proportionality:** R2, R11, R15.
3. **Seams & contracts:** R1, R2, R3, R6, R14.
4. **Failure modes:** R1, R2, R4, R9, R10, R12, R18.
5. **Unstated assumptions:** R1, R3, R7, R8, R11, R17.
6. **Alternatives & rationale:** R2, R7, R14, R15, R16.
7. **Change & reversibility:** R19.
8. **Downstream readiness:** R3, R4, R5, R6, R8, R13, R20. Pitfalls docs were present and checked: R4 (ARCH-34, ARCH-40), R6 (ARCH-13, AUTH-24), R12 (ARCH-13), R13 item 10 (testing-pitfalls section 5), R14 (NOTIFY-20, NOTIFY-21).
