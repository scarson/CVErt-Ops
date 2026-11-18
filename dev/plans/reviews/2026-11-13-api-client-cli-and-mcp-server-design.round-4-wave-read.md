# Round 4 wave read: integration defects in the CLI and MCP design

Document: `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`. Wave: diff `808b0db..e7295cf`. Read on 2026-11-13. Source checks were made against the worktree at `e7295cf` and, for the alert-event feed, against `origin/dev`. The go-sdk v1.8.0 and oapi-codegen v2.8.2 sources were read from the local module cache.

Checked and found consistent: the 50-second deadline everywhere it appears (sections 7.2, 7.8, 8.1); `open_only` removed everywhere, and `--open` only on `events list --newest`; `--all` past 10,000 items now exits 0 everywhere (section 5.4 row 2 no longer lists it); requirement FEED-1 shown as landed everywhere, and section 13 reduced to three pull requests; every `section 12 item N` reference points at the right item. Factual claims confirmed against source: chi v5.5.0 (`go.mod`); `EXTERNAL_URL` default `http://localhost:8080` and `TRUSTED_PROXIES` (`internal/config/config.go`); no access log, and the context logger adds only `request_id` (`internal/api/log_middleware.go`); `writeProblem` sets no problem type (`internal/api/contract.go`); `matched_ranges_total` and `advisories_truncated` with at most 100 advisories (`internal/api/check.go`); page sizes 20, 20 and 50, and `/cves` maximum 100; `getServer` called at `mcp/streamable.go` lines 349 and 400 on the stateless path, and a nil server answered with 400; oapi-codegen emits `Valid()` per enumeration and no list of values; the generator's `go.mod` requires `gopkg.in/yaml.v3` and a 2022 `dprotaso/go-yit`; `feed_seq` lock, backfill to negative positions, the reopen moving the position and setting `last_fired_at`, the versioned cursor refused with 400 "invalid after", `limit` at most 1,000 (100 with `expand=rule`), and the refusal of `last_match_state`/`since` in feed order (`origin/dev`: `internal/api/alert_events.go`, `migrations/000062_alert_events_feed_seq.up.sql`, `internal/store/queries/alert_rules.sql`); testing-pitfalls section 5 holds "Rate limit accounting"; implementation pitfall AUTH-24 exists; `internal/ai` links `internal/store/generated` through `internal/alert/dsl`.

## Defects, most severe first

### D1. Over HTTP, the `whoami` tool sends `GET /whoami`, and three edited spans say no tool does

- Section 7.4 table, unchanged: "`whoami` | `GET /whoami` | none | read-only".
- Section 7.8, edited: "over HTTP, no tool call spends one, because the identity comes from the authenticated request (section 7.3)."
- Section 10 AUTH-5 row, edited: "The HTTP MCP endpoint does not call it; it uses the same code in process (section 7.3)."
- Section 9.3, added: "Identity: the server is built once per MCP request ..., and no `whoami` request is made."
- Section 7.2, edited: "neither does working out the caller's identity".

What is wrong: the `whoami` tool reaches the API through the in-process transport, and `GET /whoami` is on the allowlist (it is one of the generated operations). `whoamiForAPIKey` calls `allowOrgRequest` (`internal/api/whoami.go`), so each `whoami` tool call takes a token from the org bucket. The edits are true of identity resolution only, but they are written about tool calls and about the endpoint as a whole. The 9.3 test as written cannot pass if it calls the `whoami` tool. The design must choose: either the HTTP `whoami` tool answers from the identity it already holds (and the tool table row says so), or the three spans are limited to identity resolution.

### D2. "`next_cursor` on every page in feed order, including an empty one" is false for a first page that is empty

- Section 5.3: "`events list` in feed order always prints `next_cursor`, which the endpoint returns on every page in that order, including an empty one, so a script can store the field after every run."
- Section 7.7 `list_alert_events`: "`next_after` ..., which the endpoint returns on every page in feed order."
- Section 10 FEED-1 row: "`next_cursor` is returned on every page in this order, including an empty one."
- Section 9.2: "a first run with no `--after` reads from the start and prints `next_cursor`".

Evidence: `origin/dev:internal/api/alert_events.go`, the end of `listAlertEventsHandler`. In ascending order the cursor is set from the last event, or from `p.AfterSeq` when the page is empty. With no `after` and no events, `cursor` stays `""`. `listResponse.NextCursor` is tagged `json:"next_cursor,omitempty"` (`contract.go`), so the field is absent. This is the case of an org with no events yet, polled for the first time. The text before the wave ("or, when the first page is empty, the `--after` value it was given") had the same gap but did not claim "every page". Effect on the script that 5.3 describes: `jq -r .next_cursor` gives `null`, and a next run with `--after null` gets 400 "invalid after", which is exit 8. Either the CLI prints `next_cursor` as `null` or omits it, and section 5.3 says what a script stores, or the server returns a starting cursor for an empty first page.

### D3. The `cves` commands no longer call `whoami`, but pacing and section 12 item 9 still depend on it

- Section 5.1 Organisation row, edited: "a command that calls an org-scoped endpoint asks `whoami` once per process (section 10); the `cves` commands need no org and do not ask."
- Section 12 item 13, added: "pace long runs only, from `whoami`'s rate ... a long run is a CLI command that will send more requests than half the org's burst (`--all` walks, ...)".
- Section 12 item 9, unchanged: "`whoami` now counts against the org's rate limit, so every CLI run spends one request on it."

What is wrong: `cves search --all` is an `--all` walk, so by item 13 it is paced from `whoami`'s rate. But by 5.1 it never calls `whoami`. Also, `/cves` is not under the org limiter (section 2), so pacing it leaves no room for the web UI. Item 13's definition of a long run should exclude the `cves` commands. Item 9's "every CLI run" is now wrong for the `cves` commands.

### D4. The "already present" and "already absent" recommendation cannot be read from the server's answers

- Section 12 item 11, edited: "`items remove` fails with 404 on an item already gone" and "success for an item already present or already gone"; "the MCP tools return `already_present: true` or `already_absent: true` (section 7.7)".
- Section 7.7, added: "`add_watchlist_item`: `item` as in `list_watchlist_items`; and `already_present: true` if ... the item was already on the list."
- Section 5.2 `items remove` row, unchanged: "Stops at the first failure, as `add` does." It is not marked pending.

Evidence: `internal/api/watchlists.go`. The delete-item handler answers 404 "not found" when `DeleteWatchlistItem` deletes nothing. That happens for an item already gone, a mistyped item ID, an item on another watchlist, and a wrong watchlist ID. The same handler family answers "not found" for an unknown watchlist. So turning every 404 into `already_absent` success also reports a typo or a wrong watchlist as success. For `add`, the 409 is a problem body ("item already exists in watchlist") with no item, so the `item` that 7.7 promises with `already_present: true` is not in the response. It would need another request, or a server change that neither item 11 nor section 13 lists. Separately, the section 12 preamble says a span that a pending item would change "says it is pending". The `items add` row does say this. The `items remove` row, which item 11 now also covers, does not.

### D5. Section 12 item 14: "CNA text" can be read two ways, and one reading lets full cleaning alter version strings

- Section 12 item 14, edited: "Feeds write advisory descriptions, references, CNA vendor, product and version strings, package names and CPEs" and then "Recommendation: the pitfall's full cleaning on free-text fields (descriptions and CNA text), control and invisible formatting characters stripped and a 512-character cap on every other string field".

What is wrong: "CNA text" can mean the CNA's free-text fields, or every CNA string, including vendor, product and version, which the same item has just listed. The verdict on the case for descriptions only argues only for the light cleaning ("stripping control and invisible characters from an identifier removes nothing a real identifier contains"). That argument does not cover full cleaning of identifiers. `internal/ai/sanitize.go` strips `<[^>]*>`, so a CNA version string such as `<2.0 and >1.0` becomes `1.0`. The recommendation should name the CNA fields that get full cleaning.

### D6. The transport allowlist is said to be "the operations the MCP tools call", but its definition includes one that no tool calls

- Section 7.3, edited: "a fixed list of method and path templates, the operations the MCP tools call (the generated operations less the whole-list `PUT`, which section 7.4 keeps CLI-only)".

What is wrong: section 4.2 generates 14 operations, one for each CLI request in section 5.2, and that list includes `GET /cves/{id}/sources` (`cves sources`). Removing the `PUT` leaves 13 operations. The MCP tools in section 7.4 call 12. The parenthetical would put `cves sources` on the allowlist, and that contradicts "the operations the MCP tools call". The 9.1 allowlist test does not settle which definition is meant.

### D7. Sections 7.8 and 7.9 give different rules for when stdio retries `whoami`

- Section 7.8: "Over stdio, the process also spends one `whoami` request at startup, repeated on the first tool call if it failed".
- Section 7.9, edited: "the first tool call that needs the org retries `whoami`".

What is wrong: under 7.9, `search_advisories` and `get_advisory`, which need no org, do not retry. 7.8 says the first tool call of any kind retries. One of the two needs to change.

### D8. Section 10: the NOTIFY-20 clause can be read two ways, and the pitfall that records this failure is API-12

- Section 10 FEED-1 row, added: "this settles the late-commit failure implementation pitfall NOTIFY-20 records for the evaluator."

What is wrong: the clause can be read as "the feed fixes the evaluator's failure". It does not: the evaluator keeps its rescan window, which CLAUDE.md records under NOTIFY-20. The intended reading is "the feed does not have the failure that NOTIFY-20 records for the evaluator". `dev/implementation-pitfalls.md` API-12 ("A Sequence or Timestamp Cursor Skips Rows That Commit Out of Order") is the entry for a sequence cursor, and migration 000062 cites it. API-12 says that NOTIFY-20 is the timestamp version of the same flaw.

### D9. Clauses that read as answers to reviewers, not as design text

- Section 7.1, added: "and dropping it is the steelman of section 12 item 5." "Steelman" is review vocabulary, and item 5 itself uses the label "Strongest case for HTTP only". Suggested text: "and section 12 item 5 gives the case for dropping it."
- Section 7.8, added: "(`tool_timeout_sec`; read from secondary sources, which the plan confirms in Codex's own reference)". This is source provenance placed inside the requirement sentence. It reads as an answer to an objection about the source. The pending check belongs in the plan's list of checks or in a short separate sentence.

### D10. Section 2: the cap of 100 with `expand=rule` is stated as a feed-order property, but it applies in both orders

- Section 2 alert-events row, edited: "Feed order refuses `last_match_state` and `since`, and caps pages at 100 with `expand=rule`."

Evidence: `origin/dev:internal/api/alert_events.go`. `limit` (default 100, at most 1,000, or 100 with `expand=rule`) is parsed before the `order` switch, so the newest-first order takes `limit` and has the same cap. The sentence suggests that the newest-first order has no cap. Section 10's statement of the limit is correct. This has no effect on the CLI as designed, because `--newest` sends no `--limit` and the default is 100.
