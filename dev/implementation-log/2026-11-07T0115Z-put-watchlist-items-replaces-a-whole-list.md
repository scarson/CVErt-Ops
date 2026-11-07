# PUT watchlist items replaces a whole list

## What was built

- `PUT /api/v1/orgs/{org_id}/watchlists/{id}/items` (member+): takes `{"items":[...]}` and returns `{added, removed, unchanged}`. At most 10,000 items.
- `POST .../items` accepts `item_type: "cve"` with `cve_id`.
- `parseWatchlistItem` is the one validation path for both write routes. It upper-cases CVE IDs and enforces the column length limits, so an overlong value gets a 422 and not a 500 from a `CHECK` violation.
- The SPA shows a `cve` item by its ID with its own badge icon, and says when the table shows only the first page of a long list.
- `PLAN.md` §9.1, §9.2 and the Appendix B endpoint list.

## Key decisions

- **10,000 item cap.** A CVE item is about 50 bytes of JSON, so a list at the cap is about 500 KB inside the 1 MiB request limit, and `TestReplaceWatchlistItemsAPI_CapFitsRequestLimit` proves it with real IDs. `maxItems` in a struct tag cannot read the constant, so `TestOpenAPISpec_ReplaceItemsCapMatchesHandler` ties the two together.
- **A missing `items` key is a 422, and only an explicit `[]` clears the list.** A client bug should not empty a watchlist. A body cut off by the request limit fails to parse, so it cannot read as a short list either.
- **`POST` now checks watchlist ownership.** Foreign-key checks run without RLS, so a member of another org who knew a watchlist's UUID could insert a row against it. The row was invisible to the victim, but it occupied the victim's unique index and would have broken the victim's next replace. This route returns 404 now.
- **Item fields beyond `item_type` are `omitempty` in the spec.** They were all marked required, which told API clients to send every null. That would also have doubled the size of a CVE item against the request limit. The SPA no longer sends the nulls.
- **Only a push that changes something is audited**, so a scheduled push does not fill the audit log.

## Security review

Reviewed against `.claude/skills/security-review/SKILL.md`. SQL injection: static sqlc statements with parameters only. Tenant isolation: every statement filters on `org_id` inside `withOrgTx`, and the evaluator's list-change query feeds candidates only to rules bound to that watchlist. Input validation: the CVE regex is anchored, lengths and the item cap are bounded before any query. A 404 for an unknown watchlist and for another org's watchlist are identical.

Warning, not fixed here: `watchlist_items` has no retention, so soft-deleted rows stay forever. Normal use adds a few rows per changed CVE, but a member alternating two disjoint lists can add 10,000 rows per request, up to the org's rate limit.

## Gotchas

- `internal/api/org_ratelimit` allows a burst of 10 requests on the free tier, so a table test that sends one request per case gets 429s. The validation cases are unit tests on `parseWatchlistItem`.
- A schema named `ReplaceWatchlistItemsResponse` fails `TestOpenAPISpec_SchemaNamesFitGeneratedClients`, because a generated client gives the operation's type that name.
- A Bash heredoc over about 8 KB fails with a quote error on this host. Larger edit scripts go through the Write tool.

## Quality checks

- Targeted `go test ./internal/api/` (`Watchlist|ReplaceItems|OpenAPI|Security|SpecGate`) passes.
- `npm run type-check` and `npm run lint` pass. Vitest passes for `WatchlistDetailView` and the watchlist dialog; the new view tests were confirmed failing against the previous view.
- `golangci-lint run` on the changed packages reports 0 issues.
