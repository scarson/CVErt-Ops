# Design: an API client CLI and an MCP server (CLI-1, MCP-1)

Date: 2026-11-13. Author: Claude, for Sam. Status: draft for Sam's review. No implementation code exists. New public surfaces (a binary, its commands, flags and exit codes, an MCP tool set) and one new dependency need Sam's approval before code; section 12 lists the decisions.

Review ledger: `dev/plans/reviews/2026-11-13-api-client-cli-and-mcp-server-design.ledger.md`.

## 1. Goal and scope

Two clients of the CVErt Ops HTTP API, for machines that hold an API key and no browser session:

- **CLI-1, a command-line client** for scripts on a timer: look up CVEs, check component versions, poll alert events, inspect and test alert rules, and maintain watchlist items. Scripts read its JSON output with `jq`.
- **MCP-1, an MCP server** for AI agents that patch software: the same reads as tools, with narrow input schemas and compact results, over stdio. Streamable HTTP is optional in the requirement; section 7.6 recommends deferring it.

The requirements come from the private homelab integration requirements (section 7.7, as amended by its section 9 decisions). Those decisions dropped inventory and findings, so this design has no `inventory push`, `findings list` or `findings set-state` command and no `list_findings` or `set_finding_state` tool. The requirement's `annotate` tool needs triage notes on alert events (INV-4), which are not built, so it is out of scope too.

**Not in scope:** scoped API keys (AUTH-3; a viewer-role key is how an agent is made read-only for now), MCP resources and prompts (MCP-2), rule creation or editing from either client, key rotation (AUTH-6), private advisories (INV-3), and a non-interactive bootstrap command (OPS-2).

**Depends on unbuilt work.** Three API changes are being built in a parallel session and are designed against here as the requirements state them: `GET /api/v1/whoami` (AUTH-5), an ascending `after` cursor on alert events (FEED-1) and `expand=cve,rule` on alert events (FEED-2). Section 10 lists exactly what each part of this design needs from them. Nothing that depends on them is built before they land.

**Evidence.** Code was read at `origin/dev` commit `5598af6`. The MCP SDK was built and scanned from a scratch module on 2026-11-13 (section 4). Repository status for every candidate dependency was read from the GitHub API and web searches on 2026-11-13.

## 2. Findings that shaped the design

| Finding | Evidence | Consequence |
|---|---|---|
| The server binary cannot be installed with `go install`. `web/embed.go` embeds `all:dist`, and `web/dist` is git-ignored, so a build from the module proxy fails with "no matching files found". | `web/embed.go`, `web/.gitignore`; CLAUDE.md records the same failure in fresh worktrees. | A client inside `cvert-ops` can only be had by building the frontend first or pulling the container image (section 3). |
| The container image is distroless and its entrypoint is `/cvert-ops`. | `docker/Dockerfile` | A second binary can be copied into the same image at no cost to the server. |
| The version check takes at most 500 items, under the global 1 MiB body limit. One check runs at a time on the whole server; a second request gets 503 with `Retry-After: 1`. A request that reads too many candidate rows gets 422 with problem type `urn:cvert:error:candidate_limit_exceeded`. A check that runs past 30 seconds, or a statement timeout, gets 503 without `Retry-After`. | `internal/api/check.go` (`maxCheckItems`, `maxConcurrentChecks = 1`, `checkTimeout`, `writeCheckFailure`), `internal/api/server.go` line 235. | Batching must be sequential, must split on 422, and must tell the two 503s apart (section 6). |
| Org routes share one token bucket per org: 60 requests a minute on the free tier, with a burst of 10. A refused request gets 429 with `Retry-After: 60`. `/cves` routes are authenticated but not under the org limiter. | `internal/api/middleware_tier.go`, `internal/api/cves.go` `registerCVERoutes`. | Every client request counts against a budget shared with the web UI and other keys. The clients never send requests in parallel, and they retry 429 only within a time budget (section 5.5). |
| Alert events list newest first, 100 a page, with no `limit` parameter. | `internal/api/alert_events.go` | `events list --after` and `list_alert_events` wait for FEED-1. |
| Dry-run takes a saved rule's ID; there is no dry-run of an unsaved rule. `validate` returns 200 with `valid: false` for an invalid rule. | `internal/api/alert_rules.go` `dryRunHandler`, `validateAlertRuleHandler`. | `rules dry-run <rule-id>`; `rules validate` maps `valid: false` to an exit code (section 5.4). |
| Watchlist items are added one per `POST`, removed by item ID, and replaced as a whole list (`PUT`, at most 10,000 items). | `internal/api/server.go` routes, `internal/api/watchlists.go` | `items add` sends one request per item; `items replace` is the path for a list taken from a scanner. A 10,000-item list of long package names can exceed the 1 MiB body limit; the CLI checks the encoded size before sending. |
| The web UI has pages for `/cves/:cveId` and `/watchlists/:id`, and none for alert rules or events. | `web/src/router/index.ts` | Results link CVEs and watchlists to the UI. Rules and events carry stable IDs and no link (section 7.4). |
| The DSL package imports `internal/store/generated`. | `internal/alert/dsl/accessor.go` | The MCP server cannot import it to build its DSL reference without linking store code; a test keeps a hand-written reference in step instead (section 7.3). |
| A client generated by `oapi-codegen` v2.8.2 from the served 3.0 document compiled and round-tripped every response the CLI and MCP server need, with no hand edits, during the API-1 acceptance run. | Private homelab integration requirements, section 11.1 (API-1 row). | Generation is feasible; section 4.2 weighs it against a hand-written layer on cost, not feasibility. |

## 3. Decision: a separate `cvert` binary

**Recommendation: a new command `cmd/cvert`, built as the binary `cvert`, holding both the CLI and `cvert mcp`. The container image carries it too, at `/cvert`.**

| | Separate `cvert` binary | `cvert-ops client ...` and `cvert-ops mcp` |
|---|---|---|
| Install on an agent host or workstation | `go install github.com/scarson/cvert-ops/cmd/cvert@<version>` works, because `cmd/cvert` does not import `web` (enforced, section 8.2). | Fails from the module proxy (section 2). Needs a source checkout with Node and `npm run build`, or the container image. |
| What is linked | HTTP client, cobra, the MCP SDK. | Everything the server links: pgx, feed adapters, the SPA, huma. |
| Attack surface on an agent host | No database code and no server configuration in the binary. | The whole server, idle. |
| Container image | Both binaries in one image; `docker run --entrypoint /cvert ...` runs the client. | One binary; `docker run ... client ...`. |
| Cost | A second build target in CI and the Dockerfile; the version ldflags set twice. | None beyond the commands. |

The server reads its configuration only inside `serve`, `worker` and the other server commands, so a subcommand would not trip over missing database settings. That is not a reason either way. The deciding facts are `go install` and the size of what an agent host has to run. Whether `go install` from the proxy works for this module (whose repository name differs in case from its module path) is untested; the plan's first task verifies it against a pushed branch.

## 4. Dependencies

### 4.1 MCP SDK

**Recommendation: `github.com/modelcontextprotocol/go-sdk` v1.8.0**, the official SDK. Verdict: needs Sam's sign-off, for one transitive module (`yosida95/uritemplate`, below).

| Check | Result | Notes |
|---|---|---|
| Repository status | OK | Not archived. Official SDK of the MCP project, maintained with Google. |
| Last commit | OK | 2026-11-10. |
| Last release | OK | v1.8.0, 2026-09-14. |
| Open issues | OK | 80 open; active triage. |
| Known vulnerabilities | OK for v1.8.0 | Four high-severity advisories in 2026, all fixed by v1.4.1: case-insensitive JSON field matching (GHSA-wvj2-96wp-fq3f, fixed 1.3.1), mishandled NUL characters in JSON (GHSA-q382-vc8q-7jhj, fixed 1.4.1), cross-site tool execution on HTTP servers without authorization (GHSA-89xv-2j6f-qhc8, fixed 1.4.1) and DNS rebinding protection off by default on localhost HTTP servers (GHSA-xw59-hvm2-8pj6, fixed 1.4.0). Two concern the HTTP transport, which section 7.6 defers. |
| Canonical location | OK | `github.com/modelcontextprotocol/go-sdk`. |
| License | OK | Apache-2.0 for new contributions, MIT for older ones not yet relicensed. Both compatible. |
| Transitive modules | Needs sign-off | Linked by a stdio server (measured with `go list -deps`): `google/jsonschema-go` v0.4.3 (MIT, released 2026-04), `segmentio/encoding` v0.5.4 and `segmentio/asm` v1.1.3 (MIT and MIT-0, active), `yosida95/uritemplate/v3` v3.0.2 (BSD-3-Clause, **last commit and release 2022-04**), and `golang.org/x/oauth2`, `x/time`, `x/sync`, which `go.mod` already requires. |
| Go module status | OK | On pkg.go.dev; minor releases about monthly. |

Measured from a scratch stdio server with one tool: it builds, and the binary is 11.5 MB (Windows amd64, default flags). `govulncheck` finds no reachable vulnerability in the SDK or its modules; it reports one in `golang.org/x/sys` v0.41.0, which this repository's `go.mod` already overrides with v0.49.0.

`uritemplate` fails the age rule of the `dependency-check` skill (no commit in 24 months). It is linked because the SDK supports resource templates. Both SDKs below depend on it, so no SDK avoids it. This design registers no resource or resource template (MCP-2 is out of scope), so no input reaches it. Sam decides whether that is acceptable.

Alternatives considered:

- `github.com/mark3labs/mcp-go` v1.5.0 (MIT, active, released 2026-10-30). One high advisory in 2026, in its OAuth client (GHSA-xf6j-693p-wqxx, fixed 1.2.1). Its `go.mod` adds `spf13/cast` and `santhosh-tekuri/jsonschema`, and it also depends on `uritemplate`. No advantage over the official SDK for a server that this project would maintain for years.
- Writing the JSON-RPC and MCP layer by hand. Rejected: protocol version negotiation, cancellation and schema generation are a lot of code to own, and the official SDK's own 2026 advisories (JSON field case, NUL handling) show where a hand-written parser goes wrong.

### 4.2 API client: hand-written, not generated

**Recommendation: a thin hand-written client package, with the checked-in `openapi.json` as a test oracle. No new dependency.**

| | Generated by `oapi-codegen` | Hand-written thin layer |
|---|---|---|
| New dependencies | Generator `oapi-codegen/oapi-codegen/v2` v2.8.2 as a tool (Apache-2.0, active, about 300 open issues; at least ten advisories in 2026, nearly all code injection from a crafted spec, which ours is not, and one in generated server code, which a client does not use). Runtime `oapi-codegen/runtime` v1.9.0 linked into the binary (Apache-2.0, active, no advisories), which brings `apapsch/go-jsonmerge` and `oapi-codegen/nullable`. | None. |
| Generated code | Types and methods for all 137 operations, of which the clients use 14. | Methods for the 14. |
| Keeping in sync | The 3.0 document is served but not checked in. CI would have to write it, run the generator and fail on a diff, beside the existing `schema.d.ts` check. | A test (no database) checks every operation the client calls against the checked-in `openapi.json`, which an existing test already keeps current (section 9.1). |
| Output | Typed values, re-encoded for output. | Server JSON written through unchanged (section 5.3); only the fields the client acts on are decoded. |
| MCP results | Mapped from generated types to compact shapes. | Mapped from small hand-written structs to compact shapes. Same work. |

The CLI's default output is the server's own JSON, so most responses never need a Go type. The fields the clients do read are few: cursors, check statuses and indexes, problem details, and the columns of table output. A generator would add a runtime dependency and a large generated file to read them.

## 5. The CLI

### 5.1 Configuration

| Setting | Source | Rules |
|---|---|---|
| Server URL | `CVERT_URL`, or `--url` | Base URL of the server, such as `https://cvert.example.internal`. The client appends `/api/v1`. `http://` is refused unless the host is a loopback address, because the key would cross the network in clear text. No flag overrides this. |
| API key | `CVERT_API_KEY`, or `CVERT_API_KEY_FILE` naming a file that holds it | Exactly one of the two. Both set, or neither, is a configuration error (exit 2). There is no flag for the key, so it never appears in argv or shell history. A file's content is trimmed of surrounding whitespace. The key must match `cvo_` and 64 hex characters before anything is sent; an error message never repeats the value. |
| Web UI base | `CVERT_WEB_URL` | Optional. Defaults to the server URL, where the server serves the SPA. Used only for links (section 7.4). |
| Organisation | `GET /whoami` | Not configured. A key belongs to one org; the client asks `whoami` once per process (section 10). A `CVERT_ORG_ID` setting would save that request, but it could disagree with the key and turn every call into a 403 that names the wrong cause. |

The HTTP client sends the key as `Authorization: Bearer`, keeps no cookie jar, does not follow redirects (a redirect is reported as an error), and sets a `User-Agent` of `cvert/<version>`. Per-request timeout: 60 seconds, which covers the check endpoint's 30-second limit and its 30-second write deadline.

The client never logs a request body or the key. Check items describe what an org runs, and the server does not log them either (`checkComponentsHandler`).

### 5.2 Commands

| Command | Request | Notes |
|---|---|---|
| `whoami` | `GET /whoami` | Waits for AUTH-5. |
| `cves search [flags]` | `GET /cves` | Flags mirror the endpoint's filters: `--q`, `--severity` (repeatable), `--date-from`, `--date-to`, `--cwe`, `--ecosystem`, `--package`, `--kev`, `--exploit`, `--cvss-min`, `--cvss-max`, `--epss-min`, `--epss-max`, `--limit`, `--cursor`, `--all`. |
| `cves get <id>` | `GET /cves/{id}` | Takes any stored record ID, including the advisory IDs the check endpoint returns. |
| `cves sources <id>` | `GET /cves/{id}/sources` | |
| `check [--input purls\|json\|trivy] [FILE\|-]` | `POST /orgs/{org}/check`, batched | Section 6. |
| `events list [--after CURSOR] [--rule ID] [--cve ID] [--open] [--limit N] [--all]` | `GET /orgs/{org}/alert-events?after=...&expand=cve,rule` | Waits for FEED-1 and FEED-2. `--open` sends `last_match_state=true`, as the MCP tool's `open_only` does. |
| `rules list [--all]` | `GET /orgs/{org}/alert-rules` | |
| `rules validate [FILE\|-]` | `POST /orgs/{org}/alert-rules/validate` | Body `{logic, conditions, watchlist_ids}`. |
| `rules dry-run <rule-id>` | `POST /orgs/{org}/alert-rules/{id}/dry-run` | |
| `watchlists list` | `GET /orgs/{org}/watchlists` | Added so a script can find a watchlist ID. |
| `watchlists items list <watchlist-id> [--all]` | `GET .../watchlists/{id}/items` | Added so a script can find an item ID to remove. |
| `watchlists items add <watchlist-id> (--cve ID \| --package ECO/NAME \| --cpe CPE)...` | `POST .../watchlists/{id}/items`, one per item | Repeatable flags; one request each, sequentially. `--package` splits at the first `/`, which no OSV ecosystem name contains, so `npm/@scope/name` is ecosystem `npm` and package `@scope/name`. The command stops at the first failed request, prints the items added before it, and exits with that failure's code; an item already on the list fails with 409 (exit 8). A caller that needs a repeatable operation uses `replace`. |
| `watchlists items remove <watchlist-id> <item-id>...` | `DELETE .../items/{item_id}` | Stops at the first failure, as `add` does. |
| `watchlists items replace <watchlist-id> (--file ITEMS.json \| --cves FILE\|-)` | `PUT .../watchlists/{id}/items` | `--cves` reads one CVE ID per line, the shape `jq -r` produces from a scanner report. Refused locally, with exit 2, above 10,000 items or 1 MiB encoded. |

`--all` follows `next_cursor` until the server returns none, and prints one envelope `{"items": [...]}` holding every item. It stops with an error above 10,000 items, so `cves search --all` with no filter cannot walk the whole corpus by accident. One envelope, rather than one JSON object per line, keeps every command's output a single JSON document, so the same `jq` filter works with and without `--all`.

### 5.3 Output

`--output json` is the default. A single-resource command prints the server's response body unchanged, followed by a newline. A list command without `--all` prints the server's `{items, next_cursor}` envelope unchanged. `check` prints the merged result of its batches in the server's response shape (section 6.3).

`--output table` prints fixed columns for a person at a terminal. It is not a stable interface; scripts use JSON. Table cells replace every control character with `?`, because values such as rule names are written by org members and a raw escape sequence would act on the terminal. Columns:

| Command | Columns |
|---|---|
| `cves search` | CVE, severity, CVSS v3, EPSS, KEV, modified |
| `cves get` | One row per affected range: ecosystem or CPE, package or product, introduced, fixed |
| `check` | One row per listed advisory: item index, component, status, advisory, verdict, fixed version |
| `events list` | Event ID, CVE, rule name, severity, KEV, first fired |
| `rules list` | Rule ID, name, status, logic, condition count |
| `watchlists items list` | Item ID, type, value |

Errors go to stderr as one line, `cvert: <message>`, followed by the server's problem `title` and `detail` when there is one. Nothing but the result goes to stdout.

### 5.4 Exit codes

| Code | Meaning | When |
|---|---|---|
| 0 | Success | The request succeeded and, for a search or list, returned at least one item. |
| 1 | Unexpected failure | Network error, a response the client cannot decode, a redirect. |
| 2 | Usage or configuration error | Bad flags, missing `CVERT_URL`, both or neither key setting, malformed key, unreadable input, input over a limit the client checks. No request was sent. |
| 3 | No results | A search or list returned no items; `cves get` or `cves sources` got 404. |
| 4 | Authentication failed | 401: the key is unknown, revoked or expired. |
| 5 | Permission denied | 403: the key's role is too low for the request. |
| 6 | Rate limited | 429, or the check endpoint stayed busy, after the retry budget ran out (section 5.5). |
| 7 | Server error | 5xx other than those retried. |
| 8 | Request rejected | 400, 404 on a path other than a lookup, 409, 413, 422; and `rules validate` when the server answers `valid: false`. |
| 9 | Partial result | `check` answered some items and could not answer others (section 6.2). The merged output is still printed. |

`check` exits 0 whatever the statuses of its items. A flag that fails the command when an item is affected was considered and left out: which statuses should fail differs per script (`unresolved` is a failure for some and not others), and `jq -e` expresses each choice in one line. Distinguishing 401 from 403 matters to a script's operator: 401 means replace the key, 403 means the key's role is wrong.

### 5.5 Retries

Requests are never sent in parallel. The org shares one rate bucket and the server runs one version check at a time, so parallel requests would only produce 429s and 503s for this client and everyone else.

- **429:** wait for `Retry-After` and retry, while the wait fits in the remaining budget. `--max-wait` sets the budget for the whole command, default 2 minutes. The server sends `Retry-After: 60`, so the default allows about one retry.
- **503 with `Retry-After` from `/check`:** the check slot was busy. Wait for `Retry-After` plus up to 500 ms of jitter and retry, within the same budget.
- **Connection failure before a response:** retry once, only for `GET`, `PUT` and the check `POST`, which are safe to repeat. A watchlist item `POST` is not retried.
- **Everything else** is reported at once.

### 5.6 Compatibility

The application has no users besides its developers, so the JSON output and exit codes carry no compatibility promise until a release says otherwise; `docs/client.md` says so. The client is built and tested against the spec of its own commit. A client calling a server from another commit may send a parameter the server no longer accepts, which the server rejects (exit 8), or read a field the server has renamed, which shows up as a missing value and not as an error. Nothing in this design detects version skew.

## 6. Batching `check`

### 6.1 Input

| `--input` | Format | Becomes |
|---|---|---|
| `purls` (default) | Text, one package URL per line. Blank lines and lines starting with `#` are skipped. | One `{purl}` item per line. |
| `json` | `{"items": [...]}` or a bare array, each element in the endpoint's item shape. | Passed through. |
| `trivy` | A Trivy JSON report. | One item per distinct package (below). |

**Trivy reports.** For each entry of `Results`, the CLI reads `Packages` when the report has them (Trivy writes them with `--list-all-pkgs`), and otherwise `Vulnerabilities`, which lists only packages with known vulnerabilities; it then prints a warning to stderr saying so. A package's purl is `Identifier.PURL`, or `PkgIdentifier.PURL` in a vulnerability entry. Packages with no purl are skipped and counted in a stderr summary.

For a `deb` purl the CLI substitutes the source package: name from `SrcName` and version from `SrcVersion` (with `SrcEpoch` when set), keeping the purl's `distro` qualifier. The check endpoint looks up distro packages by source name and answers `cannot_evaluate` with reason `distro_package_not_found` for a binary name (version check design, `dev/plans/2026-11-08-version-check-endpoint-design.md` section 6, distro answers). The new purl is built with `packageurl-go`, which the module already uses, so the server does the ecosystem mapping and the CLI does not repeat it. Identical purls are sent once.

The field names above come from Trivy's report type, not from a captured report. The plan's first `check` task captures a report from the Trivy version in use, with and without `--list-all-pkgs`, as a golden fixture, and confirms them.

The CLI sets no item `id`. A purl can exceed the 128 characters the server echoes back, and the result's `index` and `component` already identify the item.

### 6.2 Batches

1. Split the items, in order, into batches of at most 500 items and at most 900 KiB encoded, leaving room under the 1 MiB body limit.
2. Send the batches one after another.
3. On 422 with problem type `urn:cvert:error:candidate_limit_exceeded`, split the batch in two halves and send each, recursively.
4. On 503 without `Retry-After` (the 30-second limit or a statement timeout), split the batch in two halves once and send each. A half that times out again is not split further.
5. An item that alone gets 422 for the candidate limit, or alone times out, is unanswered. It is listed in `unanswered` (section 6.3) and the command exits 9.

A batch is never resent whole after a timeout: the server's message says to retry or split, and a batch that took 30 seconds once will usually take 30 seconds again.

### 6.3 Merged output

The merged output has the endpoint's response shape, plus one field:

- `results`: every batch's results, each `index` rewritten to the item's position in the whole input.
- `data_complete`: true only if every batch said true.
- `feeds`: one entry per feed name. Where batches disagree, `complete` is true only if every batch said true, and `last_success_at` is null if any batch reported null, and otherwise the earliest value reported.
- `unanswered`: added by the client, `[{index, problem}]`, where `problem` is the server's problem title. Empty when every item was answered.

Nothing in a result is changed except `index`. The meaning of every status and reason is the server's.

## 7. The MCP server

### 7.1 How it acts only with the caller's key, through the HTTP API

`cvert mcp` starts an MCP server on stdio. The agent host starts it as a child process, with `CVERT_URL` and `CVERT_API_KEY_FILE` (or `CVERT_API_KEY`) in its environment.

The MCP package is built from one value: an API client holding the server URL and the caller's key. Its constructor takes nothing else, no database pool, no store, no server configuration. Every tool call becomes one or more HTTP requests to the server with that key, so authentication, the key's role cap, the org rate limit and the audit log apply exactly as they do to a script using the same key. A write made through a tool is audited with the key's `api_key_id`.

Three things keep it that way:

1. A `depguard` rule refuses, in the non-test files of `cmd/cvert`, the API client package and the MCP package, any import of `internal/store`, `internal/api`, `internal/config`, `web`, `github.com/jackc/pgx`, and `database/sql`. Test files may import them, because the end-to-end tests start a real server (section 9).
2. A CI step builds `./cmd/cvert` in a checkout with no `web/dist`, which fails if anything it imports reaches `web`.
3. The tool set (section 7.2) excludes everything a viewer key could read but an agent does not need, including channels and API keys.

`stdout` carries only MCP messages; logs go to stderr. At startup the server calls `whoami`. A 401 or 403 there ends the process with exit code 4 or 5 and a message on stderr, which the agent host shows; the server does not start in a state where every tool fails.

### 7.2 Tools

Read tools are always registered. Write tools are registered only with `cvert mcp --enable-writes`, a flag in the agent host's configuration for that server. With the flag off, an agent cannot even see a write tool. With the flag on, a viewer key still gets 403 from the server, which is the guarantee: the flag narrows what the agent is offered, and the key's role decides what it can do.

| Tool | API calls | Input | Annotations |
|---|---|---|---|
| `whoami` | `GET /whoami` | none | read-only |
| `search_advisories` | `GET /cves` | `query`, `severity[]`, `in_cisa_kev`, `ecosystem`, `package_name`, `cwe_id`, `modified_since`, `min_cvss`, `min_epss`, `limit` (1 to 50, default 20), `cursor` | read-only |
| `get_advisory` | `GET /cves/{id}` | `id` | read-only |
| `check_components` | `POST /orgs/{org}/check`, batched as in section 6 | `items[]`, 1 to 500, each exactly one of `{purl}`, `{ecosystem, name, version}`, `{cpe, version}` | read-only |
| `list_alert_events` | `GET /orgs/{org}/alert-events?expand=cve,rule` | `after`, `rule_id`, `cve_id`, `open_only`, `limit` (1 to 100, default 50) | read-only; waits for FEED-1, FEED-2 |
| `list_rules` | `GET /orgs/{org}/alert-rules` | `cursor` | read-only |
| `validate_rule` | `POST .../alert-rules/validate` | `logic` (`and`, `or`), `conditions[]`, `watchlist_ids[]` | read-only |
| `dry_run_rule` | `POST .../alert-rules/{id}/dry-run` | `rule_id` | read-only |
| `list_watchlists` | `GET .../watchlists` | `cursor` | read-only |
| `list_watchlist_items` | `GET .../watchlists/{id}/items` | `watchlist_id`, `cursor` | read-only |
| `add_watchlist_item` | `POST .../watchlists/{id}/items` | `watchlist_id`, exactly one of `cve_id`, `{ecosystem, package_name}`, `cpe` | write; not destructive |
| `remove_watchlist_item` | `DELETE .../items/{item_id}` | `watchlist_id`, `item_id` | write; destructive |

`list_watchlists` and `list_watchlist_items` are not in the requirement's list. Without them an agent cannot find the IDs that the write tools take, or see which components the org watches, which the requirement's orientation use case asks for. Replacing a whole watchlist is CLI-only: one wrong call could empty a list of 10,000 items, and a scanner script, not an agent, is its caller.

Input schemas are narrow: enumerations are enumerated, numbers have bounds, strings have the server's length limits, IDs have patterns (`^CVE-\d{4}-\d{4,}$` where only a CVE ID is valid, UUID patterns for rule, watchlist and item IDs), and no object accepts properties it does not list. The schemas are generated by the SDK from Go input structs, so the struct tags are their single source.

### 7.3 Descriptions

Each tool description states what the tool answers, the units and ranges of its numbers, and its enumerations. They are written for an agent that has never seen CVErt Ops. Key content:

- **Units.** CVSS scores are 0.0 to 10.0, and `min_cvss` compares the CVSS v4 score where a CVE has one and the v3 score otherwise. EPSS is a probability from 0 to 1, not a percentage. Dates are RFC 3339 in UTC. `modified_since` compares the date of the CVE's last material change: its status, severity, CVSS, CWEs, KEV or exploit flag, affected packages or affected CPEs. A change to EPSS, the description, NVD's CPE version ranges or the CNA's product data alone does not move it.
- **`check_components` statuses.** Only `not_affected` clears a version. `affected`: at least one advisory reports the version affected. `unresolved`: nothing was established as affected, but the data leaves at least one advisory undecided for this version, so this is not a clean result. `cannot_evaluate`: the check could not be completed; read `reason`. `no_advisory_found`: no advisory names the component in the data searched, which is not a statement that it is safe. `invalid`: the item could not be read; read `error`. `data_complete: false` means a feed the item depends on has not finished a full walk or has not succeeded for 7 days, so absence of an advisory means less.
- **`check_components` reasons**, one line each, including: distro packages are named by source package (`php8.5`, not `php8.5-cli`); a .NET SDK version must be sent as the runtime version; `fix_ecosystem` of the form `Ubuntu:Pro:<release>` means the fix ships only through Ubuntu Pro; `distro_lists_fixes_only` means the distribution's feed records issued fixes only, so a clean answer is never given for it.
- **`validate_rule`:** the DSL's fields and operators, so an agent can write a rule without another call.
- **Untrusted text.** Advisory descriptions and references come from external feeds. `get_advisory` and `search_advisories` say so, so the agent treats that text as data.

The check endpoint's own field documentation (`internal/api/check.go`) stays the authoritative text. Two tests keep the descriptions from drifting: one fails when a `status` or `reason` value in the served spec is missing from the `check_components` description, and one fails when a DSL field name in `internal/alert/dsl` is missing from the `validate_rule` description. The descriptions summarise; they do not copy the server's text.

### 7.4 Results

Results are compact JSON in the MCP result's structured content, with the same JSON as one text block for hosts that read only text. Null and empty fields are omitted. Every result carries stable IDs and, where the web UI has a page, a link:

- CVEs and advisories: `id` and `url` (`<web base>/cves/<id>`).
- Watchlists: `id` and `url` (`<web base>/watchlists/<id>`).
- Rules and alert events: `id` only. The web UI has no page for either.

Per tool:

- `search_advisories`: per item `id`, `severity`, `cvss_v3`, `cvss_v4`, `epss`, `in_cisa_kev`, `exploit_available`, `modified`, `summary` (the description cut at 300 characters, with `summary_truncated`), `url`; and `next_cursor`.
- `get_advisory`: the list fields with the full description cut at 4,000 characters; `cwe_ids`; affected package ranges as `{ecosystem, package, introduced, fixed}`; NVD CPE matches with their range bounds; CNA product entries; up to 20 references as `{url, tags}` with the number omitted. Each list notes how many entries it omitted.
- `check_components`: `data_complete`, the feeds that are not complete, and per item `index`, `id`, `status`, `reason`, `component`, `counts`, and up to 20 advisories as `{advisory_id, cve_ids, verdict, reason, fixed_version, fix_major, fix_ecosystem, severity, cvss_v3, epss, in_cisa_kev, url}`, with `advisories_truncated`. `matched_ranges` is left out; `get_advisory` has the ranges. `unanswered` as in section 6.3.
- `list_alert_events`: per event `id`, `rule_id`, `rule_name`, `cve_id`, `severity`, `in_cisa_kev`, `epss`, `open`, `first_fired_at`, `last_fired_at`, `url` of the CVE; and the cursor to pass as `after` next time.
- `dry_run_rule`: `match_count`, `candidates_evaluated`, `partial`, and up to 20 sample CVE IDs with URLs.

A failed API call returns a tool error, not a protocol error, with a fixed sentence naming the HTTP status and the server's problem title and detail. The key never appears in a result.

### 7.5 Limits inside a tool call

Tool calls follow section 5.5 with a budget of 5 seconds instead of 2 minutes. An MCP host may send several tool calls at once; the server still sends one API request at a time, and a call waiting for its turn does not spend its retry budget while it waits. A busy check slot (`Retry-After: 1`) is retried inside the call. A 429 (`Retry-After: 60`) is returned to the agent as an error that says when to retry, because blocking a tool call for a minute stalls the agent with no explanation.

One MCP session costs one request at startup (`whoami`) and one request per tool call, except `check_components`, which costs one per batch of 500 items.

### 7.6 Streamable HTTP: defer

**Recommendation: build stdio only. Decide on streamable HTTP when a caller needs it.**

The requirement makes it optional, and the agents it describes run the client locally. HTTP transport is a new public surface on the server, and it is where two of the SDK's four 2026 advisories were (cross-site tool execution, DNS rebinding). If it is built later, the shape that keeps section 7.1's guarantee is:

- Mounted in `serve` at `/api/v1/mcp`, requiring a Bearer key on every request, stateless.
- The handler builds the same MCP package from an API client whose transport calls the server's own router in process, carrying the caller's `Authorization` header and client address. Requests go through the same middleware chain as any API call. No service key exists.
- `Origin` checked, and the SDK's DNS rebinding protection on.

## 8. Code layout

### 8.1 Packages

| Path | Holds |
|---|---|
| `cmd/cvert/` | cobra commands, configuration loading, output formatting, exit codes. |
| `internal/apiclient/` | The HTTP client: configuration checks, the request function, problem-detail decoding, the error type that maps to exit codes, retries, check batching and merging, and one method per operation. |
| `internal/apiclient/trivy/` | Trivy report reading (section 6.1). |
| `internal/mcpserver/` | Tool definitions, input structs, result shaping and descriptions. Built from an `*apiclient.Client`. |

The CLI and the MCP server share batching, retries and error mapping in `internal/apiclient`, so the two cannot disagree on them.

### 8.2 Build and image

- `.golangci.yml`: the `depguard` rule of section 7.1.
- CI: build `./cmd/cvert` in a job that has no `web/dist`; run its tests with the Go tests.
- `docker/Dockerfile`: build `/cvert` beside `/cvert-ops` in the builder stage and copy it into the distroless stage. The entrypoint stays `/cvert-ops`.
- Version and commit set by the same ldflags as the server; `cvert --version` prints them, and the MCP server reports them in its implementation info.

### 8.3 Documentation

`docs/client.md`: installation, configuration, the command list, exit codes, a scanner-to-watchlist example with `jq`, and an agent host configuration example using `CVERT_API_KEY_FILE`, so the key does not sit in the host's configuration file. Example host names use `example.internal`.

## 9. Tests

Every test that reaches the API runs against a real server: the production handler from `internal/api`, a testcontainers PostgreSQL database from `testutil.NewTestDB`, CVEs from `testutil.SeedCorpus`, and users, orgs and keys created through the store, served over loopback by `httptest.NewServer`. No end-to-end test uses a mock.

### 9.1 No database

- **Spec conformance.** A table in `internal/apiclient` lists each operation the client calls: method, path template, query parameters, body field names, and the response field names it reads. A test checks each against the checked-in `openapi.json`, which the existing spec test keeps equal to the served spec. A renamed field or a removed parameter fails here.
- **Configuration.** Both key settings set, neither set, a malformed key, `http://` to a non-loopback host, an unreadable key file: each exits 2 and sends no request. No command defines a flag whose name contains `key`.
- **Trivy reading** against golden reports (section 6.1): deduplication, source-package substitution, skipped packages, the warning for a report without `Packages`.
- **Batch splitting and merging**, as unit tests of the splitting logic: 500 and 501 items, the 900 KiB size bound, index rewriting, feed merging.
- **Retry policy and the 422 and 503 splits**, against an `httptest` server that returns scripted statuses. These are unit tests of the client's reaction to statuses the real server cannot be made to return on demand (a candidate-limit overrun needs more candidate rows than the seeded corpus holds; a 30-second timeout would make the test take 30 seconds).
- **Descriptions** (section 7.3): every check status and reason in the spec, and every DSL field, appears in its tool description.

### 9.2 CLI against a real server

The CLI's commands run in process through a `run(args, env, stdin, stdout, stderr) int` function, so tests assert the exit code and both streams.

- Each command's success path, with output compared to the server's response.
- `check` with 501 items in one input: two requests, one merged result, indexes 0 to 500.
- `check --input trivy` with a golden report against the seeded corpus.
- Exit codes on the real server: a revoked key (4), a viewer key adding a watchlist item (5), an empty search (3), `cves get` of an unknown ID (3), an invalid rule in `rules validate` (8), and the 11th request inside the 10-request burst of a free-tier org with `--max-wait 0` (6).
- `watchlists items replace --cves -` from stdin, then the same list again, reporting all unchanged.
- In every test, a helper fails the test if the key appears in stdout or stderr.

### 9.3 MCP tools against a real server

- An MCP client from the SDK connected in memory to the MCP server, whose API client points at the real test server. Each tool is called and its result checked: compact fields present, URLs formed, truncation counts right.
- With `--enable-writes` off, the tool list has no write tool. With it on and a viewer key, `add_watchlist_item` returns a tool error naming 403, and the watchlist is unchanged. With a member key, the item is added and the audit log has a row with the key's `api_key_id`.
- A startup with a revoked key exits 4 without serving.
- One test builds `cvert` and runs `cvert mcp` as a child process over real stdio, to check that stdout carries only MCP messages and logs go to stderr.

### 9.4 Run cost

These tests add one more package that starts a PostgreSQL container (per `internal/testutil`, one container per test binary, with a cloned database per test). The MCP and CLI tests can share one test binary to keep that to one container.

## 10. What waits for the parallel session

| Work here | Needs | Exact need |
|---|---|---|
| Every org-scoped command and tool, and MCP startup | AUTH-5 `GET /whoami` | Accepts an API key. Returns at least the org ID, org name, the key's ID, name, role and expiry, and the org's tier and rate limit per minute. The design assumes it is outside the org rate limiter, like `/cves`; if it is inside, each CLI invocation costs one more request of the org's budget, which works but should be stated in `docs/client.md`. |
| `events list --after`, `list_alert_events` | FEED-1 | An ascending order selected by `after`, a `limit` parameter, and a cursor returned on every page that holds items, including the last, so a poller can store it and resume after the last event it saw. The design treats an absent cursor on an empty page as "keep the previous one". |
| Event context in `events list` and `list_alert_events` | FEED-2 | `expand=cve,rule` giving at least severity, KEV, EPSS and the rule name. |

Everything else can be built before they land: configuration, the API client and its conformance test, exit codes, `cves` commands, check batching and Trivy reading, rule and watchlist requests (once `whoami` gives the org, they need nothing new), and the MCP read tools other than `whoami` and `list_alert_events`. In practice the plan builds the client package and the `cves` commands first and the org-scoped commands after AUTH-5 merges.

## 11. Acceptance

Adapted from the requirement, whose example question depended on per-host findings, which section 9 of the private requirements dropped.

- A script on a timer, with only `cvert` and `jq`, can check a list of purls, poll alert events with a stored cursor, and replace a watchlist's CVE items from a scanner report, without writing HTTP code.
- An agent configured with a viewer key and the default flags can answer "is component X at version V affected by CVE Y, and which version fixes it on the same release line" in at most three tool calls (`check_components`, then `get_advisory` if it needs the ranges), and is offered no tool that changes anything.
- With `--enable-writes`, the same agent with a viewer key still changes nothing (403); with a member key, its writes appear in the audit log under its key.

## 12. Decisions for Sam

1. **Binary.** A separate `cvert` binary, also shipped in the container image (section 3). Alternative: subcommands of `cvert-ops`.
2. **Client code.** Hand-written, with a spec conformance test, and no new dependency (section 4.2). Alternative: generate with `oapi-codegen` v2.8.2 and add `oapi-codegen/runtime`.
3. **MCP SDK.** `github.com/modelcontextprotocol/go-sdk` v1.8.0, accepting its transitive `yosida95/uritemplate` v3.0.2, unchanged since 2022, which no input of ours reaches (section 4.1).
4. **Streamable HTTP.** Defer; stdio only (section 7.6).
5. **Tool set.** Two read tools beyond the requirement (`list_watchlists`, `list_watchlist_items`); write tools behind `--enable-writes` limited to adding and removing one watchlist item; whole-list replace CLI-only (section 7.2).
6. **Exit codes** as in section 5.4, including 9 for a partial `check`, and `rules validate` exiting 8 on an invalid rule.
7. **Clear-text transport.** Refuse `http://` except to loopback, with no override (section 5.1).
8. **No org setting.** The org always comes from `whoami`; no `CVERT_ORG_ID` (section 5.1).
9. **PLAN.md.** It has no section on an API client or MCP server. Add one stating the binary, the rule that both clients act only through the HTTP API with the caller's key, and the write-tool flag, with this design as the detail.

## 13. Delivery

Three pull requests, each with an implementation plan reviewed first:

1. `internal/apiclient`, `cmd/cvert` with configuration, exit codes, the `cves`, `check`, `rules` and `watchlists` commands, the `depguard` rule, the CI build without `web/dist`, the Dockerfile change, and `docs/client.md`. Org-scoped commands land once AUTH-5 has merged.
2. `cvert mcp` with the read tools and the write flag.
3. `events list` and `list_alert_events`, after FEED-1 and FEED-2.
