# Design: an API client CLI and an MCP server (CLI-1, MCP-1)

Date: 2026-11-13. Author: Claude, for Sam. Status: draft for Sam's review. No implementation code exists. New public surfaces (a binary, its commands, flags and exit codes, an MCP tool set) and one new dependency need Sam's approval before code; section 12 lists the decisions, including those the design review raised.

Review ledger: `dev/plans/reviews/2026-11-13-api-client-cli-and-mcp-server-design.ledger.md`.

## 1. Goal and scope

Two clients of the CVErt Ops HTTP API, for machines that hold an API key and no browser session:

- **CLI-1, a command-line client** for scripts on a timer: look up CVEs, check component versions, poll alert events, inspect and test alert rules, and maintain watchlist items. Scripts read its JSON output with `jq`. The requirement asks for JSON by default with a table option, for `check` input as purls or a Trivy JSON report, and for exit codes that tell no results, authentication failure, rate limiting and server errors apart.
- **MCP-1, an MCP server** for AI agents that patch software: most of the same reads as tools, with narrow input schemas and compact results, over stdio. Streamable HTTP is optional in the requirement; section 7.6 recommends deferring it.

The requirements come from the private homelab integration requirements (section 7.7, as amended by its section 9 decisions). Those decisions dropped inventory and findings, so this design has no `inventory push`, `findings list` or `findings set-state` command and no `list_findings` or `set_finding_state` tool. The requirement's `annotate` tool needs triage notes on alert events (INV-4), which are not built, so it is out of scope too.

**Not in scope:** scoped API keys (AUTH-3; a viewer-role key is how an agent is made read-only for now), MCP resources and prompts (MCP-2), rule creation or editing from either client, key rotation (AUTH-6), private advisories (INV-3), and a non-interactive bootstrap command (OPS-2).

**Depends on unbuilt work.** Three API changes are being built in a parallel session and are designed against here as the requirements state them: `GET /api/v1/whoami` (AUTH-5), an ascending `after` cursor on alert events (FEED-1) and `expand=cve,rule` on alert events (FEED-2). Section 10 lists exactly what each part of this design needs from them. Nothing that depends on them is built before they land.

**Evidence.** Code was read at `origin/dev` commit `5598af6`. The MCP SDK was built and scanned from a scratch module on 2026-11-13 (section 4). Repository status for every candidate dependency was read from the GitHub API and web searches on 2026-11-13.

## 2. Findings that shaped the design

| Finding | Evidence | Consequence |
|---|---|---|
| The server binary cannot be installed with `go install`. `web/embed.go` embeds `all:dist`, and `web/dist` is git-ignored, so a build from the module proxy fails with "no matching files found". | `web/embed.go`, `web/.gitignore`; CLAUDE.md records the same failure in fresh worktrees. | A client inside `cvert-ops` can only be had by building the frontend first or pulling the container image (section 3). |
| The container image is distroless and its entrypoint is `/cvert-ops`. | `docker/Dockerfile` | A second binary can be copied into the same image at no cost to the server. |
| The version check takes at most 500 items, under the global 1 MiB body limit. One check runs at a time on the whole server; a second request gets 503 with `Retry-After: 1`. A request that reads too many candidate rows gets 422 with problem type `urn:cvert:error:candidate_limit_exceeded`. A check that runs past 30 seconds, or a statement timeout, gets 503 without `Retry-After`. | `internal/api/check.go` (`maxCheckItems`, `maxConcurrentChecks = 1`, `checkTimeout`, `writeCheckFailure`), `internal/api/server.go` line 235. | Batching must be sequential, must split on 422, and must tell the two 503s apart (section 6). A free slot is taken without a queue, so one org's long run of checks can make another org's checks wait. This design leaves the slot as it is. |
| Org routes share one token bucket per org: 60 requests a minute on the free tier, with a burst of 10. A refused request gets 429 with `Retry-After: 60`. `/cves` routes are authenticated but not under the org limiter. | `internal/api/middleware_tier.go`, `internal/api/cves.go` `registerCVERoutes`. | Every client request counts against a budget shared with the web UI and other keys. The clients never send requests in parallel, and they retry 429 only within a time budget (section 5.5). |
| Alert events list newest first, 100 a page, with no `limit` parameter. | `internal/api/alert_events.go` | `events list --after` and `list_alert_events` wait for FEED-1. |
| Dry-run takes a saved rule's ID; there is no dry-run of an unsaved rule. `validate` returns 200 with `valid: false` for an invalid rule. | `internal/api/alert_rules.go` `dryRunHandler`, `validateAlertRuleHandler`. | `rules dry-run <rule-id>`; `rules validate` maps `valid: false` to an exit code (section 5.4). |
| Watchlist items are added one per `POST`, removed by item ID, and replaced as a whole list (`PUT`, at most 10,000 items). | `internal/api/server.go` routes, `internal/api/watchlists.go` | `items add` sends one request per item; `items replace` is the path for a list taken from a scanner. A 10,000-item list of long package names can exceed the 1 MiB body limit; the CLI checks the encoded size before sending. |
| The web UI has pages for `/cves/:cveId` and `/watchlists/:id`, and none for alert rules or events. | `web/src/router/index.ts` | Results link CVEs and watchlists to the UI. Rules and events carry stable IDs and no link (section 7.4). |
| The DSL package imports `internal/store/generated` directly, in `accessor.go` only. The field catalog (`FieldDescription`, `ExportFieldDescriptions()` in `field.go`) imports only `internal/ecosystem`, and `internal/ai/schema.go` already uses it. | `internal/alert/dsl/*.go` imports | The MCP server cannot import the DSL package without linking store code. Its DSL reference either comes from the catalog moved to a store-free package or is hand-written and tested against the catalog (section 7.3; a decision for Sam, section 12). |
| The `/cves` filters `cvss_min`, `cvss_max`, `epss_min` and `epss_max` are read from the raw query string and are missing from the served spec. They are pointer fields without `query:` tags because huma refuses pointer query parameters. | `internal/api/cves.go` lines 263–268 (fields) and 304–307 (parsing); no match in `openapi.json`. | The first pull request documents them in the spec by another means than a pointer `query:` tag (section 13), so the client's conformance test can check them like every other parameter. |
| Creating and deleting a single watchlist item writes no audit row. Watchlist create, update, delete and whole-list replace do. | `internal/api/watchlists.go`: `auditLog` calls at lines 256, 307, 515, 559 and 691 only. | Item writes through either client are not audited today (sections 7.1 and 12). |
| A client generated by `oapi-codegen` v2.8.2 from the served 3.0 document compiled and round-tripped every response the CLI and MCP server need, with no hand edits, during the API-1 acceptance run. | Private homelab integration requirements, section 11.1 (API-1 row). | Generation is feasible; section 4.2 weighs it against a hand-written layer on cost, not feasibility. |

## 3. Decision: a separate `cvert` binary

**Recommendation: a new command `cmd/cvert`, built as the binary `cvert`, holding both the CLI and `cvert mcp`. The container image carries it too, at `/cvert`.**

| | Separate `cvert` binary | `cvert-ops client ...` and `cvert-ops mcp` |
|---|---|---|
| Install on an agent host or workstation | `go install github.com/scarson/cvert-ops/cmd/cvert@<commit or branch>` is expected to work (checked below; the plan's first task proves it), because `cmd/cvert` does not import `web` (enforced, section 8.2). | Fails from the module proxy (section 2). Needs a source checkout with Node and `npm run build`, or the container image. |
| What is linked | HTTP client, cobra, the MCP SDK. | Everything the server links: pgx, feed adapters, the SPA, huma. |
| Attack surface on an agent host | No database code and no server configuration in the binary. | The whole server, idle. |
| Container image | Both binaries in one image; `docker run --entrypoint /cvert ...` runs the client. | One binary; `docker run ... client ...`. |
| Cost | A second build target in CI and the Dockerfile. | None beyond the commands. |

The server reads its configuration only inside `serve`, `worker` and the other server commands, so a subcommand would not trip over missing database settings. That is not a reason either way. The deciding facts are `go install` and the size of what an agent host has to run.

What has been checked about `go install` (2026-11-13): the repository is public, `go.mod` has no `replace` directive, and the module proxy resolves the lower-case module path `github.com/scarson/cvert-ops` (`go list -m -json github.com/scarson/cvert-ops@latest` returns a pseudo-version). The repository has no release tags, so an install names a commit or a branch until releases exist. An end-to-end `go install github.com/scarson/cvert-ops/cmd/cvert@<branch>` from a clean module cache is the plan's first task; if it fails, the fallback is the container image, which carries `/cvert` either way.

Prebuilt release binaries would remove the Go toolchain from agent hosts and would make the server binary installable without Node too. No release pipeline exists, and building one is not part of this work; if one is built later, it ships `cvert` beside the server.

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

`uritemplate` fails the age rule of the `dependency-check` skill (no commit in 24 months). It is linked because the SDK supports resource templates. `mcp-go`, the other SDK considered below, depends on it too, so neither avoids it. This design registers no resource or resource template (MCP-2 is out of scope), so no input reaches it. Sam decides whether that is acceptable.

Alternatives considered:

- `github.com/mark3labs/mcp-go` v1.5.0 (MIT, active, released 2026-10-30). One high advisory in 2026, in its OAuth client (GHSA-xf6j-693p-wqxx, fixed 1.2.1). Its `go.mod` adds `spf13/cast` and `santhosh-tekuri/jsonschema`, and it also depends on `uritemplate`. It has fewer advisories, but it parses JSON with its own code, which this review did not examine, while the official SDK's two 2026 parsing advisories are fixed in the versions this design would use. For a server this project would maintain for years, the official SDK's backing by the protocol's maintainers decides it.
- Writing the JSON-RPC and MCP layer by hand. Rejected: protocol version negotiation, cancellation and schema generation are a lot of code to own, and the official SDK's own 2026 advisories (JSON field case, NUL handling) show where a hand-written parser goes wrong.

### 4.2 API client: hand-written, not generated

**Recommendation: a thin hand-written client package, with the checked-in `openapi.json` as a test oracle. No new dependency.**

| | Generated by `oapi-codegen` | Hand-written thin layer |
|---|---|---|
| New dependencies | Generator `oapi-codegen/oapi-codegen/v2` v2.8.2 as a tool (Apache-2.0, active, about 300 open issues; at least ten advisories in 2026, nearly all code injection from a crafted spec, which ours is not, and one in generated server code, which a client does not use). Runtime `oapi-codegen/runtime` v1.9.0 linked into the binary (Apache-2.0, active, no advisories), which brings `apapsch/go-jsonmerge` and `oapi-codegen/nullable`. | None. |
| Generated code | Types and methods for all 137 operations, of which the clients use 14. | Methods for the 14. |
| Keeping in sync | Types checked by the compiler. The 3.0 document is served but not checked in; CI would write it (the spec tests already fetch it in process), run the generator and fail on a diff, beside the existing `schema.d.ts` check. | A test (no database) checks every operation the client calls against the checked-in `openapi.json`, which an existing test already keeps current: names, JSON types and enum values of each parameter and field the client sends or reads (section 9.1). Weaker than compiled types for fields the client does not read, which it passes through unchanged. |
| Output | Typed values, re-encoded for output. | Server JSON written through unchanged (section 5.3); only the fields the client acts on are decoded. |
| MCP results | Mapped from generated types to compact shapes. | Mapped from small hand-written structs to compact shapes. Same work. |

The CLI's default output is the server's own JSON, so most responses never need a Go type. The fields the clients do read are few: cursors, check statuses and indexes, problem details, and the columns of table output. A generator would add a runtime dependency and a large generated file to read them.

A third option is to move the request and response types into a package that imports no store code and import it from both the server and the client, which gives compiled agreement with no generator. The check types in `internal/api/check.go` are already exported, but most handler types the client needs are unexported chi-handler structs (`alertEventEntry`, `watchlistItemEntry`, `alertRuleEntry`). Moving them is a refactor of server code for 14 operations, and it ties the client to the server's Go types rather than to the published contract. It is not recommended now; it stays open if conformance checking proves too weak.

## 5. The CLI

### 5.1 Configuration

| Setting | Source | Rules |
|---|---|---|
| Server URL | `CVERT_URL`, or `--url` | Base URL of the server, such as `https://cvert.example.internal`. The client appends `/api/v1`. `http://` is refused unless the host is a loopback address, because the key would cross the network in clear text. The server has no TLS listener, so remote use needs a TLS-terminating proxy, as the production compose stack's Caddy provides. Whether to add a setting for a private CA file, and whether plain HTTP may be allowed to a named host, are decisions for Sam (section 12). |
| API key | `CVERT_API_KEY`, or `CVERT_API_KEY_FILE` naming a file that holds it | Exactly one of the two. Both set, or neither, is a configuration error (exit 2). There is no flag for the key, so it never appears in argv or shell history. A file's content is trimmed of surrounding whitespace. The key must match `cvo_` and 64 hex characters before anything is sent; an error message never repeats the value. |
| Web UI base | `CVERT_WEB_URL` | Optional. Defaults to the server URL, where the server serves the SPA. Used only for links (section 7.4). |
| Organisation | `GET /whoami` | Not configured. A key belongs to one org; the client asks `whoami` once per process (section 10). A `CVERT_ORG_ID` setting would save that request, but it could disagree with the key and turn every call into a 403 that names the wrong cause. |

The HTTP client sends the key as `Authorization: Bearer`, keeps no cookie jar, does not follow redirects (a redirect is reported as an error), and sets a `User-Agent` of `cvert/<version>`. Per-request timeout: 60 seconds, which covers the check endpoint's 30-second limit and its 30-second write deadline. Every response body is read to the end and closed, and read through a size limit, 64 MiB for a check response and 16 MiB for anything else; a larger response is an error (exit 1). A 500-item check whose items each list 100 advisories can approach tens of megabytes, which sets the first limit.

`<version>` comes from `runtime/debug.ReadBuildInfo`: the module version for a `go install` of a tagged or pseudo version, otherwise the VCS revision Go records when it builds inside a git checkout. A build without `.git`, such as the container image (`.dockerignore` excludes it), has neither, so the Dockerfile passes the commit as a build argument into linker flags, which override `ReadBuildInfo`. No build sets the server's own version flags today (`cmd/cvert-ops/main.go` defaults to `dev`; CI runs `go build ./cmd/cvert-ops` with no flags; the Dockerfile passes `-s -w` only).

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
| `rules list [--cursor C] [--all]` | `GET /orgs/{org}/alert-rules` | |
| `rules validate [FILE\|-]` | `POST /orgs/{org}/alert-rules/validate` | Body `{logic, conditions, watchlist_ids}`. |
| `rules dry-run <rule-id>` | `POST /orgs/{org}/alert-rules/{id}/dry-run` | |
| `watchlists list [--cursor C] [--all]` | `GET /orgs/{org}/watchlists` | Added so a script can find a watchlist ID. |
| `watchlists items list <watchlist-id> [--cursor C] [--all]` | `GET .../watchlists/{id}/items` | Added so a script can find an item ID to remove. |
| `watchlists items add <watchlist-id> (--cve ID \| --package ECO/NAME \| --cpe CPE)...` | `POST .../watchlists/{id}/items`, one per item | Repeatable flags; one request each, sequentially. `--package` splits at the first `/`, which no OSV ecosystem name contains, so `npm/@scope/name` is ecosystem `npm` and package `@scope/name`. Prints `{"added": [...]}` with the server's item for each request that succeeded. The command stops at the first failed request, still prints what was added before it, and exits with that failure's code. How a 409 for an item already on the list is treated is a decision for Sam (section 12). |
| `watchlists items remove <watchlist-id> <item-id>...` | `DELETE .../items/{item_id}` | Prints `{"removed": [...]}` with the item IDs removed. Stops at the first failure, as `add` does. |
| `watchlists items replace <watchlist-id> (--file ITEMS.json \| --cves FILE\|-)` | `PUT .../watchlists/{id}/items` | `--file` takes the endpoint's own body, `{"items": [...]}`. `--cves` reads one CVE ID per line, the shape `jq -r` produces from a scanner report: each line is trimmed and upper-cased, blank lines are skipped, duplicates are sent once, and a line that is not a CVE ID fails the command with exit 2 before anything is sent (the server would refuse the whole request). Refused locally, with exit 2, above 10,000 items or 1 MiB encoded. The server replaces the whole list, so `--cves` also removes any package or CPE item on the watchlist; what to do about that is a decision for Sam (section 12). |

Every list command takes `--cursor`, to continue from a `next_cursor` it printed, and `--all`; `events list` takes `--after` in place of `--cursor`. `--all` follows `next_cursor` until the server returns none or returns an empty page, and prints one envelope `{"items": [...]}` holding every item; `events list` adds `next_cursor` to that envelope (section 5.3). It stops above 10,000 items with exit 2 and prints nothing, so `cves search --all` with no filter cannot walk the whole corpus by accident. One envelope, rather than one JSON object per line, keeps every command's output a single JSON document, so the same `jq` filter works with and without `--all`. `cves search` pages by modification date, newest first, so a CVE modified while `--all` walks the pages moves above the walk and is missed; a script that needs every change polls with `--date-from` and an overlap.

### 5.3 Output

`--output json` is the default. A single-resource command prints the server's response body unchanged, followed by a newline. A list command without `--all` prints the server's `{items, next_cursor}` envelope unchanged. `events list` is the exception that keeps a poller's place: it always prints `next_cursor`, which is the last cursor the server returned, or, when the first page is empty, the `--after` value it was given, so a script can store the field after every run. `check` prints the merged result of its batches in the server's response shape (section 6.3).

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
| 1 | Unexpected failure | Network error, a response the client cannot decode or that exceeds its size limit, a redirect. |
| 2 | Usage, configuration or client limit | Bad flags, missing `CVERT_URL`, both or neither key setting, malformed key, unreadable or empty input, input over a limit the client checks, or `--all` past 10,000 items. Except for `--all`, no request was sent. |
| 3 | No results | A search or list returned no items; `cves get` or `cves sources` got 404. |
| 4 | Authentication failed | 401: the key is unknown, revoked or expired. |
| 5 | Permission denied | 403: the key's role is too low for the request, or its creator is no longer a member of the org. |
| 6 | Rate limited | 429, or the check endpoint stayed busy, after the retry budget ran out (section 5.5). |
| 7 | Server error | 5xx other than those retried. |
| 8 | Request rejected | 400, 404 on a path other than a lookup, 409, 413, 422; and `rules validate` when the server answers `valid: false`. |
| 9 | Partial result | `check` answered some items, and every item it could not answer was left unanswered by the splits of section 6.2 (a candidate-limit or time-limit failure the splits could not get past). The merged output is still printed. |

Codes 3 (an empty list) and 8 (an invalid rule in `rules validate`) are proposals awaiting Sam's decision (section 12): exit 3 on an empty list makes every quiet poll of `events list` a non-zero exit.

`check` exits 0 whatever the statuses of its items. A flag that fails the command when an item is affected was considered and left out: which statuses should fail differs per script (`unresolved` is a failure for some and not others), and `jq -e` expresses each choice in one line. Distinguishing 401 from 403 matters to a script's operator: 401 means replace the key; 403 means the key's role is too low or the key's creator has lost membership of the org.

### 5.5 Retries

Requests are never sent in parallel. The org shares one rate bucket and the server runs one version check at a time, so parallel requests would only produce 429s and 503s for this client and everyone else. Whether the clients also pace their requests below the org's rate, to leave room for the web UI, is a decision for Sam (section 12); the rules below assume they do not.

- **429:** wait for `Retry-After` and retry, while the wait fits in the remaining budget. `--max-wait` sets the budget for the whole command, default 2 minutes. The server sends `Retry-After: 60`, so the default allows about one retry.
- **503 with `Retry-After` from `/check`:** the check slot was busy. Wait for `Retry-After` plus up to 500 ms of jitter and retry, within the same budget.
- **503 from `/check` without `Retry-After`, with a `application/problem+json` body:** the server's check time limit (section 6.2). Any other 503, such as a proxy's own page while the server is down, is a server error (exit 7) and is never split.
- **Connection failure before a response:** retry once, only for `GET`, `PUT` and the check `POST`, which are safe to repeat. A watchlist item `POST` is not retried.
- **Everything else** is reported at once.

### 5.6 Compatibility

The application has no users besides its developers, so the JSON output and exit codes carry no compatibility promise until a release says otherwise; `docs/client.md` says so. The client is built and tested against the spec of its own commit. A client calling a server from another commit may send a parameter the server no longer accepts, which the server rejects (exit 8), or read a field the server has renamed, which shows up as a missing value and not as an error. Nothing in this design detects version skew. `cvert --version` prints the client's version, and `whoami` returns the server's (section 10), so a person can compare them once server builds set a version.

The same holds for the MCP tool set: tool names, input schemas and result fields may change between commits until a release. A tool that is renamed or removed disappears from the tool list, which an agent host reports as an unknown tool, not as a wrong answer.

## 6. Batching `check`

### 6.1 Input

| `--input` | Format | Becomes |
|---|---|---|
| `purls` (default) | Text, one package URL per line. Blank lines and lines starting with `#` are skipped. Input with no purl left fails with exit 2. | One `{purl}` item per line. |
| `json` | `{"items": [...]}` or a bare array, each element in the endpoint's item shape. | Passed through. |
| `trivy` | A Trivy JSON report. | One item per distinct package (below). |

**Trivy reports.** For each entry of `Results`, the CLI reads `Packages` when the report has them (Trivy writes them with `--list-all-pkgs`), and otherwise `Vulnerabilities`, which lists only packages with known vulnerabilities; it then prints a warning to stderr saying so. A package's purl is `Identifier.PURL`, or `PkgIdentifier.PURL` in a vulnerability entry. Packages with no purl are skipped and counted in a stderr summary.

For a `deb` or `apk` purl with a `SrcName`, the CLI substitutes the source package: name from `SrcName`, version `[SrcEpoch:]SrcVersion[-SrcRelease]` (Trivy keeps the Debian revision in `SrcRelease`, separate from `SrcVersion`), keeping the purl's `distro` qualifier and dropping its `epoch` qualifier, which belongs to the binary package. The check endpoint looks up distro packages by source name and answers `cannot_evaluate` with reason `distro_package_not_found` for a binary name (version check design, `dev/plans/2026-11-08-version-check-endpoint-design.md` section 6, distro answers). The new purl is built with `packageurl-go`, which the module already uses, so the server does the ecosystem mapping and the CLI does not repeat it. Identical purls are sent once.

Purl types the endpoint does not support, such as `rpm` from Red Hat, AlmaLinux, Rocky Linux or SUSE hosts, are still sent: the server answers them `invalid` with `unsupported_purl_type`, and the stderr summary counts them, so the server stays the one authority on what it supports.

The field names and the version rule above come from Trivy's report type and its dpkg analyzer, not from a captured report. The plan's first `check` task captures reports from the Trivy version in use, from a Debian and an Alpine image, with and without `--list-all-pkgs`, as golden fixtures, and asserts the full substituted purl for each package, version string included.

Trivy's native report was chosen over a scanner-neutral CycloneDX document because the requirement names it, and because the source package fields the substitution needs are in Trivy's native report and only in Trivy-specific properties in its CycloneDX output. CycloneDX input can be added later as another `--input` value.

**Item identity.** `index` in the output is the item's position among the items sent: for `purls`, the position among the purl lines after blank and comment lines are skipped; for `json`, the position in the input array; for `trivy`, the position in the deduplicated list. For `trivy` input the CLI sets each item's `id` to Trivy's package `ID` (such as `libc6@2.36-9+deb12u4`) when it fits the server's 128-character limit, so a result can be traced to its package; for `purls` input it sets none, because a purl can exceed that limit and the `index` and `component` identify the item.

### 6.2 Batches

1. Split the items, in order, into batches of at most 500 items and at most 900 KiB encoded, leaving room under the 1 MiB body limit.
2. Send the batches one after another.
3. On 422 with problem type `urn:cvert:error:candidate_limit_exceeded`, split the batch in two halves and send each, recursively.
4. On the server's time-limit 503 (section 5.5), split the batch in two halves and send each. A half that hits the time limit again is not split further: all of its items are unanswered. A batch that came from a 422 split can be split again on a timeout, and the reverse; each response is handled by its own rule.
5. An item that alone gets 422 for the candidate limit, or alone hits the time limit, is unanswered.
6. Items left unanswered by steps 3 to 5 are listed in `unanswered` (section 6.3). If those were the only failures, the command prints the merged output and exits 9.
7. Any other failure (401, 403, 400, 413, a 422 of another problem type, 5xx, a network error, or the retry budget running out on 429 or a busy slot) stops the run: no further batch is sent, the merged output of what was answered is printed with every remaining item in `unanswered`, and the command exits with that failure's code (4, 5, 8, 7, 1 or 6), which takes precedence over 9.

A batch is never resent whole after a timeout: the server's message says to retry or split, and a batch that took 30 seconds once will usually take 30 seconds again. Each request is bounded by the server's 30-second limit, and each split level at most doubles the requests for a batch, so a batch that keeps hitting both limits costs a few minutes; the retry budget of section 5.5 covers waits, not splits.

### 6.3 Merged output

The merged output has the endpoint's response shape, plus one field:

- `results`: every batch's results, each `index` rewritten to the item's position in the whole input.
- `data_complete`: true only if every batch said true.
- `feeds`: one entry per feed name. Where batches disagree, `complete` is true only if every batch said true, and `last_success_at` is null if any batch reported null, and otherwise the earliest value reported.
- `unanswered`: added by the client, `[{index, id, problem}]`, where `problem` is the server's problem `detail` (its `title` is only the HTTP status text), or the client's own message for a failure with no problem body. Empty when every item was answered.

Nothing in a result is changed except `index`. The meaning of every status and reason is the server's.

## 7. The MCP server

### 7.1 How it acts only with the caller's key, through the HTTP API

`cvert mcp` starts an MCP server on stdio. The agent host starts it as a child process, with `CVERT_URL` and `CVERT_API_KEY_FILE` (or `CVERT_API_KEY`) in its environment.

The MCP package is built from an API client holding the server URL and the caller's key, plus the write tools the host's flags enable and the client's version. It takes no database pool, no store and no server configuration. Every tool call becomes one or more HTTP requests to the server with that key, so authentication, the key's role cap, the org rate limit and the audit log apply exactly as they do to a script using the same key. Audit entries depend on the endpoint: today the server audits watchlist create, update, delete and whole-list replace, but not single item add or delete (section 2), so a tool's item write is not audited until the server change in section 12 is made.

Four things keep it that way:

1. A `depguard` rule refuses, in the non-test files of `cmd/cvert`, the API client package and the MCP package, any import of `internal/store`, `internal/api`, `internal/config`, `web`, `github.com/jackc/pgx`, and `database/sql`. Test files may import them, because the end-to-end tests start a real server (section 9).
2. `depguard` sees only each file's own imports, so a client package that imported `internal/alert/dsl` or `internal/ai`, which import `internal/store/generated` themselves, would link store code without tripping it. So a test runs `go list -deps ./cmd/cvert` and fails when the list holds any package the rule denies.
3. A CI step builds `./cmd/cvert` in a checkout with no `web/dist`, which fails if anything it imports reaches `web`.
4. The tool set (section 7.2) excludes everything a viewer key could read but an agent does not need, including channels and API keys.

`stdout` carries only MCP messages; logs go to stderr. At startup the server calls `whoami`. A 401 or 403 there ends the process with exit code 4 or 5 and a message on stderr, which the agent host shows; the server does not start in a state where every tool fails. Any other failure there (a network error, a 5xx, a 429) does not stop it: the server starts, and the first tool call retries `whoami` and returns its error to the agent if it fails again. An agent host may start before the network or the server is up, and a process that exits then stays down until the host restarts it.

### 7.2 Tools

Read tools are always registered. Write tools are registered only with `cvert mcp --enable-writes`, a flag in the agent host's configuration for that server; whether that flag names the tools it enables is a decision for Sam (section 12). With the flag off, an agent cannot even see a write tool. With the flag on, a viewer key still gets 403 from the server, which is the guarantee: the flag narrows what the agent is offered, and the key's role decides what it can do.

| Tool | API calls | Input | Annotations |
|---|---|---|---|
| `whoami` | `GET /whoami` | none | read-only |
| `search_advisories` | `GET /cves` | `query`, `severity[]`, `in_cisa_kev`, `ecosystem`, `package_name`, `cwe_id`, `modified_since`, `min_cvss`, `min_epss`, `limit` (1 to 50, default 20), `cursor` | read-only |
| `get_advisory` | `GET /cves/{id}` | `id` | read-only |
| `check_components` | `POST /orgs/{org}/check`, as in section 6 with the limits of section 7.5 | `items[]`, 1 to 500, each exactly one of `{purl}`, `{ecosystem, name, version}`, `{cpe, version}`, with an optional `id` of at most 128 characters | read-only |
| `list_alert_events` | `GET /orgs/{org}/alert-events?expand=cve,rule` | `after`, `rule_id`, `cve_id`, `open_only`, `limit` (1 to 100, default 50) | read-only; waits for FEED-1, FEED-2 |
| `list_rules` | `GET /orgs/{org}/alert-rules` | `cursor` | read-only |
| `validate_rule` | `POST .../alert-rules/validate` | `logic` (`and`, `or`), `conditions[]`, `watchlist_ids[]` | read-only |
| `dry_run_rule` | `POST .../alert-rules/{id}/dry-run` | `rule_id` | read-only |
| `list_watchlists` | `GET .../watchlists` | `cursor` | read-only |
| `list_watchlist_items` | `GET .../watchlists/{id}/items` | `watchlist_id`, `cursor` | read-only |
| `add_watchlist_item` | `POST .../watchlists/{id}/items` | `watchlist_id`, exactly one of `cve_id`, `{ecosystem, package_name}`, `cpe` | write; not destructive |
| `remove_watchlist_item` | `DELETE .../items/{item_id}` | `watchlist_id`, `item_id` | write; destructive |

`list_watchlists` and `list_watchlist_items` are not in the requirement's list. Without them an agent cannot find the IDs that the write tools take, or see which components the org watches, which the requirement's orientation use case asks for. Replacing a whole watchlist is CLI-only: one wrong call could empty a list of 10,000 items, and a scanner script, not an agent, is its caller.

Input schemas are narrow: enumerations are enumerated, numbers have bounds, strings have the server's length limits, IDs have patterns (`^CVE-\d{4}-\d{4,}$` where only a CVE ID is valid, UUID patterns for rule, watchlist and item IDs), and no object accepts properties it does not list. The SDK's schema inference reads only a `jsonschema` tag, as a description (`jsonschema-go` v0.4.3, `infer.go`), so these constraints cannot come from tags. Each tool sets its `InputSchema` explicitly: the schema inferred from its Go input struct, with the constraints added in code beside the struct. The SDK infers a schema only when none is set (`go-sdk` v1.8.0, `server.go`), and validates input against the one it has. A test sends each tool out-of-range, wrong-enum and extra-property input and expects a refusal.

### 7.3 Descriptions

Each tool description states what the tool answers, the units and ranges of its numbers, and its enumerations. They are written for an agent that has never seen CVErt Ops. Key content:

- **Units.** CVSS scores are 0.0 to 10.0, and `min_cvss` compares the CVSS v4 score where a CVE has one and the v3 score otherwise. EPSS is a probability from 0 to 1, not a percentage. Dates are RFC 3339 in UTC. `modified_since` compares the date of the CVE's last material change: its status, severity, CVSS, CWEs, KEV or exploit flag, affected packages or affected CPEs. A change to EPSS, the description, NVD's CPE version ranges or the CNA's product data alone does not move it.
- **`check_components` statuses.** Only `not_affected` clears a version. `affected`: at least one advisory reports the version affected. `unresolved`: nothing was established as affected, but the data leaves at least one advisory undecided for this version, so this is not a clean result. `cannot_evaluate`: the check could not be completed; read `reason`. `no_advisory_found`: no advisory names the component in the data searched, which is not a statement that it is safe. `invalid`: the item could not be read; read `error`. `data_complete: false` means a feed the item depends on has not finished a full walk or has not succeeded for 7 days, so absence of an advisory means less.
- **`check_components` reasons**, one line each, including: distro packages are named by source package (`php8.5`, not `php8.5-cli`); a .NET SDK version must be sent as the runtime version; `fix_ecosystem` of the form `Ubuntu:Pro:<release>` means the fix ships only through Ubuntu Pro; `distro_lists_fixes_only` means the distribution's feed records issued fixes only, so a clean answer is never given for it.
- **`get_advisory` ranges.** Package ranges from the detail endpoint carry `introduced` and `fixed` but not `last_affected`, which the endpoint does not return; `check_components` results carry the matched ranges with every bound.
- **`validate_rule`:** the DSL's fields, operators and enumerated values, so an agent can write a rule without another call.
- **Untrusted text.** Advisory descriptions and references come from external feeds. `get_advisory` and `search_advisories` say so, so the agent treats that text as data. Whether the text is also cleaned before it reaches the agent is a decision for Sam (section 12).

The check endpoint's own field documentation (`internal/api/check.go`) stays the authoritative text. Tests keep the descriptions from drifting: one fails when a `status`, `reason`, `warnings` or `error.code` value in the served spec is missing from the `check_components` description, and one fails when a DSL field, operator or enumerated value in the DSL field catalog is missing from the `validate_rule` description. The descriptions summarise; they do not copy the server's text.

### 7.4 Results

Results are compact JSON in the MCP result's structured content, with the same JSON as one text block for hosts that read only text. A field the server can return as null keeps its null, because the server uses null to mean "not known" (`in_cisa_kev` and `epss_score` on a check advisory, for example) and that is not the same as false or zero. Booleans are always present. Only empty lists and optional strings with no value are omitted. Every result carries stable IDs and, where the web UI has a page, a link:

- CVEs and advisories: `id` and `url` (`<web base>/cves/<id>`).
- Watchlists: `id` and `url` (`<web base>/watchlists/<id>`).
- Rules and alert events: `id` only. The web UI has no page for either.

Per tool:

- `search_advisories`: per item `id`, `severity`, `cvss_v3`, `cvss_v4`, `epss`, `in_cisa_kev`, `exploit_available`, `modified`, `summary` (the description cut at 300 characters, with `summary_truncated`), `url`; and `next_cursor`.
- `get_advisory`: the list fields with the full description cut at 4,000 characters; `cwe_ids`; up to 50 affected package ranges as `{ecosystem, package, range_type, introduced, fixed}`; up to 50 NVD CPE matches with their range bounds; up to 20 CNA product entries; up to 20 references as `{url, tags}`. Each list carries the number of entries it omitted.
- `check_components`: `data_complete`, the feeds that are not complete, and per item `index`, `id`, `status`, `reason`, `error`, `warnings`, `data_complete`, `component`, `counts`, and up to 20 advisories as `{advisory_id, cve_ids, verdict, reason, fixed_version, fix_major, fix_ecosystem, severity, cvss_v3, epss, in_cisa_kev, url, matched_ranges}`, with `advisories_truncated`. `matched_ranges` holds up to 5 of the advisory's matching ranges with every bound (`introduced`, `fixed`, `last_affected`) and its evidence, because the detail endpoint does not return `last_affected`. `unanswered` as in section 6.3.
- `list_alert_events`: per event `id`, `rule_id`, `rule_name`, `cve_id`, `severity`, `in_cisa_kev`, `epss`, `open`, `first_fired_at`, `last_fired_at`, `url` of the CVE; and `next_after`, the cursor to pass as `after` next time, which is the `after` it was given when no event was returned.
- `dry_run_rule`: `match_count`, `candidates_evaluated`, `partial`, and up to 20 sample CVE IDs with URLs.

A failed API call returns a tool error, not a protocol error, with a fixed sentence naming the HTTP status and the server's problem title and detail. The key never appears in a result.

### 7.5 Limits inside a tool call

A tool call must not stall the agent: a call that blocks for a minute looks to the agent like a hang, with no explanation. So inside the MCP server:

- **One request at a time.** An MCP host may send several tool calls at once. The server sends one API request at a time, in arrival order. A call whose host cancels it while it waits leaves the queue and never sends its request; a call cancelled while its request is in flight cancels that request.
- **A deadline per call.** Every tool call has a total deadline of 60 seconds, waiting time included. When it passes, the call returns a tool error saying the server is busy with other calls and to retry.
- **Retries.** A busy check slot (`Retry-After: 1`) is retried inside the call while the deadline allows. A 429 (`Retry-After: 60`) is returned at once as an error that says when to retry.
- **`check_components`.** Its input is at most 500 items, so it is one request. It splits on the candidate-limit 422 as in section 6.2, within the deadline. On the server's time-limit 503 it does not split: it returns a tool error that says to retry with fewer items, because a split could take another 60 seconds.

One MCP session costs one request at startup (`whoami`), repeated on the first tool call if it failed, and one request per tool call, plus busy-slot retries and the requests of any 422 split.

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
| `internal/apiclient/` | The HTTP client: configuration checks, the request function with its one-request-at-a-time lane, problem-detail decoding, the error type that maps to exit codes, retries, check batching and merging, and one method per operation. |
| `internal/apiclient/trivy/` | Trivy report reading (section 6.1). |
| `internal/mcpserver/` | Tool definitions, input structs and schemas, result shaping and descriptions. Built from an `*apiclient.Client`, the enabled write tools and the version (section 7.1). |

The CLI and the MCP server share batching, retry mechanics and error mapping in `internal/apiclient`, so the two cannot disagree on how a status is read. Their policies differ where section 7.5 says so (budget, deadline, no timeout split in MCP), and each passes its policy to the client.

### 8.2 Build and image

- `.golangci.yml`: the `depguard` rule of section 7.1. The `go list -deps` test is a Go test in `cmd/cvert`.
- CI: build `./cmd/cvert` in a job that has no `web/dist`; run its tests with the Go tests.
- `docker/Dockerfile`: build `/cvert` beside `/cvert-ops` in the builder stage, with the commit passed in as a build argument (section 5.1), and copy it into the distroless stage. The entrypoint stays `/cvert-ops`.
- Version from `runtime/debug.ReadBuildInfo` (section 5.1); `cvert --version` prints it, and the MCP server reports it in its implementation info.

### 8.3 Documentation

`docs/client.md`: installation, configuration, the command list, exit codes, a scanner-to-watchlist example with `jq`, and an agent host configuration example using `CVERT_API_KEY_FILE`, so the key does not sit in the host's configuration file. Example host names use `example.internal`.

## 9. Tests

Every test that reaches the API runs against a real server: the production handler from `internal/api`, a testcontainers PostgreSQL database from `testutil.NewTestDB`, CVEs from `testutil.SeedCorpus`, and users, orgs and keys created through the store, served over loopback by `httptest.NewServer`. No end-to-end test uses a mock. The server is built with the dependencies the tested routes need, which an empty `ServerDeps{}` (as in `internal/api/smoke_test.go`) does not give: an alert evaluator, without which `dry-run` answers 503, and an audit writer, flushed before any assertion on the audit log because it writes asynchronously. The org rate limiter's clock is injected, so a rate-limit test does not race the token refill; if `ServerDeps` has no way in, the plan adds a test hook.

### 9.1 No database

- **Spec conformance.** A table in `internal/apiclient` lists each operation the client calls: method, path template, query parameters, body fields, and the response fields it reads, each with its JSON type and enum values. A test checks each against the checked-in `openapi.json`, which the existing spec test keeps equal to the served spec. A renamed field, a changed type or enumeration, or a removed parameter fails here.
- **Import boundary** (section 7.1): `go list -deps ./cmd/cvert` holds no denied package.
- **Configuration.** Both key settings set, neither set, a malformed key, `http://` to a non-loopback host, an unreadable key file: each exits 2 and sends no request. No command defines a flag whose name contains `key`.
- **Trivy reading** against golden reports (section 6.1): deduplication, the full substituted purl for `deb` and `apk` packages, `id` from the package ID, skipped packages, the warning for a report without `Packages`.
- **Batch splitting and merging**, as unit tests of the splitting logic: 500 and 501 items, the 900 KiB size bound, index rewriting, feed merging including a null `last_success_at`.
- **Retry policy, the 422 and 503 splits, and the stop rule of section 6.2**, against an `httptest` server that returns scripted statuses. These are unit tests of the client's reaction to statuses the real server cannot be made to return on demand (a candidate-limit overrun needs more candidate rows than the seeded corpus holds; a 30-second timeout would make the test take 30 seconds), including a proxy-style 503 with no problem body, which must not split.
- **Client policy:** a redirect is refused and not followed; no cookie is stored or sent; an over-limit response body is refused.
- **Input schemas** (section 7.2): each tool refuses out-of-range, wrong-enum and extra-property input.
- **Descriptions** (section 7.3): every check status, reason, warning and error code in the spec, and every DSL field, operator and enumerated value, appears in its tool description.

### 9.2 CLI against a real server

The CLI's commands run in process through a `run(args, env, stdin, stdout, stderr) int` function, so tests assert the exit code and both streams.

- Each command's success path, with output compared to the server's response.
- `check` with 501 items in one input: two requests, one merged result, indexes 0 to 500.
- `check --input trivy` with a golden report against the seeded corpus.
- Exit codes on the real server: a revoked key (4), a viewer key adding a watchlist item (5), an empty search (3, or 0 under section 12 item 7(a)), `cves get` of an unknown ID (3), an invalid rule in `rules validate` (8, or the code section 12 item 7(b) settles), and the 11th request inside the 10-request burst of a free-tier org with `--max-wait 0` (6), with the limiter's clock held still.
- `watchlists items replace --cves -` from stdin, then the same list again, reporting all unchanged.
- In every test, a helper fails the test if the key appears in stdout or stderr.

### 9.3 MCP tools against a real server

- An MCP client from the SDK connected in memory to the MCP server, whose API client points at the real test server. Each tool is called and its result checked: compact fields present, nulls kept, URLs formed, truncation counts right.
- The second acceptance criterion of section 11 as a test: for a package and version in the seeded corpus with a known affecting advisory, `check_components` alone returns that advisory with its fixed version, and `get_advisory` on its ID returns its ranges.
- With `--enable-writes` off, the tool list has no write tool. With it on and a viewer key, `add_watchlist_item` returns a tool error naming 403, and the watchlist is unchanged. With a member key, the item is added; once the server audits item writes (section 12), the audit log has a row with the key's `api_key_id`.
- A startup with a revoked key exits 4 without serving; a startup with the server unreachable keeps serving and the first tool call returns the connection error.
- Two concurrent tool calls send their requests one after the other; a call cancelled while queued sends nothing.
- One test builds `cvert` and runs `cvert mcp` as a child process over real stdio, to check that stdout carries only MCP messages and logs go to stderr.

### 9.4 Run cost

Go builds one test binary per package, and each test binary that calls `testutil.NewTestDB` starts one PostgreSQL container, with a cloned database per test. The CLI tests (`cmd/cvert`) and the MCP tests (`internal/mcpserver`) are in two packages, so they add two containers to a full test run.

## 10. What waits for the parallel session

| Work here | Needs | Exact need |
|---|---|---|
| Every org-scoped command and tool, and MCP startup | AUTH-5 `GET /whoami` | Accepts an API key. Returns at least the org ID, org name, the key's ID, name, role and expiry, the org's tier and rate limit per minute, and the server's version (which reads `dev` until server builds set it). Applies the same org membership check as org routes, so a key whose creator has left the org fails here and not on every later call. The design assumes it is outside the org rate limiter, like `/cves`; if it is inside, each CLI invocation costs one more request of the org's budget, which works but should be stated in `docs/client.md`. |
| `events list --after`, `list_alert_events` | FEED-1 | An ascending order selected by `after`; a `limit` parameter; a way to start (an ascending first page with no `after`, or a documented starting cursor); and a cursor returned on every page that holds items, including the last, so a poller can store it and resume after the last event it saw. Every event must reach a poller exactly once, including an event whose transaction commits after a later event's (with `first_fired_at DEFAULT now()` and a random UUID tiebreak, a late commit lands behind a cursor already handed out; implementation pitfall NOTIFY-20 records the same failure in the alert evaluator), and including a resolved event that is reopened, which changes an existing row. A cursor stored by a poller must stay valid across server upgrades, or be refused with a problem type of its own, so a poller can tell a stale cursor from a bad request. The design treats an absent cursor on an empty page as "keep the previous one". |
| Event context in `events list` and `list_alert_events` | FEED-2 | `expand=cve,rule` giving at least severity, KEV, EPSS and the rule name. |

Every org-scoped request needs the org ID from `whoami`, so every org-scoped command and tool, and MCP startup, waits for AUTH-5. What can be built before it lands: configuration, the API client and its conformance test, exit codes, the `cves` commands, check batching and Trivy reading as unit-tested code, and the MCP tools' schemas, descriptions and result shaping. The plan builds those first and the org-scoped commands and the MCP server after AUTH-5 merges.

## 11. Acceptance

Adapted from the requirement, whose example question depended on per-host findings, which section 9 of the private requirements dropped.

- A script on a timer, with only `cvert` and `jq`, can check a list of purls, poll alert events with a stored cursor, and set a watchlist's CVE items from a scanner report, without writing HTTP code.
- An agent configured with a viewer key and the default flags can answer "is component X at version V affected by CVE Y, and which version fixes it on the same release line" in at most two tool calls (`check_components`, then `get_advisory` if it needs more than the matched ranges), and is offered no tool that changes anything. Section 9.3 tests this against the seeded corpus.
- With `--enable-writes`, the same agent with a viewer key still changes nothing (403). With a member key its writes succeed, and, once the server audits item writes (section 12), they appear in the audit log under its key.

## 12. Decisions for Sam

Each item states the question, the options, and a recommendation. Elsewhere, the design text describes the original proposal, and each span a pending item would change says so; where a recommendation differs from the original proposal, the plan follows Sam's answer, not the text.

1. **Requirements coverage.** The requirements are summarised in section 1 from a private document reviewers could not read, so nobody has checked this design against it in full. Confirm that sections 1 and 5 to 7 cover CLI-1 and MCP-1 as amended, or name what is missing.
2. **Binary** (section 3). A separate `cvert` binary, also in the container image; or subcommands of `cvert-ops`, which cannot be installed with `go install` and link the whole server. Recommendation: separate binary.
3. **Client code** (section 4.2). Hand-written with a conformance test on names, types and enumerations, no new dependency; or generated with `oapi-codegen` v2.8.2 plus `oapi-codegen/runtime`; or request and response types moved to a shared package, a server refactor. Recommendation: hand-written.
4. **MCP SDK** (section 4.1). `github.com/modelcontextprotocol/go-sdk` v1.8.0, accepting its transitive `yosida95/uritemplate` v3.0.2, unchanged since 2022, which no input of ours reaches; or `mcp-go`, which has the same transitive module. Recommendation: the official SDK.
5. **Streamable HTTP** (section 7.6). Defer and build stdio only; or build it now inside `serve`. Recommendation: defer.
6. **Tool set and the write switch** (section 7.2). Two read tools beyond the requirement (`list_watchlists`, `list_watchlist_items`); write tools limited to adding and removing one watchlist item; whole-list replace CLI-only. The switch is either one `--enable-writes` flag, under which any write tool a later release adds is offered without anyone re-approving the host configuration, or a repeatable `--enable-write-tool NAME` that names each tool. Recommendation: the tool set as listed, with named tools.
7. **Exit codes** (section 5.4). (a) An empty list: exit 3, so a script can test for "nothing new" by exit code, but every quiet poll under `set -e` or a systemd timer then counts as a failure; or exit 0 with an empty `items`, tested with `jq -e`, keeping 3 for a single-resource 404. (b) An invalid rule in `rules validate`: exit 8, shared with malformed requests; a dedicated code 10; or exit 0, tested with `jq -e '.valid'`. Recommendation: exit 0 for empty lists, and code 10 for an invalid rule, because a linter-like command should fail on bad input and "fix your rule" differs from "your request is wrong". The requirement asks for an exit code meaning "no results"; under this recommendation that code (3) is kept for a lookup that finds nothing, and an empty list is reported by its empty `items`, so this narrows the requirement and needs Sam's agreement.
8. **Transport security** (section 5.1). `http://` is refused except to loopback. The production stack's Caddy (`docker/Caddyfile`) serves its default `localhost` host from Caddy's local CA and gets a public certificate for a public host name; a self-hosted install on a private host name, which cannot pass an HTTP challenge, often uses a private CA, which a client on another host must trust. Go reads `SSL_CERT_FILE` on Linux but not on Windows or macOS. Options: no setting (users add the CA to the system store); a `CVERT_CA_FILE` setting naming a PEM bundle added to the system roots; also allowing `http://` to a named host (the compose network's `http://app:8080`). Recommendation: add `CVERT_CA_FILE`; allow no plain HTTP beyond loopback.
9. **No org setting** (section 5.1). The org always comes from `whoami`; or an optional `CVERT_ORG_ID`. Recommendation: `whoami` only.
10. **Audit of item writes** (sections 2, 7.1). The server writes no audit row when a single watchlist item is added or deleted, though it does for watchlist changes and whole-list replace. Options: add audit entries to those two handlers in the first pull request, a small server change; or accept that item writes by a key are unaudited. Recommendation: add them; the audit work for machine keys intended every write by a key to be recorded.
11. **Watchlists fed by a scanner** (section 5.2). `items replace --cves` removes every package and CPE item on the watchlist, because the server replaces the whole list; and `items add` fails with 409 on an item already present, so neither is a repeatable "make sure these are watched". Options for `--cves`: refuse with exit 8 when the watchlist holds anything but CVE items, so a scanner gets a watchlist of its own; or read the list, keep the non-CVE items and send the merge, which can lose a concurrent edit. Options for `add`: report an item already present as success (`already_present`), which makes retries safe for scripts and agents; or keep the 409. Recommendation: refuse on a mixed watchlist, and treat an item already present as success.
12. **DSL reference for `validate_rule`** (sections 2, 7.3). Move the DSL field catalog (`FieldDescription`, `ExportFieldDescriptions()`) to a package that imports no store code and build the description from it, a small server refactor with one source of truth; or keep a hand-written description with a test over field names, operators and enumerated values. Recommendation: move the catalog.
13. **Sharing the org's request budget** (sections 2, 5.5). Web sessions and every key of an org draw from one bucket (60 a minute, burst 10, on the free tier), and the server tells a refused client to wait 60 seconds. `watchlists items list --all` on a list of 10,000 items takes 200 requests (50 a page), so with the default 2-minute budget it exits 6 after holding the bucket empty, and web users of the org get 429s meanwhile. Options: document it; have the clients pace their own requests to half the org's per-minute rate from `whoami`, which leaves the rest to the web UI and makes long runs slow but complete; or wait for per-key limits on the server (AUTH-7). Recommendation: pace in the clients now; per-key limits remain the server-side answer.
14. **Feed text given to agents** (section 7.3). Advisory descriptions and references are attacker-controlled. Implementation pitfall ARCH-13 strips markup and control characters before such text reaches a model. Options: label it as untrusted in the tool descriptions only; also strip control and invisible formatting characters and keep the length caps; or apply the full ARCH-13 cleaning, which also strips markdown links and HTML and changes the text an agent may need to quote. Recommendation: strip control and invisible formatting characters and keep the caps; write tools off by default remain the main defence.
15. **PLAN.md.** It has no section on an API client or MCP server. Add one stating the binary, the rule that both clients act only through the HTTP API with the caller's key, and the write-tool switch, with this design as the detail. Recommendation: add it.

## 13. Delivery

Three pull requests, each with an implementation plan reviewed first:

1. `internal/apiclient`, `cmd/cvert` with configuration, exit codes, the `cves`, `check`, `rules` and `watchlists` commands, the `depguard` rule and the `go list -deps` test, the CI build without `web/dist`, the Dockerfile change, and `docs/client.md`. The server's spec gains the four undocumented `/cves` score filters (section 2). Org-scoped commands land once AUTH-5 has merged.
2. `cvert mcp` with the read tools and the write flag.
3. `events list` and `list_alert_events`, after FEED-1 and FEED-2.
