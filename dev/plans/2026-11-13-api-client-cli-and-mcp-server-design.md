# Design: an API client CLI and an MCP server (CLI-1, MCP-1)

Date: 2026-11-13. Author: Claude, for Sam. Status: draft for Sam's review. No implementation code exists. New public surfaces (an MCP endpoint in the server, a client binary, its commands, flags and exit codes, an MCP tool set) and new dependencies need Sam's approval before code. Section 12 lists the decisions, with the strongest case against each recommendation. Sam has decided one (streamable HTTP is the primary MCP transport) and set a burden of proof on another (a hand-written API client must justify itself against a generated one; section 4.2 finds it does not).

Review ledger: `dev/plans/reviews/2026-11-13-api-client-cli-and-mcp-server-design.ledger.md`.

## 1. Goal and scope

Two clients of the CVErt Ops HTTP API, for machines that hold an API key and no browser session:

- **CLI-1, a command-line client** for scripts on a timer: look up CVEs, check component versions, poll alert events, inspect and test alert rules, and maintain watchlist items. Scripts read its JSON output with `jq`. The requirement asks for JSON by default with a table option, for `check` input as purls or a Trivy JSON report, and for exit codes that tell no results, authentication failure, rate limiting and server errors apart.
- **MCP-1, an MCP server** for AI agents that patch software: most of the same reads as tools, with narrow input schemas and compact results. Its primary transport is streamable HTTP, served by `cvert-ops serve` at `/api/v1/mcp` with the caller's API key on every request (section 7.2). stdio is a second transport for agent hosts that cannot send an HTTP header (section 7.9).

The MCP protocol revision targeted is 2026-07-28, read from the specification at modelcontextprotocol.io on 2026-11-13. It removed sessions and the `initialize` handshake: every request is an independent POST that carries its protocol version and client capabilities in `_meta`. That makes the HTTP endpoint an ordinary authenticated, stateless request handler, which is why it can be the primary transport.

The requirements come from the private homelab integration requirements (section 7.7, as amended by its section 9 decisions). Those decisions dropped inventory and findings, so this design has no `inventory push`, `findings list` or `findings set-state` command and no `list_findings` or `set_finding_state` tool. The requirement's `annotate` tool needs triage notes on alert events (INV-4), which are not built, so it is out of scope too.

**Not in scope:** scoped API keys (AUTH-3; a viewer-role key is how an agent is made read-only for now), MCP resources and prompts (MCP-2), the MCP authorization profile based on OAuth 2.1 (section 7.10), rule creation or editing from either client, key rotation (AUTH-6), private advisories (INV-3), and a non-interactive bootstrap command (OPS-2).

**Depends on other work.** Three API changes from a parallel session: `GET /api/v1/whoami` (AUTH-5) and `expand=cve,rule` on alert events (FEED-2) are on `dev` (pull requests 232 and 233); an ascending `after` cursor on alert events (FEED-1) is not yet built. Section 10 lists what this design needs from each and what landed. Nothing that depends on FEED-1 is built before it lands.

**Evidence.** Code was read at `origin/dev` commit `5598af6` and, for `whoami` and `expand`, at `7d3571c`. The MCP SDK was built and scanned from a scratch module, and a client was generated from the served spec, both on 2026-11-13 (section 4). Repository status for every candidate dependency was read from the GitHub API and web searches on 2026-11-13.

## 2. Findings that shaped the design

| Finding | Evidence | Consequence |
|---|---|---|
| The server binary cannot be installed with `go install`. `web/embed.go` embeds `all:dist`, and `web/dist` is git-ignored, so a build from the module proxy fails with "no matching files found". | `web/embed.go`, `web/.gitignore`; CLAUDE.md records the same failure in fresh worktrees. | A client inside `cvert-ops` can only be had by building the frontend first or pulling the container image (section 3). |
| The container image is distroless and its entrypoint is `/cvert-ops`. | `docker/Dockerfile` | A second binary can be copied into the same image at no cost to the server. |
| MCP 2026-07-28 is stateless: no sessions, no `initialize`, `server/discover` for version selection; each message is its own POST answered by one JSON object or a request-scoped SSE stream; closing the stream cancels the request; `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers must match the body; a server must answer 403 to a request whose `Origin` header is present and invalid. | Specification 2026-07-28: changelog, Streamable HTTP. | The endpoint needs no session store and fits behind the existing middleware chain (section 7.2). |
| MCP authorization is optional. An HTTP server that supports it SHOULD follow the OAuth 2.1 profile, which then requires Protected Resource Metadata. A server MUST NOT accept or pass on tokens not issued for it. A stdio server SHOULD take credentials from its environment. `tools/list` must not vary per connection, MAY vary by the request's authorization, and SHOULD be in a deterministic order. | Specification 2026-07-28: Authorization, Security Best Practices, Tools. | Static `cvo_` keys are allowed but do not follow the OAuth profile (section 7.10). The tool list can depend on the key's role (section 7.4). |
| `go-sdk` v1.8.0 negotiates 2026-07-28 as its newest version and older ones back to 2024-11-05. It has a stateless mode, a localhost DNS-rebinding check (on by default), a request body limit, and builds a server per request from `getServer(*http.Request)`. | Module source: `mcp/shared.go` line 50, `mcp/streamable.go` (`StreamableHTTPOptions`, `NewStreamableHTTPHandler`). | Each request gets a server bound to that request's credential (section 7.3). |
| The version check takes at most 500 items, under the global 1 MiB body limit. One check runs at a time on the whole server; a second request gets 503 with `Retry-After: 1`. A request that reads too many candidate rows gets 422 with problem type `urn:cvert:error:candidate_limit_exceeded`. A check that runs past 30 seconds, or a statement timeout, gets 503 without `Retry-After`. | `internal/api/check.go` (`maxCheckItems`, `maxConcurrentChecks = 1`, `checkTimeout`, `writeCheckFailure`), `internal/api/server.go` line 235. | Batching must be sequential, must split on 422, and must tell the two 503s apart (section 6). A free slot is taken without a queue, so one org's long run of checks can make another org's checks wait. This design leaves the slot as it is. |
| Org routes share one token bucket per org: 60 requests a minute on the free tier, with a burst of 10. A refused request gets 429 with `Retry-After: 60`. `/cves` routes are authenticated but not under the org limiter; `/whoami` is under it. | `internal/api/middleware_tier.go`, `internal/api/cves.go` `registerCVERoutes`, `internal/api/whoami.go`. | Every client request counts against a budget shared with the web UI and other keys. The clients never send requests in parallel, and they retry 429 only within a time budget (section 5.5). |
| Alert events list newest first, 100 a page, with no `limit` parameter. | `internal/api/alert_events.go` | `events list --after` and `list_alert_events` wait for FEED-1. |
| Dry-run takes a saved rule's ID; there is no dry-run of an unsaved rule. `validate` returns 200 with `valid: false` for an invalid rule. | `internal/api/alert_rules.go` `dryRunHandler`, `validateAlertRuleHandler`. | `rules dry-run <rule-id>`; `rules validate` maps `valid: false` to an exit code (section 5.4). |
| Watchlist items are added one per `POST`, removed by item ID, and replaced as a whole list (`PUT`, at most 10,000 items). | `internal/api/server.go` routes, `internal/api/watchlists.go` | `items add` sends one request per item; `items replace` is the path for a list taken from a scanner. A 10,000-item list of long package names can exceed the 1 MiB body limit; the CLI checks the encoded size before sending. |
| The web UI has pages for `/cves/:cveId` and `/watchlists/:id`, and none for alert rules or events. | `web/src/router/index.ts` | Results link CVEs and watchlists to the UI. Rules and events carry stable IDs and no link (section 7.7). |
| The DSL package imports `internal/store/generated` directly, in `accessor.go` only. The field catalog (`FieldDescription`, `ExportFieldDescriptions()` in `field.go`) imports only `internal/ecosystem`, and `internal/ai/schema.go` already uses it. | `internal/alert/dsl/*.go` imports | The MCP package cannot import the DSL package without linking store code. Its DSL reference either comes from the catalog moved to a store-free package or is hand-written and tested against the catalog (section 7.6; a decision for Sam, section 12). |
| The `/cves` filters `cvss_min`, `cvss_max`, `epss_min` and `epss_max` are read from the raw query string and are missing from the served spec. They are pointer fields without `query:` tags because huma refuses pointer query parameters. | `internal/api/cves.go` lines 263–268 (fields) and 304–307 (parsing); no match in `openapi.json`. | The first pull request documents them in the spec by another means than a pointer `query:` tag (section 13). A generated client cannot send them until then. |
| Creating and deleting a single watchlist item writes no audit row. Watchlist create, update, delete and whole-list replace do. | `internal/api/watchlists.go`: `auditLog` calls at lines 256, 307, 515, 559 and 691 only. | Item writes through either client are not audited today (sections 7.3 and 12). |
| A client generated by `oapi-codegen` v2.8.2 from the served 3.0 document, limited to the 14 operations the clients call, is 4,293 lines, builds and vets clean, and keeps the raw response body beside the typed one. | Measured 2026-11-13 (section 4.2). The API-1 acceptance run in the private requirements (section 11.1, API-1 row) round-tripped the same responses through such a client. | Section 4.2 recommends the generated client. |

## 3. Decision: a separate `cvert` binary

**Recommendation: a new command `cmd/cvert`, built as the binary `cvert`, holding the CLI and the stdio MCP server (`cvert mcp`). The container image carries it too, at `/cvert`.** The HTTP MCP endpoint is part of `cvert-ops serve` (section 7.2); an agent host that uses it needs no binary at all.

| | Separate `cvert` binary | `cvert-ops client ...` and `cvert-ops mcp` |
|---|---|---|
| Install on a script host or workstation | `go install github.com/scarson/cvert-ops/cmd/cvert@<commit or branch>` is expected to work (checked below; the plan's first task proves it), because `cmd/cvert` does not import `web` (enforced, section 8.2). | Fails from the module proxy (section 2). Needs a source checkout with Node and `npm run build`, or the container image. |
| What is linked | The generated API client and its wrapper, cobra, the MCP SDK. | Everything the server links: pgx, feed adapters, the SPA, huma. |
| Attack surface on a script or agent host | No database code and no server configuration in the binary. | The whole server, idle. |
| Container image | Both binaries in one image; `docker run --entrypoint /cvert ...` runs the client. | One binary; `docker run ... client ...`. |
| Cost | A second build target in CI and the Dockerfile. | None beyond the commands. |

The server reads its configuration only inside `serve`, `worker` and the other server commands, so a subcommand would not trip over missing database settings. That is not a reason either way. The deciding facts are `go install` and the size of what a script host has to run.

What has been checked about `go install` (2026-11-13): the repository is public, `go.mod` has no `replace` directive, and the module proxy resolves the lower-case module path `github.com/scarson/cvert-ops` (`go list -m -json github.com/scarson/cvert-ops@latest` returns a pseudo-version). The repository has no release tags, so an install names a commit or a branch until releases exist. An end-to-end `go install github.com/scarson/cvert-ops/cmd/cvert@<branch>` from a clean module cache is the plan's first task; if it fails, the fallback is the container image, which carries `/cvert` either way.

Prebuilt release binaries would remove the Go toolchain from script hosts and would make the server binary installable without Node too. No release pipeline exists, and building one is not part of this work; if one is built later, it ships `cvert` beside the server.

## 4. Dependencies

### 4.1 MCP SDK

**Recommendation: `github.com/modelcontextprotocol/go-sdk` v1.8.0**, the official SDK. Verdict: needs Sam's sign-off, for one transitive module (`yosida95/uritemplate`, below).

| Check | Result | Notes |
|---|---|---|
| Repository status | OK | Not archived. Official SDK of the MCP project, maintained with Google. |
| Last commit | OK | 2026-11-10. |
| Last release | OK | v1.8.0, 2026-09-14. |
| Open issues | OK | 80 open; active triage. |
| Known vulnerabilities | OK for v1.8.0 | Four high-severity advisories in 2026, all fixed by v1.4.1: case-insensitive JSON field matching (GHSA-wvj2-96wp-fq3f, fixed 1.3.1), mishandled NUL characters in JSON (GHSA-q382-vc8q-7jhj, fixed 1.4.1), cross-site tool execution on HTTP servers without authorization (GHSA-89xv-2j6f-qhc8, fixed 1.4.1) and DNS rebinding protection off by default on localhost HTTP servers (GHSA-xw59-hvm2-8pj6, fixed 1.4.0). The last two concern the HTTP transport this design makes primary; section 7.2 states how the endpoint stands without relying on either fix. |
| Protocol support | OK | Negotiates 2026-07-28 as its newest revision (`mcp/shared.go` line 50). |
| Canonical location | OK | `github.com/modelcontextprotocol/go-sdk`. |
| License | OK | Apache-2.0 for new contributions, MIT for older ones not yet relicensed. Both compatible. |
| Transitive modules | Needs sign-off | Linked by a stdio server (measured with `go list -deps`): `google/jsonschema-go` v0.4.3 (MIT, released 2026-04), `segmentio/encoding` v0.5.4 and `segmentio/asm` v1.1.3 (MIT and MIT-0, active), `yosida95/uritemplate/v3` v3.0.2 (BSD-3-Clause, **last commit and release 2022-04**), and `golang.org/x/oauth2`, `x/time`, `x/sync`, which `go.mod` already requires. The HTTP handler is in the same `mcp` package, so the list is the same for the server. |
| Go module status | OK | On pkg.go.dev; minor releases about monthly. |

Measured from a scratch stdio server with one tool: it builds, and the binary is 11.5 MB (Windows amd64, default flags). `govulncheck` finds no reachable vulnerability in the SDK or its modules; it reports one in `golang.org/x/sys` v0.41.0, which this repository's `go.mod` already overrides with v0.49.0.

`uritemplate` fails the age rule of the `dependency-check` skill (no commit in 24 months). It is linked because the SDK supports resource templates. `mcp-go`, the other SDK considered below, depends on it too, so neither avoids it. This design registers no resource or resource template (MCP-2 is out of scope), so no input reaches it. Sam decides whether that is acceptable.

Alternatives considered:

- `github.com/mark3labs/mcp-go` v1.5.0 (MIT, active, released 2026-10-30; it also documents 2026-07-28). One high advisory in 2026, in its OAuth client (GHSA-xf6j-693p-wqxx, fixed 1.2.1). Its `go.mod` adds `spf13/cast` and `santhosh-tekuri/jsonschema`, and it also depends on `uritemplate`. It has fewer advisories, but it parses JSON with its own code, which this review did not examine, while the official SDK's two 2026 parsing advisories are fixed in the versions this design would use. For a server this project would maintain for years, the official SDK's backing by the protocol's maintainers decides it.
- Writing the JSON-RPC and MCP layer by hand. Rejected: protocol version negotiation across two eras, header validation, cancellation and schema generation are a lot of code to own, and the official SDK's own 2026 advisories (JSON field case, NUL handling) show where a hand-written parser goes wrong.

### 4.2 API client: generated, with a thin wrapper

**Recommendation: generate the client with `oapi-codegen` v2.8.2 from the served OpenAPI 3.0 document, limited to the operations the clients call, and wrap it in a small hand-written package for retries, batching, pacing and exit codes.** A hand-written client was the earlier recommendation; Sam asked for very strong justification of its benefits over a generated one. Measuring the generated option removed each benefit claimed for hand-writing, so the recommendation changed.

Measured on 2026-11-13 from the 3.0 document the server serves (dumped by a temporary test, since deleted):

| | Generated, filtered (`include-operation-ids`, 14 operations) | Generated, unfiltered (140 operations) |
|---|---|---|
| Size | 4,293 lines, 173 functions | 29,521 lines |
| `go build`, `go vet` | clean | — |
| Linked modules | `oapi-codegen/runtime` v1.9.0, `apapsch/go-jsonmerge/v2` v2.0.0, `google/uuid` (already required) | same |

What the generated client gives that a hand-written one would have to rebuild or go without:

- **Types checked by the compiler for every field**, not only the fields the client reads. A renamed field or a changed type fails the build of the next regeneration, not a runtime decode.
- **Raw bytes kept.** Each response type has `Body []byte` beside the typed `JSON200` and the problem body, so the CLI still prints the server's JSON unchanged (section 5.3).
- **Transport stays ours.** The client takes any `HttpRequestDoer` and `RequestEditorFn`s, so the wrapper supplies the key, the retry and pacing rules, the one-request-at-a-time lane and, in the server, the in-process transport of section 7.3.
- **Enumerations as typed constants** (`CheckItemResultStatusAffected` and the others), with the server's field documentation as comments. The tests that keep the MCP tool descriptions complete (section 7.6) iterate over these constants instead of parsing the spec.
- **No hand-maintained conformance table.** The earlier design needed a test listing each operation's parameters and fields against `openapi.json`; regeneration replaces it.

What it costs:

- **Two runtime modules.** `oapi-codegen/runtime` v1.9.0 (Apache-2.0, released 2026-11-10, no advisories). It imports `apapsch/go-jsonmerge/v2` v2.0.0 (MIT, no advisories, **last push 2021-11**), which fails the dependency-check age rule. `runtime` uses it only to merge union types (`runtime/jsonmerge.go`); the filtered client never calls it. Like `uritemplate`, it is linked but unreachable from our code, and it needs Sam's sign-off.
- **A build-time tool.** The generator, pinned with a `tool` directive in `go.mod`, so its version is reviewed like any dependency; its own dependencies are build-time only and never linked into a binary. It has at least ten advisories in 2026, nearly all code injection from a crafted spec. Its input is the spec this repository generates from its own Go types, so those need an attacker who can already change the server's code.
- **4,293 committed generated lines**, which a reviewer skims rather than reads, as with `sqlc` output today.

**Keeping it in sync.** The existing spec test that writes `openapi.json` when `GENERATE_OPENAPI=1` is set also writes the 3.0 document, `openapi-3.0.json`, and the existing drift test checks both against the served spec. `go generate ./internal/apiclient/...` regenerates the client from that file. CI regenerates and fails on a difference (`git diff --exit-code`), beside the existing `schema.d.ts` check.

**Alternatives considered.**

- *Hand-written client with a conformance test* (the earlier recommendation). Its remaining advantages are no runtime modules and no generated code to review. The conformance test it needed checks only the fields the client reads and is itself hand-maintained, and the passthrough output it was meant to enable is available from the generated `Body`. Not recommended.
- *`ogen` v1.24.0* (Apache-2.0, active, released 2026-08-07, no advisories). Its generated code imports `go-faster/jx`, `go-faster/errors` and OpenTelemetry, a heavier runtime than `oapi-codegen`'s, for a client this small. Not recommended.
- *Request and response types moved to a shared package* imported by both server and client. Compiled agreement with no generator, but most handler types the client needs are unexported chi-handler structs (`alertEventEntry`, `watchlistItemEntry`, `alertRuleEntry`), and it ties the client to the server's Go types instead of the published contract. Not recommended.

## 5. The CLI

### 5.1 Configuration

| Setting | Source | Rules |
|---|---|---|
| Server URL | `CVERT_URL`, or `--url` | Base URL of the server, such as `https://cvert.example.internal`. The client appends `/api/v1`. `http://` is refused unless the host is a loopback address, because the key would cross the network in clear text. The server has no TLS listener, so remote use needs a TLS-terminating proxy, as the production compose stack's Caddy provides. Whether to add a setting for a private CA file, and whether plain HTTP may be allowed to a named host, are decisions for Sam (section 12). |
| API key | `CVERT_API_KEY`, or `CVERT_API_KEY_FILE` naming a file that holds it | Exactly one of the two. Both set, or neither, is a configuration error (exit 2). There is no flag for the key, so it never appears in argv or shell history. A file's content is trimmed of surrounding whitespace. The key must match `cvo_` and 64 hex characters before anything is sent; an error message never repeats the value. |
| Web UI base | `CVERT_WEB_URL` | Optional. Defaults to the server URL, where the server serves the SPA. Used only for links (section 7.7). |
| Organisation | `GET /whoami` | Not configured. A key belongs to one org; the client asks `whoami` once per process (section 10). A `CVERT_ORG_ID` setting would save that request, but it could disagree with the key and turn every call into a 403 that names the wrong cause. |

The wrapper's HTTP client sends the key as `Authorization: Bearer`, keeps no cookie jar, does not follow redirects (a redirect is reported as an error), and sets a `User-Agent` of `cvert/<version>`. Per-request timeout: 60 seconds, which covers the check endpoint's 30-second limit and its 30-second write deadline. Every response body is read to the end and closed, and read through a size limit, 64 MiB for a check response and 16 MiB for anything else; a larger response is an error (exit 1). A 500-item check whose items each list 100 advisories can approach tens of megabytes, which sets the first limit.

`<version>` comes from `runtime/debug.ReadBuildInfo`: the module version for a `go install` of a tagged or pseudo version, otherwise the VCS revision Go records when it builds inside a git checkout. A build without `.git`, such as the container image (`.dockerignore` excludes it), has neither, so the Dockerfile passes the commit as a build argument into linker flags, which override `ReadBuildInfo`. No build sets the server's own version flags today (`cmd/cvert-ops/main.go` defaults to `dev`; CI runs `go build ./cmd/cvert-ops` with no flags; the Dockerfile passes `-s -w` only).

The client never logs a request body or the key. Check items describe what an org runs, and the server does not log them either (`checkComponentsHandler`).

### 5.2 Commands

| Command | Request | Notes |
|---|---|---|
| `whoami` | `GET /whoami` | Prints the server's response (section 10). |
| `cves search [flags]` | `GET /cves` | Flags mirror the endpoint's filters: `--q`, `--severity` (repeatable), `--date-from`, `--date-to`, `--cwe`, `--ecosystem`, `--package`, `--kev`, `--exploit`, `--cvss-min`, `--cvss-max`, `--epss-min`, `--epss-max`, `--limit`, `--cursor`, `--all`. |
| `cves get <id>` | `GET /cves/{id}` | Takes any stored record ID, including the advisory IDs the check endpoint returns. |
| `cves sources <id>` | `GET /cves/{id}/sources` | |
| `check [--input purls\|json\|trivy] [FILE\|-]` | `POST /orgs/{org}/check`, batched | Section 6. |
| `events list [--after CURSOR] [--rule ID] [--cve ID] [--open] [--limit N] [--all]` | `GET /orgs/{org}/alert-events?after=...&expand=cve,rule` | Waits for FEED-1. `--open` sends `last_match_state=true`, as the MCP tool's `open_only` does. |
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

`--output json` is the default. A single-resource command prints the server's response body unchanged (the generated client's `Body`), followed by a newline. A list command without `--all` prints the server's `{items, next_cursor}` envelope unchanged. `events list` is the exception that keeps a poller's place: it always prints `next_cursor`, which is the last cursor the server returned, or, when the first page is empty, the `--after` value it was given, so a script can store the field after every run. `check` prints the merged result of its batches in the server's response shape (section 6.3).

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

Requests are never sent in parallel. The org shares one rate bucket and the server runs one version check at a time, so parallel requests would only produce 429s and 503s for this client and everyone else. Whether the clients also pace long runs below the org's rate, to leave room for the web UI, is a decision for Sam (section 12); the rules below assume they do not.

- **429:** wait for `Retry-After` and retry, while the wait fits in the remaining budget. `--max-wait` sets the budget for the whole command, default 2 minutes. The server sends `Retry-After: 60`, so the default allows about one retry.
- **503 with `Retry-After` from `/check`:** the check slot was busy. Wait for `Retry-After` plus up to 500 ms of jitter and retry, within the same budget.
- **503 from `/check` without `Retry-After`, with a `application/problem+json` body:** the server's check time limit (section 6.2). Any other 503, such as a proxy's own page while the server is down, is a server error (exit 7) and is never split.
- **Connection failure before a response:** retry once, only for `GET`, `PUT` and the check `POST`, which are safe to repeat. A watchlist item `POST` is not retried.
- **Everything else** is reported at once.

### 5.6 Compatibility

The application has no users besides its developers, so the JSON output and exit codes carry no compatibility promise until a release says otherwise; `docs/client.md` says so. The client is generated from the spec of its own commit. A client calling a server from another commit may send a parameter the server no longer accepts, which the server rejects (exit 8), or read a field the server has renamed, which shows up as a missing value and not as an error. Nothing in this design detects version skew. `cvert --version` prints the client's version; `whoami` does not yet return the server's (section 10), so comparing the two needs that follow-up and server builds that set a version.

The same holds for the MCP tool set: tool names, input schemas and result fields may change between commits until a release. Over HTTP the tools are served by the server itself, so they always match it. Over stdio they come from the `cvert` build, which can be older or newer than the server. A tool that is renamed or removed disappears from the tool list, which an agent host reports as an unknown tool, not as a wrong answer.

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

### 7.1 Two transports, one tool package

The tools live in one package, `internal/mcpserver`, built from three inputs: an API client (the generated client and its wrapper), the set of write tools to offer, and a version string. It takes no database pool, no store and no server configuration. Two transports serve it:

| | Streamable HTTP (primary) | stdio |
|---|---|---|
| Where it runs | Inside `cvert-ops serve`, at `POST /api/v1/mcp` | `cvert mcp`, a child process the agent host starts |
| Credential | The caller's `cvo_` key in `Authorization: Bearer` on every request | `CVERT_API_KEY_FILE` or `CVERT_API_KEY` in the process environment, as the specification asks of stdio servers |
| How a tool reaches the API | In process, through the server's own router (section 7.3) | Over HTTPS to `CVERT_URL` |
| Write tools offered | Set by the deployment, offered only to keys that may use them (section 7.4) | Set by the host's command line (section 7.9) |
| Version skew with the server | None: the server serves its own tools | Possible (section 5.6) |
| Needs on the agent host | The server URL and a key in the host's MCP configuration | The `cvert` binary, the URL and a key file |

HTTP is primary because the agent needs nothing installed, the tools always match the server, and the server's own middleware sees every call. stdio remains for agent hosts that cannot send a header with an HTTP MCP server, and for use against a server that has the endpoint turned off.

### 7.2 The HTTP endpoint

- **Route.** `POST /api/v1/mcp`, registered on the API router like `/whoami`: authenticated, not under `/orgs/{org_id}`, because a key belongs to one org and the tools take the org from the key. `GET` and `DELETE` get 405, as the specification asks of servers that support only 2026-07-28's shape; the SDK's stateless mode does this.
- **API keys only.** A request authenticated by a browser session cookie gets 403. Agents do not hold cookies, and a page in the user's browser must never drive tools with the user's session. This also removes the condition of the SDK's cross-site tool execution advisory, which needed an HTTP server without authorization.
- **Origin.** A request with any `Origin` header gets 403 before the SDK reads it. Agent hosts send none; browsers always do on a cross-origin POST. The specification requires 403 for an invalid `Origin`, and no browser origin is valid for this endpoint.
- **DNS rebinding.** The SDK's localhost check refuses a request that arrives from a loopback address with a non-localhost `Host`. That is exactly how a reverse proxy on the same host forwards requests, so the check is turned off (`DisableLocalhostProtection`). The attack it defends against is a browser page reaching a local server; here every request needs a Bearer key that such a page cannot hold, cookies are refused, and any `Origin` is refused.
- **Stateless, JSON responses.** `Stateless: true` and `JSONResponse: true`: each request is answered by one JSON object, with no session store and no SSE stream. No tool sends progress notifications. The SDK serves older clients that still send `initialize` with a temporary session per request.
- **Limits.** The global 1 MiB body limit applies, and the SDK's `MaxRequestBodyBytes` is set to the same value; a 500-item `check_components` call fits. The handler sets a 90-second write deadline per request, because the server sets no global `WriteTimeout` and a tool call can run 60 seconds (section 7.8).
- **Rate accounting.** The MCP POST itself is not charged to the org's bucket; each API request a tool makes is charged exactly as it would be from a script. A `tools/list` or `server/discover` costs no API request, like the unmetered `/cves` reads.
- **Logging and metrics.** The request log records the MCP method and tool name (the specification's `Mcp-Method` and `Mcp-Name` headers, which the SDK checks against the body) and never the arguments, because check items describe what an org runs. Inner API requests appear in the HTTP metrics and logs as ordinary API calls, with the outer request's ID.
- **Configuration.** `MCP_ENABLED`, default true. The endpoint exposes nothing a key cannot already reach through the REST API, and the SDK parses a body only after authentication has passed, so unauthenticated traffic never reaches it. `MCP_WRITE_TOOLS` names the write tools the deployment offers, default empty (section 7.4).

### 7.3 Acting only with the caller's key

For each HTTP request, the SDK calls `getServer(r)`, and the handler builds an MCP server for that request. Its API client uses an in-process transport: an `HttpRequestDoer` that hands each API request to the server's own router, with:

- the outer request's context, so a cancelled MCP request (the client closes the stream) cancels the API request;
- the outer request's `Authorization` header and no other credential;
- the outer request's peer address and forwarding headers, so the client-IP and trusted-proxy rules give the same address;
- the outer request's ID, so logs join the two.

The API request then runs the full middleware chain: authentication, the key's role cap, the membership check, the org rate limit, the body limit and the audit log, exactly as for a script with the same key. No service key exists. The transport accepts only the paths of the generated operations (section 4.2), so a tool cannot reach `/api/v1/mcp` itself or an admin route; and it records the response in memory through the size limits of section 5.1.

This is not the token passthrough the specification forbids. A `cvo_` key is issued by this server for this server, it is checked by the server's own middleware, and it never leaves the process. Loopback HTTP to the server's own URL was rejected: it would need the server to know its external URL and trust its own certificate, and it would double the connections for nothing the in-process call lacks.

Over stdio the same package gets the network client of section 5.1 instead, and every tool call is an HTTPS request with the key from the environment.

Audit entries depend on the endpoint: today the server audits watchlist create, update, delete and whole-list replace, but not single item add or delete (section 2), so a tool's item write is not audited until the server change in section 12 is made.

Five things keep the package honest:

1. A `depguard` rule refuses, in the non-test files of `cmd/cvert`, `internal/apiclient` and `internal/mcpserver`, any import of `internal/store`, `internal/api`, `internal/config`, `web`, `github.com/jackc/pgx`, and `database/sql`. Test files may import them, because the end-to-end tests start a real server (section 9). The in-process transport lives in `internal/api` and is passed in as an `HttpRequestDoer`, so `internal/mcpserver` never holds the router.
2. `depguard` sees only each file's own imports, so a package that imported `internal/alert/dsl` or `internal/ai`, which import `internal/store/generated` themselves, would link store code without tripping it. So a test runs `go list -deps` on `./cmd/cvert` and on `./internal/mcpserver` and fails when either list holds a denied package.
3. A CI step builds `./cmd/cvert` in a checkout with no `web/dist`, which fails if anything it imports reaches `web`.
4. The tool set (section 7.4) excludes everything a viewer key could read but an agent does not need, including channels and API keys.
5. The in-process transport's path allowlist (above).

### 7.4 Tools

Read tools are always offered. A write tool is offered only when both hold: the deployment names it (`MCP_WRITE_TOOLS` over HTTP, `--enable-write-tool` over stdio), and the key's org role is at least member, which `whoami` reports. A viewer key therefore never sees a write tool, and the server would refuse it with 403 anyway; the second check keeps the guarantee where the first is misconfigured. The specification allows the tool list to vary by the request's authorization; because it does, `tools/list` is marked `cacheScope: private` where the SDK exposes that field (the plan verifies that it does), and tools are listed in a fixed order.

| Tool | API calls | Input | Annotations |
|---|---|---|---|
| `whoami` | `GET /whoami` | none | read-only |
| `search_advisories` | `GET /cves` | `query`, `severity[]`, `in_cisa_kev`, `ecosystem`, `package_name`, `cwe_id`, `modified_since`, `min_cvss`, `min_epss`, `limit` (1 to 50, default 20), `cursor` | read-only |
| `get_advisory` | `GET /cves/{id}` | `id` | read-only |
| `check_components` | `POST /orgs/{org}/check`, as in section 6 with the limits of section 7.8 | `items[]`, 1 to 500, each exactly one of `{purl}`, `{ecosystem, name, version}`, `{cpe, version}`, with an optional `id` of at most 128 characters | read-only |
| `list_alert_events` | `GET /orgs/{org}/alert-events?expand=cve,rule` | `after`, `rule_id`, `cve_id`, `open_only`, `limit` (1 to 100, default 50) | read-only; waits for FEED-1 |
| `list_rules` | `GET /orgs/{org}/alert-rules` | `cursor` | read-only |
| `validate_rule` | `POST .../alert-rules/validate` | `logic` (`and`, `or`), `conditions[]`, `watchlist_ids[]` | read-only |
| `dry_run_rule` | `POST .../alert-rules/{id}/dry-run` | `rule_id` | read-only |
| `list_watchlists` | `GET .../watchlists` | `cursor` | read-only |
| `list_watchlist_items` | `GET .../watchlists/{id}/items` | `watchlist_id`, `cursor` | read-only |
| `add_watchlist_item` | `POST .../watchlists/{id}/items` | `watchlist_id`, exactly one of `cve_id`, `{ecosystem, package_name}`, `cpe` | write; not destructive |
| `remove_watchlist_item` | `DELETE .../items/{item_id}` | `watchlist_id`, `item_id` | write; destructive |

`list_watchlists` and `list_watchlist_items` are not in the requirement's list. Without them an agent cannot find the IDs that the write tools take, or see which components the org watches, which the requirement's orientation use case asks for. Replacing a whole watchlist is CLI-only: one wrong call could empty a list of 10,000 items, and a scanner script, not an agent, is its caller.

Write tools are named one by one rather than switched on together, so a write tool a later release adds is not offered until someone names it. This answers the requirement's "a server flag enables them per deployment" over HTTP, where the deployment is the server; whether the list form or a single switch is wanted is a decision for Sam (section 12).

### 7.5 Input schemas

Input schemas are narrow: enumerations are enumerated, numbers have bounds, strings have the server's length limits, IDs have patterns (`^CVE-\d{4}-\d{4,}$` where only a CVE ID is valid, UUID patterns for rule, watchlist and item IDs), and no object accepts properties it does not list. The SDK's schema inference reads only a `jsonschema` tag, as a description (`jsonschema-go` v0.4.3, `infer.go`), so these constraints cannot come from tags. Each tool sets its `InputSchema` explicitly: the schema inferred from its Go input struct, with the constraints added in code beside the struct. The SDK infers a schema only when none is set (`go-sdk` v1.8.0, `server.go`), and validates input against the one it has. Enumerations are taken from the generated client's constants (section 4.2), so a schema cannot offer a value the API does not accept. A test sends each tool out-of-range, wrong-enum and extra-property input and expects a refusal. No parameter is mirrored into a header (`x-mcp-header`): none is useful to an intermediary, and each one is a header the client must send and the server must check.

### 7.6 Descriptions

Each tool description states what the tool answers, the units and ranges of its numbers, and its enumerations. They are written for an agent that has never seen CVErt Ops. Key content:

- **Units.** CVSS scores are 0.0 to 10.0, and `min_cvss` compares the CVSS v4 score where a CVE has one and the v3 score otherwise. EPSS is a probability from 0 to 1, not a percentage. Dates are RFC 3339 in UTC. `modified_since` compares the date of the CVE's last material change: its status, severity, CVSS, CWEs, KEV or exploit flag, affected packages or affected CPEs. A change to EPSS, the description, NVD's CPE version ranges or the CNA's product data alone does not move it.
- **`check_components` statuses.** Only `not_affected` clears a version. `affected`: at least one advisory reports the version affected. `unresolved`: nothing was established as affected, but the data leaves at least one advisory undecided for this version, so this is not a clean result. `cannot_evaluate`: the check could not be completed; read `reason`. `no_advisory_found`: no advisory names the component in the data searched, which is not a statement that it is safe. `invalid`: the item could not be read; read `error`. `data_complete: false` means a feed the item depends on has not finished a full walk or has not succeeded for 7 days, so absence of an advisory means less.
- **`check_components` reasons**, one line each, including: distro packages are named by source package (`php8.5`, not `php8.5-cli`); a .NET SDK version must be sent as the runtime version; `fix_ecosystem` of the form `Ubuntu:Pro:<release>` means the fix ships only through Ubuntu Pro; `distro_lists_fixes_only` means the distribution's feed records issued fixes only, so a clean answer is never given for it.
- **`get_advisory` ranges.** Package ranges from the detail endpoint carry `introduced` and `fixed` but not `last_affected`, which the endpoint does not return; `check_components` results carry the matched ranges with every bound.
- **`validate_rule`:** the DSL's fields, operators and enumerated values, so an agent can write a rule without another call.
- **Untrusted text.** Advisory descriptions and references come from external feeds. `get_advisory` and `search_advisories` say so, so the agent treats that text as data. How the text is cleaned before it reaches the agent is a decision for Sam (section 12).

The check endpoint's own field documentation (`internal/api/check.go`) stays the authoritative text. Tests keep the descriptions from drifting: one fails when a check status, reason, warning or error code among the generated client's constants is missing from the `check_components` description, and one fails when a DSL field, operator or enumerated value in the DSL field catalog is missing from the `validate_rule` description. The descriptions summarise; they do not copy the server's text.

### 7.7 Results

Results are compact JSON in the MCP result's structured content, with the same JSON as one text block, as the specification asks for compatibility. A field the server can return as null keeps its null, because the server uses null to mean "not known" (`in_cisa_kev` and `epss_score` on a check advisory, for example) and that is not the same as false or zero. Booleans are always present. Only empty lists and optional strings with no value are omitted. Every result carries stable IDs and, where the web UI has a page, a link:

- CVEs and advisories: `id` and `url` (`<web base>/cves/<id>`).
- Watchlists: `id` and `url` (`<web base>/watchlists/<id>`).
- Rules and alert events: `id` only. The web UI has no page for either.

Over HTTP, `<web base>` is the server's configured external URL; over stdio it is `CVERT_WEB_URL` (section 5.1).

Per tool:

- `search_advisories`: per item `id`, `severity`, `cvss_v3`, `cvss_v4`, `epss`, `in_cisa_kev`, `exploit_available`, `modified`, `summary` (the description cut at 300 characters, with `summary_truncated`), `url`; and `next_cursor`.
- `get_advisory`: the list fields with the full description cut at 4,000 characters; `cwe_ids`; up to 50 affected package ranges as `{ecosystem, package, range_type, introduced, fixed}`; up to 50 NVD CPE matches with their range bounds; up to 20 CNA product entries; up to 20 references as `{url, tags}`. Each list carries the number of entries it omitted.
- `check_components`: `data_complete`, the feeds that are not complete, and per item `index`, `id`, `status`, `reason`, `error`, `warnings`, `data_complete`, `component`, `counts`, and up to 20 advisories as `{advisory_id, cve_ids, verdict, reason, fixed_version, fix_major, fix_ecosystem, severity, cvss_v3, epss, in_cisa_kev, url, matched_ranges}`, with `advisories_truncated`. `matched_ranges` holds up to 5 of the advisory's matching ranges with every bound (`introduced`, `fixed`, `last_affected`) and its evidence, because the detail endpoint does not return `last_affected`. `unanswered` as in section 6.3.
- `list_alert_events`: per event `id`, `rule_id`, `rule_name`, `cve_id`, `severity`, `in_cisa_kev`, `epss`, `open`, `first_fired_at`, `last_fired_at`, `url` of the CVE; and `next_after`, the cursor to pass as `after` next time, which is the `after` it was given when no event was returned.
- `dry_run_rule`: `match_count`, `candidates_evaluated`, `partial`, and up to 20 sample CVE IDs with URLs.

A failed API call returns a tool error (`isError: true`), not a protocol error, with a fixed sentence naming the HTTP status and the server's problem title and detail. The key never appears in a result.

### 7.8 Limits inside a tool call

A tool call must not stall the agent: a call that blocks for a minute looks to the agent like a hang, with no explanation. So, on both transports:

- **A deadline per call.** Every tool call has a total deadline of 60 seconds. When it passes, the call returns a tool error saying the server is busy and to retry.
- **Sequential requests within a call.** A tool's API requests run one after another.
- **Retries.** A busy check slot (`Retry-After: 1`) is retried inside the call while the deadline allows. A 429 (`Retry-After: 60`) is returned at once as an error that says when to retry.
- **`check_components`.** Its input is at most 500 items, so it is one request. It splits on the candidate-limit 422 as in section 6.2, within the deadline. On the server's time-limit 503 it does not split: it returns a tool error that says to retry with fewer items, because a split could take another 60 seconds.

Over stdio, one process serves one agent host, so the process also sends one API request at a time across concurrent tool calls, in arrival order. A call whose host cancels it while it waits leaves the queue and never sends its request; a call cancelled while its request is in flight cancels that request; waiting time counts toward the call's deadline. Over HTTP, separate MCP requests may come from separate keys and orgs, so no lane is shared between them; the org rate limit and the check slot govern them as they govern any API traffic.

A tool call costs one API request, plus busy-slot retries and the requests of any 422 split. Over stdio, the process also spends one `whoami` request at startup, repeated on the first tool call if it failed; over HTTP, the tools that need the org ask `whoami` once per MCP request.

### 7.9 stdio: `cvert mcp`

`cvert mcp [--enable-write-tool NAME]...` serves the package over stdio with the network client and the lane of section 7.8. `stdout` carries only MCP messages; logs go to stderr. At startup it calls `whoami`. A 401 or 403 there ends the process with exit code 4 or 5 and a message on stderr, which the agent host shows; the server does not start in a state where every tool fails. Any other failure there (a network error, a 5xx, a 429) does not stop it: the server starts, and the first tool call retries `whoami` and returns its error to the agent if it fails again. An agent host may start before the network or the server is up, and a process that exits then stays down until the host restarts it.

A stdio bridge to the HTTP endpoint was considered in place of running the tools locally: one tool implementation, never out of step with the server. It was not chosen because it would make stdio depend on the endpoint being enabled and would add a forwarding layer that re-lists and re-dispatches every tool. Running the same package locally costs only the version skew of section 5.6.

### 7.10 Authorization profile

The endpoint authenticates the existing `cvo_` API keys as Bearer tokens. A 401 carries `WWW-Authenticate: Bearer`, without the `resource_metadata` parameter, because no Protected Resource Metadata document exists. This follows the specification's rule that authorization is optional, and does not follow its OAuth 2.1 profile, which an HTTP server SHOULD follow when it supports authorization. The consequence: agent hosts that can send a static header (Claude Code and Codex do) can connect; a host whose remote connectors only run the OAuth discovery flow cannot. Adopting the profile means CVErt Ops acting as an OAuth resource server for an authorization server, either one built into CVErt Ops or an external identity provider issuing tokens with this server as their audience. That is a decision for Sam (section 12), and section 12 recommends against doing it in this work. The SDK's `auth.RequireBearerToken` and `auth.ProtectedResourceMetadataHandler` would carry it when it comes.

## 8. Code layout

### 8.1 Packages

| Path | Holds |
|---|---|
| `cmd/cvert/` | cobra commands, configuration loading, output formatting, exit codes, and `cvert mcp`. |
| `internal/apiclient/gen/` | The generated client (section 4.2), committed. |
| `internal/apiclient/` | The wrapper: configuration checks, the network transport, the stdio lane, problem-detail decoding, the error type that maps to exit codes, retries, pacing if adopted, check batching and merging. |
| `internal/apiclient/trivy/` | Trivy report reading (section 6.1). |
| `internal/mcpserver/` | Tool definitions, input structs and schemas, result shaping and descriptions. Built from an API client, the enabled write tools and the version (section 7.1). |
| `internal/api/mcp.go` | The HTTP endpoint: route, key-only and `Origin` checks, the per-request `getServer`, and the in-process transport (sections 7.2 and 7.3). |

The CLI and both MCP transports share batching, retry mechanics and error mapping in `internal/apiclient`, so they cannot disagree on how a status is read. Their policies differ where section 7.8 says so (budget, deadline, no timeout split in MCP), and each passes its policy to the wrapper.

### 8.2 Build and image

- `.golangci.yml`: the `depguard` rule of section 7.3. The `go list -deps` test is a Go test in `cmd/cvert`.
- `go.mod`: the generator as a `tool` directive; `go generate` regenerates `internal/apiclient/gen`.
- CI: build `./cmd/cvert` in a job that has no `web/dist`; regenerate the client and fail on a difference; run the tests with the Go tests.
- `docker/Dockerfile`: build `/cvert` beside `/cvert-ops` in the builder stage, with the commit passed in as a build argument (section 5.1), and copy it into the distroless stage. The entrypoint stays `/cvert-ops`.
- Version from `runtime/debug.ReadBuildInfo` (section 5.1); `cvert --version` prints it, and the MCP server reports it in its server info.

### 8.3 Documentation

`docs/client.md`: installation, configuration, the command list, exit codes, a scanner-to-watchlist example with `jq`, and agent host configuration examples: the HTTP endpoint with the key in an `Authorization` header, and `cvert mcp` with `CVERT_API_KEY_FILE`, so the key sits in a file of its own rather than in the host's configuration. Example host names use `example.internal`.

## 9. Tests

Every test that reaches the API runs against a real server: the production handler from `internal/api`, a testcontainers PostgreSQL database from `testutil.NewTestDB`, CVEs from `testutil.SeedCorpus`, and users, orgs and keys created through the store, served over loopback by `httptest.NewServer`. No end-to-end test uses a mock. The server is built with the dependencies the tested routes need, which an empty `ServerDeps{}` (as in `internal/api/smoke_test.go`) does not give: an alert evaluator, without which `dry-run` answers 503, and an audit writer, flushed before any assertion on the audit log because it writes asynchronously. The org rate limiter's clock is injected, so a rate-limit test does not race the token refill; if `ServerDeps` has no way in, the plan adds a test hook.

### 9.1 No database

- **Generated client in step:** regenerating from the checked-in 3.0 document produces no difference (CI), and the 3.0 document matches the served spec (the existing drift test, extended).
- **Import boundary** (section 7.3): `go list -deps` of `./cmd/cvert` and `./internal/mcpserver` holds no denied package.
- **Configuration.** Both key settings set, neither set, a malformed key, `http://` to a non-loopback host, an unreadable key file: each exits 2 and sends no request. No command defines a flag whose name contains `key`.
- **Trivy reading** against golden reports (section 6.1): deduplication, the full substituted purl for `deb` and `apk` packages, `id` from the package ID, skipped packages, the warning for a report without `Packages`.
- **Batch splitting and merging**, as unit tests of the splitting logic: 500 and 501 items, the 900 KiB size bound, index rewriting, feed merging including a null `last_success_at`.
- **Retry policy, the 422 and 503 splits, and the stop rule of section 6.2**, against an `httptest` server that returns scripted statuses. These are unit tests of the client's reaction to statuses the real server cannot be made to return on demand (a candidate-limit overrun needs more candidate rows than the seeded corpus holds; a 30-second timeout would make the test take 30 seconds), including a proxy-style 503 with no problem body, which must not split.
- **Client policy:** a redirect is refused and not followed; no cookie is stored or sent; an over-limit response body is refused.
- **Input schemas** (section 7.5): each tool refuses out-of-range, wrong-enum and extra-property input.
- **Descriptions** (section 7.6): every check status, reason, warning and error code among the generated constants, and every DSL field, operator and enumerated value, appears in its tool description.

### 9.2 CLI against a real server

The CLI's commands run in process through a `run(args, env, stdin, stdout, stderr) int` function, so tests assert the exit code and both streams.

- Each command's success path, with output compared to the server's response.
- `check` with 501 items in one input: two requests, one merged result, indexes 0 to 500.
- `check --input trivy` with a golden report against the seeded corpus.
- Exit codes on the real server: a revoked key (4), a viewer key adding a watchlist item (5), an empty search (3, or 0 under section 12 item 7(a)), `cves get` of an unknown ID (3), an invalid rule in `rules validate` (8, or the code section 12 item 7(b) settles), and the 11th request inside the 10-request burst of a free-tier org with `--max-wait 0` (6), with the limiter's clock held still.
- `watchlists items replace --cves -` from stdin, then the same list again, reporting all unchanged.
- In every test, a helper fails the test if the key appears in stdout or stderr.

### 9.3 MCP over HTTP against a real server

An MCP client from the SDK, using its streamable HTTP client transport with protocol 2026-07-28, against the real test server's `/api/v1/mcp`.

- Each tool is called and its result checked: compact fields present, nulls kept, URLs formed, truncation counts right.
- The second acceptance criterion of section 11 as a test: for a package and version in the seeded corpus with a known affecting advisory, `check_components` alone returns that advisory with its fixed version, and `get_advisory` on its ID returns its ranges.
- Authentication: no key gives 401 with `WWW-Authenticate: Bearer`; a revoked key gives 401; a browser session cookie gives 403; a request with an `Origin` header gives 403 and never reaches a tool.
- Tool list by authorization: with `MCP_WRITE_TOOLS` empty, no key sees a write tool; with it set, a viewer key sees none and a member key sees the named ones, in the same order on every call.
- The guarantee of section 7.3: each tool's API requests appear in the server's request log with the key's ID; the org rate limit counts them (a 429 inside a tool becomes a tool error); a member key's `add_watchlist_item` adds the item, and, once the server audits item writes (section 12), the audit log has a row with the key's `api_key_id`. A tool's API client cannot reach a path outside the allowlist.
- Cancellation: a client that closes the request while `check_components` runs cancels the API request.
- Older clients: a client using 2025-11-25 with `initialize` still gets answers.
- `GET /api/v1/mcp` gives 405; with `MCP_ENABLED=false` the route is absent.

### 9.4 MCP over stdio

- An SDK client connected in memory to `internal/mcpserver` built with the network client, against the real test server: the same tool checks as 9.3 on a subset, write tools offered only with `--enable-write-tool` and a member key.
- A startup with a revoked key exits 4 without serving; a startup with the server unreachable keeps serving and the first tool call returns the connection error.
- Two concurrent tool calls send their requests one after the other; a call cancelled while queued sends nothing.
- One test builds `cvert` and runs `cvert mcp` as a child process over real stdio, to check that stdout carries only MCP messages and logs go to stderr.

### 9.5 Run cost

Go builds one test binary per package, and each test binary that calls `testutil.NewTestDB` starts one PostgreSQL container, with a cloned database per test. The CLI tests (`cmd/cvert`), the HTTP MCP tests (`internal/api`, which already starts one) and the stdio MCP tests (`internal/mcpserver`) add two containers to a full test run.

## 10. What this design needs from the parallel session

| Work here | Needs | Exact need |
|---|---|---|
| Every org-scoped command and tool, and stdio MCP startup | AUTH-5 `GET /whoami` — landed (`internal/api/whoami.go`) | Landed: accepts an API key and returns `api_key {id, name, role, expires_at}` and `org {id, name, role, tier, rate_limit {scope, requests_per_minute, burst}}`; applies the org membership check, so a key whose creator has left the org fails here. It counts against the org rate limit, so each CLI invocation and each HTTP MCP request that needs the org spends one request of the org's budget on it; `docs/client.md` says so. Still missing: the server's version, which section 5.6 would use and which reads `dev` until server builds set it; a small follow-up to `whoami`. |
| `events list --after`, `list_alert_events` | FEED-1 | An ascending order selected by `after`; a `limit` parameter; a way to start (an ascending first page with no `after`, or a documented starting cursor); and a cursor returned on every page that holds items, including the last, so a poller can store it and resume after the last event it saw. Every event must reach a poller exactly once, including an event whose transaction commits after a later event's (with `first_fired_at DEFAULT now()` and a random UUID tiebreak, a late commit lands behind a cursor already handed out; implementation pitfall NOTIFY-20 records the same failure in the alert evaluator), and including a resolved event that is reopened, which changes an existing row. A cursor stored by a poller must stay valid across server upgrades, or be refused with a problem type of its own, so a poller can tell a stale cursor from a bad request. The design treats an absent cursor on an empty page as "keep the previous one". |
| Event context in `events list` and `list_alert_events` | FEED-2 `expand=cve,rule` — landed (`internal/api/alert_events.go`) | Landed: `cve {status, severity, cvss_v3_score, cvss_v4_score, in_cisa_kev, epss_score}` and `rule {name, deleted, matched_watchlist_items}`, which covers severity, KEV, EPSS and the rule name. |

Every org-scoped request needs the org ID from `whoami`, which has landed, so everything except `events list --after` and `list_alert_events` can be built now. Those two wait for FEED-1.

## 11. Acceptance

Adapted from the requirement, whose example question depended on per-host findings, which section 9 of the private requirements dropped.

- A script on a timer, with only `cvert` and `jq`, can check a list of purls, poll alert events with a stored cursor, and set a watchlist's CVE items from a scanner report, without writing HTTP code.
- An agent configured with the server's MCP URL and a viewer key can answer "is component X at version V affected by CVE Y, and which version fixes it on the same release line" in at most two tool calls (`check_components`, then `get_advisory` if it needs more than the matched ranges), and is offered no tool that changes anything. Section 9.3 tests this against the seeded corpus.
- With write tools named in the deployment, the same agent with a viewer key is still offered none and changes nothing. With a member key its writes succeed, and, once the server audits item writes (section 12), they appear in the audit log under its key.
- The same holds over stdio with `cvert mcp`.

## 12. Decisions for Sam

Each item states the question, the options, the recommendation, and the strongest case for the option not recommended, with whether that case changes the recommendation. Elsewhere, the design text describes the recommended option, and each span a pending item would change says so; the plan follows Sam's answer, not the text.

1. **Requirements coverage.** The requirements are summarised in section 1 from a private document reviewers could not read, so nobody has checked this design against it in full. Confirm that sections 1 and 5 to 7 cover CLI-1 and MCP-1 as amended, or name what is missing.

2. **Binary** (section 3). A separate `cvert` binary, also in the container image; or subcommands of `cvert-ops`. Recommendation: separate binary.
   *Strongest case for subcommands:* with HTTP primary, agent hosts no longer need any binary, so the install argument now concerns only script hosts; one artifact means one version and no client-server skew, and a script host with Docker can run the image the server already ships. *Verdict:* the case is stronger than before, but script hosts without Docker, and Windows workstations, still need a `go install`-able binary, and the server binary cannot be built without Node. Recommendation unchanged.

3. **Client code** (section 4.2). Generated with `oapi-codegen` v2.8.2, filtered to the operations used, wrapped by a thin hand-written layer, accepting `oapi-codegen/runtime` and its transitive `apapsch/go-jsonmerge/v2` (last push 2021-11, linked but never called); or hand-written with a conformance test; or shared types. Recommendation: generated.
   *Strongest case for hand-written:* no runtime modules at all, one of which fails the age rule; no 4,300 generated lines in review; no generator, with its 2026 advisory history, in the build; and the CLI passes most responses through without types. *Verdict:* the generated client keeps the raw bytes for passthrough, leaves the transport to the wrapper, and replaces a hand-maintained conformance table with the compiler; the stale module is unreachable, and the generator's advisories need a hostile spec. Sam's burden of proof for hand-written is not met. Recommendation: generated.

4. **MCP SDK** (section 4.1). `github.com/modelcontextprotocol/go-sdk` v1.8.0, accepting its transitive `yosida95/uritemplate` v3.0.2, unchanged since 2022, which no input of ours reaches; or `mcp-go`. Recommendation: the official SDK.
   *Strongest case for `mcp-go`:* MIT throughout, more widely used (about 9,200 stars against 5,300), one 2026 advisory against four, and it also supports 2026-07-28. *Verdict:* two of the official SDK's four advisories concern the HTTP transport this design now makes primary, which cuts against it; but all four are fixed, the endpoint's own controls (key only, no `Origin`) do not rely on those fixes, and the official SDK is maintained by the protocol's own maintainers. Recommendation unchanged.

5. **Streamable HTTP.** *Decided by Sam: primary.* Sections 7.1 to 7.3 carry it.
   *Strongest case for stdio only, recorded for the record:* the endpoint is a new parser on the public API surface, the SDK's HTTP transport had two high advisories in 2026, and static keys do not follow the specification's OAuth profile. *Answer in this design:* under 2026-07-28 the endpoint is a stateless authenticated POST behind the existing middleware; the SDK parses nothing until a key has authenticated; cookies and any `Origin` are refused; and the profile question is item 16.

6. **Tool set and the write switch** (section 7.4). Two read tools beyond the requirement (`list_watchlists`, `list_watchlist_items`); write tools limited to adding and removing one watchlist item; whole-list replace CLI-only; write tools named one by one (`MCP_WRITE_TOOLS`, `--enable-write-tool`) and offered only to member keys. The alternative switch is one on-or-off setting. Recommendation: as listed.
   *Strongest case for one switch:* fewer settings; an operator who enables writes wants writes, and a new write tool in a release is reviewed when the release is. *Verdict:* releases do not prompt anyone to revisit an agent deployment's settings, and naming tools costs one list. Recommendation unchanged.

7. **Exit codes** (section 5.4). (a) An empty list: exit 3; or exit 0 with an empty `items`, keeping 3 for a single-resource 404. (b) An invalid rule in `rules validate`: exit 8, shared with malformed requests; a dedicated code 10; or exit 0, tested with `jq -e '.valid'`. Recommendation: exit 0 for empty lists, and code 10 for an invalid rule. This narrows the requirement, which asks for an exit code meaning "no results", to lookups.
   *Strongest case for exit 3 on an empty list:* the requirement asks for it in terms; a script reads "nothing new" without parsing; systemd's `SuccessExitStatus=3` and `|| [ $? -eq 3 ]` handle a quiet poll in one line; `grep` set the convention. *Verdict:* this is close. Exit 0 avoids a trap for the common timer script; exit 3 follows the requirement and convention. The recommendation stays exit 0, by a small margin, and either is defensible.

8. **Transport security** (section 5.1). `http://` is refused except to loopback. The production stack's Caddy (`docker/Caddyfile`) serves its default `localhost` host from Caddy's local CA and gets a public certificate for a public host name; a self-hosted install on a private host name, which cannot pass an HTTP challenge, often uses a private CA, which a client on another host must trust. Go reads `SSL_CERT_FILE` on Linux but not on Windows or macOS. Options: no setting (users add the CA to the system store); a `CVERT_CA_FILE` setting naming a PEM bundle added to the system roots; also allowing `http://` to a named host (the compose network's `http://app:8080`). Recommendation: add `CVERT_CA_FILE`; allow no plain HTTP beyond loopback.
   *Strongest case for allowing plain HTTP to a named host:* traffic on a private compose network never leaves the host, and requiring TLS there is ceremony. *Verdict:* a key on an unencrypted network is readable by anything else on that network, and the in-container path to Caddy works. Recommendation unchanged. With HTTP MCP primary, agent hosts connect to the server directly and the same private-CA question applies to their MCP clients, which this design does not control; `docs/client.md` says so.

9. **No org setting** (section 5.1). The org always comes from `whoami`; or an optional `CVERT_ORG_ID`. Recommendation: `whoami` only.
   *Strongest case for `CVERT_ORG_ID`:* `whoami` now counts against the org's rate limit, so every CLI run spends one request on it. *Verdict:* a timer every five minutes spends 288 requests a day of a budget of 86,400 on the free tier. Recommendation unchanged.

10. **Audit of item writes** (sections 2, 7.3). Add audit entries to single item add and delete in the first pull request, a small server change; or accept that item writes by a key are unaudited. Recommendation: add them.
    *Strongest case against:* item writes are frequent and individually low-impact, and the scanner path (whole-list replace) is already audited as one entry. *Verdict:* agent writes are exactly what the audit log exists for, and they arrive one at a time. Recommendation unchanged.

11. **Watchlists fed by a scanner** (section 5.2). `items replace --cves` removes every package and CPE item on the watchlist, and `items add` fails with 409 on an item already present. Options for `--cves`: refuse with exit 8 when the watchlist holds anything but CVE items; or read, merge and send, which can lose a concurrent edit. Options for `add`: report an item already present as success (`already_present`); or keep the 409. Recommendation: refuse on a mixed watchlist, and treat an item already present as success.
    *Strongest case for merging:* it is what a person expects of "set this watchlist's CVEs", and in a single-tenant lab a concurrent edit is unlikely. *Strongest case for keeping 409:* a typo'd duplicate is visible. *Verdict:* a dedicated watchlist costs one API call to create, while a lost edit is silent; and retries after a lost response are the common case for agents. Recommendation unchanged.

12. **DSL reference for `validate_rule`** (sections 2, 7.6). Move the DSL field catalog to a package that imports no store code and build the description from it; or keep a hand-written description with a test over field names, operators and enumerated values. Recommendation: move the catalog.
    *Strongest case for hand-written:* no server refactor, and the text can be written for agents, with examples, rather than mirroring a catalog. *Verdict:* the description can still add examples around a generated field list. Recommendation unchanged.

13. **Sharing the org's request budget** (sections 2, 5.5). Web sessions and every key of an org draw from one bucket (60 a minute, burst 10, on the free tier), and the server tells a refused client to wait 60 seconds. `watchlists items list --all` on a list of 10,000 items takes 200 requests (50 a page), so with the default 2-minute budget it exits 6 after holding the bucket empty, and web users of the org get 429s meanwhile. Options: document it; pace every client request to half the org's per-minute rate from `whoami`; pace only long runs (`--all` walks and multi-batch checks); or wait for per-key limits on the server (AUTH-7).
    *Strongest case for documenting only:* pacing duplicates the server's limiter in every client, adds latency when the web UI is idle, and per-key limits are the real fix. *Verdict:* the case defeats pacing every request, not pacing long runs, which are the only runs that empty the bucket. Recommendation changed: pace long runs only, from `whoami`'s rate; per-key limits remain the server-side answer.

14. **Feed text given to agents** (section 7.6). Advisory descriptions are attacker-controlled. Implementation pitfall ARCH-13 strips markdown link syntax, HTML tags and control characters before such text reaches a model. Options: label it as untrusted only; also strip control and invisible formatting characters and keep the length caps; or apply ARCH-13's cleaning to description fields.
    *Strongest case for ARCH-13's cleaning:* the project's own pitfall requires it for model-bound feed text, and markdown images and links in a description are a known exfiltration path when an agent host renders them. *Verdict:* the case holds. Description text loses little when an inline link keeps its text and drops its target, and the `references` field keeps every URL as structured data. Recommendation changed: apply ARCH-13's cleaning (control and invisible formatting characters, HTML tags, markdown link and image syntax, keeping link text) to description fields, keep the caps, and leave `references` as structured URLs.

15. **PLAN.md.** It has no section on an API client or MCP server. Add one stating the binary, the HTTP endpoint, the rule that both clients act only through the HTTP API with the caller's key, and the write-tool setting, with this design as the detail. Recommendation: add it.
    *Strongest case against:* design documents carry detail and PLAN.md grows. *Verdict:* the rule about acting only through the API is a security invariant that belongs where future work looks first. Recommendation unchanged.

16. **MCP authorization profile** (section 7.10). Static `cvo_` keys now, with the OAuth 2.1 profile later; or the profile now. Recommendation: keys now.
    *Strongest case for the profile now:* the specification says an HTTP server SHOULD follow it; remote connector interfaces that only run OAuth discovery cannot connect without it; and a long-lived key in an agent host's configuration is a standing secret, where OAuth tokens expire. *Verdict:* the profile needs an authorization server CVErt Ops does not have, or an external identity provider issuing audience-bound tokens, plus scopes (AUTH-3, not built); the hosts the requirement names accept a static header. Recommendation unchanged; revisit with AUTH-3.

17. **The endpoint's defaults** (section 7.2). `MCP_ENABLED` on by default with no write tools, or off by default. Recommendation: on.
    *Strongest case for off:* a self-hoster who upgrades gets a new endpoint they did not ask for, in a security product. *Verdict:* the endpoint offers only what each key can already do through the REST API, write tools are off, and the SDK parses nothing before authentication. Recommendation unchanged, and `docs/client.md` and the release notes say how to turn it off.

18. **Rate accounting of MCP requests** (section 7.2). Charge only the API requests a tool makes; or also charge each MCP POST. Recommendation: API requests only.
    *Strongest case for charging each POST:* `tools/list` and `server/discover` cost the server an authenticated request each, and an agent that lists tools in a loop would be unmetered. *Verdict:* the authenticated `/cves` reads are unmetered the same way today, and charging the POST would bill a tool call twice. Recommendation unchanged.

## 13. Delivery

Four pull requests, each with an implementation plan reviewed first:

1. Spec and client: the four undocumented `/cves` score filters documented in the spec; `openapi-3.0.json` written and drift-checked; the generated client and its wrapper; `cmd/cvert` with configuration, exit codes, the `cves`, `check`, `rules` and `watchlists` commands; audit entries for item writes if Sam agrees; the `depguard` rule and the `go list -deps` test; the CI build without `web/dist` and the regeneration check; the Dockerfile change; and `docs/client.md`.
2. `internal/mcpserver` with the read tools, and the HTTP endpoint in `serve` with its write-tool setting.
3. `cvert mcp` over stdio.
4. `events list` and `list_alert_events`, after FEED-1.
