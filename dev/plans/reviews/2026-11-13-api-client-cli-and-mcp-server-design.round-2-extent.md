# Round 2 review: requirements trace, and simplicity and proportionality

Document: `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`. Requirements-pinning status: UNPINNED, so the requirements-trace lens covers internal consistency only.

Code claims below were checked in the worktree at `b493321`. The commands and their results are in each finding's evidence.

## Standing finding

**S1** · requirements trace · whole document, section 1 ("The requirements come from the private homelab integration requirements (section 7.7, as amended by its section 9 decisions)") · Requirements completeness cannot be verified because the requirements are unpinned. The source requirements are private and not in the context slot, so this round did not trace them in either direction: from each requirement to a design section, or from each design element back to a requirement. Section 1's statement that `annotate`, inventory and findings are out of scope, and section 7.2's two added tools, could not be checked against the source. · Axes: objective; remedy determinate (pin the requirements statement and run the bidirectional trace).

## Findings, most severe first

**R1** · requirements trace (internal consistency) · section 10, "Everything else can be built before they land: … rule and watchlist requests (once `whoami` gives the org, they need nothing new), and the MCP read tools other than `whoami` and `list_alert_events`."
- Claim: Section 10 contradicts itself, section 1 and section 7.1 about what can be built before AUTH-5.
- Evidence:
  - The first row of the same section 10 table says AUTH-5 is needed by "Every org-scoped command and tool, and MCP startup".
  - Section 1 says "Nothing that depends on them is built before they land."
  - Section 7.1 says that at startup the MCP server calls `whoami` and "does not start in a state where every tool fails". So no MCP tool, read or write, can run before AUTH-5. That includes `search_advisories` and `get_advisory`, which are not org-scoped.
  - `check_components`, `list_rules`, `validate_rule`, `dry_run_rule`, `list_watchlists` and `list_watchlist_items` all take `{org}` from `whoami` (section 7.2), and section 5.1 removes every other source of the org ID ("No org setting").
  - The sentence names rule and watchlist requests as things that can be built "before they land", and then, in a parenthetical, as things that need `whoami`. The next sentence ("In practice the plan builds … the org-scoped commands after AUTH-5 merges") contradicts the list just before it.
  - Section 13's first PR has the same split: it bundles the `check`, `rules` and `watchlists` commands and then says "Org-scoped commands land once AUTH-5 has merged".
- A planner will read either "build the MCP read tools now" or "build nothing org-scoped now", depending on which sentence it reads.
- Axes: objective; remedy determinate. List exactly what is buildable before AUTH-5: configuration, the client core, the conformance test, the `cves` commands, check batching and Trivy reading as units with no request sent. State that the MCP server as a whole waits for AUTH-5, because its startup calls `whoami`.

**R2** · requirements trace (internal consistency); simplicity and proportionality · sections 5.5, 6.2 and 7.5: "split the batch in two halves and send each, recursively"; "`--max-wait` sets the budget for the whole command, default 2 minutes"; "one per batch of 500 items".
- Claim: Check batching and splitting is designed without accounting for the org rate limiter that the design itself cites. The design does not say what `check` returns when the retry budget runs out partway through a batched or split run.
- Evidence:
  - `/check` is under the org limiter. `internal/api/server.go:319-322` registers `orgRateLimitMiddleware` on the `/{org_id}` group, and `/check` is registered inside that group at line 459.
  - The bucket refills 1 token a second, with a burst of `ratePerMin / 6` = 10. A refusal gets `Retry-After: 60` (`internal/api/middleware_tier.go:59-70`).
  - With the 2-minute default budget, a CLI `check` can therefore send about 20 requests: the burst, one wait, the burst again. A second 60-second wait does not fit.
  - Each 422 split costs requests. Isolating one candidate-limit item in a 500-item batch takes about 1 + 2·⌈log₂500⌉ ≈ 19 requests. Isolating two items in different halves takes about 37.
  - A 5,000-line purl list is 10 batches before any split.
  - The design never states:
    - what happens when the budget runs out after some batches were answered: exit 6 (section 5.4, "Rate limited") with the answered results discarded, or exit 9 with the remainder in `unanswered`;
    - the practical ceiling on input size for one `check` invocation.
  - For MCP (section 7.5), the 5-second budget turns the first 429 into a tool error. The design does not say whether that error carries the results already answered.
  - Section 7.5's cost line, "one per batch of 500 items", cannot describe a tool whose input is capped at 500 items (section 7.2). The real cost is driven by splits, not by batches.
- Axes: the gap is objective; the remedy is a choice. Options: return partial results with exit 9 and `unanswered` on budget exhaustion; document the request cost of splits and an input ceiling; stop splitting recursively once a request budget is spent.

**R3** · requirements trace (internal consistency) · section 5.2, "`--all` follows `next_cursor` until the server returns none, and prints one envelope `{"items": [...]}` holding every item"; section 11, "poll alert events with a stored cursor"; section 10, "a cursor returned on every page that holds items, including the last, so a poller can store it".
- Claim: `events list --after CURSOR --all` throws away the cursor that the acceptance criterion's poller has to store.
- Evidence:
  - Section 10 asks FEED-1 to return a cursor on the last page precisely so that a poller can resume.
  - Section 5.2's `--all` envelope holds only `items`, so a poller that drains new events with `--all` has no cursor to store. Without `--all` it must loop over pages itself. That is HTTP-pagination code in the script, which the acceptance criterion ("without writing HTTP code") excludes in spirit.
  - Section 10's "The design treats an absent cursor on an empty page as 'keep the previous one'" has no owner on the CLI side. Section 5.3 prints the server envelope unchanged, and the CLI keeps no state, so the script has to keep the old cursor. The design does not say so. For MCP, section 7.4 promises "the cursor to pass as `after` next time", which on an empty page must be the input `after` echoed back. That is also not stated.
- Axes: objective; remedy mostly determinate. Include the last cursor in the `--all` envelope, at least for `events list`. State who keeps the previous cursor on an empty page: the script for the CLI, the echoed input for MCP.

**R4** · requirements trace (internal consistency) · section 7.4, "`check_components`: `data_complete`, the feeds that are not complete, and per item `index`, `id`, `status`, `reason`, `component`, `counts`, and up to 20 advisories …"; section 7.3, "`data_complete: false` means a feed the item depends on has not finished a full walk".
- Claim: The compact `check_components` result drops two per-item fields that qualify a "no advisory" answer, while the tool description explains one of them in per-item terms.
- Evidence:
  - The checked-in spec's `CheckItemResult` has `data_complete` ("Every feed this item depends on is complete.") and `warnings`, whose enum is `cna_product_not_mapped`. See `openapi.json`, and `internal/api/check.go:83`.
  - The warning is set on a `no_advisory_found` CPE item (`internal/check/evaluate.go:401`, `internal/check/results.go:28-30`).
  - Section 7.3 tells the agent that `no_advisory_found` "is not a statement that it is safe" and describes `data_complete` per item. Section 7.4 returns only the top-level `data_complete`, which the spec defines over all valid items ("Every feed a valid item depends on…"), and it drops `warnings` entirely.
  - The description drift test (sections 7.3 and 9.1) covers statuses and reasons but not the `warnings` enum, so nothing would catch the omission.
  - A smaller related point: per-item `id` is listed in the result, but section 7.2's input schema allows no `id` property ("no object accepts properties it does not list"), so the field is always null and therefore always omitted.
- Axes: objective; remedy determinate. Keep per-item `data_complete` and `warnings`, add `warnings` to the description test, and drop `id` from the result list.

**R5** · requirements trace (internal consistency) · section 7.5, "A 429 (`Retry-After: 60`) is returned to the agent as an error that says when to retry, because blocking a tool call for a minute stalls the agent with no explanation."
- Claim: Section 6.2's timeout splitting, which `check_components` inherits ("batched as in section 6"), blocks a tool call for longer than the minute that section 7.5 rejects.
- Evidence:
  - A 500-item call that times out costs 30 s. Each of its two halves can then time out again, at 30 s each (section 6.2, step 4). That totals about 90 s, inside the 60-second per-request timeout of section 5.1.
  - Section 7.5 also serialises all API requests in the process, so every other tool call queues behind it for the same time.
  - The 5-second budget limits only waits for `Retry-After`. It does not limit split work, so the stated rationale does not hold for the most expensive tool.
- Axes: contestable (90 s may be acceptable for a check); remedy a choice. Either accept it and correct the rationale, or skip the timeout split in MCP and return the item as unanswered.

**R6** · simplicity and proportionality; requirements trace · section 5.4, exit 3 "A search or list returned no items".
- Claim: For section 11's script on a timer that polls `events list --after`, the normal quiet case, no new events, exits nonzero.
- Evidence:
  - Section 5.4 makes exit 0 conditional on "returned at least one item".
  - A systemd timer unit, or a cron wrapper using `set -e`, records every quiet poll as a failure unless the script special-cases 3.
  - `grep` uses the same convention, so the choice has precedent. But the design does not weigh it for the polling use case that its own acceptance criterion names.
- Axes: contestable; remedy a choice. Keep exit 3 and document it for polling, or exit 0 for an empty `events list --after`.

**R7** · requirements trace (internal consistency) · section 7.1, "The MCP package is built from one value: an API client holding the server URL and the caller's key. Its constructor takes nothing else".
- Claim: The constructor described cannot implement two other parts of the design.
- Evidence:
  - Section 7.2 registers write tools only with `--enable-writes`, and section 9.3 tests the MCP package with the flag on and off. The package therefore needs that option.
  - Section 8.2 has the MCP server report version and commit "in its implementation info", which is a second input.
  - The point of the sentence is "no database pool, no store, no server configuration". That point stands, but the literal claim is false.
- Axes: objective; remedy determinate. Reword it as "takes an API client and options; nothing that reaches the database or server configuration".

**R8** · requirements trace (internal consistency) · section 9.4, "These tests add one more package that starts a PostgreSQL container … The MCP and CLI tests can share one test binary to keep that to one container."
- Claim: Section 8.1's layout puts the two suites in different packages, which means different test binaries and two containers.
- Evidence:
  - The CLI-against-server tests use `run(args, …)` from `cmd/cvert` (section 9.2).
  - The MCP-against-server tests connect an SDK client "in memory to the MCP server" (section 9.3), naturally in `internal/mcpserver`. The `cvert mcp` stdio test builds `cmd/cvert`.
  - `internal/testutil` starts one container per test binary (project CLAUDE.md), so two packages calling `NewTestDB` cost two containers.
- Axes: objective; remedy determinate. Either name the single package that holds both suites, with `internal/mcpserver` tested only from `cmd/cvert`, or say two containers.

**R9** · simplicity and proportionality · section 5.3, "`--output table` prints fixed columns for a person at a terminal. It is not a stable interface; scripts use JSON."
- Claim: Table output is a current cost that no stated user pays for.
- Evidence:
  - Section 1 names the CLI's users as "scripts on a timer" that "read its JSON output with `jq`".
  - Section 11's acceptance criteria are all script and agent criteria.
  - Table output adds six column layouts, a control-character sanitiser with its own security rationale, and tests for each layout. The design calls the result unstable.
  - A person at a terminal has `jq` already, since that is the design's own tool.
  - Adding `--output table` later is a non-breaking change, because JSON is the default, so deferring it closes off nothing.
- Axes: contestable (the source requirement may ask for human output; it is unpinned); remedy a choice (defer, or keep with a requirement cited).

**R10** · simplicity and proportionality · section 6.1, "`trivy` | A Trivy JSON report. | One item per distinct package".
- Claim: The Trivy reader is the largest client-side component with no requirement named in the document, and the document's own acceptance criterion handles scanner output with `jq` instead.
- Evidence:
  - It needs a subpackage (`internal/apiclient/trivy/`), golden fixtures captured from a real Trivy version, a two-source fallback (`Packages` or `Vulnerabilities`) with a warning path, deb source-package substitution with epoch handling, and an unresolved verification task ("The field names above come from Trivy's report type, not from a captured report").
  - Section 11's scanner case is "replace a watchlist's CVE items from a scanner report" through `jq`, and section 5.2's `--cves` input exists for that same `jq -r` shape.
  - What counts in its favour, and keeps this finding contestable: the `deb` source-package substitution is domain logic that a hand-written `jq` filter would usually get wrong, and getting it wrong yields `distro_package_not_found` (section 6.1).
- Axes: contestable; remedy a choice. Cite the requirement that pays for the reader, or defer it to its own pull request after the core client.

**R11** · requirements trace (internal consistency) · section 1, "MCP-1, an MCP server … the same reads as tools".
- Claim: The MCP reads are a narrower set than the CLI reads, and the goal statement does not say so.
- Evidence:
  - There is no tool for `cves sources` (section 5.2 versus section 7.2).
  - `search_advisories` has no `date_to`, `cvss_max`, `epss_max` or `exploit_available` filter, although its result carries `exploit_available`.
  - The narrowing may be deliberate ("narrow input schemas"), but section 1 states parity.
- Axes: objective that the text disagrees with itself; contestable whether the narrowing matters. Remedy determinate: say "a subset of the reads".

## Per-lens lines

- Requirements trace: S1 (standing: requirements completeness unverifiable — unpinned), R1, R2, R3, R4, R5, R6, R7, R8, R11.
- Simplicity and proportionality: R2, R6, R9, R10. No other element's complexity was found unpaid. These were checked and excluded:
  - the 422 and 503 split rules, which the server's behaviour pays for;
  - `depguard` together with the CI build without `web/dist`, both cheap, and they enforce the `go install` decision;
  - the deferred streamable HTTP sketch, which costs nothing now;
  - `CVERT_WEB_URL`, the split of exit codes 4 and 5, and `--max-wait`, each small and justified in the text.
