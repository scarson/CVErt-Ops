# Round 2 review: change and reversibility

Document: `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` (read at worktree HEAD `b493321`).
Lens: change & reversibility. Requirements pinning: UNPINNED.

Scope note: the design adds no schema and no stored server-side data, so there is no data migration to assess. The findings below concern clients deployed apart from the server, state that scripts persist, existing users of the shared rate budget, and contracts that later changes would break.

## Findings, most severe first

### R1. Version skew is the normal deployment state, and neither side reports a version that could diagnose it

- **Lens:** change & reversibility (existing callers after a server change).
- **Doc anchor:** §5.6 Compatibility, "Nothing in this design detects version skew."; §8.2, "Version and commit set by the same ldflags as the server; `cvert --version` prints them"; §3, "`go install github.com/scarson/cvert-ops/cmd/cvert@<version>` works".
- **Claim:** §5.6 treats skew as an edge case, but the decision in §3 creates it. Its main reason for a separate binary is that agent hosts install the client with `go install`, apart from the server. The client and server then drift as a matter of course. The design states that skew goes undetected. It does not show that skew can be diagnosed afterwards, and it cannot be: no build path sets a version.
- **Evidence:**
  - `cmd/cvert-ops/main.go:62-64` defines `version = "dev"`, set only by `-X main.version=...`. `docker/Dockerfile` lines 38 and 46 build with `-ldflags="-s -w"` only, and `.github/workflows/ci.yml` passes no `-X` flags (grep for `main.version`/`ldflags` returns nothing). So "the same ldflags as the server" set no version. `go install` applies no ldflags at all. On every distribution path, `cvert --version` and the MCP implementation info would print `dev`.
  - §10's exact need for `whoami` lists org, key, tier and rate-limit fields, but no server version or commit. `whoami` is called once per process, so it would be the cheapest place to compare versions. It has not been built yet (AUTH-5), so adding a field now is cheaper than a second API change later.
  - §5.6 says a renamed field "shows up as a missing value and not as an error". §7.4 says "Null and empty fields are omitted". For the MCP results, a server-side rename of, say, `fixed_version` or `fix_ecosystem` therefore removes the key from the agent's result. That looks the same as "the server has no value", which for a fix version means "no fix". The §7.3 description tests catch new status or reason values only in the client's own commit. An installed `cvert mcp` describes the old set and gives no signal that a new value exists.
  - Probe (proxy resolution): `go list -m -json github.com/scarson/cvert-ops@latest` resolves to `v0.0.0-20260510080726-74ab7227a4d8` (2026-05-10). The repository has no release tags, so a `go install ...@latest` gets a months-old default-branch pseudo-version. The `@<version>` in §3 names a version scheme that does not exist yet.
- **Axes:** objective (no version is stamped anywhere; the result-shaping rule turns a rename into silent omission). Remedy is a choice: stamp versions (`-X` in the Dockerfile and CI, `debug.ReadBuildInfo` for `go install` builds), add a server version to the `whoami` need, and decide whether a mismatch warns or fails.

### R2. The new clients spend a rate budget that existing web UI users share, and one designed command cannot finish within its own default budget

- **Lens:** change & reversibility (existing callers and users).
- **Doc anchor:** §2 row 4, "Every client request counts against a budget shared with the web UI and other keys."; §5.2, "`watchlists items list <watchlist-id> [--all]`"; §5.2, "`--all` ... stops with an error above 10,000 items"; §5.5, "`--max-wait` sets the budget for the whole command, default 2 minutes."
- **Claim:** The design notes that the budget is shared, but not what that means for existing users. Every org-scoped CLI run on a timer takes tokens from the same per-org bucket the web UI uses. Serializing requests does not reduce how many are sent. A large `--all` or a multi-item `add` empties the bucket, and logged-in users of that org get 429s for a minute or more. The design does not state this or offer a mitigation, such as a per-key bucket on the server or a request cap in the client.
- **Evidence:**
  - `internal/api/middleware_tier.go:48-70`: `orgRateLimitMiddleware` keys `srv.orgRL.Allow(orgID, ...)` by org only. It does not separate session users from API keys.
  - `internal/api/watchlists.go:717`: `const limit = 50` for watchlist items, a fixed page size. A list at the 10,000-item ceiling that §5.2 allows for `--all` (and that `items replace` creates) takes 200 page requests. On the free tier (60 per minute, burst 10, `Retry-After: 60`), that is about 3.3 minutes, longer than the 2-minute default `--max-wait`. The command exits 6 after holding the org's bucket empty for 2 minutes, and the web UI is throttled the whole time.
  - `watchlists items add` with N flags sends N requests in sequence (§5.2). Eleven items empty the burst.
  - `whoami` adds one request per invocation if it is inside the limiter (§10 says this is undecided).
- **Axes:** objective (the arithmetic follows from the cited constants). Remedy is a choice: a per-key bucket, lowering the `--all` ceiling for org-scoped lists, a request-count cap per invocation, or documenting the effect on web users in `docs/client.md`.

### R3. Pollers persist a server-issued cursor across server upgrades, with no stability requirement and no stated recovery

- **Lens:** change & reversibility (persisted state, migration path).
- **Doc anchor:** §11, "poll alert events with a stored cursor"; §10 FEED-1 row, "a cursor returned on every page that holds items, including the last, so a poller can store it and resume after the last event it saw."
- **Claim:** The only durable client state in the design is the alert-event cursor that each timer script stores between runs. This state outlives server upgrades. The FEED-1 need does not require cursors to stay valid across server versions. The design also does not say what happens when a stored cursor is rejected. A rejected cursor returns 400, which is exit 8, the same code as every other rejected request (§5.4). The script cannot tell "your cursor is stale" from a bad flag. The operator then has two recovery choices, neither stated: restart from now and miss events, or restart from the beginning and replay every event.
- **Evidence:**
  - Cursors today are unversioned base64url JSON (`internal/api/contract.go:162-188`, `encodePageCursor`/`decodePageCursor`; `alertEventCursor{T, ID}` in `internal/api/alert_events.go:27-30`). A malformed one gets `400 "invalid cursor"` (`alert_events.go:71-79`).
  - The server has already changed its cursor encoding once: `decodePageCursor` "Falls back to padded URLEncoding for cursors issued before the encoding was standardized" (`contract.go:173-174`). Cursor formats do change in this codebase.
  - FEED-1 is being designed now in a parallel session, so a stability requirement can still be added to §10 at no cost.
- **Axes:** contestable (one could argue FEED-1 owns this). Remedy is a choice: require cursor format stability, or a typed problem such as `urn:cvert:error:cursor_invalid` with its own exit code, plus a documented re-baseline procedure in `docs/client.md`.

### R4. `--enable-writes` is one switch, so future write tools join it on a client upgrade with no host-configuration change

- **Lens:** change & reversibility (blast radius of a later change).
- **Doc anchor:** §7.2, "Write tools are registered only with `cvert mcp --enable-writes`"; §12 item 5, "write tools behind `--enable-writes` limited to adding and removing one watchlist item"; §1, the `annotate` tool, `set_finding_state` and `list_findings` named as out of scope only for now.
- **Claim:** The flag is all-or-nothing. A host that sets `--enable-writes` today agrees to add and remove one watchlist item. When a later release adds a write tool (the requirement already names `annotate`, pending INV-4, and the dropped findings tools), the next `go install` offers the agent that tool too. Nobody re-approves the host configuration. The design does not say how the write set grows, or whether a new write tool needs its own opt-in. The key's role remains the server-side limit, but the flag's stated purpose is to narrow "what the agent is offered", and that narrowing would erode silently.
- **Evidence:** §7.2 defines the flag only by today's two tools. No section addresses adding write tools.
- **Axes:** contestable (it is a policy choice). Remedy is a choice: a per-tool allowlist (`--enable-writes=add_watchlist_item,remove_watchlist_item`), or a stated rule that every new write tool needs a new flag.

### R5. The guarantee "acts only through the HTTP API" is enforced only on direct imports, so a later refactor can erode it while every check still passes

- **Lens:** change & reversibility (future change to a shared package).
- **Doc anchor:** §7.1 item 1, "A `depguard` rule refuses, in the non-test files of `cmd/cvert`, the API client package and the MCP package, any import of `internal/store`, ..."; item 2, "A CI step builds `./cmd/cvert` in a checkout with no `web/dist`, which fails if anything it imports reaches `web`."
- **Claim:** depguard reads each matched file's own import declarations. It does not inspect the transitive import graph. If `internal/apiclient` later imports a shared helper package, for example a purl or ecosystem helper, and that helper gains an import of `internal/store` or pgx, no depguard rule fires. The no-`web/dist` build catches only `web`. §2 row 8 already gives an example of this transitive path: `internal/alert/dsl` imports `internal/store/generated`. The guarantee therefore holds for today's code but not against later changes elsewhere in the module.
- **Evidence:** The existing depguard rule in `.golangci.yml` (lines 27-35) is a file-scoped `deny` list of packages. That form only matches direct imports. The probe for the runner, without committing it: add a non-test import of a package that itself imports `internal/store` (for example `internal/alert/dsl`) to a file under `internal/apiclient`, then run `golangci-lint run --allow-parallel-runners ./internal/apiclient/...`. Expected result: no depguard finding.
- **Axes:** objective (how depguard matches imports). Remedy is close to determinate: a no-database test that runs `go list -deps ./cmd/cvert` (or uses `golang.org/x/tools/go/packages`) and fails on any denied package, alongside or in place of the depguard rule.

### R6. The MCP tool names, input schemas and result shapes have no compatibility statement

- **Lens:** change & reversibility (existing callers).
- **Doc anchor:** §5.6, "the JSON output and exit codes carry no compatibility promise until a release says otherwise; `docs/client.md` says so."
- **Claim:** §5.6 covers only the CLI's JSON output and exit codes. The MCP surface is a separate contract. Agent host configurations, agent skills and prompts name tools (`check_components`, `list_alert_events`) and rely on result fields (`advisories_truncated`, `unanswered`). The design does not say whether that contract is unstable as well, or how a rename or a removed field would be announced. §12 asks Sam to approve "an MCP tool set" as a new public surface, but no reversal terms are attached.
- **Evidence:** No section mentions MCP surface compatibility. §8.3's `docs/client.md` contents list exit codes and configuration but not the tool contract.
- **Axes:** objective (the statement is absent). Remedy is close to determinate: extend §5.6's statement to the MCP tool set.

### R7. Decision 1 is approved before its deciding fact is verified, and no fallback is stated

- **Lens:** change & reversibility (back-out of the core choice).
- **Doc anchor:** §3, "The deciding facts are `go install` and the size of what an agent host has to run. Whether `go install` from the proxy works for this module ... is untested; the plan's first task verifies it against a pushed branch."
- **Claim:** The design asks for approval of the separate binary (§12 item 1) on a fact it has not checked. If the check fails, the plan's first task finds out after approval, and the design gives no fallback. The only remaining argument would be the size of what an agent host runs.
- **Evidence:** My probes settle most of the open question. The repository is public (`gh repo view scarson/CVErt-Ops --json visibility` returns `PUBLIC`). `go.mod` has no `replace` or `exclude` directives. The proxy resolves the lower-case module path (`go list -m -json github.com/scarson/cvert-ops@latest` succeeded, see R1). The remaining risk is small, but the doc still states no fallback, and its install line names a tagged `@<version>` that does not exist (R1).
- **Axes:** contestable (low severity now that the probes have run). Remedy is determinate: record the probe result in §3 and drop "untested", or state the fallback.

## Per-lens line

- change & reversibility: R1, R2, R3, R4, R5, R6, R7.
