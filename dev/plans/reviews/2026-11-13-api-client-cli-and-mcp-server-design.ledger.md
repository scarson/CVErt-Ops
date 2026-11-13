# Review ledger — 2026-11-13-api-client-cli-and-mcp-server-design.md

## Run 1 — 2026-11-13

### Run header (mutable — update at every phase transition)

- **Doc:** `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` · **baseline snapshot:** `c8f941d`
- **Mode:** full — **surface fired:** security; new boundary between trust-separated systems — **evidence:** section 7.1 puts an MCP server between an agent host (untrusted tool caller) and the API, holding the caller's key; section 5.1 handles the key.
- **Requirements:** unpinned — the design restates its requirements (section 1) from a private requirements document not in the repository; the session was started by another session, so the user was not asked. Requirements trace narrowed to internal consistency; standing entry P0-1 routes completeness to the gate.
- **Current phase:** 2
- **Rounds** (logical dispatch and prospective ordinal written BEFORE LAUNCH, completed at return):

| Round | Route (reviewer · slice · scope · shape · context · model+effort · prompts vN) | Snapshot | Roster | Status | Breaker evidence |
|---|---|---|---|---|---|
| 1 | Pilot — self-review (session), all lenses, whole doc | `c8f941d` | runner | complete — 13 raised (12 substantive, all fixed; 1 judged non-substantive) | ineligible — self-review · ordinal — |
| 2 | Fan-out — 6 members, all lenses in batches, whole doc, cold, prompts v4: extent batch, unstated assumptions, alternatives & rationale, change & reversibility, downstream readiness — dispatched subagents (Claude Opus 5.5, high); seam batch — cross-model (codex `gpt-6.1-sol`, high, read-only sandbox) | `(round-2 snapshot — filled after commit)` | 2a extent · 2b seam (cross-model) · 2c unstated assumptions · 2d alternatives & rationale · 2e change & reversibility · 2f downstream readiness | reserved as one concurrent group — dispatched → 0 of 6 returned | opening first independent round — exempt · backstop ordinals 1–6 (2a=1, 2b=2, 2c=3, 2d=4, 2e=5, 2f=6) |

- **Per-lens coverage** (one row per whole-doc round; cell = finding IDs or NSF):

| Round | requirements trace | unstated assumptions | alternatives & rationale | seams & contracts | failure modes | change & reversibility | downstream readiness | simplicity & proportionality |
|---|---|---|---|---|---|---|---|---|
| 1 | P0-1 (standing); internal consistency NSF | L5 | L8, L9, L10 | L1, L4 | L1, L2, L3, L4 | L11 | L3, L6, L7, L12 | L13 (non-substantive) |

- **Gate:** not posed
- **Breaker:** eligible after independently re-reviewed repair wave `not yet` · next backstop ordinal `7` · active trigger `none` · one-additional-read authorization `none` · in-flight `round 2 group: 2a–2f, ordinals 1–6`
- **Closure:** cold reader — pending · verifier — pending · pooled attempt `—` · live-vs-snapshot re-compare — pending
- Terminal state:

### Index (append-only rows; State cells edited in place)

| ID | Round | Lens(es) | Class | Disposition | State |
|---|---|---|---|---|---|
| P0-1 | P0 | requirements trace | genuine choice | confirmed | open — gate item |
| L1 | 1 | seams & contracts, failure modes | forced correction | confirmed | fixed |
| L2 | 1 | failure modes | forced correction | confirmed | fixed |
| L3 | 1 | failure modes, downstream readiness | forced correction | confirmed | fixed |
| L4 | 1 | seams & contracts, failure modes | forced correction | confirmed | fixed |
| L5 | 1 | unstated assumptions | documentary gap | confirmed | fixed |
| L6 | 1 | downstream readiness | forced correction | confirmed | fixed |
| L7 | 1 | downstream readiness | documentary gap | confirmed | fixed |
| L8 | 1 | alternatives & rationale | documentary gap | confirmed | fixed |
| L9 | 1 | alternatives & rationale | documentary gap | confirmed | fixed |
| L10 | 1 | alternatives & rationale | documentary gap | confirmed | fixed |
| L11 | 1 | change & reversibility | documentary gap | confirmed | fixed |
| L12 | 1 | downstream readiness | documentary gap | confirmed | fixed |
| L13 | 1 | simplicity & proportionality | — | judged non-substantive | closed |

### Detail — P0-1

- **Anchor:** 1. Goal and scope — "The requirements come from the private homelab integration requirements"
- **Claim:** Requirements completeness cannot be traced: the requirements are not pinned in the doc and the source is private and outside the repository. · **Evidence:** no requirements statement with a dated user confirmation; reviewers cannot read the source.
- **Axes:** objective · remedy choice · records
- **Source raw:** Phase 0 setup
- **Action:** route to the gate: Sam confirms that section 1 and section 12 cover CLI-1 and MCP-1 as amended, or names what is missing.

### Detail — L1

- **Anchor:** 6.3 Merged output — "`last_success_at` is the earliest value reported"
- **Claim:** A batch reporting `last_success_at: null` (never succeeded) has no "earliest" ordering; the merge rule could drop the null and report a success that one batch said never happened. · **Evidence:** `CheckFeedStatus.LastSuccessAt` is nullable ("null if never", `internal/api/check.go`).
- **Axes:** objective · remedy determinate · repairs
- **Source raw:** pilot
- **Action:** null wins over any time. · **taken:** rewritten · **Before:** "and `last_success_at` is the earliest value reported." · **After:** "and `last_success_at` is null if any batch reported null, and otherwise the earliest value reported."

### Detail — L2

- **Anchor:** 5.3 Output — "`--output table` prints fixed columns for a person at a terminal."
- **Claim:** Table output prints decoded string values (rule names written by org members, feed text) to a terminal; a control character such as ESC in a value becomes a terminal escape sequence. JSON output is safe because the server's encoder escapes control characters, but the table renderer decodes them back. · **Evidence:** the doc says nothing about sanitising table cells; rule and watchlist names are user-supplied.
- **Axes:** objective · remedy determinate · repairs
- **Source raw:** pilot
- **Action:** table cells replace control characters. · **taken:** sentence added to the table paragraph · **Before:** "It is not a stable interface; scripts use JSON." · **After:** "It is not a stable interface; scripts use JSON. Table cells replace every control character with `?`, because values such as rule names are written by org members and a raw escape sequence would act on the terminal."

### Detail — L3

- **Anchor:** 5.2 Commands — "Repeatable flags; one request each, sequentially."
- **Claim:** `watchlists items add` and `items remove` with several items have no stated behaviour when a request fails midway (403, 409 duplicate, 429 past budget): which items were applied, what is printed, which exit code. · **Evidence:** the server returns 409 "item already exists in watchlist" (`internal/api/watchlists.go` line 614); the doc is silent.
- **Axes:** objective · remedy determinate · repairs
- **Source raw:** pilot
- **Action:** stop at the first failure, print what was applied, exit with that failure's code; point idempotent callers at `replace`. · **taken:** sentence added to the `items add` row and a reference in the `items remove` row.

### Detail — L4

- **Anchor:** 7.5 Limits inside a tool call — "Tool calls follow section 5.5 with a budget of 5 seconds"
- **Claim:** MCP hosts may send concurrent tool calls. The doc says requests are never sent in parallel (section 5.5) but does not say how the MCP server enforces that across concurrent calls, so a plan author would have to invent it, and parallel calls would collide on the single check slot and the shared rate bucket. · **Evidence:** section 5.5 rationale; MCP allows concurrent requests.
- **Axes:** objective · remedy determinate (follows from section 5.5's rationale) · repairs
- **Source raw:** pilot
- **Action:** one API request at a time per MCP process; waiting for the turn is not counted in the 5-second retry budget. · **taken:** sentence added to section 7.5.

### Detail — L5

- **Anchor:** 7.2 Tools — "`modified_since`"
- **Claim:** `modified_since` (and the CLI's `--date-from`) filters on `date_modified_canonical`, which moves only when the CVE's material hash changes. An agent reading "modified" as "any update" would miss CVEs whose EPSS or ranges changed. · **Evidence:** `internal/merge/pipeline.go` line 178 ("date_modified_canonical is only bumped when material_hash changes").
- **Axes:** objective · remedy determinate · records — **source:** repo `internal/merge/pipeline.go`
- **Source raw:** pilot
- **Action:** add to the units bullet of section 7.3. · **taken:** bullet extended; field list corrected at write time after checking `internal/merge/hash.go` `MaterialFields` (status, severity, CVSS scores and vectors, CWE IDs, exploit and KEV flags, affected packages, affected CPEs; no description, no EPSS, no CPE match ranges or CNA data) · **After:** "`modified_since` compares the date of the CVE's last material change: its status, severity, CVSS, CWEs, KEV or exploit flag, affected packages or affected CPEs. A change to EPSS, the description, NVD's CPE version ranges or the CNA's product data alone does not move it."

### Detail — L6

- **Anchor:** 5.2 Commands — "`--package ECO/NAME`"
- **Claim:** Package names contain `/` (npm scopes, Go modules); the split rule is not stated. · **Evidence:** no OSV ecosystem name in `internal/ecosystem/ecosystem.go` contains `/`, so splitting at the first `/` is unambiguous; some contain spaces (`Red Hat`).
- **Axes:** objective · remedy determinate · repairs
- **Source raw:** pilot
- **Action:** state the split. · **taken:** clause added to the `items add` row.

### Detail — L7

- **Anchor:** 7.2 Tools — "`min_cvss`"
- **Claim:** Which CVSS version `min_cvss` compares is unstated; the endpoint compares the v4 score when present, else v3. An agent would assume v3. · **Evidence:** `internal/store/cve.go` line 164 (`COALESCE(cves.cvss_v4_score, cves.cvss_v3_score) >= ?`).
- **Axes:** objective · remedy determinate · records — **source:** repo `internal/store/cve.go`
- **Source raw:** pilot
- **Action:** add to the units bullet of section 7.3. · **taken:** bullet extended.

### Detail — L8

- **Anchor:** 5.4 Exit codes — "`check` exits 0 whatever the statuses of its items"
- **Claim:** The rejected alternative (a flag that fails the command when an item is affected) is not recorded, so a maintainer cannot tell whether it was weighed. · **Evidence:** section 5.4 states the choice without the alternative.
- **Axes:** objective · remedy determinate · records — **source:** session (the author weighed `--fail-on` while writing section 5.4)
- **Source raw:** pilot
- **Action:** record it. · **taken:** sentence rewritten.

### Detail — L9

- **Anchor:** 5.2 Commands — "`--all` follows `next_cursor` until the server returns none, and prints one envelope"
- **Claim:** The rejected alternative of one JSON object per line (NDJSON) is not recorded. · **Evidence:** section 5.2.
- **Axes:** objective · remedy determinate · records — **source:** session
- **Source raw:** pilot
- **Action:** record it in one clause. · **taken:** sentence added.

### Detail — L10

- **Anchor:** 5.1 Configuration — "Not configured. A key belongs to one org"
- **Claim:** The reason for not offering `CVERT_ORG_ID` (it saves one request per invocation) is stated only in section 12 as a decision, without why the saving is not worth it. · **Evidence:** sections 5.1 and 12.
- **Axes:** objective · remedy determinate · records — **source:** session
- **Source raw:** pilot
- **Action:** add the reason to the table cell. · **taken:** cell rewritten.

### Detail — L11

- **Anchor:** 5.3 Output, 5.4 Exit codes
- **Claim:** JSON output and exit codes become an interface for scripts, but compatibility and client/server version skew are unstated: a client built from one commit calling a server built from another. · **Evidence:** the spec conformance test (section 9.1) checks the client against the spec of its own commit only. CLAUDE.md: the application has no users besides dev testers, so no compatibility promise is owed yet.
- **Axes:** objective · remedy determinate · records — **source:** repo `CLAUDE.md` (development status)
- **Source raw:** pilot
- **Action:** add a short subsection 5.6. · **taken:** subsection added; its skew sentence corrected in the wave re-read (a renamed field decodes as a missing value, not an error) · **After:** "### 5.6 Compatibility — ... may send a parameter the server no longer accepts, which the server rejects (exit 8), or read a field the server has renamed, which shows up as a missing value and not as an error. Nothing in this design detects version skew."

### Detail — L12

- **Anchor:** 5.2 Commands — "`events list [--after CURSOR] [--rule ID] [--cve ID] [--open]`"
- **Claim:** `--open` and `open_only` do not say which API parameter they map to. · **Evidence:** the endpoint's filter is `last_match_state` (`internal/api/alert_events.go`).
- **Axes:** objective · remedy determinate · records — **source:** repo `internal/api/alert_events.go`
- **Source raw:** pilot
- **Action:** name the parameter. · **taken:** clause added to the `events list` row.

### Detail — L13

- **Anchor:** 5.1 Configuration — "`CVERT_WEB_URL`"
- **Claim:** A setting only used when the SPA is served from a different origin than the API might be unrequested.
- **Disposition:** judged non-substantive — it is one optional variable with a default, and without it every link is wrong under the Vite dev server, which developers use daily.
- **Source raw:** pilot
