# Review ledger — 2026-11-13-api-client-cli-and-mcp-server-design.md

## Run 1 — 2026-11-13

### Run header (mutable — update at every phase transition)

- **Doc:** `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` · **baseline snapshot:** `c8f941d`
- **Mode:** full — **surface fired:** security; new boundary between trust-separated systems — **evidence:** section 7.1 puts an MCP server between an agent host (untrusted tool caller) and the API, holding the caller's key; section 5.1 handles the key.
- **Requirements:** unpinned — the design restates its requirements (section 1) from a private requirements document not in the repository; the session was started by another session, so the user was not asked. Requirements trace narrowed to internal consistency; standing entry P0-1 routes completeness to the gate.
- **Current phase:** 4 (gate posed). On resume: record Sam's answers, fold them, run the Phase 5 re-sweep check against `b493321`, then closure (cold reader + ledger verifier on one snapshot).
- **Rounds** (logical dispatch and prospective ordinal written BEFORE LAUNCH, completed at return):

| Round | Route (reviewer · slice · scope · shape · context · model+effort · prompts vN) | Snapshot | Roster | Status | Breaker evidence |
|---|---|---|---|---|---|
| 1 | Pilot — self-review (session), all lenses, whole doc | `c8f941d` | runner | complete — 13 raised (12 substantive, all fixed; 1 judged non-substantive) | ineligible — self-review · ordinal — |
| 2 | Fan-out — 6 members, all lenses in batches, whole doc, cold, prompts v4: extent batch, unstated assumptions, alternatives & rationale, change & reversibility, downstream readiness — dispatched subagents (Claude Opus 5.5, high); seam batch — cross-model (codex `gpt-6.1-sol`, high, read-only sandbox) | `b493321` | 2a extent · 2b seam (cross-model) · 2c unstated assumptions · 2d alternatives & rationale · 2e change & reversibility · 2f downstream readiness | complete — 6 of 6 returned (codex exit 0, report complete with per-lens lines); 73 raw findings → 39 ledger rows (35 substantive: 27 fixed, 8 escalated; 4 other) | opening first independent round — exempt · grouped as-raised substantive 35 · previous-wave repairs judged defective / independently reviewed: n/a (pilot wave not separately re-reviewed by a qualifying round) · review-record substantive / total substantive 0/35 · backstop ordinals 1–6 · evaluation: exempt |
| 2w | Repair-wave integration read — dispatched subagent (Claude Opus 5.5, high), wave diff vs `b493321` + whole doc, elective, not a lens round | working tree after round-2 fixes | 1 agent | complete — 14 defects (W1–W14), all fixed | elective — not qualifying · ordinal — |
| 3 | Gate — posed 2026-11-13: 15 items (section 12 of the doc); user not reachable from this session | — | — | stopped awaiting user | — |

- **Per-lens coverage** (one row per whole-doc round; cell = finding IDs or NSF):

| Round | requirements trace | unstated assumptions | alternatives & rationale | seams & contracts | failure modes | change & reversibility | downstream readiness | simplicity & proportionality |
|---|---|---|---|---|---|---|---|---|
| 1 | P0-1 (standing); internal consistency NSF | L5 | L8, L9, L10 | L1, L4 | L1, L2, L3, L4 | L11 | L3, L6, L7, L12 | L13 (non-substantive) |
| 2 | F4, F5, F8, F17, F18, F19, F20, F21, F30; standing finding F38 (duplicate of P0-1) | F1, F2, F3, F4, F6, F11, F13, F14, F16, F17, F23, F26, F36, F37 | F14, F21, F23, F24, F25, F26, F27, F28, F29 | F4, F5, F6, F7, F8, F12 | F4, F5, F6, F7, F8 | F13, F14, F30, F31, F32, F33 | F1, F2, F3, F4, F5, F6, F9, F10, F11, F12, F13, F15, F17, F23, F34, F35 | F21, F22, F23, F30 |

- **Gate:** posed 2026-11-13 — the batched list is section 12 of the doc (15 items): rows P0-1, F1, F21 (with F28), F24, F25, F26, F30, F32, F35, plus the design's original decisions (binary, client code, MCP SDK, streamable HTTP, tool set, no org setting, PLAN.md). Gate basis: round 2 yielded 35 substantive, all dispositioned; the integration read added 14 forced corrections and no new escalations.
- **Breaker:** eligible after independently re-reviewed repair wave `not yet` · next backstop ordinal `7` · active trigger `none` · one-additional-read authorization `none` · in-flight `none`
- **Closure:** cold reader — not dispatched · verifier — not dispatched · pooled attempt `—` · live-vs-snapshot re-compare — pending
- **Round table** (derived from the index rows):

| Round | Route | Raised | Substantive | Fixed | Escalated | Other | Open |
|---|---|---|---|---|---|---|---|
| 1 | Pilot — self-review (session), all lenses, whole doc | 13 | 12 | 12 | 0 | 1 | 0 |
| 2 | Fan-out — 6 members, cold, prompts v4: 5 dispatched subagents (Claude Opus 5.5, high) + seam batch cross-model (codex `gpt-6.1-sol`, high) | 39 | 35 | 27 | 8 | 4 | 8 |
| 2w | Repair-wave integration read — dispatched subagent (Claude Opus 5.5, high), elective [^w] | 14 | 14 | 14 | 0 | 0 | 8 |
| 3 | Gate — posed, 15 items; stopped awaiting user [^g] | — | — | — | — | — | 8 |

[^w]: Repair-wave discipline rule 4 (wave above ten fixes). Elective: counts toward no gate timing, coverage or breaker evidence. [^g]: The 8 open rows plus the phase-minted P0-1 are in the gate list with the original design decisions.

- Terminal state: stopped awaiting user (2026-11-13) — the gate (section 12 of the doc) awaits Sam's answers; this session was started by another session and cannot reach him. Rows X1–X3 (post-gate merge of `dev`) are unreviewed and fall to the resumed run's re-sweep check and closure legs.

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
| F1 | 2 | unstated assumptions, downstream readiness | forced correction + genuine choice | confirmed | false claim fixed; server audit change — gate |
| F2 | 2 | unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| F3 | 2 | unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| F4 | 2 | requirements trace, seams & contracts, failure modes, unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| F5 | 2 | requirements trace, seams & contracts, failure modes, downstream readiness | forced correction | confirmed | fixed |
| F6 | 2 | seams & contracts, failure modes, unstated assumptions | forced correction | confirmed | fixed |
| F7 | 2 | seams & contracts, failure modes | forced correction | confirmed | fixed |
| F8 | 2 | requirements trace, seams & contracts, failure modes | forced correction | confirmed | fixed |
| F9 | 2 | downstream readiness | forced correction | confirmed | fixed |
| F10 | 2 | downstream readiness | forced correction | confirmed | fixed |
| F11 | 2 | unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| F12 | 2 | seams & contracts, downstream readiness | forced correction | confirmed | fixed |
| F13 | 2 | change & reversibility, unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| F14 | 2 | alternatives & rationale, change & reversibility, unstated assumptions | forced correction | confirmed | fixed |
| F15 | 2 | downstream readiness | forced correction | confirmed | fixed |
| F16 | 2 | unstated assumptions | forced correction | confirmed | fixed |
| F17 | 2 | requirements trace, unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| F18 | 2 | requirements trace | forced correction | confirmed | fixed |
| F19 | 2 | requirements trace | forced correction | confirmed | fixed |
| F20 | 2 | requirements trace | forced correction | confirmed | fixed |
| F21 | 2 | requirements trace, simplicity & proportionality, alternatives & rationale | genuine choice | confirmed | open — gate |
| F22 | 2 | simplicity & proportionality | documentary gap | false positive (requirement names it); scope line added | fixed |
| F23 | 2 | simplicity & proportionality, alternatives & rationale, unstated assumptions, downstream readiness | forced correction + documentary gap | confirmed | fixed |
| F24 | 2 | alternatives & rationale | genuine choice | confirmed | open — gate |
| F25 | 2 | alternatives & rationale | genuine choice | confirmed | open — gate |
| F26 | 2 | alternatives & rationale, unstated assumptions | forced correction + genuine choice | confirmed | proxy 503 fixed; CA file — gate |
| F27 | 2 | alternatives & rationale | forced correction + documentary gap | confirmed | fixed; decision 2 stays a gate item |
| F28 | 2 | alternatives & rationale | genuine choice | duplicate of F21 (merged) | open — gate via F21 |
| F29 | 2 | alternatives & rationale | forced correction + documentary gap | confirmed | fixed |
| F30 | 2 | requirements trace, simplicity & proportionality, change & reversibility, unstated assumptions | genuine choice | confirmed | open — gate |
| F31 | 2 | change & reversibility | forced correction | confirmed | fixed |
| F32 | 2 | change & reversibility | genuine choice | confirmed | open — gate |
| F33 | 2 | change & reversibility | forced correction | confirmed | fixed |
| F34 | 2 | downstream readiness | forced correction | confirmed | fixed |
| F35 | 2 | downstream readiness | genuine choice | confirmed | open — gate |
| F36 | 2 | unstated assumptions | documentary gap | confirmed | fixed |
| F37 | 2 | unstated assumptions | documentary gap | confirmed | fixed |
| F38 | 2 | requirements trace | — | duplicate of P0-1 | closed |
| F39 | 2 | requirements trace, simplicity & proportionality | — | duplicate of F4 (merged) | closed |
| W1 | 2w | repair integration | forced correction | confirmed | fixed |
| W2 | 2w | repair integration | forced correction | confirmed | fixed |
| W3 | 2w | repair integration | forced correction | confirmed | fixed |
| W4 | 2w | repair integration | forced correction | confirmed | fixed |
| W5 | 2w | repair integration | forced correction | confirmed | fixed |
| W6 | 2w | repair integration | forced correction | confirmed | fixed |
| W7 | 2w | repair integration | forced correction | confirmed | fixed |
| W8 | 2w | repair integration | forced correction | confirmed | fixed |
| W9 | 2w | repair integration | forced correction | confirmed | fixed |
| W10 | 2w | repair integration | forced correction | confirmed | fixed |
| W11 | 2w | repair integration | forced correction | confirmed | fixed |
| W12 | 2w | repair integration | forced correction | confirmed | fixed |
| W13 | 2w | repair integration | forced correction | confirmed | fixed |
| W14 | 2w | repair integration | forced correction | confirmed | fixed |
| X1 | M | requirements trace, downstream readiness | documentary gap | confirmed | fixed |
| X2 | M | requirements trace, downstream readiness | documentary gap | confirmed | fixed |
| X3 | M | downstream readiness | documentary gap | confirmed | fixed |

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

Round 2 raw reports: `round-2-extent.md` (extent), `round-2-seam.md` (seam, cross-model), `round-2-assumptions.md` (assumptions), `round-2-alternatives.md` (alternatives), `round-2-change.md` (change), `round-2-readiness.md` (readiness). Each detail names the raw IDs it merges.

### Detail — F1

- **Anchor:** 7.1 — "A write made through a tool is audited with the key's `api_key_id`"; also 9.3, 11.
- **Claim:** False today: `createWatchlistItemHandler` and `deleteWatchlistItemHandler` write no audit row. Verified: `auditLog` calls in `internal/api/watchlists.go` are at lines 256, 307, 515, 559, 691 only (tier refusal, watchlist create, update, delete, replace).
- **Raw:** assumptions R1, readiness R1. **Axes:** objective · remedy choice.
- **Action:** (a) forced: rewrite 7.1, 9.3 and 11 to state the truth and make the audit assertion conditional on the server change; (b) gate: add audit entries to item add and delete (server change) or accept unaudited item writes.

### Detail — F2

- **Anchor:** 7.2 — "The schemas are generated by the SDK from Go input structs, so the struct tags are their single source."
- **Claim:** `jsonschema-go` v0.4.3 reads only a `jsonschema` tag, as the description (`infer.go` lines 79–81, 329–336); enums, bounds, patterns and one-of cannot come from tags.
- **Raw:** assumptions R2, readiness R3. **Axes:** objective · determinate (the SDK accepts an explicit `Tool.InputSchema`; `go-sdk` v1.8.0 `server.go` line 319 infers only when it is nil — verified).
- **Action:** rewrite: build each schema in code from the inferred schema of the input struct, add constraints in code, test that out-of-range input is refused.

### Detail — F3

- **Anchor:** 9.1 spec conformance; 5.2 `--cvss-min`...; 7.2 `min_cvss`, `min_epss`.
- **Claim:** `cvss_min`, `cvss_max`, `epss_min`, `epss_max` are parsed from the raw query (`internal/api/cves.go` lines 262–267, no `query:` tag) and absent from `openapi.json` (verified: zero matches). The conformance test would fail, and the served spec is incomplete, which API-1 requires it not to be.
- **Raw:** assumptions R3, readiness R4. **Axes:** objective · determinate (the spec must describe the API).
- **Action:** add to PR 1: document the four parameters in the server's spec; the conformance test needs no exemption.

### Detail — F4

- **Anchor:** 6.2 Batches; 5.5; 7.5.
- **Claim:** Undefined branches: a multi-item half that times out twice; whether 422 and 503 splits compose; a later batch failing after earlier ones succeeded (401/403/429/5xx/network); exit 6 versus 9 precedence; the MCP queue has no bound, no cancellation rule and no total deadline; a timeout split can hold one tool call about 90 s, against 7.5's own reason for not waiting on 429.
- **Raw:** extent R2 (part), extent R5, seam R4, seam R5, assumptions R9, assumptions R10, readiness R5, readiness R9. **Axes:** objective · remedy follows from the doc's own rules (print what was answered; never resend a batch whole after a timeout; one request at a time).
- **Action:** rewrite 6.2 steps 4–5 and add a failure rule; rewrite 7.5: FIFO lane, cancellation leaves the queue and never sends, `check_components` does not split on timeout, every tool call has a 60-second total deadline.

### Detail — F5

- **Anchor:** 5.2 — "prints one envelope `{"items": [...]}`"; 10 FEED-1 row.
- **Claim:** `events list --all` drops the cursor a poller must store; no bootstrap for a first poll; `--all` stop condition conflicts with a cursor on every non-empty page.
- **Raw:** extent R3, seam R3, readiness R6. **Axes:** objective · determinate for the envelope; bootstrap depends on FEED-1 and is stated as a need.
- **Action:** `events list` always prints `next_cursor` (with `--all`, the last cursor received; on an empty page, the `--after` value it was given); `--all` stops on an empty page; 10 states the bootstrap need.

### Detail — F6

- **Anchor:** 10 FEED-1 row.
- **Claim:** FEED-1 needs, as listed, do not require that late-committing events and reopened events are delivered. `first_fired_at DEFAULT now()` with a UUID tiebreak skips late commits (pitfall NOTIFY-20); `ReopenAlertEvent` changes an existing row behind the cursor.
- **Raw:** seam R1 (cross-model), assumptions R5. **Axes:** objective · determinate on this side (state the need).
- **Action:** add both to the FEED-1 row; leave a hand-over note for the parallel session in the shared notes folder.

### Detail — F7

- **Anchor:** 7.4 — "`matched_ranges` is left out; `get_advisory` has the ranges."
- **Claim:** `GET /cves/{id}` package ranges lack `last_affected` and the MCP shape drops `range_type`, so the fallback loses range meaning the check result carries.
- **Raw:** seam R2 (cross-model). **Axes:** objective · determinate.
- **Action:** keep up to 5 `matched_ranges` per advisory in `check_components`; `get_advisory` ranges include `range_type`, and the description says `last_affected` is not in the detail endpoint.

### Detail — F8

- **Anchor:** 7.4 `check_components` result; 7.3.
- **Claim:** Result drops per-item `data_complete`, `warnings` and `error`, which 7.3 tells the agent to read; lists `id`, which the input schema cannot set.
- **Raw:** extent R4, seam R6. **Axes:** objective · determinate.
- **Action:** add optional `id` to input items; keep `data_complete`, `warnings`, `error`; drift test covers `warnings` and `error.code` values.

### Detail — F9

- **Anchor:** 7.4 — "Null and empty fields are omitted."
- **Claim:** Drops the server's null-means-unknown (`in_cisa_kev`, `epss_score`) and makes false booleans ambiguous.
- **Raw:** readiness R7. **Axes:** objective · determinate.
- **Action:** rewrite: nullable fields keep null; booleans always present; only empty lists and absent optional strings are omitted.

### Detail — F10

- **Anchor:** 5.2, 5.4.
- **Claim:** Unspecified: stdout of multi-item `add`/`remove`; exit code past the 10,000-item `--all` cap (exit 2 says no request was sent); empty `check` input; `--file` format for `replace`; `--cves` normalisation.
- **Raw:** readiness R10, R11. **Axes:** objective · determinate.
- **Action:** state each.

### Detail — F11

- **Anchor:** 6.1, 6.3.
- **Claim:** `index` meaning for purls and Trivy input is unclear; `unanswered.problem` uses the problem title, which is always the HTTP status text (`contract.go`).
- **Raw:** assumptions R17, readiness R13. **Axes:** objective · determinate.
- **Action:** define `index` per input form; Trivy items carry Trivy's package ID as `id` when it fits; `problem` takes the problem `detail`.

### Detail — F12

- **Anchor:** 5.2 command table.
- **Claim:** Only `cves search` takes `--cursor`; `watchlists list` has neither `--cursor` nor `--all` though the server pages it at 20 (`watchlists.go` line 356).
- **Raw:** seam R7 (cross-model), readiness R14. **Axes:** objective · determinate.
- **Action:** every list command takes `--cursor` and `--all`.

### Detail — F13

- **Anchor:** 7.1 item 1.
- **Claim:** depguard checks direct imports only; `internal/alert/dsl` and `internal/ai` reach `internal/store/generated` transitively.
- **Raw:** change R5, assumptions R8, readiness R15. **Axes:** objective · determinate.
- **Action:** add a test over `go list -deps ./cmd/cvert` that fails on any denied package.

### Detail — F14

- **Anchor:** 3; 8.2 — "Version and commit set by the same ldflags as the server".
- **Claim:** No build sets those ldflags (Dockerfile and CI pass `-s -w` only); `go install` applies none; the repository has no tags, so `@<version>` names nothing; release binaries were not weighed.
- **Raw:** alternatives R4, R5; change R1, R7; assumptions R13. **Axes:** objective · determinate for the version source; release binaries recorded as out of scope.
- **Action:** version from `runtime/debug.ReadBuildInfo`, overridable by ldflags; 3 records the probe result (public repo, no `replace`, proxy resolves the lower-case path; reviewer change R7) and that installs name a commit or branch until releases exist; request server version from `whoami` (10); release binaries recorded as not built here.

### Detail — F15

- **Anchor:** 7.1 — "A 401 or 403 there ends the process".
- **Claim:** Network errors, 5xx, 429 and redirects at startup are undefined; pitfall ARCH-28 argues against exiting on unreachability.
- **Raw:** readiness R8. **Axes:** objective · determinate.
- **Action:** 401/403 exit; any other failure starts the server and retries `whoami` on the first tool call.

### Detail — F16

- **Anchor:** 5.4 — "403 means the key's role is wrong."
- **Claim:** 403 also results from a removed or deactivated membership of the key's creator; `whoami` built like `/cves` auth could pass while every org route returns 403.
- **Raw:** assumptions R7. **Axes:** objective · determinate.
- **Action:** reword; 10 asks that `whoami` apply the org membership check.

### Detail — F17

- **Anchor:** 9.
- **Claim:** One test binary is impossible with tests in two packages; harness omits `ServerDeps.AlertEvaluator` (dry-run returns 503 without it) and `AuditWriter` (async; must be flushed); exit-6 test races the token refill; acceptance criterion 2 names no test; client policy (redirect refusal, no cookie jar, bounded and drained bodies) is untested.
- **Raw:** extent R8, assumptions R15, R16, readiness R17, R18, R19. **Axes:** objective · determinate.
- **Action:** rewrite 9 accordingly.

### Detail — F18

- **Anchor:** 10 — "Everything else can be built before they land: … rule and watchlist requests … and the MCP read tools other than `whoami` and `list_alert_events`".
- **Claim:** Contradicts the same section's first row, section 1 and 7.1: every org-scoped request and MCP startup need `whoami`.
- **Raw:** extent R1. **Axes:** objective · determinate.
- **Action:** rewrite the paragraph and 13's first PR.

### Detail — F19

- **Anchor:** 7.1 — "Its constructor takes nothing else".
- **Claim:** The write-tool setting and version are also inputs.
- **Raw:** extent R7. **Action:** reword: no database, store or server configuration.

### Detail — F20

- **Anchor:** 1 — "the same reads as tools".
- **Claim:** The tools are a subset of the CLI's reads.
- **Raw:** extent R11. **Action:** reword to "most of the same reads".

### Detail — F21

- **Anchor:** 5.4 exit codes 3 and 8.
- **Claim:** Exit 3 on an empty list makes every quiet poll a failure under `set -e` or a systemd timer, against the doc's own `check` rationale (`jq -e`); `rules validate` invalid shares 8 with malformed requests. Both decisions lack rationale.
- **Raw:** extent R6, alternatives R2, alternatives R10 (merged from F28). **Axes:** contestable · choice.
- **Action:** gate. Interim text marks the codes as pending.

### Detail — F22

- **Anchor:** 5.3 `--output table`.
- **Claim:** Table output is unrequested.
- **Raw:** extent R9. **Disposition:** false positive: CLI-1 in the private requirements specifies `--output json|table`. The doc did not say so, which is a documentary gap. **Source:** session (task brief). **Action:** section 1 states that CLI-1 asks for JSON by default and a table option.

### Detail — F23

- **Anchor:** 6.1 Trivy.
- **Claim:** (a) proportionality and CycloneDX alternative unrecorded; (b) `SrcVersion` lacks the Debian revision, which Trivy keeps in `SrcRelease` (readiness R2, from Trivy's dpkg analyzer); (c) apk packages need the same source substitution; rpm purls are refused by the endpoint (`unsupported_purl_type`); (d) the binary purl's `epoch` qualifier must not survive substitution.
- **Raw:** extent R10, alternatives R9, assumptions R4, R14, readiness R2. **Axes:** (a) documentary — **source:** session (the task brief names Trivy reports as an input); (b)–(d) objective, determinate.
- **Action:** version = `[SrcEpoch:]SrcVersion[-SrcRelease]`; apk substitution; rpm and other types sent and answered `invalid`, counted on stderr; epoch qualifier replaced; record why Trivy and not CycloneDX.

### Detail — F24

- **Anchor:** 5.2 `items replace --cves`; `items add` 409; 11.
- **Claim:** `replace --cves` deletes any package or CPE item on the same watchlist (server removes items not in the request, `watchlists.go` line 93); `add` is not repeatable and `replace` is not a repeatable add; acceptance says "replace a watchlist's CVE items".
- **Raw:** alternatives R1, R8. **Axes:** objective defect · remedy choice.
- **Action:** gate.

### Detail — F25

- **Anchor:** 2 DSL row; 7.3.
- **Claim:** Only `accessor.go` imports the store; `FieldDescription` and `ExportFieldDescriptions()` (`field.go` 58–68) could move to a store-free package, giving the description a canonical source; the planned test checks field names only.
- **Raw:** alternatives R3. **Axes:** objective (alternative exists) · choice.
- **Action:** forced part: correct the 2 row's reason; gate: extract the catalog or keep hand-written text with a test over names, operators and enum values.

### Detail — F26

- **Anchor:** 5.1 `http://` refusal; 6.2 503 handling.
- **Claim:** (a) The default Caddy config issues from Caddy's local CA, so remote clients need a CA setting the design lacks; the compose-network path `http://app:8080` is refused; (b) a proxy's own 503 would be split as a check timeout.
- **Raw:** alternatives R6, assumptions R12. **Axes:** (a) contestable · choice; (b) objective · determinate.
- **Action:** (b) forced: split only on the server's problem response; state that remote use needs a TLS-terminating proxy. (a) gate.

### Detail — F27

- **Anchor:** 4.2 "Keeping in sync" row.
- **Claim:** (a) Names-only conformance is weaker than generated types; (b) a shared exported-types package is an unmentioned third option.
- **Raw:** alternatives R7. **Axes:** (a) objective · determinate (check types and enums too); (b) documentary — **source:** session.
- **Action:** widen the conformance test; add the third option to 4.2 with why it is not recommended; decision 2 stays at the gate.

### Detail — F29

- **Anchor:** 4.1 alternatives.
- **Claim:** "Both SDKs below" names one; the advisory comparison with `mcp-go` is unanswered.
- **Raw:** alternatives R11. **Action:** fix wording; record that the official SDK's parsing advisories are fixed in v1.4.1 and that `mcp-go` has its own parser, unaudited here.

### Detail — F30

- **Anchor:** 2 rate row; 5.5.
- **Claim:** One org bucket serves the web UI and every key; a client honouring `Retry-After: 60` gets about 10 requests a minute; `watchlists items list --all` at 10,000 items needs 200 requests and fails after holding the bucket empty, giving web users 429s.
- **Raw:** extent R2 (part), change R2, assumptions R6. **Axes:** objective · choice.
- **Action:** gate (client-side pacing from `whoami`'s rate, document only, or wait for per-key limits).

### Detail — F31

- **Anchor:** 10 FEED-1 row.
- **Claim:** A stored cursor must survive server upgrades or be refused distinctly; a stale cursor today gives 400, the same exit as any bad request.
- **Raw:** change R3. **Action:** add the need to 10.

### Detail — F32

- **Anchor:** 7.2 `--enable-writes`.
- **Claim:** A later release's new write tools would join an existing host's approval silently.
- **Raw:** change R4. **Axes:** contestable · choice. **Action:** gate.

### Detail — F33

- **Anchor:** 5.6.
- **Claim:** MCP tool names, schemas and results are a contract with no compatibility statement.
- **Raw:** change R6. **Action:** extend 5.6.

### Detail — F34

- **Anchor:** 7.4 `get_advisory`.
- **Claim:** Only references have a cap.
- **Raw:** readiness R12. **Action:** caps of 50 package ranges, 50 CPE matches and 20 CNA entries, each with an omitted count.

### Detail — F35

- **Anchor:** 7.3 untrusted text.
- **Claim:** Pitfall ARCH-13 strips markup and control characters before feed text reaches a model; the design only labels it.
- **Raw:** readiness R16. **Axes:** contestable · choice. **Action:** gate.

### Detail — F36

- **Anchor:** 2 check row.
- **Claim:** The single server-wide check slot is taken without a queue; one org's large check run can starve another org's MCP calls.
- **Raw:** assumptions R9. **Action:** record as a server property the clients cannot change.

### Detail — F37

- **Anchor:** 5.2 `--all`.
- **Claim:** `cves search --all` pages on `date_modified_canonical DESC`, so a CVE modified during the walk can be skipped.
- **Raw:** assumptions R11. **Action:** state the limitation.

### Round 2 repair wave — where each fix landed (taken)

Claim deltas swept by wording across the doc after the edits (grep for `ldflags`, `three tool`, `audited with`, `struct tags`, `Null and empty`, `nothing else`, `the same reads`, `one test binary`, `@<version>`, `exit 3`).

- F1: 2 (new row on unaudited item writes), 7.1 paragraph 1 rewritten, 9.3 and 11 audit assertions made conditional, 12 item 10.
- F2: 7.2 last paragraph rewritten (explicit `InputSchema`, constraints in code, refusal test); 9.1 "Input schemas" bullet. Evidence checked: `jsonschema-go` v0.4.3 `infer.go`, `go-sdk` v1.8.0 `server.go` line 319.
- F3: 2 (new row on the score filters), 13 item 1. Evidence: zero matches for `"cvss_min"` in `openapi.json`.
- F4: 6.2 steps 4–7 and the closing sentence; 7.5 rewritten (lane, cancellation, 60-second deadline, no timeout split in MCP); 8.1 `apiclient` row adds the lane; 9.3 concurrency test.
- F5: 5.2 paragraph after the table (`--all` stop condition, `events list` envelope); 5.3 `events list` sentence; 7.4 `list_alert_events` `next_after`; 10 FEED-1 bootstrap need.
- F6: 10 FEED-1 row (late commits, reopened events). Hand-over note written to the shared notes folder.
- F7: 7.3 `get_advisory` ranges bullet; 7.4 `get_advisory` (`range_type`) and `check_components` (`matched_ranges`, up to 5).
- F8: 7.2 `check_components` input (`id`); 7.4 result fields; 7.3 drift test covers `warnings`, `error.code`.
- F9: 7.4 first paragraph (nulls kept, booleans present).
- F10: 5.2 `add`, `remove`, `replace` rows; 5.4 exit 2 row; 6.1 `purls` row (empty input).
- F11: 6.1 "Item identity" paragraph (replaces the paragraph that set no `id`); 6.3 `unanswered` uses `detail`.
- F12: 5.2 `rules list`, `watchlists list`, `items list` rows; paragraph after the table.
- F13: 7.1 item 2 (new); 8.2 first bullet; 9.1 "Import boundary" bullet.
- F14: 3 table install cell and cost row; 3 paragraphs on the `go install` probe (re-run 2026-11-13: proxy returns `v0.0.0-20260510080726-74ab7227a4d8`; repository PUBLIC) and release binaries; 5.1 version paragraph; 8.2 last bullet; 10 `whoami` row (server version); 5.6 `whoami` sentence.
- F15: 7.1 last paragraph; 9.3 startup test.
- F16: 5.4 exit 5 row and the 401/403 sentence; 10 `whoami` row (membership check).
- F17: 9 opening paragraph (ServerDeps, injected clock); 9.2 exit-code bullet; 9.3 acceptance test and concurrency test; 9.4 rewritten; 9.1 client-policy bullet; 5.1 response-body limits.
- F18: 10 closing paragraph rewritten; 13 item 1 unchanged in substance.
- F19: 7.1 paragraph 1 first sentence.
- F20: 1, MCP-1 bullet.
- F22: 1, CLI-1 bullet (requirement names JSON default and a table option).
- F23: 6.1 substitution paragraph, unsupported purl types paragraph, golden fixture paragraph, CycloneDX paragraph.
- F25 (forced part): 2 DSL row rewritten; 7.3 `validate_rule` bullet and drift test.
- F26 (forced part): 5.5 new 503 bullet; 5.1 URL row (TLS-terminating proxy; CA question pointed at 12).
- F27: 4.2 "Keeping in sync" row; paragraph on a shared types package.
- F29: 4.1 `uritemplate` paragraph ("`mcp-go`, the other SDK considered below"); `mcp-go` bullet's advisory comparison.
- F31: 10 FEED-1 row (cursor across upgrades).
- F33: 5.6 second paragraph (MCP tool contract).
- F34: 7.4 `get_advisory` caps.
- F36: 2 check row, added sentence.
- F37: 5.2 paragraph after the table, last sentence.
- Gate rows F1, F21, F24, F25, F26, F30, F32, F35 and P0-1: 12 rewritten as the batched decision list (items 1 and 6 to 14 are new; items 2 to 5, 9 and 15 carry the original decisions); 5.2, 5.4, 7.2 and 7.3 spans mark the pending decisions.

### Round 2w — repair-wave integration read (elective; repair discipline rule 4; raw `round-2-wave-read.md`, IDs D1–D14)

A fresh-context Opus read of the round-2 wave diff against `b493321`. Not a lens round and not a qualifying read; its rows are forced corrections of the wave's own text. Facts re-checked by the runner before editing: `ci.yml` line 222 runs `go build ./cmd/cvert-ops` with no flags; `.dockerignore` line 2 excludes `.git`; `docker/Caddyfile` line 25 `{$CADDY_HOST:localhost}` (local CA only for the `localhost` default); `internal/api/cves.go` lines 263–268 hold the four pointer fields, untagged because huma panics on pointer query parameters.

- **W1 (D1):** 12's preamble says the text follows each recommendation, but 5.4, 7.2, 9.2, 11 and 13 follow the original proposal and 5.5 does not mark pacing as pending; 7.1 and 7.2 describe different write switches. **Action:** preamble rewritten to say the text describes the original proposal and marks affected spans; 5.5 marks pacing pending; 7.1 wording matches either switch.
- **W2 (D2):** exit 9 defined two ways (5.4 "even alone" against 6.2's twice-timed-out half). **Action:** 5.4 row and 6.2 step 6 state one rule: items the server could not answer after the splits of steps 3–5.
- **W3 (D3):** 6.2's "three requests, about 90 seconds" worst case is wrong once 422 and timeout splits interleave. **Action:** replace the figure with the bound that applies: the command's retry budget does not cover splits; state that each split level at most doubles the requests and that timeouts are bounded by 30 seconds each.
- **W4 (D4):** server version relied on, but always `"dev"`; CI passes no flags; `/cvert` in the image reports no VCS revision because `.dockerignore` drops `.git`. **Action:** 5.1 version paragraph corrected; 10 asks `whoami` for the server version and notes it reads `dev` until builds set it; 5.6 sentence adjusted; 8.2 Dockerfile bullet passes the version as a build argument.
- **W5 (D5):** `cvert whoami` prints the client version vs "single-resource command prints the body unchanged". **Action:** client version goes to `cvert --version` only; 5.6 sentence rewritten.
- **W6 (D6):** `events list` lacks `--cursor` though "every list command takes `--cursor`". **Action:** the paragraph names `events list` as taking `--after` in place of `--cursor`.
- **W7 (D7):** 8.1 claims CLI and MCP cannot disagree on retries and that the MCP package is built from the client alone. **Action:** 8.1 sentence and row rewritten.
- **W8 (D8):** 12 item 8 misstates Caddy. **Action:** item 8 rewritten: the default `localhost` host uses Caddy's local CA; a private host name needs a certificate from a private CA or DNS challenge.
- **W9 (D9):** `go install ./cmd/cvert@<branch>` is invalid; table says "works". **Action:** full module path; table cell says "is expected to work" with the check pointed at the plan.
- **W10 (D10):** 6.2 step 7 omits 400, 413 and other 422s. **Action:** step 7 adds them (exit 8).
- **W11 (D11):** 12 item 7 recommendation departs from the requirement's "no results" exit code without saying so. **Action:** item 7 says so, and keeps a no-results code for lookups.
- **W12 (D12):** 12 item 13's "over 10,000 … exits 6" conflicts with `--all` stopping above 10,000 with exit 2. **Action:** "a list of 10,000 items".
- **W13 (D13):** rebuttal-shaped clauses in 5.2, 4.1, the 2 check row, and 9.2's wrong decision pointer. **Action:** rewritten as plain design text; 9.2 points at 7(b).
- **W14 (D14):** `internal/alert/dsl` imports store code directly; `cves.go` line numbers; the `go list -deps` test placed in `.golangci.yml`; 7.5's request count. **Action:** corrected each; F3's spec fix notes huma's pointer restriction.

### Post-gate merge of `dev` (round M, runner, not a review round)

After the gate was posed, `origin/dev` moved to `7d3571c`: `GET /whoami` (PR #232) and `expand=cve,rule` on alert events (PR #233) landed; the ascending `after` cursor (FEED-1) did not. Merged into this branch as `bd90312`. Section 10 described both as unbuilt, so three spans became stale. Source for every row: repo at `bd90312`.

- **X1:** 10 `whoami` row. Landed shape (`internal/api/whoami.go`): `principal`, `user_id`, `api_key {id, name, role, expires_at}`, `org {id, name, role, tier, rate_limit {scope, requests_per_minute, burst}}`; applies the membership check (line 78); is inside the org rate limiter (`allowOrgRequest`, line 82); returns no server version. **Action:** row rewritten to state what landed and what is still missing (server version); 5.6 sentence adjusted.
- **X2:** 10 FEED-2 row. Landed: `cve {status, severity, cvss_v3_score, cvss_v4_score, in_cisa_kev, epss_score}` and `rule {name, deleted, matched_watchlist_items}`. **Action:** row rewritten as landed.
- **X3:** 1 "Depends on unbuilt work", 10 heading and closing paragraph, 13 items 1 and 3, 5.2 `whoami` and `events list` rows, 7.2 `list_alert_events` row. **Action:** state that AUTH-5 and FEED-2 have landed and only FEED-1 is outstanding.

### Detail — F38, F39

- F38: extent standing finding S1 — duplicate of P0-1. F39: extent R5 — merged into F4.
