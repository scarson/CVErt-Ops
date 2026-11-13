# Handoff: API client CLI and MCP server design (requirements CLI-1, MCP-1)

Written 2026-11-13 by the session that wrote and reviewed the design. For the next agent that resumes the design review or plans the implementation.

## Headline state

- **Design:** `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`. Draft for Sam's review; no implementation code.
- **Branch:** `claude/cli-mcp-design-5a3740` (worktree `.claude/worktrees/cli-mcp-design-5a3740`), merged with `origin/dev` at `9bcf4ab`. The commit that adds this file is the tip and is pushed with it; `git log -1` on the branch gives it.
- **Pull request:** [scarson/CVErt-Ops#235](https://github.com/scarson/CVErt-Ops/pull/235), into `dev`, docs only: the design, its review record under `dev/plans/reviews/`, pitfall API-13 in `dev/implementation-pitfalls.md`, and the implementation-log entry `dev/implementation-log/2026-11-13T1042Z-cli-and-mcp-server-design.md`. Do not merge it before Sam has answered the decisions; it records a design that is not approved.
- **Design review:** `superpowers-plus:design-review-cycle`, Run 1 in the ledger `dev/plans/reviews/2026-11-13-api-client-cli-and-mcp-server-design.ledger.md`. Terminal state **stopped awaiting user** (second posing): 17 open decisions in section 12 of the design. The run resumes; it is not finished.
- **Requirements:** the private homelab integration requirements, sections 7.7 and 9. They are outside this repository, must never be committed or quoted here, and host names from them must not appear here. Their location is in the side-session notes folder that the Claude desktop app keeps for the session group this work belongs to (the group started from the integration-requirements session), file `cli-mcp-handoff-private.md`; Sam can also give it.
- The worktree has a copy of `web/dist` (git-ignored) so `internal/api` builds; it is not part of any commit.

## What the design says, in one paragraph

A separate `cvert` binary holds the CLI (`whoami`, `cves`, `check` with purl, JSON or Trivy input and batching against the 500-item cap, `events` in feed order, `rules`, `watchlists`) with JSON output, `--output table`, exit codes 0–9, and configuration from `CVERT_URL` and `CVERT_API_KEY` / `CVERT_API_KEY_FILE` only. The MCP server's primary transport is streamable HTTP inside `cvert-ops serve` at `POST /api/v1/mcp` (MCP 2026-07-28, stateless), API keys only, any `Origin` refused, tools reaching the API in process with the caller's key through the full middleware chain; `cvert mcp` over stdio is the second transport and the last pull request. The API client is generated with `oapi-codegen` v2.8.2, filtered to 14 operations, under a thin hand-written wrapper. MCP SDK: `github.com/modelcontextprotocol/go-sdk` v1.8.0. Three pull requests (section 13).

## What happened this session (decisions and their sources)

| When | What | Where recorded |
|---|---|---|
| Start | Design written: separate binary, hand-written client, stdio first with HTTP deferred, go-sdk | Design commit `c8f941d` |
| Review round 1–2 | Author pilot (13 rows) and six cold reviewers, one cross-model (39 rows); 41 fixes; the gate posed 15 decisions | Ledger rows L1–L13, F1–F39, W1–W14 |
| Gate 1 | `whoami` and `expand=cve,rule` landed on `dev` mid-review; section 10 updated | Ledger rows X1–X3 |
| Sam's answers | "Strong disagree on deferring streamable HTTP — that should be primary if anything." "Hand-rolled API client needs very strong justification of benefits over generated." Steelman every decision; an independent Fable review; read the 2026-07-28 spec | Ledger "Gate answers"; rows G1–G3 |
| Fold | MCP 2026-07-28 read; go-sdk checked; a filtered client generated and measured; HTTP made primary; client recommendation changed to generated; steelman added to every section 12 item | Design commit `808b0db` |
| Round 4 | Re-sweep: Claude Fable all lenses + Codex seam batch; 23 rows; FEED-1 landed (`9bcf4ab`) and section 10 rewritten | Ledger rows K1–K23, X4 |
| Round 4w | Integration read of the fixes; 10 defects fixed | Ledger rows V1–V10; design commit `b537a9d` |

Recommendations the steelman changed: item 13 (pace long org-scoped runs only, not every request) and item 14 (clean feed and member text, not only label it). Item 7 is marked as a close call.

## Open decisions (section 12 of the design is authoritative)

Seventeen open: 1 requirements coverage; 2 separate binary; 3 generated client, plus whether the generator gets its own `tools/go.mod`; 4 go-sdk and its stale transitive `yosida95/uritemplate`; 6 tool set and named write tools; 7 exit codes for empty lists and invalid rules; 8 `CVERT_CA_FILE`; 9 no org setting; 10 audit rows for single watchlist item writes; 11 item-type-scoped whole-list replace and `already_present`; 12 move the DSL field catalog out of the DSL package; 13 pacing; 14 cleaning text given to agents and moving `Sanitize`; 15 a PLAN.md section; 16 no OAuth profile now; 17 endpoint on by default; 18 MCP POSTs not rate-charged. Item 5 is decided (HTTP primary). Item 3 was answered as a burden of proof that the hand-written option did not meet; Sam still gives the final word.

Two dependency sign-offs sit inside those items, both for modules that fail the dependency-check age rule but are linked and unreachable from this code: `yosida95/uritemplate` v3.0.2 (item 4) and `apapsch/go-jsonmerge/v2` v2.0.0 (item 3).

## How to resume the design review

Follow `superpowers-plus:design-review-cycle` from its Phase 4 gate, with the ledger as the only state:

1. Record Sam's answers in the ledger as the first edit, and clear the Terminal state line.
2. Fold each answer (row before edit), keeping the design's section 12 as the decision list.
3. Phase 5: diff the design against `808b0db`, the snapshot of the last default-route whole-doc round (round 4). A re-sweep is required if the diff adds or removes a section, or restructures material carrying other findings than those the diff implements.
4. Closure: one snapshot, materialised to a scratch path, a cold reader (all lenses) and a ledger verifier against it; both clean on the same ref; the closure checklist; the completion commit; then `superpowers-plus:editorial-pass`.
5. The convergence breaker is eligible from now on (round 4 re-reviewed the round-2 wave). The next qualifying read is backstop ordinal 7.

## Seams with other work

- **The parallel session (machine-caller-basics) is done.** Its pull requests 232 (`whoami`), 233 (`expand=cve,rule`) and 234 (ascending feed) are on `dev`. One request to it, or to whoever touches `whoami` next, is still open: `whoami` returns no server version (section 5.6 of the design would use it, and every server build reports `dev` until build flags set one). The needs note for that session is `cli-mcp-needs-from-machine-caller-basics.md` in the session notes folder.
- **First poll of an empty feed:** with no `after` and no events, the feed endpoint returns no `next_cursor` (`omitempty`). The design handles it on the client (an empty `--after` means "from the start"). A server-side start cursor would be simpler for clients; not requested yet.
- **Server changes the client work depends on**, all in the design's first pull request: string query parameters for the four `/cves` score filters (the generated client cannot send them until the spec documents them), the `urn:cvert:error:check_time_limit` problem type, and, if Sam agrees, item-write audit rows and the scoped replace.
- **Two server refactors gated on decisions:** moving the DSL field catalog (item 12) and moving `Sanitize` out of `internal/ai` (item 14). The MCP package's import boundary forbids both packages as they are.

## Verify before building (open checks the design hands to the plan)

- `go install github.com/scarson/cvert-ops/cmd/cvert@<branch>` end to end from a clean module cache (section 3).
- The request headers Claude Code and Codex send to an HTTP MCP server, to confirm neither sends `Origin` (section 7.2).
- Codex's default `tool_timeout_sec` in its own reference (secondary sources say 60 s; the design's deadline is 50 s) (section 7.8).
- Whether go-sdk v1.8.0 lets a server set `cacheScope` on `tools/list` (section 7.4).
- Trivy report field names and the source-version rule, from captured reports of a Debian and an Alpine image, with and without `--list-all-pkgs` (section 6.1).
- Status checks of the generator's modules when `tools/go.mod` is created (section 4.2).

## Operational notes from this session

- **Codex install broke mid-session:** `codex exec` exited 1 with "Missing optional dependency @openai/codex-win32-x64" after the global package was upgraded to 0.169.0 without its platform binary. Fix: check no `npm install` of codex is running, then `npm install -g @openai/codex@<installed version>`. Logged in the papercuts log.
- **Codex as a cold reviewer without scratch to clean:** `codex exec -C <worktree> -s read-only -m gpt-6.1-sol -c model_reasoning_effort=high --output-last-message <raw-report path> - < brief.md`, from a script file, in the background. The read-only sandbox cannot write the report, so `--output-last-message` writes it. Count the round finished only on exit 0 with a complete report.
- **Getting the served OpenAPI 3.0 document without a database:** a temporary test in `internal/api` that serves `/api/v1/openapi-3.0.json` from `newOpenAPITestHandler(t)` and writes the body to a path, run once and deleted. `internal/api` needs `web/dist` to build (copy it from the main checkout).
- **Generating the filtered client for measurement:** `go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2 -config cfg.yaml openapi-3.0.json` with `output-options.include-operation-ids` listing the 14 operation IDs (section 4.2 lists the operations).
- The scratch probes of this session (the go-sdk build, the chi routing probe, the `go get -tool` probe, the generated client) lived in a session scratchpad and are gone; the design and the ledger record their results.
- Claude Fable was used once, at Sam's explicit request; the review skill uses Claude Opus at high effort otherwise.

## Priority queue

1. Sam answers section 12 (17 items). Nothing below moves before this.
2. Resume the review run and reach closure (see "How to resume").
3. Merge PR 235 into `dev` once the review completes.
4. Write the implementation plan for the design's first pull request with `writing-plans-enhanced`, carrying the "Verify before building" checks as its first tasks.
5. Request the server version in `whoami` (small; any session).

## Continuation prompt

> You are resuming the design of the CVErt-Ops API client CLI and MCP server. Read `dev/plans/reviews/2026-11-13-api-client-cli-and-mcp-server-design.handoff.md` first, then the design `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` (section 12 is the decision list) and the review ledger beside it. The design review (`superpowers-plus:design-review-cycle`, Run 1) is stopped awaiting Sam's answers to section 12. If Sam has answered, record the answers in the ledger as the first edit, fold them, run the Phase 5 re-sweep check against `808b0db`, and take the review to closure. Never commit or quote the private homelab integration requirements or homelab host names. Work in a worktree branched from `dev`, on PR 235's branch `claude/cli-mcp-design-5a3740`.

## Review of this handoff

Rounds run on the written draft, in order; findings were fixed before the next pass.

- **Round 1 — naive fresh agent (2 findings applied):** the headline said "pushed" before the push; reworded. The location of the private requirements' pointer ("the session notes for this group of sessions") gave a fresh agent nothing to look for; it now names the folder the desktop app keeps and says Sam can give it.
- **Round 2 — recency bias (0 findings):** checked that the first-round decisions, the dependency sign-offs and the requirements-coverage item survive beside the late fold; they do (session table, sign-offs paragraph, item 1).
- **Round 3 — seams (1 finding applied):** PR 235's description still described the first draft (hand-written client, HTTP deferred, 15 decisions); rewritten to match the design at this tip, outside this file.
- **Round 4 — operational guardrails (0 findings):** the Codex install fix, the read-only Codex recipe and the `web/dist` copy are here; the install fix is also in the papercuts log.
- **Round 5 — loss-averse (0 findings):** the scratch probes' results are in the design and the ledger, and the two reproductions that matter (spec dump, client generation) are written out here.
- **Round 6 — public-repository exposure (session-specific: the work depends on a private document while landing in a public repository) (0 findings):** searched this file, the implementation-log entry and the pitfall for the requirements' text, their file path and homelab host names; none present. The private pointer is in a notes file outside the repository.
- **Round 7 — decision provenance (session-specific: Sam's answers changed two recommendations and the steelman changed two more) (0 findings):** Sam's words are quoted verbatim in the session table and the ledger, and each changed recommendation names what changed it.
- **Second full pass through rounds 1–7:** no findings.
