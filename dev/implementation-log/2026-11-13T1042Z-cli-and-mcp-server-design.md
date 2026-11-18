# API client CLI and MCP server design: written, reviewed, stopped at the decision gate

## What was built

- `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`, the design for requirements CLI-1 and MCP-1, and its review record in `dev/plans/reviews/` (ledger, raw reviewer reports, handoff). No code or migration. Pull request 235.
- `dev/implementation-pitfalls.md` API-13: an in-process request built on the outer request's context is routed with the outer route.

## Decisions and gotchas

- Streamable HTTP is the primary MCP transport, at `POST /api/v1/mcp` inside `serve` (Sam's decision). MCP 2026-07-28 is stateless, so the endpoint is an ordinary authenticated POST handler. stdio (`cvert mcp`) stays, last, because the requirement asks for it.
- Tools reach the API in process with the caller's own key and the full middleware chain. The inner request needs a fresh context: with the outer context, chi reuses the outer routing state and answers 404 (probe against chi v5.5.0; pitfall API-13).
- The caller's org and effective role come from the authenticated request, not a `whoami` call: the SDK calls `getServer` twice per request and it cannot return an error.
- The API client is generated with `oapi-codegen` v2.8.2, filtered to the 14 operations used (4,293 lines, builds and vets clean), replacing the earlier hand-written recommendation after Sam asked for strong justification. Its `tool` directive would add 14 modules to `go.mod`, including the archived `gopkg.in/yaml.v3`; the design recommends a separate `tools/go.mod`.
- Requirement FEED-1 landed during the review (pull request 234); `next_cursor` is absent on the first poll of an org with no events, which the clients handle.
- Server changes the design puts in its first pull request: the four `/cves` score filters declared so the spec documents them; a problem type for the check endpoint's time-limit 503; and, if Sam agrees, audit rows for single watchlist item writes and a whole-list replace scoped to one item type.
- The design review is stopped at its decision gate with 17 open decisions (section 12 of the design); closure runs after Sam answers.

## Quality checks

- Review: author pilot; six cold reviewers (five Claude Opus 5.5, one Codex `gpt-6.1-sol`, high); a re-sweep by Claude Fable (all lenses) and Codex (security batch); two fresh-context reads of the fix waves. 107 ledger rows in all.
- Claims checked against code at `5598af6` and `origin/dev` `9bcf4ab`, the MCP 2026-07-28 specification, `go-sdk` v1.8.0 and `oapi-codegen` v2.8.2 sources, and `govulncheck` on a scratch MCP server.
- No tests ran, because no code changed.
