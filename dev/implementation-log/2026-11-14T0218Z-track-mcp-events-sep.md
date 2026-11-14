# CLI and MCP design tracks the MCP Events extension

## What was done

`dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` section 7.4 now records the MCP Events extension (SEP-3415) as tracked and not built, and section 1 lists it as not in scope. The note gives the extension's three delivery modes and how each fits the stateless MCP server: poll mode can be served from the same alert-event feed as `list_alert_events`; stream mode conflicts with one JSON response per request; webhook mode adds stored subscriptions and duplicates notification channels. It says when poll mode is added (the SEP merges in final form and the MCP SDK implements it) and when webhook mode would be considered.

The same note records that Drasi was evaluated and is not used.

## Decisions and gotchas

- **Why Drasi is not used.** It reads PostgreSQL through logical replication. The replication role receives every committed change in the published tables, so it reads every org's rows outside the `orgID` parameter and row-level security. Its MCP output has no authentication or per-client filtering. An operator who runs Drasi can still feed it from a CVErt-Ops webhook channel, which needs no database access.
- **SEP status was read from the pull request on 2026-11-14:** open, labelled `accepted`, final wording and reference implementation pending.
- The design's 17 open decisions (section 12) are unchanged; this note adds none.

## Quality checks

Docs only; no tests run.
