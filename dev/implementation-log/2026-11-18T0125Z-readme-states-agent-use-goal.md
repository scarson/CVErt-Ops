# README states agent use as a main goal

## What was built

| Feature | Files | Description |
|---|---|---|
| Agent-use goal in the README | `README.md` | A "Main Goal: Easy for AI Agents to Use" section directly under the introduction. It states that CVErt Ops is meant to be as easy for AI agents and scripts to use as for people, through the HTTP API, a CLI and an MCP server, and lists what supports that today (API-first design, OpenAPI 3.1 spec, RFC 9457 errors, cursor pagination, org-scoped API keys with role caps). |

## Key decisions

- **The CLI and MCP server are marked "Designed, not yet built".** No code exists for either; the README points to the design in `dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md` instead of describing them as features.
- **No claim of stable problem types.** Only some API errors carry a problem type (the version check's candidate-limit 422 does; its time-limit 503 does not yet), so the README says clients can tell failures apart by status code.

## Quality checks

- Docs-only change; no tests run.
