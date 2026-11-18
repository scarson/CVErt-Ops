# Phase 8A — Shared Foundation

**Branch:** None (landed directly on `dev`)
**Plan:** `dev/plans/2026-03-10-phase8-ops-phase8a-plan.md`
**PR:** #11 (bundled with code review fixes and documentation)

## What was built

5 tasks delivering foundational prerequisites that Phase 8B (Observe), 8C (Operate), and 8D (Extend) all depend on:

1. **`system_settings` migration (000034)** — System-level key-value table (`TEXT` PK, `BYTEA` value). NOT org-scoped, no RLS. Used by doctor encryption sentinel and CLI tools.
2. **`RequireSiteAdmin()` middleware verification** — Confirmed existing middleware is tested and correct. No new code.
3. **Security event type constants** (`internal/secure/events.go`) — 12 event type constants + 3 severity levels + `Severity()` lookup function with unexported `eventSeverity` map.
4. **Custom source precedence verification** (`internal/merge/resolve_custom_test.go`) — 4 tests codifying that `otherSources()` lets unknown source names contribute to union fields without winning scalar precedence. Added `IsReservedSourceName` helper in `internal/ingest/feeds.go`.
5. **Schema version bump** — `expectedSchemaVersion` from 30 to 34.

## Key decisions

- **Severity map unexported:** Initially exported `EventSeverity` map was refactored to unexported `eventSeverity` with a `Severity()` accessor function for cleaner encapsulation.
- **`system_settings` is NOT org-scoped:** No `org_id`, no RLS. Used only by site admins and CLI tools.
- **`IsReservedSourceName` is a semantic wrapper:** Delegates to `IsKnownFeed()` but provides a domain-meaningful name for config validation of custom feeds.

## Gotchas

- **gosec G101 false positives:** 3 `//nolint:gosec` suppressions needed on event constants containing "key", "token", "password" substrings (gosec thinks they're hardcoded credentials).
- **Schema version jump from 30 to 34:** Migrations 31-33 came from Phase 6/7 work before Phase 8A was planned.
- **No dedicated branch:** Phase 8A was intentionally a pre-gate on `dev`, bundled into PR #11 alongside code review fixes and documentation.

## Tests

| File | Tests |
|------|-------|
| `internal/secure/events_test.go` | 2 (`TestEventSeverityMapIsExhaustive`, `TestEventSeverityValues`) |
| `internal/merge/resolve_custom_test.go` | 4 (custom source CVSS, only-source, references union, packages union) |
| `internal/ingest/feeds_test.go` | 1 (`TestIsReservedSourceName`) |
| **Total** | **7** |

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean (3 gosec false positives suppressed inline)
