# Phase 8D — Extend Pillar

**Branch:** `phase-8d-extend` (worktree, concurrent with 8B/8C)
**Plan:** `dev/plans/2026-03-10-phase8-ops-extend-plan.md`
**PR:** #13 → merged to dev; #15 merged 8B/8C/8D to main

## What was built

7 batches across 15 tasks implementing the "Extend" pillar — config-driven generic feed adapters and an inbound webhook for custom CVE sources:

1. **Dependencies** — `tidwall/gjson` for JSON field mapping, `go.yaml.in/yaml/v4` for config parsing (not the archived `gopkg.in/yaml.v3`)
2. **Config system** (`internal/feed/generic/config.go`) — YAML config struct with validation (required fields, reserved name collision via `ingest.IsReservedSourceName`, cron expression checks), `LoadDir` for directory scanning, `Loader` struct with `Rescan()` for SIGHUP integration
3. **Generic feed adapter** (`internal/feed/generic/adapter.go`) — Implements `feed.Adapter`. JSON format with gjson field mapping, CSAF format via shared parser. 4 pagination strategies (none/offset/cursor/link-header), 4 auth types (none/bearer/basic/header with env-var credentials), rate limiting via `x/time/rate`, 50MB response cap, null byte sanitization
4. **Scheduler bridge** (`internal/feed/generic/scheduler.go`) — Converts generic configs to `ingest.FeedScheduleEntry` with cron-to-interval conversion. `AdapterFactory` wraps the built-in factory, creating generic adapters for known generic feed names and falling back to built-in adapters otherwise
5. **Inbound webhook** (`internal/api/ingest.go`) — `POST /api/v1/orgs/{org_id}/ingest` accepting CVE patches via JSON. Validates source name (non-reserved), CVE ID format, 100-patch limit. N patches consume N rate-limit tokens. Calls `merge.Ingest` per-patch independently. Returns 202 partial success or 400 if all rejected
6. **`validate-feeds` CLI** (`cmd/cvert-ops/validate.go`) — `cvert-ops validate-feeds` subcommand. Reads `CVERTOPS_FEEDS_DIR`, validates all YAML configs, reports errors. `--dry-run` flag stubbed for future connectivity testing
7. **Migration 000038** — Drops `cve_sources_source_name_check` constraint to allow custom feed names (validated at app layer via `IsReservedSourceName` instead)

## Key decisions

- **Timeout as string:** Config stores timeout as `string` (e.g., `"30s"`) rather than `time.Duration` — parsed at adapter creation time to avoid YAML marshaling issues with duration types.
- **Pagination raw count:** `nextPage` receives `rawCount` (before CVE ID filtering) to prevent filtered-out records from causing premature last-page detection.
- **Adapter factory wrapping:** Generic feeds don't modify `KnownFeeds` or `NewAdapter`. `AdapterFactory` wraps the built-in factory with a map lookup, cleanly separating generic from built-in feeds.
- **CSAF reuse:** CSAF format bypasses gjson mapping entirely and delegates to shared `csaf.Parse` — no mapping config needed for CSAF feeds.
- **Rate limit accounting on webhook:** N-1 additional tokens consumed (middleware already consumed 1 for the request itself).

## Gotchas

- **`cve_sources_source_name_check` constraint:** The Phase 7 migration hardcoded allowed source names. 8D's custom feeds need arbitrary names → migration 000038 drops the constraint in favor of app-layer validation.
- **Cursor URL encoding:** Cursor values from upstream APIs needed URL encoding when interpolated into pagination URLs (commit `9aa4be0`).
- **CSAF null bytes:** CSAF advisory strings contained null bytes that needed sanitization before database insertion (commit `9aa4be0`).
- **Empty CVE IDs:** Some records had no CVE ID — needed to be filtered rather than producing empty patches (commit `9aa4be0`).
- **Config test default mismatch:** Test assumed `RegistrationMode` default `"open"` but code default is `"invite-only"` (pre-existing, commit `b0ad824`).

## Tests

| File | Tests |
|------|-------|
| `internal/feed/generic/adapter_test.go` | 23 |
| `internal/feed/generic/config_test.go` | 20 |
| `internal/feed/generic/scheduler_test.go` | 3 |
| `internal/api/ingest_test.go` | 11 |
| `cmd/cvert-ops/validate_test.go` | 6 |
| **Total** | **63** |

## Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean (post-review fixes in `a9a2bb2`)
- **Go unit tests:** 63/63 pass across generic feed, ingest, and validate packages
- **Post-merge fix:** `d17460e` resolved integration issues from 8B/8C/8D merge
