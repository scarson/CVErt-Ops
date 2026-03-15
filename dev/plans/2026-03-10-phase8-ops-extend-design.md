# Extend — Design

**Date:** 2026-03-10
**Status:** Design approved
**Pillar:** Extend
**Prerequisites:** Phase 8A (custom source precedence tier in merge/pipeline.go)
**Overview doc:** `2026-03-10-ops-maturity-overview.md`

## Current State

- `feed.Adapter` interface: `Fetch(ctx, cursor) → (*FetchResult, error)`
- 8 concrete adapters (NVD, MITRE, KEV, GHSA, OSV, EPSS, MSRC, Red Hat)
- Adding a feed requires: implement interface, add to `KnownFeeds` slice, add to `NewAdapter` switch
- Feed → merge pipeline is adapter-agnostic: `merge.Ingest(ctx, store, patch, sourceName)`
- Notification channels: webhook + email
- All adapters use streaming JSON, injected HTTP clients, per-source rate limiters

## Two Independent Features

| Feature | Use case | Mechanism |
|---------|----------|-----------|
| **Config-driven generic feed adapter** | "I have a URL that returns vulnerability data in a standard-ish format" | Poll-based, YAML config, no code |
| **Inbound webhook** | "My internal scanner can push findings" | Push-based, API endpoint, no code |

These are independent and cover separate scenarios. No overlap.

## 1. Config-Driven Generic Feed Adapter

### Config Format

YAML files in `CVERTOPS_FEEDS_DIR` (default `./feeds.d/`). Uses **gjson** path syntax (NOT JSONPath).

Dependencies: `github.com/tidwall/gjson`, `github.com/yaml/go-yaml` (official YAML org fork — `gopkg.in/yaml.v3` is archived/unmaintained as of mid-2025; verify exact module path via `go get` before implementation).

```yaml
name: internal-scanner
url: "https://vulnscanner.internal/api/v1/findings"
schedule: "0 */4 * * *"              # cron expression
auth:
  type: bearer                        # none | bearer | basic | header
  token_env: "INTERNAL_SCANNER_TOKEN" # env var NAME, never literal token
  # basic auth: username_env + password_env
  # header auth: header_name + header_value_env
format: json                          # json | csaf
rate_limit: 2                         # requests/second, default 1
timeout: 30s                          # per-request HTTP timeout, default 30s
pagination:
  type: offset                        # none | offset | cursor | link-header
  page_param: "page"                  # offset: query param for page number
  size_param: "per_page"              # offset: query param for page size
  page_size: 100                      # offset: items per page
  # cursor type additional fields:
  # cursor_param: "after"             # query param name for cursor value
  # cursor_path: "meta.next_cursor"   # gjson path to next cursor in response
mapping:
  root: "findings"                    # gjson path to the array of records
  fields:
    cve_id: "cve"                     # REQUIRED — must map to a CVE ID
    description: "summary"
    severity: "risk_level"
    cvss_v3_score: "cvss_score"
    cvss_v3_vector: "cvss_vector"
    references: "links.#.url"
    date_published: "first_seen"
    date_modified: "last_updated"
    raw_payload: "@this"              # gjson: whole record
  # Fields with no match in the response → nil in CanonicalPatch (not an error)
  # Only cve_id is required in mapping.fields
```

### Pagination Stop Conditions

| Type | Stop when |
|------|-----------|
| `none` | Single request, `LastPage = true` |
| `offset` | Result array length < `page_size` |
| `cursor` | `gjson.Get(response, cursor_path)` is empty string or absent |
| `link-header` | No `rel="next"` in response `Link` header (RFC 8288) |

### Implementation: `internal/feed/generic/`

Files:
- `adapter.go` — implements `feed.Adapter`, handles fetch/parse/map cycle
- `config.go` — YAML parsing, validation, config struct definitions
- `adapter_test.go` — comprehensive tests (see test cases below)

The generic adapter:
1. Loads config from YAML at startup
2. Reads auth token from the env var named in config (never from YAML itself)
3. Fetches URL with auth headers, using its own `http.Client` with configurable timeout (default 30s). Standard HTTP client — NOT safeurl (operators may intentionally target internal hosts)
4. Applies pagination per config
5. Extracts record array using gjson `root` path
6. Maps each record's fields to `CanonicalPatch` using gjson field paths
7. Returns `FetchResult` with patches + cursor
8. Rate limits all requests (default 1/s if not configured, always enforced)

### What It Supports

- JSON responses with configurable structure (gjson for root array and each field)
- CSAF format (reuses existing shared CSAF parser from MSRC/Red Hat adapters — field mapping not needed, just `format: csaf`)
- Three pagination styles + `none`
- Four auth patterns: `none`, `bearer`, `basic`, `header`
- Per-feed rate limiting

### What It Explicitly Does NOT Support

- XML/HTML parsing
- GraphQL APIs (use inbound webhook with a script)
- OAuth2 flows (use a token-refresh sidecar/proxy)
- Streaming responses (SSE, WebSocket)
- Response transformations beyond field mapping (no scripting, no Lua, no CEL)

**If an API doesn't fit the config format, use the inbound webhook (§2) and push data from a script.** Keeping the generic adapter simple is a feature.

### Scheduler Integration

The scheduler accepts a `[]GenericFeedConfig` alongside built-in `KnownFeeds`. Generic feeds scheduled using their cron expression. They appear in `feed_sync_state` and admin UI identically to built-in feeds.

The config `name` field = `sourceName` in `merge.Ingest` = key in `feed_sync_state`.

`KnownFeeds` slice is NOT modified. `NewAdapter` factory switch is NOT modified. The ingest handler checks if a feed is generic and instantiates the generic adapter with the loaded config directly.

### Reserved Name Protection

Config `name` must not collide with built-in feed names (`nvd`, `mitre`, `kev`, `ghsa`, `osv`, `epss`, `msrc`, `redhat`). Rejected at config validation time with clear error message.

### Custom Source Precedence

Generic feed sources get the `custom` precedence tier in `merge/pipeline.go` (Phase 8A deliverable) — below all built-in sources, above "no data." Test: generic feed patches CVE with CVSS 8.0, NVD patches same CVE with 7.5 → canonical record shows 7.5 (NVD wins).

### Config Loading & Lifecycle

- **Startup:** Scan `CVERTOPS_FEEDS_DIR`, validate all YAML files, register valid feeds. Invalid configs logged as warnings, not fatal.
- **Removed config:** Feed disappears from scheduler. `feed_sync_state` record preserved in DB (history). Admin UI shows only active feeds.
- **Loads at startup only.** The adapter exposes a `Rescan()` method for future SIGHUP integration (Secure pillar, Phase 8E). SIGHUP wiring is NOT this pillar's responsibility.
- **URL safety:** No SSRF protection (operator-configured URLs, not user-supplied). Validation logs a warning (not error) if URL resolves to private/link-local IP, as a courtesy.
- **Auth env var unset:** If the referenced env var doesn't exist at runtime, log a warning and send request without auth header. Don't panic or fail silently.

### Required Test Cases (minimum)

| # | Test | Config | Verifies |
|---|------|--------|----------|
| 1 | Simple flat array | JSON array at root, all fields mapped | Basic mapping works, all fields populated |
| 2 | Nested with envelope | Data at `data.results`, fields at nested paths | Root path extraction from envelope |
| 3 | Sparse fields | Only cve_id + description mapped | Unmapped fields nil, no error (testing-pitfalls §9.3) |
| 4 | CSAF format | `format: csaf`, no mapping | CSAF parser reuse, output matches MSRC adapter |
| 5 | Offset pagination | 3 pages, last has fewer records | Stop condition, cursor advancement |
| 6 | Cursor pagination | 2 pages, empty cursor_path on last | Stop condition |
| 7 | Auth: bearer | httptest verifies Authorization header | Token injected from env var |
| 8 | Auth: env var unset | Env var not set | Warning logged, request sent without auth |
| 9 | Invalid YAML | Missing required `name` field | Validation rejects at startup |
| 10 | Rate limiting | Rapid sequential Fetch calls | Throttled to configured rate |
| 11 | URL unreachable | Nonexistent host | Returns error, doesn't panic (testing-pitfalls §8.1) |
| 12 | Null bytes in response | Record with `\x00` in description | Sanitized before merge (testing-pitfalls §9.1) |
| 13 | CVSS 0.0 preservation | Record with `cvss_score: 0.0` | Score is 0.0 not nil (testing-pitfalls §9.2 / §4.4) |
| 14 | Reserved name | Config `name: "nvd"` | Validation rejects |
| 15 | Link-header pagination | Response with Link rel=next | Follows link, stops when no next |

## 2. Inbound Webhook for Custom Feed Ingestion

### Endpoint

`POST /api/v1/orgs/{org_id}/ingest`

### Authentication & Authorization

Org-scoped API key (existing mechanism). RBAC: `RequireOrgRole("member")` — allows member, admin, owner.

### Rate Limiting

Counts as **N requests** where N = number of patches in the body. A 100-patch request consumes 100 units from the org's rate limit bucket. Prevents amplification via stolen API key.

### Request Format

```json
{
  "source_name": "internal-scanner",
  "patches": [
    {
      "cve_id": "CVE-2026-12345",
      "description": "Buffer overflow in libfoo",
      "severity": "HIGH",
      "cvss_v3_score": 8.1,
      "cvss_v3_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "references": [
        {"url": "https://example.com/advisory", "source": "internal"}
      ],
      "date_published": "2026-03-01T00:00:00Z",
      "date_modified": "2026-03-09T00:00:00Z"
    }
  ]
}
```

### Field Requirements

- `source_name` (top-level): required, non-empty
- `patches[].cve_id`: required, must match `^CVE-\d{4}-\d{4,}$`
- All other patch fields: optional (pointer types in `CanonicalPatch`)

### Reserved Source Name Protection

`source_name` must not collide with built-in feed names. Returns 400 if it does.

### Processing

- Max 100 patches per request (checked before processing, returns 400 if exceeded)
- Per-patch error independence: process all patches regardless of individual failures (same pattern as notification fan-out)
- Each patch calls `merge.Ingest(ctx, store, patch, sourceName)` independently
- The handler does NOT wrap in a transaction helper — `merge.Ingest` manages its own advisory-locked transactions
- The handler uses org context only for RBAC verification

### Source Precedence

Inbound webhook sources get the same `custom` precedence tier as generic adapter sources.

### Response

- All accepted → `202 Accepted`
- Some accepted, some rejected → `202 Accepted` with error details
- ALL rejected → `400 Bad Request`

```json
{
  "accepted": 3,
  "rejected": 1,
  "errors": [
    {"index": 2, "cve_id": "INVALID", "error": "cve_id must match CVE-YYYY-NNNNN format"}
  ]
}
```

### What It Doesn't Do

- No cursor management (caller pushes when ready)
- No pagination (100-patch limit; callers batch larger sets)
- No webhook signature verification on inbound (authenticated via API key)
- No `feed_sync_state` record (state lives in caller's system)

### Files

- Create: `internal/api/ingest.go`, `internal/api/ingest_test.go`
- Modify: `internal/api/server.go` — register one route in org-scoped group

## 3. Feed Config Validation CLI

`cvert-ops validate-feeds` — new cobra subcommand (`cmd/cvert-ops/validate.go`).

Validates all YAML files in `CVERTOPS_FEEDS_DIR`:
- YAML syntax
- Required fields (name, url, format, mapping.root, mapping.fields.cve_id)
- No reserved name collisions
- Cron expression validity
- Auth env var is set (warns if not)
- `--dry-run` flag: fetches first page from URL, verifies connectivity and mapping

Exit code 0 if all valid, 1 if any errors.

### Relationship to Doctor

`cvert-ops doctor` performs light feed config validation (YAML parses, required fields present, no reserved names). `validate-feeds` does deep validation (connectivity, mapping verification). Different tools, different depth.

## Files to Create and Modify

| Action | File |
|--------|------|
| Create | `internal/feed/generic/adapter.go` |
| Create | `internal/feed/generic/config.go` |
| Create | `internal/feed/generic/adapter_test.go` |
| Create | `internal/api/ingest.go` |
| Create | `internal/api/ingest_test.go` |
| Create | `cmd/cvert-ops/validate.go` |
| Modify | `internal/ingest/feeds.go` — generic feed detection (NOT KnownFeeds or NewAdapter) |
| Modify | `internal/ingest/scheduler.go` — schedule generic feeds alongside built-in |
| Modify | `internal/api/server.go` — register one route in org-scoped group |

Cross-pillar touch: only `server.go` modified by both Extend (one org route) and Operate (admin routes in different group). Minimal conflict.

## What We Won't Build

- Plugin runtime (Go plugins, WASM, hashicorp/go-plugin)
- Custom notification channel types via config (webhook URL covers Slack/Teams)
- Scripting/transformation layer in generic adapter
- GraphQL support in generic adapter
- OAuth2 in generic adapter (use sidecar)

## Subagent Risk Areas

| Risk | Mitigation |
|------|------------|
| gjson syntax vs JSONPath | Plan uses gjson syntax in ALL examples. `root: "findings"` not `root: "$.findings"`. Agent must not use JSONPath anywhere. |
| Pagination stop condition ambiguity | Exact stop condition per type specified above. |
| Scheduler integration pattern | Do NOT modify `KnownFeeds` or `NewAdapter`. Scheduler accepts `[]GenericFeedConfig` separately. |
| Transaction handling in webhook | Handler does NOT use `withOrgTx`. `merge.Ingest` manages its own transactions. |
| Rate limit accounting for webhook | Count as N requests (N = patch count). Test: rate limit is 10/min, POST 15 patches → error. (testing-pitfalls §5.3) |
| Reserved source name collision | Reject at config validation and at API request time. Test both paths. |
| SIGHUP independence | Startup-only. `Rescan()` exists but not called until Secure pillar wires SIGHUP. |
| Custom precedence placement | Phase 8A adds tier to `merge/pipeline.go`. Plan specifies which file and data structure. Test: custom CVSS vs NVD CVSS → NVD wins. |
| Test coverage minimum | 15 test cases enumerated above. Agent implements all 15. |
| YAML library | `github.com/yaml/go-yaml` (official fork). Verify module path via `go get`. Fallback: `github.com/goccy/go-yaml`. |
| gjson dependency | `github.com/tidwall/gjson`. New dependency — `go get` in setup. |
| Null-byte sanitization | Verify merge.Ingest handles it. Test with `\x00` in description. (testing-pitfalls §9.1) |
| CVSS 0.0 preservation | Test that `cvss_v3_score: 0.0` maps to `*float64` pointing to 0.0, not nil. (testing-pitfalls §4.4 / §9.2) |
| Feed config directory security | YAML files placed on disk by operator, not uploadable via API. Admin UI shows configs read-only. |
| Generic adapter HTTP client | Own `http.Client` with configurable timeout. NOT safeurl (operators target internal hosts intentionally). |
| Response code for all-rejected | 400, not 202. Partial success → 202 with errors. All success → 202. |
