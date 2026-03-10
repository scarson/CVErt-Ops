# Extend Pillar — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Config-driven generic feed adapter (YAML + gjson), inbound webhook for custom feed ingestion, and `validate-feeds` CLI.

**Architecture:** Generic adapter in `internal/feed/generic/` implements `feed.Adapter` interface. Inbound webhook in `internal/api/ingest.go` calls `merge.Ingest` directly. Both use the `custom` precedence tier from Phase 8A. Config loaded from `CVERTOPS_FEEDS_DIR` at startup.

**Tech Stack:** Go, `tidwall/gjson`, `github.com/yaml/go-yaml` (verify exact module path via `go get`), chi, huma

**References:**
- Design: `dev/plans/2026-03-10-ops-extend-design.md`
- Testing pitfalls: `dev/testing-pitfalls.md` (referenced as `tp§N.N`)
- Feed interface: `internal/feed/interface.go`
- Merge entry: `internal/merge/pipeline.go:38` (`Ingest` function)
- Ingest handler: `internal/ingest/handler.go`
- Scheduler: `internal/ingest/scheduler.go`
- Known feeds: `internal/ingest/feeds.go` (`KnownFeeds`, `IsReservedSourceName` from Phase 8A)

**CRITICAL — File Ownership:** This pillar creates `internal/feed/generic/`, `internal/api/ingest.go`, `cmd/cvert-ops/validate.go`. It modifies `internal/ingest/feeds.go` (generic feed detection) and `internal/ingest/scheduler.go` (schedule generic feeds). It adds ONE route to `internal/api/server.go` in the org-scoped group. Do NOT touch `internal/metrics/`, `internal/log/`, `internal/secure/`, `internal/doctor/`, or admin routes.

**CRITICAL — Dependencies:** Before implementation begins, add dependencies:
```bash
go get github.com/tidwall/gjson
go get github.com/yaml/go-yaml  # verify exact module path — may be gopkg.in/yaml.v3 replacement
```
If `github.com/yaml/go-yaml` doesn't resolve, try `github.com/goccy/go-yaml` as fallback per design doc.

**CRITICAL — Do NOT modify `KnownFeeds` or `NewAdapter` in `internal/ingest/feeds.go`.** Generic feeds bypass the adapter factory entirely.

---

## Batch 1: YAML Config Parsing & Validation

### Task 1: Add Dependencies

**Step 1:** Run `go get github.com/tidwall/gjson`
**Step 2:** Run `go get github.com/yaml/go-yaml` (verify exact module path). If this fails, try `github.com/goccy/go-yaml`. Document whichever works.
**Step 3:** Run `go mod tidy`
**Step 4:** Commit go.mod + go.sum

### Task 2: Config Struct & YAML Parsing

**Files:**
- Create: `internal/feed/generic/config.go`
- Create: `internal/feed/generic/config_test.go`

**Context:** The config struct maps the YAML format from design doc §1. All fields have exact names and types specified. The `mapping.fields` map uses gjson path syntax (NOT JSONPath — no `$.` prefix).

**Step 1: Write test — parse valid YAML config**

```go
func TestParseConfig_ValidYAML(t *testing.T) {
    yaml := `
name: internal-scanner
url: "https://vulnscanner.internal/api/v1/findings"
schedule: "0 */4 * * *"
auth:
  type: bearer
  token_env: "INTERNAL_SCANNER_TOKEN"
format: json
rate_limit: 2
timeout: 30s
pagination:
  type: offset
  page_param: "page"
  size_param: "per_page"
  page_size: 100
mapping:
  root: "findings"
  fields:
    cve_id: "cve"
    description: "summary"
    severity: "risk_level"
    cvss_v3_score: "cvss_score"
`
    cfg, err := generic.ParseConfig([]byte(yaml))
    require.NoError(t, err)
    assert.Equal(t, "internal-scanner", cfg.Name)
    assert.Equal(t, "bearer", cfg.Auth.Type)
    assert.Equal(t, "findings", cfg.Mapping.Root)
    assert.Equal(t, "cve", cfg.Mapping.Fields["cve_id"])
}
```

**Step 2: Write test — validation rejects missing required fields (design doc test case #9)**

```go
func TestValidateConfig_MissingName(t *testing.T) {
    cfg := &generic.Config{URL: "http://example.com", ...}
    err := cfg.Validate()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "name")
}
```

Required fields: `name`, `url`, `format`, `mapping.root`, `mapping.fields.cve_id`.

**Step 3: Write test — reserved name rejection (design doc test case #14)**

```go
func TestValidateConfig_ReservedName(t *testing.T) {
    cfg := &generic.Config{Name: "nvd", ...all other fields valid...}
    err := cfg.Validate()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "reserved")
}
```

Uses `ingest.IsReservedSourceName()` from Phase 8A.

**Step 4: Implement config struct**

```go
// ABOUTME: YAML configuration format and validation for config-driven generic feed adapters.
// ABOUTME: Parsed from files in CVERTOPS_FEEDS_DIR; validated at startup and by validate-feeds CLI.
package generic

type Config struct {
    Name       string         `yaml:"name"`
    URL        string         `yaml:"url"`
    Schedule   string         `yaml:"schedule"`
    Auth       AuthConfig     `yaml:"auth"`
    Format     string         `yaml:"format"`     // "json" or "csaf"
    RateLimit  float64        `yaml:"rate_limit"`  // requests/second, default 1
    Timeout    time.Duration  `yaml:"timeout"`     // default 30s
    Pagination PaginationConfig `yaml:"pagination"`
    Mapping    MappingConfig  `yaml:"mapping"`
}

type AuthConfig struct {
    Type          string `yaml:"type"`           // none | bearer | basic | header
    TokenEnv      string `yaml:"token_env"`
    UsernameEnv   string `yaml:"username_env"`
    PasswordEnv   string `yaml:"password_env"`
    HeaderName    string `yaml:"header_name"`
    HeaderValueEnv string `yaml:"header_value_env"`
}

type PaginationConfig struct {
    Type        string `yaml:"type"`         // none | offset | cursor | link-header
    PageParam   string `yaml:"page_param"`
    SizeParam   string `yaml:"size_param"`
    PageSize    int    `yaml:"page_size"`
    CursorParam string `yaml:"cursor_param"`
    CursorPath  string `yaml:"cursor_path"`  // gjson path
}

type MappingConfig struct {
    Root   string            `yaml:"root"`   // gjson path to array
    Fields map[string]string `yaml:"fields"` // field name → gjson path
}
```

**Step 5: Implement `Validate()` method.** Check required fields, cron expression validity, reserved name collision.

**Step 6: Run tests → PASS. Step 7: Commit.**

### Task 3: Config Directory Loading

**Files:**
- Modify: `internal/feed/generic/config.go` — add `LoadDir` function
- Add tests to `internal/feed/generic/config_test.go`

**Context:** `LoadDir(dir string) ([]Config, []error)` scans a directory for `*.yaml`/`*.yml` files, parses and validates each. Invalid configs are returned as errors (not fatal — logged as warnings at startup). Valid configs are returned for registration.

**Step 1: Write test — load directory with mix of valid/invalid configs**

Use `t.TempDir()` to create temp directory with test YAML files.

**Step 2: Implement `LoadDir`.** Use `os.ReadDir`, filter `.yaml`/`.yml`, parse each, validate each. Return valid configs and accumulated errors separately.

**Step 3: Run tests → PASS. Step 4: Commit.**

---

## Batch 2: Generic Feed Adapter

### Task 4: Adapter Core — JSON Mapping with gjson

**Files:**
- Create: `internal/feed/generic/adapter.go`
- Create: `internal/feed/generic/adapter_test.go`

**Context:** The adapter implements `feed.Adapter` interface: `Fetch(ctx, cursor) → (*FetchResult, error)`. For `format: json`, it:
1. Fetches URL with auth headers
2. Extracts record array using gjson `root` path
3. Maps each record to `CanonicalPatch` using gjson field paths
4. Returns `FetchResult` with patches + cursor

**CRITICAL — gjson syntax, NOT JSONPath:** Config uses `root: "findings"` not `root: "$.findings"`. Field paths like `"links.#.url"` for array extraction. Test with gjson's actual syntax.

**Step 1: Write test — simple flat array (design doc test case #1)**

```go
func TestAdapter_SimpleFlatArray(t *testing.T) {
    // httptest server returning JSON array at root with all fields mapped
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]any{
            "items": []map[string]any{
                {"cve": "CVE-2026-0001", "summary": "Test vuln", "cvss_score": 8.1},
            },
        })
    }))
    defer srv.Close()

    cfg := &generic.Config{
        Name: "test-feed", URL: srv.URL, Format: "json",
        Mapping: generic.MappingConfig{
            Root: "items",
            Fields: map[string]string{
                "cve_id": "cve", "description": "summary", "cvss_v3_score": "cvss_score",
            },
        },
    }
    adapter := generic.NewAdapter(cfg, srv.Client())
    result, err := adapter.Fetch(context.Background(), nil)
    require.NoError(t, err)
    require.Len(t, result.Patches, 1)
    assert.Equal(t, "CVE-2026-0001", result.Patches[0].CVEID)
    assert.Equal(t, "Test vuln", *result.Patches[0].DescriptionPrimary)
    assert.Equal(t, 8.1, *result.Patches[0].CVSSv3Score)
}
```

**Step 2: Write test — nested envelope (design doc test case #2)**

Data at `data.results`, fields at nested paths like `scoring.cvss`.

**Step 3: Write test — sparse fields (design doc test case #3, tp§9.3)**

Only `cve_id` + `description` mapped. Other fields must be nil, no error.

**Step 4: Write test — CVSS 0.0 preservation (design doc test case #13, tp§4.4, tp§9.2)**

```go
func TestAdapter_CVSS00Preserved(t *testing.T) {
    // Response has cvss_score: 0.0
    // Verify result.Patches[0].CVSSv3Score is *float64 pointing to 0.0, NOT nil
    assert.NotNil(t, result.Patches[0].CVSSv3Score)
    assert.Equal(t, 0.0, *result.Patches[0].CVSSv3Score)
}
```

**Step 5: Write test — null bytes in response (design doc test case #12, tp§9.1)**

Description contains `\x00`. Verify it's sanitized before reaching CanonicalPatch.

**Step 6: Implement adapter**

```go
// ABOUTME: Config-driven generic feed adapter implementing feed.Adapter.
// ABOUTME: Fetches JSON/CSAF from configurable URLs with gjson field mapping.
package generic

func NewAdapter(cfg *Config, client *http.Client) *Adapter { ... }
func (a *Adapter) Fetch(ctx context.Context, cursor json.RawMessage) (*FetchResult, error) { ... }
```

Key implementation details:
- HTTP client with configurable timeout (default 30s). Standard `http.Client` — NOT safeurl (operators may target internal hosts)
- Auth token read from `os.Getenv(cfg.Auth.TokenEnv)` at request time (never from YAML)
- If auth env var is unset: log warning, send request without auth header (design doc §1)
- Rate limiting via `golang.org/x/time/rate` (default 1 req/s if not configured)
- gjson for root path extraction and field mapping
- Null byte sanitization on all string fields

**Step 7: Run tests → PASS. Step 8: Commit.**

### Task 5: Pagination Support

**Files:**
- Modify: `internal/feed/generic/adapter.go`
- Add tests to `internal/feed/generic/adapter_test.go`

**Context:** Four pagination types with exact stop conditions from design doc:

| Type | Stop when |
|------|-----------|
| `none` | Single request, `LastPage = true` |
| `offset` | Result array length < `page_size` |
| `cursor` | `gjson.Get(response, cursor_path)` is empty string or absent |
| `link-header` | No `rel="next"` in response `Link` header (RFC 8288) |

**Step 1: Write test — offset pagination (design doc test case #5)**

```go
func TestAdapter_OffsetPagination(t *testing.T) {
    // httptest server serves 3 pages: page 1 has 100 items, page 2 has 100, page 3 has 47
    // Verify adapter fetches all 3 pages and stops (last page has < page_size items)
    callCount := 0
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        callCount++
        page := r.URL.Query().Get("page")
        // Return appropriate items per page
        // ...
    }))
    // Verify all patches collected, exactly 3 HTTP requests made
}
```

**Step 2: Write test — cursor pagination (design doc test case #6)**

2 pages. Second page has empty `cursor_path` value → stop.

**Step 3: Write test — link-header pagination (design doc test case #15)**

Response includes `Link: <url>; rel="next"` header. Stop when header absent.

**Step 4: Implement pagination** in the `Fetch` method. Each pagination type is a separate strategy.

**CRITICAL:** The adapter's `Fetch` returns one page at a time (matching `feed.Adapter` interface). The caller (ingest handler) calls `Fetch` repeatedly until `LastPage = true`. The cursor tracks pagination state.

**Step 5: Run tests → PASS. Step 6: Commit.**

### Task 6: Auth Patterns

**Files:**
- Add tests to `internal/feed/generic/adapter_test.go`

**Context:** Four auth types. Test that correct headers are sent.

**Step 1: Write test — bearer auth (design doc test case #7)**

```go
func TestAdapter_BearerAuth(t *testing.T) {
    t.Setenv("TEST_TOKEN", "secret-token-123")
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "Bearer secret-token-123", r.Header.Get("Authorization"))
        // return valid response
    }))
    cfg := &generic.Config{
        Auth: generic.AuthConfig{Type: "bearer", TokenEnv: "TEST_TOKEN"},
        // ...
    }
    // ...
}
```

**Step 2: Write test — auth env var unset (design doc test case #8)**

```go
func TestAdapter_AuthEnvVarUnset(t *testing.T) {
    // Don't set env var. Verify:
    // 1. Request sent WITHOUT auth header (not panic/error)
    // 2. Warning logged
}
```

**Step 3: Implement basic + header auth types if not already done in Task 4.**

**Step 4: Run tests → PASS. Step 5: Commit.**

### Task 7: Rate Limiting & Error Handling

**Files:**
- Add tests to `internal/feed/generic/adapter_test.go`

**Step 1: Write test — rate limiting (design doc test case #10)**

```go
func TestAdapter_RateLimiting(t *testing.T) {
    requestTimes := []time.Time{}
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestTimes = append(requestTimes, time.Now())
        // return response with pagination to trigger multiple requests
    }))
    cfg := &generic.Config{RateLimit: 2, ...} // 2 requests/second
    // Verify requests are spaced at least 500ms apart
}
```

**Step 2: Write test — URL unreachable (design doc test case #11, tp§8.1)**

```go
func TestAdapter_URLUnreachable(t *testing.T) {
    cfg := &generic.Config{URL: "http://nonexistent.invalid:9999", ...}
    _, err := adapter.Fetch(context.Background(), nil)
    assert.Error(t, err)
    // Must not panic
}
```

**Step 3: Run tests → PASS. Step 4: Commit.**

### Task 8: CSAF Format Support

**Files:**
- Modify: `internal/feed/generic/adapter.go`
- Add tests to `internal/feed/generic/adapter_test.go`

**Context:** When `format: csaf`, reuse existing shared CSAF parser from MSRC/Red Hat adapters. Field mapping not needed — CSAF has a standard structure.

**Step 1: Write test — CSAF format (design doc test case #4)**

Verify output matches what the MSRC adapter would produce for the same CSAF input.

**Step 2: Implement** — detect `format: csaf`, bypass gjson mapping, use existing CSAF parser.

**Step 3: Run test → PASS. Step 4: Commit.**

---

## Batch 3: Inbound Webhook

### Task 9: Inbound Webhook Endpoint

**Files:**
- Create: `internal/api/ingest.go`
- Create: `internal/api/ingest_test.go`
- Modify: `internal/api/server.go` — add one route in org-scoped group

**Context:** `POST /api/v1/orgs/{org_id}/ingest`. Org-scoped API key auth (existing mechanism). RBAC: `RequireOrgRole("member")`. Each patch calls `merge.Ingest` independently.

**Request format:**
```json
{
    "source_name": "internal-scanner",
    "patches": [{"cve_id": "CVE-2026-12345", ...}]
}
```

**Response:**
- All accepted → 202 with `{"accepted": N, "rejected": 0, "errors": []}`
- Partial → 202 with errors array
- All rejected → 400

**CRITICAL — Rate limiting:** Counts as N requests where N = number of patches. Design doc: "A 100-patch request consumes 100 units from the org's rate limit bucket."

**CRITICAL — Reserved name:** `source_name` must not collide with built-in feeds. Return 400 if it does.

**CRITICAL — Transaction handling:** The handler does NOT wrap in `withOrgTx`. `merge.Ingest` manages its own advisory-locked transactions. The handler uses org context only for RBAC verification.

**CRITICAL — Max patches:** 100 per request. Checked before processing, returns 400 if exceeded.

**Step 1: Write test — happy path with valid patches**

```go
func TestIngestHandler_AcceptsValidPatches(t *testing.T) {
    body := `{"source_name": "my-scanner", "patches": [
        {"cve_id": "CVE-2026-0001", "description": "Test"}
    ]}`
    // POST /api/v1/orgs/{org_id}/ingest with member auth
    // Assert 202 with accepted: 1, rejected: 0
}
```

**Step 2: Write test — reserved source name → 400**

```go
func TestIngestHandler_RejectsReservedSourceName(t *testing.T) {
    body := `{"source_name": "nvd", "patches": [...]}`
    // Assert 400
}
```

**Step 3: Write test — invalid CVE ID format → partial acceptance**

```go
func TestIngestHandler_PartialFailure(t *testing.T) {
    body := `{"source_name": "scanner", "patches": [
        {"cve_id": "CVE-2026-0001"},
        {"cve_id": "INVALID"}
    ]}`
    // Assert 202 with accepted: 1, rejected: 1, errors[0].index: 1
}
```

**Step 4: Write test — all patches invalid → 400**

**Step 5: Write test — exceeds 100 patch limit → 400**

**Step 6: Write test — CVE ID regex validation**

`cve_id` must match `^CVE-\d{4}-\d{4,}$`.

**Step 7: Write test — rate limit accounting (tp§5.3)**

```go
func TestIngestHandler_RateLimitCountsAsNRequests(t *testing.T) {
    // Org rate limit is 10/min
    // POST 15 patches in one request → should fail rate limit
}
```

**Step 8: Write test — RBAC (tp§11.1)**

- Member → 202 (allowed)
- Viewer → 403 (denied)
- Unauthenticated → 401

**Step 9: Implement handler**

```go
// ABOUTME: Inbound webhook endpoint for custom feed data ingestion.
// ABOUTME: Accepts CVE patches via POST, validates, and routes each to merge.Ingest.
package api

func (srv *Server) ingestHandler(w http.ResponseWriter, r *http.Request) { ... }
```

**Step 10: Wire route** in server.go org-scoped group:

In the `/{org_id}` route block, add:
```go
r.With(srv.RequireOrgRole(RoleMember)).Post("/ingest", srv.ingestHandler)
```

**Step 11: Run tests → PASS. Step 12: Commit.**

---

## Batch 4: Scheduler Integration

### Task 10: Generic Feed Registration with Scheduler

**Files:**
- Modify: `internal/ingest/scheduler.go` — accept `[]generic.Config` alongside built-in schedule
- Modify: `internal/ingest/feeds.go` — do NOT modify `KnownFeeds` or `NewAdapter`
- Create: `internal/ingest/generic_integration_test.go`

**Context:** The scheduler accepts generic feed configs and schedules them using their cron expressions. Generic feeds appear in `feed_sync_state` identically to built-in feeds. The config `name` field = `sourceName` in `merge.Ingest` = key in `feed_sync_state`.

**CRITICAL:** `KnownFeeds` is NOT modified. `NewAdapter` is NOT modified. The scheduler creates `generic.Adapter` instances directly from configs.

**Step 1: Modify `Scheduler` struct** to accept optional generic configs.

```go
func NewSchedulerWithGenericFeeds(st SchedulerStore, genericConfigs []generic.Config) *Scheduler {
    // Build schedule entries from generic configs using their cron expressions
    // Add to scheduler alongside built-in schedule
}
```

**Step 2: Write test** — generic feed is scheduled and executed.

**Step 3: Write test** — generic feed appears in `feed_sync_state` after successful run.

**Step 4: Implement. Step 5: Run tests → PASS. Step 6: Commit.**

### Task 11: Config Loading at Startup

**Files:**
- Modify: `cmd/cvert-ops/main.go` — load generic configs from `CVERTOPS_FEEDS_DIR`
- Modify: `internal/config/config.go` — add `FeedsDir` field

**Context:** On startup, scan `CVERTOPS_FEEDS_DIR`, validate all YAML files, register valid feeds. Invalid configs logged as warnings, not fatal. If env var not set, skip.

**Step 1: Add config field:**
```go
FeedsDir string `env:"CVERTOPS_FEEDS_DIR"`
```

**Step 2: In `runServe`**, after pool creation, before scheduler start:
```go
var genericConfigs []generic.Config
if cfg.FeedsDir != "" {
    configs, errs := generic.LoadDir(cfg.FeedsDir)
    for _, e := range errs {
        slog.Warn("invalid feed config", "error", e)
    }
    genericConfigs = configs
}
```

**Step 3: Pass to scheduler. Step 4: Commit.**

### Task 12: Rescan Method (for Secure Pillar SIGHUP)

**Files:**
- Create or modify: generic feed loader to expose `Rescan()` method

**Context:** Loads at startup only. The adapter exposes a `Rescan()` method for future SIGHUP integration (Secure pillar, Phase 8E). SIGHUP wiring is NOT this pillar's responsibility. Just create the method.

```go
func (l *Loader) Rescan() ([]Config, []error) {
    return LoadDir(l.dir)
}
```

**Step 1: Implement. Step 2: Write test. Step 3: Commit.**

---

## Batch 5: Validate-Feeds CLI

### Task 13: `cvert-ops validate-feeds` Command

**Files:**
- Create: `cmd/cvert-ops/validate.go`
- Modify: `cmd/cvert-ops/main.go` — add `root.AddCommand(validateFeedsCmd())`

**Context:** New cobra subcommand. Validates all YAML files in `CVERTOPS_FEEDS_DIR`:
- YAML syntax
- Required fields (name, url, format, mapping.root, mapping.fields.cve_id)
- No reserved name collisions
- Cron expression validity
- Auth env var is set (warns if not)
- `--dry-run` flag: fetches first page from URL, verifies connectivity and mapping

Exit code 0 if all valid, 1 if any errors.

**Step 1: Implement the command** following the pattern of `migrateCmd()`.

**Step 2: Test** by creating a temp directory with test YAML files and running the command.

**Step 3: Commit.**

---

## Batch 6: Comprehensive Test Cases

### Task 14: Remaining Design Doc Test Cases

Verify ALL 15 test cases from the design doc are covered. Cross-reference:

| # | Test | Covered in |
|---|------|-----------|
| 1 | Simple flat array | Task 4 |
| 2 | Nested with envelope | Task 4 |
| 3 | Sparse fields | Task 4 |
| 4 | CSAF format | Task 8 |
| 5 | Offset pagination | Task 5 |
| 6 | Cursor pagination | Task 5 |
| 7 | Auth: bearer | Task 6 |
| 8 | Auth: env var unset | Task 6 |
| 9 | Invalid YAML | Task 2 |
| 10 | Rate limiting | Task 7 |
| 11 | URL unreachable | Task 7 |
| 12 | Null bytes | Task 4 |
| 13 | CVSS 0.0 | Task 4 |
| 14 | Reserved name | Task 2 |
| 15 | Link-header pagination | Task 5 |

If any are missing, write them now.

**Run:** `go test ./internal/feed/generic/ -v -race -count=1`
Expected: ALL 15+ tests PASS.

**Commit if any new tests added.**

---

## Batch 7: Final Verification

### Task 15: Full Test Suite

**Step 1:** `go test ./... -race -count=1`
**Step 2:** `golangci-lint run`
**Step 3:** Fix issues. Final commit.

---

## Subagent Failure Modes to Watch For

| Risk | What goes wrong | Mitigation |
|------|----------------|------------|
| gjson vs JSONPath syntax | Agent uses `$.findings` instead of `findings` | Design doc examples all use gjson syntax; tests verify with gjson |
| Agent modifies `KnownFeeds` or `NewAdapter` | Design explicitly says NOT to | Bold warning at top of plan and in Task 10 |
| Pagination stop conditions wrong | Offset stops at wrong point, cursor never stops | Exact stop conditions from design doc in Task 5 |
| CVSS 0.0 dropped (tp§4.4, tp§9.2) | Go truthiness check drops zero value | Task 4 has explicit test for `0.0` preservation |
| Null bytes crash Postgres (tp§9.1) | Unsanitized `\x00` in text field | Task 4 has explicit null byte test |
| Auth env var panic | `os.Getenv("")` on empty config field | Task 6 tests unset env var — log warning, proceed without auth |
| Rate limit not enforced | Adapter makes unlimited requests | Task 7 verifies request timing |
| Inbound webhook uses `withOrgTx` | Transaction scoping conflicts with `merge.Ingest` | Design doc says handler does NOT use `withOrgTx`; Task 9 is explicit |
| Rate limit accounting wrong for webhook (tp§5.3) | 100-patch request counts as 1 request | Task 9 test verifies N-request accounting |
| YAML library import path wrong | `gopkg.in/yaml.v3` is archived | Task 1 verifies actual import path via `go get` |
| Reserved name not checked at both points | Config validation and API request both need checks | Task 2 (config) and Task 9 (API) both test reserved names |
| Scheduler integration modifies wrong files | Agent changes `NewAdapter` switch | Explicit "Do NOT modify" in Task 10 |
