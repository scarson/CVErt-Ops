# Phase 9, Stage 3: API Contract Convergence — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Converge all Chi JSON endpoints onto the same API contract as Huma endpoints: RFC 9457 errors, `{items, next_cursor}` list envelopes, opaque cursor pagination, pointer-based PATCH DTOs, and `Location` headers on 201 — then eliminate `orgFetch` by generating OpenAPI specs for Chi routes via spec-only Huma declarations and switching the frontend to the typed `openapi-fetch` client.

**Architecture:** Shared helper functions (not middleware) standardize the contract in Chi handlers. A separate Huma API instance produces OpenAPI specs for Chi routes without touching production routing. Per-family spec registration functions embed the same DTO types as Chi handlers to minimize drift. Each route family's backend and frontend updates land together.

**Tech Stack:** Go 1.26, chi, huma v2.37.2, OpenAPI 3.1, openapi-typescript, openapi-fetch, Vue 3, TypeScript

**Proposal:** `dev/plans/2026-03-15-phase9-stage3-api-contract-convergence-proposal.md`
**Gate Decision:** `dev/research-findings/openapi-evaluation-gate.md` — Candidate 1 (spec-only Huma) selected.

**Execution environment:** All command examples assume the Bash tool running from the repo root. Do not prefix commands with `cd /c/Users/Sam/Code/CVErt-Ops` — the Bash tool already runs from the project directory. Use `rg` instead of `grep -r` where practical.

---

## Constraints (from proposal — do not deviate)

1. Route registration stays on Chi for all org-scoped and admin routes. No Huma handler migration.
2. Shared helpers are called by handlers, not error-catching middleware.
3. Backend + frontend changes for a route family land in the same commit.
4. No store-layer changes except pagination query adjustments required by cursor standardization.
5. Transaction helper discipline unchanged (no `WorkerTx` from API handlers).
6. Error semantics: 400 malformed, 422 validation, 401 unauth, 403 RBAC, 403+type tier, 404 not found, 429 rate limit.
7. List endpoints without pagination still use `{"items": [...]}` envelope; `next_cursor` omitted.
8. Helpers must produce JSON field-for-field identical to huma's `ErrorModel` output.

## Testing Requirements (from proposal — every task must satisfy applicable items)

See proposal §Testing And Verification Requirements for the full 14-item list. Key items per task type:

- **Shared helpers (Task 0):** Requirement #12 — unit tests proving output matches huma's format exactly.
- **Handler conversions:** Requirements #1 (error-path differentiation), #2 (validation symmetry), #4 (cross-endpoint parity), #10 (no silent success on missing resources), #11 (downstream error propagation).
- **PATCH DTO conversions:** Requirement #3 (zero-value vs absent).
- **Cursor standardization:** Requirement #6 (malformed cursors, page boundaries, final page).
- **Frontend updates:** Requirements #7 (visible error handling), #13 (cache/navigation).
- **OpenAPI spec:** Requirement #14 (spec regression — paths, methods, schemas).
- **Security:** Requirements #5 (RLS safety), #9 (RBAC regression).

## Huma ErrorModel Reference

The shared helpers must produce JSON **field-for-field identical** to huma's actual serialized output. Verified against huma v2.37.2:

**Simple error (no field-level details):**
```json
{
  "title": "Bad Request",
  "status": 400,
  "detail": "human-readable explanation"
}
```

**Validation error (with field-level details):**
```json
{
  "title": "Unprocessable Entity",
  "status": 422,
  "detail": "validation failed",
  "errors": [
    {
      "message": "expected required property name to be present",
      "location": "body.name",
      "value": null
    }
  ]
}
```

**CRITICAL:** Huma's `ErrorModel.Type` field has `omitempty` and is **never set** by `huma.NewError()`. This means the `type` field is **absent** from standard huma error output. Our `writeProblem` helper must NOT set `Type` to `"about:blank"` — leave it as empty string so `omitempty` drops it, matching huma exactly. The `writeProblemTyped` helper is the only one that sets `type` (for tier-limit problem types).

Headers: `Content-Type: application/problem+json`

Key fields: `title` (HTTP status text), `status` (int), `detail` (string), `errors` (optional array of `{message, location, value}`). `type` is only present when using a custom problem type URI (e.g., tier limits).

## Cursor Format Standard

All paginated endpoints will use opaque base64-encoded JSON cursors. The internal structure varies per endpoint but is opaque to clients:

```
?cursor=<base64url(json)>&limit=N
```

Response envelope:
```json
{"items": [...], "next_cursor": "..."}
```

`next_cursor` is omitted (not `null`, not `""`) when there are no more results.

This matches the existing Huma CVE endpoint cursor format. **Encoding must be `base64.RawURLEncoding` (no `=` padding)** — matching `cves.go` lines 133/141. The old `encodeTimeCursor`/`decodeTimeCursor` (pipe-separated, padded `URLEncoding`) and `encodeDeliveryCursor` (slash-separated, plaintext) will be replaced by the shared cursor helper. `decodeCursor` accepts both padded and unpadded formats for backward compatibility, but `encodeCursor` always emits unpadded.

## Important Notes for Subagent Execution

### `writeJSON` stays for success responses

`writeJSON` (defined in `internal/api/orgs.go`) remains the success-response writer. Only `http.Error(w, ...)` calls are replaced with `writeProblem`/`writeProblemWithErrors`. Do NOT redefine `writeJSON` in `contract.go` — it already exists and is shared across all handler files.

### Anti-enumeration patterns MUST be preserved

Some handlers intentionally return identical responses regardless of whether a resource exists, to prevent information leakage. **Do not change the status code or add resource-specific detail messages** for these endpoints:

- `createInvitationHandler` — always returns 202 whether email exists or not (proposal §Testing #1 / testing-pitfalls §3a)
- `forgotPasswordHandler` — always returns 200
- `loginHandler` — generic error for both "wrong password" and "user not found"

When converting these endpoints to `writeProblem`, use the SAME generic message for all error paths that the current code uses.

### Frontend scope: many route families have no frontend views yet

The orgFetch audit found consumers in only these files:

**Admin views:** `AdminSystemView.vue`, `AdminUsersView.vue`, `AdminFeedsView.vue`, `AdminOrgsView.vue`, `AdminDashboardView.vue`, `AdminDeliveriesView.vue`, `AdminAuditLogView.vue`

**Org views:** `FeedStatusView.vue`, `WatchlistListView.vue`, `WatchlistDetailView.vue`, `MembersView.vue`, `GroupsView.vue`, `CreateOrgView.vue`

**Dialogs:** `AddItemDialog.vue`, `CreateWatchlistDialog.vue`, `InviteMemberDialog.vue`, `GroupDialog.vue`, `GroupMembersDialog.vue`

There are **NO** frontend views for: alert rules, alert events, notification channels, org-scoped deliveries, reports, saved searches, SSO, AI/NL search, ingest, or org tier. These features have backend endpoints but no frontend consumers yet.

**Consequence:** Tasks 5-12 (alert rules, channels, deliveries, reports, saved searches, SSO, audit log, AI/ingest/tier) have **backend-only** work — contract convergence + spec-only Huma declarations, but no frontend lockstep since there are no consumers. The proposal's lockstep rule ("backend + frontend land together") is satisfied trivially because there's nothing to update on the frontend.

Spec-only Huma declarations are still created for these routes so the typed client is ready when their views are built.

### Existing envelope types and cursor functions: delete when replaced

When a handler's custom envelope type (e.g., `watchlistListResponse`, `alertRuleListResponse`) is replaced by the generic `writeList` helper, **delete the old type**. It's dead code. Similarly, when all consumers of `encodeTimeCursor`/`decodeTimeCursor` have been migrated to the shared `encodeCursor`/`decodeCursor`, delete the old functions from `watchlists.go`.

### Whitespace validation for all string fields

When a handler validates that a required string field is not empty, always use `strings.TrimSpace()` before the check. Testing-pitfalls §4b: `""` and `"   "` are both "empty" from a business perspective.

```go
// WRONG: allows whitespace-only names
if req.Name == "" { ... }

// RIGHT: rejects whitespace-only names
if strings.TrimSpace(req.Name) == "" { ... }

// For pointer PATCH DTOs:
if req.Name != nil && strings.TrimSpace(*req.Name) == "" { ... }
```

### Frontend error and navigation requirements

When converting a view from orgFetch to typed client:

1. **Error states, not blank pages** (testing-pitfalls §12): Every GET call must render an error message on failure — never a blank page or a misleading "no results" empty state. If the existing code has an error rendering pattern, preserve it. If it silently fails (no catch block), add error state rendering.

2. **Org-switch cache invalidation** (testing-pitfalls §12): If the view watches `orgId` or a route param to trigger data refresh, verify this still works after the migration. The typed client uses different reactive patterns than orgFetch.

3. **Mutation error feedback** (testing-pitfalls §12): Every POST/PATCH/DELETE call must show visible error feedback on failure. Read the existing orgFetch error handling and replicate it with the typed client's error shape.

### RBAC regression

For each route family, run existing handler tests after making changes. If a test file exists (e.g., `groups_test.go`), all existing tests must still pass. If no test file exists, at minimum verify one representative endpoint with viewer/member/admin roles.

## Conversion Recipe (reference for all tasks after Task 1)

Each task follows this exact recipe. Task 1 demonstrates it fully; subsequent tasks reference this section.

### Backend conversion steps (per handler file):

1. **Replace `http.Error` with `writeProblem`/`writeProblemWithErrors`:**
   - Malformed JSON from `json.Decoder`: use `decodeJSON(r, &req)` → if non-nil, `writeProblem(w, 400, detail.Message); return`
   - Invalid path params (bad UUID): `writeProblem(w, 400, "invalid {param_name}")`
   - Validation failures (missing/invalid fields): `writeProblemWithErrors(w, 422, "validation failed", &huma.ErrorDetail{Message: "...", Location: "body.field"})` — note: uses `huma.ErrorDetail` directly, not a clone type
   - Not found: `writeProblem(w, 404, "{resource} not found")`
   - Tier limit: `writeProblemTyped(w, 403, problemTypeTierLimit, "...")`
   - Internal error: `writeProblem(w, 500, "internal error")`
   - Conflict: `writeProblem(w, 409, "...")`
   - Rate limit: `writeProblem(w, 429, "...")`

2. **Replace bare array responses with `writeList`:**
   - `writeJSON(w, 200, entries)` → `writeList(w, entries, "")`
   - For paginated endpoints: `writeList(w, entries, nextCursor)`

3. **Replace custom envelope types with `writeList`:**
   - Delete the old `fooListResponse` struct
   - Replace the manual envelope construction with `writeList(w, items, cursor)`

4. **Replace custom cursor functions with shared helpers:**
   - Define a cursor struct in the handler file (e.g., `type watchlistCursor struct { T string \`json:"t"\`; ID string \`json:"id"\` }`)
   - Replace `encodeTimeCursor(t, id)` with `encodeCursor(watchlistCursor{T: t.UTC().Format(time.RFC3339Nano), ID: id.String()})`
   - Replace `decodeTimeCursor(s)` with `decodeCursor(s, &cursor)`
   - Replace `?after_time=&after_id=` params with `?cursor=` param

5. **Add Location header to 201 Created responses:**
   - Before `writeJSON(w, 201, ...)`, call `writeLocation(w, r, resourceID.String())`

6. **Convert PATCH DTOs to pointers** (only where needed — groups, orgs):
   - Change `Name string` → `Name *string \`json:"name,omitempty"\``
   - Update handler to read existing resource, apply non-nil fields, validate non-empty on provided values

### Spec-only Huma declaration steps (per route family):

1. Add a `registerXxxSpecOps(api huma.API)` function in `openapi_spec.go`
2. Define wrapper input/output types that embed the real DTO types
3. Register each operation with `huma.Register(api, huma.Operation{...}, noopHandler[In, Out]())`
4. Add the call to `registerAllSpecOps`

### Frontend conversion steps (only for tasks with existing views):

1. Import `client` from `@/lib/api/client`
2. Replace `orgFetch(url, init)` with the appropriate typed client call
3. For list responses: change `data` or `data as T[]` → `data.items`
4. For error handling: replace `resp.ok` check + `data.detail` with typed `error` from destructured response
5. For mutations: replace `resp.ok` check with `error` check, show `error.detail` in toast/message
6. Run `npm run type-check` to verify type safety

## Route Family Task Map

| Task | Route Family | Backend Files | Frontend Files | Paginated | PATCH DTO Fix |
|------|-------------|---------------|----------------|-----------|---------------|
| 0 | Shared primitives | `contract.go`, `openapi_spec.go` | — | — | — |
| 1 | Groups (reference) | `groups.go` | `GroupsView.vue`, `GroupDialog.vue`, `GroupMembersDialog.vue` | No | Yes (`updateGroupBody`) |
| 2 | Orgs + Members + Invitations | `orgs.go` | `CreateOrgView.vue`, `MembersView.vue`, `InviteMemberDialog.vue` | No | Yes (`updateOrgBody`) |
| 3 | API Keys | `apikeys.go` | *(backend only — preflight check for consumers)* | No | No |
| 4 | Watchlists | `watchlists.go` | `WatchlistListView.vue`, `WatchlistDetailView.vue`, `AddItemDialog.vue`, `CreateWatchlistDialog.vue` | Yes (2) | No (already pointer) |
| 5 | Alert Rules + Events | `alert_rules.go`, `alert_events.go` | *(no views exist yet — backend only)* | Yes (2) | No (already pointer) |
| 6 | Channels | `channels.go` | *(no views exist yet — backend only)* | No | No (already pointer) |
| 7 | Deliveries | `deliveries.go` | *(no views exist yet — backend only)* | Yes (1) | No |
| 8 | Reports | `reports.go` | *(no views exist yet — backend only)* | No | No (already pointer) |
| 9 | Saved Searches | `saved_searches.go` | *(no views exist yet — backend only)* | Partial (execute) | No (already pointer) |
| 10 | SSO + Audit Log | `sso.go`, `audit_log.go` | *(no views exist yet — backend only)* | Yes (audit: 1) | No (already pointer) |
| 11 | AI + Ingest + Org Tier | `ai.go`, `ingest.go`, `org_tier.go` | *(no views exist yet — backend only)* | No | No |
| 12 | Admin feeds + system | `feeds.go`, `admin_system.go` | `AdminFeedsView.vue`, `AdminSystemView.vue`, `AdminDashboardView.vue` (feeds section), `FeedStatusView.vue` | Yes (feed logs: 1) | No |
| 13 | Admin orgs + users + deliveries + audit | `admin_orgs.go`, `admin_users.go`, `admin_deliveries.go`, `admin_helpers.go` | `AdminOrgsView.vue`, `AdminUsersView.vue`, `AdminDeliveriesView.vue`, `AdminDashboardView.vue` (counts), `AdminAuditLogView.vue` | Yes (4) | No |
| 14 | orgFetch elimination + final | `openapi_test.go` | `orgFetch.ts`, `client.ts`, `schema.d.ts` | — | — |

**Note:** Tasks 5-11 are backend-only because no frontend views exist for those route families yet. The spec-only Huma declarations are still created so the typed client is ready when those views are built. The admin Task 13 split reflects that `adminAuditLogHandler` lives in `admin_system.go`, and the admin dashboard view is touched by both Tasks 12 and 13 (different sections).

---

## Task 0: Shared Contract Primitives

**Goal:** Build the foundation helpers that all subsequent tasks depend on. Unit-test them in isolation before any handler uses them.

**Files:**
- Create: `internal/api/contract.go` — RFC 9457 error helpers, JSON decode helper, list envelope helper, cursor helpers
- Create: `internal/api/contract_test.go` — unit tests proving format matches huma
- Create: `internal/api/openapi_spec.go` — spec-only Huma registration infrastructure
- Modify: `internal/api/openapi_test.go` — integrate spec-only API into spec generation

### Step 1: Write failing tests for RFC 9457 error helpers

Create `internal/api/contract_test.go` with tests that verify:

```go
func TestWriteProblem_MatchesHumaFormat(t *testing.T) {
    // Verify our helper produces EXACTLY the same JSON as huma.
    humaErr := huma.Error400BadRequest("name is required")
    humaJSON, _ := json.Marshal(humaErr)

    rec := httptest.NewRecorder()
    writeProblem(rec, http.StatusBadRequest, "name is required")
    chiJSON := rec.Body.Bytes()

    var humaMap, chiMap map[string]any
    if err := json.Unmarshal(humaJSON, &humaMap); err != nil {
        t.Fatalf("unmarshal huma: %v", err)
    }
    if err := json.Unmarshal(chiJSON, &chiMap); err != nil {
        t.Fatalf("unmarshal chi: %v", err)
    }

    // Huma omits "type" (empty + omitempty). Our helper must too.
    if _, hasType := chiMap["type"]; hasType {
        t.Error("writeProblem must NOT emit 'type' field (huma omits it)")
    }

    // Field-for-field comparison of present fields.
    for _, key := range []string{"title", "status", "detail"} {
        if chiMap[key] != humaMap[key] {
            t.Errorf("field %q: got %v, want %v", key, chiMap[key], humaMap[key])
        }
    }

    // Same key set (no extra or missing keys).
    if len(chiMap) != len(humaMap) {
        t.Errorf("key count: got %d, want %d\n  chi: %v\n  huma: %v",
            len(chiMap), len(humaMap), chiMap, humaMap)
    }
}

func TestWriteValidationProblem_MatchesHumaFormat(t *testing.T) {
    humaErr := huma.Error422UnprocessableEntity("validation failed",
        &huma.ErrorDetail{Message: "too short", Location: "body.name", Value: "a"})
    humaJSON, _ := json.Marshal(humaErr)

    rec := httptest.NewRecorder()
    writeProblemWithErrors(rec, http.StatusUnprocessableEntity, "validation failed",
        &huma.ErrorDetail{Message: "too short", Location: "body.name", Value: "a"})
    chiJSON := rec.Body.Bytes()

    var humaMap, chiMap map[string]any
    json.Unmarshal(humaJSON, &humaMap)
    json.Unmarshal(chiJSON, &chiMap)

    // Compare top-level fields.
    for _, key := range []string{"title", "status", "detail"} {
        if chiMap[key] != humaMap[key] {
            t.Errorf("field %q: got %v, want %v", key, chiMap[key], humaMap[key])
        }
    }

    // Compare errors array structure.
    chiErrors, _ := chiMap["errors"].([]any)
    humaErrors, _ := humaMap["errors"].([]any)
    if len(chiErrors) != len(humaErrors) {
        t.Fatalf("errors length: got %d, want %d", len(chiErrors), len(humaErrors))
    }
    chiErr0, _ := chiErrors[0].(map[string]any)
    humaErr0, _ := humaErrors[0].(map[string]any)
    for _, key := range []string{"message", "location", "value"} {
        if fmt.Sprint(chiErr0[key]) != fmt.Sprint(humaErr0[key]) {
            t.Errorf("errors[0].%s: got %v, want %v", key, chiErr0[key], humaErr0[key])
        }
    }
}

func TestWriteProblem_ParityAcrossStatusCodes(t *testing.T) {
    // Verify parity with huma for all status codes used in the API.
    cases := []struct {
        status    int
        detail    string
        humaFunc  func(string, ...error) huma.StatusError
    }{
        {400, "bad request", huma.Error400BadRequest},
        {401, "not authenticated", huma.Error401Unauthorized},
        {403, "forbidden", huma.Error403Forbidden},
        {404, "not found", huma.Error404NotFound},
        {429, "rate limit exceeded", huma.Error429TooManyRequests},
    }
    for _, tc := range cases {
        t.Run(fmt.Sprintf("%d", tc.status), func(t *testing.T) {
            humaErr := tc.humaFunc(tc.detail)
            humaJSON, _ := json.Marshal(humaErr)

            rec := httptest.NewRecorder()
            writeProblem(rec, tc.status, tc.detail)
            chiJSON := rec.Body.Bytes()

            var humaMap, chiMap map[string]any
            json.Unmarshal(humaJSON, &humaMap)
            json.Unmarshal(chiJSON, &chiMap)

            for _, key := range []string{"title", "status", "detail"} {
                if chiMap[key] != humaMap[key] {
                    t.Errorf("field %q: got %v, want %v", key, chiMap[key], humaMap[key])
                }
            }

            // Must have same key set (no extra or missing keys).
            if len(chiMap) != len(humaMap) {
                t.Errorf("key count: got %d, want %d\n  chi: %v\n  huma: %v",
                    len(chiMap), len(humaMap), chiMap, humaMap)
            }
        })
    }
}

func TestWriteProblem_ContentType(t *testing.T) {
    rec := httptest.NewRecorder()
    writeProblem(rec, http.StatusNotFound, "not found")
    if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
        t.Errorf("Content-Type = %q, want application/problem+json", ct)
    }
}

func TestWriteProblemTyped_IncludesType(t *testing.T) {
    rec := httptest.NewRecorder()
    writeProblemTyped(rec, http.StatusForbidden, problemTypeTierLimit, "limit reached")
    var body map[string]any
    json.Unmarshal(rec.Body.Bytes(), &body)
    if body["type"] != problemTypeTierLimit {
        t.Errorf("type = %v, want %s", body["type"], problemTypeTierLimit)
    }
}

func TestDecodeJSON_MalformedInput(t *testing.T) {
    r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
    detail := decodeJSON(r, &struct{}{})
    if detail == nil {
        t.Fatal("expected error detail for malformed JSON")
    }
    if detail.Location != "body" {
        t.Errorf("location = %q, want 'body'", detail.Location)
    }
}

func TestDecodeJSON_ValidInput(t *testing.T) {
    r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
    var dst struct{ Name string `json:"name"` }
    detail := decodeJSON(r, &dst)
    if detail != nil {
        t.Fatalf("unexpected error: %v", detail)
    }
    if dst.Name != "test" {
        t.Errorf("name = %q, want 'test'", dst.Name)
    }
}

func TestWriteList_EmptySlice(t *testing.T) {
    rec := httptest.NewRecorder()
    writeList[string](rec, nil, "")
    var body map[string]any
    json.Unmarshal(rec.Body.Bytes(), &body)
    items, ok := body["items"].([]any)
    if !ok {
        t.Fatal("items is not an array")
    }
    if len(items) != 0 {
        t.Errorf("items length = %d, want 0", len(items))
    }
    if _, hasCursor := body["next_cursor"]; hasCursor {
        t.Error("next_cursor should be omitted when empty")
    }
}

func TestWriteList_WithCursor(t *testing.T) {
    rec := httptest.NewRecorder()
    writeList(rec, []string{"a", "b"}, "abc123")
    var body map[string]any
    json.Unmarshal(rec.Body.Bytes(), &body)
    if body["next_cursor"] != "abc123" {
        t.Errorf("next_cursor = %v, want 'abc123'", body["next_cursor"])
    }
}

func TestCursorRoundTrip(t *testing.T) {
    type testCursor struct {
        T  string `json:"t"`
        ID string `json:"id"`
    }
    orig := testCursor{T: "2026-01-01T00:00:00Z", ID: "abc-123"}
    encoded := encodeCursor(orig)
    if encoded == "" {
        t.Fatal("encodeCursor returned empty")
    }
    var decoded testCursor
    if err := decodeCursor(encoded, &decoded); err != nil {
        t.Fatalf("decodeCursor: %v", err)
    }
    if decoded != orig {
        t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, orig)
    }
}

func TestEncodeCursor_NoPadding(t *testing.T) {
    // encodeCursor must use RawURLEncoding (no '=' padding), matching
    // the existing Huma CVE cursor format in cves.go.
    type cur struct {
        T  string `json:"t"`
        ID string `json:"id"`
    }
    encoded := encodeCursor(cur{T: "2026-01-01T00:00:00Z", ID: "abc"})
    if strings.Contains(encoded, "=") {
        t.Errorf("cursor contains padding: %q", encoded)
    }
}

func TestDecodeCursor_Invalid(t *testing.T) {
    var dst struct{}
    if err := decodeCursor("not-base64!!!", &dst); err == nil {
        t.Error("expected error for invalid base64")
    }
    if err := decodeCursor(base64.RawURLEncoding.EncodeToString([]byte("not-json")), &dst); err == nil {
        t.Error("expected error for invalid JSON inside base64")
    }
}

func TestDecodeCursor_AcceptsPaddedFallback(t *testing.T) {
    // Backward compatibility: decodeCursor should accept padded cursors
    // issued before the encoding was standardized.
    type cur struct {
        T  string `json:"t"`
        ID string `json:"id"`
    }
    orig := cur{T: "2026-01-01T00:00:00Z", ID: "abc"}
    padded := base64.URLEncoding.EncodeToString(mustJSON(orig))
    var decoded cur
    if err := decodeCursor(padded, &decoded); err != nil {
        t.Fatalf("decodeCursor should accept padded: %v", err)
    }
    if decoded != orig {
        t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, orig)
    }
}

func TestParseLimitParam(t *testing.T) {
    t.Run("missing returns default", func(t *testing.T) {
        r := httptest.NewRequest(http.MethodGet, "/", nil)
        rec := httptest.NewRecorder()
        limit, ok := parseLimitParam(rec, r, 50, 200)
        if !ok || limit != 50 {
            t.Errorf("got (%d, %v), want (50, true)", limit, ok)
        }
    })
    t.Run("valid value", func(t *testing.T) {
        r := httptest.NewRequest(http.MethodGet, "/?limit=25", nil)
        rec := httptest.NewRecorder()
        limit, ok := parseLimitParam(rec, r, 50, 200)
        if !ok || limit != 25 {
            t.Errorf("got (%d, %v), want (25, true)", limit, ok)
        }
    })
    t.Run("exceeds max", func(t *testing.T) {
        r := httptest.NewRequest(http.MethodGet, "/?limit=999", nil)
        rec := httptest.NewRecorder()
        _, ok := parseLimitParam(rec, r, 50, 200)
        if ok {
            t.Error("expected failure for limit > max")
        }
        if rec.Code != http.StatusBadRequest {
            t.Errorf("status = %d, want 400", rec.Code)
        }
    })
}
```

### Step 2: Run tests to verify they fail

```bash
go test ./internal/api/ -run TestWriteProblem -v -count=1
```

Expected: compilation errors (functions don't exist yet).

### Step 3: Implement shared helpers in `contract.go`

**Important:** `writeJSON` already exists in `orgs.go` and is used by all handler files. Do NOT redefine it in `contract.go`. The helpers below call `writeJSON` for success responses (via `writeList`) and write directly for problem responses.

```go
// ABOUTME: Shared contract helpers for Chi JSON handlers.
// ABOUTME: Produces RFC 9457 Problem Details using huma's ErrorModel/ErrorDetail types directly.
package api

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "strings"

    "github.com/danielgtaylor/huma/v2"
)

// writeProblem writes an RFC 9457 Problem Details response using huma's ErrorModel.
// Does NOT set the "type" field — huma omits it via omitempty, so we must too.
func writeProblem(w http.ResponseWriter, status int, detail string) {
    w.Header().Set("Content-Type", "application/problem+json")
    w.WriteHeader(status)
    resp := huma.ErrorModel{
        Title:  http.StatusText(status),
        Status: status,
        Detail: detail,
    }
    if err := json.NewEncoder(w).Encode(resp); err != nil {
        slog.Error("writeProblem: encode failed", "error", err)
    }
}

// writeProblemWithErrors writes an RFC 9457 response with field-level error details.
// Uses huma.ErrorDetail directly — no custom clone types.
func writeProblemWithErrors(w http.ResponseWriter, status int, detail string, errs ...*huma.ErrorDetail) {
    w.Header().Set("Content-Type", "application/problem+json")
    w.WriteHeader(status)
    resp := huma.ErrorModel{
        Title:  http.StatusText(status),
        Status: status,
        Detail: detail,
        Errors: errs,
    }
    if err := json.NewEncoder(w).Encode(resp); err != nil {
        slog.Error("writeProblemWithErrors: encode failed", "error", err)
    }
}

// writeProblemTyped writes an RFC 9457 response with a custom problem type URI.
// Used for tier-limit failures to distinguish from RBAC 403s.
func writeProblemTyped(w http.ResponseWriter, status int, problemType, detail string) {
    w.Header().Set("Content-Type", "application/problem+json")
    w.WriteHeader(status)
    resp := huma.ErrorModel{
        Type:   problemType,
        Title:  http.StatusText(status),
        Status: status,
        Detail: detail,
    }
    if err := json.NewEncoder(w).Encode(resp); err != nil {
        slog.Error("writeProblemTyped: encode failed", "error", err)
    }
}

// Tier-limit problem type URI (Finding 34).
const problemTypeTierLimit = "urn:cvert:error:tier-limit"

// decodeJSON decodes JSON from the request body into dst.
// Returns a *huma.ErrorDetail on malformed JSON, nil on success.
// The caller is responsible for semantic validation after decode.
func decodeJSON(r *http.Request, dst any) *huma.ErrorDetail {
    if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
        return &huma.ErrorDetail{
            Message:  fmt.Sprintf("invalid JSON: %s", err.Error()),
            Location: "body",
        }
    }
    return nil
}

// listResponse is the standard list envelope for all endpoints.
type listResponse[T any] struct {
    Items      []T    `json:"items"`
    NextCursor string `json:"next_cursor,omitempty"`
}

// writeList writes a list response in the standard envelope.
func writeList[T any](w http.ResponseWriter, items []T, nextCursor string) {
    // Ensure items is never null in JSON output.
    if items == nil {
        items = []T{}
    }
    writeJSON(w, http.StatusOK, listResponse[T]{
        Items:      items,
        NextCursor: nextCursor,
    })
}

// encodeCursor encodes cursor fields as opaque base64url JSON (no padding).
// Uses RawURLEncoding to match the existing Huma CVE cursor format in cves.go.
func encodeCursor(v any) string {
    raw, err := json.Marshal(v)
    if err != nil {
        return ""
    }
    return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeCursor decodes an opaque base64url JSON cursor into dst.
// Tries RawURLEncoding first (canonical). Falls back to padded URLEncoding
// for cursors issued before the encoding was standardized.
func decodeCursor(s string, dst any) error {
    raw, err := base64.RawURLEncoding.DecodeString(s)
    if err != nil {
        // Fallback: try padded URLEncoding for backward compatibility.
        raw, err = base64.URLEncoding.DecodeString(s)
        if err != nil {
            return fmt.Errorf("invalid cursor encoding: %w", err)
        }
    }
    if err := json.Unmarshal(raw, dst); err != nil {
        return fmt.Errorf("invalid cursor format: %w", err)
    }
    return nil
}

// parseLimitParam extracts and validates the limit query parameter.
// Returns the default if not specified, or writes a problem response and
// returns 0, false on invalid input.
func parseLimitParam(w http.ResponseWriter, r *http.Request, defaultLimit, maxLimit int) (int, bool) {
    s := r.URL.Query().Get("limit")
    if s == "" {
        return defaultLimit, true
    }
    var limit int
    if _, err := fmt.Sscanf(s, "%d", &limit); err != nil || limit < 1 || limit > maxLimit {
        writeProblem(w, http.StatusBadRequest,
            fmt.Sprintf("invalid limit: must be 1-%d", maxLimit))
        return 0, false
    }
    return limit, true
}

// writeLocation sets the Location header for 201 Created responses.
func writeLocation(w http.ResponseWriter, r *http.Request, pathSuffix string) {
    // Build location relative to the current request path.
    loc := strings.TrimSuffix(r.URL.Path, "/") + "/" + pathSuffix
    w.Header().Set("Location", loc)
}
```

### Step 4: Run tests to verify they pass

```bash
go test ./internal/api/ -run "TestWriteProblem|TestDecodeJSON|TestWriteList|TestCursor|TestParseLimit" -v -count=1
```

### Step 5: Implement spec-only Huma infrastructure

Create `internal/api/openapi_spec.go`:

```go
// ABOUTME: Spec-only Huma operation declarations for Chi-backed routes.
// ABOUTME: Generates OpenAPI specs without affecting production routing or middleware.
package api

import (
    "context"
    "net/http"

    "github.com/danielgtaylor/huma/v2"
    "github.com/danielgtaylor/huma/v2/adapters/humachi"
    "github.com/go-chi/chi/v5"
)

// noopHandler returns a huma handler that does nothing. Used for spec-only
// operation declarations where no request will ever be routed.
func noopHandler[I, O any]() func(context.Context, *I) (*O, error) {
    return func(context.Context, *I) (*O, error) {
        return nil, nil
    }
}

// newSpecOnlyAPI creates a throwaway Huma API instance for spec generation.
// Operations registered here produce OpenAPI path/schema entries but never
// handle real HTTP traffic.
func newSpecOnlyAPI() (huma.API, *chi.Mux) {
    r := chi.NewMux()
    api := humachi.New(r, huma.DefaultConfig("CVErt Ops Spec-Only", "0.0.0"))
    return api, r
}

// registerAllSpecOps registers spec-only declarations for all Chi-backed
// route families. Called during OpenAPI spec generation to produce a merged spec.
func registerAllSpecOps(api huma.API) {
    registerGroupsSpecOps(api)
    // Each subsequent task adds its registration call here:
    // registerOrgsSpecOps(api)
    // registerWatchlistsSpecOps(api)
    // registerAlertRulesSpecOps(api)
    // etc.
}

// mergeSpecPaths copies paths and component schemas from a spec-only API
// into the production OpenAPI document.
//
// Collision rules:
// - Path collision: panics. A spec-only path that already exists in the production
//   spec is a bug (the route should be on Huma, not spec-only).
// - Schema collision: compares JSON serialization. Identical schemas are deduplicated
//   (e.g., ErrorModel). Semantically different schemas with the same name are a bug
//   and cause a panic. This prevents silent overwrites.
func mergeSpecPaths(prod, specOnly huma.API) {
    prodSpec := prod.OpenAPI()
    soSpec := specOnly.OpenAPI()

    if prodSpec.Paths == nil {
        prodSpec.Paths = map[string]*huma.PathItem{}
    }
    for path, item := range soSpec.Paths {
        if _, exists := prodSpec.Paths[path]; exists {
            panic(fmt.Sprintf("mergeSpecPaths: path collision on %q — route exists in both production and spec-only APIs", path))
        }
        prodSpec.Paths[path] = item
    }

    if prodSpec.Components == nil {
        prodSpec.Components = &huma.Components{}
    }
    if prodSpec.Components.Schemas == nil {
        prodSpec.Components.Schemas = huma.NewMapRegistry("#/components/schemas/", huma.DefaultSchemaNamer)
    }
    if soSpec.Components != nil && soSpec.Components.Schemas != nil {
        soSchemas := soSpec.Components.Schemas.Map()
        existing := prodSpec.Components.Schemas.Map()
        for name, schema := range soSchemas {
            if existingSchema, exists := existing[name]; exists {
                // Collision: compare schemas. Identical = safe dedup. Different = bug.
                existingJSON, _ := json.Marshal(existingSchema)
                newJSON, _ := json.Marshal(schema)
                if string(existingJSON) != string(newJSON) {
                    panic(fmt.Sprintf("mergeSpecPaths: schema collision on %q — same name, different definition", name))
                }
                continue // identical, skip
            }
            existing[name] = schema
        }
    }
}
```

### Step 6: Update `openapi_test.go` to use spec merge

Modify `internal/api/openapi_test.go` to create the spec-only API, register all spec ops, and merge before writing:

```go
// After getting the production spec from the server...
// Create spec-only API and register Chi route declarations.
specAPI, _ := newSpecOnlyAPI()
registerAllSpecOps(specAPI)

// Merge spec-only paths/schemas into production spec.
mergeSpecPaths(srv.humaAPI, specAPI)

// Re-fetch the merged spec for validation and output.
```

The exact integration depends on how `srv.humaAPI` is exposed — may need a `HumaAPI()` accessor method on `Server`.

**Merge tests to add in `openapi_test.go` or `contract_test.go`:**

```go
func TestMergeSpecPaths_NoDuplicatePaths(t *testing.T) {
    // Verify merged spec has no path that appears in both APIs.
    // mergeSpecPaths panics on collision — this test confirms no panic.
    specAPI, _ := newSpecOnlyAPI()
    registerAllSpecOps(specAPI)
    // If this doesn't panic, there are no collisions.
}

func TestMergeSpecPaths_StableGeneration(t *testing.T) {
    // Run merge twice, compare output — must be identical.
    // Ensures no map iteration order randomness affects the spec.
}

func TestMergedSpec_FrontendTypegenSucceeds(t *testing.T) {
    // GENERATE_OPENAPI=1 produces a valid spec that openapi-typescript
    // can consume. Verified by running npx openapi-typescript in CI.
}
```

### Step 7: Run all tests

```bash
go test ./internal/api/ -v -count=1
```

### Step 8: Commit

```bash
git add internal/api/contract.go internal/api/contract_test.go \
       internal/api/openapi_spec.go internal/api/openapi_test.go
git commit -m "feat(api): add shared contract primitives for API convergence

RFC 9457 error helpers, JSON decode helper, list envelope,
cursor encode/decode, limit parser, Location header helper,
and spec-only Huma infrastructure for OpenAPI generation."
```

---

## Task 1: Groups (Reference Family)

**Goal:** Apply all shared primitives to the groups route family as the reference implementation. This task establishes the exact pattern every subsequent task follows.

**Files:**
- Modify: `internal/api/groups.go` — replace `http.Error` with `writeProblem`, bare arrays with `writeList`, add `writeLocation`, convert PATCH DTO to pointers
- Modify: `internal/api/openapi_spec.go` — add `registerGroupsSpecOps()`
- Modify/Create: `internal/api/groups_test.go` — handler tests for converged contract
- Modify: `web/src/views/GroupsView.vue` — switch from `orgFetch` to typed client
- Modify: `web/src/components/settings/GroupDialog.vue` — switch to typed client
- Modify: `web/src/components/settings/GroupMembersDialog.vue` — switch to typed client
- Regenerate: `web/src/lib/api/schema.d.ts` — from merged openapi.json

### Step 1: Write failing handler tests

Test the converged contract for each endpoint in the groups family:

```go
// TestGroupsContract verifies the converged API contract for groups endpoints.
func TestGroupsContract(t *testing.T) {
    t.Run("create returns RFC 9457 on invalid JSON", func(t *testing.T) {
        // POST with malformed JSON → 400, Content-Type: application/problem+json
        // Body contains {type, title, status, detail}
    })

    t.Run("create returns RFC 9457 on missing name", func(t *testing.T) {
        // POST with {} → 422, errors[].location = "body.name"
    })

    t.Run("create returns 201 with Location header", func(t *testing.T) {
        // POST with valid body → 201, Location: /api/v1/orgs/{org_id}/groups/{id}
    })

    t.Run("list returns envelope not bare array", func(t *testing.T) {
        // GET → 200, {"items": [...]} (not bare array)
    })

    t.Run("patch with omitted name preserves existing", func(t *testing.T) {
        // PATCH with {"description": "new"} → name unchanged (pointer DTO)
    })

    t.Run("patch with empty name returns 422", func(t *testing.T) {
        // PATCH with {"name": ""} → 422 (explicit empty string, not omitted)
    })

    t.Run("get nonexistent returns RFC 9457 404", func(t *testing.T) {
        // GET with unknown UUID → 404, application/problem+json
    })

    t.Run("list members returns envelope", func(t *testing.T) {
        // GET /groups/{id}/members → {"items": [...]}
    })
}
```

### Step 2: Convert `updateGroupBody` to pointer-based DTO

```go
// Before:
type updateGroupBody struct {
    Name        string `json:"name"`
    Description string `json:"description"`
}

// After:
type updateGroupBody struct {
    Name        *string `json:"name,omitempty"`
    Description *string `json:"description,omitempty"`
}
```

Update `updateGroupHandler` to handle pointer semantics: read existing group first, apply only non-nil fields, validate that `*Name` is not empty string if provided.

### Step 3: Convert all `http.Error` calls in `groups.go`

Replace every `http.Error(w, msg, status)` with the appropriate helper:

| Current | Replacement |
|---------|------------|
| `http.Error(w, "bad request", 400)` | `writeProblem(w, 400, "bad request")` |
| `http.Error(w, "invalid request body", 400)` | `writeProblem(w, 400, decodeErr.Message)` where decodeErr from `decodeJSON` |
| `http.Error(w, "name is required", 400)` | `writeProblemWithErrors(w, 422, "validation failed", &huma.ErrorDetail{Message: "name is required", Location: "body.name"})` |
| `http.Error(w, "invalid group_id", 400)` | `writeProblem(w, 400, "invalid group_id")` |
| `http.Error(w, "not found", 404)` | `writeProblem(w, 404, "group not found")` |
| `http.Error(w, "internal error", 500)` | `writeProblem(w, 500, "internal error")` |

### Step 4: Convert list responses to envelopes

```go
// Before (listGroupsHandler):
writeJSON(w, http.StatusOK, entries)

// After:
writeList(w, entries, "")  // no pagination → no cursor
```

Same for `listGroupMembersHandler`.

### Step 5: Add Location header to create

```go
// In createGroupHandler, before writeJSON:
writeLocation(w, r, group.ID.String())
writeJSON(w, http.StatusCreated, groupEntry{...})
```

### Step 6: Add `registerGroupsSpecOps` to `openapi_spec.go`

Based on the gate POC pattern. Wrapper types embed existing DTOs:

```go
func registerGroupsSpecOps(api huma.API) {
    type createGroupInput struct {
        OrgID string          `path:"org_id" format:"uuid"`
        Body  createGroupBody `json:"body"`
    }
    type createGroupOutput struct {
        Header http.Header `header:"Location"`
        Body   groupEntry
    }
    huma.Register(api, huma.Operation{
        OperationID: "create-group",
        Method:      http.MethodPost,
        Path:        "/orgs/{org_id}/groups",
        Summary:     "Create group",
        Tags:        []string{"Groups"},
    }, noopHandler[createGroupInput, createGroupOutput]())

    // ... register all 8 operations (list, get, update, delete, list-members, add-member, remove-member)
}
```

### Step 7: Regenerate OpenAPI spec and TypeScript types

```bash
GENERATE_OPENAPI=1 go test ./internal/api/ -run TestOpenAPISpec -v -count=1
cd web && npx openapi-typescript ../openapi.json -o src/lib/api/schema.d.ts
```

### Step 8: Update frontend — switch from orgFetch to typed client

**`GroupsView.vue`:**
```typescript
// Before:
const resp = await orgFetch(`/api/v1/orgs/${orgId}/groups`)
const data = await resp.json() as GroupEntry[]

// After:
const { data, error } = await client.GET('/orgs/{org_id}/groups', {
  params: { path: { org_id: orgId } }
})
if (error) { /* handle RFC 9457 error */ return }
const groups = data.items  // list envelope
```

**`GroupDialog.vue`:** Switch create/update calls from orgFetch to `client.POST`/`client.PATCH`. Error handling reads `error.detail` from the typed RFC 9457 response.

**`GroupMembersDialog.vue`:** Switch member list, add, remove calls.

### Step 9: Run full test suite

```bash
go test ./internal/api/ -v -count=1
cd web && npm run test:unit && npm run type-check
```

### Step 10: Commit

```bash
git add internal/api/groups.go internal/api/groups_test.go \
       internal/api/openapi_spec.go internal/api/openapi_test.go \
       openapi.json web/src/lib/api/schema.d.ts \
       web/src/views/GroupsView.vue \
       web/src/components/settings/GroupDialog.vue \
       web/src/components/settings/GroupMembersDialog.vue
git commit -m "feat(api): converge groups route family to unified contract

Replace http.Error with RFC 9457 writeProblem helpers, convert list
responses to {items} envelope, add Location header on 201, convert
updateGroupBody to pointer DTO, register spec-only Huma declarations,
switch frontend from orgFetch to typed openapi-fetch client."
```

---

## Task 2: Orgs + Members + Invitations

**Files:**
- Modify: `internal/api/orgs.go`
- Modify: `internal/api/openapi_spec.go` — add `registerOrgsSpecOps()`
- Modify/Create: `internal/api/orgs_test.go`
- Modify: `web/src/views/CreateOrgView.vue`
- Modify: `web/src/views/MembersView.vue`
- Modify: `web/src/components/settings/InviteMemberDialog.vue`

**PATCH DTO fix:** Convert `updateOrgBody` to pointer-based:
```go
// Before:
type updateOrgBody struct {
    Name string `json:"name"`
}
// After:
type updateOrgBody struct {
    Name *string `json:"name,omitempty"`
}
```

`updateMemberRoleBody` stays non-pointer — role is required, not optional.

**List response changes:**
- `listMembersHandler`: bare array → `writeList(w, entries, "")` (no pagination)
- `listInvitationsHandler`: bare array → `writeList(w, entries, "")` (no pagination)

**Status code changes:**
- Create org: 201 + Location header
- Create invitation: 202 (stays — async semantics) + Location header
- Validation errors: 400 → 422 with `huma.ErrorDetail` where applicable

**Frontend:** `MembersView.vue` currently parses bare arrays for members and invitations. Switch to `data.items` from typed client. `CreateOrgView.vue` and `InviteMemberDialog.vue` switch from orgFetch to typed client with RFC 9457 error handling.

**Commit boundary:** All orgs.go changes + all 3 frontend files in one commit.

**Pattern:** Follow Task 1 exactly — same helper calls, same test structure, same frontend migration pattern.

---

## Task 3: API Keys

**Files:**
- Modify: `internal/api/apikeys.go`
- Modify: `internal/api/openapi_spec.go` — add `registerAPIKeysSpecOps()`
- Modify/Create: `internal/api/apikeys_test.go`

**Frontend:** Backend-only. Preflight check: run `rg "apikey\|api-key\|api_key" web/src/ --glob "*.{ts,vue}" -l` to confirm no dedicated API key UI exists. If a consumer is found, convert it; if not (expected), skip frontend work for this task.

**List response:** `listAPIKeysHandler` returns bare array → `writeList(w, entries, "")`

**Create:** `createAPIKeyHandler` returns 201 → add Location header.

**Error handling:** Replace all `http.Error` with `writeProblem`. The privilege escalation check (member trying to create admin key) should be 403.

**Commit boundary:** apikeys.go + spec in one commit.

---

## Task 4: Watchlists

**Files:**
- Modify: `internal/api/watchlists.go` — replace cursor format, use shared helpers
- Modify: `internal/api/openapi_spec.go` — add `registerWatchlistsSpecOps()`
- Modify/Create: `internal/api/watchlists_test.go`
- Modify: `web/src/views/WatchlistListView.vue`
- Modify: `web/src/views/WatchlistDetailView.vue`
- Modify: `web/src/components/watchlist/AddItemDialog.vue`
- Modify: `web/src/components/watchlist/CreateWatchlistDialog.vue`

**Cursor migration (critical):**

Replace `encodeTimeCursor`/`decodeTimeCursor` (pipe-separated, base64) with shared `encodeCursor`/`decodeCursor` (JSON, base64url):

```go
// Watchlist cursor (internal — opaque to clients)
type watchlistCursor struct {
    T  string `json:"t"`  // created_at RFC3339Nano
    ID string `json:"id"` // UUID tiebreaker
}
```

Both `listWatchlistsHandler` (created_at DESC, id DESC) and `listWatchlistItemsHandler` (id ASC) need cursor conversion. They use different sort orders, so they need different cursor types or at minimum different decode logic.

**Response envelope:** Watchlists already use `watchlistListResponse` and `watchlistItemsResponse` envelopes. Rename/replace them with `writeList[watchlistEntry]` and `writeList[watchlistItemEntry]` using the generic helper.

**Status codes:** `createWatchlistItemHandler` already uses 422 for validation — keep it but use `writeProblemWithErrors`.

**Tier-limit response (Finding 34):** `createWatchlistHandler` returns 403 for tier limits. Change to `writeProblemTyped(w, 403, problemTypeTierLimit, "watchlist limit reached for current tier")` to distinguish from RBAC 403.

**Location headers:** Add to `createWatchlistHandler` (201) and `createWatchlistItemHandler` (201).

**Frontend:** `WatchlistListView.vue` currently reads `{items?: WatchlistEntry[]}` — already close to envelope format but uses optional items. Switch to typed client. `WatchlistDetailView.vue` handles 404 with `notFound` flag — adapt to RFC 9457 error parsing.

**Testing:** Cursor tests are especially important here (requirement #6): malformed cursor → 400, page boundary with exactly limit results, empty final page, cursor from different endpoint type rejected.

**Commit boundary:** watchlists.go + 4 frontend files + spec.

---

## Task 5: Alert Rules + Alert Events (backend only — no frontend views exist)

**Files:**
- Modify: `internal/api/alert_rules.go`
- Modify: `internal/api/alert_events.go`
- Modify: `internal/api/openapi_spec.go` — add `registerAlertRulesSpecOps()`, `registerAlertEventsSpecOps()`
- Modify/Create: `internal/api/alert_rules_test.go`, `internal/api/alert_events_test.go`

**Cursor:** Alert rules and events both use `encodeTimeCursor`/`decodeTimeCursor`. Replace with shared cursor helper (same pattern as Task 4).

**Existing envelopes:** Both already use envelope responses (`alertRuleListResponse`, `alertEventsListResponse`). Replace with `writeList`.

**Complex validation:** `createAlertRuleHandler` and `updateAlertRuleHandler` have validation error formatting via `valErrsToEntries()`. Convert these to `&huma.ErrorDetail{...}` entries and use `writeProblemWithErrors(w, 422, "validation failed", ...)`.

**Tier limit:** Alert rule creation is tier-gated. Use `writeProblemTyped` with `problemTypeTierLimit`.

**Status 202:** `createAlertRuleHandler` returns 202 when rule status is "activating". This stays — it's correct async semantics. Add Location header.

**Location headers:** Add to create (201/202).

**Alert events are read-only:** Just error format conversion and cursor migration.

**Commit boundary:** Both files + spec in one commit (same domain).

---

## Task 6: Channels (backend only — no frontend views exist)

**Files:**
- Modify: `internal/api/channels.go`
- Modify: `internal/api/openapi_spec.go` — add `registerChannelsSpecOps()`
- Modify/Create: `internal/api/channels_test.go`

**Already pointer PATCH:** `patchChannelBody` already uses `*string`, `*json.RawMessage`.

**Existing envelope:** `channelListResponse` already wraps items. Replace with `writeList`.

**Tier limit:** `createChannelHandler` is tier-gated → `writeProblemTyped`.

**Validation:** `validateWebhookURL` and `validateEmailConfig` return errors → convert to `writeProblemWithErrors` with field-level details.

**Secret operations:** `rotateSecretHandler` and `clearSecondarySecretHandler` return 422 for non-webhook channels → use `writeProblem(w, 422, ...)`.

**409 on delete with active bindings:** Already correct status, just format with `writeProblem`.

**Location header:** Add to `createChannelHandler` (201).

**Commit boundary:** channels.go + spec in one commit.

---

## Task 7: Deliveries (backend only — no org-scoped frontend views exist)

**Files:**
- Modify: `internal/api/deliveries.go`
- Modify: `internal/api/openapi_spec.go` — add `registerDeliveriesSpecOps()`
- Modify/Create: `internal/api/deliveries_test.go`

**Cursor migration (critical):** `encodeDeliveryCursor` uses a different format (`RFC3339Nano/uuid`, NOT base64). Replace with shared cursor helper:

```go
type deliveryCursor struct {
    T  string `json:"t"`  // created_at RFC3339Nano
    ID string `json:"id"` // UUID tiebreaker
}
```

**Breaking change for clients using raw cursor values:** Since cursors are opaque, this should be transparent — but clients must not persist cursors across deployments. The test should verify that old-format cursors are rejected cleanly (400, not panic).

**Query param migration:** The current handler uses `after_created_at` and `after_id` as separate query params (Finding 43 — broken delivery cursor contract). Replace with `?cursor=<opaque>&limit=N`. The `rule_id`, `channel_id`, and `status` filter params stay.

**429 on replay:** Already correct. Format with `writeProblem`.

**Commit boundary:** deliveries.go + spec in one commit.

---

## Task 8: Reports (backend only — no frontend views exist)

**Files:**
- Modify: `internal/api/reports.go`
- Modify: `internal/api/openapi_spec.go` — add `registerReportsSpecOps()`
- Modify/Create: `internal/api/reports_test.go`

**Already pointer PATCH:** `patchReportBody` uses pointers.

**Existing envelopes:** `reportListResponse` and `channelListResponse` already wrap items. Replace with `writeList`.

**Validation:** Timezone, scheduled_time, severity_threshold validation → convert to `writeProblemWithErrors` with field-level details.

**Location header:** Add to `createReportHandler` (201).

**Channel binding sub-resources:** `bindChannelToReportHandler` (PUT, 204), `unbindChannelFromReportHandler` (DELETE, 204) — just error format conversion.

**Commit boundary:** reports.go + spec in one commit.

---

## Task 9: Saved Searches (backend only — no frontend views exist)

**Files:**
- Modify: `internal/api/saved_searches.go`
- Modify: `internal/api/openapi_spec.go` — add `registerSavedSearchesSpecOps()`
- Modify/Create: `internal/api/saved_searches_test.go`

**List response:** `listSavedSearchesHandler` returns bare array → `writeList`.

**Execute sub-route:** `executeSavedSearchHandler` has cursor-based pagination (`?cursor=&limit=`). Already uses its own cursor format — convert to shared helper.

**Access control errors:** Private saved search access returns 403/404 → format with `writeProblem`.

**DSL validation:** Re-validates DSL on PATCH → convert validation errors to `writeProblemWithErrors`.

**Location header:** Add to `createSavedSearchHandler` (201).

**Commit boundary:** saved_searches.go + spec in one commit.

---

## Task 10: SSO + Audit Log (backend only — no frontend views exist)

**Files:**
- Modify: `internal/api/sso.go`
- Modify: `internal/api/audit_log.go`
- Modify: `internal/api/openapi_spec.go` — add `registerSSOSpecOps()`, `registerAuditLogSpecOps()`
- Modify/Create: `internal/api/sso_test.go`, `internal/api/audit_log_test.go`

**SSO:**
- `createSSOBody.Enabled` is `*bool`, `patchSSOBody` uses pointers — already correct.
- Enterprise gate: Tier check returns 403 → `writeProblemTyped(w, 403, problemTypeTierLimit, ...)`.
- URL validation, scope validation → `writeProblemWithErrors`.
- `putSSODomainsHandler` (PUT) — just error format conversion.

**Audit Log (org-scoped — `/orgs/{org_id}/audit-log`):**
- Cursor migration: Uses `encodeTimeCursor`/`decodeTimeCursor` → shared cursor helper.
- Existing envelope: `auditLogListResponse` already wraps items. Replace with `writeList`. Delete old `auditLogListResponse` type.
- Enterprise gate: Returns 403 for non-enterprise → `writeProblemTyped`.
- **Note:** After this task, if `encodeTimeCursor`/`decodeTimeCursor` have no remaining consumers (check alert_rules.go, alert_events.go, watchlists.go from Tasks 4-5), delete them from `watchlists.go`.

**Commit boundary:** Both files in one commit.

---

## Task 11: AI + Ingest + Org Tier (backend only — no frontend views exist)

**Files:**
- Modify: `internal/api/ai.go`
- Modify: `internal/api/ingest.go`
- Modify: `internal/api/org_tier.go`
- Modify: `internal/api/openapi_spec.go` — add `registerAISpecOps()`, `registerIngestSpecOps()`, `registerOrgTierSpecOps()`
- Modify/Create: tests for each

**AI handlers:**
- `nlSearchHandler`: Tier-gated (daily quota) → `writeProblemTyped` for tier limit, `writeProblem` for other errors. Response is a search result object — no list envelope needed.
- `summarizeHandler`: Tier-gated → same pattern.

**Ingest handler:**
- `ingestHandler`: Validates CVE ID format, patch count limits → `writeProblemWithErrors` with per-patch validation errors. Tier-gated → `writeProblemTyped`.

**Org tier:**
- `getOrgTierHandler`: Read-only, returns single object. Just error format conversion.

**Also:** Replace `parseIntParam` in `saved_searches.go` with the shared `parseLimitParam` from `contract.go` if not already done in Task 9. If done in Task 9, skip here.

**Commit boundary:** All three files in one commit.

---

## Task 12: Admin Feeds + System

**Files:**
- Modify: `internal/api/feeds.go`
- Modify: `internal/api/admin_system.go` — includes `adminAuditLogHandler`, `adminReindexHandler`, `adminConfigHandler`
- Modify: `internal/api/openapi_spec.go` — add `registerAdminFeedsSpecOps()`, `registerAdminSystemSpecOps()`
- Modify/Create: tests for admin feed and system handlers
- Modify: `web/src/views/admin/AdminFeedsView.vue`
- Modify: `web/src/views/admin/AdminSystemView.vue`
- Modify: `web/src/views/admin/AdminDashboardView.vue` (feeds section only)
- Modify: `web/src/views/FeedStatusView.vue`

**Feed list envelope:** `listFeedsHandler` returns `{"feeds": [...]}` → normalize to `{"items": [...]}`. Frontend currently reads `.feeds` — update to `.items`.

**Feed logs pagination:** `feedLogsHandler` uses `parseKeysetParams` → convert to shared cursor helper.

**Admin system:** `adminReindexHandler` (409 on duplicate), `adminConfigHandler` (no error path) — just error format conversion.

**Admin audit log** (`adminAuditLogHandler` in `admin_system.go`): Uses `parseKeysetParams` → convert to shared cursor helper. This is a separate handler from the org-scoped `listAuditLogHandler` in `audit_log.go`.

**Frontend:** Switch all admin feed views from orgFetch to typed client. `FeedStatusView.vue` also uses orgFetch for feed status/trigger — convert.

**Commit boundary:** feeds.go + admin_system.go + 4 frontend files in one commit.

---

## Task 13: Admin Orgs + Users + Deliveries

**Files:**
- Modify: `internal/api/admin_orgs.go`
- Modify: `internal/api/admin_users.go`
- Modify: `internal/api/admin_deliveries.go`
- Modify: `internal/api/admin_helpers.go` — `parseKeysetParams` can be deleted after this task if all consumers are migrated
- Modify: `internal/api/openapi_spec.go` — add `registerAdminOrgsSpecOps()`, `registerAdminUsersSpecOps()`, `registerAdminDeliveriesSpecOps()`
- Modify/Create: tests for admin handlers
- Modify: `web/src/views/admin/AdminOrgsView.vue`
- Modify: `web/src/views/admin/AdminUsersView.vue`
- Modify: `web/src/views/admin/AdminDeliveriesView.vue`
- Modify: `web/src/views/admin/AdminDashboardView.vue` (counts section)
- Modify: `web/src/views/admin/AdminAuditLogView.vue`

**Cursor migration (critical):** All three list endpoints use `parseKeysetParams` with separate `after_time`/`after_id` query params. Replace with `?cursor=<opaque>&limit=N` pattern.

**Admin deliveries:** `adminListDeliveriesHandler`, `adminRetryDeliveryHandler`, `adminBulkRetryDeliveriesHandler`. List already uses `{items, has_more}` envelope. Normalize to `{items, next_cursor}`. 409 on retry → `writeProblem`.

**Admin users/orgs:** Keyset-paginated lists already use `{items, has_more}` envelope. Normalize to `{items, next_cursor}`.

**Frontend pagination — wire up cursor-based pagination:**

The admin views currently show "Pagination coming soon" when `has_more` is true. This task must implement actual cursor-based pagination. For each paginated admin view:

1. Add a `nextCursor` ref (initially `undefined`)
2. After list response, set `nextCursor = data.next_cursor`
3. Add a "Load More" button (visible when `nextCursor` is defined)
4. On "Load More" click, call `client.GET(path, { params: { query: { cursor: nextCursor, limit: 50 } } })`
5. **Append** new items to existing array (don't replace)
6. Update `nextCursor` from new response
7. When `next_cursor` is absent in response, hide the button

This applies to: `AdminOrgsView`, `AdminUsersView`, `AdminDeliveriesView`, `AdminAuditLogView`.

**`AdminDashboardView.vue`:** Uses limit=1 requests just for counts. After conversion, these still work — just need typed client calls and `data.items.length` instead of raw parsing.

**`parseKeysetParams` cleanup:** After this task, verify no consumers remain. If all admin keyset endpoints and feed logs (Task 12) are migrated, delete `parseKeysetParams` from `admin_helpers.go`. If `admin_helpers.go` becomes empty, delete the file.

**Commit boundary:** All admin org/user/delivery handlers + 5 frontend files in one commit.

---

## Task 14: orgFetch Elimination + Final Verification

**Goal:** Remove `orgFetch`, verify complete OpenAPI coverage, regenerate final TypeScript types, run full test suites.

**Files:**
- Delete: `web/src/lib/api/orgFetch.ts` (after confirming zero imports)
- Delete: `web/src/lib/api/__tests__/orgFetch.test.ts`
- Modify: `web/src/lib/api/client.ts` — move any shared logic (coalesced refresh) that orgFetch used
- Regenerate: `openapi.json` — final merged spec
- Regenerate: `web/src/lib/api/schema.d.ts` — final TypeScript types
- Modify: `internal/api/openapi_test.go` — add comprehensive path coverage assertions

### Step 1: Verify zero orgFetch imports remain

```bash
rg "orgFetch" web/src/ --glob "*.{ts,vue}" | grep -v "__tests__/orgFetch"
```

If any remain, they were missed in earlier tasks — fix them first.

### Step 2: Delete orgFetch

```bash
rm web/src/lib/api/orgFetch.ts
rm web/src/lib/api/__tests__/orgFetch.test.ts
```

### Step 3: Verify coalescedRefresh

`orgFetch.ts` imports `coalescedRefresh` from `client.ts`. Verify this function remains in `client.ts` (it's still used by the refresh middleware).

### Step 4: Regenerate final OpenAPI spec

```bash
GENERATE_OPENAPI=1 go test ./internal/api/ -run TestOpenAPISpec -v -count=1
```

### Step 5: Add comprehensive spec path assertions

In `openapi_test.go`, verify that ALL expected paths exist in the merged spec. Check every org-scoped and admin path:

```go
expectedPaths := []string{
    "/orgs/{org_id}/groups",
    "/orgs/{org_id}/groups/{group_id}",
    "/orgs/{org_id}/groups/{group_id}/members",
    "/orgs/{org_id}/watchlists",
    // ... all paths
    "/admin/feeds",
    "/admin/orgs",
    // ... all admin paths
}
for _, p := range expectedPaths {
    if _, ok := paths[p]; !ok {
        t.Errorf("missing expected path: %s", p)
    }
}
```

### Step 6: Regenerate TypeScript types

```bash
cd web && npx openapi-typescript ../openapi.json -o src/lib/api/schema.d.ts
```

### Step 7: Run full test suites

```bash
go test ./... -count=1
cd web && npm run test:unit && npm run type-check && npm run lint
```

### Step 8: Final commit

```bash
git add -A  # after git status review
git commit -m "feat(api): complete API contract convergence, eliminate orgFetch

All Chi endpoints now return RFC 9457 errors, list envelopes, and
opaque cursors matching the Huma contract. OpenAPI spec covers all
routes via spec-only Huma declarations. Frontend uses typed
openapi-fetch client exclusively. orgFetch removed."
```

---

## Verification Checklist (run after all tasks complete)

- [ ] `rg "http\.Error" internal/api/*.go` returns 0 matches in handler files (middleware files may retain some)
- [ ] `rg "orgFetch" web/src/ --glob "*.{ts,vue}"` returns 0 matches
- [ ] `go test ./internal/api/ -run TestOpenAPISpec -v` passes and verifies all expected paths
- [ ] `GENERATE_OPENAPI=1 go test ./internal/api/ -run TestOpenAPISpec` produces a valid spec
- [ ] `npx openapi-typescript openapi.json -o /dev/null` produces no errors
- [ ] `cd web && npm run type-check` passes (typed client calls are type-safe)
- [ ] `cd web && npm run test:unit` passes
- [ ] `cd web && npm run lint` passes
- [ ] `golangci-lint run` passes
- [ ] No `Content-Type: text/plain` responses from any JSON endpoint (all errors are `application/problem+json`, all success is `application/json`)
- [ ] Every list endpoint returns `{"items": [...]}` (never bare array)
- [ ] Every create endpoint returns `Location` header
- [ ] Every paginated endpoint uses `?cursor=` (no `after_time`/`after_id`)
- [ ] Tier-limit 403 responses have `"type": "urn:cvert:error:tier-limit"`

---

## Risk Assessment

**Low risk:** Error format conversion, list envelope wrapping, Location headers — mechanical changes with no behavioral impact beyond response format.

**Medium risk:** Cursor format migration — existing cursor values in client state will break on deploy. Mitigation: cursors are ephemeral (session-scoped, not persisted), so a page refresh clears them.

**Medium risk:** Frontend orgFetch→typed client migration — each view needs careful testing for error handling and data binding. Mitigation: TDD, type-check catches most issues statically.

**Low risk:** Spec-only Huma declarations — zero impact on production routing (separate API instance). Drift between spec and runtime is the main ongoing risk, mitigated by CI spec validation tests.
