# Agent 5: API Design & Developer Experience
**Date:** 2026-03-10
**Scope:** Full review

---

### [MAJOR] Inconsistent error response format: chi handlers return plaintext, huma handlers return RFC 9457

**Evidence:** All chi-registered handlers (orgs, watchlists, channels, alert_rules, groups, deliveries, reports, apikeys, audit_log, saved_searches) use `http.Error(w, "message", statusCode)` returning `text/plain`. Huma-registered handlers (auth, cves) return `huma.Error4xxXxx()` generating RFC 9457 Problem Details JSON.

**Problem:** PLAN.md §16 mandates RFC 9457 Problem Details for all error responses. The majority of the API returns bare text errors instead. An API consumer's generic error handler that parses JSON problem details will get parse failures on most endpoints.

**Risk:** Every client must handle two completely different error formats depending on which endpoint they hit. This is the single most visible inconsistency to API consumers.

**Suggested approach:** Migrate chi-registered handlers to huma, or create a shared error response helper that writes RFC 9457 JSON from chi handlers.

---

### [MAJOR] Inconsistent list response shapes — some paginated objects, some bare arrays

**Evidence:** `GET /cves` and `GET /watchlists` return `{"items": [...], "next_cursor": "..."}`. But `GET /members`, `GET /api-keys`, `GET /invitations`, `GET /groups`, `GET /group-members`, `GET /saved-searches` return bare JSON arrays `[...]`.

**Problem:** Clients must know per-endpoint whether to read `response.items` or treat the response as the array. Adding pagination later to bare-array endpoints is a breaking change.

**Risk:** Frontend already handles both shapes. Future pagination on members/groups/api-keys requires a breaking response shape change.

**Suggested approach:** Wrap all list responses in `{"items": [...]}` consistently. Add pagination support to currently-unpaginated endpoints that could grow (members, api-keys).

---

### [MAJOR] Dual API client on frontend — typed openapi-fetch for huma routes, untyped orgFetch for chi routes

**Evidence:** `web/src/lib/api/client.ts` creates a typed `openapi-fetch` client, but `web/src/lib/api/orgFetch.ts` is a separate untyped fetch wrapper. The typed client is only used for auth and CVE endpoints. Every org-scoped endpoint uses `orgFetch` with manual URL construction and `as` type casts.

**Problem:** Chi-registered handlers are not in the OpenAPI spec (only huma routes get generated), forcing the frontend to bypass the typed client for most of the API. No compile-time type safety for most API calls.

**Risk:** Type drift between frontend and backend is invisible until runtime. If the backend adds or renames a field, no build step catches the mismatch.

**Suggested approach:** This is a downstream symptom of the chi/huma split. Migrating chi handlers to huma would auto-generate OpenAPI coverage and enable the typed client for all endpoints.

---

### [MAJOR] Inconsistent pagination cursor mechanisms across endpoints

**Evidence:** Six different pagination patterns: (1) CVE list: `?cursor=`, base64 JSON, `base64.RawURLEncoding`; (2) Watchlists/alert-rules: `?after=`, base64 `time|uuid`, `base64.URLEncoding`; (3) Deliveries: `?after_created_at=` + `?after_id=` as separate params; (4) Watchlist items: `?after=`, raw UUID; (5) Saved searches: not paginated; (6) Alert rules: hardcoded `limit=20`, no client-controllable page size.

**Problem:** A client developer cannot predict how pagination works for any given endpoint. Parameter names, encoding, and cursor opacity all vary.

**Risk:** Each new endpoint integration requires figuring out a novel pagination contract. The delivery cursor's `next_cursor` response value doesn't match its expected input format — it's unusable as returned.

**Suggested approach:** Standardize on a single opaque cursor pattern (e.g., base64 JSON `{"d":"...","id":"..."}`) for all paginated endpoints with a shared `?cursor=` param.

---

### [MINOR] No `Location` header on 201 Created responses

**Evidence:** All creation handlers (watchlists, channels, alert_rules, api-keys, groups, reports, saved_searches) return 201 without `Location`.

**Problem:** RFC 9110 §15.3.2 recommends `Location` header. Machine clients expect it.

**Risk:** Minor friction for API integrators — they must parse the body to find the resource URL.

---

### [MINOR] PATCH on groups uses non-pointer fields — cannot clear optional values

**Evidence:** `groups.go:29-33` — `updateGroupBody` uses `string` not `*string`.

**Problem:** PLAN.md §16 mandates pointer types for PATCH fields. Sending `{"description": ""}` is indistinguishable from omitting it.

**Risk:** Clients cannot make partial updates or clear fields.

---

### [MINOR] Inconsistent validation error status codes (400 vs 422 for same error)

**Evidence:** "name is required" returns 422 in channels.go and reports.go, but 400 in groups.go, watchlists.go, alert_rules.go, and saved_searches.go.

**Problem:** Same validation failure uses different status codes per endpoint.

**Risk:** Clients cannot use status codes to distinguish parse errors from validation errors.

---

### [MINOR] Tier limit violations return 403 — indistinguishable from RBAC rejections

**Evidence:** `createAlertRuleHandler` line 199, plus watchlists, channels, orgs — all return 403 for tier limits.

**Problem:** 403 semantically means "no permission." Tier limits are a different concept (quota exhausted). Clients can't distinguish "wrong role" from "need higher tier."

**Risk:** Confusing error handling for clients and frontend.

---

### [MINOR] `InCISAKEV` boolean filter silently treats non-"true" values as false

**Evidence:** `cves.go:261-263` — `strings.EqualFold(i.InCISAKEV, "true")`. Sending `?in_cisa_kev=yes` or `?in_cisa_kev=1` silently filters to false.

**Problem:** No validation error on invalid boolean values. Users get silently wrong results.

**Risk:** Users get fewer results than expected from a typo or convention mismatch, with no error to diagnose.

---

### [MINOR] Delivery list cursor is unusable — response format doesn't match request format

**Evidence:** `deliveries.go:88` — `next_cursor` is `<RFC3339Nano>/<uuid>` combined, but the endpoint expects `after_created_at` + `after_id` as separate params.

**Problem:** Client cannot forward `next_cursor` from response back as a query parameter.

**Risk:** Clients must ignore `next_cursor` and manually extract values from the last item.
