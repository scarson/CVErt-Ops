# Agent 5: API Design & Developer Experience
**Date:** 2026-03-18 03:08
**Scope:** Full review

---

### [MAJOR] Missing API key query string rejection middleware (PLAN.md requirement)

**Evidence:** PLAN.md section 16 explicitly requires returning 400 Bad Request if a request includes an API key in any query parameter, and scanning for common parameter names at the middleware layer before reaching any handler. Grep across internal/api/ returns zero results for any such middleware.
**Problem:** The API accepts requests with API keys in query parameters without rejection. PLAN.md correctly identifies this as a security risk: tokens in query strings are logged by every proxy, CDN, browser history, and Referer headers. This is listed as a required control.
**Risk:** API keys leaked via access logs, browser history, or Referer headers. Any downstream consumer who puts the key in a query string gets no warning that they are doing something dangerous.

### [MAJOR] Per-org rate limiter (orgRateLimitMiddleware) missing Retry-After header on 429

**Evidence:** internal/api/middleware_tier.go:70 -- the org rate limiter returns writeProblem(w, http.StatusTooManyRequests, "rate limit exceeded") with no Retry-After header. Compare with the IP rate limiter in ratelimit.go:89 which correctly sets w.Header().Set("Retry-After", "60").
**Problem:** PLAN.md section 16.1 states exceeded limits return 429 Too Many Requests with Retry-After header. The per-org rate limiter omits this header while the per-IP rate limiter includes it. API consumers have no indication of when to retry.
**Risk:** Clients cannot implement proper backoff. Well-behaved clients that respect Retry-After will have no guidance; they will either retry too aggressively (worsening the problem) or too conservatively (degrading UX).

### [MAJOR] Dual framework approach creates inconsistent error formats

**Evidence:** CVE endpoints use huma (via huma.Register) while all org-scoped endpoints use raw chi handlers with writeProblem/writeProblemWithErrors. Huma endpoints return Content-Type: application/json with its own error envelope; chi handlers return Content-Type: application/problem+json via writeProblem. The password_change_required response in middleware_auth.go:87-94 uses json.NewEncoder with a raw map that omits the status field entirely.
**Problem:** API consumers cannot rely on a single error response format. The huma-generated errors and the chi writeProblem errors have different Content-Type headers and potentially different envelope shapes. The force-password-reset response at middleware_auth.go:87-94 writes a JSON object without a status field, violating RFC 9457 which recommends the status member.
**Risk:** Frontend error handling must accommodate multiple error shapes. Any generic error interceptor that relies on Content-Type: application/problem+json will miss huma errors. API documentation consumers get confused by two different error formats for the same API.

### [MAJOR] CVE endpoints are unauthenticated -- no auth middleware applied

**Evidence:** server.go:234 -- registerCVERoutes(api, srv.store) is called directly on the API router without any auth middleware. The /cves, /cves/{cve_id}, and /cves/{cve_id}/sources endpoints are publicly accessible. Compare with all org-scoped routes which go through RequireAuthenticated() and RequireOrgRole().
**Problem:** The CVE corpus is described in CLAUDE.md as global/shared data, but the code comments at cves.go:22 say all endpoints are public read-only and auth middleware is added in Phase 2. If CVE data should remain fully public, this is fine. But it means anyone can enumerate the entire CVE database without authentication, which may not match the intended access model for a SaaS product with tiered pricing.
**Risk:** If public access is unintentional, the entire CVE corpus is exposed. Even if intentional, there is no rate limiting on these endpoints (they bypass the org rate limiter since no org context exists). A scraper could hammer /cves with no per-org limits applied. The IP rate limiter at 10 req/min is the only protection.

### [MAJOR] Inconsistent pagination: some list endpoints have no pagination at all

**Evidence:** The following list endpoints fetch all rows without any limit or cursor support:
- listChannelsHandler (channels.go:211) with no limit
- listMembersHandler (orgs.go:188) with no limit
- listInvitationsHandler (orgs.go:497) with no limit
- listAPIKeysHandler (apikeys.go:152) with no limit
- listReportsHandler (reports.go:201) with no limit
- listFeedsHandler (feeds.go:46) returns all feeds

Compare with listAlertRulesHandler which uses proper keyset pagination with limit=20.
**Problem:** While some of these collections are naturally small (feeds are about 10, invitations are few), channels, API keys, and reports can grow. An org with hundreds of API keys or channels will get unbounded response payloads.
**Risk:** Memory pressure from serializing large collections. Denial of service if an org creates many resources. Inconsistent API surface confuses consumers who expect pagination on all list endpoints.

### [MINOR] Alert rules list has hardcoded page size with no client override

**Evidence:** alert_rules.go:329 -- const limit = 20. The alert rules list handler does not accept a limit query parameter. Compare with listDeliveriesHandler which uses parseLimitParam(w, r, 50, 200) allowing client-specified page sizes.
**Problem:** API consumers cannot control page size for alert rules. Other paginated endpoints (deliveries, feed logs, admin deliveries, saved searches, alert events) accept a limit parameter. This inconsistency means clients must handle two different pagination contracts.
**Risk:** Clients that need larger pages for UI display or batch processing must make multiple requests. The API surface is unpredictable -- clients cannot assume limit works on all paginated endpoints.

### [MINOR] Alert events list has hardcoded page size (100) with no client override

**Evidence:** alert_events.go:43 -- const limit = 100. Same pattern as alert rules.
**Problem:** Same as above. Inconsistent with other paginated endpoints that accept limit.
**Risk:** Same as above.

### [MINOR] Watchlist list has hardcoded page size (20) with no client override

**Evidence:** watchlists.go:266 -- const limit = 20. Same pattern.
**Problem:** Same inconsistency.
**Risk:** Same.

### [MINOR] Stale comment documents cursor parameter as ?after= instead of ?cursor=

**Evidence:** Alert events handler function comment at alert_events.go:34 says "via ?after= cursor" but the code at line 68 reads r.URL.Query().Get("cursor").
**Problem:** The comment is misleading but the code is correct and consistent with all other endpoints.
**Risk:** Developers reading the comment may try to use ?after= which will be silently ignored.

### [MINOR] Frontend uses raw fetch() instead of typed client for several endpoints

**Evidence:** web/src/stores/auth.ts:81,102,120 uses raw fetch for forgot-password, reset-password, verify-email. web/src/views/admin/AdminSystemView.vue:75 uses fetch for /admin/doctor. web/src/views/LoginView.vue:29 and RegisterView.vue:32 use fetch for /auth/providers.
**Problem:** These bypass the typed openapi-fetch client, losing type safety and the automatic CSRF/refresh middleware. The forgotPassword, resetPassword, and verifyEmail methods manually add X-Requested-By headers, but LoginView.vue and RegisterView.vue fetching /auth/providers do not (safe since these are GETs, but inconsistent). The admin doctor fetch uses credentials: include but skips the refresh interceptor.
**Risk:** If the API schema changes, these raw fetch calls will not produce type errors at build time. Future developers may copy these patterns and introduce bugs. The admin doctor view would fail silently on 401 since it has no refresh logic.

### [MINOR] createAlertRuleBody.Enabled is a non-pointer bool, risks zero-value confusion

**Evidence:** alert_rules.go:32 -- Enabled bool. When the client omits enabled from the JSON body, Go deserializes it as false. The handler at line 253-256 checks if the field is false then sets status to draft.
**Problem:** Unlike PATCH structs which correctly use pointer types, the CREATE struct uses a bare bool. If a client sends a body without enabled, the rule is created as draft -- which may be surprising since the client did not explicitly request draft mode.
**Risk:** A client that forgets to set enabled to true gets a draft rule that never activates. This is probably the correct default, but it is undocumented behavior relying on Go zero-value semantics rather than explicit specification.

### [MINOR] Admin retry delivery returns 200 with JSON body instead of 204 No Content

**Evidence:** admin_deliveries.go:107 -- writeJSON(w, http.StatusOK, ...). Compare with the org-scoped replayDeliveryHandler at deliveries.go:307 which returns http.StatusNoContent.
**Problem:** Two endpoints that do the same thing (retry a delivery) return different status codes and response formats. The admin endpoint returns 200 with a body; the org endpoint returns 204 with no body.
**Risk:** API consumers and documentation must account for two different patterns for the same operation.

### [MINOR] Admin bulk retry uses limit query parameter for something other than pagination

**Evidence:** admin_deliveries.go:116 -- parseLimitParam(w, r, 100, 1000) is used to control how many failed deliveries to retry, not for pagination.
**Problem:** The limit parameter name is conventionally used for pagination page size throughout this API. Reusing it for maximum number of retries on a POST endpoint is confusing. A parameter name like max or batch_size would be clearer.
**Risk:** API documentation will show limit on a POST endpoint where it means something different than on GET endpoints.

### [MINOR] No Cache-Control headers on any API response

**Evidence:** No handler or middleware sets Cache-Control headers. The CVE list endpoint is read-only and potentially cacheable, but returns no caching directives.
**Problem:** Without explicit Cache-Control: no-store on authenticated endpoints, intermediate caches (corporate proxies, CDN edge nodes) may cache sensitive responses. Without Cache-Control headers on the public CVE endpoints, every request hits the backend even when results have not changed.
**Risk:** Stale cached responses for authenticated endpoints (security). Unnecessary backend load for cacheable public endpoints (performance).

### [MINOR] Inconsistent 404 detail messages across handlers

**Evidence:** Different handlers return different detail strings for 404:
- alert_rules.go:315 -- "not found"
- orgs.go:98 -- "org not found"
- orgs.go:271 -- "user not found in org"
- channels.go:196 -- "not found"
- reports.go:405 -- "channel not found"
- orgs.go:547 -- "invitation not found"
**Problem:** Some 404s include the resource type in the message while others use generic "not found". The inconsistency makes it harder for API consumers to programmatically distinguish between different not-found cases.
**Risk:** Low. Clients should rely on the HTTP path context, not the error detail, to determine what was not found. But the inconsistency is noticeable.

### [MINOR] The unbindChannelFromReport handler does not verify binding exists before deleting

**Evidence:** reports.go:446 -- srv.store.UnbindChannelFromReport is called without checking if the binding exists first. Compare with unbindRuleChannelHandler at alert_rules.go:797-807 which checks ChannelRuleBindingExists and returns 404 if not found.
**Problem:** unbindChannelFromReport will return 204 even if the binding never existed. This makes DELETE idempotent (arguably correct for REST) but is inconsistent with the alert-rules unbind endpoint which returns 404 for non-existent bindings.
**Risk:** Clients get different behavior from two structurally identical unbind operations. One is idempotent (report channel unbind), the other is not (rule channel unbind).

### [MINOR] createChannelBody.Type defaults to webhook when omitted

**Evidence:** channels.go:83-84 -- if req.Type is empty, it defaults to webhook. The type field is not documented as having a default value.
**Problem:** Implicit defaults without documentation. A client that omits type gets a webhook channel. If the API schema documents type as required, the implicit default contradicts the schema.
**Risk:** Clients may accidentally create webhook channels when they meant to specify a type.

### [MINOR] ListCVEsInput has undocumented query parameters not visible in OpenAPI

**Evidence:** cves.go:218-222 -- CVSSMin, CVSSMax, EPSSMin, EPSSMax are resolved from raw query strings in the Resolve method because huma panics on pointer types. These fields have no query: tag and are not visible in the generated OpenAPI spec.
**Problem:** API consumers reading the OpenAPI spec will not discover cvss_min, cvss_max, epss_min, epss_max query parameters. They exist and work, but are invisible in the documentation.
**Risk:** Undiscoverable API features. Consumers must read the source code or rely on external documentation to learn about numeric range filters for CVSS and EPSS.

### [MINOR] testChannelHandler always returns 200 even when the test fails

**Evidence:** channels.go:521 -- writeJSON(w, http.StatusOK, resp) where resp.Success may be false and resp.Error contains the failure message.
**Problem:** HTTP 200 with success:false is an unusual pattern. Most APIs would return 502 or 422 to indicate that the test delivery failed. Returning 200 means generic error handlers will not catch test failures.
**Risk:** Monitoring tools that check HTTP status codes will report the endpoint as healthy even when channel tests fail. Clients must inspect the response body to determine success.

### [MINOR] password_change_required error response bypasses writeProblem helper

**Evidence:** middleware_auth.go:87-94 uses inline json.NewEncoder(w).Encode(...) instead of the shared writeProblem or writeProblemTyped helper. The response omits the status field that all other error responses include.
**Problem:** This is the only error response in the API that is hand-crafted instead of using the shared helpers. It produces a response missing the status field that RFC 9457 recommends and that all other error responses include.
**Risk:** Frontend code that checks error.status on problem responses will get undefined for this specific error type. The inconsistency creates a special case that every client must handle separately.
