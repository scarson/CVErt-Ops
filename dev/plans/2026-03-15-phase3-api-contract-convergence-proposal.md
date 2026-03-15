# Revised Phase 3: API Contract Convergence Proposal

> **Relationship to existing remediation plan:** This document recommends replacing `Phase 3: Chi→Huma Migration` in `dev/plans/2026-03-10-health-review-remediation.md` with a lower-risk `Phase 3: API Contract Convergence`, while leaving the rest of that remediation plan intact.

**Date:** 2026-03-15

**Goal:** Remove user-visible API contract inconsistencies without rewriting the working Chi middleware stack.

**Architecture:** The health-review findings tied to the Chi/Huma split are real, but they are primarily API contract problems, not proof that the current router stack must be replaced wholesale. The revised phase keeps Huma where it already works well, keeps the nested Chi middleware tree where it is currently correct, and converges the contract through shared helpers, DTO cleanup, pagination normalization, and frontend cleanup.

**Tech Stack:** Go 1.26, `chi`, `huma` v2.37.2, OpenAPI 3.1, Vue 3, `openapi-fetch`

---

## Reviewed Sources

- `PLAN.md`
- `dev/health-reviews/2026-03-10-project-health-review.md`
- `dev/plans/2026-03-10-health-review-remediation.md`
- `dev/research-findings/chi-huma-middleware-conflicts.md`
- `internal/api/server.go`
- `internal/api/groups.go`
- `internal/api/middleware_auth.go`
- `internal/api/middleware_rbac.go`
- `internal/api/middleware_tier.go`
- `internal/api/cves.go`
- `internal/api/auth.go`
- `internal/api/openapi_test.go`
- `web/src/lib/api/client.ts`
- `web/src/lib/api/orgFetch.ts`
- `C:\Users\Sam\go\pkg\mod\github.com\danielgtaylor\huma\v2@v2.37.2\group.go`
- `C:\Users\Sam\go\pkg\mod\github.com\danielgtaylor\huma\v2@v2.37.2\adapters\humachi\humachi.go`
- `C:\Users\Sam\go\pkg\mod\github.com\danielgtaylor\huma\v2@v2.37.2\openapi.go`

---

## My Read

1. The original intent was not "Chi or Huma"; it was "Huma plus Chi." `PLAN.md:33-41` chooses `huma + chi` specifically to get OpenAPI 3.1 generation, automatic request validation, and RFC 9457 Problem Details from Huma while preserving Chi's middleware ecosystem and router flexibility. That same decision is restated in `PLAN.md:1333-1388` and `PLAN.md:1689-1705`. In other words, the intended architecture was already hybrid, not framework-pure.

2. The live implementation only partially realizes that intent. The main Huma API is created once on the top-level API router in `internal/api/server.go:201-203`, and it currently registers only the auth and CVE routes. Org-scoped and admin endpoints remain nested Chi route trees in `internal/api/server.go:220-410`. That means the OpenAPI-generated surface is materially smaller than the runtime surface, which is why `internal/api/openapi_test.go` currently spot-checks Huma paths like `/auth/register`, `/auth/login`, `/cves`, and `/cves/{cve_id}` but does not verify org-scoped paths.

3. The current Chi tree is not trivial to migrate because the complexity is in the middleware composition, not in the handler bodies. The org route hierarchy in `internal/api/server.go:255-410` depends on router-level `RequireAuthenticated`, `RequireOrgRole`, `tierMiddleware`, and `orgRateLimitMiddleware`, and then uses `r.With(...)` to raise the minimum role on individual operations. Those middlewares are not thin wrappers. `internal/api/middleware_auth.go:13-91` injects auth and API key state into context. `internal/api/middleware_rbac.go:15-61` parses `org_id`, loads membership, caps API-key role, and injects `ctxOrgID` and `ctxRole`. `internal/api/middleware_tier.go:16-69` depends on `ctxOrgID` and injects tier resolution used downstream by org rate limiting. This is a working stack with real sequencing dependencies.

4. The health review is correct that the split leaks directly into the product contract. The review calls out inconsistent error formats, list shapes, pagination patterns, and frontend client ergonomics, and the code confirms those observations. For example, `internal/api/groups.go:43-198` manually decodes JSON, performs manual validation, returns plain-text `http.Error(...)` responses, and returns a bare array from `listGroupsHandler`. On the frontend side, `web/src/lib/api/client.ts:1-67` provides a typed `openapi-fetch` client for Huma-covered routes, while `web/src/lib/api/orgFetch.ts:1-48` exists specifically because org-scoped Chi endpoints are outside the OpenAPI schema. The problem is real and user-visible.

5. The key technical conflict is not that Chi and Huma cannot coexist. They already do. The real conflict is that deeply nested Chi middleware trees do not map cleanly onto Huma's middleware and grouping model. Huma middleware is `func(huma.Context, func(huma.Context))`, while Chi middleware is `func(http.Handler) http.Handler`. Chi context propagation into Huma works only when Chi middleware runs first at router level because `humachi` builds its context from the post-middleware request. That is visible in `humachi.go`, where `Handle()` registers `a.router.MethodFunc(op.Method, op.Path, ...)` and passes the request into `chiContext`, and `chiContext.Context()` returns `c.r.Context()`. The reverse direction does not work cleanly because a Chi middleware that calls `r.WithContext(newCtx)` produces a new `*http.Request`, but the `chiContext.r` field is unexported.

6. The remediation plan's preferred Option C is materially unstable, not merely unproven. In `group.go`, Huma's `PrefixModifier` rewrites `modified.Path = prefix + modified.Path` before passing the operation onward. In `humachi.go`, the adapter registers the route using that same `op.Path`. In `openapi.go`, Huma stores the documentation path using `o.Paths[op.Path]`. That means a `huma.NewGroup("/orgs/{org_id}")` prefix simultaneously affects runtime registration and spec registration through the same field. If that group is created on a Chi sub-router already mounted at `/orgs/{org_id}`, the runtime route path doubles while the OpenAPI path looks correct. The current remediation plan already hints at this conflict, but because the same field drives both routing and documentation, it should be treated as a real architectural blocker for the planned migration pattern.

---

## Perspectives

### API Consumer / Product Quality

From an API consumer perspective, the health review is right. A client should not have to know which framework backs an endpoint in order to parse errors, consume list responses, or page through results. Findings 6, 7, 9, 31, 32, 33, 34, and 43 are contract-quality issues first.

### Engineering Delivery Risk

From a delivery-risk perspective, the current Phase 3 is the highest-risk part of the remediation plan because it couples contract cleanup to a difficult router and middleware migration. That is a poor trade when Findings 1 and 2 are more operationally critical and when the contract inconsistencies can be fixed without replatforming the route tree.

### Architecture Purity / Maintainability

From an architecture-purity perspective, a single registration model would be nice, but "one framework everywhere" is not the same thing as "one API contract everywhere." The current system already has route families that naturally want different transport behavior, such as redirect-heavy OAuth/OIDC routes in Chi and JSON-heavy Huma routes. Pursuing purity at the cost of destabilizing auth and RBAC is not a good trade.

### Frontend / OpenAPI Leverage

From a frontend perspective, complete OpenAPI coverage is genuinely valuable. `PLAN.md:2038-2045` explicitly says the OpenAPI spec should be the single source for generated client types and future docs. But "full typed client coverage" and "full Huma handler migration" are related goals, not identical goals. The team can improve the contract and simplify the frontend immediately while treating complete OpenAPI coverage as a separate, bounded spike.

---

## Recommendation

1. Do not proceed with the full `Phase 3: Chi→Huma Migration` as currently written in `dev/plans/2026-03-10-health-review-remediation.md`.

2. Replace it with `Phase 3: API Contract Convergence`, a lower-risk phase focused on unifying the observable API contract while preserving the current, working Chi middleware stack.

3. Keep Huma where it already works well today: top-level JSON endpoints that do not depend on the nested org/admin middleware tree.

4. Keep Chi where it currently carries the correct behavior: org-scoped routes, admin routes, and redirect-heavy flows that rely on layered router middleware and per-route role escalation.

5. Treat "complete OpenAPI coverage for all JSON routes" as an optional, bounded spike with explicit proof criteria, not as the default mechanism for fixing the contract findings.

---

## Reasoning

1. The health-review findings behind Phase 3 are valid, but the proposed remediation mechanism is riskier than necessary because it ties user-facing contract cleanup to a hard routing/middleware migration.

2. The current plan's preferred migration pattern depends on a Huma group strategy whose routing and documentation behavior share the same `op.Path` field. That is a poor foundation for a large migration because the failure mode is not cosmetic; it affects route correctness.

3. The current Chi middleware stack is not accidental glue. It performs auth, org scoping, RBAC, tier resolution, and org rate limiting in a known-good order. Rewriting or emulating that stack inside Huma would be new architecture work, not a thin adaptation layer.

4. The highest-value outcomes from the health review are contract outcomes: RFC 9457 errors, consistent list shapes, one cursor pattern, safer PATCH DTOs, and fewer frontend exceptions. Those can be delivered directly, incrementally, and with lower regression risk.

5. A revised Phase 3 should therefore optimize for contract convergence and preserved behavior. If the project still wants full Huma migration later, it should happen only after a spike proves a route-registration pattern that preserves middleware semantics and produces correct runtime paths and correct OpenAPI paths at the same time.

---

## Revised Phase 3 Proposal

### New Phase Title

`Phase 3: API Contract Convergence`

### Goal

Remove user-visible API contract inconsistencies without rewriting the working Chi middleware stack.

### Findings Addressed

- Finding 6: inconsistent error response format
- Finding 7: inconsistent list response shapes
- Finding 8: dual frontend API client
- Finding 9: inconsistent pagination cursor mechanisms
- Finding 31: missing `Location` headers on `201 Created`
- Finding 32: non-pointer PATCH fields
- Finding 33: inconsistent validation status codes
- Finding 34: tier limit responses indistinguishable from RBAC responses
- Finding 43: broken delivery cursor contract

### Decision Status

This document is a decision and scoping proposal, not an execution checklist. It is intended to replace the architectural direction of the original Phase 3 before a separate implementation plan is written. Subagents should not execute directly from this document without a follow-on implementation plan that assigns exact files, tests, and commit boundaries.

### Scope Boundaries

**In scope for the revised Phase 3:**

- Chi JSON endpoints under `/api/v1/orgs/...` that currently return plain-text errors, mixed list shapes, or inconsistent cursor contracts
- Chi JSON endpoints under `/api/v1/admin/...` where the same shared error and envelope helpers can be applied without routing-framework changes
- The frontend stores/composables that consume those endpoints and currently special-case Chi/Huma contract differences

**Out of scope for the revised Phase 3:**

- Re-registering org-scoped routes on Huma
- Re-registering admin routes on Huma
- OAuth/OIDC redirect and callback endpoints
- Static routes, SPA fallback, and non-JSON endpoints
- Huma-registered auth and CVE routes except where compatibility tests are needed
- Any store-layer refactor unrelated to the contract issues being fixed

### Locked Implementation Defaults

The following defaults are fixed for this revised phase and are not left to implementer interpretation:

1. Route registration stays on the current framework for each route family. Org-scoped and admin routes remain Chi-registered in this phase.

2. The main phase does not introduce a new router, a new OpenAPI generator, or an OpenAPI post-processing pipeline.

3. Shared contract helpers should live in `internal/api` unless a concrete cross-package reuse case requires a different home.

4. `orgFetch` is allowed to remain after the main phase. Finding 8 is considered addressed in the main phase when frontend contract branching is materially reduced; complete elimination of `orgFetch` is deferred to the optional OpenAPI-coverage spike.

5. Backend and frontend changes that alter a route family's response contract must land together in the same task or commit. No backend-only contract changes that knowingly break the current frontend.

6. Store transaction helpers and RLS enforcement paths are not to be changed opportunistically. If a contract fix appears to require store-layer changes, those changes must be explicitly justified and tested as org-scoped security-sensitive work.

7. Shared error behavior must preserve the intended semantics from `PLAN.md`: `400` for malformed input, `422` for validation failures, `401` for unauthenticated requests, `403` for RBAC failures, `403` with a distinct problem `type` for tier-limit failures, `404` for not found, and `429` for rate limiting.

8. List endpoints that are not yet paginated must still adopt the `{"items": [...]}` envelope. `next_cursor` remains optional and should be omitted when pagination is not implemented.

### Scope

1. Introduce shared RFC 9457 Problem Details output for Chi JSON handlers so Chi and Huma JSON routes return the same class of error response.

2. Introduce shared request decode and validation helpers for Chi routes so handler boilerplate is reduced and malformed-request versus validation failures are handled consistently.

3. Introduce shared list-envelope helpers so org-scoped endpoints converge on `{"items": [...], "next_cursor": "..."}` rather than mixing bare arrays and wrapped results.

4. Introduce shared cursor helpers so paginated endpoints converge on one `?cursor=` parameter and one opaque encoding format instead of multiple incompatible schemes.

5. Convert PATCH DTOs on Chi routes to pointer-based request structs where the health review identified zero-value update bugs or future zero-value ambiguity.

6. Standardize `Location` headers on relevant `201 Created` responses.

7. Standardize error typing for tier-limit failures so they remain `403` but are distinguishable from RBAC failures through machine-readable problem types.

8. Update the frontend so stores and composables consume the converged contract. `orgFetch` should remain a transport helper only where needed, not a contract escape hatch.

9. Add an explicit optional spike for complete OpenAPI coverage. The spike should be separate from the contract-convergence work and should not block Phase 3 completion.

### Recommended Execution Sequence

To reduce ambiguity for a future implementation plan, the intended rollout order is:

1. Establish shared Chi contract primitives first: RFC 9457 writer/helper, request decode helper, validation helper conventions, list-envelope helper, cursor helper, and `Location` helper.

2. Apply those primitives to one representative org-scoped route family without changing route registration. `groups` is the preferred reference family because it exercises create, list, get, patch, delete, and nested membership routes while staying smaller than watchlists or alert rules.

3. Roll the same contract pattern across the remaining org-scoped JSON route families.

4. Normalize the paginated route families and the deliveries cursor contract after the shared cursor helper exists.

5. Update frontend stores/composables in lockstep with each backend contract change so no route family is left in a half-migrated state.

6. Run the optional OpenAPI-coverage spike only after the main contract-convergence work is stable, and only with explicit proof criteria.

### Optional Spike: Complete OpenAPI Coverage

This spike is separate from the main phase and should only proceed with explicit exit criteria. It must prove all of the following on at least one representative org-scoped route family before broader adoption:

1. Correct runtime routing with no doubled path segments
2. Correct OpenAPI path generation
3. Preserved auth, RBAC, tier, and rate-limit behavior
4. Preserved per-route role escalation semantics

If any of those conditions fail, the spike should be recorded as inconclusive or negative, and the system should continue with the converged hybrid architecture.

### Non-Goals

- No wholesale rewrite of `RequireAuthenticated`
- No wholesale rewrite of `RequireOrgRole`
- No wholesale rewrite of `tierMiddleware`
- No wholesale rewrite of `orgRateLimitMiddleware`
- No assumption that every JSON route must become Huma-registered in this phase
- No routing-framework purity refactor for its own sake

### Subagent Failure Modes To Prevent

The follow-on implementation plan should explicitly guard against these failure modes:

1. A subagent infers that "contract convergence" means "convert routes to Huma." That is incorrect for this phase.

2. A subagent interprets Finding 8 to mean `orgFetch` must be deleted immediately. That is not required for the main phase.

3. A subagent applies a new helper to one handler but not its sibling handlers in the same route family, creating a new inconsistency instead of removing one.

4. A subagent changes backend contract shape without updating the consuming frontend code in the same task.

5. A subagent expands scope into store-layer or middleware rewrites because the document did not clearly forbid that drift.

6. A subagent treats this proposal as sufficient execution guidance instead of first writing a detailed implementation plan.

### Required Follow-On Planning

Before any subagent-driven development begins, write a dedicated implementation plan that:

1. Breaks the revised phase into exact route-family tasks with exact file lists.

2. States which tests are added or updated for each task.

3. Defines the expected status codes and response shapes for each touched endpoint family.

4. Pairs each backend contract task with its required frontend updates.

5. States commit boundaries explicitly so partially migrated contract changes do not leak across tasks.

### Testing And Verification Requirements

Any implementation plan derived from this proposal should be reviewed against `dev/testing-pitfalls.md`, with the following items treated as mandatory rather than optional:

1. **Error-path differentiation:** For any shared error helper, tests must distinguish malformed input from semantic validation failure. Invalid JSON, invalid UUIDs, and invalid cursors should exercise `400` paths. Business-rule failures should exercise `422` paths. Do not collapse them into one generic error test.

2. **Validation symmetry:** When a create route validates a field, the matching PATCH/update route must be tested for the same invalid values. This includes empty strings and whitespace-only strings, not just `""`.

3. **Zero-value vs absent PATCH behavior:** For every pointer-based PATCH DTO introduced by this phase, tests must prove the difference between omitted fields and explicit zero values such as `""` or `false`.

4. **Cross-endpoint security parity:** When a helper or problem type is applied to one route in a family, the implementation task must grep for sibling endpoints that perform the same operation category and verify they receive the same treatment. Do not fix one endpoint and leave its siblings inconsistent.

5. **RLS safety and transaction-helper discipline:** If any handler change requires store-layer adjustment, tests and code review must verify that API paths still use org-scoped transaction helpers and do not introduce `WorkerTx` usage into `internal/api`. For any changed org-scoped store query, use the restricted `AppStore` path in tests where applicable.

6. **Cursor and pagination coverage:** When standardizing a paginated endpoint, include tests for malformed cursors, page-boundary correctness, final-page behavior, and response-shape consistency. Cursor helper work is incomplete if it only tests the happy path.

7. **Frontend visible error handling:** For every frontend store or view updated by this phase, test that failed reads render an actual error state rather than a blank page or misleading empty-state UI, and that failed mutations produce visible user feedback.

8. **Request retry safety:** If any contract cleanup touches `web/src/lib/api/client.ts` or `web/src/lib/api/orgFetch.ts`, include tests that prove retry logic resends the request body correctly and does not reintroduce duplicate refresh behavior.

9. **RBAC regression coverage:** For at least one representative endpoint per touched route family, verify role outcomes across viewer/member/admin and unauthenticated cases so contract cleanup does not weaken access enforcement.

10. **No silent success on missing resources:** Where this phase standardizes errors, tests should prove that missing-resource paths remain intentionally defined. Do not accidentally convert a `404` contract into a silent `204`.

11. **Downstream error propagation:** When a store call or helper returns an error, tests must verify that the handler returns the intended problem response instead of silently succeeding, returning an empty list, or degrading to an unrelated status code.

---

## Acceptance Criteria

1. Chi and Huma JSON endpoints return the same error format class: RFC 9457 Problem Details.

2. Org-scoped list endpoints use a consistent list envelope and cursor contract.

3. The frontend no longer has to special-case error parsing and list-shape handling by endpoint family.

4. Existing auth, RBAC, tier-resolution, and org-rate-limit behavior remains unchanged.

5. Complete Huma migration is explicitly deferred unless a bounded spike proves a working pattern with correct runtime routing, correct OpenAPI paths, preserved middleware behavior, and preserved per-route role escalation.

---

## Important Changes to Existing Direction

1. This proposal preserves the health-review findings and their priority, but it changes the remediation mechanism for Findings 6, 7, 8, 9, 31, 32, 33, 34, and 43.

2. Phases 1, 2, 4, 5, and 6 in `dev/plans/2026-03-10-health-review-remediation.md` remain broadly valid.

3. Only Phase 3 should be replaced, because its current architecture assumptions conflict with the actual Huma/Chi behavior verified in the repo and local dependency source.

4. The revised phase treats contract convergence as the required outcome and framework unification as optional future research.

---

## Review Checklist

- Verify that this document remains a standalone proposal and does not overwrite the existing remediation plan.
- Verify that `My Read`, `Perspectives`, `Recommendation`, and `Reasoning` remain present as first-class sections.
- Verify that the revised phase title, scope, non-goals, and acceptance criteria remain explicit.
- Verify that scope boundaries, locked implementation defaults, execution order, and subagent failure modes are explicit enough that a later implementation plan does not need to re-decide them.
- Verify that `Testing And Verification Requirements` remains aligned with `dev/testing-pitfalls.md` and is specific enough to prevent happy-path-only implementation work.
- Verify that each core technical claim is backed by a repo document, a code reference, or the local Huma source inspected during this review.
- Verify that any future implementation plan derived from this document separates contract convergence from OpenAPI-coverage experimentation.

---

## Assumptions

- The save location follows the user-requested `dev/plans` convention even though the `writing-plans` skill normally points to `docs/plans`.
- This is a new standalone proposal document and does not replace or overwrite `dev/plans/2026-03-10-health-review-remediation.md`.
- The earlier planning-only assumption that no file would be created in the current turn has been superseded by this saved proposal document.
