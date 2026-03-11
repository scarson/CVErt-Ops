# Chi/Huma Middleware Conflicts and Migration Decision

**Date:** 2026-03-11
**Context:** Phase 3 of the remediation plan proposes migrating org-scoped chi handlers to huma for automatic OpenAPI spec generation and input validation. Three confirmed technical conflicts make this migration non-trivial.

## What Huma Provides

Huma generates OpenAPI 3.1 specs from Go structs at registration time. You define input/output types, and huma handles:

- **OpenAPI spec generation** — no hand-written spec to keep in sync with code
- **Automatic request validation** — struct tags (`required`, `minimum`, `pattern`) produce JSON Schema validation with RFC 9457 error responses
- **Content negotiation** — JSON/CBOR out of the box
- **RFC 9457 Problem Details** — standardized error format automatically
- **Typed path/query/header params** — parsed and validated before your handler runs

We already use huma for CVE routes (`GET /cves`, `GET /cves/{cve_id}`, `GET /cves/{cve_id}/sources`) and auth routes. These are public/simple routes with no per-route RBAC middleware — they work fine.

## What Huma Costs

The org-scoped routes are the problem. They use chi middleware for auth, RBAC, tier enforcement, and rate limiting — all applied via chi's `r.Use()` and `r.With()` on nested sub-routers. Migrating these to huma hits three confirmed technical walls.

## The Three Confirmed Problems

### Problem 1: Middleware Type Incompatibility

Chi middleware signature:
```go
func(http.Handler) http.Handler
```

Huma middleware signature (used by `huma.Operation.Middlewares` and `Group.UseMiddleware`):
```go
func(ctx huma.Context, next func(huma.Context))
```

These are fundamentally incompatible types. You cannot pass `RequireOrgRole`, `RequireAuthenticated`, `tierMiddleware`, or `orgRateLimitMiddleware` to huma's `Operation.Middlewares` field. Every middleware would need to be rewritten or wrapped.

**Wrapping is harder than it looks.** A naive `chiToHuma` adapter would need to:
1. Extract `*http.Request` and `http.ResponseWriter` from `huma.Context` (possible via `humachi.Unwrap()`)
2. Create an `http.Handler` that calls `next(ctx)` when the chi middleware calls `next.ServeHTTP()`
3. But the chi middleware may call `r.WithContext(newCtx)` to inject values — the new request's context needs to flow back into the huma context

Step 3 is where it breaks. `chiContext.r` is an unexported field. When chi middleware does `next.ServeHTTP(w, r.WithContext(newCtx))`, the new request `r` is a *different* object. The huma context still holds the old request reference. There's no public API to update it.

### Problem 2: Path Doubling with Groups

The org routes are mounted on a chi sub-router at `/orgs/{org_id}`:
```go
apiRouter.Route("/orgs", func(r chi.Router) {
    r.Route("/{org_id}", func(r chi.Router) {
        r.Use(srv.RequireOrgRole(RoleViewer))
        // handlers registered here see paths relative to /{org_id}
    })
})
```

To use huma on this sub-router, you'd create a huma API instance on it, then use `huma.NewGroup` for path prefixing:
```go
orgHuma := humachi.New(orgSubRouter, humaConfig)
grp := huma.NewGroup(orgHuma, "/orgs/{org_id}")
```

**The path doubling:** `huma.NewGroup` installs a `PrefixModifier` that prepends the prefix to `op.Path` (group.go:32). Then `groupAdapter.Handle()` calls through to `a.router.MethodFunc(op.Method, op.Path, ...)` (humachi.go:159). But the chi sub-router is *already* mounted at `/orgs/{org_id}` — so the final registered route is `/orgs/{org_id}/orgs/{org_id}/groups`.

This is not speculative. The code path is:
1. `PrefixModifier`: `modified.Path = "/orgs/{org_id}" + "/groups"` → `/orgs/{org_id}/groups`
2. `humachi.Handle()`: `a.router.MethodFunc("GET", "/orgs/{org_id}/groups", handler)` — registered on the sub-router already at `/orgs/{org_id}`
3. Chi resolves: `/api/v1/orgs/{org_id}` (sub-router mount) + `/orgs/{org_id}/groups` (route path) → doubled

**Without** `huma.NewGroup`, you'd register paths like `Path: "/groups"` — routing works, but the OpenAPI spec shows `/groups` instead of `/orgs/{org_id}/groups` because `AddOperation()` uses `op.Path` directly as the spec key (openapi.go:1526).

So you're stuck: use NewGroup and get doubled routes, or skip it and get wrong OpenAPI paths.

### Problem 3: Context Propagation Direction

**Good news:** Chi middleware context values *do* flow into huma handlers. `humachi.Handle()` creates `chiContext{r: r}` where `r` is the post-middleware request. `chiContext.Context()` returns `c.r.Context()`. So values like `ctxOrgID`, `ctxRole`, `ctxUserID` set by chi middleware *are* accessible in huma handlers.

**Bad news:** This only works when chi middleware runs *before* huma. If you tried to wrap chi middleware inside huma middleware (Problem 1), the context propagation direction reverses and breaks.

This means the working pattern is: chi middleware on the sub-router → huma handler. Which is exactly what we have today for the CVE/auth routes. The problem is that this doesn't let you use huma's `Operation.Middlewares` for per-route RBAC (like `RequireOrgRole(RoleAdmin)` on PATCH but `RoleViewer` on GET).

## Current Architecture

The codebase has a split architecture:
- **Huma routes:** CVE endpoints (3 routes) and auth endpoints — public, no per-route RBAC
- **Chi routes:** Everything else (~60 routes) — org-scoped with per-route RBAC via `.With()`

The chi routes work correctly. The RBAC middleware, tier enforcement, rate limiting, and per-route role escalation (`RoleAdmin` for writes, `RoleViewer` for reads) all function as designed.

## The Alternative: Fix Findings Without Huma Migration

The remediation plan's Phase 3 exists because the project health review identified findings like:
- Missing OpenAPI spec for org routes
- Manual JSON error responses instead of RFC 9457
- Manual input parsing instead of declarative validation
- Inconsistent error formats across chi vs huma routes

Every one of these can be fixed without migrating to huma:

| Finding | Chi-Native Fix |
|---------|---------------|
| No OpenAPI spec for org routes | Generate from code annotations, or write spec manually, or use swaggo/swag |
| Manual error responses | Shared `problemDetail()` helper that emits RFC 9457 JSON |
| Manual input parsing | Validation helper using `go-playground/validator` |
| Inconsistent error formats | Single error middleware that wraps all routes |
| Pointer PATCH fields | Already a code pattern, not a framework issue |
| Cursor pagination | Shared pagination helper, framework-independent |

These are smaller, targeted fixes that don't require touching the routing architecture.

## Trade-Off Analysis

### Complete the Huma Migration (Phase 3 as planned)

**Benefits:**
- Single framework for all routes — consistency
- Automatic OpenAPI spec for the full API — always in sync with code
- Automatic validation — less boilerplate per handler
- Content negotiation for free

**Costs:**
- Must solve all three technical problems (middleware rewrite, path doubling, context flow)
- Step 0 prototyping required before any handler migration can begin
- Risk: if no clean solution exists, Phase 3 becomes a dead end after significant investment
- Every existing chi middleware (`RequireOrgRole`, `RequireAuthenticated`, `tierMiddleware`, `orgRateLimitMiddleware`, `csrfProtect`) needs a huma-native equivalent or a working wrapper
- ~60 handlers to migrate, each with per-route RBAC that needs to be replicated in huma's middleware model
- `.With(srv.RequireOrgRole(RoleAdmin))` per-route pattern has no obvious huma equivalent without per-operation middlewares working

**Risk level:** High. The path-doubling problem in particular has no obvious solution — it's a fundamental mismatch between chi's sub-router model and huma's group model.

### Chi-Native Fixes (Replace Phase 3)

**Benefits:**
- No routing architecture changes — zero risk of breaking existing auth/RBAC
- Targeted fixes: each finding addressed individually
- Can be done incrementally, one handler at a time
- The RBAC middleware pattern (`r.With(srv.RequireOrgRole(...))`) continues working unchanged
- Lower total effort — helpers vs full migration

**Costs:**
- Two frameworks in the codebase (huma for CVE/auth, chi for everything else)
- OpenAPI spec for org routes requires a separate solution (annotations, manual spec, or a different generator)
- No automatic validation on chi routes — must be explicit
- Ongoing divergence between huma and chi route patterns

**Risk level:** Low. These are additive changes, not architectural rewrites.

### Hybrid: Keep Huma Where It Works, Chi Where It Must

This is effectively the current state, but made intentional:
- Huma for routes that don't need per-route RBAC middleware (public endpoints, simple auth gates)
- Chi for routes that need the full RBAC middleware stack with per-route role requirements
- Shared helpers for error formatting, validation, and pagination used by both

**Benefits:**
- Pragmatic — uses each framework where it's strongest
- No migration risk
- Can gradually move routes to huma if/when the middleware problems are solved upstream

**Costs:**
- Two patterns to maintain
- New developers need to understand both
- OpenAPI spec still incomplete for chi routes

## Recommendation

The chi-native fix approach has the best risk/reward ratio. Phase 3 as currently planned requires solving problems that may not have clean solutions — and if the prototyping in Step 0 fails, the entire phase is wasted effort.

That said, huma is genuinely valuable for the routes that already use it. The CVE endpoints benefit from automatic validation and spec generation. The question is whether that value justifies the cost of migrating the org-scoped routes, which have a fundamentally different middleware requirement.

My honest assessment: every finding that Phase 3 addresses can be fixed with 20-50 lines of shared helpers on chi. The huma migration is an architectural preference, not a technical necessity. If the middleware problems were trivially solvable, migration would be worth it for long-term consistency. But they're not trivially solvable, and the current split architecture works.

## Open Questions for Decision

1. **How important is a complete, auto-generated OpenAPI spec?** If critical, huma migration is more justified. If "nice to have," chi-native fixes are sufficient.

2. **Is the two-framework split acceptable long-term?** If not, the question becomes: migrate everything to huma (hard), or migrate the 3 huma routes back to chi (easy, but loses auto-validation).

3. **Would you consider a different framework entirely?** If neither chi-only nor chi+huma is satisfying, there are alternatives (e.g., Fuego, which is designed for chi-compatible OpenAPI generation). But that's a much larger discussion.

4. **Should Step 0 prototyping proceed regardless?** Even if you lean toward chi-native fixes, spending a few hours on Step 0 would definitively prove or disprove whether the middleware problems are solvable. That data has value for the long-term decision.
