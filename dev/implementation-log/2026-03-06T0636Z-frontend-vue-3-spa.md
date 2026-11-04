# Frontend — Vue 3 SPA

> **Date:** 2026-03-04 through 2026-03-06
> **Commits:** `dd99764`..`9b6d40e` on `dev` (102 commits)
> **Plan:** `dev/plans/2026-03-03-frontend-design.md` (design), `dev/plans/2026-03-03-frontend-implementation-plan.md` (implementation)
> **A11y spec:** `dev/specs/accessibility-spec.md`

## What was built

| Feature | Key files | Description |
|---|---|---|
| Project scaffolding | `web/` (184 source files) | Vue 3 + TypeScript, Vite, Tailwind CSS v4, shadcn-vue (reka-ui primitives), Pinia, Vue Router 4 |
| SPA embedding in Go binary | `web/embed.go`, `internal/api/server.go` | `//go:embed all:dist` with `fs.Sub`; SPA fallback serves `index.html` for client-side routes |
| OpenAPI-typed API client | `web/src/lib/api/client.ts`, `web/src/lib/api/orgFetch.ts` | `openapi-typescript` generates types from spec; `openapi-fetch` with CSRF middleware and 401 refresh interceptor with coalesced refresh |
| Auth store | `web/src/stores/auth.ts` | Pinia store: login/logout, session restore, org context with localStorage persistence |
| Router + guards | `web/src/router/index.ts` | Auth guard, org guard, title guard with h1 focus for screen readers |
| Layouts | `web/src/layouts/` | PublicLayout (login/register) + AuthenticatedLayout (sidebar nav, org switcher, mobile sheet) |
| All views | `web/src/views/` | Login, Register, Create Org, CVE Search, CVE Detail, Watchlist List/Detail, Members, Groups, Feed Status, Invitation acceptance, Password reset, Email verification, 404 |
| Shared components | `ErrorAlert.vue`, `LoadingSkeleton.vue`, `EmptyState.vue` | Reusable error display (with retry prop), skeleton loading, empty state |
| Keyset pagination | `web/src/composables/usePagination.ts` | Cursor stack for prev/next navigation; reset on filter change |
| WCAG 2.1 AA a11y | All views/components | 10 dedicated a11y commits: `lang` attribute, skip-to-main, icon labels, `aria-live` regions, form error association, h1 focus on navigation |
| Frontend CI | `.github/workflows/ci.yml` | `test-web` (type-check + lint + vitest), `build-web` jobs; frontend build required by all Go test jobs for `embed.go` |
| Backend OAuth redirect | `internal/auth/`, `internal/config/` | `FRONTEND_URL` config; OAuth callbacks redirect to frontend instead of returning JSON |

## Key implementation decisions

- **SPA embedded in Go binary** — `//go:embed all:dist` with SPA fallback handler. Single binary deployment, no separate web server
- **Coalesced token refresh** — When multiple API calls get 401 simultaneously, a single `refreshPromise` is shared. Prevents thundering-herd refresh calls
- **Stale response guards** — All async fetches use an incrementing `fetchId` counter; responses discarded if a newer fetch was initiated
- **Two Pinia stores only** — `auth` (session/org context) and `ui` (sidebar state). YAGNI applied strictly
- **shadcn-vue for accessible primitives** — Dialog, Select, DropdownMenu come with correct ARIA roles. A11y work focused on what primitives don't cover
- **URL sanitization** — `safeHref` utility strips non-http(s) URLs from CVE references to prevent XSS via `javascript:` URLs

## Tests added

32 test files across views, components, stores, composables, and API client covering login/register flows, CVE search/detail, watchlist management, member/group management, invitation acceptance, pagination, auth store, router guards, and API client CSRF/refresh behavior.

## Gotchas discovered

- **Go nil slice → JSON `null`** — Router guard crashed on `auth.user?.orgs?.length` when orgs was `null`
- **Stale responses on rapid navigation** — Required incrementing counter pattern in every async view
- **Org switch requires explicit re-fetch** — `onMounted` doesn't re-run; all org-scoped views need `watch` on `activeOrgId`
- **Mobile sidebar Sheet stays open on navigation** — Required explicit close in router `afterEach` hook

## Quality checks

- **Type safety:** `vue-tsc --build` in CI
- **Linting:** ESLint + Prettier enforced in CI
- **Two rounds of bug hunts** identified and fixed ~20 bugs (stale responses, org-switch gaps, infinite reload loops, dialog stale state, double-submit vulnerabilities)
