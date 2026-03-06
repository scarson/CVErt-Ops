# Frontend Design: CVErt Ops Web Application

**Date:** 2026-03-03
**Scope:** Core workflow frontend — Vue 3 SPA embedded in Go binary
**PLAN.md refs:** §20 (Frontend), §7 (Auth), §16 (API contract), Appendix B (endpoints)

---

## Decisions Made (Resolved in Brainstorming)

| Topic | Decision |
|---|---|
| Rendering strategy | SPA (Vue + API calls) — SSR provides no value for a logged-in application |
| Framework | Vue 3 + TypeScript — most readable for backend developer reviewing AI-generated code |
| Styling | Tailwind CSS — most reliable AI code generation target, deterministic utility classes |
| Component library | shadcn-vue (Radix Vue) — accessible headless primitives, owned source files |
| State management | Pinia — official Vue 3 store; only auth + UI stores (YAGNI) |
| API client | openapi-typescript + openapi-fetch — typed, lightweight, stays in sync with backend |
| Deployment | Embedded in Go binary via `embed.FS` — single binary, single Docker image |
| Repo structure | Same repo, `web/` directory — single CI pipeline, direct embed.FS reference |
| Initial scope | Core workflow first — validate stack, establish patterns, then expand |
| Frontend is open source | Yes — same repo, same license as backend |
| Browser support | Evergreen only (Chrome, Firefox, Safari, Edge) |
| Dark mode | Deferred — shadcn-vue supports it; groundwork in place |
| Login page | Standard form (email + password + OAuth buttons) — not email-first (YAGNI for SSO) |
| Org ID in URLs | No — active org from Pinia store + localStorage (can add later without breaking) |
| Navigation | Sidebar — scales better than top nav for this many sections |
| Token refresh | Reactive (on 401) — proactive timer is a future enhancement |
| E2E tests | Playwright, added as second frontend work stream (not deferred indefinitely) |

---

## Tech Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Framework | Vue 3 + TypeScript | Readable templates, stable Composition API, strong AI generation |
| Build | Vite | Standard for Vue 3, fast HMR, built-in proxy |
| Styling | Tailwind CSS | Deterministic utility classes, best AI generation target |
| Components | shadcn-vue (Radix Vue) | Accessible primitives, owned source files, customizable |
| State | Pinia | Official Vue 3 store, minimal API surface |
| Routing | Vue Router 4 (history mode) | Clean URLs, requires SPA fallback handler |
| API client | openapi-typescript + openapi-fetch | End-to-end typed from OpenAPI spec |
| Testing | Vitest + Vue Test Utils | Bundled with Vite, Vue-native |
| Linting | ESLint + Prettier + vue-tsc | Lint, format, and type-check |
| Deployment | embed.FS in Go binary | Single binary deployment |

---

## Project Structure

```
web/                          # npm project + Go package (coexist without interference)
  embed.go                    # //go:embed all:dist → exports web.Assets
  .gitignore                  # node_modules/, dist/, .vite/, coverage/
  src/
    api/                      # Generated OpenAPI types + fetch client (git-tracked)
    assets/                   # Static assets (icons, images)
    components/
      ui/                     # shadcn-vue component copies (Button, Dialog, Table, etc.)
      [feature]/              # Feature-specific components (CveSearchFilters, WatchlistItemRow)
    composables/              # Shared composition functions (useAuth, usePagination)
    layouts/                  # AuthenticatedLayout (sidebar + content), PublicLayout (minimal)
    router/                   # Vue Router config + navigation guards
    stores/                   # auth (user + active org), ui (toasts, sidebar state)
    views/                    # Page-level components (one per route)
    App.vue
    main.ts
  public/                     # Favicon, static files served as-is
  index.html                  # Vite entry point (proper meta tags: viewport, charset, description)
  package.json
  package-lock.json           # Committed — required for npm ci in CI
  vite.config.ts              # Dev proxy: /api → localhost:8080
  tailwind.config.ts
  tsconfig.json
.node-version                 # Node.js 20+ LTS (at repo root)
```

### Go-Side Additions

**`web/embed.go`** — single file, exports embedded FS:
```go
package web

import "embed"

//go:embed all:dist
var Assets embed.FS
```

Go and npm coexist in `web/` without interference: Go ignores non-`.go` files, npm ignores `.go` files. `node_modules/` doesn't contain Go packages.

**`internal/api/server.go`** — three additions to route registration:

1. **`/api/*` JSON 404 catch-all** — registered after all real API routes, before SPA fallback. Prevents API paths from returning `index.html`. Returns RFC 9457 Problem Details JSON.

2. **SPA fallback handler** — registered as the final catch-all (`/*`). Logic: try to serve the requested path from `web.Assets` embedded FS → if file exists, serve it with cache headers → if file doesn't exist, serve `index.html` (Vue Router handles client-side routing). File existence is checked against the embedded FS, not by extension.

3. **Cache headers** — hashed Vite assets (`assets/index-a1b2c3.js`): `Cache-Control: public, max-age=31536000, immutable`. `index.html`: `Cache-Control: no-cache` (references hashed assets, must always be fresh). CSP header configured based on actual external resource usage (fonts, CDN).

### Build and Embed

`dist/` is gitignored entirely. No placeholder files. If someone runs `go build` without `npm run build` first, they get a clear error: `pattern all:dist: no matching files found`. Build order is documented.

---

## Initial Scope — Core Workflow Pages

### Public (Unauthenticated)

| Page | Route | Description |
|------|-------|-------------|
| Login | `/login` | Email/password fields, OAuth buttons (GitHub, Google), register link |
| Register | `/register` | Email/password/name, OAuth buttons. Handles invite-only 403 with helpful message |
| Invitation | `/invitations/{token}` | Shows invite info (org name, role). Accept after login. If unauth, "Login to accept" links to `/login?redirect=/invitations/{token}` |

### Authenticated

| Page | Route | Description |
|------|-------|-------------|
| Create Organization | `/create-org` | First-time user flow. Simple name/description form |
| CVE Search | `/cves` | Primary landing page. Search bar, severity/vendor/date filters, paginated results table. Search state in URL query params (`?severity=critical&cursor=abc`) for back/forward and shareable URLs |
| CVE Detail | `/cves/{cve_id}` | Full CVE view: description, CVSS breakdown, EPSS score, affected products, references, source comparison. Read-only |
| Watchlist List | `/watchlists` | User's watchlists with item counts, last-updated. "New Watchlist" dialog (not a separate page). Empty state for new users |
| Watchlist Detail | `/watchlists/{id}` | Items in watchlist, add/remove items, edit name/description |
| Members | `/settings/members` | List org members, invite by email, assign roles (owner/admin/member/viewer), remove |
| Groups | `/settings/groups` | List groups, create/edit/delete, manage group membership |
| Feed Status | `/admin/feeds` | Per-feed table: last run time, status (success/error/running), record counts, "Run Now" button |
| 404 | `/:pathMatch(.*)` | Catch-all for unknown frontend routes |

### Navigation

**Sidebar layout** with sections:
- CVE Search
- Watchlists
- Settings → Members, Groups
- Admin → Feed Status
- User menu (logout) + org switcher (multi-org users)

### Routing Behavior

- `/` unauthenticated → redirect to `/login`
- `/` authenticated → redirect to `/cves` (CVE Search)
- Login page supports `?redirect=` query param for post-login navigation (used by invitation flow)
- Auth guard on all authenticated routes — redirect to `/login` if no valid session
- Org guard after auth — redirect to `/create-org` if user has no orgs

---

## Auth Flow

### Token Architecture

All tokens are **HttpOnly cookies** set by the backend. The frontend never sees, stores, or transmits tokens directly. The browser sends cookies automatically.

| Cookie | Path | Max-Age | Purpose |
|--------|------|---------|---------|
| `access_token` | `/` | 15 min | Sent with all requests |
| `refresh_token` | `/api/v1/auth` | 7 days | Sent only to auth endpoints |

### Login Flow

1. User submits credentials → `POST /api/v1/auth/login` → backend sets cookies
2. Frontend calls `GET /api/v1/auth/me` → receives user profile + org list
3. If `redirect` query param exists → navigate there (invitation acceptance)
4. Else if no orgs → `/create-org`
5. Else if one org → auto-select, navigate to `/cves`
6. Else → org selector, then `/cves`

### OAuth Flow

1. User clicks "Login with GitHub" → browser navigates to `GET /api/v1/auth/oauth/github`
2. Server sets state cookie, redirects to GitHub
3. GitHub redirects to server callback → server processes, sets JWT cookies
4. Server redirects to `FRONTEND_URL` (configurable; defaults to `/`)
5. Frontend loads, calls `/auth/me`, proceeds normally

**Backend change needed:** OAuth callback currently returns JSON `{user_id}`. Must redirect to `FRONTEND_URL` config value instead. `FRONTEND_URL` defaults to `/` (same-origin in production). Set to `http://localhost:5173` in development.

### Session Management

- **Active org:** stored in Pinia auth store + localStorage for persistence across page refresh
- **On page load:** read `activeOrgId` from localStorage → validate against `/auth/me` org list → if invalid (user removed from org), clear and redirect to org selector
- **On 401:** interceptor calls `POST /api/v1/auth/refresh` (refresh cookie scoped to `/api/v1/auth` is sent automatically) → retry original request. Uses single-refresh lock to prevent concurrent refresh calls from multiple simultaneous 401s
- **On 403 with invalid org:** re-fetch `/auth/me`, check org membership, redirect to org selector if removed
- **Refresh fails:** clear all auth state, redirect to `/login`
- **Logout:** `POST /api/v1/auth/logout` → backend clears cookies → frontend clears Pinia + localStorage → redirect to `/login`

### CSRF Protection

All state-changing requests (POST/PUT/PATCH/DELETE) must include `X-Requested-By: CVErt-Ops` header. Backend CSRF middleware requires this when cookie auth is present. Added as default middleware on the API client for all non-GET requests.

---

## API Client

### Stack

- **`openapi-typescript`** — generates TypeScript interfaces from the OpenAPI 3.1 spec
- **`openapi-fetch`** — lightweight typed fetch wrapper using those interfaces

### Configuration

```typescript
const client = createClient<paths>({
  baseUrl: '/api/v1',
  credentials: 'include', // send cookies
})

// Middleware: CSRF header on mutations
client.use({
  onRequest({ request }) {
    if (request.method !== 'GET') {
      request.headers.set('X-Requested-By', 'CVErt-Ops')
    }
    return request
  }
})

// Middleware: 401 refresh interceptor (with single-refresh lock)
```

### Type Generation Workflow

Triggered when backend API changes (same cadence as `sqlc generate`):

```bash
# Interim: curl from running server
curl http://localhost:8080/openapi > web/openapi.json

# Future: cobra subcommand (doesn't exist yet)
go run ./cmd/cvert-ops openapi > web/openapi.json

# Regenerate TypeScript types
cd web && npm run generate-api
```

Generated types are git-tracked. CI verifies freshness (fail if generated output differs from committed).

### Pinia Stores

Only two stores — everything else is component-local state or URL params:

| Store | Contents | Why global |
|-------|----------|-----------|
| `auth` | User info, active org ID, org list | Needed by route guards, API client, nav, every page |
| `ui` | Toast queue, sidebar collapsed state | Cross-component UI state |

CVE search results, watchlist data, member lists — all component-local. No store needed.

---

## Development Workflow

### Prerequisites

- Go 1.26+
- Node.js 20+ LTS (pinned in `.node-version`)
- npm

### Day-to-Day

Two terminals:
```
Terminal 1: go run ./cmd/cvert-ops serve    # Go API on :8080
Terminal 2: cd web && npm run dev           # Vite on :5173 with HMR
```

Access the app at `localhost:5173`. Vite proxies `/api/` to Go server. Frontend changes are instant (HMR). Backend changes require restarting the Go server.

No frontend environment variables needed — API is same-origin in production and proxied in development.

### npm Scripts

| Script | Command | Purpose |
|--------|---------|---------|
| `dev` | `vite` | Dev server with HMR + API proxy to :8080 |
| `build` | `vite build` | Production build → `dist/` |
| `test` | `vitest` | Unit/component tests |
| `lint` | `eslint .` | Lint check |
| `type-check` | `vue-tsc --noEmit` | TypeScript verification for .vue files |
| `generate-api` | `openapi-typescript openapi.json -o src/api/types.ts` | Regenerate API types from spec |

### Production Build

```bash
cd web && npm run build     # → web/dist/
go build ./cmd/cvert-ops    # embeds web/dist/ into binary
```

Single binary serves both API and frontend. No separate containers, no CDN, no reverse proxy required.

---

## CI Pipeline

Frontend steps run before `go build` (Go needs the built frontend to embed):

```
1. cd web && npm ci                    # install from lockfile
2. npm run lint && npm run type-check  # static analysis
3. npm run test                        # unit/component tests
4. npm run build                       # production build → dist/
5. go build ./cmd/cvert-ops            # embeds dist/, produces binary
6. go test ./...                       # backend tests
```

Additionally: verify generated API types are fresh (diff committed output against regenerated output).

---

## Testing

### Component and Store Tests

- **Vitest + Vue Test Utils** — TDD per CLAUDE.md
- Test scope: component rendering, user interactions, store state management, router guard behavior, API client interceptor (refresh lock, CSRF header)
- Test environment: `happy-dom` or `jsdom`

### E2E Tests

- **Playwright** — added as the second frontend work stream, before building the next batch of pages
- Covers full user flows: login → search → detail → watchlist CRUD
- Not deferred indefinitely — sequenced after core workflow component tests are established

---

## Cross-Cutting Requirements

- **Loading states:** skeleton components during API calls (shadcn-vue provides these)
- **Toast notifications:** success/error feedback for CRUD operations (shadcn-vue toast)
- **Error states:** consistent error display on API failure (network errors, 4xx, 5xx)
- **Empty states:** helpful messages for new users ("Create your first watchlist"), not blank pages
- **Desktop-first, responsive:** primary audience is DevSecOps on desktop. Tailwind responsive utilities make mobile passable without optimization effort
- **Accessibility:** WCAG 2.1 AA via Radix Vue (keyboard navigation, ARIA labels, focus management)
- **Global error handler:** `app.config.errorHandler` catches unhandled errors, prevents blank screens

---

## Backend Integration Points

Changes needed in the Go backend to support the frontend:

| # | Change | Scope |
|---|--------|-------|
| 1 | OAuth callback: redirect to `FRONTEND_URL` config instead of returning JSON | `internal/api/auth.go` — both GitHub and Google callbacks |
| 2 | `FRONTEND_URL` config field (defaults to `/`, set to Vite URL in dev) | `internal/config/config.go` |
| 3 | `web/embed.go` — embed `dist/` directory | New file in `web/` |
| 4 | SPA fallback handler — serve embedded files, fall back to `index.html` | `internal/api/server.go` |
| 5 | `/api/*` JSON 404 catch-all — prevent API paths from returning `index.html` | `internal/api/server.go` |
| 6 | Cache headers for static assets (immutable for hashed, no-cache for index.html) | SPA handler |
| 7 | CSP header — `script-src 'self'`, configured for any external resources | Middleware or SPA handler |
| 8 | `openapi` cobra subcommand — dump spec without starting server (optional, curl works) | `cmd/cvert-ops/` |

---

## Deferred Items

| Item | Why deferred |
|------|-------------|
| Public app homepage / marketing landing page | Not needed for core workflow |
| Alert rule builder, notification channels, reports | Built after core patterns are established |
| AI features (NL search, CVE summarization) | Backend Phase 4 features, not core workflow |
| Password reset, profile editing | Same form patterns as login/register, no new patterns |
| Dark mode toggle | shadcn-vue supports it; add later without architectural change |
| Audit log viewer | Enterprise-only feature |
| Advanced admin features | Beyond feed status |
| SSO discovery on login page | Enterprise Phase 5 feature; login page architecture supports adding it |
| Email-first login flow | YAGNI — standard form works, SSO discovery adds one API call later |

---

## Implementation Notes

These details surfaced during design review. Not architectural decisions, but important for the implementation plan:

- **Refresh lock:** The 401 interceptor must use a mutex/promise lock. If three API calls get 401 simultaneously, only one refresh fires; the others queue and retry after the single refresh completes.
- **OAuth in dev:** `FRONTEND_URL=http://localhost:5173` makes OAuth redirect to Vite. The OAuth *callback* URL still points to Go (`:8080`) — only the post-processing redirect changes.
- **Cookie Path:** Refresh token is `Path=/api/v1/auth`. The refresh interceptor must POST to `/api/v1/auth/refresh` specifically — any other path won't include the cookie.
- **Route guard ordering:** Auth check → org check → page load. Each guard can redirect independently.
- **Chi route ordering:** Register API routes (huma) → `/api/*` JSON 404 → `/*` SPA fallback. Verify during implementation that huma's subrouter handles API 404s within `/api/v1/` without falling through.
- **No frontend env vars:** The API is always same-origin (production) or proxied (development). No `VITE_API_BASE_URL` or similar.