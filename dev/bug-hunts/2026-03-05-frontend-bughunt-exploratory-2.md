# Bug Hunt Report — Frontend Exploratory #2 (Depth-First)

## Scope

Analyzed the Vue 3 SPA in `.worktrees/frontend/web/src/` on branch `feature/frontend`. Started from the four high-risk areas specified in the brief and followed threads through their callers/callees.

**Files explored deeply (with thread-following):**
- `lib/api/client.ts` — CSRF middleware, 401 refresh interceptor
- `lib/api/orgFetch.ts` — raw fetch wrapper for non-OpenAPI endpoints
- `stores/auth.ts` — session management, org context, localStorage
- `router/index.ts` — auth guard, org guard, session restore
- `composables/usePagination.ts` — cursor stack
- All 10 view components (Login, Register, Invitation, CreateOrg, CveSearch, CveDetail, WatchlistList, WatchlistDetail, Members, Groups)
- All 5 dialog components (InviteMember, CreateWatchlist, AddItem, GroupDialog, GroupMembers)
- `OrgSwitcher.vue`, `UserMenu.vue`, `AppSidebar.vue`, `App.vue`, `main.ts`
- `lib/utils.ts`, `stores/ui.ts`
- All 4 CVE display components (SearchFilters, ResultsTable, ScoreCard, SourceComparison)

**Excluded:** `components/ui/` (shadcn-vue generated), test files.

## Bugs

### 1. Infinite page reload loop for unauthenticated users

**Location:** `lib/api/client.ts:40-59` + `router/index.ts:105-107`
**Severity:** critical

**Evidence:** When an unauthenticated user visits any page (including `/login`):

1. Auth guard (`router/index.ts:105-107`) sees `!auth.isAuthenticated`, calls `await auth.fetchMe()`
2. `fetchMe()` calls `client.GET('/auth/me')` which returns 401
3. `refreshMiddleware.onResponse` (`client.ts:40`) intercepts — URL `/api/v1/auth/me` is NOT in the exclusion list (only `/auth/refresh` and `/auth/login` are excluded at line 45)
4. `refreshTokens()` fires and fails (no refresh cookie)
5. Line 58: `window.location.href = '/login'` is assigned — scheduling a hard browser navigation
6. Middleware returns the original 401 response; `fetchMe()` resolves with `false`
7. Auth guard completes — either allows the route or does a soft redirect to `/login`
8. The pending `window.location.href = '/login'` fires after the current event loop, causing a full page reload
9. On reload, the Vue app boots and GOTO step 1

Setting `window.location.href` to the current URL causes a reload in all browsers. The result is the login page flickers and reloads in an infinite loop.

**Impact:** No unauthenticated user can ever see the login page. The app is unusable for anyone who isn't already logged in. This is a ship-blocker.

### 2. Dual `refreshPromise` — token refresh not coalesced across typed client and raw fetch

**Location:** `lib/api/client.ts:22` and `lib/api/orgFetch.ts:8`
**Severity:** significant

**Evidence:** Both modules declare their own independent `refreshPromise` variable:

```typescript
// client.ts:22
let refreshPromise: Promise<boolean> | null = null

// orgFetch.ts:8
let refreshPromise: Promise<boolean> | null = null
```

They share the same `refreshTokens()` function (orgFetch imports it from client.ts), but the coalescing logic operates on separate variables. If a typed client request and an `orgFetch` request both receive 401 simultaneously:
- `client.ts` creates `refreshPromise` A → calls `refreshTokens()`
- `orgFetch.ts` creates `refreshPromise` B → calls `refreshTokens()` independently
- Two concurrent `POST /auth/refresh` calls fire

**Impact:** If the backend uses refresh token rotation (standard security practice — the old refresh token is invalidated when a new one is issued), the second refresh call finds the token already consumed and fails. One of the two callers redirects to `/login`, logging the user out mid-session.

### 3. All org-scoped views use raw `fetch()` — bypassing the 401 refresh interceptor

**Location:** 10 components, ~30 call sites
**Severity:** significant

**Evidence:** The codebase has two API patterns:
- **Typed client** (`client.ts`): Has `refreshMiddleware` that retries on 401 after refreshing tokens. Used only for CVE endpoints.
- **Raw `fetch()`**: Used directly in all org-scoped views. No refresh interceptor.

`orgFetch.ts` exists as a wrapper with 401 refresh+retry, but **no view uses it**. Every raw `fetch()` call just shows a generic error on 401.

Affected views and call sites:
- `WatchlistDetailView.vue`: lines 61, 86, 135, 162 (4 endpoints)
- `WatchlistListView.vue`: lines 51, 90 (2 endpoints)
- `MembersView.vue`: lines 100, 127, 145, 185, 210 (5 endpoints)
- `GroupsView.vue`: lines 65, 119 (2 endpoints)
- `GroupMembersDialog.vue`: lines 69-80, 101, 138 (4 endpoints)
- `GroupDialog.vue`: line 93 (1 endpoint)
- `CreateWatchlistDialog.vue`: line 72 (1 endpoint)
- `InviteMemberDialog.vue`: line 90 (1 endpoint)
- `AddItemDialog.vue`: line 112 (1 endpoint)
- `CreateOrgView.vue`: line 25 (1 endpoint)

**Impact:** When the access token expires mid-session:
- CVE search/detail pages auto-recover (typed client refreshes transparently)
- Watchlists, members, groups, invitations, and org creation all break with generic error messages
- The user sees "Failed to load members" etc. and has no recourse except refreshing the page

This affects the entire org management surface area of the app.

### 4. Invitation acceptance matches org by name instead of ID

**Location:** `views/InvitationView.vue:71`
**Severity:** minor

**Evidence:**
```typescript
const joinedOrg = auth.user?.orgs?.find((o) => o.name === invitation.value?.org_name)
```

After accepting an invitation, `fetchMe()` refreshes the user's org list, then the code searches for the joined org by `name`. Org names are not guaranteed unique (only `org_id` is unique). If two organizations share the same name, this could select the wrong one and call `setActiveOrg()` with the wrong ID.

The `POST /auth/invitations/{token}/accept` response likely includes the `org_id`, but the code discards the response body entirely (line 51 only destructures `error` and `response`, not `data`).

**Impact:** If two orgs share a name, the user could be switched to the wrong org after accepting an invitation — potentially viewing another org's data.

## Design Concerns

### Auth guard calls `fetchMe()` on every navigation for unauthenticated users

`router/index.ts:105-107`:
```typescript
if (!auth.isAuthenticated) {
  await auth.fetchMe()
}
```

This runs on EVERY navigation when the user isn't authenticated — including navigations to public pages like `/login` and `/register`. There's no "already tried and failed" flag, so each route change fires `GET /auth/me`. Beyond compounding Bug #1, this adds latency to every public page navigation even after Bug #1 is fixed. A `sessionChecked` flag would prevent redundant calls after the first failure.

### `window.location.href` redirect in middleware is a side-effect bomb

Both `client.ts:58` and `orgFetch.ts:50` use `window.location.href = '/login'` to handle failed refresh. This is a hard navigation that:
- Can't be caught or prevented by callers
- Races with Vue router's soft navigation
- Creates Bug #1's infinite loop

The middleware should return the 401 response and let the calling code decide how to handle auth failure (e.g., the auth store's `clearAuth()` + router redirect). Moving the redirect out of the middleware and into a centralized auth-failure handler would eliminate this entire class of bugs.

### Inconsistent API call patterns create a maintenance hazard

The codebase has three ways to make API calls:
1. `client.GET/POST/...` — typed, has CSRF and refresh middleware
2. `orgFetch()` — raw but has CSRF and refresh middleware (exists but unused)
3. `fetch()` — raw, manual CSRF, no refresh

Pattern 3 is used everywhere that pattern 2 should be. This inconsistency means every new org-scoped feature will likely copy the raw `fetch()` pattern from existing views, perpetuating Bug #3. The `orgFetch` wrapper should replace all raw `fetch()` calls, or the chi-registered endpoints should be added to the OpenAPI schema so the typed client can be used.