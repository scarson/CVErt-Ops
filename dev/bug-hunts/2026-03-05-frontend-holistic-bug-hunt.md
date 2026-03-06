# Bug Hunt Report — Frontend Holistic Analysis

**Date:** 2026-03-05
**Branch:** `feature/frontend`
**Scope:** All production source files in `.worktrees/frontend/web/src/` excluding `components/ui/` (shadcn-vue generated) and test files. 38 files read.

## Scope

**Files read:**
- Bootstrap: `main.ts`, `App.vue`
- Router: `router/index.ts`
- Stores: `stores/auth.ts`, `stores/ui.ts`, `stores/counter.ts`
- API layer: `lib/api/client.ts`, `lib/api/schema.d.ts`, `lib/utils.ts`
- Composables: `composables/usePagination.ts`
- Layouts: `layouts/PublicLayout.vue`, `layouts/AuthenticatedLayout.vue`
- Shell components: `AppSidebar.vue`, `OrgSwitcher.vue`, `UserMenu.vue`, `LoadingSkeleton.vue`, `EmptyState.vue`, `ErrorAlert.vue`
- CVE components: `cve/CveSearchFilters.vue`, `cve/CveResultsTable.vue`, `cve/CveScoreCard.vue`, `cve/CveSourceComparison.vue`
- Watchlist components: `watchlist/CreateWatchlistDialog.vue`, `watchlist/AddItemDialog.vue`
- Settings components: `settings/GroupDialog.vue`, `settings/GroupMembersDialog.vue`, `settings/InviteMemberDialog.vue`
- Views: `LoginView`, `RegisterView`, `CreateOrgView`, `InvitationView`, `CveSearchView`, `CveDetailView`, `WatchlistListView`, `WatchlistDetailView`, `MembersView`, `GroupsView`, `FeedStatusView`, `NotFoundView`

**Approach:** Read every file, built a mental model of the full data flow (auth → router guards → layout → views → API calls → store mutations), then traced cross-cutting concerns: auth state, org context, API client usage patterns, error handling, and reactive state management.

## Bugs

### 1. RegisterView: No navigation after successful registration
**Location:** `views/RegisterView.vue:59`
**Severity:** significant
**Evidence:** After successful registration, the code auto-logs the user in:
```typescript
await auth.login(email.value, password.value)
```
But unlike `LoginView.vue:32` which calls `router.push(redirect)` on success, RegisterView does nothing after `auth.login()` resolves. The user is authenticated (store state is set) but remains on the `/register` page staring at the registration form. The auth guard only runs on navigation, not on store state changes, so there's no automatic redirect.

Compare with LoginView.vue:31-33:
```typescript
if (result.success) {
  const redirect = (route.query.redirect as string) || '/cves'
  router.push(redirect)
}
```
**Impact:** After registration, users are stuck on the register page. They must manually navigate elsewhere. Clicking any sidebar link would trigger the auth guard redirect, but the immediate experience is broken.

---

### 2. Org switch does not refetch page data — stale cross-org data displayed
**Location:** `components/OrgSwitcher.vue:39`, all org-scoped views
**Severity:** significant
**Evidence:** When a user switches orgs via OrgSwitcher, `auth.setActiveOrg(org.org_id)` updates the reactive store and localStorage. But every org-scoped view (`WatchlistListView`, `WatchlistDetailView`, `MembersView`, `GroupsView`) only fetches data in `onMounted()`, which doesn't re-fire when `activeOrgId` changes.

The `apiBase()` function in each view uses `auth.activeOrgId` reactively:
```typescript
function apiBase() {
  return `/api/v1/orgs/${auth.activeOrgId}/watchlists`
}
```
So future API calls (e.g., creating a watchlist) will target the NEW org, but the currently displayed data is from the OLD org.

**Impact:** After switching orgs, the user sees Org A's watchlists/members/groups but any create/delete/edit action targets Org B. This causes data confusion and could result in accidental operations on the wrong org.

---

### 3. MembersView: Admin can see role dropdown for peer admins, but current role is missing from options
**Location:** `views/MembersView.vue:68-75`
**Severity:** significant
**Evidence:** `canChangeRole(member)` returns `true` when `isAdmin && member.role !== 'owner'`. This means an admin sees a role Select dropdown for other admins.

But `rolesAssignableBy('admin')` filters `ASSIGNABLE_ROLES` by `ROLE_HIERARCHY[r] < 3`, which returns only `['member', 'viewer']`. The current role `admin` (level 3) is not in the dropdown options.

The Select component receives `:model-value="m.role"` (which is `'admin'`) but the options only contain `member` and `viewer`. The user sees a dropdown where:
- The displayed value is "admin" (not selectable)
- The only options are demotion choices
- There's no way to keep the current role

**Impact:** An admin viewing another admin's row sees a dropdown that can only demote. If they interact with it (even accidentally), the peer admin gets demoted irreversibly — only an owner can re-promote. The backend may reject this, producing a silent failure. Either way, the UX is broken: either show a badge (not a dropdown) for peers, or include the current role in the options.

---

### 4. WatchlistDetailView: Blank page on network/server errors
**Location:** `views/WatchlistDetailView.vue:54-74`
**Severity:** significant
**Evidence:** `fetchWatchlist()` handles HTTP 404 (sets `notFound = true`) and sets `loading = false` in the catch block, but never sets an `error` ref. The template has three states:
```html
<div v-if="loading">Loading...</div>
<div v-else-if="notFound">Not found</div>
<template v-else-if="watchlist">Content</template>
```

When a network error occurs or the server returns 500:
- `loading` → `false` (in catch)
- `notFound` → `false` (never set)
- `watchlist` → `null` (never set)

None of the three `v-if` conditions match. The page renders blank with no indication of what happened.

Compare with `WatchlistListView.vue` and `MembersView.vue` which both set `error.value` in their catch blocks and display it.

**Impact:** Any server or network error on the watchlist detail page produces a completely blank page — no error message, no retry option.

---

### 5. ErrorAlert: Retry button can never render
**Location:** `components/ErrorAlert.vue:23`
**Severity:** minor
**Evidence:** The retry button's visibility is conditioned on:
```html
<Button v-if="$attrs.onRetry" ...>
```
But `retry` is declared in `defineEmits<{ retry: [] }>()` on line 13-14. In Vue 3, when an event is declared via `defineEmits`, the corresponding `on*` listener is consumed by the emit system and NOT passed to `$attrs`. So `$attrs.onRetry` is always `undefined`, and the button never renders.

The correct check would be either:
- Remove `retry` from defineEmits and use `$attrs.onRetry` as a fallthrough listener, or
- Use a separate prop like `showRetry: boolean` to control visibility

**Impact:** Low — ErrorAlert doesn't appear to be used with `@retry` in any current view. But the component is fundamentally broken for its retry feature.

---

### 6. Refresh middleware retry fails for requests with body
**Location:** `lib/api/client.ts:63`
**Severity:** minor (latent — not triggered by current code)
**Evidence:** After a successful token refresh, the middleware retries the original request:
```typescript
return fetch(request, { credentials: 'include' })
```
The `request` parameter is the original Request object whose body was already consumed by the first `fetch()` call (internally by openapi-fetch). Per the Fetch spec, re-fetching a consumed Request throws a TypeError because the body stream is locked/disturbed.

Currently, all authenticated endpoints used via the typed client are either GET (no body) or excluded from refresh (login, refresh). So this bug is never hit. But the first time a POST/PUT/PATCH endpoint with a body is added to the typed client, it will fail on token refresh.

**Impact:** No current impact, but a latent bug. The fix is to clone the request before the initial fetch: store `const clonedRequest = request.clone()` before the initial fetch, then retry with the clone.

## Design Concerns

### Raw fetch vs. typed client split
10+ org-scoped endpoints use raw `fetch()` (watchlists, members, groups, invitations) while auth and CVE endpoints use the openapi-fetch typed client. The raw fetch calls:
- **Bypass the token refresh middleware** — if the access token expires, these calls return 401 without automatic retry. The user sees "Failed to load..." with no indication that their session expired.
- **Bypass runtime type checking** — responses are cast with `as Type` without validation, silently producing wrong types if the API evolves.
- **Manually duplicate CSRF headers** — each call adds `'X-Requested-By': 'CVErt-Ops'` manually, which is fragile.

The schema.d.ts file doesn't include org-scoped paths (no `/orgs/{org_id}/...` entries), which is likely why raw fetch is used. Once the schema is expanded, migrating to the typed client would fix all three issues.

### No URL sanitization on CVE reference links
`CveDetailView.vue:279` and `CveSourceComparison.vue:94` bind user-controllable URLs to `<a :href="...">`. While CVE data comes from trusted upstream sources (NVD, MITRE, etc.), defense-in-depth suggests validating that URLs use `http:` or `https:` schemes before rendering, particularly since this is a security product. A `javascript:` URL in a poisoned CVE record would execute in the user's authenticated session.
