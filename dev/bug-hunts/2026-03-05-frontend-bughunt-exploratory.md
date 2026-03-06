# Bug Hunt Report — Frontend (Exploratory)

**Date:** 2026-03-05
**Scope:** Vue 3 SPA in `.worktrees/frontend/web/src/` on branch `feature/frontend`
**Method:** Depth-first from high-risk entry points

## Scope

Files analyzed deeply (with thread-following):
- `lib/api/client.ts` — CSRF middleware, 401 refresh interceptor (chosen: single point of failure for all typed API calls)
- `stores/auth.ts` — session management, org context (chosen: auth state drives all org-scoped operations)
- `router/index.ts` — auth/org guards (chosen: access control gate)
- `composables/usePagination.ts` — keyset cursor stack (chosen: state corruption risk)
- All 12 views (`Login`, `Register`, `CreateOrg`, `CveSearch`, `CveDetail`, `WatchlistList`, `WatchlistDetail`, `Members`, `Groups`, `FeedStatus`, `Invitation`, `NotFound`)
- All 5 dialog components (`CreateWatchlistDialog`, `AddItemDialog`, `InviteMemberDialog`, `GroupDialog`, `GroupMembersDialog`)
- `OrgSwitcher`, `UserMenu`, `AppSidebar`, `App.vue`, both layouts

Files intentionally skipped: `components/ui/*` (shadcn-vue generated), test files, `CveScoreCard`, `CveSourceComparison`, `CveSearchFilters` (leaf display components with minimal logic).

## Bugs

### 1. Refresh middleware retry silently fails for body-carrying requests

**Location:** `lib/api/client.ts:63`
**Severity:** significant (currently latent)

**Evidence:** When a 401 triggers token refresh, the middleware retries the original request:
```ts
return fetch(request, { credentials: 'include' })
```
The `request` object's body stream was already consumed by the first `fetch()` call. Per the Fetch spec, calling `fetch()` with a Request whose `bodyUsed` is `true` throws a `TypeError`. This means any POST/PUT/PATCH request retried after a token refresh will throw instead of completing.

**Impact:** Currently latent — no typed-client mutations with request bodies are subject to refresh retry (`/auth/login` and `/auth/register` are excluded at line 45; `/auth/invitations/{token}/accept` has no body; all other mutations use raw `fetch()`). This WILL break when raw-fetch endpoints are migrated to the typed client. The fix is to clone the request before the first fetch or before retrying: `return fetch(request.clone(), { credentials: 'include' })` — but note the clone must happen *before* the first fetch consumes the body.

---

### 2. Raw fetch calls bypass the refresh middleware — no 401 recovery for org-scoped operations

**Location:** All org-scoped views and dialogs:
- `views/WatchlistListView.vue:50`
- `views/WatchlistDetailView.vue:56,78,125,146`
- `views/MembersView.vue:97,124,140,172,192`
- `views/GroupsView.vue:64,115`
- `views/CreateOrgView.vue:25`
- `components/watchlist/CreateWatchlistDialog.vue:72`
- `components/watchlist/AddItemDialog.vue:112`
- `components/settings/InviteMemberDialog.vue:90`
- `components/settings/GroupDialog.vue:93`
- `components/settings/GroupMembersDialog.vue:68-79,98,131`

**Severity:** significant

**Evidence:** These endpoints use raw `fetch()` instead of the `openapi-fetch` client. The typed client at `lib/api/client.ts` registers `csrfMiddleware` and `refreshMiddleware` — raw fetch calls get neither.

The `X-Requested-By` CSRF header IS manually added to mutating raw-fetch calls (POST/PATCH/DELETE), so CSRF protection works. But 401 handling does not — when the access token expires:
- CVE endpoints (typed client): token is silently refreshed, request retried, user sees no interruption
- Org-scoped endpoints (raw fetch): 401 → `!resp.ok` → generic "Failed to load" error or silent mutation failure

**Impact:** After access token expiry, all org-scoped operations break until page reload. The user sees "Failed to load watchlists" / "Failed to load members" errors with no recovery path. Mutations (create watchlist, delete member, etc.) fail silently — the API returns 401 but most mutation error handlers either show a generic message or catch silently.

---

### 3. Org switcher does not trigger data re-fetch — stale cross-org data

**Location:** `components/OrgSwitcher.vue:39` triggers `auth.setActiveOrg(org.org_id)`. No view watches `activeOrgId` for re-fetch.

**Severity:** significant

**Evidence:** `setActiveOrg()` in `stores/auth.ts:25-28` only updates the reactive ref and localStorage:
```ts
function setActiveOrg(orgId: string) {
  activeOrgId.value = orgId
  localStorage.setItem(ACTIVE_ORG_KEY, orgId)
}
```
All org-scoped views (WatchlistListView, MembersView, GroupsView) fetch data in `onMounted` using `apiBase()` which reads `auth.activeOrgId`. When the org switches:
1. The displayed list data is from Org A (fetched at mount time)
2. `apiBase()` now returns Org B's URL
3. New mutations (create, delete) go to Org B's API
4. The list still shows Org A's data

**Impact:** After switching orgs, the user sees stale data from the previous org. If they create a watchlist, it goes to Org B but doesn't appear in the list (which shows Org A data). If they delete an item, the DELETE hits Org B's API with an ID from Org A's data — the server would return 404 (item doesn't exist in Org B), and the frontend silently removes it from the displayed list even though nothing was actually deleted.

---

### 4. Invitation acceptance does not activate the accepted org

**Location:** `views/InvitationView.vue:69-70`

**Severity:** significant

**Evidence:** After successfully accepting an invitation:
```ts
await auth.fetchMe()
router.push('/cves')
```
`fetchMe()` refreshes the user's data (now includes the new org) and validates the persisted `activeOrgId`. If the user already belonged to another org, `activeOrgId` remains set to that org (it's still valid). The auto-select at `auth.ts:55-57` only fires when the user has exactly one org. After accepting an invitation, they have at least two.

The accept API response data is not captured — `data` is not destructured from `client.POST(...)`, so even if the API returns the org_id, it's ignored.

**Impact:** User accepts invitation to Org B, lands on CVE search in Org A's context. They must manually find and switch to Org B via the org switcher. Confusing for new users joining their first team.

---

### 5. Registration: no navigation after successful registration + auto-login

**Location:** `views/RegisterView.vue:58-59`

**Severity:** significant

**Evidence:** After successful registration:
```ts
// Auto-login after successful registration.
await auth.login(email.value, password.value)
```
`auth.login()` authenticates the user and returns `{ success: boolean }`, but the return value is not checked and no `router.push()` follows. The user is now authenticated but still viewing the registration form with all fields populated.

The auth guard's "redirect authenticated users away from public pages" check (`router/index.ts:118-124`) only fires on navigation events, not on reactive state changes. Since no navigation is triggered, the user stays on `/register`.

**Impact:** After registration, the user must manually navigate away from the registration page. If they re-submit the form, they'll get a 409 "Email already registered" error from their own registration.

---

### 6. CVE detail view does not re-fetch on route param change

**Location:** `views/CveDetailView.vue:110-113`

**Severity:** minor (currently latent)

**Evidence:** Data fetching happens only in `onMounted`:
```ts
onMounted(() => {
  fetchCve()
  fetchSources()
})
```
While `cveId` is a computed from `route.params.cveId` (line 20 — reactive), the fetch functions are not called when it changes. In Vue Router, navigating from `/cves/CVE-2024-001` to `/cves/CVE-2024-002` reuses the same component instance (same route record, different param). `onMounted` does not re-fire.

**Impact:** Currently latent — no in-app links navigate between CVE detail pages. But if cross-CVE links are added (e.g., in references or related CVEs), the detail view will show stale data from the first CVE.

## Design Concerns

### Dual API pattern creates an inconsistency surface

The codebase uses two different patterns for API calls:
- **Typed client** (`openapi-fetch`): CVE endpoints, auth endpoints — gets CSRF middleware, refresh middleware, type safety
- **Raw `fetch()`**: Watchlists, members, groups, orgs, invitations — manually adds CSRF headers, no refresh, no type safety

Any middleware added to the typed client in the future (request logging, error normalization, rate limiting) will only apply to half the endpoints. The split isn't by feature importance — it's by whether the endpoint happens to be in the OpenAPI schema.

### Silent mutation failures across raw-fetch views

Most mutation error handlers in raw-fetch views either swallow errors silently or show minimal feedback:
- `WatchlistDetailView.vue:158` — delete item: empty `catch {}`
- `MembersView.vue:156-158` — change role: empty `catch {}`
- `MembersView.vue:204-206` — cancel invitation: empty `catch {}`
- `GroupMembersDialog.vue:87-88,124-126,143-144` — all operations: empty `catch {}`

When the server rejects a mutation (auth error, validation error, race condition), the user gets no feedback. The UI doesn't change, creating the impression the operation succeeded.

### Admin navigation visible to all roles

`AppSidebar.vue:33-35` renders the admin section ("Feed Status") unconditionally — no role check. Any authenticated user (including viewers) sees admin navigation. Currently the target page is a placeholder, so there's no data leak, but this will need gating when real admin features ship.
