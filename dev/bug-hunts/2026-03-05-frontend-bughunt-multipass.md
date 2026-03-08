# Frontend Bug Hunt Report — Multi-Pass (Re-run)

## Scope
Vue 3 SPA frontend in `.worktrees/frontend/web/src/` (branch `feature/frontend`).
Excluded: `components/ui/` (shadcn-vue primitives), all test files.

**Files analyzed (~40):**
- Infrastructure: `router/index.ts`, `stores/auth.ts`, `stores/ui.ts`, `lib/api/client.ts`, `lib/api/orgFetch.ts`, `composables/usePagination.ts`, `main.ts`, `lib/utils.ts`
- Layouts: `AuthenticatedLayout.vue`, `PublicLayout.vue`
- Views: `LoginView`, `RegisterView`, `InvitationView`, `CreateOrgView`, `CveSearchView`, `CveDetailView`, `FeedStatusView`, `MembersView`, `GroupsView`, `WatchlistListView`, `WatchlistDetailView`, `NotFoundView`
- Components: `AppSidebar`, `OrgSwitcher`, `UserMenu`, `EmptyState`, `ErrorAlert`, `LoadingSkeleton`
- CVE components: `CveSearchFilters`, `CveResultsTable`, `CveScoreCard`, `CveSourceComparison`
- Dialog components: `CreateWatchlistDialog`, `AddItemDialog`, `InviteMemberDialog`, `GroupDialog`, `GroupMembersDialog`

All five passes performed.

### Previous Report Status

This is a re-run. The previous report (same date) found 8 bugs. Of those, **6 have been fixed:**
- ~~Org-scoped views don't react to org switch~~ — all four views now watch `activeOrgId`
- ~~RegisterView doesn't navigate after registration~~ — now has `router.push('/create-org')`
- ~~WatchlistDetailView blank page on error~~ — now has error state branch
- ~~Pagination race condition~~ — CveSearchView now uses `fetchId` counter
- ~~MembersView role change silent swallow~~ — now sets `roleChangeError` + forces re-render
- ~~Confirmation dialogs double-submit~~ — all now have submitting guards + disabled buttons

**2 bugs persist** (re-confirmed below as bugs #1 and #5).

---

## Bugs

### 1. Raw fetch() calls bypass 401 refresh middleware — expired sessions cause opaque errors on all org-scoped pages
**Location:** All org-scoped views and dialogs (10+ files); `orgFetch.ts` exists but is never imported
**Severity:** significant
**Evidence:** The `openapi-fetch` client (`lib/api/client.ts:38-65`) has `refreshMiddleware` that intercepts 401 responses, calls `/auth/refresh`, and retries. A wrapper `orgFetch.ts` was written to provide the same behavior for raw `fetch()` calls — it imports `refreshTokens` from `client.ts` and implements the same coalesce-refresh-retry pattern. But no component or view imports `orgFetch`. Every org-scoped endpoint uses raw `fetch()` directly:

```typescript
// GroupsView.vue — raw fetch, no refresh handling
const resp = await fetch(apiBase(), {
  method: 'GET',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
})
```

When the access token expires:
- CVE pages (using `client.GET`) → automatic refresh + retry → works
- Members/Groups/Watchlists (using raw `fetch()`) → 401 → "Failed to load" error

**Impact:** After token expiry, all org-scoped pages break with generic errors. User must reload or navigate to a typed-client page (CVE search) to trigger a refresh.
**Found in:** Pass 2 — Cross-sibling pattern violations

---

### 2. Router guard fails to redirect orgless users when API returns `orgs: null`
**Location:** `router/index.ts:82`
**Severity:** significant
**Evidence:** The router guard checks:
```typescript
if (requiresOrg && auth.isAuthenticated && auth.user?.orgs?.length === 0) {
  return { name: 'create-org' }
}
```
The Go backend serializes nil slices as `null` in JSON (standard Go behavior). When `orgs` is `null`:
- `null?.length` → `undefined`
- `undefined === 0` → `false`
- Redirect does NOT trigger

The user proceeds to an org-required page with `activeOrgId = null`, causing API URLs like `/api/v1/orgs/null/members` → 404.

The second guard check is also affected:
```typescript
if (requiresOrg && auth.isAuthenticated && !auth.activeOrgId
    && auth.user?.orgs && auth.user.orgs.length > 0) {
  auth.setActiveOrg(auth.user.orgs[0]!.org_id)
}
```
When `orgs` is `null`: `auth.user?.orgs` → `null` → falsy → short-circuits correctly (no crash). But the missing redirect in the first check means the user reaches the page anyway.

**Fix:** `(auth.user?.orgs?.length ?? 0) === 0` or `!auth.user?.orgs?.length`
**Impact:** Users with no orgs whose backend returns `orgs: null` bypass create-org redirect and land on a broken dashboard.
**Found in:** Pass 1 — Contract violations

---

### 3. CveDetailView lacks stale response protection when cveId changes
**Location:** `CveDetailView.vue` — `fetchCve()` and `fetchSources()` functions, `watch(cveId, ...)` at bottom of script
**Severity:** minor
**Evidence:** CveSearchView correctly uses a `fetchId` counter to discard stale responses:
```typescript
// CveSearchView — correct
let fetchId = 0
async function fetchCves() {
  const currentFetchId = ++fetchId
  // ... fetch ...
  if (currentFetchId !== fetchId) return  // discard stale
}
```

CveDetailView watches `cveId` and fires two parallel requests with no staleness guard:
```typescript
watch(cveId, () => {
  fetchCve()    // no fetchId check
  fetchSources() // no fetchId check
})
```
If `cveId` changes rapidly (e.g., browser back/forward, linked CVEs), old responses can overwrite new data — the user sees details for a different CVE than the URL indicates.

**Impact:** Under rapid navigation, CVE detail page can display data for the wrong CVE. Low probability in typical use but achievable with browser history navigation.
**Found in:** Pass 3 — Failure mode reasoning / Pass 4 — Concurrency reasoning

---

### 4. GroupMembersDialog silently swallows fetchData errors
**Location:** `GroupMembersDialog.vue` — `fetchData()` catch block
**Severity:** minor
**Evidence:**
```typescript
async function fetchData() {
  loading.value = true
  try {
    const [groupResp, orgResp] = await Promise.all([...])
    if (groupResp.ok) { groupMembers.value = await groupResp.json() }
    if (orgResp.ok) { orgMembers.value = await orgResp.json() }
  } catch {
    // Silently fail
  } finally {
    loading.value = false
  }
}
```
On network error: catch block is empty, `loading` clears, `groupMembers` stays `[]`. The dialog displays "No members in this group yet" — indistinguishable from a genuinely empty group.

Compare with GroupsView.fetchGroups() which properly sets `error.value` on failure.

**Impact:** Admin opens group members dialog during network issues, sees "no members", might not investigate further.
**Found in:** Pass 5 — Error propagation

---

### 5. WatchlistDetailView.fetchItems() has no catch block — network errors unhandled
**Location:** `WatchlistDetailView.vue` — `fetchItems()` function
**Severity:** minor
**Evidence:**
```typescript
async function fetchItems() {
  try {
    const resp = await fetch(`${apiBase()}/items`, {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })
    if (resp.ok) {
      const data = await resp.json() as { items?: WatchlistItemEntry[] }
      items.value = data.items ?? []
    }
  } finally {
    loading.value = false
  }
}
```
No `catch` block. On network error: the exception propagates through `onMounted()` to Vue's global `errorHandler` (`console.error`). The `finally` block sets `loading = false`, and `items` stays `[]`. User sees "No items in this watchlist" — misleading when the real problem is a network failure.

Additionally, when `resp.ok` is false (e.g., 403, 500), no error is set — items stays empty with no error message.

**Impact:** Network errors or non-ok responses on the items endpoint produce a misleading "empty" state with no error feedback.
**Found in:** Pass 3 — Failure mode reasoning / Pass 5 — Error propagation

---

### 6. MembersView.cancelInvitation() silently fails
**Location:** `MembersView.vue` — `cancelInvitation()` function
**Severity:** minor
**Evidence:**
```typescript
async function cancelInvitation(invitationId: string) {
  try {
    const resp = await fetch(`${apiBase()}/invitations/${invitationId}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
    })
    if (resp.ok) {
      invitations.value = invitations.value.filter((i) => i.id !== invitationId)
    }
  } catch {
    // Silently fail
  }
}
```
On error (network or HTTP): no feedback. The invitation stays in the list (correct), but the admin has no idea the cancellation failed. Compare with `confirmRemove()` in the same file which properly sets `removeError.value`.

**Impact:** Admin clicks cancel on an invitation, nothing happens, no error shown. Minor since the invitation remains visible (indicating it wasn't cancelled), but inconsistent with sibling actions.
**Found in:** Pass 5 — Error propagation

---

## Design Concerns

### orgFetch.ts exists but is unused — dual refresh pools are a latent race condition
`orgFetch.ts` was written to solve bug #1 (raw fetch lacking 401 refresh), but is never imported. It also introduces a second `refreshPromise` variable independent of `client.ts`'s:
```typescript
// client.ts
let refreshPromise: Promise<boolean> | null = null

// orgFetch.ts
let refreshPromise: Promise<boolean> | null = null  // separate variable!
```
If both are used simultaneously (e.g., after someone starts importing orgFetch), concurrent 401s from the typed client and orgFetch would trigger **two independent** refresh calls, racing on the refresh token rotation. The fix is either to share the coalescing state or to route all requests through the typed client.

### Dialog reset timing is inconsistent across siblings
- **Reset on open:** GroupDialog, GroupMembersDialog (`if (isOpen) resetForm()`)
- **Reset on close:** InviteMemberDialog, CreateWatchlistDialog, AddItemDialog (`if (!isOpen) resetForm()`)

Both approaches are functionally correct. However, "reset on open" is slightly safer (guarantees clean state even if close was missed), while "reset on close" is more intuitive (cleanup happens when dismissed). Standardizing on one approach would reduce cognitive overhead for future contributors.

### InviteMemberDialog stays open after success — unlike all other dialogs
After a successful invitation, InviteMemberDialog shows a success message and stays open. All other dialogs (CreateWatchlistDialog, AddItemDialog, GroupDialog) auto-close via `emit('update:open', false)` after success. This is likely intentional (allowing the admin to see confirmation before dismissing), but breaks the pattern established by the other four dialogs.