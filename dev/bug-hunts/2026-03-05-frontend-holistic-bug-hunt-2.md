# Bug Hunt Report — Frontend Holistic Analysis #2

## Scope

Read all 40 production source files in `.worktrees/frontend/web/src/` excluding `components/ui/` (generated shadcn-vue) and test files. Analysis focused on cross-component state flow, API call consistency, router guard assumptions vs component mount behavior, and reactive data handling.

Files analyzed: `main.ts`, `App.vue`, `router/index.ts`, `stores/auth.ts`, `stores/ui.ts`, `lib/api/client.ts`, `lib/api/orgFetch.ts`, `lib/api/schema.d.ts`, `lib/utils.ts`, `composables/usePagination.ts`, both layouts, all 7 components (AppSidebar, OrgSwitcher, UserMenu, LoadingSkeleton, EmptyState, ErrorAlert), all 4 CVE components, all 3 settings dialogs, both watchlist dialogs, and all 11 views.

## Bugs

### 1. `orgFetch` wrapper exists but is never imported — all org-scoped views lack 401 refresh+retry

**Location:** Every org-scoped view and dialog that uses raw `fetch()`:
- `views/WatchlistListView.vue:51`
- `views/WatchlistDetailView.vue:61, 86, 135, 162`
- `views/MembersView.vue:100, 127, 145, 185, 210`
- `views/GroupsView.vue:65, 119`
- `views/CreateOrgView.vue:25`
- `components/settings/GroupDialog.vue:93`
- `components/settings/GroupMembersDialog.vue:70-79, 101, 138`
- `components/settings/InviteMemberDialog.vue:90`
- `components/watchlist/CreateWatchlistDialog.vue:72`
- `components/watchlist/AddItemDialog.vue:112`

**Severity:** significant

**Evidence:** `lib/api/orgFetch.ts` was written specifically to wrap raw `fetch()` with the same CSRF header and 401→refresh→retry logic as the typed client's middleware. However, **zero files import or use it**. Every org-scoped view and dialog calls `fetch()` directly.

The typed client (`lib/api/client.ts`) has `refreshMiddleware` that transparently handles 401s — but only for calls made through `client.GET/POST/etc.` The typed client is only used by: auth store (`fetchMe`, `login`, `logout`), `CveSearchView`, `CveDetailView`, `InvitationView`, and `RegisterView`.

All other views (watchlists, members, groups, create-org) and their dialogs use raw `fetch()` with no 401 handling.

**Impact:** If a user's access token expires while they're on any org-scoped page (watchlists, members, groups), all subsequent API calls fail permanently with "Failed to load..." errors. The user must manually navigate away and back (triggering the router auth guard) or refresh the page to recover. This is especially likely for users who leave a tab open and return to it later.

---

### 2. Dual independent `refreshPromise` deduplication — typed client and `orgFetch` would fight

**Location:** `lib/api/client.ts:22` and `lib/api/orgFetch.ts:8`

**Severity:** minor (currently latent — orgFetch is never called, see bug #1)

**Evidence:** Both modules declare their own `let refreshPromise: Promise<boolean> | null = null`. If orgFetch were actually used, a concurrent 401 from a typed-client request and an orgFetch request would each independently call `refreshTokens()`. Since the refresh endpoint rotates the refresh token, the second call would likely invalidate the token issued by the first, causing an auth cascade failure.

**Impact:** Currently latent. If bug #1 is fixed by adopting `orgFetch`, this becomes a real race condition that could log users out unexpectedly under concurrent API calls.

---

### 3. Invitation accept identifies joined org by `name` instead of `org_id`

**Location:** `views/InvitationView.vue:71`

**Severity:** minor

**Evidence:**
```ts
const joinedOrg = auth.user?.orgs?.find((o) => o.name === invitation.value?.org_name)
```

After accepting an invitation, `auth.fetchMe()` refreshes the user's org list. The code then finds the just-joined org by matching on `org_name`. If two organizations share the same display name (org names are not guaranteed unique across the platform), this could activate the wrong org.

The root cause is that the `GET /auth/invitations/{token}` response (`GetInvitationOutputBody`) returns `org_name` but not `org_id`, and the `POST /auth/invitations/{token}/accept` response has no body. The frontend has no reliable way to identify the joined org.

**Impact:** If the user is already a member of an org with the same name as the one they're joining, `find()` returns the first match (the pre-existing org), and the user is switched to the wrong org after accepting. They'd need to manually switch orgs via the OrgSwitcher.

---

### 4. Mobile sidebar (Sheet) doesn't close on navigation

**Location:** `layouts/AuthenticatedLayout.vue:29-43`

**Severity:** minor

**Evidence:**
```vue
<Sheet v-model:open="mobileOpen">
  <!-- ... -->
  <SheetContent side="left" class="w-60 p-0">
    <AppSidebar />
  </SheetContent>
</Sheet>
```

`mobileOpen` is only set to `true` by the hamburger button click (`@click="mobileOpen = true"`) and back to `false` by the Sheet's built-in close mechanisms (overlay click, escape key, close button). When a user taps a `RouterLink` inside `AppSidebar`, vue-router navigates to the new page, but the Sheet stays open because `mobileOpen` is never set to `false`.

reka-ui's Sheet does not auto-close on child link clicks or route changes — clicks on RouterLinks are *inside* the Sheet content, not outside it.

**Impact:** On mobile, after tapping a nav item, the sidebar Sheet remains open overlaying the new page content. The user must explicitly close the sheet (tap overlay or swipe) after every navigation. This makes mobile navigation feel broken.

---

### 5. `MembersView` role-change Select has mismatched value/options for admin-viewing-admin

**Location:** `views/MembersView.vue:307-324` and `views/MembersView.vue:70-73`

**Severity:** minor

**Evidence:** When an admin user views another admin's role:

1. `canChangeRole(m)` returns `true` (admin viewing non-owner) → Select renders
2. `model-value` is `'admin'` (the member's current role)
3. `rolesAssignableBy('admin')` returns `['member', 'viewer']` — excludes `admin` because the filter uses strict `<`: `ROLE_HIERARCHY[r]! < callerLevel`

The Select trigger displays "admin" (the model-value), but the dropdown options only contain "Member" and "Viewer". The current role is not represented in the options list. Opening and closing the Select without selecting works fine (value preserved), but it's a confusing UX — the user sees a changeable dropdown with no way to keep the current value.

**Impact:** An admin user sees a role-change dropdown for fellow admins that implies the role can be managed, but the only actions available are demotion. If they accidentally select an option, they demote the other admin with no "undo" path (they can't re-assign admin).

---

### 6. `InvitationView` captures route param as non-reactive constant

**Location:** `views/InvitationView.vue:16`

**Severity:** minor

**Evidence:**
```ts
const token = route.params.token as string
```

`token` is a plain `const`, not a `computed()`. If the user navigates from `/invitations/abc` to `/invitations/def` (same route component, different param), Vue Router reuses the component instance. `route.params.token` updates reactively, but `token` retains the original value. The `onMounted` hook doesn't re-fire, so invitation details for the new token are never fetched.

Compare with `CveDetailView.vue:21` which correctly uses `computed(() => route.params.cveId as string)` and a `watch(cveId, ...)` to re-fetch on param changes.

**Impact:** If a user navigates between two invitation URLs without a full page reload (e.g., browser back/forward, or a programmatic `router.push`), they see stale invitation details from the first token. The accept button would try to accept the wrong invitation. In practice this is unlikely since invitation URLs are typically visited from email links (full navigation), but it's a latent correctness bug.

## Design Concerns

### Inconsistent API response parsing across views

Views that use the typed client (`CveSearchView`, `CveDetailView`) get response parsing from the OpenAPI schema — the list endpoint returns `{ items: [...], next_cursor: ... }`.

Views that use raw `fetch()` parse responses inconsistently:
- `WatchlistListView:63` expects `{ items?: WatchlistEntry[] }` (wrapper object)
- `WatchlistDetailView:93` expects `{ items?: WatchlistItemEntry[] }` (wrapper object)
- `MembersView:112` expects `MemberEntry[]` (raw array)
- `MembersView:134` expects `InvitationEntry[]` (raw array)
- `GroupsView:77` expects `GroupEntry[]` (raw array)
- `GroupMembersDialog:83-86` expects raw arrays for both calls

These endpoints aren't in the OpenAPI schema yet, so the correct format is unknown from the frontend's perspective. If the backend follows huma's standard response wrapping (all list endpoints return `{ items: [...] }`), then the raw-array parsings would silently set the ref to the wrapper object instead of the array. Vue's `v-for` on a non-array object produces no output — the page would show empty state instead of data, with no error.

### `refreshMiddleware` retry uses raw `fetch()` — bypasses middleware chain

`client.ts:64`:
```ts
return fetch(request.clone(), { credentials: 'include' })
```

The retry after token refresh uses raw `fetch()`, not the openapi-fetch client. This means the retry response bypasses any other middleware in the chain. Currently CSRF is the only other middleware (and the cloned request already has the header), but if additional middleware is added later (logging, metrics, error normalization), retried requests won't go through it.

Additionally, `request.clone()` on a Request whose body was consumed by the original `fetch()` call may throw `TypeError: Already read` for POST/PATCH/DELETE requests. Whether this happens depends on how openapi-fetch constructs and passes the Request object internally. If it does throw, the retry silently fails and the 401 response is returned to the caller. GETs (no body) are unaffected.

### No loading/error feedback for several destructive actions

- `WatchlistDetailView:160-177` — `deleteItem()` silently fails on error (empty catch block, item stays in list)
- `MembersView:208-225` — `cancelInvitation()` silently fails
- `GroupMembersDialog:134-154` — `removeMember()` shows error but there's no retry mechanism

These are minor UX issues — the user gets no feedback that their action failed, or sees an error with no way to retry except closing and reopening the dialog.