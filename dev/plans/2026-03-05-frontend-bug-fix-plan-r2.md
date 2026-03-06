# Frontend Bug Fix Plan — Round 2

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 12 bugs from the second frontend bug hunter round — 1 critical, 2 significant, 9 minor.

**Architecture:** Fix the critical auth loop first, then the router guard, then wire up `orgFetch` across all org-scoped views to get 401 refresh coverage. After infrastructure fixes, mop up UX bugs (mobile sidebar, silent errors, stale responses, invitation reactivity, role dropdown).

**Tech Stack:** Vue 3 + TypeScript, Vitest, openapi-fetch, vue-router, pinia, reka-ui (shadcn-vue)

**Worktree:** All work happens in `.worktrees/frontend`. Run git commands with `git -C .worktrees/frontend`. Run vitest with `cd .worktrees/frontend/web && npx vitest run`.

---

## Bug Inventory

| # | Bug | Severity | Task |
|---|-----|----------|------|
| B1 | orgFetch dead code — raw fetch() bypasses 401 refresh | significant | 3 |
| B2 | Dual refreshPromise (latent until B1 fixed) | minor (latent) | 3 |
| B3 | Invitation org match by name, not ID | minor | 7 |
| B4 | Infinite page reload loop for unauthenticated users | **critical** | 1 |
| B5 | Router guard null orgs bypass (`null?.length !== 0`) | significant | 2 |
| B6 | Mobile sidebar doesn't close on navigation | minor | 4 |
| B7 | Admin role Select mismatch (admin-viewing-admin) | minor | 8 |
| B8 | InvitationView non-reactive token param | minor (latent) | 7 |
| B9 | CveDetailView stale response race (no fetchId) | minor | 6 |
| B10 | GroupMembersDialog silent fetchData errors | minor | 5 |
| B11 | WatchlistDetailView.fetchItems() missing catch | minor | 5 |
| B12 | MembersView.cancelInvitation() silent fail | minor | 5 |

---

## Task 1: Fix infinite page reload loop (B4) — CRITICAL

**Problem:** When an unauthenticated user visits any page (including `/login`):
1. Auth guard calls `fetchMe()` → `client.GET('/auth/me')` → 401
2. `refreshMiddleware` intercepts — `/auth/me` is NOT in the exclusion list
3. `refreshTokens()` fails (no refresh cookie)
4. `window.location.href = '/login'` fires — hard page reload
5. On reload, app boots → GOTO step 1

**Fix:** (A) Broaden the auth-endpoint exclusion to cover ALL `/auth/` paths, (B) remove `window.location.href` hard redirects from both modules (return 401, let auth guard handle redirect on next navigation), (C) add `sessionChecked` flag to auth store to skip redundant fetchMe() calls after the first failure.

**Files:**
- Modify: `web/src/lib/api/client.ts:45`
- Modify: `web/src/lib/api/orgFetch.ts:49-51`
- Modify: `web/src/stores/auth.ts`
- Modify: `web/src/lib/api/__tests__/client.test.ts`
- Modify: `web/src/lib/api/__tests__/orgFetch.test.ts`
- Modify: `web/src/router/__tests__/guards.test.ts`

### Step 1: Write failing test — refreshMiddleware should not intercept `/auth/me` 401s

In `web/src/lib/api/__tests__/client.test.ts`, add to the `refresh middleware` describe block:

```typescript
it('does not attempt refresh for auth/me endpoint', async () => {
  const { refreshMiddleware } = await import('../client')
  const fetchMock = vi.fn()
  globalThis.fetch = fetchMock

  const meRequest = new Request('http://localhost/api/v1/auth/me')
  const meResponse = new Response('unauthorized', { status: 401 })

  const result = await refreshMiddleware.onResponse!({
    ...middlewareParams(meRequest),
    response: meResponse,
  })

  expect((result as Response).status).toBe(401)
  expect(fetchMock).not.toHaveBeenCalled()
})
```

### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/lib/api/__tests__/client.test.ts`
Expected: FAIL — the middleware currently intercepts `/auth/me` and tries to refresh.

### Step 3: Fix the middleware exclusion

In `web/src/lib/api/client.ts`, change line 45 from:

```typescript
if (request.url.includes('/auth/refresh') || request.url.includes('/auth/login')) {
```

to:

```typescript
if (request.url.includes('/auth/')) {
```

This excludes ALL auth endpoints (`/auth/me`, `/auth/refresh`, `/auth/login`, `/auth/logout`, `/auth/register`, `/auth/invitations/*`) from the refresh interceptor. None of these should trigger a token refresh — they're the auth system itself.

### Step 4: Run test to verify it passes

Run: `cd .worktrees/frontend/web && npx vitest run src/lib/api/__tests__/client.test.ts`
Expected: PASS.

### Step 5: Remove `window.location.href` redirect from client.ts

In `web/src/lib/api/client.ts`, change lines 57-59 from:

```typescript
    if (!success) {
      window.location.href = '/login'
      return response
    }
```

to:

```typescript
    if (!success) {
      return response
    }
```

### Step 6: Remove `window.location.href` redirect from orgFetch.ts

In `web/src/lib/api/orgFetch.ts`, change lines 49-51 from:

```typescript
  if (!refreshed) {
    window.location.href = '/login'
    return resp
  }
```

to:

```typescript
  if (!refreshed) {
    return resp
  }
```

### Step 7: Update orgFetch redirect test

In `web/src/lib/api/__tests__/orgFetch.test.ts`, update the "redirects to /login" test to expect a 401 response instead of a redirect:

```typescript
it('returns 401 response when refresh fails', async () => {
  const fetchMock = vi.fn()
  fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
  fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }))
  globalThis.fetch = fetchMock

  const { orgFetch } = await import('../orgFetch')
  const resp = await orgFetch('/api/v1/orgs/123/members')

  expect(resp.status).toBe(401)
})
```

### Step 8: Update client.ts redirect test

In `web/src/lib/api/__tests__/client.test.ts`, update the "redirects to /login when refresh fails" test:

```typescript
it('returns original 401 response when refresh fails', async () => {
  const { refreshMiddleware } = await import('../client')

  const fetchMock = vi.fn()
  fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }))
  globalThis.fetch = fetchMock

  const request = new Request('http://localhost/api/v1/cves')
  const response = new Response('unauthorized', { status: 401 })

  const result = await refreshMiddleware.onResponse!({
    ...middlewareParams(request),
    response,
  })

  expect((result as Response).status).toBe(401)
})
```

### Step 9: Add `sessionChecked` flag to auth store

In `web/src/stores/auth.ts`, add a `sessionChecked` ref and update `fetchMe()`:

After line 16 (`const activeOrgId = ref<string | null>(null)`), add:

```typescript
const sessionChecked = ref(false)
```

In `fetchMe()`, add `sessionChecked.value = true` after the `client.GET` call (regardless of success/failure):

```typescript
async function fetchMe(): Promise<boolean> {
  const { data, error } = await client.GET('/auth/me')
  sessionChecked.value = true
  if (error || !data) {
    return false
  }
  // ... rest unchanged
}
```

In `clearAuth()`, reset the flag:

```typescript
function clearAuth() {
  user.value = null
  activeOrgId.value = null
  sessionChecked.value = false
  localStorage.removeItem(ACTIVE_ORG_KEY)
}
```

Add `sessionChecked` to the return object.

### Step 10: Update auth guard to skip redundant fetchMe()

In `web/src/router/index.ts`, change lines 105-107 from:

```typescript
  if (!auth.isAuthenticated) {
    await auth.fetchMe()
  }
```

to:

```typescript
  if (!auth.isAuthenticated && !auth.sessionChecked) {
    await auth.fetchMe()
  }
```

### Step 11: Write test for sessionChecked behavior

In `web/src/router/__tests__/guards.test.ts`, add:

```typescript
it('does not call fetchMe when session was already checked and failed', async () => {
  const auth = useAuthStore()
  auth.sessionChecked = true
  const fetchSpy = vi.spyOn(auth, 'fetchMe').mockResolvedValue(false)

  const router = createTestRouter()
  await router.push('/login')
  await router.isReady()

  expect(fetchSpy).not.toHaveBeenCalled()
  expect(router.currentRoute.value.name).toBe('login')
})
```

### Step 12: Write auth.test.ts tests for sessionChecked

In `web/src/stores/__tests__/auth.test.ts`, add a new describe block:

```typescript
describe('sessionChecked', () => {
  it('starts as false', () => {
    const auth = useAuthStore()
    expect(auth.sessionChecked).toBe(false)
  })

  it('is set to true after successful fetchMe', async () => {
    const meData = {
      user_id: 'u1',
      email: 'test@example.com',
      display_name: 'Test',
      orgs: [],
    }
    vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

    const auth = useAuthStore()
    await auth.fetchMe()

    expect(auth.sessionChecked).toBe(true)
  })

  it('is set to true after failed fetchMe', async () => {
    vi.mocked(client.GET).mockResolvedValue({ data: undefined, error: { detail: 'unauthorized' }, response: {} as Response })

    const auth = useAuthStore()
    await auth.fetchMe()

    expect(auth.sessionChecked).toBe(true)
  })

  it('is reset to false on clearAuth', async () => {
    vi.mocked(client.POST).mockResolvedValue({ data: undefined, error: undefined, response: {} as Response })

    const auth = useAuthStore()
    auth.sessionChecked = true

    await auth.logout()

    expect(auth.sessionChecked).toBe(false)
  })
})
```

### Step 13: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

### Step 14: Commit

```bash
git -C .worktrees/frontend add web/src/lib/api/client.ts web/src/lib/api/orgFetch.ts web/src/stores/auth.ts web/src/router/index.ts web/src/lib/api/__tests__/client.test.ts web/src/lib/api/__tests__/orgFetch.test.ts web/src/router/__tests__/guards.test.ts web/src/stores/__tests__/auth.test.ts
git -C .worktrees/frontend commit -m "fix: prevent infinite reload loop on unauthenticated page load"
```

---

## Task 2: Fix router guard null orgs bypass (B5)

**Problem:** Go serializes nil slices as `null` in JSON. `null?.length` returns `undefined`, and `undefined === 0` is `false`, so users with no orgs skip the create-org redirect and land on broken pages with `activeOrgId = null`.

**Files:**
- Modify: `web/src/router/index.ts:127`
- Modify: `web/src/router/__tests__/guards.test.ts`

### Step 1: Write failing test

In `web/src/router/__tests__/guards.test.ts`, add:

```typescript
it('redirects to /create-org when user has null orgs (Go nil slice)', async () => {
  const auth = useAuthStore()
  auth.user = {
    user_id: 'u1',
    email: 'test@example.com',
    display_name: 'Test',
    orgs: null as unknown as [],
  }
  vi.spyOn(auth, 'fetchMe').mockResolvedValue(true)

  const router = createTestRouter()
  await router.push('/cves')
  await router.isReady()

  expect(router.currentRoute.value.name).toBe('create-org')
})
```

### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/router/__tests__/guards.test.ts`
Expected: FAIL — the guard currently allows navigation because `null?.length === 0` is `false`.

### Step 3: Fix the guard check

In `web/src/router/index.ts`, change line 127 from:

```typescript
  if (requiresOrg && auth.isAuthenticated && auth.user?.orgs?.length === 0) {
```

to:

```typescript
  if (requiresOrg && auth.isAuthenticated && !auth.user?.orgs?.length) {
```

The `!` coercion handles `null`, `undefined`, `0`, and empty arrays — all cases where the user has no orgs.

### Step 4: Run test to verify it passes

Run: `cd .worktrees/frontend/web && npx vitest run src/router/__tests__/guards.test.ts`
Expected: PASS.

### Step 5: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

### Step 6: Commit

```bash
git -C .worktrees/frontend add web/src/router/index.ts web/src/router/__tests__/guards.test.ts
git -C .worktrees/frontend commit -m "fix: router guard handles null orgs from Go nil slice"
```

---

## Task 3: Consolidate refresh coalescing + wire orgFetch (B1, B2)

**Problem:** (B1) All org-scoped views use raw `fetch()`, bypassing the 401 refresh+retry that `orgFetch` provides. `orgFetch.ts` exists but is never imported. (B2) `client.ts` and `orgFetch.ts` each maintain their own `refreshPromise` — concurrent 401s from both patterns would fire two refresh calls, breaking token rotation.

**Fix:** (A) Export the coalesced refresh logic from `client.ts` so `orgFetch.ts` shares the same promise, (B) replace all raw `fetch()` calls in org-scoped views/dialogs with `orgFetch()`.

**Files:**
- Modify: `web/src/lib/api/client.ts` (export coalesced refresh)
- Modify: `web/src/lib/api/orgFetch.ts` (use shared coalescing)
- Modify: 10 view/dialog files (replace raw fetch with orgFetch import)
- Modify: `web/src/lib/api/__tests__/orgFetch.test.ts`

### Part A: Fix dual refreshPromise

#### Step 1: Export coalesced refresh from client.ts

In `web/src/lib/api/client.ts`, rename the existing module-level `refreshPromise` and export a `coalescedRefresh()` function that both the middleware and orgFetch can call:

Replace lines 20-35:

```typescript
// Prevents multiple concurrent refresh calls when several API requests
// receive 401 simultaneously.
let refreshPromise: Promise<boolean> | null = null

export async function refreshTokens(): Promise<boolean> {
  try {
    const res = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-Requested-By': 'CVErt-Ops' },
    })
    return res.ok
  } catch {
    return false
  }
}
```

With:

```typescript
async function refreshTokens(): Promise<boolean> {
  try {
    const res = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-Requested-By': 'CVErt-Ops' },
    })
    return res.ok
  } catch {
    return false
  }
}

// Prevents multiple concurrent refresh calls when several API requests
// receive 401 simultaneously. Shared by the typed client middleware and orgFetch.
let refreshPromise: Promise<boolean> | null = null

export function coalescedRefresh(): Promise<boolean> {
  if (!refreshPromise) {
    refreshPromise = refreshTokens().finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}
```

Note: `refreshTokens` is no longer exported — everything goes through `coalescedRefresh()`. The `.finally()` clears the promise after resolution, so the next 401 triggers a fresh refresh.

#### Step 2: Update refreshMiddleware to use coalescedRefresh

In the same file, update `refreshMiddleware.onResponse` — replace:

```typescript
    if (!refreshPromise) {
      refreshPromise = refreshTokens()
    }

    const success = await refreshPromise
    refreshPromise = null
```

With:

```typescript
    const success = await coalescedRefresh()
```

#### Step 3: Update orgFetch.ts to use coalescedRefresh

Replace the entirety of `web/src/lib/api/orgFetch.ts`:

```typescript
// ABOUTME: Shared fetch wrapper for org-scoped API calls not in the OpenAPI schema.
// ABOUTME: Applies credentials, CSRF headers, and 401 refresh+retry — matching the typed client's middleware.

import { coalescedRefresh } from './client'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * Fetch wrapper for org-scoped endpoints that aren't in the OpenAPI schema.
 * Applies the same protections as the typed client:
 * - `credentials: 'include'` on every request
 * - `X-Requested-By: CVErt-Ops` on state-changing methods
 * - 401 → refresh token → retry (with body preservation)
 */
export async function orgFetch(
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)

  if (!SAFE_METHODS.has(method)) {
    headers.set('X-Requested-By', 'CVErt-Ops')
    if (!headers.has('Content-Type') && init.body) {
      headers.set('Content-Type', 'application/json')
    }
  }

  const resp = await fetch(url, {
    ...init,
    method,
    headers,
    credentials: 'include',
  })

  if (resp.status !== 401) {
    return resp
  }

  // Attempt token refresh (coalesced with typed client).
  const refreshed = await coalescedRefresh()

  if (!refreshed) {
    return resp
  }

  // Retry with the same parameters — body is a string (not a stream), so it's safe to reuse.
  return fetch(url, {
    ...init,
    method,
    headers,
    credentials: 'include',
  })
}
```

#### Step 4: Update orgFetch tests

In `web/src/lib/api/__tests__/orgFetch.test.ts`, the existing tests should still pass since they mock `globalThis.fetch`. The refresh call now goes through `coalescedRefresh` → `refreshTokens` → `fetch`, which is the same underlying `fetch` mock.

Run: `cd .worktrees/frontend/web && npx vitest run src/lib/api/__tests__/orgFetch.test.ts`
Expected: PASS.

Also run the client tests to verify the middleware still works:

Run: `cd .worktrees/frontend/web && npx vitest run src/lib/api/__tests__/client.test.ts`
Expected: PASS.

### Part B: Replace raw fetch() with orgFetch in all views/dialogs

This is a mechanical change across 10 files. For each file:
1. Add `import { orgFetch } from '@/lib/api/orgFetch'`
2. Replace `fetch(url, { method, credentials: 'include', headers: {...}, body })` with `orgFetch(url, { method, body })`
3. Remove manual `credentials: 'include'` and `'X-Requested-By': 'CVErt-Ops'` headers (orgFetch handles both)

**Files to modify** (listed with the `fetch()` call lines to replace):

1. **`views/WatchlistListView.vue`** — `fetchWatchlists()` line 51, `confirmDelete()` line 90
2. **`views/WatchlistDetailView.vue`** — `fetchWatchlist()` line 61, `fetchItems()` line 86, `saveName()` line 135, `deleteItem()` line 162
3. **`views/MembersView.vue`** — `fetchMembers()` line 100, `fetchInvitations()` line 127, `changeRole()` line 145, `confirmRemove()` line 185, `cancelInvitation()` line 210
4. **`views/GroupsView.vue`** — `fetchGroups()` line 65, `confirmDelete()` line 119
5. **`views/CreateOrgView.vue`** — the `fetch` call for org creation
6. **`components/settings/GroupDialog.vue`** — the `fetch` call for create/update
7. **`components/settings/GroupMembersDialog.vue`** — `fetchData()` lines 70-79, `addMember()` line 101, `removeMember()` line 138
8. **`components/settings/InviteMemberDialog.vue`** — the `fetch` call for invitation
9. **`components/watchlist/CreateWatchlistDialog.vue`** — the `fetch` call for creation
10. **`components/watchlist/AddItemDialog.vue`** — the `fetch` call for adding item

#### Step 5: Wire orgFetch into each file

The pattern for each file is the same. Here are the representative transformations:

**For GET calls** — remove credentials and headers, just pass the URL:

Before:
```typescript
const resp = await fetch(`${apiBase()}/members`, {
  method: 'GET',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
})
```

After:
```typescript
const resp = await orgFetch(`${apiBase()}/members`)
```

**For POST/PATCH/DELETE with body** — keep method and body, remove credentials/CSRF:

Before:
```typescript
const resp = await fetch(`${apiBase()}/members/${userId}`, {
  method: 'PATCH',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-By': 'CVErt-Ops',
  },
  body: JSON.stringify({ role: newRole }),
})
```

After:
```typescript
const resp = await orgFetch(`${apiBase()}/members/${userId}`, {
  method: 'PATCH',
  body: JSON.stringify({ role: newRole }),
})
```

**For DELETE without body** — keep method only:

Before:
```typescript
const resp = await fetch(`${apiBase()}/members/${userId}`, {
  method: 'DELETE',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-By': 'CVErt-Ops',
  },
})
```

After:
```typescript
const resp = await orgFetch(`${apiBase()}/members/${userId}`, {
  method: 'DELETE',
})
```

Apply this pattern to ALL fetch() calls in the 10 files listed above. Add `import { orgFetch } from '@/lib/api/orgFetch'` to each file.

#### Step 6: Update test assertions — remove `headers` checks from view/dialog tests

**Why:** `orgFetch` constructs a `new Headers()` instance and passes it to `fetch()`. The existing test assertions use `expect.objectContaining({ 'Content-Type': 'application/json', 'X-Requested-By': 'CVErt-Ops' })` which matches plain objects but NOT `Headers` instances. These assertions will fail after the orgFetch wiring.

**Fix:** Remove the `headers: expect.objectContaining({...})` property from `expect.objectContaining()` in all fetch mock assertions across view/dialog tests. The `orgFetch.test.ts` test suite already verifies that correct headers are applied — view tests should only assert on `method`, `credentials`, and `body`.

**Files and assertion locations to fix (19 assertions across 10 files):**

1. **`views/__tests__/MembersView.test.ts`** — 4 assertions (around lines 372, 436, 506, 611)
2. **`views/__tests__/WatchlistDetailView.test.ts`** — 2 assertions (around lines 320, 388)
3. **`views/__tests__/WatchlistListView.test.ts`** — 2 assertions (around lines 301, 396)
4. **`views/__tests__/GroupsView.test.ts`** — 2 assertions (around lines 390, 490)
5. **`views/__tests__/CreateOrgView.test.ts`** — 1 assertion (around line 111, uses exact `headers: {...}`)
6. **`components/settings/__tests__/GroupMembersDialog.test.ts`** — 2 assertions (around lines 214, 266)
7. **`components/settings/__tests__/InviteMemberDialog.test.ts`** — 1 assertion (around line 159)
8. **`components/settings/__tests__/GroupDialog.test.ts`** — 2 assertions (around lines 161, 228)
9. **`components/watchlist/__tests__/CreateWatchlistDialog.test.ts`** — 1 assertion (around line 160)
10. **`components/watchlist/__tests__/AddItemDialog.test.ts`** — 2 assertions (around lines 196, 232)

**Pattern:** In each assertion, remove the entire `headers: expect.objectContaining({...})` block (or `headers: {...}` for exact matches). Keep `method`, `credentials`, and `body`.

Before:
```typescript
expect(mockFetch).toHaveBeenCalledWith(
  `/api/v1/orgs/${TEST_ORG_ID}/members/${userId}`,
  expect.objectContaining({
    method: 'PATCH',
    credentials: 'include',
    headers: expect.objectContaining({
      'Content-Type': 'application/json',
      'X-Requested-By': 'CVErt-Ops',
    }),
  }),
)
```

After:
```typescript
expect(mockFetch).toHaveBeenCalledWith(
  `/api/v1/orgs/${TEST_ORG_ID}/members/${userId}`,
  expect.objectContaining({
    method: 'PATCH',
    credentials: 'include',
  }),
)
```

#### Step 7: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

#### Step 8: Commit

```bash
git -C .worktrees/frontend add web/src/lib/api/client.ts web/src/lib/api/orgFetch.ts web/src/lib/api/__tests__/orgFetch.test.ts web/src/views/ web/src/components/
git -C .worktrees/frontend commit -m "fix: wire orgFetch into all org-scoped views for 401 refresh coverage"
```

---

## Task 4: Fix mobile sidebar close on navigation (B6)

**Problem:** On mobile, `AuthenticatedLayout.vue` renders `AppSidebar` inside a `Sheet`. When a `RouterLink` inside the sidebar is clicked, vue-router navigates but the Sheet stays open because `mobileOpen` is never set to `false`.

**Files:**
- Modify: `web/src/layouts/AuthenticatedLayout.vue`

**Note:** No TDD for this fix — testing Sheet overlay + responsive breakpoint behavior in jsdom is impractical (Sheet renders via portal, visibility depends on CSS media queries). Verified by running the full suite after the change.

### Step 1: Add route watcher to close the sheet

In `web/src/layouts/AuthenticatedLayout.vue`, update the script block. Add `useRoute` and a `watch`:

```vue
<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { Menu } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetContent,
  SheetTitle,
} from '@/components/ui/sheet'
import AppSidebar from '@/components/AppSidebar.vue'

const route = useRoute()
const mobileOpen = ref(false)

watch(() => route.path, () => {
  mobileOpen.value = false
})
</script>
```

### Step 2: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

### Step 3: Commit

```bash
git -C .worktrees/frontend add web/src/layouts/AuthenticatedLayout.vue
git -C .worktrees/frontend commit -m "fix: close mobile sidebar sheet on route navigation"
```

---

## Task 5: Fix remaining silent error handlers (B10, B11, B12)

Three components silently swallow errors — users see misleading "empty" states on failures.

**Files:**
- Modify: `web/src/components/settings/GroupMembersDialog.vue`
- Modify: `web/src/views/WatchlistDetailView.vue`
- Modify: `web/src/views/MembersView.vue`
- Modify: corresponding test files

### Part A: GroupMembersDialog.fetchData() error state (B10)

#### Step 1: Write failing test

In `web/src/components/settings/__tests__/GroupMembersDialog.test.ts`, add a test that verifies an error message is displayed when fetchData fails. (Check the existing test file to find the right describe block and helper setup — follow the existing pattern.)

```typescript
it('shows error when fetching group members fails', async () => {
  mockFetch.mockRejectedValueOnce(new Error('Network error'))
  await mountDialog()
  await flushPromises()

  expect(bodyText()).toContain('Failed to load')
})
```

#### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/components/settings/__tests__/GroupMembersDialog.test.ts`
Expected: FAIL — currently shows "No members" on error.

#### Step 3: Add error state to GroupMembersDialog

In `web/src/components/settings/GroupMembersDialog.vue`, add a `fetchError` ref:

After `const actionError = ref('')` add:

```typescript
const fetchError = ref('')
```

Update `fetchData()` — change the catch block:

```typescript
} catch {
  fetchError.value = 'Failed to load group members. Please try again.'
} finally {
```

Also clear `fetchError` at the start of `fetchData()`:

```typescript
async function fetchData() {
  loading.value = true
  fetchError.value = ''
```

And in the `watch` reset:

```typescript
if (isOpen) {
  groupMembers.value = []
  orgMembers.value = []
  selectedUserId.value = ''
  actionError.value = ''
  fetchError.value = ''
  fetchData()
}
```

In the template, add error display after the loading state and before the `v-else`:

```html
<div v-if="loading" class="flex items-center justify-center py-8 text-muted-foreground">
  <Loader2 class="mr-2 size-5 animate-spin" />
  Loading members...
</div>

<div v-else-if="fetchError" class="py-6 text-center text-sm text-destructive">
  {{ fetchError }}
</div>

<template v-else>
```

#### Step 4: Run test to verify it passes

Expected: PASS.

### Part B: WatchlistDetailView.fetchItems() error state (B11)

#### Step 5: Write failing test

In `web/src/views/__tests__/WatchlistDetailView.test.ts`, add:

```typescript
it('shows error when fetching items fails (network error)', async () => {
  mockWatchlistSuccess()
  mockFetch.mockRejectedValueOnce(new Error('Network error'))

  await mountView()
  await flushPromises()

  expect(wrapper.text()).toContain('Failed to load items')
})
```

#### Step 6: Fix fetchItems

In `web/src/views/WatchlistDetailView.vue`, add an `itemsError` ref:

```typescript
const itemsError = ref('')
```

Update `fetchItems()`:

```typescript
async function fetchItems() {
  itemsError.value = ''

  try {
    const resp = await orgFetch(`${apiBase()}/items`)

    if (resp.ok) {
      const data = await resp.json() as { items?: WatchlistItemEntry[] }
      items.value = data.items ?? []
    } else {
      itemsError.value = 'Failed to load items. Please try again.'
    }
  } catch {
    itemsError.value = 'Failed to load items. Please try again.'
  } finally {
    loading.value = false
  }
}
```

In the template, add error display for items after the "Items" heading section, before the empty/table states:

```html
<!-- Items error -->
<p v-if="itemsError" class="text-sm text-destructive">{{ itemsError }}</p>

<!-- Empty items state -->
<Card v-else-if="items.length === 0" class="py-12">
```

Also add a similar error handler for `deleteItem()`:

```typescript
async function deleteItem(itemId: string) {
  try {
    const resp = await orgFetch(`${apiBase()}/items/${itemId}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      items.value = items.value.filter((i) => i.id !== itemId)
    } else {
      itemsError.value = 'Failed to delete item. Please try again.'
    }
  } catch {
    itemsError.value = 'Failed to delete item. Please try again.'
  }
}
```

### Part C: MembersView.cancelInvitation() error feedback (B12)

#### Step 7: Write failing test

In `web/src/views/__tests__/MembersView.test.ts`, add:

```typescript
it('shows error when cancelling invitation fails', async () => {
  setupAuthStore('admin')
  mockMembersSuccess([makeMember()])
  mockInvitationsSuccess([
    makeInvitation({ id: 'inv-1', email: 'fail@example.com' }),
  ])
  await mountView()
  await flushPromises()

  mockFetch.mockReset()
  mockFetch.mockResolvedValueOnce({ ok: false, status: 500, json: () => Promise.resolve({}) })

  const cancelBtns = wrapper.findAll('[data-testid="cancel-invitation-btn"]')
  await cancelBtns[0]!.trigger('click')
  await flushPromises()

  expect(wrapper.text()).toContain('Failed to cancel invitation')
  // Invitation should still be in the list
  expect(wrapper.text()).toContain('fail@example.com')
})
```

#### Step 8: Fix cancelInvitation

In `web/src/views/MembersView.vue`, add a `cancelError` ref:

```typescript
const cancelError = ref('')
```

Update `cancelInvitation()`:

```typescript
async function cancelInvitation(invitationId: string) {
  cancelError.value = ''

  try {
    const resp = await orgFetch(`${apiBase()}/invitations/${invitationId}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      invitations.value = invitations.value.filter((i) => i.id !== invitationId)
    } else {
      cancelError.value = 'Failed to cancel invitation. Please try again.'
    }
  } catch {
    cancelError.value = 'Failed to cancel invitation. Please try again.'
  }
}
```

In the template, add error display above the invitations table:

```html
<div v-if="invitations.length > 0" class="space-y-4">
  <h2 class="text-lg font-semibold tracking-tight">Pending Invitations</h2>
  <p v-if="cancelError" class="text-sm text-destructive">{{ cancelError }}</p>
  <Table>
```

#### Step 9: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

#### Step 10: Commit

```bash
git -C .worktrees/frontend add web/src/components/settings/GroupMembersDialog.vue web/src/views/WatchlistDetailView.vue web/src/views/MembersView.vue web/src/components/settings/__tests__/GroupMembersDialog.test.ts web/src/views/__tests__/WatchlistDetailView.test.ts web/src/views/__tests__/MembersView.test.ts
git -C .worktrees/frontend commit -m "fix: surface error messages for group members, watchlist items, and invitation cancellation"
```

---

## Task 6: Fix CveDetailView stale response race (B9)

**Problem:** `CveDetailView` watches `cveId` and fires `fetchCve()` + `fetchSources()` with no stale response protection. If `cveId` changes rapidly (browser back/forward), old responses can overwrite new data — showing details for the wrong CVE.

`CveSearchView` already has the correct pattern: a `fetchId` counter that increments on each call and discards stale responses.

**Files:**
- Modify: `web/src/views/CveDetailView.vue`
- Modify: `web/src/views/__tests__/CveDetailView.test.ts`

### Step 1: Write failing test

**Important:** The existing `useRoute` mock returns a plain (non-reactive) object, so changing `mockRouteParams` won't trigger the component's watcher. Instead, test the `fetchId` mechanism directly by calling `fetchCve()` twice via `defineExpose`.

First, add `defineExpose({ fetchCve })` to the end of `CveDetailView.vue`'s `<script setup>` block (before `</script>`). This follows the existing pattern — see `MembersView.vue:241` for precedent.

Then, in `web/src/views/__tests__/CveDetailView.test.ts`, add:

```typescript
it('discards stale response when fetchCve is called again before previous resolves', async () => {
  // Mount with initial data
  mockGET.mockResolvedValueOnce({ data: makeCVEDetail({ cve_id: 'CVE-2024-12345' }) })
  mockGET.mockResolvedValueOnce({ data: { sources: makeSources() }, error: undefined })

  const { default: CveDetailView } = await import('@/views/CveDetailView.vue')
  const wrapper = mount(CveDetailView)
  await flushPromises()

  expect(wrapper.text()).toContain('CVE-2024-12345')

  // Set up a slow response (will become stale)
  let resolveStale: (v: unknown) => void
  const stalePromise = new Promise((resolve) => { resolveStale = resolve })
  mockGET.mockReturnValueOnce(stalePromise)

  // Trigger first refetch — increments fetchId
  const vm = wrapper.vm as any
  vm.fetchCve()

  // Before it resolves, trigger another refetch — increments fetchId again
  mockGET.mockResolvedValueOnce({
    data: makeCVEDetail({ cve_id: 'CVE-2024-12345', description_primary: 'Fresh data' }),
  })
  vm.fetchCve()
  await flushPromises()

  // Fresh data should be showing
  expect(wrapper.text()).toContain('Fresh data')

  // Now resolve the stale promise
  resolveStale!({
    data: makeCVEDetail({ cve_id: 'CVE-2024-12345', description_primary: 'Stale data' }),
  })
  await flushPromises()

  // Should still show fresh data, not stale
  expect(wrapper.text()).toContain('Fresh data')
  expect(wrapper.text()).not.toContain('Stale data')
})
```

### Step 2: Add fetchId counter

In `web/src/views/CveDetailView.vue`, add a fetchId counter and stale-response guard:

After `const error = ref('')` add:

```typescript
let fetchId = 0
```

Update `fetchCve()`:

```typescript
async function fetchCve() {
  const currentFetchId = ++fetchId
  loading.value = true
  error.value = ''
  notFound.value = false

  const { data, error: apiError } = await client.GET('/cves/{cve_id}', {
    params: { path: { cve_id: cveId.value } },
  })

  if (currentFetchId !== fetchId) return

  if (apiError || !data) {
    loading.value = false
    if (apiError && 'status' in apiError && apiError.status === 404) {
      notFound.value = true
    } else {
      error.value = 'Failed to load CVE details. Please try again.'
    }
    return
  }

  cve.value = data
  loading.value = false
}
```

Update `fetchSources()`:

```typescript
async function fetchSources() {
  const currentFetchId = fetchId
  sourcesLoading.value = true

  const { data } = await client.GET('/cves/{cve_id}/sources', {
    params: { path: { cve_id: cveId.value } },
  })

  if (currentFetchId !== fetchId) return

  sources.value = data?.sources ?? []
  sourcesLoading.value = false
}
```

Note: `fetchSources` captures the current `fetchId` without incrementing — the increment happens in `fetchCve`, and both read the same counter.

Also add `defineExpose({ fetchCve })` at the end of the `<script setup>` block (after the `watch` call, before `</script>`) — needed for test access since the route mock isn't reactive. This follows the existing pattern in `MembersView.vue:241`.

### Step 3: Run tests

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/CveDetailView.test.ts`
Expected: PASS.

### Step 4: Commit

```bash
git -C .worktrees/frontend add web/src/views/CveDetailView.vue web/src/views/__tests__/CveDetailView.test.ts
git -C .worktrees/frontend commit -m "fix: discard stale responses in CveDetailView on rapid cveId changes"
```

---

## Task 7: Fix InvitationView bugs (B3, B8)

**Problem:** (B8) `token` is captured as a plain `const` from `route.params.token`. If the route param changes (same component, different token), the component uses the stale value. (B3) After accepting, the code finds the joined org by `name` instead of `org_id` — names aren't guaranteed unique.

**Files:**
- Modify: `web/src/views/InvitationView.vue`
- Modify: `web/src/views/__tests__/InvitationView.test.ts`

### Step 1: Verify B8 fix doesn't break existing tests

B8 (non-reactive token) is a latent bug — it only triggers if the route param changes while the InvitationView is mounted (unlikely in practice since `/invitations/:token` is a distinct URL per token). The fix replaces `onMounted` with `watch(token, ..., { immediate: true })` which is functionally equivalent for the initial load.

The existing `useRoute` mock returns a plain object (not reactive), so testing re-fetch on token change requires a reactive mock. Since existing tests already cover the initial load path (which `{ immediate: true }` preserves), focus on verifying the refactor doesn't break existing tests rather than adding a hard-to-write reactive test.

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/InvitationView.test.ts`
Expected: All existing tests PASS after the `onMounted` → `watch` refactor.

### Step 2: Make token reactive

In `web/src/views/InvitationView.vue`, change line 16 from:

```typescript
const token = route.params.token as string
```

to:

```typescript
const token = computed(() => route.params.token as string)
```

Add `computed` to the import from `vue`:

```typescript
import { ref, computed, watch } from 'vue'
```

Replace `onMounted` with a `watch` on `token`:

```typescript
watch(token, async () => {
  loading.value = true
  error.value = ''
  invitation.value = null
  acceptError.value = ''

  const { data, error: apiError, response } = await client.GET('/auth/invitations/{token}', {
    params: { path: { token: token.value } },
  })

  loading.value = false

  if (apiError) {
    const status = (response as Response | undefined)?.status
    if (status === 404) {
      error.value = 'This invitation link is invalid.'
    } else if (status === 410) {
      error.value = 'This invitation has expired or has already been used.'
    } else {
      error.value = 'Failed to load invitation details.'
    }
    return
  }

  invitation.value = data
}, { immediate: true })
```

Update all references to `token` in the template and script to use `token.value` (inside script) — note that in the template, `token` already unwraps automatically as a computed ref.

In `acceptInvitation()`, update the `params` to use `token.value`:

```typescript
const { error: apiError, response } = await client.POST('/auth/invitations/{token}/accept', {
  params: { path: { token: token.value } },
})
```

And update the login link in the template:

```html
<RouterLink
  :to="`/login?redirect=/invitations/${token}`"
```

(This already works since template auto-unwraps computed refs.)

### Step 3: Fix org match by name (B3)

The cleanest fix is to search by `org_id` if available. Since the invitation API returns `org_name` but not `org_id`, and the accept endpoint returns no body, we can't get the `org_id` directly. The best we can do without an API change is to search more defensively.

However, the most robust fix given the current API: after `fetchMe()`, if the user's org list grew by exactly one entry compared to before, that's the joined org. Alternatively, since invitation responses include `org_name`, and `fetchMe()` returns the full org list, we can find the newest org by `joined_at` timestamp if available, or just trust the name match for now since org name collision is very unlikely in practice.

Keep the name match but add a comment noting the limitation:

```typescript
await auth.fetchMe()
// Match by name since the invitation API doesn't return org_id.
// Name collision is theoretically possible but unlikely in practice.
const joinedOrg = auth.user?.orgs?.find((o) => o.name === invitation.value?.org_name)
if (joinedOrg) {
  auth.setActiveOrg(joinedOrg.org_id)
}
router.push('/cves')
```

> **Note for plan executor:** If you find that the backend's `GET /auth/invitations/{token}` response includes an `org_id` field (check the OpenAPI schema), use that instead of name matching. Same for the `POST .../accept` response body.

### Step 4: Run tests

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/InvitationView.test.ts`
Expected: PASS.

### Step 5: Commit

```bash
git -C .worktrees/frontend add web/src/views/InvitationView.vue web/src/views/__tests__/InvitationView.test.ts
git -C .worktrees/frontend commit -m "fix: make invitation token reactive and note org name match limitation"
```

---

## Task 8: Fix admin role Select mismatch (B7)

**Problem:** When an admin views another admin's role, `rolesAssignableBy('admin')` returns `['member', 'viewer']` (strict `<`). The Select's `model-value` is `'admin'` but `'admin'` is not in the options list. The dropdown shows the current role but only offers demotion.

**Fix:** Change strict `<` to `<=` so the current role is included in the options. This lets the Select display correctly while still allowing demotion. An admin "assigning" admin to a peer admin is a no-op (backend validates).

**Files:**
- Modify: `web/src/views/MembersView.vue:72`
- Modify: `web/src/views/__tests__/MembersView.test.ts`

### Step 1: Write failing test

In `web/src/views/__tests__/MembersView.test.ts`, add:

First, update the `defineExpose` in `MembersView.vue` (line 241) to also expose `rolesAssignableBy`:

```typescript
defineExpose({ changeRole, rolesAssignableBy })
```

Then add the test:

```typescript
it('rolesAssignableBy includes current role for peer-level display', async () => {
  setupAuthStore('admin')
  mockMembersSuccess([])
  mockInvitationsSuccess([])
  await mountView()
  await flushPromises()

  const vm = wrapper.vm as any
  // Admin (level 3) should see: admin, member, viewer
  // Bug (<): returns only ['member', 'viewer'] — admin's own role is excluded
  // Fix (<=): returns ['admin', 'member', 'viewer'] — includes peer-level role
  expect(vm.rolesAssignableBy('admin')).toEqual(['admin', 'member', 'viewer'])
})
```

### Step 2: Fix rolesAssignableBy

In `web/src/views/MembersView.vue`, change line 72 from:

```typescript
return ASSIGNABLE_ROLES.filter((r) => ROLE_HIERARCHY[r]! < callerLevel)
```

to:

```typescript
return ASSIGNABLE_ROLES.filter((r) => ROLE_HIERARCHY[r]! <= callerLevel)
```

### Step 3: Run tests

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/MembersView.test.ts`
Expected: PASS.

### Step 4: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

### Step 5: Commit

```bash
git -C .worktrees/frontend add web/src/views/MembersView.vue web/src/views/__tests__/MembersView.test.ts
git -C .worktrees/frontend commit -m "fix: include current role in assignable options for admin role dropdown"
```
