# Frontend Bug Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 13 bugs found by three independent bug hunter analyses of the Vue 3 SPA frontend.

**Architecture:** Fixes are organized into 8 tasks by dependency order. Task 1 creates a shared `orgFetch()` utility that centralizes raw `fetch()` patterns (CSRF, credentials, 401 refresh). Tasks 2-4 fix auth/navigation flows. Tasks 5-7 fix UI state bugs. Task 8 hardens error handling across all views and dialogs.

**Tech Stack:** Vue 3 + TypeScript, Pinia stores, openapi-fetch, Vitest + @vue/test-utils

**Working directory:** `.worktrees/frontend/web/src/`
**Test command:** `npx vitest run` (from `.worktrees/frontend/web/`)
**Lint/typecheck:** `npx vue-tsc --noEmit && npx eslint .` (from `.worktrees/frontend/web/`)
**Build:** `npx vite build` (from `.worktrees/frontend/web/`)

---

## Bug Inventory

These bugs were identified across three independent analyses (Exploratory, Holistic, Multipass). Each task references the original bug IDs.

| # | Bug | Severity | Task |
|---|-----|----------|------|
| B1 | Raw fetch() bypasses 401 refresh middleware | significant | 1 |
| B2 | Org switch doesn't trigger data re-fetch | significant | 5 |
| B3 | RegisterView no navigation after registration | significant | 2 |
| B4 | Refresh middleware body-consumption on retry | minor (latent) | 1 |
| B5 | WatchlistDetailView blank page on errors | significant | 6 |
| B6 | Role change silent failure + visual mismatch | significant | 8 |
| B7 | Invitation acceptance doesn't activate joined org | significant | 3 |
| B8 | CVE detail no re-fetch on route param change | minor (latent) | 4 |
| B9 | ErrorAlert retry button never renders | minor | 7 |
| B10 | Pagination race condition (concurrent requests) | minor | ~~4~~ DONE |
| B11 | 9 action handlers silently swallow errors | significant (collective) | 8 |
| B12 | Confirmation dialogs no double-submit guard | minor | 8 |
| B13 | URL sanitization on CVE reference links | design concern | 4 |

---

## Task 1: Create shared `orgFetch()` utility (fixes B1, B4)

All org-scoped views use raw `fetch()` that bypasses the typed client's CSRF and refresh middleware. Rather than migrating everything to `openapi-fetch` (which requires adding org-scoped paths to `schema.d.ts`), create a shared fetch wrapper that applies the same protections.

**Files:**
- Create: `lib/api/orgFetch.ts`
- Create: `lib/api/__tests__/orgFetch.test.ts`
- Modify: `lib/api/client.ts` — export `refreshTokens` so orgFetch can reuse it

### Step 1: Write the failing tests

Create `lib/api/__tests__/orgFetch.test.ts`:

```typescript
// ABOUTME: Tests for the org-scoped fetch wrapper.
// ABOUTME: Verifies CSRF headers, credentials, 401 refresh+retry, and body-safe retry.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('orgFetch', () => {
  let originalFetch: typeof globalThis.fetch
  let originalLocation: Location

  beforeEach(() => {
    originalFetch = globalThis.fetch
    originalLocation = window.location
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...originalLocation, href: '' },
    })
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    Object.defineProperty(window, 'location', {
      writable: true,
      value: originalLocation,
    })
    vi.restoreAllMocks()
    vi.resetModules()
  })

  it('includes credentials on GET requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('[]', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [, init] = fetchMock.mock.calls[0]!
    expect(init.credentials).toBe('include')
  })

  it('adds CSRF header to POST requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members', {
      method: 'POST',
      body: JSON.stringify({ user_id: 'abc' }),
    })

    const [, init] = fetchMock.mock.calls[0]!
    expect(init.headers.get('X-Requested-By')).toBe('CVErt-Ops')
    expect(init.headers.get('Content-Type')).toBe('application/json')
  })

  it('adds CSRF header to DELETE requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('', { status: 204 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members/456', { method: 'DELETE' })

    const [, init] = fetchMock.mock.calls[0]!
    expect(init.headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('does not add CSRF header to GET requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('[]', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members')

    const [, init] = fetchMock.mock.calls[0]!
    expect(init.headers.get('X-Requested-By')).toBeNull()
  })

  it('retries on 401 after successful token refresh', async () => {
    const fetchMock = vi.fn()
    // 1st call: original request → 401
    fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
    // 2nd call: refresh → 200
    fetchMock.mockResolvedValueOnce(new Response('', { status: 200 }))
    // 3rd call: retry → 200
    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    const resp = await orgFetch('/api/v1/orgs/123/members')

    expect(resp.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    // 2nd call should be the refresh
    expect(fetchMock.mock.calls[1]![0]).toBe('/api/v1/auth/refresh')
  })

  it('redirects to /login when refresh fails', async () => {
    const fetchMock = vi.fn()
    fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
    fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    const resp = await orgFetch('/api/v1/orgs/123/members')

    expect(resp.status).toBe(401)
    expect(window.location.href).toBe('/login')
  })

  it('preserves body on POST retry after 401 refresh (B4 fix)', async () => {
    const body = JSON.stringify({ role: 'admin' })
    const fetchMock = vi.fn()
    fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
    fetchMock.mockResolvedValueOnce(new Response('', { status: 200 }))
    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members/456', {
      method: 'PATCH',
      body,
    })

    // 3rd call (retry) should have the body
    const retryInit = fetchMock.mock.calls[2]![1]
    expect(retryInit.body).toBe(body)
  })
})
```

### Step 2: Run tests to verify they fail

Run: `cd .worktrees/frontend/web && npx vitest run src/lib/api/__tests__/orgFetch.test.ts`
Expected: FAIL — module `../orgFetch` does not exist.

### Step 3: Export `refreshTokens` from client.ts

In `lib/api/client.ts`, the `refreshTokens` function is currently module-private. We need to export it so `orgFetch` can reuse it rather than duplicating the refresh logic.

Change line 24 from:
```typescript
async function refreshTokens(): Promise<boolean> {
```
to:
```typescript
export async function refreshTokens(): Promise<boolean> {
```

Also fix the body-consumption bug (B4) in the refresh middleware retry (line 63). Change:
```typescript
    // Retry the original request with fresh cookies.
    return fetch(request, { credentials: 'include' })
```
to:
```typescript
    // Retry the original request with fresh cookies.
    // Clone the request before retrying — the original body stream was consumed by the first fetch.
    return fetch(request.clone(), { credentials: 'include' })
```

**Important:** This `.clone()` fix addresses B4 for the typed client path. The `orgFetch` utility addresses B4 for the raw-fetch path by storing the body string and re-constructing.

### Step 4: Write the `orgFetch` implementation

Create `lib/api/orgFetch.ts`:

```typescript
// ABOUTME: Shared fetch wrapper for org-scoped API calls not in the OpenAPI schema.
// ABOUTME: Applies credentials, CSRF headers, and 401 refresh+retry — matching the typed client's middleware.

import { refreshTokens } from './client'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

let refreshPromise: Promise<boolean> | null = null

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

  // Attempt token refresh (coalesced).
  if (!refreshPromise) {
    refreshPromise = refreshTokens()
  }
  const refreshed = await refreshPromise
  refreshPromise = null

  if (!refreshed) {
    window.location.href = '/login'
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

### Step 5: Run tests to verify they pass

Run: `cd .worktrees/frontend/web && npx vitest run src/lib/api/__tests__/orgFetch.test.ts`
Expected: All 7 tests PASS.

### Step 6: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All 320+ tests PASS. The `refreshTokens` export is additive; the `.clone()` change doesn't break existing tests (all current typed-client 401 tests use GET).

### Step 7: Commit

```bash
git -C .worktrees/frontend add web/src/lib/api/orgFetch.ts web/src/lib/api/__tests__/orgFetch.test.ts web/src/lib/api/client.ts
git -C .worktrees/frontend commit -m "feat(api): add orgFetch wrapper with CSRF + 401 refresh for org-scoped endpoints"
```

---

## Task 2: Fix RegisterView navigation after registration (fixes B3)

After successful registration + auto-login, the user is stuck on `/register`. Add `router.push` matching the LoginView pattern.

**Files:**
- Modify: `views/RegisterView.vue:58-59`
- Modify: `views/__tests__/RegisterView.test.ts`

### Step 1: Write the failing test

Add to the existing `RegisterView.test.ts` test file. Find the test for successful registration and verify it asserts navigation. If no such test exists, add one:

```typescript
it('navigates to /create-org after successful registration and auto-login', async () => {
  // Mock successful registration
  fetchMocker.mockResponseOnce(JSON.stringify({}), { status: 200 })
  // Mock successful login
  fetchMocker.mockResponseOnce(JSON.stringify({}), { status: 200 })
  // Mock fetchMe
  fetchMocker.mockResponseOnce(
    JSON.stringify({ user_id: 'u1', email: 'test@example.com', orgs: [] }),
    { status: 200 },
  )

  // Fill form and submit...
  // Assert: router.push was called with '/create-org'
})
```

**Note:** Read the existing test file first to match its mock setup pattern exactly. The test should verify that after successful register + login, `router.push('/create-org')` is called (new user has no orgs, so `/create-org` is the right destination).

### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/RegisterView.test.ts`
Expected: FAIL — no navigation occurs.

### Step 3: Fix RegisterView.vue

In `views/RegisterView.vue`, add `useRouter` import and navigation after login. Change lines 4-8 in `<script setup>`:

```typescript
import { ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
```

Then change lines 57-59:

```typescript
    // Auto-login after successful registration.
    const result = await auth.login(email.value, password.value)
    if (result.success) {
      router.push('/create-org')
    } else {
      error.value = result.error ?? 'Login failed after registration'
    }
```

And add after `const auth`:
```typescript
const router = useRouter()
```

### Step 4: Run test to verify it passes

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/RegisterView.test.ts`
Expected: PASS.

### Step 5: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

### Step 6: Commit

```bash
git -C .worktrees/frontend add web/src/views/RegisterView.vue web/src/views/__tests__/RegisterView.test.ts
git -C .worktrees/frontend commit -m "fix: navigate to create-org after successful registration"
```

---

## Task 3: Fix invitation acceptance to activate joined org (fixes B7)

After accepting an invitation, the user lands on `/cves` but `activeOrgId` is still set to their previous org (if any). The new org is in their org list after `fetchMe()` but never activated.

**Files:**
- Modify: `views/InvitationView.vue:67-70`
- Modify: `views/__tests__/InvitationView.test.ts`

### Step 1: Write the failing test

Add a test that verifies after accepting an invitation, the newly joined org is set as active. Read the existing test file first to match its setup pattern.

The test should:
1. Set up user already authenticated with Org A active
2. Accept invitation to Org B
3. Mock `fetchMe` returning user with [Org A, Org B]
4. Assert that `auth.setActiveOrg` was called with Org B's ID
5. Assert navigation to `/cves`

**Key detail:** The accept endpoint response includes the org_id. We need to capture it.

### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/InvitationView.test.ts`
Expected: FAIL — activeOrgId remains on Org A.

### Step 3: Fix InvitationView.vue

In `views/InvitationView.vue`, after the accept call succeeds, capture the org_id from the invitation data (already available in `invitation.value`) and set it as active before navigating:

Change lines 67-70:
```typescript
    await auth.fetchMe()
    router.push('/cves')
```

to:

```typescript
    await auth.fetchMe()
    // Activate the org the user just joined.
    if (invitation.value?.org_id) {
      auth.setActiveOrg(invitation.value.org_id)
    }
    router.push('/cves')
```

**Note:** Check whether the invitation response includes `org_id`. Look at the invitation type. If the invitation fetch response doesn't include `org_id`, we need to extract it from the accept response instead. The accept endpoint likely returns the membership entry which includes the org_id.

Read `InvitationView.vue:19` — the invitation type is `{ org_name: string; role: string; expires_at: string }`. It does NOT include `org_id`. So we need to either:
1. Add `org_id` to the invitation type and expect the API to return it (check the API schema), OR
2. Extract it from the accept response

Check the OpenAPI schema for `/auth/invitations/{token}` GET response — if it includes `org_id`, update the type. If not, check the POST accept response.

If neither provides `org_id`, use the org_name to find the matching org after fetchMe:
```typescript
    await auth.fetchMe()
    // Activate the org the user just joined.
    const joinedOrg = auth.user?.orgs?.find(o => o.name === invitation.value?.org_name)
    if (joinedOrg) {
      auth.setActiveOrg(joinedOrg.org_id)
    }
    router.push('/cves')
```

### Step 4: Run test to verify it passes

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/InvitationView.test.ts`
Expected: PASS.

### Step 5: Commit

```bash
git -C .worktrees/frontend add web/src/views/InvitationView.vue web/src/views/__tests__/InvitationView.test.ts
git -C .worktrees/frontend commit -m "fix: activate joined org after invitation acceptance"
```

---

## Task 4: Fix CVE detail re-fetch and URL sanitization (fixes B8, B13)

Two minor/latent bugs in the CVE views. (B10 pagination race was already fixed via fetch ID counter in CveSearchView.vue.)

**Files:**
- Modify: `views/CveDetailView.vue:110-113`
- Modify: `views/CveSearchView.vue:30-58`
- Modify: `views/CveDetailView.vue:279` (template)
- Modify: `components/cve/CveSourceComparison.vue:92`
- Modify/create tests as needed

### Part A: CVE detail re-fetch on route param change (B8)

#### Step 1: Write the failing test

In `views/__tests__/CveDetailView.test.ts`, add a test that navigates from one CVE detail to another via route param change and verifies data is re-fetched.

#### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/CveDetailView.test.ts`
Expected: FAIL — second CVE data never fetched.

#### Step 3: Fix CveDetailView.vue

Add a `watch` on `cveId` to re-fetch. In the `<script setup>` section, add after the `onMounted` block (line 113):

```typescript
import { ref, onMounted, computed, watch } from 'vue'
```

Then replace `onMounted`:
```typescript
onMounted(() => {
  fetchCve()
  fetchSources()
})

watch(cveId, () => {
  fetchCve()
  fetchSources()
})
```

Or more concisely, use `watch` with `{ immediate: true }` and remove `onMounted`:
```typescript
watch(cveId, () => {
  fetchCve()
  fetchSources()
}, { immediate: true })
```

#### Step 4: Run test to verify it passes

Expected: PASS.

### Part B: URL sanitization on CVE reference links (B13)

> **B10 (pagination race) was already fixed** in the frontend worktree using a fetch ID counter pattern — `fetchId` increments on each call, and stale responses are discarded when `currentFetchId !== fetchId`. No changes needed.

#### Step 5: Add a URL sanitizer utility

Create a small helper or add inline validation. The simplest approach is a computed/filter in the template:

In `lib/utils.ts` (or wherever shared utilities live), add:

```typescript
/**
 * Returns the URL if it uses a safe scheme (http/https), or '#' otherwise.
 * Prevents javascript: and data: URL injection in user-controllable href attributes.
 */
export function safeHref(url: string): string {
  try {
    const parsed = new URL(url)
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return url
    }
    return '#'
  } catch {
    return '#'
  }
}
```

Write a quick test for it in `lib/__tests__/utils.test.ts` (create if needed):

```typescript
import { describe, it, expect } from 'vitest'
import { safeHref } from '../utils'

describe('safeHref', () => {
  it('allows https URLs', () => {
    expect(safeHref('https://nvd.nist.gov/vuln/detail/CVE-2024-001')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-001')
  })

  it('allows http URLs', () => {
    expect(safeHref('http://example.com')).toBe('http://example.com')
  })

  it('blocks javascript: URLs', () => {
    expect(safeHref('javascript:alert(1)')).toBe('#')
  })

  it('blocks data: URLs', () => {
    expect(safeHref('data:text/html,<h1>hi</h1>')).toBe('#')
  })

  it('handles malformed URLs', () => {
    expect(safeHref('not a url')).toBe('#')
  })
})
```

#### Step 6: Apply safeHref in CveDetailView and CveSourceComparison

In `views/CveDetailView.vue` line 279, change:
```html
<a :href="ref.url" ...>
```
to:
```html
<a :href="safeHref(ref.url)" ...>
```

Import `safeHref` from `@/lib/utils`.

In `components/cve/CveSourceComparison.vue` line 92, change:
```html
<a :href="source.source_url" ...>
```
to:
```html
<a :href="safeHref(source.source_url)" ...>
```

Import `safeHref` from `@/lib/utils`.

#### Step 7: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

#### Step 8: Commit

```bash
git -C .worktrees/frontend add web/src/views/CveDetailView.vue web/src/views/CveSearchView.vue web/src/components/cve/CveSourceComparison.vue web/src/lib/utils.ts
git -C .worktrees/frontend commit -m "fix: CVE detail re-fetch on param change, pagination race, URL sanitization"
```

---

## Task 5: Fix org switch data re-fetch (fixes B2)

When a user switches orgs via the OrgSwitcher, all org-scoped views still show the previous org's data. Each view needs to watch `activeOrgId` and re-fetch.

**Files:**
- Modify: `views/MembersView.vue`
- Modify: `views/GroupsView.vue`
- Modify: `views/WatchlistListView.vue`
- Modify: `views/WatchlistDetailView.vue`
- Modify: tests for each view

### Step 1: Write failing tests

For each of the 4 views, add a test that:
1. Mounts the view with Org A active
2. Mocks initial data fetch (Org A data)
3. Changes `auth.activeOrgId` to Org B
4. Asserts a new fetch was triggered with Org B's URL

Read each test file first to match its mock setup pattern. The key assertion is that after changing `activeOrgId`, the fetch function is called again with the new org's API base URL.

### Step 2: Run tests to verify they fail

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: The new tests FAIL — no re-fetch triggered.

### Step 3: Add `watch(activeOrgId)` to each view

In each of the 4 views, add a `watch` on the auth store's `activeOrgId` that calls the view's fetch function. The pattern is:

```typescript
import { watch } from 'vue'

// After the existing onMounted block:
watch(
  () => auth.activeOrgId,
  () => {
    fetchMembers() // or fetchGroups(), fetchWatchlists(), etc.
  },
)
```

**For WatchlistDetailView**, the watcher should navigate back to the watchlist list since the current watchlist ID belongs to the previous org:
```typescript
import { useRouter } from 'vue-router'
const router = useRouter()

watch(
  () => auth.activeOrgId,
  () => {
    router.push('/watchlists')
  },
)
```

Apply the pattern to:
- `views/MembersView.vue` — watch → `fetchMembers()`
- `views/GroupsView.vue` — watch → `fetchGroups()`
- `views/WatchlistListView.vue` — watch → `fetchWatchlists()`
- `views/WatchlistDetailView.vue` — watch → `router.push('/watchlists')`

### Step 4: Run tests to verify they pass

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

### Step 5: Commit

```bash
git -C .worktrees/frontend add web/src/views/MembersView.vue web/src/views/GroupsView.vue web/src/views/WatchlistListView.vue web/src/views/WatchlistDetailView.vue
git -C .worktrees/frontend commit -m "fix: re-fetch data on org switch in all org-scoped views"
```

---

## Task 6: Fix WatchlistDetailView blank page on errors (fixes B5)

WatchlistDetailView handles 404 and success but has no error state for other HTTP errors (500, 403, etc.). The page goes blank.

**Files:**
- Modify: `views/WatchlistDetailView.vue`
- Modify: `views/__tests__/WatchlistDetailView.test.ts`

### Step 1: Write the failing test

Add a test for server error (500) response:

```typescript
it('shows error message when API returns 500', async () => {
  // Mock 500 response for fetchWatchlist
  // Assert: error message is displayed, not blank page
})
```

### Step 2: Run test to verify it fails

Expected: FAIL — blank page, no error message.

### Step 3: Fix WatchlistDetailView.vue

Add an `error` ref and set it in the error paths:

```typescript
const error = ref('')
```

In `fetchWatchlist()`, change the error handling:
```typescript
async function fetchWatchlist() {
  error.value = ''

  try {
    const resp = await fetch(apiBase(), {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!resp.ok) {
      if (resp.status === 404) {
        notFound.value = true
      } else {
        error.value = 'Failed to load watchlist. Please try again.'
      }
      loading.value = false
      return
    }

    watchlist.value = await resp.json() as WatchlistEntry
  } catch {
    error.value = 'Failed to load watchlist. Please try again.'
    loading.value = false
  }
}
```

In the template, add error state between notFound and loaded:
```html
<!-- Not found state -->
<div v-else-if="notFound" ...>...</div>

<!-- Error state -->
<div v-else-if="error" class="py-16 text-center">
  <p class="text-sm text-destructive">{{ error }}</p>
</div>

<!-- Loaded state -->
<template v-else-if="watchlist">...</template>
```

### Step 4: Run test to verify it passes

Expected: PASS.

### Step 5: Commit

```bash
git -C .worktrees/frontend add web/src/views/WatchlistDetailView.vue web/src/views/__tests__/WatchlistDetailView.test.ts
git -C .worktrees/frontend commit -m "fix: show error state in WatchlistDetailView for non-404 errors"
```

---

## Task 7: Fix ErrorAlert retry button never rendering (fixes B9)

The retry button checks `$attrs.onRetry`, but `retry` is declared in `defineEmits`, which causes Vue to consume the `onRetry` listener from `$attrs`. The button never appears.

**Files:**
- Modify: `components/ErrorAlert.vue`
- Create or modify: `components/__tests__/ErrorAlert.test.ts`

### Step 1: Write the failing test

```typescript
import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ErrorAlert from '../ErrorAlert.vue'

describe('ErrorAlert', () => {
  it('renders retry button when @retry listener is provided', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed' },
      attrs: { onRetry: () => {} },
    })

    expect(wrapper.find('button').exists()).toBe(true)
    expect(wrapper.find('button').text()).toContain('Retry')
  })

  it('does not render retry button when no @retry listener is provided', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed' },
    })

    const buttons = wrapper.findAll('button')
    expect(buttons.filter(b => b.text().includes('Retry'))).toHaveLength(0)
  })

  it('emits retry event when button is clicked', async () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed' },
      attrs: { onRetry: () => {} },
    })

    await wrapper.find('button').trigger('click')
    expect(wrapper.emitted('retry')).toHaveLength(1)
  })
})
```

### Step 2: Run test to verify it fails

Run: `cd .worktrees/frontend/web && npx vitest run src/components/__tests__/ErrorAlert.test.ts`
Expected: First test FAILS — button not found (because `$attrs.onRetry` is `undefined` when `retry` is in `defineEmits`).

### Step 3: Fix ErrorAlert.vue

Replace the `$attrs.onRetry` check with a `showRetry` prop. This is the cleanest fix:

```vue
<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useAttrs } from 'vue'

defineProps<{
  title?: string
  message: string
}>()

const emit = defineEmits<{
  retry: []
}>()

const attrs = useAttrs()
const hasRetryListener = 'onRetry' in attrs
</script>
```

Wait — `useAttrs()` won't contain `onRetry` either when `retry` is in `defineEmits`. The two cleanest options:

**Option A:** Remove `retry` from `defineEmits` and use `$attrs.onRetry` directly:
```vue
<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

defineProps<{
  title?: string
  message: string
}>()
</script>

<template>
  <Alert variant="destructive">
    <AlertTitle>{{ title ?? 'Error' }}</AlertTitle>
    <AlertDescription class="flex items-center justify-between">
      <span>{{ message }}</span>
      <Button v-if="$attrs.onRetry" variant="outline" size="sm" @click="($attrs.onRetry as Function)?.()">
        Retry
      </Button>
    </AlertDescription>
  </Alert>
</template>
```

**Option B (recommended):** Add a boolean prop `retryable` to control visibility:
```vue
<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

defineProps<{
  title?: string
  message: string
  retryable?: boolean
}>()

const emit = defineEmits<{
  retry: []
}>()
</script>

<template>
  <Alert variant="destructive">
    <AlertTitle>{{ title ?? 'Error' }}</AlertTitle>
    <AlertDescription class="flex items-center justify-between">
      <span>{{ message }}</span>
      <Button v-if="retryable" variant="outline" size="sm" @click="emit('retry')">
        Retry
      </Button>
    </AlertDescription>
  </Alert>
</template>
```

**Use Option B** — it's explicit, type-safe, and follows Vue conventions. Update the test to use `props: { message: '...', retryable: true }` instead of `attrs: { onRetry: ... }`.

### Step 4: Run test to verify it passes

Expected: PASS.

### Step 5: Commit

```bash
git -C .worktrees/frontend add web/src/components/ErrorAlert.vue web/src/components/__tests__/ErrorAlert.test.ts
git -C .worktrees/frontend commit -m "fix: ErrorAlert retry button uses retryable prop instead of broken attrs check"
```

---

## Task 8: Fix silent error swallowing + double-submit + role change visual mismatch (fixes B6, B11, B12)

This is the error handling sweep. 9 action handlers silently swallow errors. Confirmation dialogs lack double-submit protection. The role change Select shows wrong state after failure.

**Files to modify:**
- `views/MembersView.vue` — changeRole, confirmRemove, cancelInvitation
- `views/GroupsView.vue` — confirmDelete
- `views/WatchlistListView.vue` — confirmDelete
- `views/WatchlistDetailView.vue` — saveName, deleteItem
- `components/settings/GroupMembersDialog.vue` — addMember, removeMember
- Tests for each

### Overview of the pattern

Every silent error handler needs the same treatment:
1. **Show error feedback** when `!resp.ok` or on catch
2. **Don't close dialog** on failure (confirmation dialogs currently close in `finally`)
3. **Add submitting guard** to confirmation handlers (prevents double-submit)
4. **Revert visual state** on role change failure

### Part A: MembersView — changeRole visual mismatch + error (B6)

#### Step 1: Write the failing test

```typescript
it('reverts role display and shows error when role change PATCH fails', async () => {
  // Mount with members list including an admin
  // Call changeRole('userId', 'member') — mock PATCH returning 403
  // Assert: error message displayed
  // Assert: member's role in the list is still 'admin' (not 'member')
})
```

#### Step 2: Verify it fails, then fix

The fix for `changeRole()` in MembersView:

```typescript
const roleChangeError = ref('')

async function changeRole(userId: string, newRole: string) {
  roleChangeError.value = ''

  try {
    const resp = await orgFetch(`${apiBase()}/members/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role: newRole }),
    })

    if (resp.ok) {
      const updated: MemberEntry = await resp.json()
      members.value = members.value.map((m) =>
        m.user_id === userId ? { ...m, role: updated.role } : m,
      )
    } else {
      roleChangeError.value = 'Failed to change role. Please try again.'
      // Force re-render to snap Select back to actual role value.
      members.value = [...members.value]
    }
  } catch {
    roleChangeError.value = 'Failed to change role. Please try again.'
    members.value = [...members.value]
  }
}
```

Add `roleChangeError` display in the template (after the table or as an inline toast-style alert).

Also switch from `fetch()` to `orgFetch()` (import from `@/lib/api/orgFetch`).

### Part B: MembersView — confirmRemove error + double-submit (B11, B12)

Fix `confirmRemove()`:

```typescript
const removing = ref(false)
const removeError = ref('')

async function confirmRemove() {
  if (!removeTarget.value || removing.value) return
  removing.value = true
  removeError.value = ''

  const userId = removeTarget.value.user_id

  try {
    const resp = await orgFetch(`${apiBase()}/members/${userId}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      members.value = members.value.filter((m) => m.user_id !== userId)
      removeDialogOpen.value = false
      removeTarget.value = null
    } else {
      removeError.value = 'Failed to remove member. Please try again.'
    }
  } catch {
    removeError.value = 'Failed to remove member. Please try again.'
  } finally {
    removing.value = false
  }
}
```

Key changes:
- Added `removing` guard (B12)
- Don't close dialog on failure — only on success
- Show error in dialog on failure (B11)
- Use `orgFetch` instead of raw `fetch` (B1)

### Part C: MembersView — cancelInvitation error (B11)

```typescript
async function cancelInvitation(invitationId: string) {
  try {
    const resp = await orgFetch(`${apiBase()}/invitations/${invitationId}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      invitations.value = invitations.value.filter((i) => i.id !== invitationId)
    }
    // Invitation cancellation failure is non-critical — silently ignore.
    // The invitation will remain visible in the list.
  } catch {
    // Network error — invitation stays in list.
  }
}
```

**Note:** `cancelInvitation` is one case where silent failure is acceptable — the invitation stays visible and the user can retry. But we should still use `orgFetch` for 401 handling.

### Part D: Apply the same pattern to GroupsView.confirmDelete

```typescript
const deleting = ref(false)
const deleteError = ref('')

async function confirmDelete() {
  if (!deleteTarget.value || deleting.value) return
  deleting.value = true
  deleteError.value = ''

  const id = deleteTarget.value.id

  try {
    const resp = await orgFetch(`${apiBase()}/${id}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      groups.value = groups.value.filter((g) => g.id !== id)
      deleteDialogOpen.value = false
      deleteTarget.value = null
    } else {
      deleteError.value = 'Failed to delete group. Please try again.'
    }
  } catch {
    deleteError.value = 'Failed to delete group. Please try again.'
  } finally {
    deleting.value = false
  }
}
```

Show `deleteError` inside the AlertDialog. Disable the Delete button while `deleting`.

### Part E: Apply to WatchlistListView.confirmDelete

Same pattern as GroupsView.

### Part F: Apply to WatchlistDetailView — saveName and deleteItem errors

```typescript
const saveError = ref('')
const deleteError = ref('')

// saveName: show saveError on failure
// deleteItem: show deleteError on failure (or per-item error)
```

### Part G: Apply to GroupMembersDialog — addMember and removeMember errors

```typescript
const actionError = ref('')

// addMember: set actionError on failure
// removeMember: set actionError on failure
```

### Part H: Migrate all raw fetch() calls to orgFetch

While fixing error handling, also replace every `fetch()` call in these files with `orgFetch()` from `@/lib/api/orgFetch`. This resolves B1 for all org-scoped views. The changes are:

- `MembersView.vue`: fetchMembers, fetchInvitations, changeRole, confirmRemove, cancelInvitation
- `GroupsView.vue`: fetchGroups, confirmDelete
- `WatchlistListView.vue`: fetchWatchlists, confirmDelete
- `WatchlistDetailView.vue`: fetchWatchlist, fetchItems, saveName, deleteItem
- `GroupMembersDialog.vue`: fetchData, addMember, removeMember
- `InviteMemberDialog.vue`: submit handler
- `CreateWatchlistDialog.vue`: submit handler
- `AddItemDialog.vue`: submit handler
- `GroupDialog.vue`: submit handler
- `CreateOrgView.vue`: submit handler

For each file:
1. Add `import { orgFetch } from '@/lib/api/orgFetch'`
2. Replace `fetch(url, { method, credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-Requested-By': 'CVErt-Ops' }, body })` with `orgFetch(url, { method, body })`
3. Remove manual `credentials: 'include'` and `X-Requested-By` headers — `orgFetch` handles these

### Step 3: Run full test suite

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests PASS.

Some existing tests may need updates because they mock `fetch` directly — after switching to `orgFetch`, the mock patterns may need adjustment. If tests fail, update the mocks to account for `orgFetch`'s behavior (it still calls `fetch` internally, so `vi.fn()` mocks on `globalThis.fetch` should still work).

### Step 4: Run lint and typecheck

Run: `cd .worktrees/frontend/web && npx vue-tsc --noEmit && npx eslint .`
Expected: Clean.

### Step 5: Commit

This task is large — commit in sub-parts:

```bash
# Commit 1: MembersView error handling + orgFetch migration
git -C .worktrees/frontend add web/src/views/MembersView.vue web/src/views/__tests__/MembersView.test.ts
git -C .worktrees/frontend commit -m "fix: MembersView error handling, role change revert, double-submit guard"

# Commit 2: GroupsView + WatchlistListView + WatchlistDetailView
git -C .worktrees/frontend add web/src/views/GroupsView.vue web/src/views/WatchlistListView.vue web/src/views/WatchlistDetailView.vue
git -C .worktrees/frontend commit -m "fix: error feedback and double-submit guards for delete confirmations"

# Commit 3: Dialog components orgFetch migration
git -C .worktrees/frontend add web/src/components/settings/ web/src/components/watchlist/ web/src/views/CreateOrgView.vue
git -C .worktrees/frontend commit -m "refactor: migrate all raw fetch() to orgFetch for consistent 401 handling"

# Commit 4: GroupMembersDialog error handling
git -C .worktrees/frontend add web/src/components/settings/GroupMembersDialog.vue
git -C .worktrees/frontend commit -m "fix: GroupMembersDialog error feedback on add/remove failures"
```

---

## Admin role dropdown UX concern

The Holistic analysis found that admins see a role dropdown for peer admins containing only demotion options (member, viewer) — the current role "admin" isn't in the options. This creates a UX trap where any interaction demotes the peer.

**This is NOT a bug fix — it's a UX improvement.** The behavior is technically correct (admins can't assign roles equal to or above their own). But the UI should show a badge (not a dropdown) for members whose role the current user can't meaningfully change without demotion risk.

**Recommendation:** Change `canChangeRole` to return `false` when the member's current role is `admin` and the caller is also `admin`. This would show a badge instead of a dropdown, avoiding accidental demotion. But this is a design decision — discuss with Sam before implementing.

---

## Verification Checklist

After all tasks are complete:

1. `npx vitest run` — all tests pass
2. `npx vue-tsc --noEmit` — no type errors
3. `npx eslint .` — no lint errors
4. `npx vite build` — build succeeds
5. Manual smoke test (if dev server available):
   - Register → lands on create-org page (not stuck on register)
   - Accept invitation → lands in the correct org
   - Switch orgs → data refreshes
   - Let session expire → org-scoped pages auto-refresh token
   - Delete watchlist → error shown if server rejects
   - Change member role → reverts on failure
   - CVE reference links with `javascript:` → rendered as `#`
