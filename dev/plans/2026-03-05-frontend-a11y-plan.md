# Frontend Accessibility (A11y) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bring the Vue frontend into compliance with the accessibility spec (`dev/plans/accessibility-spec.md`) by fixing all P0/P1/P2 gaps identified in the audit.

**Architecture:** Pure template and router changes — no new components, no API changes, no state management changes. All fixes are additive ARIA attributes, semantic improvements, and test assertions. Work happens in the existing `feature/frontend` worktree at `.worktrees/frontend`.

**Tech Stack:** Vue 3, shadcn-vue (reka-ui), Tailwind CSS v4, lucide-vue-next, Vitest + @vue/test-utils

**Reference:** `dev/plans/accessibility-spec.md` — the full spec these changes implement.

**Worktree:** `.worktrees/frontend` (branch: `feature/frontend`)

**Run tests:** `cd .worktrees/frontend/web && npx vitest run`

---

### Task 1: HTML lang attribute + route title quality (P0)

Two trivial P0 fixes: set `lang="en"` on `<html>` and use explicit route titles instead of auto-generated ones.

**Files:**
- Modify: `web/index.html:2`
- Modify: `web/src/router/index.ts:14-97` (add `meta.title` to routes)
- Modify: `web/src/router/index.ts:144-151` (titleGuard reads `meta.title`)
- Test: `web/src/router/__tests__/guards.test.ts`

**Step 1: Write failing tests for explicit route titles**

In `web/src/router/__tests__/guards.test.ts`, add to the `title guard` describe block:

```ts
it('uses explicit meta.title for CVE routes', async () => {
  const auth = useAuthStore()
  auth.user = {
    user_id: 'u1',
    email: 'test@example.com',
    display_name: 'Test',
    orgs: [{ org_id: 'org-1', name: 'My Org', role: 'admin' }],
  }
  auth.setActiveOrg('org-1')
  vi.spyOn(auth, 'fetchMe').mockResolvedValue(true)

  const router = createTestRouter()
  await router.push('/cves')
  await router.isReady()

  expect(document.title).toBe('CVE Search | CVErt Ops')
})
```

Also update the existing test at line 267 — it currently expects `'Cve Search | CVErt Ops'`. Update it to expect `'CVE Search | CVErt Ops'`.

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/router/__tests__/guards.test.ts`
Expected: FAIL — title is `'Cve Search | CVErt Ops'` not `'CVE Search | CVErt Ops'`

**Step 3: Add explicit `meta.title` to all routes and update titleGuard**

In `web/src/router/index.ts`, add `title` to each route's `meta`:

```ts
{ path: '/login', name: 'login', meta: { layout: 'public', requiresAuth: false, title: 'Log In' } },
{ path: '/register', name: 'register', meta: { layout: 'public', requiresAuth: false, title: 'Register' } },
{ path: '/invitations/:token', name: 'invitation', meta: { layout: 'public', requiresAuth: false, title: 'Invitation' } },
{ path: '/create-org', name: 'create-org', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: false, title: 'Create Organization' } },
{ path: '/cves', name: 'cve-search', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'CVE Search' } },
{ path: '/cves/:cveId', name: 'cve-detail', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'CVE Detail' } },
{ path: '/watchlists', name: 'watchlists', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Watchlists' } },
{ path: '/watchlists/:id', name: 'watchlist-detail', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Watchlist' } },
{ path: '/settings/members', name: 'members', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Members' } },
{ path: '/settings/groups', name: 'groups', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Groups' } },
{ path: '/admin/feeds', name: 'feed-status', meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Feed Status' } },
```

Update `titleGuard` to use `meta.title` first, falling back to auto-generated:

```ts
export const titleGuard: NavigationHookAfter = (to) => {
  const title = typeof to.meta.title === 'string'
    ? to.meta.title
    : typeof to.name === 'string'
      ? to.name.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
      : ''
  document.title = title ? `${title} | CVErt Ops` : 'CVErt Ops'
}
```

**Step 4: Fix `<html lang="">`**

In `web/index.html`, change line 2:

```html
<html lang="en">
```

**Step 5: Update existing title test expectations**

In `guards.test.ts`, update test expectations to match the new explicit titles:
- `'Cve Search | CVErt Ops'` → `'CVE Search | CVErt Ops'`
- `'Feed Status | CVErt Ops'` stays the same (already correct)
- `'Login | CVErt Ops'` → `'Log In | CVErt Ops'`

**Step 6: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run src/router/__tests__/guards.test.ts`
Expected: PASS

**Step 7: Run full test suite**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 8: Commit**

```bash
git -C .worktrees/frontend add web/index.html web/src/router/index.ts web/src/router/__tests__/guards.test.ts
git -C .worktrees/frontend commit -m "a11y: set html lang=en and add explicit route titles"
```

---

### Task 2: aria-label on all icon-only buttons (P0)

Add `aria-label` to every icon-only button. There are 11 instances across 5 files.

**Files:**
- Modify: `web/src/views/WatchlistDetailView.vue:255-291,368-375`
- Modify: `web/src/views/WatchlistListView.vue:229-236`
- Modify: `web/src/views/GroupsView.vue:238-261`
- Modify: `web/src/views/MembersView.vue:338-346,376-381`
- Modify: `web/src/components/settings/GroupMembersDialog.vue:238-245`
- Test: `web/src/views/__tests__/WatchlistDetailView.test.ts`
- Test: `web/src/views/__tests__/WatchlistListView.test.ts`
- Test: `web/src/views/__tests__/GroupsView.test.ts`
- Test: `web/src/views/__tests__/MembersView.test.ts`
- Test: `web/src/components/settings/__tests__/GroupMembersDialog.test.ts`

**Step 1: Write failing tests**

In each test file, add an a11y assertion. For example, in `WatchlistListView.test.ts`, inside a describe block after the table renders with data:

```ts
it('has accessible labels on icon-only action buttons', async () => {
  mockListSuccess()
  await mountView()
  await flushPromises()

  const deleteBtn = findTestId('delete-watchlist-btn')
  expect(deleteBtn).not.toBeNull()
  expect(deleteBtn!.getAttribute('aria-label')).toBe('Delete watchlist')
})
```

Add similar tests in each of the other 4 test files:

**WatchlistDetailView.test.ts** — add inside the existing describe block, after the edit mode tests:
```ts
it('has accessible labels on icon-only action buttons', async () => {
  mockWatchlistSuccess()
  mockItemsSuccess([makePackageItem()])
  await mountView()
  await flushPromises()

  const editBtn = findTestId('edit-name-btn')
  expect(editBtn!.getAttribute('aria-label')).toBe('Edit watchlist name')

  const deleteItemBtn = findTestId('delete-item-btn')
  expect(deleteItemBtn!.getAttribute('aria-label')).toBe('Remove item')
})

it('has accessible labels on inline edit buttons', async () => {
  mockWatchlistSuccess()
  mockItemsSuccess([])
  await mountView()
  await flushPromises()

  // Enter edit mode first
  await clickTestId('edit-name-btn')
  await flushPromises()

  const saveBtn = findTestId('save-name-btn')
  expect(saveBtn!.getAttribute('aria-label')).toBe('Save name')

  const cancelBtn = findTestId('cancel-name-btn')
  expect(cancelBtn!.getAttribute('aria-label')).toBe('Cancel editing')
})
```

**GroupsView.test.ts** — add inside the admin-user describe block. Follow the existing test setup pattern (read the test file to find the `mockGroupsSuccess`, `mountView`, and similar helpers):
```ts
it('has accessible labels on icon-only action buttons', async () => {
  // Use the same setup as existing admin tests (mock groups list + mount + flush)
  mockGroupsSuccess()
  await mountView()
  await flushPromises()

  const editBtn = findTestId('edit-group-btn')
  expect(editBtn!.getAttribute('aria-label')).toBe('Edit group')

  const membersBtn = findTestId('manage-members-btn')
  expect(membersBtn!.getAttribute('aria-label')).toBe('Manage members')

  const deleteBtn = findTestId('delete-group-btn')
  expect(deleteBtn!.getAttribute('aria-label')).toBe('Delete group')
})
```

**MembersView.test.ts** — add inside the admin-user describe block. Follow the existing mount pattern:
```ts
it('has accessible labels on icon-only action buttons', async () => {
  // Use the same setup as existing admin tests (mock members + invitations + mount + flush)
  mockMembersSuccess()
  mockInvitationsSuccess()
  await mountView()
  await flushPromises()

  const removeBtn = findTestId('remove-member-btn')
  expect(removeBtn!.getAttribute('aria-label')).toBe('Remove member')

  const cancelBtn = findTestId('cancel-invitation-btn')
  expect(cancelBtn!.getAttribute('aria-label')).toBe('Cancel invitation')
})
```

**Note for subagent:** The helper names above (`mockGroupsSuccess`, `mockMembersSuccess`, `mockInvitationsSuccess`, `mountView`, `findTestId`) are approximations — read each test file to find the actual helpers and adapt accordingly. The pattern is always: mock data → mount → flush → query by testid.

**GroupMembersDialog.test.ts** — after rendering with group members:
```ts
it('has accessible label on remove member button', async () => {
  const removeBtn = findTestId('remove-group-member-btn')
  expect(removeBtn!.getAttribute('aria-label')).toBe('Remove member')
})
```

**Step 2: Run tests to verify they fail**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: FAIL — all `aria-label` assertions fail (attribute is null)

**Step 3: Add aria-label to all 11 buttons**

In each file, add `aria-label="..."` to the `<Button>` elements:

**WatchlistDetailView.vue:**
```vue
<!-- Line ~258: edit name -->
<Button variant="ghost" size="sm" data-testid="edit-name-btn" aria-label="Edit watchlist name" @click="startEditName">
<!-- Line ~277: save name -->
<Button variant="ghost" size="sm" data-testid="save-name-btn" aria-label="Save name" :disabled="saving" @click="saveName">
<!-- Line ~285: cancel edit -->
<Button variant="ghost" size="sm" data-testid="cancel-name-btn" aria-label="Cancel editing" :disabled="saving" @click="cancelEditName">
<!-- Line ~370: delete item -->
<Button variant="ghost" size="sm" data-testid="delete-item-btn" aria-label="Remove item" @click="deleteItem(item.id)">
```

**WatchlistListView.vue:**
```vue
<!-- Line ~231: delete watchlist -->
<Button variant="ghost" size="sm" data-testid="delete-watchlist-btn" aria-label="Delete watchlist" @click="promptDelete(wl)">
```

**GroupsView.vue:**
```vue
<!-- Line ~240: edit group -->
<Button variant="ghost" size="sm" data-testid="edit-group-btn" aria-label="Edit group" @click="openEditDialog(g)">
<!-- Line ~248: manage members -->
<Button variant="ghost" size="sm" data-testid="manage-members-btn" aria-label="Manage members" @click="openMembersDialog(g)">
<!-- Line ~256: delete group -->
<Button variant="ghost" size="sm" data-testid="delete-group-btn" aria-label="Delete group" @click="promptDelete(g)">
```

**MembersView.vue:**
```vue
<!-- Line ~340: remove member -->
<Button v-if="canRemove(m)" variant="ghost" size="sm" data-testid="remove-member-btn" aria-label="Remove member" @click="promptRemove(m)">
<!-- Line ~378: cancel invitation -->
<Button variant="ghost" size="sm" data-testid="cancel-invitation-btn" aria-label="Cancel invitation" @click="cancelInvitation(inv.id)">
```

**GroupMembersDialog.vue:**
```vue
<!-- Line ~240: remove group member -->
<Button variant="ghost" size="sm" data-testid="remove-group-member-btn" aria-label="Remove member" @click="removeMember(m.user_id)">
```

**Step 4: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 5: Commit**

```bash
git -C .worktrees/frontend add web/src/views/ web/src/components/settings/GroupMembersDialog.vue
git -C .worktrees/frontend commit -m "a11y: add aria-label to all icon-only buttons"
```

---

### Task 3: Skip-to-main-content link + sr-only action column headers (P1)

**Files:**
- Modify: `web/src/layouts/AuthenticatedLayout.vue:18-53`
- Modify: `web/src/views/WatchlistListView.vue:208`
- Modify: `web/src/views/WatchlistDetailView.vue:346`
- Modify: `web/src/views/GroupsView.vue:226`
- Modify: `web/src/views/MembersView.vue:298,361`
- Test: `web/src/views/__tests__/WatchlistListView.test.ts`

**Step 1: Write failing test for skip link**

Add a test that mounts the AuthenticatedLayout and checks for the skip link. Since layout tests are tricky (the layout wraps RouterView), we can test the rendered HTML attribute directly. Alternatively, add a simple assertion in any view test that uses the full layout. However, since our existing tests mount views directly (not via router), the simplest approach is a new focused test.

Create a test assertion in an existing view test file — e.g., `WatchlistListView.test.ts`:

```ts
it('renders sr-only text in action column header', async () => {
  mockListSuccess()
  await mountView()
  await flushPromises()

  const tableHeaders = wrapper.findAll('th')
  const lastHeader = tableHeaders[tableHeaders.length - 1]
  expect(lastHeader?.text()).toBe('Actions')
  // It should be sr-only (visually hidden but screen-reader accessible)
  expect(lastHeader?.find('.sr-only').exists()).toBe(true)
})
```

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/WatchlistListView.test.ts`
Expected: FAIL — the last `<th>` has empty text content

**Step 3: Add sr-only text to all 5 empty action column headers**

In each file, replace the empty `<TableHead>` with:

```vue
<TableHead class="w-16">
  <span class="sr-only">Actions</span>
</TableHead>
```

Files and approximate lines:
- `WatchlistListView.vue:208` — `<TableHead class="w-16" />`
- `WatchlistDetailView.vue:346` — `<TableHead class="w-16" />`
- `GroupsView.vue:226` — `<TableHead v-if="isAdmin" class="w-32" />`
- `MembersView.vue:298` — `<TableHead v-if="isAdmin" class="w-16" />`
- `MembersView.vue:361` — `<TableHead class="w-16" />`

Each becomes a non-self-closing tag with `<span class="sr-only">Actions</span>` inside. Preserve existing classes and `v-if` directives.

**Step 4: Add skip-to-main-content link in AuthenticatedLayout.vue**

At the very top of the template (first child of the root `<div>`), add:

```vue
<a
  href="#main-content"
  class="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-background focus:px-4 focus:py-2 focus:text-foreground focus:shadow-lg"
>
  Skip to main content
</a>
```

Then update the `<main>` tag (line ~48) to add the target id:

```vue
<main id="main-content" class="flex-1 overflow-y-auto">
```

**Step 5: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 6: Commit**

```bash
git -C .worktrees/frontend add web/src/layouts/AuthenticatedLayout.vue web/src/views/
git -C .worktrees/frontend commit -m "a11y: add skip-to-main link and sr-only action column headers"
```

---

### Task 4: role="alert" on error messages (P1)

Add `role="alert"` to all error `<p>` elements so screen readers announce errors immediately.

**Files:**
- Modify: `web/src/views/LoginView.vue:81`
- Modify: `web/src/views/RegisterView.vue:132`
- Modify: `web/src/views/CveSearchView.vue:110`
- Modify: `web/src/views/WatchlistListView.vue:178,259`
- Modify: `web/src/views/WatchlistDetailView.vue:233,303`
- Modify: `web/src/views/GroupsView.vue:196,294`
- Modify: `web/src/views/MembersView.vue:283,289,408`
- Modify: `web/src/components/watchlist/CreateWatchlistDialog.vue:137`
- Modify: `web/src/components/watchlist/AddItemDialog.vue:262`
- Modify: `web/src/components/settings/InviteMemberDialog.vue:171`
- Modify: `web/src/components/settings/GroupDialog.vue:157`
- Modify: `web/src/components/settings/GroupMembersDialog.vue:203`
- Test: `web/src/views/__tests__/LoginView.test.ts`

**Step 1: Write failing test**

In `LoginView.test.ts`, find or add a test for the error state:

```ts
it('displays error message with role="alert" for screen readers', async () => {
  const auth = useAuthStore()
  vi.spyOn(auth, 'login').mockResolvedValue({
    success: false,
    error: 'Invalid email or password',
  })

  await wrapper.find('input[type="email"]').setValue('test@example.com')
  await wrapper.find('input[type="password"]').setValue('password')
  await wrapper.find('form').trigger('submit')
  await flushPromises()

  const errorEl = wrapper.find('.text-destructive')
  expect(errorEl.exists()).toBe(true)
  expect(errorEl.attributes('role')).toBe('alert')
})
```

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/LoginView.test.ts`
Expected: FAIL — `role` attribute is undefined

**Step 3: Add `role="alert"` to all error paragraphs**

This is a mechanical change across all files. Every `<p>` or `<div>` that displays an error message conditionally (with `v-if="error"` or similar) gets `role="alert"` added.

**Before starting,** verify the complete list by running:
```bash
cd .worktrees/frontend/web && grep -rn 'v-if="error\|v-if=".*[Ee]rror\|text-destructive' src/ --include="*.vue" | grep -v node_modules
```

The pattern to find and update:
```vue
<!-- BEFORE -->
<p v-if="error" class="text-sm text-destructive">{{ error }}</p>

<!-- AFTER -->
<p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>
```

Apply to every instance in every file listed above. Count: approximately 15 error elements.

**Important:** Only add `role="alert"` to error messages that appear dynamically (conditionally rendered with `v-if`). Static text does not need it.

**Step 4: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 5: Commit**

```bash
git -C .worktrees/frontend add web/src/views/ web/src/components/
git -C .worktrees/frontend commit -m "a11y: add role=alert to all error messages"
```

---

### Task 5: aria-live on loading regions (P1)

Wrap loading/content transitions in `aria-live="polite"` regions so screen readers announce state changes. Also add `aria-hidden="true"` to loading spinner icons (Loader2).

**Files:**
- Modify: `web/src/views/CveSearchView.vue:110-112`
- Modify: `web/src/views/WatchlistListView.vue:170-240`
- Modify: `web/src/views/WatchlistDetailView.vue:216-380`
- Modify: `web/src/views/GroupsView.vue:188-266`
- Modify: `web/src/views/MembersView.vue:276-388`
- Modify: `web/src/views/CveDetailView.vue:134-312`
- Modify: `web/src/components/cve/CveResultsTable.vue:78-85`
- Modify: `web/src/components/settings/GroupMembersDialog.vue:196-198`
- Test: `web/src/components/cve/__tests__/CveResultsTable.test.ts`

**Step 1: Write failing test**

In `CveResultsTable.test.ts`, add:

```ts
it('has aria-live region for loading state announcements', async () => {
  // Use the existing mountTable helper (dynamically imports + mounts)
  await mountTable({ items: [], loading: true })

  const liveRegion = wrapper.find('[aria-live]')
  expect(liveRegion.exists()).toBe(true)
  expect(liveRegion.attributes('aria-live')).toBe('polite')
})
```

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/components/cve/__tests__/CveResultsTable.test.ts`
Expected: FAIL — no element with `aria-live` attribute

**Step 3: Add aria-live regions**

The approach: wrap the conditional loading/error/content blocks in a `<div aria-live="polite">`. Don't nest multiple `aria-live` regions.

**CveResultsTable.vue** — wrap the root `<div>`:
```vue
<template>
  <div aria-live="polite">
    <Table>
      <!-- existing content -->
    </Table>
  </div>
</template>
```

**For page-level views** (CveSearchView, WatchlistListView, WatchlistDetailView, GroupsView, MembersView, CveDetailView): wrap the loading/error/content section (NOT the entire page — keep the header and actions outside the live region) in `<div aria-live="polite">`.

For example, in **WatchlistListView.vue** around lines 170-240:
```vue
<!-- After the header div -->
<div aria-live="polite">
  <!-- Loading state -->
  <div v-if="loading" ...>...</div>
  <!-- Error state -->
  <div v-else-if="error" ...>...</div>
  <!-- Empty state -->
  <Card v-else-if="watchlists.length === 0" ...>...</Card>
  <!-- Table -->
  <Table v-else>...</Table>
</div>
```

Apply the same pattern to all 6 page views and the GroupMembersDialog.

Also add `aria-hidden="true"` to all `<Loader2>` spinner icons so they're not announced:
```vue
<Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
```

There are ~8 instances of `<Loader2>` across all files (views + CveResultsTable + GroupMembersDialog).

**Step 4: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 5: Commit**

```bash
git -C .worktrees/frontend add web/src/views/ web/src/components/
git -C .worktrees/frontend commit -m "a11y: add aria-live regions for loading state announcements"
```

---

### Task 6: Form error association — aria-invalid + aria-describedby (P1)

Associate error messages with their form fields using `aria-invalid` and `aria-describedby`. This is the most complex a11y task.

**Files:**
- Modify: `web/src/views/LoginView.vue`
- Modify: `web/src/views/RegisterView.vue`
- Modify: `web/src/components/watchlist/CreateWatchlistDialog.vue`
- Modify: `web/src/components/watchlist/AddItemDialog.vue`
- Modify: `web/src/components/settings/InviteMemberDialog.vue`
- Modify: `web/src/components/settings/GroupDialog.vue`
- Test: `web/src/views/__tests__/LoginView.test.ts`
- Test: `web/src/views/__tests__/RegisterView.test.ts`

**Step 1: Write failing test**

In `LoginView.test.ts`, in the error handling describe block (after the existing "shows error message on failed login" test):

```ts
it('associates error message with form via aria-describedby', async () => {
  const auth = useAuthStore()
  vi.spyOn(auth, 'login').mockResolvedValue({
    success: false,
    error: 'Invalid email or password',
  })

  await wrapper.find('input[type="email"]').setValue('test@example.com')
  await wrapper.find('input[type="password"]').setValue('password')
  await wrapper.find('form').trigger('submit')
  await flushPromises()

  // Error element should have id and role="alert" (added in Task 4)
  const errorEl = wrapper.find('[role="alert"]')
  expect(errorEl.exists()).toBe(true)
  expect(errorEl.attributes('id')).toBe('login-error')

  // Form fields should reference the error
  const emailInput = wrapper.find('#email')
  expect(emailInput.attributes('aria-invalid')).toBe('true')
  expect(emailInput.attributes('aria-describedby')).toBe('login-error')
})
```

**Note:** This test depends on Task 4 having already added `role="alert"`. Since tasks execute sequentially, this dependency is satisfied.

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/LoginView.test.ts`
Expected: FAIL — no `aria-invalid` attribute on inputs

**Step 3: Add aria-invalid + aria-describedby to form fields**

The pattern for each form:

```vue
<Input
  id="email"
  v-model="email"
  type="email"
  :aria-invalid="!!error || undefined"
  :aria-describedby="error ? 'login-error' : undefined"
/>
<!-- ... -->
<p v-if="error" id="login-error" class="text-sm text-destructive" role="alert">
  {{ error }}
</p>
```

**LoginView.vue:**
- Add `:aria-invalid="!!error || undefined"` and `:aria-describedby="error ? 'login-error' : undefined"` to both email and password `<Input>` elements
- Add `id="login-error"` to the error `<p>` element

**RegisterView.vue:**
- Add `:aria-invalid="!!error || undefined"` and `:aria-describedby="error ? 'register-error' : undefined"` to email, password, and confirm-password inputs
- Add `id="register-error"` to the error `<p>`

**CreateWatchlistDialog.vue:**
- Add `:aria-invalid="!!error || undefined"` to the name input
- Add `:aria-describedby="error ? 'create-watchlist-error' : undefined"` to the name input
- Add `id="create-watchlist-error"` to the error `<p>`

**AddItemDialog.vue:**
- Add `:aria-invalid="!!error || undefined"` to the active field inputs (package-name or cpe input)
- Add `id="add-item-error"` to the error `<p>`
- Add `:aria-describedby="error ? 'add-item-error' : undefined"` to the inputs

**InviteMemberDialog.vue:**
- Add `:aria-invalid="!!error || undefined"` and `:aria-describedby="error ? 'invite-error' : undefined"` to the email input
- Add `id="invite-error"` to the error `<p>`

**GroupDialog.vue:**
- Add `:aria-invalid="!!error || undefined"` and `:aria-describedby="error ? 'group-error' : undefined"` to the name input
- Add `id="group-error"` to the error `<p>`

**Important:** Use `!!error || undefined` (not `!!error`) so the attribute is omitted when false, rather than rendering `aria-invalid="false"`. Vue omits attributes with value `undefined`.

**Step 4: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 5: Commit**

```bash
git -C .worktrees/frontend add web/src/views/ web/src/components/
git -C .worktrees/frontend commit -m "a11y: associate form errors with fields via aria-invalid and aria-describedby"
```

---

### Task 7: Inline edit labels + aria-hidden on decorative icons (P2)

Two cleanup items: (1) add accessible labels to the inline edit inputs in WatchlistDetailView, (2) add `aria-hidden="true"` to all icons that appear next to visible text.

**Files:**
- Modify: `web/src/views/WatchlistDetailView.vue:268-299`
- Modify: All files with icon + text buttons/links (see list below)
- Test: `web/src/views/__tests__/WatchlistDetailView.test.ts`

**Step 1: Write failing test for inline edit labels**

In `WatchlistDetailView.test.ts`, in the edit mode test section:

```ts
it('provides accessible labels for inline edit inputs', async () => {
  mockWatchlistSuccess()
  mockItemsSuccess([])
  await mountView()
  await flushPromises()

  // Enter edit mode
  await clickTestId('edit-name-btn')
  await flushPromises()

  const nameInput = findTestId('edit-name-input')
  expect(nameInput).not.toBeNull()
  expect(nameInput!.getAttribute('aria-label')).toBe('Watchlist name')

  const descInput = findTestId('edit-description-input')
  expect(descInput).not.toBeNull()
  expect(descInput!.getAttribute('aria-label')).toBe('Watchlist description')
})
```

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/views/__tests__/WatchlistDetailView.test.ts`
Expected: FAIL — `aria-label` is null

**Step 3: Add labels to inline edit inputs**

In `WatchlistDetailView.vue`, add `aria-label` to both edit inputs:

```vue
<Input
  v-model="editName"
  data-testid="edit-name-input"
  aria-label="Watchlist name"
  class="max-w-sm text-lg font-semibold"
  :disabled="saving"
/>
<!-- ... -->
<Input
  v-model="editDescription"
  data-testid="edit-description-input"
  aria-label="Watchlist description"
  placeholder="Description (optional)"
  class="max-w-sm"
  :disabled="saving"
/>
```

**Step 4: Add `aria-hidden="true"` to all decorative icons next to text**

Add `aria-hidden="true"` to every icon that appears alongside visible text. These icons are purely decorative — the adjacent text already conveys the meaning.

Files and locations (each icon component gets `aria-hidden="true"`):

**AuthenticatedLayout.vue:**
- `<Menu>` icon in mobile header button — already has sr-only sibling, but add `aria-hidden="true"` to the icon itself

**AppSidebar.vue:**
- `<component :is="item.icon">` in all 3 nav sections — these are next to text labels

**CveSearchView.vue:**
- `<ChevronLeft>` in Previous button
- `<ChevronRight>` in Next button

**WatchlistListView.vue:**
- `<Plus>` in "New Watchlist" buttons (2 instances)
- `<FileText>` in empty state — decorative, has adjacent text

**WatchlistDetailView.vue:**
- `<ArrowLeft>` in "Back to Watchlists" link
- `<Plus>` in "Add Item" button
- `<Package>` and `<Cpu>` icons inside Badge (have adjacent text label)

**GroupsView.vue:**
- `<Plus>` in "New Group" buttons (2 instances)
- `<Users>` in empty state — decorative

**MembersView.vue:**
- `<Plus>` in "Invite Member" button

**CveDetailView.vue:**
- `<ArrowLeft>` in "Back to search" link
- `<ExternalLink>` in reference links — decorative, URL text is adjacent

**LoginView.vue:**
- `<Github>` in "GitHub" button

**RegisterView.vue:**
- `<Github>` in "GitHub" button

**AddItemDialog.vue:**
- `<Package>` in "Package" button
- `<Cpu>` in "CPE" button

**UserMenu.vue:**
- `<LogOut>` in "Log out" menu item

**InviteMemberDialog.vue:**
- `<UserPlus>` in success message

**CveResultsTable.vue:**
- `<Loader2>` in loading state — already handled in Task 5

The pattern is always the same:
```vue
<!-- BEFORE -->
<Plus class="mr-2 size-4" />

<!-- AFTER -->
<Plus class="mr-2 size-4" aria-hidden="true" />
```

**Step 5: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass

**Step 6: Commit**

```bash
git -C .worktrees/frontend add web/src/
git -C .worktrees/frontend commit -m "a11y: add aria-hidden to decorative icons and labels to inline edit inputs"
```

---

### Task 8: Route-change focus management (P2)

Focus the `<h1>` on each route change so screen readers announce the new page.

**Files:**
- Modify: `web/src/router/index.ts:144-151`
- Test: `web/src/router/__tests__/guards.test.ts`

**Step 1: Write failing test**

In `guards.test.ts`, add a test in the `title guard` describe block:

```ts
import { nextTick } from 'vue'

it('focuses the h1 element after route change', async () => {
  const auth = useAuthStore()
  auth.user = {
    user_id: 'u1',
    email: 'test@example.com',
    display_name: 'Test',
    orgs: [{ org_id: 'org-1', name: 'My Org', role: 'admin' }],
  }
  auth.setActiveOrg('org-1')
  vi.spyOn(auth, 'fetchMe').mockResolvedValue(true)

  // Create an h1 in the DOM to simulate a page heading
  const h1 = document.createElement('h1')
  h1.textContent = 'Test Page'
  document.body.appendChild(h1)

  try {
    const router = createTestRouter()
    await router.push('/cves')
    await router.isReady()

    // Focus happens in a nextTick callback inside titleGuard
    await nextTick()

    expect(document.activeElement).toBe(h1)
    expect(h1.getAttribute('tabindex')).toBe('-1')
  } finally {
    document.body.removeChild(h1)
  }
})
```

**Note:** The `nextTick` import may already exist in the test file — add it to the existing import if so, don't duplicate. The `try/finally` ensures cleanup even on test failure.

**Step 2: Run test to verify it fails**

Run: `cd .worktrees/frontend/web && npx vitest run src/router/__tests__/guards.test.ts`
Expected: FAIL — `document.activeElement` is not the h1

**Step 3: Add focus management to titleGuard**

In `web/src/router/index.ts`, import `nextTick` from Vue and add focus logic to the afterEach hook:

```ts
import { nextTick } from 'vue'

export const titleGuard: NavigationHookAfter = (to) => {
  const title = typeof to.meta.title === 'string'
    ? to.meta.title
    : typeof to.name === 'string'
      ? to.name.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
      : ''
  document.title = title ? `${title} | CVErt Ops` : 'CVErt Ops'

  // Focus the page heading for screen reader announcement
  nextTick(() => {
    const heading = document.querySelector('h1')
    if (heading instanceof HTMLElement) {
      heading.setAttribute('tabindex', '-1')
      heading.focus()
    }
  })
}
```

**Step 4: Run tests to verify they pass**

Run: `cd .worktrees/frontend/web && npx vitest run src/router/__tests__/guards.test.ts`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd .worktrees/frontend/web && npx vitest run`
Expected: All tests pass. Note: other tests should not be affected since they mount components directly (not via router), so the afterEach hook doesn't fire. If any tests break due to focus side-effects, investigate and fix.

**Step 6: Commit**

```bash
git -C .worktrees/frontend add web/src/router/
git -C .worktrees/frontend commit -m "a11y: focus h1 on route change for screen reader announcement"
```

---

## Summary

| Task | Priority | What | Files touched |
|------|----------|------|---------------|
| 1 | P0 | `lang="en"` + explicit route titles | 3 |
| 2 | P0 | `aria-label` on 11 icon-only buttons | 10 |
| 3 | P1 | Skip link + sr-only action headers | 6 |
| 4 | P1 | `role="alert"` on error messages | 13 |
| 5 | P1 | `aria-live` loading regions + spinner `aria-hidden` | 8 |
| 6 | P1 | `aria-invalid` + `aria-describedby` on forms | 8 |
| 7 | P2 | Inline edit labels + `aria-hidden` decorative icons | 15 |
| 8 | P2 | Route-change focus management | 2 |
