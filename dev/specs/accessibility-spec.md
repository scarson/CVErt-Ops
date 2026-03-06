# CVErt Ops — Accessibility Specification (A11y)

## 1. Introduction & Philosophy

This document outlines the accessibility standards for the CVErt Ops web application. Accessibility is a core requirement — a security product that isn't usable by people with disabilities is failing at its job.

CVErt Ops is a data-heavy application: tables, forms, dialogs, search, and alert configuration. These patterns have well-established accessibility solutions that we must apply consistently.

**Guiding Principle:** All users, regardless of ability, should be able to perceive, understand, navigate, and interact with CVErt Ops effectively.

## 2. Conformance Target

- **Minimum Standard:** WCAG 2.1 Level AA conformance.
- **Aspiration:** Level AAA where it meaningfully improves usability without undue burden (e.g., enhanced contrast for the data-dense tables that dominate the UI).

## 3. Tech Stack Context

| Layer | Choice | A11y Implications |
|-------|--------|-------------------|
| Components | shadcn-vue (reka-ui primitives) | Built-in ARIA roles, keyboard handling, focus management for dialogs, selects, dropdowns, tabs |
| Styling | Tailwind CSS v4 | Utility classes for focus rings, screen-reader-only text (`sr-only`), responsive layout |
| Framework | Vue 3 Composition API | Dynamic ARIA binding via `:aria-*`, `v-if`/`v-show` for live region control |
| Router | Vue Router | Route announcements, focus management on navigation |
| Icons | lucide-vue-next | SVG icons — need `aria-hidden` or labels depending on context |

**Key advantage:** reka-ui (the primitive layer under shadcn-vue) provides accessible components out of the box — Dialog, AlertDialog, Select, DropdownMenu, Tabs all ship with correct ARIA roles, keyboard navigation, and focus trapping. Our job is to use them correctly, not to reimplement.

## 4. General Principles (POUR)

### 4.1. Perceivable

#### Text Alternatives (WCAG 1.1)

- All non-decorative images MUST have descriptive `alt` text.
- Decorative images MUST have `alt=""`.
- Icon-only buttons (common in CVErt Ops — trash, edit, pencil icons) MUST have an accessible label:

```vue
<!-- CORRECT: Icon button with accessible label -->
<Button variant="ghost" size="sm" aria-label="Delete watchlist">
  <Trash2 class="size-4 text-destructive" />
</Button>

<!-- WRONG: No accessible label — screen reader announces "button" with no context -->
<Button variant="ghost" size="sm">
  <Trash2 class="size-4 text-destructive" />
</Button>
```

- lucide-vue-next icons render as inline SVG. When inside a labeled button or next to visible text, add `aria-hidden="true"` to the icon to prevent double-announcement:

```vue
<!-- Icon + visible text: hide icon from AT -->
<Button>
  <Plus class="mr-2 size-4" aria-hidden="true" />
  New Watchlist
</Button>
```

**Icon decision tree:**

1. **Icon-only button** → `aria-label` on the `<Button>`, `aria-hidden="true"` on the icon (defense-in-depth)
2. **Icon + visible text** → `aria-hidden="true"` on the icon (prevents double-announcement)
3. **Standalone decorative icon** (e.g., empty state illustration) → `aria-hidden="true"`
4. **Standalone meaningful icon** (no adjacent text) → `aria-label` on the icon or wrap in a `<span>` with `aria-label`

**Checklist:**
- [ ] Every `<img>` has an `alt` attribute (descriptive or empty)
- [ ] Every icon-only button has `aria-label` describing the action
- [ ] Icons next to visible text have `aria-hidden="true"`
- [ ] Icon-only buttons also have `aria-hidden="true"` on the icon SVG

#### Adaptable (WCAG 1.3)

- **Semantic HTML:** Use elements according to their meaning — `<nav>`, `<main>`, `<h1>`-`<h6>`, `<button>` (not `<div @click>`), `<table>` for tabular data.
- **ARIA supplementation:** reka-ui components handle most ARIA automatically. When building custom components, add `role`, `aria-label`, `aria-describedby`, `aria-expanded`, `aria-hidden` as needed.
- **Meaningful sequence:** DOM order MUST match visual order. Avoid CSS that reorders content in ways that break screen reader flow.

#### Distinguishable (WCAG 1.4)

- **Color contrast:** Minimum 4.5:1 for normal text, 3:1 for large text (18px+ or 14px+ bold) and UI components/graphical objects.
- **No color-only meaning:** Error states MUST use icons and/or text in addition to red color. Badge variants MUST be distinguishable beyond color (e.g., role badges include the role name as text).
- **Text resizing:** UI MUST remain functional at 200% browser zoom.
- **Tailwind-specific:** Use `text-destructive` paired with error text/icons, never color alone. shadcn-vue's Badge component renders text content, satisfying this requirement.

**Checklist:**
- [ ] Text contrast verified against background (4.5:1 / 3:1)
- [ ] UI component contrast verified (3:1)
- [ ] Error/warning/success states use text and/or icons, not just color
- [ ] 200% zoom tested — no content loss or overlap

### 4.2. Operable

#### Keyboard Accessible (WCAG 2.1)

- All functionality MUST be operable via keyboard.
- **No keyboard traps:** Focus MUST be movable away from any component using only the keyboard. reka-ui's Dialog and AlertDialog handle focus trapping with Escape-to-close — verify this works.
- **Visible focus:** Focus indicators MUST be clearly visible. Tailwind's `ring` utilities and shadcn-vue's default focus styles handle this. Do not suppress `outline` without providing an alternative.

```css
/* shadcn-vue provides focus-visible styles via Tailwind.
   NEVER do this: */
*:focus { outline: none; } /* WRONG — removes all focus indicators */

/* If customizing, ensure high-contrast focus ring: */
*:focus-visible {
  outline: 2px solid hsl(var(--ring));
  outline-offset: 2px;
}
```

- **Data tables:** Table rows/cells are not interactive by default, but action buttons within cells MUST be keyboard-reachable. The delete/edit buttons in our tables already use `<Button>` (focusable by default).

#### Enough Time (WCAG 2.2)

- JWT token refresh happens reactively on 401 — no session timeout dialogs currently. If session expiration UX is added, provide a way to extend.

#### Seizures (WCAG 2.3)

- No flashing content. The `animate-spin` on `Loader2` is a continuous rotation (not a flash) and is acceptable.

#### Navigable (WCAG 2.4)

- **Skip to main content:** Add a skip link as the first focusable element in the app shell, jumping past the sidebar navigation to `<main>`.

```vue
<!-- In App.vue or AuthenticatedLayout.vue -->
<a
  href="#main-content"
  class="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-background focus:px-4 focus:py-2 focus:text-foreground focus:shadow-lg"
>
  Skip to main content
</a>
<!-- ... sidebar ... -->
<main id="main-content">
  <RouterView />
</main>
```

- **Page titles:** Each route MUST set `document.title` to a descriptive value. Use Vue Router's `afterEach` hook:

```ts
router.afterEach((to) => {
  document.title = `${to.meta.title ?? 'CVErt Ops'} — CVErt Ops`
})
```

- **Heading hierarchy:** Each page MUST have exactly one `<h1>`. Subsections use `<h2>`, then `<h3>`. Current pages already follow this (e.g., "Members" `<h1>`, "Pending Invitations" `<h2>`).
- **Link purpose:** Link text MUST describe the destination. Avoid "click here" — use descriptive text like "Back to Watchlists" (already done in WatchlistDetailView).
- **Form labels:** All form inputs MUST have associated `<label>` elements or `aria-label`. shadcn-vue's FormField + FormLabel handle this when used correctly.

**Checklist:**
- [ ] Skip-to-main-content link implemented
- [ ] Every route sets `document.title`
- [ ] Each page has exactly one `<h1>` with logical heading hierarchy
- [ ] All form inputs have visible labels or `aria-label`
- [ ] Link text describes destination

### 4.3. Understandable

#### Readable (WCAG 3.1)

- The `<html>` element MUST have `lang="en"`. (i18n is not currently planned; update this if localization is added.)

#### Predictable (WCAG 3.2)

- Navigation is consistent — sidebar is always in the same position with the same items.
- Interactive elements behave predictably — clicking a row doesn't navigate (links are explicit), delete buttons always prompt confirmation.

#### Input Assistance (WCAG 3.3)

- **Error identification:** Form validation errors MUST be displayed as text associated with the invalid field via `aria-describedby`. Set `aria-invalid="true"` on invalid controls.

```vue
<!-- Pattern for form field errors -->
<div>
  <Label :for="fieldId">Email</Label>
  <Input
    :id="fieldId"
    v-model="email"
    :aria-invalid="!!emailError || undefined"
    :aria-describedby="emailError ? `${fieldId}-error` : undefined"
  />
  <p v-if="emailError" :id="`${fieldId}-error`" class="text-sm text-destructive" role="alert">
    {{ emailError }}
  </p>
</div>
```

**Vue binding note:** The `|| undefined` on `:aria-invalid` is intentional. Without it, Vue renders `aria-invalid="false"` in the DOM when there's no error — technically valid but noisy. With `|| undefined`, the attribute is omitted entirely when not needed.

- **Error prevention:** Destructive actions (delete watchlist, remove member, delete group) MUST use confirmation dialogs. Already implemented via AlertDialog.

### 4.4. Robust

#### Parsing (WCAG 4.1)

- HTML MUST be well-formed — Vue's compiler enforces this at build time.
- No duplicate `id` attributes. When rendering lists of form elements, generate unique IDs.

#### Name, Role, Value (WCAG 4.1.2)

- reka-ui components handle roles and states automatically for: Dialog, AlertDialog, Select, DropdownMenu, Tabs, Checkbox, RadioGroup.
- Custom interactive elements MUST have appropriate `role`, accessible name, and state attributes.

**Checklist:**
- [ ] Custom interactive components have appropriate `role`
- [ ] Components have accessible names (via `aria-label`, `aria-labelledby`, or text content)
- [ ] States (`aria-checked`, `aria-selected`, `aria-expanded`) are dynamically updated
- [ ] No duplicate `id` attributes in rendered HTML

## 5. Component-Specific Guidance

### 5.1. shadcn-vue / reka-ui Components

These components provide built-in accessibility. Use them instead of building custom equivalents:

| Component | Built-in A11y | Our responsibility |
|-----------|--------------|-------------------|
| Dialog / AlertDialog | Focus trap, Escape-to-close, `role="dialog"`, `aria-modal` | Provide `DialogTitle` and `DialogDescription` (required by reka-ui) |
| Select | `role="combobox"`, keyboard nav, `aria-expanded` | Provide meaningful option labels |
| AlertDialogCancel/Action | Auto-focus management | N/A (we replaced Action with Button for async ops — ensure Button still has proper labeling) |
| Table | Semantic `<table>` elements | Use `TableHeader`/`TableHead` for column headers — reka-ui renders `<th scope="col">` |
| Badge | Renders as `<span>` | Include visible text (not icon-only badges) |
| Button | Focusable, keyboard-activatable | Provide `aria-label` for icon-only buttons; use `disabled` not `pointer-events-none` |

### 5.2. Data Tables

Data tables are the primary UI pattern in CVErt Ops. Ensure:

- Tables use `<table>`, `<thead>`, `<th>`, `<tbody>`, `<tr>`, `<td>` — shadcn-vue's Table components render these correctly.
- Column headers MUST be in `<th>` elements (not styled `<td>`).
- Action columns with no header text SHOULD use `<th>` with `sr-only` text or `aria-label`:

```vue
<TableHead class="w-16">
  <span class="sr-only">Actions</span>
</TableHead>
```

- Empty tables MUST announce that they're empty (current empty states with Card + text satisfy this).

### 5.3. Route Changes

- On route change, focus MUST move to the new page's `<h1>` or to `<main>`. Without this, screen reader users get no indication that an SPA navigation occurred.
- Implement route-change focus management in the router's `afterEach` hook:

```ts
// In router setup or App.vue
router.afterEach((to) => {
  nextTick(() => {
    const heading = document.querySelector('h1')
    if (heading instanceof HTMLElement) {
      heading.setAttribute('tabindex', '-1')
      heading.focus()
    }
  })
})
```

### 5.4. Loading States

- Loading spinners MUST have `aria-label="Loading"` or be accompanied by visible text ("Loading members...").
- Consider wrapping loading regions with `aria-live="polite"` so screen readers announce when content loads:

```vue
<div aria-live="polite">
  <div v-if="loading">
    <Loader2 class="animate-spin" aria-hidden="true" />
    Loading members...
  </div>
  <div v-else>
    <!-- loaded content -->
  </div>
</div>
```

### 5.5. Error Messages and Alerts

- Inline error messages SHOULD use `role="alert"` to announce immediately to screen readers.
- Error messages in forms MUST be associated with their field via `aria-describedby`.

**`role="alert"` vs `aria-live` — when to use which:**

- **`role="alert"`** — For error messages that appear after user action (form validation, API errors). Announces immediately and assertively. Use on the `<p>` element that contains the error text.
- **`aria-live="polite"`** — For content regions that update asynchronously (search results loading, member list after invite). Announces at the next pause in speech. Use as a wrapper `<div>` around the dynamic region.
- Do not combine both on the same element — `role="alert"` implies `aria-live="assertive"`, so adding `aria-live="polite"` creates conflicting semantics.

### 5.6. New Component/View Checklist

When adding a new view or form component, verify all of the following before considering it complete:

- [ ] All form inputs have `<Label>` with matching `for`/`id`
- [ ] Error messages have a unique `id`, `role="alert"`, and are linked to the invalid field via `aria-describedby`
- [ ] Invalid inputs have `:aria-invalid="!!error || undefined"`
- [ ] All decorative icons (next to visible text) have `aria-hidden="true"`
- [ ] All icon-only buttons have `aria-label` describing the action
- [ ] Page has exactly one `<h1>`
- [ ] Route entry in `router/index.ts` has `meta.title`
- [ ] Dynamic content regions (search results, lists that change after mutations) have `aria-live="polite"` wrapper
- [ ] Loading states have visible text ("Loading...") or `aria-label="Loading"` on the spinner

## 6. Testing & Validation

### 6.1. Automated

- **axe-core:** Add `vitest-axe` for component-level a11y assertions in unit tests. Run `axe` checks on rendered components.
- **Lighthouse:** Run accessibility audits in CI via Lighthouse CI.
- **eslint-plugin-vuejs-accessibility:** Add to ESLint config for static analysis of Vue templates.

#### 6.1.1. Manual ARIA Assertions (Current Pattern)

Until `vitest-axe` is integrated, test ARIA attributes directly in Vitest:

```ts
it('associates error message with form via aria-describedby', async () => {
  // Trigger the error state (e.g., submit with bad credentials)
  await wrapper.find('form').trigger('submit')
  await flushPromises()

  const input = wrapper.find('#email')
  expect(input.attributes('aria-invalid')).toBe('true')
  expect(input.attributes('aria-describedby')).toBe('login-error')

  const errorEl = wrapper.find('#login-error')
  expect(errorEl.attributes('role')).toBe('alert')
  expect(errorEl.text()).toContain('Invalid credentials')
})
```

Test the relationship between elements, not just that attributes exist — verify the `aria-describedby` value matches the error element's `id`.

### 6.2. Manual

- **Keyboard-only navigation:** Test all flows without a mouse — login, search CVEs, create watchlist, manage members, configure alerts.
- **Screen reader testing:** Test with NVDA (Windows) and VoiceOver (macOS) on key flows.
- **Zoom testing:** Verify 200% browser zoom on all pages — no content loss, no horizontal scroll for primary content.
- **Color contrast:** Verify with browser DevTools or axe.

### 6.3. Key Flows to Test

1. Login → search CVEs → view detail
2. Create watchlist → add items → delete item
3. Invite member → change role → remove member
4. Create group → manage members → delete group
5. Sidebar navigation (keyboard only)
6. Dialog open/close/escape (focus management)

## 7. Implementation Priority

| Priority | Item | Status |
|----------|------|--------|
| P0 | `aria-label` on all icon-only buttons | Done |
| P0 | `lang="en"` on `<html>` | Done |
| P0 | `document.title` per route | Done |
| P1 | Skip-to-main-content link | Done |
| P1 | `sr-only` text on action column headers | Done |
| P1 | `role="alert"` on error messages | Done |
| P1 | `aria-live="polite"` on dynamic content regions | Done |
| P1 | `aria-invalid` + `aria-describedby` on form errors | Done |
| P1 | `aria-hidden="true"` on decorative icons | Done |
| P2 | Route-change focus management (`nextTick` + `h1.focus()`) | Done |
| P2 | `vitest-axe` integration | Not started |
| P2 | `eslint-plugin-vuejs-accessibility` | Not started |
| P3 | Screen reader testing on all key flows | Ongoing |
| P3 | Lighthouse CI integration | Not started |

## 8. Continuous Improvement

Accessibility is ongoing. Review this spec when:
- Adding new component types (charts, drag-and-drop, etc.)
- Adding internationalization
- Adding dark mode (verify contrast in both themes)
- Receiving user feedback about accessibility barriers
