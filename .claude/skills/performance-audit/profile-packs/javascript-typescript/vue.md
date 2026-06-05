# JS/TS performance module: Vue
> Load when Vue (`vue`, `*.vue` SFCs, Nuxt) is detected — see the module map in `../javascript-typescript.md`. Core lanes + Runtime notes live in `../javascript-typescript.md`; this file is the Vue lens only.

## Vue

> Scope: Vue 3 with the Composition API and `<script setup>`, including Nuxt SSR/SSG deployments.
> The recurring performance theme is four levers applied together: **bound reactivity granularity**
> (don't let Vue proxy-wrap data that never needs to drive the DOM), **cache derived values**
> (computed over methods; debounced/narrow watchers), **skip diffing static and stable subtrees**
> (v-once, v-memo, stable keys), and **lazy/split the bundle** (async components, route splitting,
> lazy hydration). When a signal in one bullet implicates bundle size or build output, also consult
> the `bundling-build` module and the `payload-startup` lane in `../javascript-typescript.md`.

- **Reactivity granularity — deep `reactive`/`ref` on large structures**: Vue 3 wraps every nested
  property in a Proxy, so a single large `reactive({})` tree pays an O(n) cost at setup and on
  deep mutations. If only a small slice of the object ever drives the DOM, the rest of the proxy
  machinery is pure overhead. `shallowRef`/`shallowReactive` make only the top-level reference
  reactive; `markRaw` opts an object out of reactivity entirely — use it for third-party class
  instances, large lookup tables, or canvas/WebGL objects attached to component state. Vue 3.5
  included a reactivity rewrite reported to reduce memory and improve large-array performance;
  the durably correct framing is to keep reactive trees as narrow as possible regardless of
  runtime version (verify against the currency brief for your version).

- **Computed vs methods vs watchers — caching and dependency scope**: `computed` properties cache
  their result and only recompute when a tracked reactive dependency changes, so a template
  reading a computed ten times in one render pays the derivation cost once. A method called in the
  template recomputes on every render regardless of input stability — the footgun is using a method
  where the value is truly derived from reactive state and doesn't need to be called with arguments.
  `watchEffect` collects all reactive reads at runtime (easy to write, easy to over-read); explicit
  `watch` with a narrow source expression limits the dependency surface and makes the trigger
  condition auditable. Either form doing heavy synchronous work on every change should be debounced
  or restructured to narrow what triggers it (cross-reference the `concurrency` lane in
  `../javascript-typescript.md`).

- **Template diffing — `v-once`, `v-memo`, and `v-if`/`v-for` placement**: `v-once` renders a
  subtree once and skips it in all future patch cycles — correct for content that is truly static
  after mount (legal text, static imagery, translated labels that don't change). `v-memo` accepts a
  dependency array and skips a subtree's diff when every value in the array is the same as the
  last render; for list rows keyed on stable identifiers with infrequently changing display fields,
  this can eliminate O(n) diffing under a frequent parent update. Placing `v-if` and `v-for` on the
  same element forces Vue to evaluate the condition for every item before deciding whether to render;
  wrap with a `<template>` tag to separate the two (verify against the currency brief for your
  version).

- **List rendering — `key` correctness and virtualization**: `:key` set to array index on a
  reorderable, filterable, or pageable list causes Vue to patch the wrong DOM nodes and re-render
  rows that haven't changed — use a stable domain identifier. For large lists (hundreds of rows
  or more), virtual scrolling (e.g., `vue-virtual-scroller`) renders only the visible viewport
  slice, keeping DOM node count bounded and eliminating O(n) mount/unmount costs on filter changes.
  The combination of index keys and no virtualization on a large list is the worst case: full DOM
  teardown and rebuild on every sort or filter (verify against the currency brief for your version).

- **Props and component granularity — inline allocations and reactive destructuring**: object or
  array literals, and arrow-function handlers, written inline in a template (`<Child :config="{}"`,
  `@click="() => ..."`) create a new reference on every parent render; child components receiving
  them will see the prop as "changed" even when the logical value is identical. In Vue 3.5, props
  can be destructured in `<script setup>` while preserving reactivity via the compiler transform —
  confirm the project's Vue version supports this before relying on it. Over-deep component trees
  multiply the patch work per update; prefer fewer, coarser components for very high-frequency
  updates (e.g., real-time data feeds) where component boundary overhead accumulates
  (verify against the currency brief for your version).

- **Watcher leaks and unbounded reactive stores**: `watch`/`watchEffect` return a stop handle that
  must be called when the owning component or composable is torn down — effects created outside a
  component lifecycle (in a utility module, a global composable called once at app init, or a
  Pinia action) are never auto-stopped and accumulate for the process lifetime. Global reactive
  stores (`reactive` objects or Pinia stores) that grow unbounded — caches that append but never
  evict, event-log arrays that keep every entry — create both a memory leak and a watcher fan-out
  cost as more components subscribe. Also check for DOM event listeners attached in `onMounted`
  without a matching removal in `onUnmounted` (cross-reference the `memory` lane in
  `../javascript-typescript.md`).

- **SSR and hydration cost (Nuxt)**: full hydration at page load walks the entire component tree
  and re-creates the reactive graph client-side even for below-the-fold or interaction-free
  sections. Vue 3 / Nuxt expose lazy-hydration strategies — `hydrateOnVisible` defers until the
  element enters the viewport, `hydrateOnIdle` defers to `requestIdleCallback`, and
  `hydrateOnInteraction` defers until a pointer or keyboard event — so above-the-fold and
  interactive components hydrate first. `defineAsyncComponent` combined with lazy hydration splits
  the component's JS out of the initial chunk and delays execution. Nuxt's component islands
  (`<NuxtIsland>`) let entire subtrees remain server-rendered HTML with no client JS. Hydration
  mismatches (server HTML differs from client render) force a full client-side re-render of the
  affected subtree and log a warning — they are a correctness and performance issue simultaneously
  (verify against the currency brief for your version).

- **Bundle size — async components, auto-imports, and tree-shaking**: route-level code splitting
  via dynamic `import()` in the router config keeps each route's component graph out of the initial
  bundle; `defineAsyncComponent` does the same at the component level and can be combined with a
  loading/error slot to keep UX clean during load. Nuxt's auto-import feature is convenient but can
  silently pull in large composables or utility modules on every route if the import graph is not
  audited; verify which modules end up in the critical-path chunk with a bundle analyzer. Vue's
  compiler tree-shakes runtime helpers by default in a properly configured build, but hand-rolling
  `Vue.createVNode` or importing from `vue` internals can defeat that (cross-reference the
  `bundling-build` module and the `payload-startup` lane in `../javascript-typescript.md`;
  verify against the currency brief for your version).
