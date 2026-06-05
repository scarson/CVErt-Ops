# JS/TS performance module: React
> Load when React (`react`/`react-dom`, `*.jsx`/`*.tsx` with JSX, Next.js) is detected — see the module map in `../javascript-typescript.md`. Core lanes + Runtime notes live in `../javascript-typescript.md`; this file is the React lens only.

## React

> Scope: React component trees and their host environments (browser, SSR, RSC). The recurring theme
> is **minimising re-render scope and work-per-render** — keep references stable so memoization
> actually holds, move expensive computation off the render path, and move work off the client
> entirely where Server Components or SSR can absorb it.

- **Re-render cascade from unstable inline props**: a parent re-render re-renders every unmemoized
  child; an inline object, array, or function literal (`style={{ color }}`, `onClick={() => …}`)
  creates a new reference each render, breaking `React.memo`'s shallow comparison and voiding any
  memoization downstream. Look for JSX attributes that construct values — object literals, array
  literals, arrow functions — at the call site rather than in a stable variable, `useMemo`, or
  `useCallback`. The **React Compiler** (React 19-era) auto-memoizes these when it can prove
  stability, making manual `useMemo`/`useCallback` largely redundant in compiler-enabled codebases;
  flag manual memoization the compiler now handles as clutter, and flag *missing* memoization in
  codebases that have not adopted the compiler where child re-render cost is measurable (verify
  against the currency brief for your version).

- **`React.memo` misuse — absent where it helps, present where it doesn't**: a pure component that
  receives stable props but sits under a frequently-updating parent is a candidate for `React.memo`;
  its absence means the component always re-renders even when its output cannot change. The inverse
  is equally worth flagging: wrapping a component whose props nearly always differ (e.g., receives a
  new object each render from a non-memoized parent) adds a shallow-comparison cost with no
  memoization benefit — the memo wrapper just burns cycles on the comparison. Look for the asymmetry
  between how often props actually change and whether the wrapper is present (verify against the
  currency brief for your version; cross-reference the **Algorithmic** lane in
  `../javascript-typescript.md`).

- **Context re-render fan-out**: every consumer of a context re-renders when the context value
  reference changes; a context whose value is an object literal recreated each render (`value={{ user,
  dispatch }}`) re-renders all consumers on every parent render regardless of whether the consumed
  slice changed. Look for: single monolithic contexts holding both stable config and high-churn
  state; object or array values that are not stabilized with `useMemo`; consumers that only read one
  field of a multi-field context. The fix space is: split contexts by update frequency, stabilize
  the value reference, or move high-churn state to an external store with `useSyncExternalStore` or
  a selector-based library (Zustand, Redux Toolkit selectors) that lets components subscribe to
  a narrow slice (verify against the currency brief for your version).

- **Expensive work in the render body**: computation run directly in the function body (not wrapped
  in `useMemo`) re-executes on every render triggered by any state or prop change, even unrelated
  ones. Look for: large array transforms (sort, filter, reduce) over props or state; heavy object
  construction; regex execution over long strings; tree-traversal — all inline in the component
  body. The condition to flag is unstable inputs combined with expensive work; `useMemo` with a
  precise dependency array defers recomputation to actual input changes. Also check effects used
  purely to derive state: `useEffect` that reads state A and `setState(derive(A))` is a
  double-render pattern — derive the value during render instead ("You Might Not Need an Effect")
  (cross-reference the **Algorithmic** lane in `../javascript-typescript.md`).

- **Effect-driven re-subscribe and dependency churn**: `useEffect` hooks whose dependency arrays
  contain unstable references (inline objects, functions, derived arrays) re-fire on every render
  even when the logical dependency has not changed, creating re-subscribe loops for subscriptions,
  timers, or data-fetch chains. Look for: effects whose `deps` include values computed inline or
  passed as props without stabilization; effects that set state unconditionally (triggering another
  render → another effect fire); data-fetching effects that chain (`fetchA → setState → fetchB in
  another effect`), creating sequential waterfalls the framework's data layer or a single async
  function would eliminate. Cross-reference "You Might Not Need an Effect" for the derived-state
  pattern and the **Data access & I/O** lane in `../javascript-typescript.md` for the fetch-waterfall
  pattern.

- **Concurrent feature gaps — `useTransition` and `useDeferredValue`**: CPU-heavy state updates
  (filtering a large list, re-rendering a large tree) that run synchronously block user input and
  produce jank; wrapping the expensive update in `startTransition` or `useTransition` marks it
  non-urgent so React can interrupt it in favor of user input. Look for: event handlers that both
  update fast-response UI (input value) and trigger expensive derived renders in the same
  synchronous path. Separately, `useDeferredValue` lets a display value lag behind a fast-updating
  source (e.g., showing the previous filtered list while the new filter renders), eliminating
  per-keystroke jank without debounce gymnastics. Missing Suspense boundaries block progressive and
  streaming SSR rendering — every data-fetching or lazy-loaded subtree that could independently
  suspend should be wrapped so the rest of the tree can render without it (verify against the
  currency brief for your version).

- **State structure causing unnecessary breadth**: over-broad state — storing derived values
  alongside source, duplicating state across siblings, lifting state higher than the deepest common
  ancestor that needs it — causes more components to re-render than logically necessary. Look for:
  `useState` holding values computable from other state or props (should be derived during render or
  via `useMemo`); state lifted to a top-level provider when only a local subtree cares; uncontrolled
  input patterns that update a shared store on every keystroke, re-rendering a large tree per
  character (local state + debounced sync, or `useDeferredValue`, bounds this). Also flag
  index-as-key on reorderable or filterable lists: React uses the key to decide whether to reuse a
  component instance, so an index key on a reordering list forces full remount and DOM teardown of
  every shifted item; long lists with stable-but-numerous items need virtualization
  (react-window / TanStack Virtual) rather than rendering all nodes into the DOM (verify against
  the currency brief for your version; cross-reference the **Memory** lane in
  `../javascript-typescript.md`).

- **Heavy component patterns — inline definitions and missing lazy-loading**: defining a component
  function inside another component's render body creates a new function reference and a new React
  component *type* on every parent render; React sees a different type and unmounts+remounts the
  entire subtree rather than reconciling it — look for function components declared with `function`
  or arrow syntax inside another component's body. Separately, heavy components (charts, rich-text
  editors, large third-party widgets) rendered unconditionally at mount, even when off-screen or
  conditionally shown, pay their parse and init cost on every page load; `React.lazy` + Suspense
  defers that cost to first use (cross-reference the **Payload / startup / build** lane and the
  `bundling-build` module in `../javascript-typescript.md`).

- **SSR / RSC and hydration cost**: in Next.js App Router and similar RSC runtimes, marking a
  component `"use client"` ships its module and all its imports to the browser bundle; overuse
  converts what could be zero-JS Server Components into client-side JavaScript, inflating
  Time-to-Interactive. Look for: `"use client"` applied to large subtrees or layout components
  where only a small leaf needs interactivity; data fetching done client-side (useEffect + fetch)
  that could run on the server; heavy third-party imports pulled into client components. Hydration
  itself has a cost proportional to the amount of server-rendered HTML being reconciled on the
  client — look for large server-rendered trees where selective or progressive hydration strategies
  (lazy hydration, islands) would reduce main-thread work at startup (verify against the currency
  brief for your version; cross-reference the **Payload / startup / build** lane and the
  `bundling-build` module).
