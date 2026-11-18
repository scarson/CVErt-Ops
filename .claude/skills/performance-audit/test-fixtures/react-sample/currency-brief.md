---
schema_version: 1
framework: react
ecosystem: npm
researched_against_version: 18.x
latest_known_at_research: 19.x
researched_on: 2026-06-03
fallback_ttl_days: 180
sources:
  - https://react.dev/reference/react-dom/client/createRoot
  - https://react.dev/reference/react/Component
  - https://react.dev/blog
---

> HAND-AUTHORED for the Lane 5 React fixture test. In real use this file is produced by the
> currency-protocol research step; here it is the brief the workhorse would pass to Lane 5.

## Superseded patterns (old → new)
- `ReactDOM.render(el, container)` → `createRoot(container).render(el)` (deprecated in React 18; the
  legacy root opts out of concurrent features and automatic batching).
- Legacy lifecycles `componentWillReceiveProps` / `componentWillMount` / `componentWillUpdate` →
  `getDerivedStateFromProps`, `componentDidUpdate`, or function components + hooks. Deprecated since
  16.3; only `UNSAFE_`-prefixed aliases remain.
- A fresh inline object/array/function passed as a prop to a `React.memo` child → stabilize with
  `useMemo` / `useCallback` (or rely on the React 19 compiler if enabled).

## New fast-path APIs (and the version that introduced them)
- React 18: `createRoot`, automatic batching, `useTransition` / `useDeferredValue` for non-urgent
  updates, `useId`.
- React 19: the React Compiler (automatic memoization), the `use()` hook.

## Changed defaults
- React 18 enables automatic batching of state updates outside event handlers by default.

## Known perf regressions / fixes by version
- (none relevant to this fixture)
