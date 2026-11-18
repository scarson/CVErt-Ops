# Expected Findings — React Lane 7 (payload / startup / build)

**Purpose:** exercise **Lane 7 (payload / startup / build)** — conditional, runs because this is a
frontend stack. Scope: `entry.jsx`, `HeavyChart.jsx`, `Home.jsx`, `Rarely.jsx`, `package.json`.
`*.jsx` are illustrative (not built).

## How to run

Dispatch a Lane 7 agent with the shared preamble + Lane 7 body from `../../lane-prompts.md` and the
Lane 7 + bundle bullets of `../../profile-packs/javascript-typescript.md` as the lens; scope = this
directory (including `package.json`). Do NOT let it read `expected-findings.md` or this file.

## Planted issues (should be found)

| # | File:loc | Issue |
|---|----------|-------|
| 1 | `entry.jsx` `import _ from "lodash"` | whole-library import to use only `debounce` → defeats tree-shaking; use `lodash/debounce` or `lodash-es` |
| 2 | `entry.jsx` `import moment from "moment"` | heavy, non-tree-shakeable date lib for one format call → lighter alternative (Intl / date-fns) |
| 3 | `entry.jsx` `const PRECOMPUTED = ...` | expensive work (100k iterations) at module top-level → runs at startup, blocks first paint; defer/lazy |
| 4 | `entry.jsx` `import { HeavyChart }` | heavy component used only on the rare "report" route imported eagerly → `React.lazy` + code-split |

## Decoy (should NOT be flagged)

| File:loc | Why ignored |
|----------|-------------|
| `entry.jsx` `const Rarely = React.lazy(() => import("./Rarely"))` | already correctly code-split. Flagging it is a precision failure. |

## Scoring

- **Recall** = (# of {1,2,3,4} found) / 4.
- **Precision** = the already-lazy `Rarely` route is not flagged; no fabricated findings.
- Lane 7 reasoning should be structural (import shape, manifest deps, module-top-level work, route
  usage) — it cannot measure real bundle bytes without a build, and should not invent specific KB figures.
