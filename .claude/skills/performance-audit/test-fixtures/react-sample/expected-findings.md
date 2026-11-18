# Expected Findings — React fixture

**Purpose:** exercise (a) the **JS/TS pack's React subsection** via the render/memoization/key
signals, and (b) **Lane 5 (framework-idiom currency)** for React using `currency-brief.md`.
`*.jsx` are illustrative (not executed/built).

## How to run

- **React-perf lanes:** dispatch Lane 1, Lane 2, and Lane 4 agents with the shared preamble + that
  lane body from `../../lane-prompts.md` and the **React subsection** of
  `../../profile-packs/javascript-typescript.md` as the lens; scope = `ProductList.jsx` + `Row.jsx`.
- **Lane 5 with-brief:** Lane 5 agent + the contents of `currency-brief.md` as `[currency brief]`;
  scope = `index.jsx` + `LegacyWidget.jsx` (+ ProductList for the inline-prop currency note).
- **Lane 5 offline:** same but `[currency brief]` = "unavailable — offline" → expect LOW confidence,
  no fabricated version claims.

Do NOT let the agents read this rubric.

## Planted issues (should be found)

| # | File:loc | Lane / lens | Issue |
|---|----------|-------------|-------|
| 1 | `ProductList.jsx` `.map` body | 1 / React | `categories.find()` inside `.map()` → O(n²) per render; build a Map once |
| 2 | `ProductList.jsx` `<Row key={i}>` | 1 / React | index as key in a reordering (sorted/filtered) list |
| 3 | `ProductList.jsx` `const sorted = [...].sort()` | 2 / React | expensive sort/derivation in render, unmemoized; re-runs on every keystroke |
| 4 | `ProductList.jsx` `style={{...}}` / `onSelect={() => ...}` → `Row` | 4 / React | fresh inline object + closure each render defeat `React.memo` on `<Row>` |
| A | `LegacyWidget.jsx` `componentWillReceiveProps` | 5 (currency) | deprecated lifecycle per brief → `getDerivedStateFromProps`/hooks |
| B | `index.jsx` `ReactDOM.render(...)` | 5 (currency) | deprecated API per brief → `createRoot(...).render(...)` |

## Decoy (should NOT be flagged)

| File:loc | Why ignored |
|----------|-------------|
| `ProductList.jsx` `const total = useMemo(...)` | already correctly memoized with the right dependency. Flagging it is a precision failure. |

## Scoring

- **React-perf recall** = (# of {1,2,3,4} found) / 4.
- **Lane 5 with-brief recall** = (# of {A,B} found) / 2, each citing the brief entry.
- **Precision** = the `useMemo` decoy is not flagged; no fabricated findings.
- **Offline Lane 5** = A/B (if mentioned) carry LOW confidence + "manual currency check"; no
  confident version-specific claims invented without the brief.
