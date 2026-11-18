// Representative React (illustrative — NOT executed; no build/install needed).
// Exercises the JS/TS pack's React subsection + Lane 1/2/4 signals.
import React, { useState, useMemo } from "react";
import { Row } from "./Row";

// Hot path: re-renders on every keystroke in the filter box.
export function ProductList({ products, categories }) {
  const [query, setQuery] = useState("");

  // DECOY (should NOT be flagged): this derivation is ALREADY correctly memoized with the right
  // dependency. Flagging correctly-memoized code is a precision failure.
  const total = useMemo(() => products.reduce((s, p) => s + p.price, 0), [products]);

  // PLANTED REACT-PERF #3 (Lane 2/1 — expensive work in render, not memoized): the full sort runs
  // on every render, including keystrokes that only change `query`. Should be useMemo([products]).
  const sorted = [...products].sort((a, b) => b.price - a.price);

  const rows = sorted
    .filter((p) => p.name.includes(query))
    .map((p, i) => {
      // PLANTED REACT-PERF #1 (Lane 1 — O(n^2) in render): linear scan per product, every render.
      // Build a Map(id -> category) once instead.
      const category = categories.find((c) => c.id === p.categoryId);
      return (
        // PLANTED REACT-PERF #2 (Lane 1/React — unstable key): index as key in a list that is
        // sorted/filtered (reorders) defeats reconciliation and risks state bugs + extra work.
        // PLANTED REACT-PERF #4 (Lane 4/React — fresh inline object + function each render):
        // a new `style` object and `onSelect` closure are created per render, defeating React.memo
        // on <Row>, so every Row re-renders even when its data is unchanged.
        <Row
          key={i}
          product={p}
          category={category}
          style={{ padding: 4 }}
          onSelect={() => console.log(p.id)}
        />
      );
    });

  return (
    <div>
      <div>Total: ${total}</div>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      {rows}
    </div>
  );
}
