import React from "react";

// Memoized so it should only re-render when its props change by reference. But ProductList passes a
// fresh `style` object and `onSelect` closure on every render (see PLANTED REACT-PERF #4), which
// defeats this memo entirely — every Row re-renders on every parent render.
export const Row = React.memo(function Row({ product, category, style, onSelect }) {
  return (
    <div style={style} onClick={onSelect}>
      {product.name} — {category?.name} — ${product.price}
    </div>
  );
});
