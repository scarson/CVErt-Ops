import React from "react";
import ReactDOM from "react-dom";
import { ProductList } from "./ProductList";

// PLANTED LANE 5 #B (deprecated API): `ReactDOM.render` was deprecated in React 18 in favor of
// `createRoot(container).render(...)`. The legacy root opts out of concurrent features. The
// currency brief flags this; identifiable as stale only against the brief (works fine on React 17).
ReactDOM.render(
  <ProductList products={[]} categories={[]} />,
  document.getElementById("root")
);
