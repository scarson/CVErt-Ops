import React from "react";

// Rarely-visited route. Already lazy-loaded via React.lazy in entry.jsx — this is the DECOY:
// it is correctly code-split, so Lane 7 must NOT flag it.
export default function Rarely() {
  return <div>Rarely visited</div>;
}
