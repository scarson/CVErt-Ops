// A deliberately "heavy" component (imagine it pulls in a large charting dependency).
// Only used on the rarely-visited "report" route — a prime code-splitting candidate (see entry.jsx 7#4).
import React from "react";

export function HeavyChart({ series }) {
  return <div className="chart">{series.length} points</div>;
}
