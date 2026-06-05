// Application entry — exercises Lane 7 (payload / startup / build). Illustrative; not built.
import React, { Suspense } from "react";
import _ from "lodash"; // PLANTED 7#1 (whole-library import): pulls all of lodash into the bundle to
                        // use only `debounce`; defeats tree-shaking. Use `lodash/debounce` or `lodash-es`.
import moment from "moment"; // PLANTED 7#2 (heavy non-tree-shakeable dep): moment ships all locales and
                            // is not tree-shakeable; for one format call a lighter option (Intl /
                            // date-fns) cuts a large chunk of bundle weight.
import { HeavyChart } from "./HeavyChart"; // PLANTED 7#4 (eager import of a heavy, rarely-used component):
                                          // HeavyChart is only rendered on the "report" route but is
                                          // imported eagerly, so it ships in the initial bundle. Should be
                                          // React.lazy(() => import("./HeavyChart")) + code-split.
import { Home } from "./Home";

// PLANTED 7#3 (expensive work at module top-level / startup): runs during initial module evaluation,
// blocking first paint and inflating startup cost — 100k iterations of date formatting at boot.
const PRECOMPUTED = _.range(0, 100000).map((n) => moment().add(n, "days").format("YYYY-MM-DD"));

// DECOY (correctly code-split — must NOT be flagged): a rarely-used route is already lazy-loaded.
const Rarely = React.lazy(() => import("./Rarely"));

export function App({ route }) {
  const onResize = _.debounce(() => {}, 200); // only one lodash function is actually used — see 7#1
  return (
    <div onResize={onResize}>
      {route === "report" ? <HeavyChart series={PRECOMPUTED} /> : <Home />}
      <Suspense fallback={null}>{route === "rare" ? <Rarely /> : null}</Suspense>
    </div>
  );
}
