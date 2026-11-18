# JS/TS performance module: Bundling & build (Vite / webpack / esbuild / Rollup)
> Load when a frontend build is detected (`vite`/`webpack`/`esbuild`/`rollup`/`turbopack` config, a `dist/` bundle, or a browser-targeted `package.json`) — see the module map in `../javascript-typescript.md`. Core lanes + Runtime notes live in `../javascript-typescript.md`; this file is the Bundling & build lens only.

## Bundling & build (Vite / webpack / esbuild / Rollup)

> Scope: the mechanics of what ends up in the shipped bundle and why — tree-shaking failure modes,
> code-splitting strategy, transpilation target accuracy, heavy-dependency cost, CSS weight, asset
> handling, and build-pipeline throughput. The recurring theme is: **ship less JS, split by route,
> tree-shake real dead code, target the right ES version, and measure before optimising** — a bundle
> analyser is the starting point, not a checklist. Quick-hits (named imports, missing lazy-loading,
> `NODE_ENV`, duplicate deps, missing minification, render-blocking scripts) are covered in the core
> **payload/startup/build** lane in `../javascript-typescript.md`; this file goes deeper into the
> bundler mechanics behind each.

- **CommonJS deps block tree-shaking entirely**: ES module tree-shaking requires static `import`/`export`
  syntax — bundlers (Rollup, Vite, webpack 5, esbuild) cannot eliminate dead exports from a CommonJS
  module because `require()` is dynamic and `module.exports` is a runtime value. When a dependency
  publishes only a CJS build, the entire package is included regardless of what the consumer imports.
  Look for packages that lack an `"exports"` map with an `"import"` (ESM) condition or a `"module"`
  field in `package.json`; check whether the bundler's resolution is picking up the CJS entrypoint
  — tools like `rollup-plugin-visualizer` or `webpack-bundle-analyzer` will show the full blob rather
  than individual exports. Prefer ESM-native alternatives or the package's explicit ESM build (e.g.,
  `lodash-es` over `lodash`) where the cost matters (cross-reference the **payload/startup/build**
  lane in `../javascript-typescript.md`; verify against the currency brief for your version).

- **`"sideEffects"` missing or wrong in `package.json` prevents dead-code elimination**: bundlers
  that support the `"sideEffects"` field use it to decide whether an imported-but-unused module can
  be dropped entirely. Without it (or when set to `true`), every imported file is retained even if
  nothing is used from it, because the bundler must assume the `import` has observable side effects.
  The failure modes are symmetric: a library that omits the field keeps unused modules in the bundle;
  a library that sets `"sideEffects": false` incorrectly (e.g., a CSS import or a global polyfill
  that actually mutates the environment) will be silently dropped, causing runtime errors. Look for
  packages with no `"sideEffects"` key whose contribution shows up as unexpectedly large in a bundle
  report, and for first-party code that imports CSS or polyfills via side-effect-only imports that
  must be listed as exceptions (e.g., `["*.css", "./src/polyfills.js"]`) (verify against the currency
  brief for your version).

- **Barrel files defeat tree-shaking and slow builds**: an `index.ts` that re-exports every module
  in a directory (barrel export pattern) forces the bundler to load, parse, and analyse every file
  in that barrel to determine which exports are live — even when the consumer only imports one
  symbol. This creates two costs: (1) graph-time: the bundler must crawl the entire re-export chain
  before it can mark dead code, slowing incremental builds as the barrel grows; (2) tree-shaking
  accuracy: if any re-exported module has side effects the bundler cannot statically prove away, the
  whole barrel is retained. Look for `index.ts` files with tens of `export * from '…'` or `export {
  X } from '…'` lines at the component/feature directory level; in monorepos this pattern can make
  every internal package import pull in an entire sub-tree. Deep path imports (`import { Button }
  from '@ui/components/Button'` instead of `import { Button } from '@ui'`) bypass the barrel and
  unlock per-file dead-code elimination (cross-reference the **payload/startup/build** lane for
  named-import guidance; verify against the currency brief for your version).

- **Over-splitting causes request waterfalls; under-splitting ships everything**: dynamic `import()`
  creates a chunk boundary, but the optimal granularity is route-level or feature-level — not
  per-component. Too many tiny chunks means the browser must fire sequential requests to resolve a
  module graph at runtime (a waterfall), erasing the latency win of splitting; too few chunks means
  a user visiting one route downloads the code for all others. Look for: shared utilities or vendor
  libraries duplicated across multiple chunks (each chunk bundled its own copy instead of sharing
  one via `splitChunks` / Rollup's `manualChunks`); overly granular splitting (many < 5 kB chunks
  behind a single route); or a single monolithic vendor chunk containing libraries used on only one
  route. The right model is large shared chunks for truly shared code, plus per-route chunks for
  route-specific code; `<link rel="modulepreload">` for critical next-route chunks eliminates the
  perceived waterfall on predictable navigations (cross-reference `React.lazy`/`defineAsyncComponent`
  / Angular `@defer` notes in the `react`, `vue`, `angular` modules; verify against the currency
  brief for your version).

- **Heavy dependency pulled for one function**: large libraries with no tree-shakable ESM build
  impose their full weight on the bundle regardless of usage. The canonical example is `moment.js`
  (~300 kB minified + locale data), which bundles all locale files by default and cannot be
  tree-shaken because it is CommonJS; the alternatives `date-fns` (ESM, per-function imports),
  `dayjs` (~2 kB), or the platform `Temporal` API carry a fraction of the cost for equivalent
  functionality. The pattern generalises: a large icon library imported as `import { IconA } from
  '@icons/all'`, a full i18n locale bundle, or a complete polyfill suite pulled in for one method
  all show up as the same failure mode in a bundle analyser — a large blob disproportionate to the
  feature surface used. Run `rollup-plugin-visualizer` or `webpack-bundle-analyzer` and sort by
  size; flag any dependency where the used surface is clearly a small fraction of the included
  weight (verify against the currency brief for your version).

- **Transpilation target too broad inflates payload and polyfill cost**: shipping ES5-compatible
  output when the audience is modern browsers forces the transpiler to emit verbose helper code for
  every class, arrow function, optional chain, and destructure. `@babel/runtime` helper deduplication
  (`@babel/plugin-transform-runtime`) avoids per-file inline copies, but the helpers themselves
  still add weight. `core-js` polyfills are the larger risk: `useBuiltIns: 'entry'` with a broad
  `browserslist` can inject tens of kB of polyfills for browser features the target already supports
  natively. Look for: a `browserslist` query like `"> 0.5%, last 2 versions"` that includes legacy
  IE or Android 4; `core-js` appearing as a large chunk in the bundle report; Babel in the critical
  build path when esbuild or SWC (5–20× faster) would meet the same target. Differential serving
  (a modern `<script type="module">` build + a legacy `<script nomodule>` fallback) is an option
  where IE11 or Android legacy support is genuinely required but modern users must not pay the
  penalty (cross-reference the `tslib` / `importHelpers` note for TypeScript codebases; verify
  against the currency brief for your version).

- **Unoptimised CSS weight and render-blocking style**: utility CSS frameworks (Tailwind, UnoCSS,
  Windi) ship near-zero unused CSS when purging is configured correctly, but if the content paths
  (`content` / `purge` array) miss source files, entire utility sets are included. CSS-in-JS
  runtimes (emotion, styled-components, runtime `@emotion/css`) evaluate and inject styles at
  JavaScript runtime, adding both bundle weight (the runtime) and a style-injection cost per render
  that pure static CSS avoids; zero-runtime CSS-in-JS alternatives (vanilla-extract, Linaria, Panda
  CSS) or utility frameworks move this cost to build time. Missing critical-CSS extraction means the
  browser must download and parse the full stylesheet before rendering above-the-fold content — look
  for large, non-inlined stylesheets linked in `<head>` without `media` queries deferring off-screen
  styles. These are distinct failure modes: purge misconfiguration ≈ raw payload; runtime CSS-in-JS
  ≈ JS bundle + render cost; blocking CSS ≈ render latency even if the file is small (cross-reference
  the render-blocking note in the **payload/startup/build** lane of `../javascript-typescript.md`;
  verify against the currency brief for your version).

- **Slow builds from type-checking in the bundler hot path and absent caching**: TypeScript
  type-checking during the bundler's transform step (`ts-loader` in full-type-check mode, `vite`
  with `vite-plugin-checker` on every save) blocks the hot-module-replacement pipeline on the
  slowest part of the TypeScript toolchain. The standard split is: bundler handles transpile-only
  transforms (esbuild/SWC strip types without checking, making HMR near-instant) while `tsc
  --noEmit` runs type checking separately in CI or as a parallel watcher. Separately, missing
  persistent caching (`cache: true` in webpack 5 filesystem cache, Vite's pre-bundling cache,
  Turborepo/Nx task caching for monorepos) means full rebuilds from scratch on every CI run or
  fresh container. Look for: `ts-loader` without `transpileOnly: true`; no `cache` section in
  `webpack.config`; CI steps that never restore a build cache; barrel imports (see above) that force
  large graph re-analysis on each incremental build (verify against the currency brief for your
  version).
