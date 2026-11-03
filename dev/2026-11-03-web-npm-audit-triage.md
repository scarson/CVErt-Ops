# Web SPA npm audit triage — 2026-11-03

Scope: `web/` (Vue 3 SPA). Trigger: `npm install` on 2026-11-02 reported 35 vulnerabilities (24 moderate, 10 high, 1 critical). Baseline was the `dev` lockfile at `ecd103f`.

## Outcome

| | Before | After |
|---|---|---|
| Critical | 1 | 0 |
| High | 10 | 0 |
| Moderate | 24 | 20 |

The 20 remaining moderates come from two root advisories, `minimatch` <11.0.1 and `glob` <14.0.2. Both are confined to lint and test tooling, and neither has a patched release in any version range the parent packages accept. See "Left unfixed" below.

Every fix is an in-range update: a patch or minor release within the major version already declared. There are no major-version bumps, no dependency replacements, and no `overrides`. `npm audit fix --force` was not used. Its two suggestions were a downgrade of `openapi-typescript` 7→6.7.6 and a downgrade of `@vue/eslint-config-typescript` 14→4.0.0, and both were rejected.

## What ships to users

Only one fixed package ships in the production bundle: `vue` (3.5.32 → 3.5.44). Its advisory (GHSA-g2v6-rqmx-r4w6, XSS in `@vue/server-renderer`) affects server-side rendering only. This SPA has no SSR. `src/` does not import `vue/server-renderer`, `renderToString` or `createSSRApp`, and the built `dist/` contains no server-renderer code. The advisory was not reachable here. The upgrade was taken anyway because `vue` is a runtime dependency and staying current on its patch line is cheap.

Every other advisory below is in build, dev-server, test or codegen tooling, which is not in the bundle.

## Fixed advisories

"Reachable" means an attacker-controlled input can reach the vulnerable code path in this project's actual use of the package.

| Package (before → after) | Severity | Direct / transitive (path) | Ships? | Reachable here? | Advisories |
|---|---|---|---|---|---|
| `shell-quote` 1.8.3 → 1.12.0 | **critical** | transitive: `npm-run-all2` | no (build scripts) | No. It quotes and parses `run-s`/`run-p` arguments taken from our own `package.json` scripts. | GHSA-w7jw-789q-3m8p (newline not escaped in `quote()`), GHSA-395f-4hp3-45gv (quadratic `parse()`) |
| `vue` / `@vue/*` 3.5.32 → 3.5.44 | high | direct | yes (runtime) | No. The bug is SSR-only and this app has no SSR (see above). | GHSA-g2v6-rqmx-r4w6 |
| `vite` 8.0.8 → 8.3.5 | high | direct (dev) | no (dev server, bundler) | Partly, on a developer workstation. The dev server binds to localhost only (no `server.host` in `vite.config.ts`). The `launch-editor` Windows issues (UNC-path NTLMv2 hash disclosure, `%` escaping, flag injection) apply to the Windows dev machines used on this project. | GHSA-v6wh-96g9-6wx3, GHSA-698v-4r3x-3vcv, GHSA-r825-w8mm-5pxw, GHSA-587h-7wmj-h5pm, GHSA-9jrq-w75r-8gcw, GHSA-rq7h-c2jc-7f22, GHSA-fx2h-pf6j-xcff |
| `postcss` 8.5.8 → 8.5.32 | high | transitive: `vite`, `@vue/compiler-sfc` | no (build) | No. It only processes our own CSS and SFC styles; there is no untrusted CSS or `sourceMappingURL`. | GHSA-qx2v-qp2m-jg93, GHSA-6g55-p6wh-862q, GHSA-fxqj-rqcc-2cmp, GHSA-r28c-9q8g-f849 |
| `nanoid` 3.3.11 → 3.3.20 | high | transitive: `postcss` | no (build) | No. `postcss` never passes negative or zero sizes. | GHSA-28wg-ghj8-5hjv, GHSA-2v37-7h3g-55p8, GHSA-xwg4-73v4-xw9w |
| `source-map-js` 1.2.1 → 1.2.2 | high | transitive: `postcss`, `@vue/compiler-*`, `@tailwindcss/node` | no (build) | No. It only reads source maps the build generates itself. | GHSA-68fv-2mgg-jv7q |
| `undici` 7.25.0 → 7.30.1 | high | transitive: `jsdom` | no (unit tests) | No. jsdom in Vitest makes no outbound requests to untrusted hosts. | ~29 advisories (TLS bypass, CRLF and header injection, cache disclosure, several DoS); see `npm audit` before this change |
| `js-yaml` 4.1.1 → 4.3.2 (via `@redocly/openapi-core` 1.34.11 → 1.34.22) | high | transitive: `openapi-typescript` | no (codegen, `npm run generate-api`) | No. Its only input is our own `../openapi.json`. | GHSA-h67p-54hq-rp68, GHSA-52cp-r559-cp3m, GHSA-5p4m-2wfm-xmqj, GHSA-2883-xcg3-v3hh |
| `js-cookie` 3.0.5 → 3.0.8 | high | transitive: `@vue/test-utils` → `js-beautify` | no (tests) | No. `js-cookie` serves only `js-beautify`'s browser UI, which the test path never loads. | GHSA-qjx8-664m-686j |
| `brace-expansion` 2.0.2 → 2.1.7, 5.0.4 → 5.0.12 | high | transitive: `minimatch` (eslint, editorconfig, glob, redocly) | no (lint, tests, codegen) | No. Brace patterns come from our own config files. | GHSA-f886-m6hf-6m8v, GHSA-jxxr-4gwj-5jf2, GHSA-3jxr-9vmj-r5cp, GHSA-mh99-v99m-4gvg, GHSA-rgw5-rvv9-x895, GHSA-q2hr-2g5m-vwhr, GHSA-qhr7-859c-m2p7, GHSA-6j4f-fj2g-mc7p |
| `vitest`, `@vitest/mocker` 4.1.0 → 4.1.12 | moderate | direct (dev) | no (tests) | No. These are mock-registration and redirect bugs in the Vitest browser and server mocker; tests run locally against our own code. | GHSA-82fw-gwwq-j7x9, GHSA-qxg6-89mg-rqv8 |
| `postcss-selector-parser` 7.1.1 → 7.1.7 | moderate | transitive: `eslint-plugin-vue` | no (lint) | No. It parses selectors from our own source. | GHSA-w9m9-85wc-3x92, GHSA-rj75-hqrm-r3gf |
| `@humanfs/node` 0.16.7 → 0.16.8 | moderate | transitive: `eslint` | no (lint) | No. ESLint does not do a recursive copy. | GHSA-p498-v437-472g |

`minimatch` also moved 10.2.4 → 10.2.6 (latest 10.x), which does not clear its advisory (see below).

## Left unfixed (moderate only)

Neither of these is reachable here, and neither ships. Each can only be fixed by forcing a version that a parent package's declared range does not allow. That needs an `npm overrides` entry or a major bump, and under `CLAUDE.md` both are decisions for Sam, not something to apply unasked.

1. **`minimatch` <11.0.1 — GHSA-g3hv-75wg-m249 (DoS via globparts amplification).** It accounts for 18 of the 20 audit entries, through `eslint` 10, `@eslint/config-array`, `@typescript-eslint/*`, `typescript-eslint`, `eslint-plugin-vue`, `vue-eslint-parser`, `@vue/eslint-config-typescript`, `@vitest/eslint-plugin`, `eslint-config-prettier`, `editorconfig`, `glob`, `js-beautify`, `@redocly/openapi-core` and `openapi-typescript`.
   - **Fix status:** the only patched release is 11.0.1+, and no backport exists for 5.x, 9.x or 10.x. The parent ranges are `eslint` `^10.2.4`, `@typescript-eslint/typescript-estree` `^10.2.2`, `editorconfig` `^9.0.1`, and `@redocly/openapi-core`, which pins exactly `5.1.9`.
   - **Reachability:** patterns come only from our own ESLint config, `.editorconfig` and the redocly defaults. No user input reaches `minimatch`, and it runs only in lint and codegen.
   - **Recommendation:** accept, and re-check when ESLint or typescript-eslint move to `minimatch` 11. An `overrides` entry forcing `minimatch@11` into parents that declare `^10`/`^9`/`5.1.9` would be a compatibility risk with no security benefit here.
2. **`glob` <14.0.2 — GHSA-3g3m-2fjr-6pw4 (AbortSignal cancellation bypass).** The path is `@vue/test-utils` 2.4.6 → `js-beautify` 1.15.4 → `glob` 10.5.0.
   - **Fix status:** the only patched release is 14.0.2. Raising `@vue/test-utils` to 2.5.1 (in range) moves to `js-beautify` 2, which still uses `glob` `^13`, so it would not clear the advisory.
   - **Reachability:** `@vue/test-utils` uses `js-beautify` only to format HTML strings in `wrapper.html()`. It never globs the filesystem, and no AbortSignal is involved.
   - **Recommendation:** accept, and re-check when `js-beautify` moves to `glob` 14.

## Supply-chain verification

Per `CLAUDE.md` ("Third-Party Dependencies") and the `dependency-check` skill, every target version was checked before the lockfile changed:

- **Registry:** none of the targets is deprecated, and all are the latest release in their major line. Licenses are MIT, BSD-3-Clause (`source-map-js`), Apache-2.0 (`@humanfs/*`) and BlueOak-1.0.0 (`minimatch`). `vue`, `vite`, `vitest`, `postcss`, `nanoid`, `undici`, `js-cookie` and `@redocly/openapi-core` publish with SLSA provenance. None of the target versions has an install script, and the lockfile's install-script packages are the same two as before (`vue-demi`, `fsevents`).
- **Web and OSV:** OSV.dev reports no open advisories against any target except `minimatch` 10.2.6 (above). No 2026 npm compromise campaign names any of these packages; the campaigns checked include axios, TanStack, Mini Shai-Hulud, the keyv/cacheable worm and node-ipc. The GHSA pages for `vue`, `vite`, `undici`, `shell-quote`, `postcss`, `js-yaml`, `js-cookie`, `nanoid`, `vitest`, `@humanfs/node`, `minimatch` and `glob` confirm the patched-in versions.
- **Release-age caution:** `@redocly/openapi-core` was pinned to 1.34.22 (published 2026-10-22) instead of 1.34.23 (published 2026-11-02, one day before this change). 1.34.20+ is the first line that pins the patched `js-yaml` 4.3.2.
- **keyv/cacheable worm (CSA Singapore AD-2026-009):** the malicious versions are `keyv` 6.0.0, `flat-cache` 6.1.24, `file-entry-cache` 11.1.6 and `cacheable` 2.5.1. Our chain is unchanged at `eslint` → `file-entry-cache` 8.0.0 → `flat-cache` 4.0.1 → `keyv` 4.5.4, so it is not affected.

## Other lockfile movement

The update moved 80 lockfile entries. Beyond the packages above:

- `vite` 8.3 brings `rolldown` 1.0.0-rc.15 → 1.2.16 (with its platform bindings) and a direct `lightningcss` 1.33.0 dependency, nested under `vite`. `lightningcss` was already in the tree at 1.32.0 through `@tailwindcss/node`.
- Smaller updates came from the same parents: Babel parser patches, `@vitest/*` siblings, `chai`, `tinyglobby`, `tinyrainbow` and `picomatch`.
- `@humanfs/types` is new, from the same `humanwhocodes/humanfs` repository as `@humanfs/node`.
- `@emnapi/*`, `@napi-rs/wasm-runtime`, `@tybys/wasm-util` and `@rolldown/binding-wasm32-wasi` were dropped.

`package.json` changed only `vite` `^8.0.8` → `^8.3.5` and `vitest` `^4.0.18` → `^4.1.12`. These raise the floors to the patched versions so a regenerated lockfile cannot resolve back to vulnerable ones, and npm also restored the missing indentation on the `vitest` line.

## Config changes needed by Vite 8.3

Vite 8.3 warns at config load about patterns that its native config loader (planned as the default in a future major) does not support. The project's tests must produce clean output, so the patterns were fixed instead of silenced with `VITE_CONFIG_NATIVE_IGNORE_WARNING`:

- `web/vite.config.ts`: `__dirname` → `import.meta.dirname`.
- `web/vitest.config.ts`: `import './vite.config'` → `import './vite.config.ts'`.
- `web/tsconfig.node.json`: `allowImportingTsExtensions: true`, which is valid because that config already sets `noEmit: true`.

## Tooling problems hit (and how they were worked around)

- **`npm audit fix` refuses to run (ERESOLVE).** It tries to move `@vitest/eslint-plugin` to 1.6.28, which declares an optional peer of `typescript >=6.0.0`, and the project pins `typescript ~5.9.3`. Until TypeScript moves to 6, use targeted `npm update <pkg>` instead of `npm audit fix`.
- **npm 11.4.2 crashes updating `vite` or `vitest`** with `Cannot read properties of null (reading 'edgesOut')` in arborist `#loadPeerSet`. The crash starts at `@vitest/eslint-plugin`'s optional peer `vitest: "*"`, which resolves to `vitest` 5.1.0, whose optional `@vitest/browser-*` peers send arborist into a nested peer set with a null parent. npm 11.21.1 (`npx npm@11.21.1 install ...`) handles the same request correctly. The resulting lockfile installs cleanly with `npm ci` on npm 11.4.2, and CI uses Node 24's bundled npm. Developers who hit this should upgrade their global npm.

## Follow-ups (not done here)

- **`npm-run-all2` 8.x has had no release since 2025-05-25.** 9.x is active (9.0.4, 2026-10-21) but is a major bump: ESM-only, requiring Node `^22.22.2 || ^24.15.0 || >=26`. That needs Sam's approval and a Node-floor check.
- **TypeScript 5.9 → 6.** This blocks `@vitest/eslint-plugin` ≥1.6.28 and so blocks `npm audit fix`. It is a major bump that needs its own change.
- Re-check `minimatch` and `glob` when ESLint/typescript-eslint adopt `minimatch` 11 and `js-beautify` adopts `glob` 14.

## Verification

All of these ran in `web/` after the change; the full output is clean, with no warnings:

- `npm run type-check`: passed
- `npm run test:unit -- --run --testTimeout=30000`: 32 files and 430 tests passed
- `npm run lint`: oxlint reported 0 warnings and 0 errors; eslint was clean
- `npm run build`: built
- `npm ci` with npm 11.4.2 against the new lockfile: succeeded, lockfile unchanged
- `npm audit`: 20 moderate, 0 high, 0 critical
