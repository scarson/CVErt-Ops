# Web SPA Toolchain Majors — TypeScript 6, npm-run-all2 9 (2026-11-03)

Took the two major bumps that the npm audit triage left as follow-ups, both approved by Sam. The full record, including the TypeScript 7 assessment, is the "Follow-up: TypeScript 6 and npm-run-all2 9" section of `dev/2026-11-03-web-npm-audit-triage.md`.

| Area | Files | Change |
|------|-------|--------|
| Manifest | `web/package.json` | `typescript` `~6.0.3`, `npm-run-all2` `^9.0.4`, `engines.node` `^24.15.0 \|\| >=26.0.0`, `overrides` letting `openapi-typescript` accept the root `typescript` |
| Lockfile | `web/package-lock.json` | `typescript` 6.0.3, `npm-run-all2` 9.0.4 and its dependencies (`pidtree` 1, `read-package-json-fast` 6, `which` 7, ...); nothing else moved |

## Key implementation decisions

- **No TypeScript 7, no 6 + 7 side-by-side install**: `vue-tsc` (Volar) and `typescript-eslint` need the 6.0 API, and `tsc` 7.0.2 reports `TS2307` on every `.vue` import, so it could only check the build config files. Revisit when 7.1 is stable and both tools support it.
- **`overrides` for `openapi-typescript`**: its latest release (7.13.0) declares peer `typescript ^5.x`, which makes `npm ci` fail with ERESOLVE. Codegen output is byte-identical under 6.0.3. Remove the override when upstream widens the peer range (openapi-ts/openapi-typescript#2723).
- **Node floor raised to `npm-run-all2` 9's range**, without the Node 22 branch.
- **`npm audit fix` still not applied**: it clears no advisory and would move ESLint's cache chain to versions one release below the keyv/cacheable worm's compromised ones.

## Gotchas discovered

- `npm install` only warns about the `openapi-typescript` peer conflict; `npm ci` fails on it. Check `npm ci` after any peer-range change.
- Piping `npm ci` into `head` kills the install partway through and leaves a broken tree (`npm ls` then shows `typescript@` with no version).
- npm 11.19.1 (bundled with Node 24.22.2) warns about `vue-demi`'s postinstall not being covered by `allowScripts`.

## Quality checks

- With Node 24.22.2, from cold caches: `npm run type-check`, `npm run test:unit -- --run --testTimeout=30000` (430 tests), `npm run lint`, `npm run build`: all pass with clean output.
- `npm ci` succeeds on npm 11.19.1 and 11.4.2; `npm run generate-api` output unchanged; `npm audit` unchanged (20 moderate).
- Go suite not run (no Go changes).
