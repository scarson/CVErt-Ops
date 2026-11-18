# Web SPA Dependency Audit — npm Advisories (2026-11-03)

Cleared the critical and all high `npm audit` advisories in `web/` with in-range lockfile updates. Full triage, reachability per advisory, and the supply-chain checks: `dev/2026-11-03-web-npm-audit-triage.md`.

| Area | Files | Change |
|------|-------|--------|
| Lockfile | `web/package-lock.json` | `vue` 3.5.44, `vite` 8.3.5, `vitest` 4.1.12, `postcss` 8.5.32, `nanoid` 3.3.20, `source-map-js` 1.2.2, `shell-quote` 1.12.0, `undici` 7.30.1, `js-yaml` 4.3.2 (via `@redocly/openapi-core` 1.34.22), `brace-expansion`, `postcss-selector-parser`, `@humanfs/node`, `js-cookie` |
| Manifest | `web/package.json` | `vite` floor `^8.3.5`, `vitest` floor `^4.1.12` so a regenerated lock cannot resolve to vulnerable versions |
| Vite config | `web/vite.config.ts`, `web/vitest.config.ts`, `web/tsconfig.node.json` | `import.meta.dirname` and an explicit `.ts` import, clearing the Vite 8.3 native-config-loader warning |

## Key implementation decisions

- **No `npm audit fix --force`**: its suggestions were downgrades (`openapi-typescript` 6.7.6, `@vue/eslint-config-typescript` 4.0.0).
- **`@redocly/openapi-core` pinned to 1.34.22, not 1.34.23**: 1.34.23 was one day old.
- **20 moderates left**: `minimatch` <11 and `glob` <14.0.2, lint/test tooling only, not reachable, and no patched release fits the parents' ranges. Sam accepted them until upstream moves; no `overrides`.

## Gotchas discovered

- `npm audit fix` fails with ERESOLVE: it wants `@vitest/eslint-plugin` 1.6.28, which needs TypeScript ≥6.
- npm 11.4.2 crashes (`reading 'edgesOut'`) when updating `vite` or `vitest`; npm 11.21.1 via `npx` works, and its lockfile installs with npm 11.4.2.

## Quality checks

- `npm run type-check`, `npm run test:unit -- --run --testTimeout=30000` (430 tests), `npm run lint`, `npm run build`: all pass with clean output.
- `npm audit`: 20 moderate, 0 high, 0 critical (was 24 / 10 / 1).
- Go suite not run (no Go changes).
