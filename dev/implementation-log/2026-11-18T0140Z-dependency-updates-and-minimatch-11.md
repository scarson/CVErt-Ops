# Dependency updates and minimatch 11

## What was built

| Change | Files | Description |
|---|---|---|
| Go security updates | `go.mod`, `go.sum` | `go-jose/v4` 4.1.4 → 4.1.6 (GHSA-mgcc-cww5-fp2q, GHSA-vvm8-gf78-28g4, GHSA-4w3g-jfj2-cw2q) and `otel/trace` 1.44.0 → 1.47.0 (GHSA-q7gw-24fr-5p69), with `otel` and `otel/metric` moved to the same version; `otel/log` 1.47.0 comes in as an indirect module. These were the open dependabot pull requests 257 and 240, which targeted `main`. |
| Routine Go updates | `go.mod`, `go.sum` | `golang.org/x/time` 0.15.0 → 0.16.0 (dependabot 269). `automemlimit` 0.7.5 → 1.0.2 (dependabot 270 proposed 1.0.1). |
| npm updates | `web/package.json`, `web/package-lock.json` | `@vitest/eslint-plugin` 1.6.13 → 1.6.28 (dependabot 271). `eslint` 10.1.0 → 10.15.0 and typescript-eslint 8.58 → 8.73, whose new releases require minimatch 11. |
| minimatch 11 everywhere it was vulnerable | `web/package.json` `overrides` | GHSA-g3hv-75wg-m249 (denial of service through glob-pattern amplification) affects minimatch 7.0.0 up to 11.0.1. After the eslint upgrade, the remaining vulnerable copies were js-beautify's `editorconfig` and `glob` (via `@vue/test-utils`), which pin minimatch 9; even the newest js-beautify pins `~10.2.4`. Overrides scoped to `js-beautify` move both to minimatch `^11.0.9`. |

## Key decisions

- **automemlimit 1.x keeps the blank-import behavior.** `cmd/cvert-ops/main.go` uses `import _ "github.com/KimMachineGun/automemlimit"`. In 1.0.2 its `init` calls `memlimit.Set` with the defaults 0.x used: 90% of the cgroup limit from `FromCgroup`, a non-empty `GOMEMLIMIT` skips it, and `AUTOMEMLIMIT` sets the ratio or `off`. 1.0.2 also treats an empty `GOMEMLIMIT` as unset. With no cgroup limit, 1.x sets `GOMEMLIMIT` to `math.MaxInt64`, which is Go's default. The repository is active (last push 2026-11-16) and not archived.
- **Overrides are scoped, not global.** A top-level `minimatch` override would also move `@redocly/openapi-core` (via `openapi-typescript`), which pins minimatch 5.1.9 exactly, is outside the vulnerable range, and calls the default-export API that minimatch 10 removed. `editorconfig` 1.0.7 uses `Minimatch`, and `glob` 10.5.0 uses `Minimatch`, `GLOBSTAR`, `escape` and `unescape`; minimatch 11 exports all four.
- **Lockfile entries removed by hand.** `npm install` kept the locked nested 9.0.9 copies after the override was added. Deleting `node_modules/editorconfig/node_modules/minimatch` and `node_modules/glob/node_modules/minimatch` from `package-lock.json` made npm resolve them to the deduplicated 11.0.9.

## Gotchas discovered

- `npm ls minimatch` reports the deduplicated copy under `glob` as `invalid: "^11.0.9"` although its version satisfies the range. `npm ci` succeeds, so it is a reporting problem in `npm ls` with overrides on deduplicated packages, not a broken install.
- Dependabot security updates open against the default branch (`main`) regardless of `target-branch: dev` in `.github/dependabot.yml`, and alerts are evaluated against `main`. With `main` behind `dev`, most open alerts were already fixed on `dev`.
- CI (`.github/workflows/ci.yml`) runs only on pull requests to `main` and pushes to `main`, so dependabot pull requests to `dev` get CodeQL and nothing else; they must be tested locally.

## Not addressed

- `npm audit` also reports picomatch ReDoS (all versions, no fixed release yet) through vite, vitest, typescript-eslint, vue-tsc and others, and glob below 14.0.2 (AbortSignal cancellation bypass) through js-beautify. Neither is in GitHub's dependabot alerts. Both are in build and test tooling only.

## Quality checks

- `npm ci`: succeeds. `npm run lint`: 0 warnings; `--fix` changed no files. `npm run type-check`: clean. `vitest run`: 540 of 540 pass. `npm run build`: succeeds.
- `go build ./...`: succeeds. `golangci-lint run --allow-parallel-runners`: 0 issues.
- `go test ./... -count=1 -timeout=600s`: see the pull request.
