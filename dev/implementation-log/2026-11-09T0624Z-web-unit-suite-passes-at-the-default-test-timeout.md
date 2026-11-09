# Web unit suite passes at the default test timeout

> **Date:** 2026-11-09
> **Commits:** `05fe379` on `claude/beautiful-ellis-0879f8`

## What was built

| Feature | Files | Description |
|---|---|---|
| Static component imports in tests | `web/src/views/__tests__/AccountView.test.ts`, and the `ChangePasswordCard`, `MfaSettingsCard`, `ForcedPasswordStep`, `MfaChallengeStep`, `MfaEnrollStep` and `MfaEnrollment` test files under `web/src/components` | Each file imports its component at the top instead of running `await import('../X.vue')` in a helper called from the test body |

## Key implementation decisions

- **Static imports, not a longer timeout** — `testTimeout` stays at the default 5 seconds, so it still catches a test that really hangs. Static imports are resolved during file collection, outside the test timeout.
- **Helpers that no longer await anything are synchronous** — the mount helpers in the `AccountView`, `ChangePasswordCard` and `MfaEnrollment` tests had `await import()` as their only asynchronous step. No assertion changed.

## Gotchas discovered

- **An in-test `import()` is slow only the first time** — later tests in the file get the module from the cache, so the timeout hits the first test in each file. The set of failing files varies with machine load: `AccountView` passed in the baseline run for this change and failed in earlier ones.
- **A timed-out test keeps running** — in `MfaSettingsCard`, the first test finished after the second test's `vi.resetAllMocks()`, so `client.GET` returned `undefined`. That failed the second test and raised an unhandled rejection at `loadStatus`. Treat such a second failure as a consequence of the first.
- **`vi.resetModules` is not used anywhere in `web/src`** — a component imported inside a test was already shared by every test in the file, so moving the import to the top does not change module state between tests.

## Quality checks

- **Baseline, full `npx vitest run` before the change:** 7 of 540 failed with `Test timed out in 5000ms`, 1 unhandled rejection; test-body time 73 s
- **Full `npx vitest run` after the change, three consecutive runs:** 540 of 540 each, no unhandled errors; test-body time 14–18 s
- **`vue-tsc --build`:** clean
- **oxlint and eslint on the changed test directories:** clean
- **Go tests:** not run; no Go code changed
