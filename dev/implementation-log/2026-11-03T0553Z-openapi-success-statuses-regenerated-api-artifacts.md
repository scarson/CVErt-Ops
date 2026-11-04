# OpenAPI Success Statuses + Regenerated API Artifacts

> **Date:** 2026-11-02
> **Branch:** `claude/openapi-statuses-and-artifacts-712d84` (cut from `fix/openapi-async-status`, which documents the 202 endpoints)

## What was built

| Change | Files | Description |
|---|---|---|
| 201 Created documented on create endpoints | `internal/api/openapi_spec.go` | `DefaultStatus: http.StatusCreated` on the 9 spec-only create operations whose Chi handlers answer 201 with a Location header: orgs, API keys, channels, groups, reports, saved searches, SSO, watchlists, watchlist items. huma had documented 200 for each. |
| Status regression table | `internal/api/openapi_test.go` | `TestOpenAPISpec_SuccessStatusMatchesHandler` now covers every 201, 202 and 204 operation in the spec (35 operations, 36 success responses: alert-rule create documents both 201 and 202), including the huma-native `/auth/register` (201) and `DELETE /auth/mfa/methods/{method}` (204). A `noBody` flag asserts that 204 responses document no body. |
| Regenerated spec | `openapi.json` | Last regenerated 2026-03-16 (`df7ec56`). Adds 11 paths (`/auth/mfa/*`, `/admin/reload-config`, `/admin/security-events`) and 23 component schemas; removes 3. |
| Regenerated frontend types | `web/src/lib/api/schema.d.ts` | `npm run generate-api` from the new spec. |
| Test fixtures | `web/src/{components,router,stores,views}/__tests__/*.test.ts` | 27 `/auth/me` fixtures gain `force_password_reset: false`, now a required field of the response type. Type-only; no behaviour change. |

## Key implementation decisions

- **204 endpoints needed no spec change** — huma documents 204 by default for an operation whose output has no `Body` field, and the 19 documented Chi operations whose handlers answer 204 already declare body-less outputs. They are in the test table to guard against a `Body` being added later. Further 201/204 handlers sit on routes with no spec operation (MFA-requirement set and removal, SCIM config create and delete, SCIM v2 users and groups) and are not covered; see the gotcha below.
- **Removed schemas are renames, not lost endpoints** — `UpdateMemberRoleBody` and `UpdateMemberRoleResponseBody` became `PatchMemberBody` and `PatchMemberResponseBody` when member PATCH gained `active` and `scim_exempt` (`d7e4774`); `SavedSearchExecuteResponse` became `ListResponseCVEItem` when saved-search execute moved to `writeList` (`055b1d0`).

## Gotchas discovered

- **Chi routes with no spec operation** — `/orgs/{org_id}/members/{user_id}/{reset-mfa,force-password-reset,require-mfa}`, `/orgs/{org_id}/mfa-settings`, `/orgs/{org_id}/sso/scim*`, `/orgs/{org_id}/sso/link`, the OAuth/OIDC redirect routes and the SCIM v2 protocol routes (`/orgs/{org_id}/scim/v2/*`) are not in `openapi.json`, so the success-status check cannot cover them.
- **vitest timeouts under load** — with other sessions and Docker running, 7-9 web unit tests time out at the 5 s default (a different set each run); all 430 pass with `--testTimeout=30000`.

## Quality checks

- **Tests:** `TestOpenAPISpec*` pass; failed first with 9 create endpoints documenting 200
- **Frontend:** `npm run type-check` clean, `npm run lint` clean, `vitest run` 430/430 (with 30 s timeout)
- **Code review:** codex (gpt-6.1-sol, high) — no contract defects; regenerated both artifacts in scratch byte-for-byte identical; two low findings on this entry's coverage counts (fixed)
