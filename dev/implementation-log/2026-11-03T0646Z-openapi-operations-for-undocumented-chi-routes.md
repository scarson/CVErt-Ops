# OpenAPI Operations for Undocumented Chi Routes

> **Date:** 2026-11-03
> **Branch:** `claude/hungry-khayyam-68844e` (cut from `claude/openapi-statuses-and-artifacts-712d84`, which contains `fix/openapi-async-status`; neither was merged into `dev` yet)

## What was built

| Change | Files | Description |
|---|---|---|
| Org MFA administration operations | `internal/api/openapi_spec.go` | `registerOrgMFASpecOps`: member `reset-mfa` and `force-password-reset` (200), `require-mfa` POST (201) and DELETE (204), org `PATCH /mfa-settings` (200). |
| SCIM config operations | `internal/api/openapi_spec.go` | `registerSCIMConfigSpecOps`: `/orgs/{org_id}/sso/scim` POST (201) / GET / PATCH / DELETE (204), `rotate-token`, `groups`, `groups/{id}/mapping`. Reuses the handler DTOs in `scim_admin.go`. |
| SSO identity-link operation | `internal/api/openapi_spec.go` | `GET /orgs/{org_id}/sso/link` documented as 302 Found with a `Location` header and no body. |
| Test coverage | `internal/api/openapi_test.go` | 9 paths added to `expectedPaths`; 5 operations added to `TestOpenAPISpec_SuccessStatusMatchesHandler` (two 201 without Location, two 204, one 302 with Location). |
| Regenerated artifacts | `openapi.json`, `web/src/lib/api/schema.d.ts` | 9 new paths. |

## Key implementation decisions

- **No Location header on the two 201 operations** — `adminRequireMFAHandler` and `createSCIMConfigHandler` do not call `writeLocation`; neither creates a resource with its own URL.
- **OAuth/OIDC redirect routes and SCIM v2 protocol routes left out** — whether they belong in the spec is a decision for Sam.

## Gotchas discovered

- **`/sso/link` errors are plain text** — the handler reports errors with `http.Error` (text/plain), while huma documents the default error as `application/problem+json`.
- **PATCH bodies document optional fields as required** — huma treats a field without `omitempty` as required, so `PatchSCIMConfigBody` and `PatchSCIMGroupMappingBody` (and the existing `PatchSSOBody`, `PatchAlertRuleBody`, `PatchReportBody`, `PatchWatchlistBody`, `PatchChannelBody`) list every field as required.

## Quality checks

- **Tests:** `TestOpenAPISpec` and `TestOpenAPISpec_SuccessStatusMatchesHandler` failed first on the 9 missing paths, then pass; all `OpenAPI|Spec` tests in `internal/api` pass
- **Lint:** `golangci-lint run ./internal/api/...` 0 issues
- **Frontend:** `npm run generate-api`, `npm run type-check` and `npm run lint` clean
