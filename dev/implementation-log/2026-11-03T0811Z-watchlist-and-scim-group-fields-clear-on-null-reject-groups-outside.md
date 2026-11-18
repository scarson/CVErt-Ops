# Watchlist and SCIM Group Fields — Clear on Null, Reject Groups Outside the Org

> **Date:** 2026-11-03
> **Branch:** `fix/watchlist-group-clear`

## What was built

| Part | Files | Description |
|---|---|---|
| `clearableField[T]` | `internal/api/contract.go` | PATCH field type whose `UnmarshalJSON` sets `Sent`; `Value` is nil for JSON `null`. Its huma `Schema` documents the value type as nullable |
| Watchlist group clear | `internal/api/watchlists.go` | `patchWatchlistBody.GroupID` is a `clearableField[string]`; `group_id: null` removes the watchlist from its group |
| SCIM group mapping clear | `internal/api/scim_admin.go` | `patchSCIMGroupMappingBody.MappedGroupID` is a `clearableField[uuid.UUID]`; `mapped_group_id: null` clears the mapping and removes the SCIM group's members from the notification group |
| Group ownership check | `internal/api/watchlists.go` | `resolveWatchlistGroup` requires an active group in the org for `group_id` on create and PATCH; otherwise 422 |
| Spec | `openapi.json`, `web/src/lib/api/schema.d.ts` | `group_id` and `mapped_group_id` are `string \| null` |

## Key implementation decisions

- **A struct with `UnmarshalJSON` instead of a double pointer.** `encoding/json` decodes JSON `null` into a `**string` by setting the outer pointer to nil, the same as an omitted key. A type that implements `json.Unmarshaler` is called for every key present in the input, including `null`, so it can record presence.
- **Only these two fields.** The other nullable PATCH fields already have a clear path: report `severity_threshold`, SCIM `mapped_role` and the description fields clear or reset with `""`. A UUID field cannot take `""`.
- **The SCIM handler needed no logic change.** It already removed members from the old notification group when the mapping changed and treated a nil mapping as cleared; only the decoding never produced that case.

## Gotchas discovered

- **Postgres runs foreign-key checks without RLS.** `watchlists.group_id REFERENCES groups(id)` accepted another org's group, so a member could attach a watchlist to it. A deleted (soft-deleted) group was also accepted, and an unknown group returned a 500 from the foreign-key violation. Any other org-scoped column that references another org-scoped table by `id` alone needs the same handler check.
- **The PostToolUse formatter hook reformats untouched code** in edited Go files (expands one-line struct types, removes double blank lines and a trailing blank line). Those hunks were reverted so the diff holds only this change.

## Quality checks

- **New tests:** `TestClearableField_Decode`, `TestClearableField_DecodeWrongType`, `TestWatchlist_PatchGroupID`, `TestGroupMapping_ClearNotificationGroup`, `TestOpenAPISpec_PatchClearableFieldsNullable` and `TestWatchlist_GroupMustBelongToOrg` each failed before its fix.
- **Go:** `go test ./internal/api/ -run '^(TestClearableField_|TestOpenAPISpec_Patch|TestWatchlist|TestGroupMapping_)'` passes; golangci-lint: 0 issues on `internal/api`.
- **Frontend:** `generate-api`, `type-check` and `lint` clean.
