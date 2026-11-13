# /auth/me lists only active memberships

## What was done

`GET /auth/me` listed every org the user had ever joined, including those where an admin had deactivated the membership. Every org route refuses a deactivated member with 403, so the SPA offered orgs the user could not open. The `ListUserOrgs` query now also requires `om.deactivated_at IS NULL`. `/auth/me` and `/whoami` are its only callers. `/whoami` already skipped deactivated memberships through its own membership check, which stays, because it also serves API keys.

## Decisions and gotchas

- The SPA has no handling for deactivated orgs (no reference to deactivation in `web/src`), so leaving them out changes nothing it relies on.
- Found while building `/whoami`; it was listed as a follow-up and is fixed here.

## Quality checks

- `TestListUserOrgs_LeavesOutDeactivatedMemberships` (store) failed before the query change, listing both orgs, and passes after it.
- `TestGetMe_LeavesOutDeactivatedMembership` (API) was written after the fix and passes. It never ran against the old query; the store test covers the change.
- `go test ./internal/store/ -run TestListUserOrgs` and `./internal/api/ -run 'TestGetMe|TestWhoami'`: pass.
