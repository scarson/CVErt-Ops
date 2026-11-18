# Channel config secrets masked in API and audit

## What was built

- `channelResponseConfig` in `internal/api/channels.go` masks `config` on every route that returns a channel: create, get, list, patch, `GET .../alert-rules/{id}/channels` and `GET .../reports/{id}/channels`.
- `audit.RedactChannelConfig` is the one definition of the masked view, used by API responses and by audit records. Every `custom_headers` value becomes `[REDACTED]` with header names kept, `url` becomes `scheme://host/***`, and the existing key-name rules (`secret`, `token`, and so on) still apply.
- `resolveMaskedChannelConfig` runs before validation on create and patch. On patch it replaces masked values with the stored values at the same key. On create it rejects them, since nothing is stored.
- `redactSecrets` now masks `custom_headers` for channel entities. Header values were written to `audit_log` in clear text before this.

## Key decisions

- **Masked for every role, admins included.** This matches `signing_secret`, which is shown only at creation. An admin-role API key handed to an agent then has no route to the credential, and the handlers need no role branch.
- **The whole URL path and query are masked, not only query tokens.** Slack, Discord and Teams webhooks carry their secret in the path, and no general rule can tell a secret path from a plain one. This is the rule the audit log already used.
- **A masked value is kept only while the scheme and host are unchanged.** Otherwise a caller could repoint the channel at a host they control, keep the placeholder, and have delivery send the credential there. A changed scheme or host returns 422 until each secret is sent again. The check compares the masked forms of the two URLs, so a port change counts as a new destination too.
- **Placeholders never reach storage.** A masked value with no stored counterpart and a masked URL on another host both return 422.
- **`config` on PATCH still replaces the whole object.** Omitting a header deletes it, as before.

## Gotchas

- `web/src` has no channel screens; only the generated `schema.d.ts` mentions these routes. No client change was needed.
- Audit rows written before this change still hold header values in `old_state` and `new_state`. This change does not rewrite them.
- Delivery errors shown to org members were checked: `notify.ErrorForOrg` withholds transport errors, which can contain the URL.

## Quality checks

- Every test in `internal/api/channels_redaction_test.go` except the fresh-credential move failed before the fix. All pass after it, including a read of each route with a viewer API key and a round-trip edit checked through `notify.ChannelWebhookConfig`.
- `go test ./internal/audit/ ./internal/api/ -count=1 -timeout=590s` with `TESTCONTAINERS_RYUK_DISABLED=true`.
- `golangci-lint run ./internal/api/ ./internal/audit/`: 0 issues.
- `security-review` checklist: no failures in the areas this change touches (tenant isolation, SSRF validation of the resolved URL, input validation, sensitive data exposure).
