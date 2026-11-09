# Scrub channel secrets from audit history

## What was built

- Migration `000056_scrub_channel_headers_from_audit_log` masks `old_state` and `new_state` on existing `audit_log` rows with `entity_type = 'channel'`.
- `audit.RedactChannelConfig` is now an allowlist. `url` is reduced to scheme and host, header maps keep names with masked values, and `recipients` shows only when it is a list of strings containing `@`. The value of any other key is masked whole.
- `headers` is treated like `custom_headers`, because `POST .../channels/{id}/test` read that key until 2026-11-02 and stored configs may hold credentials under it.
- `channelAuditState` merges the masked config, and a config key can no longer replace the channel's `name` or `type` in audit state.
- `redactSecrets` follows lists, which also covers non-channel entity types.
- `resolveMaskedChannelConfig` rejects a masked value inside a list, because a list element has no key to restore from, and keeps JSON numbers exact.

## Key decisions

- **Allowlist instead of more keyword rules.** `config` accepts arbitrary keys and delivery reads only `url`, `custom_headers` and `recipients`. Keyword matching cannot cover names or nesting nobody anticipated, and masking the rest loses nothing delivery uses.
- **A one-time owner migration is compatible with the audit table's restrictions.** `cvert_ops_app` has `SELECT, INSERT, DELETE` on `audit_log` and no `UPDATE`, so the application still cannot edit history. There is no trigger, and retention already deletes rows. Nothing states the table is tamper-evident.
- **The scrub cannot be undone.** The down migration is a no-op.
- **`name` is kept in old rows only when it looks genuine.** It must match `entity_name`, or for `old_state`, `new_state` must match `entity_name`, which is how a rename looks. Masking every `name` that differs would erase real rename history. A config `name` removed in the same update that a record shows looks like a rename and stays.

## Gotchas

- golang-migrate runs with `MultiStatementEnabled` and splits a file on every semicolon, including inside comments and function bodies. Each piece runs in autocommit, so `SET LOCAL` has no effect on later statements. The migration uses session `SET` and `RESET`.
- With `FORCE ROW LEVEL SECURITY`, an owner that is not a superuser updates zero rows without `app.bypass_rls`, and reports success. The test runs as such an owner, and it fails when the setting is removed.
- The org rate limit allows a burst of 10 requests on the free tier. `newChannelRedactionFixture` uses 6, so each test using it has room for 4 more.

## Quality checks

- Each new test failed before its fix.
- `go test ./migrations/ ./internal/audit/ ./internal/api/ -count=1 -timeout=590s` with `TESTCONTAINERS_RYUK_DISABLED=true`: pass.
- `golangci-lint run ./migrations/ ./internal/audit/ ./internal/api/`: 0 issues.
- Three Codex review rounds, reading code only. Round 1 reported 4 findings and round 2 reported 3, all confirmed and fixed here. Round 3 reported none, with its brief narrowed to exclude a value deliberately placed in a field nothing reads, in a shape the masking already covers.
- The full `go test ./...` suite was not run.
