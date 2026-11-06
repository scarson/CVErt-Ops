# API keys, audit and feed state work under production database settings

## What was built

- Migration 000051 changes all 27 RLS policies to `org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid`.
- The default query mode is `cache_describe`, replacing `simple_protocol`, which `DB_QUERY_EXEC_MODE` now rejects at startup. `extended_protocol` remains for direct connections.
- `testutil.NewTestDB` pools use `store.DefaultQueryExecMode`, so the suite encodes parameters the way a deployment does.
- `TestRLS_EveryPolicyFailsClosedOnSessionWithEmptyOrgSetting` sweeps every table with RLS as the app role on one session. `docker/smoke-test.sh` now runs an API key flow and fails if the app logged an error.

## Key decisions

- This reverses the simple protocol decision in PLAN §19.2 and pitfall API-7, both updated. pgx documents that simple protocol encodes `[]byte` as `bytea` and that `string` must be used for `json` and `jsonb`. 111 tests failed when the test pools ran in that mode, across feed sync state, audit, security events, notifications and alert evaluation.
- `cache_describe` over fixing call sites: it keeps every `json.RawMessage` argument working and needs no change at each site. Registering `[]byte` as `jsonb` was not an option, because `token_hash` columns are real `bytea`.
- `cache_describe` over `describe_exec`: one round trip after the first execution of a statement on a connection, rather than two every time.
- PgBouncer compatibility comes from the pgx source: `execParams` sends the SQL with each execution as an unnamed statement. Not tested against a real PgBouncer.

## Gotchas

- After `SET LOCAL app.org_id`, the session's value is `''`, not NULL. `''::uuid` raises an error at planning time, so `app.bypass_rls = 'on'` does not avoid it. This is pitfall ARCH-45.
- Neither bug could fail in the test suite as it stood: `TestDB.Store` connects as a superuser, which skips RLS, and the test pools used pgx's default query mode. Both appeared the first time a client called the real stack with an API key.
- `cache_describe` caches statement descriptions per connection, so a schema change under a running binary can cause decode errors until its connections recycle. Migrations run before the app starts, in both Compose and `serve`.
- A `.env` still holding `DB_QUERY_EXEC_MODE=simple_protocol` now stops the app at startup with a message naming the valid values.

## Quality checks

- `go test ./cmd/... ./internal/... ./docker/... ./migrations/...`: 35 packages pass. The new RLS tests failed before the migration.
- `docker/smoke-test.sh` passes on fresh volumes. A typed `openapi-typescript` client against a fresh stack: API key reads and writes succeed, a key on an admin route gets 403, and the app logs no errors.
- Not run: the web suite, unaffected here.
