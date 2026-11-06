# Serve no longer hangs on auto-migrate; migrate no longer needs the JWT secret

## What was built

- `autoMigrate` returns: every `cvert-ops serve` start used to block forever before listening.
- `cvert-ops migrate` reads only `DATABASE_URL` and `DATABASE_URL_MIGRATE` (`config.LoadMigration`), so the one-shot `migrate` container starts without `JWT_SECRET`.
- `testutil.TestDB.URL` and an exported `testutil.OwnerOption`, for tests that need their own connection or container.

## Key decisions

- The explicit `pg_advisory_unlock` is gone. `autoMigrate` caps the pool at one connection, and golang-migrate's Postgres driver pins that connection until the driver closes, so the unlock waited for a connection that could never come back. A goroutine dump of the running container showed the main goroutine parked at the unlock in `database/sql.(*DB).conn`.
- `migrateUp` now closes the migrator, which ends the session. The advisory lock is session-scoped, so that is what releases it.

## Gotchas

- `TestAutoMigrate_InvalidURL_ReturnsError` could not catch this: it fails at the ping. Nothing ran `autoMigrate` against a real database until this change. The new test does, and asserts the lock is free afterwards.

## Quality checks

- `go test ./cmd/cvert-ops/ ./internal/config/ ./internal/testutil/`, `go vet ./...`, and `golangci-lint` on the changed packages pass. The new test failed by timeout before the fix.
- Full suite not run: Sam asked for full runs only when really needed while the machine is under test load.
