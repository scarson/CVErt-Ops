# Production Compose stack starts and receives its settings

## What was built

- `docker/init-app-role.sh` replaces `docker/init.sql`: the `cvert_ops_app` password comes from `APP_DB_PASSWORD`, and the grant uses `POSTGRES_DB` instead of a fixed name.
- `APP_DB_PASSWORD` is required in `docker/compose.yml`, with no default in any compose file. `.env.example` holds the development value.
- `docker/compose.prod.yml` passes every app setting from `.env` as a bare key. Only Caddy publishes host ports, Postgres sits on `cvert-data-net` alone, and Mailpit moves behind a profile.
- `docker/compose_test.go` and `docker/smoke-test.sh` (CI job `stack-smoke`).
- Deployment docs moved to `docker compose exec` for Postgres, with a new runbook, `docs/deployment/runbooks/app-db-password.md`.

## Key decisions

- Bare keys rather than `env_file`, so `POSTGRES_PASSWORD` and `DATABASE_URL_MIGRATE` stay out of the app container. A Go test fails when a setting the binary reads is missing from the overlay. An unset bare key is not passed, so the app's default applies.
- Passthrough lives only in the overlay, because `.env.example` holds `go run` values such as `SMTP_HOST=localhost` that would break the development container stack.
- `\getenv` in psql, so the password is never on a command line and psql quotes it. The test password contains quotes, a dollar sign and a backslash.

## Gotchas

The stack had never started from a clean checkout. Rendering tests found none of these; only starting it did, which is why `stack-smoke` exists:

- `postgres:18-alpine` refuses a volume at `/var/lib/postgresql/data`. The mount is now `/var/lib/postgresql`. A development volume created under an older image keeps its old data at the volume root, unread; there are no production deployments.
- CRLF working copies on Windows stop mounted scripts (`env: can't execute 'bash\r'`). `.gitattributes` forces LF on `*.sh`.
- The Dockerfile had no frontend stage, so a clean clone failed at `//go:embed all:dist`, and a checkout with a local placeholder shipped the placeholder.
- `generate-cert.sh` failed under Git Bash: `MSYS_NO_PATHCONV` also stopped path conversion for `-keyout`, and `2>/dev/null` hid the error.
- A missing cert file makes Docker create a directory at the bind-mount path, and the script then fails on it. Generate the cert before the first `up`; to recover, remove those directories first.
- `/metrics` on the main port returns 200 from the web UI's fallback page. The smoke test checks for Prometheus content, not the status code.
- A container's `Config.Env` lists an unset bare key with no `=`; the variable is not set at runtime.

## Quality checks

- `go test ./docker/` passes, including the role script against a real Postgres, and failed first against the old compose files.
- `docker/smoke-test.sh` passes on Compose v2.35.1: fresh volumes, `/readyz` through Caddy, the built web UI, app sessions as `cvert_ops_app`, role attributes, and only Caddy publishing ports.
- Not tested: a real public certificate through Caddy, or mail through a real relay.
