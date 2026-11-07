# Postgres TLS wrapper executable

## What was built

- `docker/postgres-tls/docker-entrypoint-wrapper.sh` is stored with mode `100755`. `docker/compose.yml` runs it as the Postgres container's entrypoint, so the container cannot start unless the file is executable.

## Key decisions

- Changed only the git file mode. `generate-cert.sh` stays `100644`, because the docs and `docker/smoke-test.sh` run it with `bash`, not directly.

## Gotchas

- Docker Desktop on Windows mounts bind-mounted files as `0755`, so the missing executable bit had no effect on Windows hosts. On Linux the mount keeps the checkout's `0644`, and the container fails with `exec: "/usr/local/bin/tls-entrypoint.sh": permission denied`.
- The file has been `100644` since it was added on 2026-03-06. The production Compose smoke job, added to `dev` on 2026-11-06, first ran on Linux in CI run 42416129653 (draft PR 182 to `main`) and failed with that error. CI runs only on PRs to `main`, so `dev` had not run the job before.

## Quality checks

- `git ls-tree` shows the file as `100755`.
- The CI smoke job is the test for this change. It runs on a draft PR to `main` from this branch.
