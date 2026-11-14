# Give the Compose Postgres 256 MB of /dev/shm

## What was built

| Feature | Files | Description |
|---|---|---|
| Shared memory size | `docker/compose.yml` | The `postgres` service sets `shm_size: 256mb`. The production overlay (`docker/compose.prod.yml`) inherits it. |
| Render test | `docker/compose_test.go` (`TestPostgresGetsSharedMemoryForParallelQueries`) | Renders the development and production stacks with `docker compose config`. It requires `shm_size` to be exactly 256 MiB, and no more than half of the Postgres memory limit where the stack sets one. |
| Operator docs | `docs/deployment/production.md` | New section "PostgreSQL Shared Memory": what `/dev/shm` holds, why 64 MB fails, how it counts against the memory limit, and what to set when Postgres runs in the operator's own container. |
| Plan record | `dev/plans/2026-11-13-product-match-rules-plan.md` | Discoveries records the fix. |

## Key decisions

- **Why still fix it after parallel query was turned off for rule statements.** `SET LOCAL max_parallel_workers_per_gather = 0` applies only to rule statements: the evaluator, saved searches and AI search. Search, facets, reports and list endpoints still run with the server default of 2 workers. Their parallel hashes and bitmap scans share the same 64 MB, and nobody measured them on the full corpus. Sam approved the change on 2026-11-14.
- **256 MB.** `/dev/shm` is a tmpfs, and its pages are charged to the container's memory cgroup only while they are in use, so the size is a ceiling, not a reservation. The production overlay's 1 GB limit leaves room for the documented 256 MB `shared_buffers` and a full 256 MB `/dev/shm`. The test's half-of-limit check keeps a later change to either value from making the two compete.

## Gotchas discovered

- `docker compose config --format json` renders `shm_size` and `deploy.resources.limits.memory` as byte counts in JSON strings (`"268435456"`), not numbers.

## Quality checks

- `TestPostgresGetsSharedMemoryForParallelQueries` failed first in both stacks (`shm_size` rendered empty), then passed. `go test ./docker/ -count=1`: pass.
