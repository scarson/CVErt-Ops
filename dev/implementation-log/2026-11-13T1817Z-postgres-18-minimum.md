# PostgreSQL 18 is the oldest supported version

## What was done

Sam asked to run on the latest PostgreSQL rather than four major versions behind. The documented minimum was "PostgreSQL 15+" in `CLAUDE.md`, `AGENTS.md`, `README.md` (stack table and requirements) and `PLAN.md` (stack table and deployment section). Every place that runs a server already used `postgres:18-alpine`: both Compose files, `internal/testutil`, the API smoke test, and the Ryuk crash helper. Those six documentation lines now say 18+.

The MATCH-2 design (`dev/plans/2026-11-13-product-match-rules-design.md`) had a section 13 step to repeat its measurements on PostgreSQL 15, because its no-ecosystem package query relies on btree skip scan, which arrived in PostgreSQL 18. With 18 as the minimum, that step is removed, the section 2 and section 5.3 wording states that every supported server has skip scan, and the condition for revisiting the no-ecosystem package decision is the section 13 measurement on the kept ingest. The handoff (`dev/plans/2026-11-13-product-match-rules-handoff.md`) drops the PostgreSQL 15 measurement from the implementation plan brief. The review records under `dev/plans/reviews/` are left as written.

## Decisions and gotchas

- **Not PostgreSQL 19 yet.** On 2026-11-13, 19 RC 2 is the newest build (released 2026-11-12), and general availability is planned for 2026-11-19 (postgresql.org RC 1 announcement). 18.7 is the newest stable release. Moving the images to 19 waits for its release.
- **Nothing in the code checks the server version**, so the minimum is documentation only. Nothing known breaks on 15 to 17; the MATCH-2 query would be slower there.
- **Historical plans keep "PostgreSQL 15+"** in their tech-stack headers; they record what was true when written.

## Quality checks

Docs only; no tests run.
