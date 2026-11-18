# Red Hat feed: a caught-up flag in the cursor, and the kept ingest's feed resumed

## What was done

- **Cursor flag.** The Red Hat adapter's cursor (`internal/feed/redhat`) gains `caught_up`, as the NVD cursor has. It is set when a walk reaches a list page with fewer than 100 entries, and a full page carries forward the value it was given. A cleared cursor starts without it, so a refill can be told apart from a finished walk. The version check does not read Red Hat data yet, so `check.FeedStatuses` does not report this feed. The proposal for reading Red Hat package states (`dev/plans/2026-11-13-redhat-unfixed-package-states-proposal.md`) adds it there when that is built.
- **Kept ingest.**
  - The full-ingest worker had stopped making Red Hat progress at list page 645. The merge of CVE-2006-4339 failed on a reference URL over the btree row limit, which migration 000060 fixes on `dev`, and the feed was in backoff after 14 failures.
  - The worker was stopped while idle and restarted on a build of `dev` at `c8d0cd7`, which migrated `cvert_ops` from version 59 to 61.
  - The feed's backoff was cleared. It resumed from page 645 and passed CVE-2006-4339.

## Decisions and gotchas

- `start-worker.ps1` starts the worker with its stderr redirected to `worker.err.log`, which replaced the previous worker's log. Earlier restarts had kept the old log under a commit-named file first. The database was not affected.
- A verified full dump of the kept ingest from 2026-11-12 exists (see the kept-data README), so the migration had a restore point.

## Quality checks

- `go test ./internal/feed/redhat/ ./internal/ingest/`: pass. The new assertions failed to compile before the field existed.
- `golangci-lint run --allow-parallel-runners ./internal/feed/redhat/...`: 0 issues.
