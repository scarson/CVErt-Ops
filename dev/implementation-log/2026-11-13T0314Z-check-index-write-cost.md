# Version check: index write cost measured (Phase 4 Step 6)

## What was done

Phase 4 Step 6 of `dev/plans/2026-11-09-version-check-endpoint-plan.md`: measured how much the four check lookup indexes (migrations 000059 and 000061) slow the merge pipeline, on a copy of the complete ingest. This finishes Phase 4. PR #218 was already merged to `dev` as `d6919bf` (Step 5).

Result: the cost is smaller than the variation between identical runs on this host. Over four alternating runs that re-merged the same week of NVD records (about 12,000 each), the runs with the indexes averaged 2,364 merges per minute and the runs without averaged 2,556. That is about 7% fewer per minute with the indexes, and the fastest and slowest runs of each case overlap. The table is in the plan's Phase 4 notes ("Index write cost"). Design sections 9 and 13 record the result.

## Decisions and gotchas

- **Re-merging unchanged data is a valid write test.** `canonicalize` deletes and re-inserts all child rows of a CVE on every merge, so a copy that already holds the window's data still exercises every index.
- **Merge time is not the job's run time.** NVD fetch time and HTTP 524 retries vary a lot. The rate comes from `cve_raw_payloads.ingested_at` (each merge's transaction start): the sum of the gaps between consecutive NVD rows, leaving out gaps of 5 s or more.
- **Every run restored the same dump**, so no run merged data an earlier run had rewritten, and every run read one fixed NVD window, not "now minus 7 days".
- **Four runs, not two.** The first pair suggested merges took 1.5 times as long with the indexes. A repeat run with the indexes came close to the faster run without them, and a repeat run without them was slower than that. Runs of the same case differed by about 40%, most likely because Docker Desktop on this host is shared with other sessions. The kept Phase 2 worker ran only one 6-second NVD job during the measurements.
- The run script first read single-line psql output with `(...)[0]`, which in PowerShell indexes the string's first character, and ended the first attempt early. That attempt was discarded, and every reported run started from a fresh restore.
- `cvert_phase4` and the dump were dropped afterwards. The kept ingest (`cvert_ops`, its volume, container and worktree) was not changed.

## Quality checks

- Docs-only change; no code changed, so no tests were run for it. Full suite last passed at `453ec86`, the code merged as `d6919bf`.
