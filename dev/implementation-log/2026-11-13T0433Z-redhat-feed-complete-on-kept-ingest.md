# Kept ingest: Red Hat feed complete, proposal figures re-taken

## What was done

- The kept full ingest's worker was restarted, between jobs, on a build of `dev` at `2ec711d`. That build includes the Red Hat cursor's `caught_up` flag and the rule that distros whose feeds list fixes only are never cleared.
- The Red Hat feed finished its walk at 2026-11-13T04:32Z. Its cursor reads `{"caught_up": true, "after_date": "2026-11-13"}`, it stores 66,621 CVEs, and the worker log has no errors. Red Hat's list API has 670 pages of 100, the last holding 40.
- The figures in `dev/plans/2026-11-13-redhat-unfixed-package-states-proposal.md` were re-taken on the complete feed:
  - `package_state` holds 471,019 entries;
  - RHEL 8 to 10 have 46,258 unfixed entries and 773 under investigation;
  - the RHEL 9 binary-to-source map is unchanged at 4,410 of 4,885 names.
  
  So the 400 unmapped names are not missing data, and the proposal no longer says they partly were.

## Decisions and gotchas

- The restart waited for a moment with no running job, so no job was cut off. A job left `running` blocks the feed's next job until stale recovery (12 minutes).
- The previous worker's log was kept as `worker-c8d0cd7.log` before the restart.
- In PowerShell, `... | Tee-Object file | Select-Object -First N` stops the pipeline after N lines, so the file holds only those lines. One log had to be re-taken.

## Quality checks

- Documentation only; no code changed.
