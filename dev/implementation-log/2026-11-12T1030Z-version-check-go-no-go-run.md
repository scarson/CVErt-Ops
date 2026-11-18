# Version check: Phase 4 go/no-go run on the complete ingest

## What was done

Phase 4 Steps 1 to 3 of `dev/plans/2026-11-09-version-check-endpoint-plan.md`, on a copy of the complete Phase 2 ingest. The copy was migrated to version 61 and served by PR #218 at `7dae4bf`. The results are in the plan's Phase 4 notes ("Go/no-go run, 2026-11-12"), and the reasons Sam is asked to decide on are in Discoveries. The Phase 2 session's record of its phase is in the same commit: banner, status row, Deviations, Discoveries, and its Step 5 and Step 6 measurements. Two corrections were made to that record. Its sentence on CPE items and the 50,000-row limit predated the CPE row filter. Its drop candidate, `cve_affected_packages_eco_pkg_idx`, was already dropped by migration 000061.

The headline for design section 13: every product's current release answers `cannot_evaluate`, and nothing is Affected. That covers Node `26.13.1`, PHP `8.5.12`, .NET SDK `10.0.404`, nginx `1.31.7`, OpenSSL `4.0.4` and PostgreSQL `18.6`. The six releases have 338 cannot-evaluate advisories:

| Reason | Advisories |
|---|---|
| `cna_indeterminate` | 166 |
| `cna_cannot_clear` | 117 |
| `cna_name_uncertain` | 48 |
| `no_version_bounds` | 4 |
| `invalid_range` | 3 |

The acceptance examples pass. Step 4, the report to Sam, follows this commit; Steps 5 and 6 wait for his decision.

## Decisions and gotchas

- **Choosing "current" from NVD gave versions that are not current.** The CNAs publish fixes NVD has not yet analysed: Node `26.12.1`, the highest NVD fix, is Affected by 15 Node CNA advisories fixed in `26.13.1`. Each current version was instead found by stepping to the highest same-line `fixed_version` the endpoint reported until none was Affected (plan, Deviations).
- **.NET runtime and SDK versions share one product.** Microsoft's CNA does this, and so does NVD's `microsoft:.net`. A runtime version such as `10.0.15` therefore falls inside SDK ranges such as `[10.0.0, 10.0.403)`, and so answers Affected. An advisory with both kinds of range reports no `fixed_version`.
- **The copy had to be migrated.** At version 59 the copy kept the CPE index on the whole value, while the statement at `7dae4bf` compares `left(cpe_normalized, 512)`. Measuring there would have timed a full table scan.
- **The first full copy failed partway.** Docker Desktop was quit twice during the copy (09:17Z and 09:40Z), and the restore was in progress at the second quit. The dump had finished before it, so the copy script gained a `-ReuseDump` switch and restored from the dump left in the container. The kept ingest database came back healthy and not in recovery.
- **The endpoint's per-org rate limit refused the search for current versions after 13 quick requests.** The cost and JIT probes were spaced 6 to 8 seconds apart.
- **JIT was compared with an overlay build** whose check snapshot sets `jit = on`. Allocations were identical, and JIT on was never faster.

## Quality checks

- Full suite: `go test ./... -count=1 -timeout=600s` passed at `7dae4bf` (39 packages, 0 failures, 109 s), run in a worktree pinned to that commit.
- Acceptance: pass (plan, Phase 4 notes).
- This commit changes only the plan and this log; no code.
