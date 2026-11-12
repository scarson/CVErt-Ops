# Version check: the go/no-go decision recorded and re-measured

## What was done

The plan (`dev/plans/2026-11-09-version-check-endpoint-plan.md`) now records the decision on Phase 4 Step 4, the roll-up change built in `0241f0d` (`2026-11-12T1336Z-check-unresolved-status-and-ubuntu-streams.md`), and its re-measurement on the copy of the complete ingest.

- Status table, Overall line and the Phase 4 banner.
- A Deviation for the decision: Sam delegated it to two independent reviews, whose consensus changed the design.
- Discoveries from the review measurements:
  - the nginx and Node CPE spellings the name table lacked;
  - the Ubuntu Pro sub-streams;
  - what the 48 `cna_name_uncertain` and 117 `cna_cannot_clear` advisories were.
- Phase 4 notes "After the roll-up change": every current release now answers `unresolved`, except the .NET SDK (`sdk_version_not_comparable`). nginx's `cna_cannot_clear` fell from 27 to 2, OpenSSL's `cna_indeterminate` from 85 to 43, and nginx `1.29.3` gained 2 Affected advisories that NVD files under `f5:nginx_open_source`. Acceptance passes.

## Decisions and gotchas

Three earlier figures were corrected:

- **Ubuntu Pro-only records.** 34,326 counted the FIPS and Realtime sub-streams. The plain-stream figure is 27,145 `UBUNTU-CVE-*` records.
- **OpenSSL `1.1.1w`.** It answered `invalid_version` on 322 of its 328 advisories, not all of them.
- **.NET bounds.** NVD's `microsoft:.net` rows do not mix runtime and SDK versions; every bound is runtime-numbered.

## Quality checks

Docs only; no code. Measurement: the 22 go/no-go items and 6 Ubuntu probes on the copy, `serve` built at `0241f0d`.
