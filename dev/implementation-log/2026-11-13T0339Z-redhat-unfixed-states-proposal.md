# Proposal: unfixed Red Hat package states for the version check

## What was done

Sam asked for a design study, not code: could Red Hat's per-package states let RHEL items in the version check earn `not_affected`? Today the stored Red Hat-family rows list issued fixes only. The proposal is `dev/plans/2026-11-13-redhat-unfixed-package-states-proposal.md`. Its figures come from read-only queries on the kept full ingest (`cvert_ops`).

## Findings

- OSV Red Hat rows are RHSA errata under their own IDs, with binary RPM names (`kernel-core`, `openssl-libs`) and fixed versions only.
- The Red Hat Security Data API, which `internal/feed/redhat` already fetches, gives per-package states:
  - the states are Affected, Fix deferred, Will not fix, Out of support scope, Under investigation and Not affected;
  - products are named at major-release level, with no repository;
  - packages are named by source package.
  
  The adapter keeps these only as vendor enrichment, and the check does not read them.
- Of 517 RHEL 9 source names with an unfixed state, 288 also occur as an OSV binary name. A binary-to-source map, derived by joining OSV RHSA rows to `affected_release` on advisory and NEVRA, maps 4,410 of 4,885 RHEL 9 binary names to exactly one source.
- The kept ingest's Red Hat feed stopped at page 645 on the reference URL index limit, which migration 000060 fixes on `dev`. So its counts are lower bounds. The adapter's cursor has no `caught_up` flag.
- Alpine has no authoritative unfixed source. SUSE publishes per-CVE CSAF VEX files, which were not examined in detail.

## Recommendation recorded

- Build the status-only rule now: fix-only distros answer `unresolved` where they would answer `not_affected`.
- Defer reading Red Hat states until RHEL clearing is a product need. The shape to build when it is: a separate state table, RHEL 8 to 10 main streams, and a `source_name` item field plus the derived map.
- Four decisions are listed for Sam.

## Quality checks

- Documentation only; no code changed.
