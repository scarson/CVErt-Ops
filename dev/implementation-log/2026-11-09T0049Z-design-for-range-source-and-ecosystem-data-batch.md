# Design for the range, source and ecosystem data batch

## What was done

Wrote `dev/plans/2026-11-08-cve-range-data-batch-design.md`, covering per-branch ranges and GHSA range parsing (DATA-1), one
`cve_sources` row per OSV advisory (DATA-4) and one ecosystem vocabulary (DATA-5). No implementation code or migration was written.
The design waits for Sam's review.

## Findings not in PLAN.md

- All 37,597 reviewed GHSA advisories use 9 range shapes, listed in the design. None is null, uses `!=` or has more than two constraints.
- OSV distro records link to CVEs through `upstream`, not `aliases`, so an OSV refetch for the alias overwrite bug needs about 62,000 records
  out of 2.37 million.
- The material hash's package sort stops at `introduced`. A throwaway test confirmed two ranges sharing `introduced` hash differently by input order.
- Today one withdrawn source tombstones a CVE, and a changed alias on a real CVE renames or merges the whole CVE. One row per advisory
  makes the first far more common.

## Quality checks

The `schema-review` checklist was applied to the proposed migration, with no failures. No new dependency is proposed. No test suite was run:
the commit changes only documents.
