# MATCH-2: review decisions and the set-condition limit for and rules

## What was built

| Feature | Files | Description |
|---|---|---|
| Decisions recorded | `dev/plans/2026-11-13-product-match-rules-plan.md`, design section 17, `PLAN.md` §10.2 | The four review fixes decided under Sam's delegation, the 10-set limit for `and` rules, the CLI/MCP discovery and the saved-search follow-up. |
| Measurement | `internal/alert/kept_ingest_measure_test.go`, measurements file | `TestKeptIngestAndSetSweep`: `and` rules of 2 to 50 set conditions, realtime and batch, read-only on the kept ingest. |

## Key decisions

- Limit set conditions in `and` rules to 10: realtime planning of one CVE was 4.3 ms with 10 sets and 15.9 ms with 20, and realtime evaluates every organisation's rules on each changed CVE.

## Quality checks

- golangci-lint v2.15.0 with `--build-tags keptingest` on `./internal/alert/`: 0 issues. Docs and a build-tagged harness only.
