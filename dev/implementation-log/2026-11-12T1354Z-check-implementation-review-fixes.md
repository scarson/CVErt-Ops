# Version check: fixes from the two reviews of the roll-up change

## What was done

The two reviewers who agreed the roll-up change also reviewed its implementation, `0241f0d`. These fixes follow from what they found. Design sections 4.5, 4.7 and 6 record them.

- **CNA names are shared across a row's spellings (P1, found by Codex).** `nodejs:nodejs`, newly in the Node row, read only its own CNA name and the table's, not `nodejs / node.js`. So an item under it could miss a CNA entry naming `node.js` and answer `not_affected` where `nodejs:node.js` answers Affected. `.net` and `.net_core` had the same gap before. `NamesFor` now gives every spelling the own names of every spelling in its row.
- **Sub-streams fail closed (found by Fable).** The corpus has `Ubuntu:Nvidia-BlueField:22.04:LTS` and `:24.04:LTS`, which are partial streams outside `Pro:`. These were read alone and could be cleared. `IsSubStream` is now true for any `Ubuntu:` ecosystem that is not a release's standard or plain Pro stream.
- **Failure flags decide the advisory's reason (both reviewers).** A row's `invalid_version` was hidden when an earlier row was `invalid_range`. The item was then `cannot_evaluate` with a null reason, and no advisory said why. Both version-failure kinds are now kept (`Outcome.InvalidVersion` and `Outcome.UnknownVersionScheme`; before, only the first was kept, so the result depended on row order). `withFailureReason` shows them in this order: `too_many_ranges`, `evaluation_failed`, `unknown_version_scheme`, `invalid_version`. A masked `evaluation_failed` is now shown and logged.
- **SDK detection reads digits (both reviewers).** `strconv.Atoi` overflowed on a third component past 19 digits, which skipped the rule. The first fix read an all-zero component (`10.0.0`) as an SDK number, which both reviewers found in a confirmation round; the rule now counts significant digits, and `10.0.0` and `10.0.000` are tested.
- **Exclusion prefixes end at a word boundary (Codex).** `.NET FrameworkExtensions` is not the .NET Framework.
- **Suffix bounds refuse wildcard shapes (Fable).** `1.0-beta.x` matched the suffix grammar.
- `PLAN.md`'s endpoint summary names `unresolved` and the one check slot.
- **Tests added** for the gaps both reviewers listed:
  - `IsSubStream`;
  - SDK boundaries (`10.0.99`, `10.0.100`, `.net_core` with four components);
  - sub-stream items with an unresolved advisory or retracted rows only;
  - fixes across streams (a later Pro fix, and an unbounded standard row);
  - more suffix shapes;
  - an API integration test that runs both streams and a sub-stream through SQL.

## Decisions and gotchas

- **Not changed: one error log line per advisory for `evaluation_failed`** (Fable, low). The path is unreachable today, and a line per advisory names each advisory affected.
- **`2.x` expectation corrected.** A true line wildcard such as `2.x` still goes through the existing wildcard path, which places `4.0` past line 2 correctly. The test first expected Indeterminate there.

## Quality checks

- `go test ./internal/check/ ./internal/ecosystem/`: pass. Break tests: reverting each fix, one at a time, fails a test. That covers shared names, SDK overflow, the version-failure reason, the masked evaluation failure, both flags kept, the exclusion boundary, sub-streams failing closed and the wildcard guard.
- `go test ./internal/api/ -run 'Check|OpenAPI'` and `./internal/store/ -run Check`: pass.
- `golangci-lint run --allow-parallel-runners`: 0 issues.
- `openapi.json` and `schema.d.ts` regenerated.
