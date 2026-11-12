# Check endpoint: read CPE rows through the bounded index key

## What was built

Merging `dev` into PR #218's branch brought migration 000061 (bounded CPE and package keys, PR #225), which rebuilt `cve_cpe_matches_check_idx` on `left(cpe_normalized, 512) COLLATE "C"` so a CPE of any length fits a btree row. The branch's CPE statements still compared `cpe_normalized COLLATE "C"`, which matches no index, so after the merge every CPE lookup would have scanned `cve_cpe_matches` in full: correct answers, but no index. Git merged the code without a conflict; only the plan's Discoveries conflicted. Sam decided the bounded key on 2026-11-12 (plan, Discoveries), and PR #225 updated Task 3.9's text and design section 9 to match. This commit brings the code into line.

- `check.CPEKey` gains `Prefix`, the whole CPE prefix. `check.CPEKeyFor(prefix)` builds every key: `Lo` is the prefix cut to `check.CPEKeyRunes` (512) runes, as SQL `left` cuts, and `Hi` is `Lo` with its last rune incremented (`nextPrefix`), built after the cut. For a prefix within 512 runes, `Hi` is the prefix ending in `;`, as before.
- `internal/store/check.go`: `cpeIndexExpr` returns `left(<column>, 512) COLLATE "C"`. The CPE statement and the nearby-name statement's `NOT EXISTS` probe both range on it with `Lo` and `Hi`, and recheck `starts_with(cpe_normalized, prefix)`. The nearby-name statement carries each key's prefixes in a third `chr(31)`-joined parameter beside the lows and highs.
- `cutRunes` takes its rune count, so CNA names (256) and CPE keys (512) share it. `upperOfPrefix` is gone; `nextPrefix` gives the same bound for a prefix ending in `:`.
- `nearKeyID` identifies a vendor range by its `Prefix`.

## Decisions and gotchas

- A request cannot form a CPE prefix over 512 characters today: an item's `cpe` is at most 512 characters, and the prefix stops at the product. The cut and the recheck still matter, because without `left(...)` in the predicate the index is not used at all, and the key builder is the one place that has to agree with the index's length.
- `TestCheckCPEIndexMatchesQuery` read the `check_lookups` migration (000059), which no longer holds the index's current definition. It now reads the last up migration, in migration order, that creates `cve_cpe_matches_check_idx`. Migration files are CRLF in this checkout, so the test matches the `CREATE INDEX` line with `\s`, not `\n`.
- The two new integration tests passed before the change, because the old statements compared whole values. They guard the recheck: a break test (run once, not committed) removed each `starts_with` in turn, and each removal failed its own test (`TestReadCheckCandidates_CPEPrefixOverIndexLength`, `TestReadCheckCandidates_CNANearVendorOverIndexLength`), then the file was restored.
- golangci-lint in `GOPATH/bin` was built with Go 1.26 and refuses a Go 1.27.4 module. The CI pin, v2.15.0, was built into a scratch directory for this run, leaving the shared binary alone.

## Quality checks

- `go test ./internal/check/ -count=1`: pass.
- `go test ./internal/store/ -run 'ReadCheck|TestCheck|Below|OrgSnapshot' -count=1`: pass.
- `go test ./internal/api/ -run Check -count=1`: pass.
- `golangci-lint run ./internal/check/... ./internal/store/...` (v2.15.0): 0 issues.
- Full suite: started in the background after this commit; result recorded in the Phase 4 log entry.
