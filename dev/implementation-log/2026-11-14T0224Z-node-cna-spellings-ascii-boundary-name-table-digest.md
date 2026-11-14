# Node.js CNA spellings, ASCII product boundary, name table digest

## What was built

MATCH-2 plan Task 1.3, in `internal/check/names.go`:

- The Node.js row of the CNA name table gains `node.js` / `node.js` and `the node.js project` / `node.js`, so `NamesFor(nodejs:node.js)` lists five names.
- `IsOtherProduct` treats any character other than an ASCII letter or digit after a prefix as a word boundary, the same test the rule compiler's SQL exclusion will make with `!~ '^[a-z0-9]'`. A non-ASCII letter after `.NET Framework` is now a boundary.
- `nameTableDigest`, the SHA-256 of the table and `otherProducts` as JSON through `digestOf(table, other)`, pinned by `TestNameTableDigest`. Its failure message points to the re-check step in the product match rules design, section 3.4, which an edit that changes a stored match must ship with.

## Key decisions

- `TestNameTableDigestCoversEveryField` mutates a copy of the table (a row, a CPE spelling, a CNA name, a prefix flag, a fragment, a nearby-name vendor, an added and a changed other product) and asserts each changes the digest, so the pin cannot pass with a digest that ignores a field.
- Pinned digest: `f91e7929f51adec89ba190330d9674af25993b48322c2b0b5293072e4394a18b`, computed after the Node row change.

## Gotchas

- `TestKeysFor` and `TestKeysForItemUses` in `keys_test.go` enumerate the Node row's names through their keys, so they gained the two names and the .NET key indices moved up by two.

## Quality checks

- `go test ./internal/check/... -count=1`: pass.
- `go test ./internal/store/... -count=1 -run Check` and `go test ./internal/api/... -count=1 -run Check` (testcontainers): pass; the version check endpoint's stored answers do not change.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
