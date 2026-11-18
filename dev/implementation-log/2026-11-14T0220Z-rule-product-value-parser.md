# Alert rule product value parser

## What was built

MATCH-2 plan Task 1.2. `check.ParseProductValue` reads an `affected.cpe_product` value, `vendor:product` as a CPE 2.3 name writes them, into a lower-cased `ProductRef` with no part and with redundant escapes dropped. It refuses, in order: more than 255 characters; a character outside printable ASCII (checked before lower-casing); not exactly two non-empty components; a component that is `*` or `-` or holds an unescaped `*` or `?`; a component ending in an unescaped backslash; and the first unescaped character that CPE 2.3 requires escaped, named in the message.

## Key decisions

- **One message added.** The design requires the printable-ASCII refusal but its message table has no message for it. The parser uses `value must be printable ASCII with no spaces, as a CPE 2.3 name is`, as the plan specifies.
- **One escape walk, three readers.** `unescapedBytes` yields the bytes a backslash does not escape. `firstUnescapedInvalid`, `escapedAsCPERequires` (the version check's rule, which still accepts unescaped `*` and `?`) and `hasUnescapedWildcard` all read it. `escapedAsCPERequires` cannot call `firstUnescapedInvalid` directly, because that stops at the first `*` or `?`, which the check accepts.
- **The check-endpoint invariant is tested both ways.** Every accepted value, placed in a full CPE, parses through `ParseItem` with no error. Every refusal also records what the check does with it: the check refuses each one except unescaped `*`/`?` inside a component and the 256-character value, whose limit in the check is the whole CPE's 512.

## Gotchas

- The design's test list (section 12) says each refusal the rule adds is also refused by the check, which contradicts section 3.1 for unescaped `*` and `?`. The tests follow section 3.1: everything the rule accepts, the check accepts.

## Quality checks

- `go test ./internal/check/... -count=1 -run 'ProductValue|ParseItem'`: pass; whole `internal/check` package: pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
