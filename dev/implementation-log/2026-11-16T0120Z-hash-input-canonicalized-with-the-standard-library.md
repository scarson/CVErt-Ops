# Hash input canonicalized with the standard library

## What was built

| Feature | Files | Description |
|---|---|---|
| One canonicalization helper | `internal/merge/canonical.go`, `hash.go`, `match_inputs.go` | `ComputeMaterialHash` and `ComputeMatchInputsHash` both call `canonicalJSON`. Commit `efdc8f7`, no behaviour change. |
| Standard-library canonicalizer | `internal/merge/canonical.go`, `go.mod`, `go.sum` | `canonicalJSON` runs `jsontext.Value.Canonicalize` (RFC 8785) on a copy of its input. `github.com/cyberphone/json-canonicalization` is no longer a dependency; `go mod tidy` removed only its `go.mod` line and two `go.sum` lines. Commit `77d8418`. |
| Canonical output pins | `internal/merge/canonical_test.go` | `TestCanonical_RFC8785Output`: 62 values, each marshaled with v1 `json.Marshal` as `{"v": value}`, with the literal canonical bytes expected. Also checks the input buffer is not modified. `TestCanonical_RejectsInvalidInput`: duplicate names, invalid UTF-8, trailing data, a leading zero and truncated input fail. |
| Docs | `PLAN.md` (tech stack table, §5 material_hash), `dev/research.md` (JSON Canonicalization) | Name `jsontext.Value.Canonicalize` and the reason: standard library, same RFC, one fewer third-party dependency in the `material_hash` path. |

## Key decisions

- **Differential before the swap.** While both canonicalizers were present, the 62-value table compared `jsoncanonical.Transform(b)` and `jsontext.Value(b).Canonicalize()` byte for byte: all 62 equal. Cases cover every value kind `MaterialFields` and `matchInputs` marshal (strings, bools, `*float64` including nil and negative zero, string slices, `[2]string` arrays, slices of structs, both real structs), CVSS and EPSS floats, float64 boundaries (`5e-324`, `2.2250738585072014e-308`, `1.7976931348623157e308`, `1e20`, `1e21`, `1e-6`, `1e-7`), integers above 2^53 (both round through float64, for example `123456789012345678` becomes `123456789012345680`), every escape v1 emits (`<`, `>`, `&`, U+2028, U+2029, control characters, `"`, `\`), invalid UTF-8 that v1 replaces with U+FFFD, keys whose UTF-16 order differs from UTF-8 order (U+1F600 sorts before U+E000), nested arrays of objects, and empty containers. The expected strings in the committed table are those outputs.
- **`slices.Clone` kept.** `Canonicalize` rewrites the value in place (`append((*v)[:0], ...)`). The hash code does not reuse `raw`, but the helper does not modify its argument, and the test checks that.
- **Behaviour on malformed input differs; v1 Marshal never produces it.** Both refuse duplicate member names and trailing data. Only `Canonicalize` refuses invalid UTF-8 bytes and leading zeros (`01`), which the reference transform passed through. Only the reference transform refused a top-level non-object and out-of-range numbers (`1e400`; `Canonicalize` writes `1.7976931348623157e+308`). The hash code always canonicalizes the output of v1 `json.Marshal` of a struct, which is an object with valid UTF-8 and no out-of-range numbers, so the panics in both hash functions still fire only on impossible input.
- **Dated perf-audit reports left as written.** `docs/perf-audits/2026-06-05-*.md` name the old library; they record the state on that date.

## Gotchas discovered

- The Write and Edit tools decode `\uXXXX` in their input. The table's escapes were written with a placeholder and expanded by a script; the file holds only ASCII.

## Quality checks

- `go test ./internal/merge/ -count=1` after the helper commit: pass.
- `go test ./internal/merge/ -run TestCanonical -count=1 -v` with both canonicalizers: 62 of 62 subtests pass (identical bytes).
- `go test ./internal/merge/ -count=1 -v` after the swap: pass, no failures or skips. Includes `TestMaterialHash_GoldenCorpusMatchesPins` (golden pins unchanged; `testdata/golden_material_hashes.json` not edited), `TestIngest_MatchInputsRecheckSignal`, the seven `TestComputeMatchInputsHash_*` tests and both `TestCanonical_*` tests.
- `golangci-lint run --allow-parallel-runners ./internal/merge/...`: 0 issues. `go build ./...`: ok.
- `grep -rn cyberphone --include=*.go .`: no hits.
- Full suite not run (the coordinator runs it once per phase).
