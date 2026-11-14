# match_inputs_hash computed beside material_hash

## What was built

| Feature | Files | Description |
|---|---|---|
| Hash | `internal/merge/match_inputs.go` | `ComputeMatchInputsHash(cna, cpe)` is the sha256 hex of the JCS form of `{"cna": [[vendor, product], ...], "cpe": ["part:vendor:product", ...]}`, both lists sorted and distinct. CNA names are ASCII lower-cased (`lowerASCII`, a `strings.Map` over A to Z), a missing value is `""`. Only CPE matches with `Vulnerable` set contribute; nil lists encode as `[]`. Versions and every other field are left out. |
| CPE product key | `internal/check/cpe.go` | `CPEProductKey(cpeNormalized)` returns `part:vendor:product` split on unescaped colons by `splitCPE`, escapes kept as stored, `""` below 5 components. |
| Merge | `internal/merge/pipeline.go` | `canonicalize` computes the hash (step 5.5) from the resolved CNA rows and CPE matches, under the same per-CVE lock and transaction as `material_hash`, and passes it to `UpsertCVE`. |
| Upsert | `internal/store/queries/cves.sql`, `internal/store/generated/` | `UpsertCVE` inserts `match_inputs_hash` (`$19`) and `date_match_inputs_changed` (`$5`, the merge clock), and on conflict stamps `date_match_inputs_changed` with `EXCLUDED.date_modified_canonical` when the stored hash `IS DISTINCT FROM` the new one, so a stored NULL stamps once. `date_modified_canonical` keeps its own CASE on `material_hash` only. `sqlc generate` adds the two fields to `generated.CVE` and `UpsertCVEParams`, and `GetCVE`/`ListCVEs` now select them. |

The hash carries the re-check signal of MATCH-2 design section 7 (`dev/plans/2026-11-13-product-match-rules-design.md`; Sam's ruling in section 15.1: a separate signal, never a `material_hash` change). `MaterialFields` is unchanged. Realtime and batch evaluation start reading the signal in the next plan tasks (5.4, 5.5).

## Key decisions

- Verify-first (plan Task 5.3, ASCII-only lower-casing): with `lowerASCII`, `Node.js`/`node.js` CNA copies give one hash and `string(rune(0x212A)) + "node"` versus `knode` give two (`TestComputeMatchInputsHash_CaseOnlyCNACopiesHashAlike`, `TestComputeMatchInputsHash_KelvinSignDiffersFromK` pass). With `lowerASCII` temporarily returning `strings.ToLower(s)`, the KELVIN SIGN test failed (both hashed `82bac1b4...`) and the other six passed. The ASCII form was restored before anything else ran.
- A vulnerable CPE match whose `CPEProductKey` is `""` (fewer than 5 components) adds nothing: it names no product, so no product condition can match it.
- `cveColumns`/`scanCVERow` in `internal/store/dsl_executor.go` list 21 columns and scan the same 21; the two new `generated.CVE` fields stay zero there. The API maps `generated.CVE` field by field (`internal/api/cves.go` `cveToItem`), so neither column is exposed.
- `go list -deps ./internal/check` lists only `internal/ecosystem` and `internal/version` from this module, so `internal/merge` importing `internal/check` makes no cycle.
- sqlc rewrote every generated file with LF endings in this CRLF checkout. Only `cves.sql.go` and `models.go` had content changes (`git diff --ignore-cr-at-eol --stat`); the rest were restored with one pathspec `git restore`.

## Quality checks

- Unit: `TestCPEProductKey` and the seven `TestComputeMatchInputsHash_*` tests failed first on the undefined functions.
- Integration: `TestIngest_MatchInputsRecheckSignal` (`internal/merge/match_inputs_integration_test.go`) failed first on a NULL `match_inputs_hash`. It checks a new CVE's two dates are equal (one bound clock value), then sets `date_match_inputs_changed` to the fixed `2000-01-01T00:00:00Z` before each re-ingest and never compares clock readings across transactions: a CNA product change alone (`n/a` to `Node.js`) leaves `material_hash` and `date_modified_canonical` alone and replaces the stamp; an unchanged re-ingest and an NVD copy differing only in ASCII case keep the hash and exactly the fixed stamp; a stored NULL hash is stamped on the next merge and not on the one after.
- `go test ./internal/merge/... ./internal/check/... -count=1`: pass (merge 179 tests, 54 subtests; check 106 tests, 660 subtests).
- `go test ./internal/store/... -count=1 -run 'CVE|Upsert|Merge'`: pass (48 tests). `go test ./migrations/... -count=1`: pass (6, previous commit).
- `go test ./internal/merge/... -run 'Hash|Golden' -count=1`: pass, and `git status` shows no golden file changed.
- `go build ./...`, `go vet -tags keptingest ./internal/alert/`: clean. golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
