# SCIM PATCH values that name one attribute twice refused

## What was built

| Feature | Files | Description |
|---|---|---|
| Member values decoded strictly | `internal/api/scim_groups_handler.go` (`extractMemberValues`, `extractRemoveTargets`, `scimPatchGroup`) | `extractMemberValues` returns `([]uuid.UUID, error)`. Empty or `null` → no members. Otherwise `jsontext.Value(raw).Kind()` picks the shape: `[` decodes `[]SCIMGroupMember`, `{` decodes one `SCIMGroupMember`, each with `jsonv2.Unmarshal(raw, &x, scimJSONOptions)`; any other kind is an error. Non-UUID member values are still skipped. `extractRemoveTargets` passes the error through. The PATCH `add` (path `members`) and `remove` callers write 400 `invalidValue` "invalid members value". |
| Pathless replace duplicate check | `internal/api/scim_users.go` (`hasCaseFoldedDuplicateKey`, `foldKey`, `scimPatchUser`) | After the `map[string]json.RawMessage` decode, a value with two keys equal under `strings.EqualFold` gets 400 `invalidValue` "pathless operation value has duplicate attributes". The `strings.ToLower` switch is unchanged. |
| Tests | `internal/api/scim_groups_handler_test.go`, `internal/api/scim_users_test.go`, `internal/api/scim_types_test.go` | `TestSCIMPatchGroup_MemberValueNamedTwiceRefused` (add array, remove array, add single object, add string value; store membership unchanged), `TestSCIMPatchGroup_MemberValueAccepted` (array, single object with `Value`, non-UUID skipped, add without value and remove with `null` stay 200 no-ops), `TestSCIMPatchUser_PathlessReplaceAttributeNamedTwice` (`{"active":false,"Active":true}` and a duplicated ignored attribute refused with the member still active; `{"Active":false}` deactivates), `TestHasCaseFoldedDuplicateKey`, `TestFoldKey_AgreesWithEqualFold`. Separate commit: `TestDecodeSCIMBody_RefusedNestedAndPatchOp` (case-variant duplicate inside a group member, `Operations` + `operations`) and a content-type check in `TestSCIMPatchGroup_DuplicateAttributeRefused`. Every handler test body holds one operation. |

## Key decisions

- **Linear duplicate check.** A pairwise `strings.EqualFold` loop over the map keys is quadratic, and the key count is IdP-controlled up to the 1 MB body limit. `foldKey` maps each rune to the smallest rune of its `unicode.SimpleFold` orbit, which is the equivalence `strings.EqualFold` uses, and the keys go into a set. `TestFoldKey_AgreesWithEqualFold` checks agreement on ASCII and on multi-member orbits (Kelvin sign, long s, sigma forms, sharp s).
- **Any EqualFold duplicate is refused,** including attributes the pathless switch ignores (`displayName` + `DISPLAYNAME`), as the plan states.
- **Value of another kind is refused.** A members value that is a string, number or bool was a silent no-op; it now gets the 400, as the plan states.

## Gotchas discovered

- `jsontext.Value.Kind()` skips leading whitespace, so the kind dispatch works on raw bytes that keep the whitespace around the value.
- The new helper tests (`TestHasCaseFoldedDuplicateKey`, `TestFoldKey_AgreesWithEqualFold`) were written after the helper, which came out of implementation; the handler tests were red first.

## Quality checks

- Red: before the change, the four `MemberValueNamedTwiceRefused` subtests got 200 (B added in the add case), and the two refused pathless cases got 200 (the first left the user deactivated, by map order). The control subtests passed before and after.
- `go test ./internal/api/ -run 'TestSCIM|TestScim|TestDecodeSCIMBody|TestHasCaseFoldedDuplicateKey|TestFoldKey' -count=1 -v`: 87 top-level tests pass (132 including subtests), 0 fail, 0 skip.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
