# SCIM PATCH values that name one attribute twice refused

## What was built

| Feature | Files | Description |
|---|---|---|
| Member values decoded strictly | `internal/api/scim_groups_handler.go` (`extractMemberValues`, `extractRemoveTargets`, `scimPatchGroup`) | `extractMemberValues` returns `([]uuid.UUID, error)`. Empty or `null` → no members. Otherwise `jsontext.Value(raw).Kind()` picks the shape: `[` decodes `[]SCIMGroupMember`, `{` decodes one `SCIMGroupMember`, each with `jsonv2.Unmarshal(raw, &x, scimJSONOptions)`; any other kind is an error. Non-UUID member values are still skipped. `extractRemoveTargets` passes the error through. The PATCH `add` (path `members`) and `remove` callers write 400 `invalidValue` "invalid members value". |
| Pathless replace duplicate check | `internal/api/scim_users.go` (`namesAttributeTwice`, `scimPatchUser`) | After the `map[string]json.RawMessage` decode, a value with two keys whose `strings.ToLower` forms are equal gets 400 `invalidValue` "pathless operation value has duplicate attributes". The check uses the same normalisation as the `strings.ToLower` switch that applies the keys, so no two keys can reach one case. |
| Debug logging of refused members values | `internal/api/scim_groups_handler.go` (`scimPatchGroup`) | The add and remove paths log the `extractMemberValues` error with `slog.DebugContext`. Probed on go1.27.4: the jsonv2 errors name JSON pointers, member names and Go types (`duplicate object member name "VALUE" within "/0"`, `cannot unmarshal JSON number into Go string within "/0/value"`), never member values. |
| Tests | `internal/api/scim_groups_handler_test.go`, `internal/api/scim_users_test.go`, `internal/api/scim_types_test.go` | `TestSCIMPatchGroup_MemberValueNamedTwiceRefused` (add array, remove array, add single object, add string value, remove string value; store membership unchanged), `TestSCIMPatchGroup_MemberValueAccepted` (array, single object with `Value`, non-UUID skipped, add without value and remove with `null` stay 200 no-ops), `TestSCIMPatchUser_PathlessReplaceAttributeNamedTwice` (`{"active":false,"Active":true}`, `active` plus `act` U+0130 `ve`, and a duplicated ignored attribute refused with the member still active; `{"Active":false}` deactivates), `TestNamesAttributeTwice` (includes Kelvin sign and U+0130, which lower to ASCII, and long s, which does not). Separate commit: `TestDecodeSCIMBody_RefusedNestedAndPatchOp` (case-variant duplicate inside a group member, `Operations` + `operations`) and a content-type check in `TestSCIMPatchGroup_DuplicateAttributeRefused`. Every handler test body holds one operation. |

## Key decisions

- **Duplicates are matched with the switch's normalisation, not `strings.EqualFold`.** The plan named `EqualFold`, and the first version used it (through a `unicode.SimpleFold` key). Review found that `strings.ToLower` and `EqualFold` differ: `strings.ToLower` turns U+0130 into `i`, but `EqualFold` does not match it to `i`. So `{"active":false,"act` U+0130 `ve":true}` passed an `EqualFold` check while both keys reached the switch's `"active"` case, and map order decided the result. `namesAttributeTwice` puts `strings.ToLower(k)` into a set: the cost is linear in an IdP-controlled key count (up to the 1 MB body limit), and two keys are refused exactly when they would reach one case.
- **Any duplicate is refused,** including attributes the pathless switch ignores (`displayName` + `DISPLAYNAME`).
- **Value of another kind is refused.** A members value that is a string, number or bool was a silent no-op; it now gets the 400, as the plan states.

## Gotchas discovered

- `jsontext.Value.Kind()` skips leading whitespace, so the kind dispatch works on raw bytes that keep the whitespace around the value.
- `strings.ToLower` and `strings.EqualFold` are different equivalences (U+0130 lowers to `i` but does not fold to it; long s folds to `s` but does not lower to it). A duplicate check must use the normalisation of the code that consumes the keys.

## Quality checks

- Red: before the change, the four `MemberValueNamedTwiceRefused` subtests got 200 (B added in the add case), and the two refused pathless cases got 200 (the first left the user deactivated, by map order). The control subtests passed before and after. Before the `strings.ToLower` fix, the U+0130 handler case got 200. The remove-with-string-value subtest was added after the kind check existed and passed on its first run.
- `go test ./internal/api/ -run 'TestSCIM|TestScim|TestDecodeSCIMBody|TestNamesAttributeTwice' -count=1 -v`: 86 top-level tests pass (134 including subtests), 0 fail, 0 skip.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
