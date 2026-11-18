# Record that the DSL fixes shipped without a version bump

## What was built

| Feature | Files | Description |
|---|---|---|
| Versioning record | `PLAN.md` §10.5 | A bullet beside "Package correlation shipped without a bump (MATCH-2)" records that the regex case default, the `or` + regex refusal and the operator and `null` refusals shipped at `dsl_version` 1 with no old compiler kept, with the reasons and the effects on stored rules. |

## Key decisions

- No `dsl_version` bump. Decided by the MATCH-2 implementation session under Sam's standing delegation ("bias to action; decide what is basically correct"), because the project has no users, package correlation shipped the same way, and an old compiler kept for old rules would keep the wrong answers the fixes correct.

## Quality checks

- Docs only. The full suite passed at `0d27ead`, the code this entry describes; no rerun.
