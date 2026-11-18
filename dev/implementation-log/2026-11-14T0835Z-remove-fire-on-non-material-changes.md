# Remove the alert-rule flag fire_on_non_material_changes

## What was built

| Feature | Files | Description |
|---|---|---|
| Design note | `dev/plans/2026-11-14-remove-fire-on-non-material-changes-design.md` | Why the flag goes, in plain language: how `material_hash` suppresses repeats, why EPSS is outside it, what the flag would have sent, and what a useful trigger would look like instead. |
| Migration | `migrations/000064_drop_alert_rules_fire_on_non_material_changes.{up,down}.sql` | Drops the column; the down migration restores it with its old default, `false`. |
| Store | `internal/store/queries/alert_rules.sql`, `internal/store/generated/`, `internal/store/alert_rule.go` | Create and update no longer write the column; the list query no longer selects it. |
| API | `internal/api/alert_rules.go` | Create, PATCH and the rule entry no longer carry the field. |
| Generated API | `openapi.json`, `web/src/lib/api/schema.d.ts` | Regenerated; the diff is only the field. |
| Docs | `PLAN.md` §10.4, `dev/plans/2026-11-13-product-match-rules-plan.md` | §10.4 says changes outside `material_hash` never re-fire a rule, and why the flag was removed. |
| Test | `internal/api/alert_rules_test.go` (`TestAlertRule_NoFireOnNonMaterialChanges`) | A create that still sends the field succeeds, and the response has no such key. `validRuleDSL` no longer sends it. |

## Key decisions

- **Remove rather than build** (Sam, 2026-11-14). Nothing read the flag. Built as specified, it would re-alert about once a day per matching CVE for a rule with an EPSS condition, and in bursts on feed re-publishes otherwise; building it also needed a second dedup record on `alert_events`.

## Gotchas discovered

- The OpenAPI schemas for alert-rule bodies say `additionalProperties: false`, but the chi handlers decode with `json.Decoder` (`internal/api/contract.go` `decodeJSON`), which ignores unknown fields. So a client that sends the removed field is not refused. This mismatch applies to every handler that uses `decodeJSON`; not changed here.
- The scripted line removal also deleted the list query's `Select(...)` and `Scan` lines, which named the column beside others; both were restored with the column left out.

## Quality checks

- `TestAlertRule_NoFireOnNonMaterialChanges`: the response key was always present before (the field had no `omitempty`), so the assertion fails on the old code. `go test ./internal/api/ -run TestAlertRule`, `./internal/store/ -run AlertRule`, `./migrations/...`: pass.
- `sqlc generate`: only `alert_rules.sql.go` and `models.go` changed.
