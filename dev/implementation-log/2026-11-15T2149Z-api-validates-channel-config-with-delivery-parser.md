# API validates channel config with the delivery parser

## What was built

| Feature | Files | Description |
|---|---|---|
| Shared validation for create and PATCH | `internal/api/channels.go` (`validateChannelConfig`, `validateWebhookConfig`, `validateEmailConfig`, `channelConfigParseError`) | Both handlers call `validateChannelConfig` after `resolveMaskedChannelConfig`. Webhook config is decoded with `notify.ParseWebhookSettings`, then checked for a non-empty url and with `validateWebhookURL`. `validateEmailConfig` decodes with `notify.ParseEmailSettings` and returns `([]string, *huma.ErrorDetail)`; the recipient-count, RFC 5322 and duplicate errors stay at `body.config.recipients`. The `map[string]any` decodes are gone. |
| Parse error mapping | `internal/api/channels.go` (`channelConfigParseError`) | Unknown name → `body.config.<pointer>`, "unexpected property". Pointer `/url` → `body.config.url`, "webhook config must include a non-empty url". `/custom_headers` → "custom_headers must be an object of header names to strings". Under `/custom_headers/` → `body.config.custom_headers.<name>`, "custom_headers values must be strings". `/recipients` or under it → `body.config.recipients`, "email config must include a recipients array". Anything else (config not an object) → `body.config` with the type's existing message. |
| Location helper | `internal/api/contract.go` (`jsonLocation`, `bodyLocation`) | `jsonLocation(root, ptr)` renders a JSON Pointer under any root in huma's location format; `bodyLocation(ptr)` is `jsonLocation("body", ptr)`, so `decodeJSON` is unchanged. |
| Channel test endpoint | `internal/api/channels.go` (`testEmailChannel`) | Reads stored email config through `validateEmailConfig`, so the test endpoint and delivery use the same parser; the detail's message is the test error. |
| OpenAPI docs | `internal/api/channels.go` (`createChannelBody`, `patchChannelBody`), `openapi.json`, `web/src/lib/api/schema.d.ts` | The `config` descriptions name the keys each type takes, say names are case-sensitive and other keys are refused. |
| Doc fix | `internal/notify/channel_config.go` | `ParseWebhookSettings`/`ParseEmailSettings` comments said the error is returned wrapped; it is returned as jsonv2 reports it. |
| Tests | `internal/api/channels_test.go`, `internal/api/channels_redaction_test.go`, `internal/api/contract_test.go` | `TestChannelConfig_ParseErrors` (16 configs, each through create and, except `null`, PATCH; asserts status, `errors[0].location` and `errors[0].message`), `TestCreateChannel_RefusesKeysDeliveryDoesNotRead`, `TestChannelConfig_StoredUnrecognisedFieldsMasked`, `TestJSONLocation`. |

## Key decisions

- **Unknown keys refused (Sam, 2026-11-15).** `TestChannelConfig_UnrecognisedFieldsMaskedAndKeptOnRoundTrip` asserted that create stores keys delivery does not read. It is split: create now returns 422 at `body.config.account`, and a row with those keys stored through `store.CreateNotificationChannel` is still shown masked, accepts a name-only PATCH (audit old and new state hold none of the values), and refuses a PATCH that sends its config back, at `body.config.account` with the row unchanged. `account` is reported because `resolveMaskedChannelConfig` re-encodes with v1 `json.Marshal`, which sorts keys, and v2 reports the first unknown member it reads.
- **Null strings.** The parsers refuse `null` for `url`, a header value and a recipient (see the strict channel config parser entry of the same date); the API reports these at the pointer rows above: `{"url":null}` gets the url message, `{"X-A":null}` the header-value message, `[null]` recipients the recipients-array message.

## Gotchas discovered

- `PATCH {"config":null}` does not reach config validation: `decodeJSON` (v2) decodes `null` into the `*json.RawMessage` field as a nil pointer, which the handler treats as "config not sent" (probed on go1.27.4). The `null` rows are therefore tested on create only.
- `validation.MsgUnexpectedProperty` is a variable, not a constant, so it cannot go in a `const` block.
- The audit test helper `assertNoCredential` checks the fixture's webhook credential strings only; the stored-row test uses its own check for the inert field values.

## Quality checks

- Red: before the handler change, `TestChannelConfig_ParseErrors`, `TestCreateChannel_RefusesKeysDeliveryDoesNotRead` and `TestChannelConfig_StoredUnrecognisedFieldsMasked` failed (case variants refused only as a missing url, unknown keys and non-string header values accepted with 201, wrong locations for non-object email config); `TestJSONLocation` did not compile.
- `go test ./internal/api/ -run 'TestChannel|TestCreateChannel|TestPatchChannel|TestBodyLocation|TestJSONLocation|TestDecodeJSON|TestOpenAPISpec' -count=1 -v`: 58 top-level tests pass, 0 fail.
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/notify/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
