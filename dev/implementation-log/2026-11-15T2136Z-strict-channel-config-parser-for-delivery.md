# Strict channel config parser for delivery

## What was built

| Feature | Files | Description |
|---|---|---|
| Typed channel config parsers | `internal/notify/channel_config.go` | `WebhookSettings{URL, CustomHeaders}` and `EmailSettings{Recipients}`, decoded by `ParseWebhookSettings` and `ParseEmailSettings` with `encoding/json/v2` plus `RejectUnknownMembers(true)`. A config that is not a JSON object is refused before the decode (v2 decodes `null` into a struct without error). The jsonv2 error is wrapped with `%w`, so a caller can read `*jsonv2.SemanticError`, test it against `jsonv2.ErrUnknownName`, and read its `JSONPointer`. |
| Webhook delivery | `internal/notify/webhook.go` (`ChannelWebhookConfig`), `internal/notify/worker.go` (`deliverWebhook`) | `ChannelWebhookConfig` returns `(WebhookConfig, error)`. A refused config is a `permanentDeliveryError` "parse webhook config: ...": the delivery fails at once, and the reason is shown to org members (it describes their own channel). Before, decode errors were discarded and the delivery went out with whatever v1 had filled in, or failed on an empty URL and was retried until exhausted. |
| Email delivery | `internal/notify/worker.go` (`deliverEmail`) | Reads recipients through `ParseEmailSettings`; the permanent "parse email config" and "no recipients" failures are unchanged. |
| Channel test endpoint | `internal/api/channels.go` (`testWebhookChannel`) | A refused stored config is reported as a failed test (502, `success: false`, "parse webhook config: ..."); nothing is sent. |
| Tests | `internal/notify/channel_config_test.go`, `internal/notify/worker_test.go`, `internal/notify/webhook_test.go`, `internal/api/channel_test_notification_test.go`, `internal/api/channels_redaction_test.go` | `TestParseWebhookSettings`, `TestParseEmailSettings` (case variant, unknown key, header value not a string, recipients not an array, `[]`/`"x"`/`null`); `TestWorker_EmailConfigCaseVariantFailsPermanently` (no SMTP connection to a counting listener); `TestWorker_WebhookHeaderNotStringFailsPermanently` (no request reaches the receiver); `TestChannelTest_Webhook_StoredConfigRefused` (no request, no stored value in the error). The `headers`-key case in `TestChannelWebhookConfig_CustomHeadersReachReceiver` now asserts the unknown-name error at `/headers` instead of a 401. |

## Key decisions

- **Why.** The API validates channel config with case-sensitive map lookups and masks it by exact key, while delivery decoded it with v1, which matches names case-insensitively. An email config `{"Recipients":[...]}` was shown masked but delivered to its addresses, and a `custom_headers` value that is not a string was delivered as an empty header. Delivery now reads config with the parser the API will validate with (the API side is the next task of the JSON v2 migration plan, phase 1).
- **Unknown keys refused.** Sam accepted refusing config keys delivery does not read (2026-11-15). Stored rows with such keys now fail delivery permanently; the plan's pre-deploy query lists them before the phase merges.
- **Null refused for strings.** v2 decodes JSON `null` into a Go string as `""` without error, so `{"url":null}`, a `null` header value and a `null` recipient would decode to empty values. The parser options add a `*string` unmarshaler (`jsonv2.WithUnmarshalers(jsonv2.UnmarshalFromFunc(...))`) that refuses `null` and returns `errors.ErrUnsupported` for anything else, so default decoding continues. The error is a `*jsonv2.SemanticError` at the value's pointer (`/url`, `/custom_headers/X-A`, `/recipients/0`), not `ErrUnknownName`. `"custom_headers":null` and `"recipients":null` still decode to a nil map and nil slice.
- **Masking unchanged.** `audit.RedactChannelConfig`, `channelResponseConfig`, `channelAuditState` and `resolveMaskedChannelConfig` still handle arbitrary stored maps, so rows written earlier keep their extra keys masked on display.

## Gotchas discovered

- `DefaultOptionsV1` lives in `encoding/json`, not `encoding/json/v2`; `jsonv2.DefaultOptionsV1` does not compile.
- An unmarshaler built with `UnmarshalFromFunc` hands a value back to default decoding by returning `errors.ErrUnsupported`; `encoding/json/v2` has no `SkipFunc` sentinel.
- v2 type-error messages name the JSON kind, Go type and pointer, not the value (probed on go1.27.4 with number, boolean, object and string mismatches), so a parse error does not echo a stored header value or URL.
- `noctx` refuses `net.Listen` in tests; use `(&net.ListenConfig{}).Listen(ctx, ...)`.

## Quality checks

- Break-tests: with the parser made case-insensitive and `deliverWebhook` ignoring the parse error, both worker tests failed (an SMTP connection was made and the delivery stayed `pending`; the webhook delivery was retried on an empty URL). With `testWebhookChannel` ignoring the parse error, `TestChannelTest_Webhook_StoredConfigRefused` failed (the error was the withheld-cause message). All pass on the real code.
- `go test ./internal/notify/ -count=1`: pass (101 top-level tests).
- `go test ./internal/api/ -run 'TestChannel|TestPatchChannel|TestCreateChannel|TestTestChannel' -count=1 -v`: 40 top-level tests pass, 0 fail.
- `golangci-lint run --allow-parallel-runners ./internal/notify/... ./internal/api/...`: 0 issues.
- Null-string fix: the `null` header value, `null` URL and `null` recipient rows failed before the unmarshaler was added and pass after; `go test ./internal/notify/ -run 'TestParse' -count=1` passes, as do `TestWorker_EmailConfigCaseVariantFailsPermanently`, `TestWorker_WebhookHeaderNotStringFailsPermanently` and `TestChannelWebhookConfig_CustomHeadersReachReceiver`; lint of both packages: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
