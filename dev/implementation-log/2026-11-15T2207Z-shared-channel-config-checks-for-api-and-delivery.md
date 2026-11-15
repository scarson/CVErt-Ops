# Shared channel config checks for API and delivery

## What was built

| Feature | Files | Description |
|---|---|---|
| Webhook settings check | `internal/notify/channel_config.go` (`CheckWebhookSettings`, `ErrWebhookNoURL`, `HeaderError`) | Refuses a missing or blank url, and a custom header whose name is not an RFC 9110 token, whose value has a control character other than tab (CR, LF, NUL, DEL included, as `httpguts.ValidHeaderFieldValue` refuses), that sets a header in `deniedHeaders`, or whose name equals another's under `http.CanonicalHeaderKey`. Names are checked in sorted order, so of two invalid headers the first by name is reported. `HeaderError.Message` is fixed text and never holds the value; `Error()` is `<message> (header "<name>")`. `deniedHeaders` also holds the hop-by-hop names `upgrade`, `keep-alive`, `proxy-connection`, `te` and `trailer`. |
| Email recipient check | `internal/notify/channel_config.go` (`CheckEmailRecipients`, `RecipientError`) | The recipient-count (at most 50), RFC 5322 and case-insensitive duplicate checks, moved from the API. `Error()` returns `Problem`, which names no recipient; `Detail()` adds the recipient and is used only by the API's create/PATCH validation, whose messages are unchanged. |
| Delivery | `internal/notify/webhook.go` (`ChannelWebhookConfig`), `internal/notify/worker.go` (`deliverEmail`) | `ChannelWebhookConfig` runs `CheckWebhookSettings`; `deliverEmail` runs `CheckEmailRecipients`. Both failures are permanent. `Send` still filters `deniedHeaders` for a `WebhookConfig` built another way. |
| API | `internal/api/channels.go` (`validateWebhookConfig`, `validateEmailConfig`, `readEmailRecipients`, `testEmailChannel`) | A header error is reported at `body.config.custom_headers.<name>` (at `body.config.custom_headers` for an empty name) with the `HeaderError` message. A blank url is matched with `errors.Is(err, notify.ErrWebhookNoURL)` and reported with that error's text, the same text the parse-error `/url` case uses. The `config` doc strings state the url, recipient and header rules and list the reserved names. Email messages and locations are unchanged. The channel test endpoint reports a refused stored email config as "stored email config is invalid: <problem>" without the recipient. |
| Tests | `internal/notify/channel_config_test.go`, `internal/notify/webhook_test.go`, `internal/notify/worker_test.go`, `internal/api/channels_test.go` | `TestCheckWebhookSettings`, `TestCheckEmailRecipients`, `TestChannelWebhookConfig_RefusesWhatDeliveryCannotSend`, `TestWorker_WebhookBlankURLFailsPermanently`, `TestWorker_WebhookReservedHeaderFailsPermanently`, `TestWorker_EmailRecipientInvalidFailsPermanently`, `TestTestEmailChannel_StoredConfigErrorNamesNoRecipient`; six header rows added to `TestChannelConfig_ParseErrors`, which now runs on the enterprise tier, fails explicitly on 429, and checks that no refused PATCH changed stored config. |

## Key decisions

- **No new dependency.** `golang.org/x/net/http/httpguts` is only an indirect dependency, so the token and field-value checks are small local functions.
- **Delivery errors name no recipient.** `deliverEmail` wraps a recipient error in `permanentDeliveryError`, which `ErrorForOrg` passes to `last_error_for_org`, readable by org viewers through GET /deliveries; `audit.RedactChannelConfig` masks a stored recipient that lacks '@', so naming it there would expose a value the channel responses hide. `TestWorker_EmailRecipientInvalidFailsPermanently` checks both recorded errors.
- **Reserved headers refused, not dropped.** A header in `deniedHeaders` used to be dropped silently at send time; it is now refused at the API and fails delivery permanently, so the stored config and what is sent agree.

## Gotchas discovered

- A header value with `\u0000` reached Postgres before this change and made create and PATCH return 500 (JSONB refuses NUL); it is now a 422.
- Without the checks, a blank url failed delivery with `unsupported protocol scheme ""` and was retried, and an invalid recipient failed at SMTP (`set bcc`) and was retried.

## Quality checks

- Break-test: with `CheckWebhookSettings` skipped in `ChannelWebhookConfig` and `CheckEmailRecipients` skipped in `deliverEmail`, the four new delivery tests failed (pending status, a reserved header delivered, retries); all pass on the real code.
- Recipient leak: before `Error()` was reduced to `Problem`, `TestWorker_EmailRecipientInvalidFailsPermanently` failed with the recipient in `last_error` and `last_error_for_org`, and `TestCheckEmailRecipients` failed on `Error()`.
- `go test ./internal/notify/ -count=1`: pass.
- `go test ./internal/api/ -run 'TestChannel|TestCreateChannel|TestPatchChannel|TestValidateChannelConfig|TestTestEmailChannel|TestOpenAPISpec' -count=1 -v`: 55 top-level tests pass, 0 fail.
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/notify/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
