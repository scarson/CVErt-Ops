// ABOUTME: Typed notification channel config and the one decoder that API validation and delivery share.
// ABOUTME: Names match case-sensitively and keys delivery does not read are refused, so what is validated is what is used.
package notify

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
)

// WebhookSettings is the config JSON stored for a webhook channel.
// WebhookConfig (webhook.go) is the delivery-time view built from it plus the
// channel's signing secrets.
type WebhookSettings struct {
	URL           string            `json:"url"`
	CustomHeaders map[string]string `json:"custom_headers,omitzero"`
}

// EmailSettings is the config JSON stored for an email channel.
type EmailSettings struct {
	Recipients []string `json:"recipients"`
}

// channelConfigOptions: v2 defaults (case-sensitive names, no duplicates,
// valid UTF-8) plus refusal of keys this type does not define and of null
// where a string is expected. v2 decodes null into a string as "" without
// error, which would deliver an empty header value, recipient or URL.
var channelConfigOptions = jsonv2.JoinOptions(
	jsonv2.RejectUnknownMembers(true),
	jsonv2.WithUnmarshalers(jsonv2.UnmarshalFromFunc(refuseNullString)),
)

// errConfigNotObject reports a config that is not a JSON object.
var errConfigNotObject = errors.New("config must be a JSON object")

// errNullString reports JSON null where the config expects a string.
var errNullString = errors.New("null is not a string")

// refuseNullString refuses JSON null for a string target and leaves every
// other value to the default decoding (errors.ErrUnsupported).
func refuseNullString(dec *jsontext.Decoder, _ *string) error {
	if dec.PeekKind() == jsontext.KindNull {
		return errNullString
	}
	return errors.ErrUnsupported
}

// ParseWebhookSettings decodes a webhook channel's config JSON. A decode error
// is returned as jsonv2 reports it, so callers can read its *jsonv2.SemanticError
// and JSONPointer.
func ParseWebhookSettings(raw []byte) (WebhookSettings, error) {
	return parseChannelSettings[WebhookSettings](raw)
}

// ParseEmailSettings decodes an email channel's config JSON. A decode error
// is returned as jsonv2 reports it, so callers can read its *jsonv2.SemanticError
// and JSONPointer.
func ParseEmailSettings(raw []byte) (EmailSettings, error) {
	return parseChannelSettings[EmailSettings](raw)
}

// parseChannelSettings decodes raw into T with channelConfigOptions. The kind is
// checked first because v2 decodes null into a struct without error.
func parseChannelSettings[T any](raw []byte) (T, error) {
	var cfg T
	if jsontext.Value(raw).Kind() != '{' {
		return cfg, errConfigNotObject
	}
	err := jsonv2.Unmarshal(raw, &cfg, channelConfigOptions)
	return cfg, err
}
