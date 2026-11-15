// ABOUTME: Typed notification channel config, its decoder, and the content checks that API validation and delivery share.
// ABOUTME: Names match case-sensitively and keys delivery does not read are refused, so what is validated is what is used.
package notify

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strings"
)

// maxEmailRecipients is the most recipients an email channel may have.
const maxEmailRecipients = 50

// ErrWebhookNoURL reports webhook settings with a missing or blank url.
var ErrWebhookNoURL = errors.New("webhook config must include a non-empty url")

// HeaderError reports a custom header that delivery cannot send. Message is
// fixed text and never contains the header's value.
type HeaderError struct {
	Name    string // the header name as stored in custom_headers
	Message string
}

func (e *HeaderError) Error() string {
	return fmt.Sprintf("custom header %q: %s", e.Name, e.Message)
}

// CheckWebhookSettings reports settings that delivery cannot send: a blank url
// (ErrWebhookNoURL), or a custom header (*HeaderError) whose name is not an RFC
// 9110 token, whose value holds a control character, that sets a header Send
// computes itself, or whose name equals another's apart from letter case.
// Headers are checked in name order, so the same config reports the same header.
func CheckWebhookSettings(s WebhookSettings) error {
	if strings.TrimSpace(s.URL) == "" {
		return ErrWebhookNoURL
	}
	names := make([]string, 0, len(s.CustomHeaders))
	for name := range s.CustomHeaders {
		names = append(names, name)
	}
	slices.Sort(names)
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		canonical := http.CanonicalHeaderKey(name)
		switch {
		case !isHeaderToken(name):
			return &HeaderError{Name: name, Message: "custom_headers name is not a valid header name"}
		case !isHeaderValue(s.CustomHeaders[name]):
			return &HeaderError{Name: name, Message: "custom_headers value contains a control character"}
		case deniedHeaders[strings.ToLower(name)]:
			return &HeaderError{Name: name, Message: "custom_headers cannot set " + canonical}
		case seen[canonical]:
			return &HeaderError{Name: name, Message: "custom_headers names must differ by more than letter case"}
		}
		seen[canonical] = true
	}
	return nil
}

// isHeaderToken reports whether name is a non-empty RFC 9110 token, the form
// of a header field name.
func isHeaderToken(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isAlnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !isAlnum && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// isHeaderValue reports whether value can be sent as a header field value: no
// control character other than horizontal tab, and no DEL.
func isHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// RecipientError reports email recipients that delivery refuses. Problem is
// fixed text that names no recipient; Error adds the recipient when there is one.
type RecipientError struct {
	Problem string
	detail  string
}

func (e *RecipientError) Error() string {
	if e.detail != "" {
		return e.detail
	}
	return e.Problem
}

// CheckEmailRecipients reports a recipient list delivery refuses: empty, more
// than maxEmailRecipients, an entry that is not an RFC 5322 address, or two
// entries with the same address ignoring letter case.
func CheckEmailRecipients(recipients []string) error {
	if len(recipients) == 0 {
		return &RecipientError{Problem: "email config must include at least one recipient"}
	}
	if len(recipients) > maxEmailRecipients {
		return &RecipientError{Problem: fmt.Sprintf("email config must not exceed %d recipients", maxEmailRecipients)}
	}
	seen := make(map[string]bool, len(recipients))
	for _, r := range recipients {
		addr, err := mail.ParseAddress(r)
		if err != nil {
			return &RecipientError{Problem: "invalid email recipient", detail: fmt.Sprintf("invalid email recipient %q: %v", r, err)}
		}
		normalized := strings.ToLower(addr.Address)
		if seen[normalized] {
			return &RecipientError{Problem: "duplicate email recipient", detail: "duplicate email recipient: " + normalized}
		}
		seen[normalized] = true
	}
	return nil
}

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
