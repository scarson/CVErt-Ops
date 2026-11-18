// ABOUTME: Write-time secret redaction for audit log old_state/new_state fields.
// ABOUTME: Keyword-based substring matching with special URL handling for channels.
package audit

import (
	"net/url"
	"strings"
)

// sensitiveKeywords are case-insensitive substrings that trigger redaction.
var sensitiveKeywords = []string{
	"secret",
	"password",
	"api_key",
	"token",
	"private_key",
	"key_hash",
}

// RedactedValue replaces a secret value in audit state and API responses.
const RedactedValue = "[REDACTED]"

// RedactChannelConfig returns a copy of a notification channel's config with
// secrets masked. Audit records and API responses both show this view. Config
// accepts any keys and delivery reads only url, custom_headers and recipients,
// so the value of any other key is masked whole: its shape cannot be trusted.
func RedactChannelConfig(config map[string]any) map[string]any {
	out := make(map[string]any, len(config))
	for k, v := range config {
		switch {
		case isChannelHeadersKey(k):
			out[k] = redactHeaderValues(v)
		case k == "url":
			if s, ok := v.(string); ok {
				out[k] = RedactURL(s)
				continue
			}
			out[k] = RedactedValue
		case k == "recipients" && isAddressList(v):
			out[k] = v
		default:
			out[k] = RedactedValue
		}
	}
	return out
}

// redactSecrets returns a copy of state with sensitive fields replaced by "[REDACTED]".
// For entityType "channel", the "url" field is reduced to scheme+host only and every
// header value is masked, because any header can carry a credential.
// Recurses into nested map[string]any values.
func redactSecrets(entityType string, state map[string]any) map[string]any {
	if state == nil {
		return nil
	}
	out := make(map[string]any, len(state))
	for k, v := range state {
		if isSensitiveKey(k) {
			out[k] = RedactedValue
			continue
		}
		if entityType == "channel" && strings.EqualFold(k, "url") {
			if s, ok := v.(string); ok {
				out[k] = RedactURL(s)
				continue
			}
		}
		if entityType == "channel" && isChannelHeadersKey(k) {
			out[k] = redactHeaderValues(v)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = redactSecrets(entityType, nested)
			continue
		}
		if list, ok := v.([]any); ok {
			out[k] = redactList(entityType, list)
			continue
		}
		out[k] = v
	}
	return out
}

// redactList applies redactSecrets to every object in a list, at any depth.
func redactList(entityType string, list []any) []any {
	out := make([]any, len(list))
	for i, element := range list {
		switch v := element.(type) {
		case map[string]any:
			out[i] = redactSecrets(entityType, v)
		case []any:
			out[i] = redactList(entityType, v)
		default:
			out[i] = element
		}
	}
	return out
}

// isSensitiveKey returns true if the key contains any sensitive keyword (case-insensitive).
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isAddressList reports whether value has the shape of email channel recipients:
// a list in which every element is a string containing an address sign.
func isAddressList(value any) bool {
	list, ok := value.([]any)
	if !ok {
		return false
	}
	for _, element := range list {
		address, ok := element.(string)
		if !ok || !strings.Contains(address, "@") {
			return false
		}
	}
	return true
}

// isChannelHeadersKey reports whether a config key holds outbound HTTP headers.
// Delivery reads custom_headers. Stored configs can also hold headers, the key
// the channel test route once read.
func isChannelHeadersKey(key string) bool {
	return strings.EqualFold(key, "custom_headers") || strings.EqualFold(key, "headers")
}

// redactHeaderValues keeps header names and masks every value. A value that is
// not a header map is masked whole.
func redactHeaderValues(headers any) any {
	m, ok := headers.(map[string]any)
	if !ok {
		return RedactedValue
	}
	out := make(map[string]any, len(m))
	for name := range m {
		out[name] = RedactedValue
	}
	return out
}

// RedactURL extracts scheme+host from a URL, replacing the path with "***".
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return RedactedValue
	}
	return u.Scheme + "://" + u.Host + "/***"
}
