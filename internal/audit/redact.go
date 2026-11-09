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
// secrets masked. Audit records and API responses both show this view.
func RedactChannelConfig(config map[string]any) map[string]any {
	return redactSecrets("channel", config)
}

// redactSecrets returns a copy of state with sensitive fields replaced by "[REDACTED]".
// For entityType "channel", the "url" field is reduced to scheme+host only and every
// "custom_headers" value is masked, because any header can carry a credential.
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
		if entityType == "channel" && strings.EqualFold(k, "custom_headers") {
			out[k] = redactHeaderValues(v)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = redactSecrets(entityType, nested)
			continue
		}
		out[k] = v
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
