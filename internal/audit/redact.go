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

// redactSecrets returns a copy of state with sensitive fields replaced by "[REDACTED]".
// For entityType "channel", the "url" field is reduced to scheme+host only.
// Recurses into nested map[string]any values.
func redactSecrets(entityType string, state map[string]any) map[string]any {
	if state == nil {
		return nil
	}
	out := make(map[string]any, len(state))
	for k, v := range state {
		if isSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}
		if entityType == "channel" && strings.EqualFold(k, "url") {
			if s, ok := v.(string); ok {
				out[k] = redactURL(s)
				continue
			}
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

// redactURL extracts scheme+host from a URL, replacing the path with "***".
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[REDACTED]"
	}
	return u.Scheme + "://" + u.Host + "/***"
}
