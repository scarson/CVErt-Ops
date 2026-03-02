// ABOUTME: Tests for write-time secret redaction in audit log entries.
// ABOUTME: Verifies keyword matching, case-insensitivity, nesting, and URL domain extraction.
package audit

import (
	"testing"
)

func TestRedactSecrets_FieldNames(t *testing.T) {
	t.Parallel()
	// All keyword matches should be redacted.
	keywords := []string{"secret", "password", "api_key", "token", "private_key", "key_hash"}
	for _, kw := range keywords {
		state := map[string]any{kw: "sensitive-value-123"}
		got := redactSecrets("alert_rule", state)
		if got[kw] != "[REDACTED]" {
			t.Errorf("keyword %q: got %v, want [REDACTED]", kw, got[kw])
		}
	}
}

func TestRedactSecrets_CaseInsensitive(t *testing.T) {
	t.Parallel()
	state := map[string]any{
		"Signing_Secret": "abc123",
		"PASSWORD":       "hunter2",
	}
	got := redactSecrets("channel", state)
	if got["Signing_Secret"] != "[REDACTED]" {
		t.Errorf("Signing_Secret: got %v, want [REDACTED]", got["Signing_Secret"])
	}
	if got["PASSWORD"] != "[REDACTED]" {
		t.Errorf("PASSWORD: got %v, want [REDACTED]", got["PASSWORD"])
	}
}

func TestRedactSecrets_SubstringMatch(t *testing.T) {
	t.Parallel()
	state := map[string]any{
		"webhook_signing_secret": "secret-val",
		"auth_token_v2":          "tok-val",
	}
	got := redactSecrets("channel", state)
	if got["webhook_signing_secret"] != "[REDACTED]" {
		t.Errorf("webhook_signing_secret: got %v, want [REDACTED]", got["webhook_signing_secret"])
	}
	if got["auth_token_v2"] != "[REDACTED]" {
		t.Errorf("auth_token_v2: got %v, want [REDACTED]", got["auth_token_v2"])
	}
}

func TestRedactSecrets_NestedJSON(t *testing.T) {
	t.Parallel()
	state := map[string]any{
		"config": map[string]any{
			"api_key": "nested-secret",
			"name":    "visible",
		},
	}
	got := redactSecrets("channel", state)
	nested, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("config: expected map[string]any, got %T", got["config"])
	}
	if nested["api_key"] != "[REDACTED]" {
		t.Errorf("nested api_key: got %v, want [REDACTED]", nested["api_key"])
	}
	if nested["name"] != "visible" {
		t.Errorf("nested name: got %v, want visible", nested["name"])
	}
}

func TestRedactSecrets_ChannelURL(t *testing.T) {
	t.Parallel()
	state := map[string]any{
		"url": "https://hooks.slack.com/services/T00/B00/xxxx",
	}
	got := redactSecrets("channel", state)
	if got["url"] != "https://hooks.slack.com/***" {
		t.Errorf("channel url: got %v, want https://hooks.slack.com/***", got["url"])
	}
}

func TestRedactSecrets_NonChannelURLUntouched(t *testing.T) {
	t.Parallel()
	// For non-channel entities, url field should NOT be redacted.
	state := map[string]any{
		"url": "https://example.com/path",
	}
	got := redactSecrets("alert_rule", state)
	if got["url"] != "https://example.com/path" {
		t.Errorf("non-channel url: got %v, want unchanged", got["url"])
	}
}

func TestRedactSecrets_PreservesNonSecret(t *testing.T) {
	t.Parallel()
	state := map[string]any{
		"name":        "My Rule",
		"description": "A rule",
		"enabled":     true,
		"count":       42,
	}
	got := redactSecrets("alert_rule", state)
	if got["name"] != "My Rule" {
		t.Errorf("name: got %v, want My Rule", got["name"])
	}
	if got["description"] != "A rule" {
		t.Errorf("description: got %v, want A rule", got["description"])
	}
	if got["enabled"] != true {
		t.Errorf("enabled: got %v, want true", got["enabled"])
	}
	if got["count"] != 42 {
		t.Errorf("count: got %v, want 42", got["count"])
	}
}

func TestRedactSecrets_NilState(t *testing.T) {
	t.Parallel()
	got := redactSecrets("channel", nil)
	if got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
}

func TestRedactSecrets_EmptyMap(t *testing.T) {
	t.Parallel()
	got := redactSecrets("channel", map[string]any{})
	if got == nil {
		t.Error("empty input: got nil, want empty map")
	}
	if len(got) != 0 {
		t.Errorf("empty input: got %d entries, want 0", len(got))
	}
}
