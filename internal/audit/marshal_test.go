// ABOUTME: Unit tests for marshalState edge cases not covered by Writer integration tests.
// ABOUTME: Internal package test to access unexported marshalState function.
package audit

import (
	"encoding/json"
	"testing"
)

func TestMarshalState_StructInput(t *testing.T) {
	t.Parallel()
	// Handlers pass structs (e.g., alertRuleToEntry result). marshalState should
	// marshal to JSON, unmarshal to map, redact, then re-marshal.
	type fakeEntry struct {
		Name          string `json:"name"`
		SigningSecret string `json:"signing_secret"`
	}
	got, err := marshalState("channel", fakeEntry{Name: "test", SigningSecret: "hunter2"})
	if err != nil {
		t.Fatalf("marshalState: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if m["signing_secret"] != "[REDACTED]" {
		t.Errorf("signing_secret: got %v, want [REDACTED]", m["signing_secret"])
	}
	if m["name"] != "test" {
		t.Errorf("name: got %v, want test", m["name"])
	}
}

func TestMarshalState_NonObjectJSON(t *testing.T) {
	t.Parallel()
	// A string value can't be unmarshalled to map — should be returned as-is.
	got, err := marshalState("alert_rule", "just a string")
	if err != nil {
		t.Fatalf("marshalState: %v", err)
	}
	var s string
	if err := json.Unmarshal(got, &s); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if s != "just a string" {
		t.Errorf("got %q, want %q", s, "just a string")
	}
}

func TestMarshalState_Nil(t *testing.T) {
	t.Parallel()
	got, err := marshalState("alert_rule", nil)
	if err != nil {
		t.Fatalf("marshalState: %v", err)
	}
	if got != nil {
		t.Errorf("got %s, want nil", string(got))
	}
}
