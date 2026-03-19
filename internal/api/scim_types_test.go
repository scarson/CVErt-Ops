// ABOUTME: Tests for SCIM 2.0 response types, error helper, bool parser, and filter parser.
// ABOUTME: Validates RFC 7644 compliance for error format and content type.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteSCIMError(t *testing.T) {
	t.Parallel()

	t.Run("full error with scimType", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		writeSCIMError(w, http.StatusConflict, "uniqueness", "userName already exists")

		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
		}

		ct := w.Header().Get("Content-Type")
		if ct != "application/scim+json" {
			t.Errorf("Content-Type = %q, want %q", ct, "application/scim+json")
		}

		var body SCIMError
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if len(body.Schemas) != 1 || body.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
			t.Errorf("schemas = %v, want error schema", body.Schemas)
		}
		if body.Status != "409" {
			t.Errorf("status = %q, want %q", body.Status, "409")
		}
		if body.SCIMType != "uniqueness" {
			t.Errorf("scimType = %q, want %q", body.SCIMType, "uniqueness")
		}
		if body.Detail != "userName already exists" {
			t.Errorf("detail = %q, want %q", body.Detail, "userName already exists")
		}
	})

	t.Run("scimType omitted when empty", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		writeSCIMError(w, http.StatusForbidden, "", "SCIM provisioning is disabled")

		raw := w.Body.Bytes()
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, exists := m["scimType"]; exists {
			t.Error("scimType should be omitted when empty")
		}
	})
}

func TestWriteSCIMJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	writeSCIMJSON(w, http.StatusCreated, map[string]string{"key": "value"})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/scim+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/scim+json")
	}

	var m map[string]string
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["key"] != "value" {
		t.Errorf("body key = %q, want %q", m["key"], "value")
	}
}

func TestParseSCIMBool_JSONBool(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input json.RawMessage
		want  bool
	}{
		{json.RawMessage(`true`), true},
		{json.RawMessage(`false`), false},
	}

	for _, tc := range cases {
		got, err := parseSCIMBool(tc.input)
		if err != nil {
			t.Errorf("parseSCIMBool(%s) error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("parseSCIMBool(%s) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseSCIMBool_StringBool(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input json.RawMessage
		want  bool
	}{
		{json.RawMessage(`"True"`), true},
		{json.RawMessage(`"False"`), false},
		{json.RawMessage(`"true"`), true},
		{json.RawMessage(`"false"`), false},
	}

	for _, tc := range cases {
		got, err := parseSCIMBool(tc.input)
		if err != nil {
			t.Errorf("parseSCIMBool(%s) error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("parseSCIMBool(%s) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseSCIMBool_Invalid(t *testing.T) {
	t.Parallel()

	cases := []json.RawMessage{
		json.RawMessage(`"invalid"`),
		json.RawMessage(`123`),
	}

	for _, input := range cases {
		_, err := parseSCIMBool(input)
		if err == nil {
			t.Errorf("parseSCIMBool(%s) expected error, got nil", input)
		}
	}
}

func TestParseSCIMFilter_SingleEq(t *testing.T) {
	t.Parallel()

	exprs, err := parseSCIMFilter(`userName eq "sam@example.com"`)
	if err != nil {
		t.Fatalf("parseSCIMFilter error: %v", err)
	}
	if len(exprs) != 1 {
		t.Fatalf("got %d expressions, want 1", len(exprs))
	}
	if exprs[0].Attr != "userName" {
		t.Errorf("attr = %q, want %q", exprs[0].Attr, "userName")
	}
	if exprs[0].Op != "eq" {
		t.Errorf("op = %q, want %q", exprs[0].Op, "eq")
	}
	if exprs[0].Value != "sam@example.com" {
		t.Errorf("value = %q, want %q", exprs[0].Value, "sam@example.com")
	}
}

func TestParseSCIMFilter_Compound(t *testing.T) {
	t.Parallel()

	exprs, err := parseSCIMFilter(`userName eq "sam" and active eq "true"`)
	if err != nil {
		t.Fatalf("parseSCIMFilter error: %v", err)
	}
	if len(exprs) != 2 {
		t.Fatalf("got %d expressions, want 2", len(exprs))
	}
	if exprs[0].Attr != "userName" || exprs[0].Value != "sam" {
		t.Errorf("expr[0] = %+v, want userName eq sam", exprs[0])
	}
	if exprs[1].Attr != "active" || exprs[1].Value != "true" {
		t.Errorf("expr[1] = %+v, want active eq true", exprs[1])
	}
}

func TestParseSCIMFilter_UnsupportedOp(t *testing.T) {
	t.Parallel()

	_, err := parseSCIMFilter(`userName sw "sam"`)
	if err == nil {
		t.Fatal("expected error for unsupported operator")
	}
	if got := err.Error(); !contains(got, "sw") {
		t.Errorf("error %q should mention unsupported operator %q", got, "sw")
	}
}

func TestParseSCIMFilter_Empty(t *testing.T) {
	t.Parallel()

	exprs, err := parseSCIMFilter("")
	if err != nil {
		t.Fatalf("parseSCIMFilter error: %v", err)
	}
	if len(exprs) != 0 {
		t.Errorf("got %d expressions, want 0", len(exprs))
	}
}

func TestSCIMUser_JSON(t *testing.T) {
	t.Parallel()

	user := SCIMUser{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:          "abc-123",
		ExternalID:  "ext-456",
		UserName:    "sam@example.com",
		DisplayName: "Sam",
		Active:      true,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      "2026-01-01T00:00:00Z",
			LastModified: "2026-01-02T00:00:00Z",
			Location:     "/scim/v2/Users/abc-123",
		},
	}

	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	schemas, ok := m["schemas"].([]any)
	if !ok || len(schemas) != 1 {
		t.Errorf("schemas = %v, want 1-element array", m["schemas"])
	}

	meta, ok := m["meta"].(map[string]any)
	if !ok {
		t.Fatalf("meta is not an object: %T", m["meta"])
	}
	if meta["resourceType"] != "User" {
		t.Errorf("meta.resourceType = %v, want %q", meta["resourceType"], "User")
	}

	if m["userName"] != "sam@example.com" {
		t.Errorf("userName = %v, want %q", m["userName"], "sam@example.com")
	}
	if m["active"] != true {
		t.Errorf("active = %v, want true", m["active"])
	}
}

// contains is a small helper to avoid importing strings in the test file
// (since the production code already imports it).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
