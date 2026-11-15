// ABOUTME: Tests for SCIM 2.0 response types, error helper, body decoder, bool parser, and filter parser.
// ABOUTME: Validates RFC 7644 compliance for error format and content type.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// assertSCIMBadRequest checks that w holds a 400 SCIM error with the given
// scimType and the detail "invalid JSON body".
func assertSCIMBadRequest(t *testing.T, w *httptest.ResponseRecorder, wantSCIMType string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var body SCIMError
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Status != "400" {
		t.Errorf("status field = %q, want %q", body.Status, "400")
	}
	if body.SCIMType != wantSCIMType {
		t.Errorf("scimType = %q, want %q", body.SCIMType, wantSCIMType)
	}
	if body.Detail != "invalid JSON body" {
		t.Errorf("detail = %q, want %q", body.Detail, "invalid JSON body")
	}
}

func TestDecodeSCIMBody_Refused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{"case-variant duplicate attribute", `{"userName":"a","USERNAME":"b"}`},
		{"exact duplicate attribute", `{"userName":"a","userName":"b"}`},
		{"trailing second value", `{"userName":"a"} {"userName":"b"}`},
		{"invalid UTF-8 in a string", `{"userName":"a` + string([]byte{0xff}) + `b"}`},
		{"empty body", ``},
		{"malformed JSON", `{"userName":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, scimType := range []string{"", "invalidValue"} {
				w := httptest.NewRecorder()
				r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/Users", strings.NewReader(tc.body))
				var req scimUserRequest
				if decodeSCIMBody(w, r, &req, scimType) {
					t.Fatalf("decodeSCIMBody(%q) = true, want false (decoded %+v)", tc.body, req)
				}
				assertSCIMBadRequest(t, w, scimType)
			}
		})
	}
}

func TestDecodeSCIMBody_Accepted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		body           string
		wantUserName   string
		wantExternalID string
	}{
		{"attribute names match case-insensitively", `{"UserName":"a","externalId":"x"}`, "a", "x"},
		{"underscore names are not folded onto attributes", `{"userName":"a","user_name":"b","external_id":"x"}`, "a", ""},
		{"dash names are not folded onto attributes", `{"userName":"a","user-name":"b","external-id":"x"}`, "a", ""},
		{
			"unknown extension attributes are ignored",
			`{"userName":"a","externalId":"x","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"x"}}`,
			"a", "x",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/Users", strings.NewReader(tc.body))
			var req scimUserRequest
			if !decodeSCIMBody(w, r, &req, "") {
				t.Fatalf("decodeSCIMBody(%q) = false, want true (response: %s)", tc.body, w.Body.String())
			}
			if req.UserName != tc.wantUserName {
				t.Errorf("UserName = %q, want %q", req.UserName, tc.wantUserName)
			}
			if req.ExternalID != tc.wantExternalID {
				t.Errorf("ExternalID = %q, want %q", req.ExternalID, tc.wantExternalID)
			}
			if w.Body.Len() != 0 {
				t.Errorf("response body written on success: %s", w.Body.String())
			}
		})
	}
}

// TestDecodeSCIMBody_OversizedBody checks that a body cut off by
// http.MaxBytesReader (as middleware.RequestSize applies to every route) is
// refused with a 400 rather than decoded or left waiting.
func TestDecodeSCIMBody_OversizedBody(t *testing.T) {
	t.Parallel()

	body := `{"userName":"a","displayName":"` + strings.Repeat("x", 2048) + `"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/Users", strings.NewReader(body))
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var req scimUserRequest
	if decodeSCIMBody(w, r, &req, "") {
		t.Fatal("decodeSCIMBody = true for a body over the size limit, want false")
	}
	assertSCIMBadRequest(t, w, "")
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
