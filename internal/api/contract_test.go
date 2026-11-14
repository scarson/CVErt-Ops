// ABOUTME: Unit tests for shared contract helpers.
// ABOUTME: Verifies RFC 9457 output matches huma's ErrorModel format field-for-field.
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestWriteProblem_MatchesHumaFormat(t *testing.T) {
	humaErr := huma.Error400BadRequest("name is required")
	humaJSON, _ := json.Marshal(humaErr)

	rec := httptest.NewRecorder()
	writeProblem(rec, http.StatusBadRequest, "name is required")
	chiJSON := rec.Body.Bytes()

	var humaMap, chiMap map[string]any
	if err := json.Unmarshal(humaJSON, &humaMap); err != nil {
		t.Fatalf("unmarshal huma: %v", err)
	}
	if err := json.Unmarshal(chiJSON, &chiMap); err != nil {
		t.Fatalf("unmarshal chi: %v", err)
	}

	if _, hasType := chiMap["type"]; hasType {
		t.Error("writeProblem must NOT emit 'type' field (huma omits it)")
	}

	for _, key := range []string{"title", "status", "detail"} {
		if chiMap[key] != humaMap[key] {
			t.Errorf("field %q: got %v, want %v", key, chiMap[key], humaMap[key])
		}
	}

	if len(chiMap) != len(humaMap) {
		t.Errorf("key count: got %d, want %d\n  chi: %v\n  huma: %v",
			len(chiMap), len(humaMap), chiMap, humaMap)
	}
}

func TestWriteValidationProblem_MatchesHumaFormat(t *testing.T) {
	humaErr := huma.Error422UnprocessableEntity("validation failed",
		&huma.ErrorDetail{Message: "too short", Location: "body.name", Value: "a"})
	humaJSON, _ := json.Marshal(humaErr)

	rec := httptest.NewRecorder()
	writeProblemWithErrors(rec, http.StatusUnprocessableEntity, "validation failed",
		&huma.ErrorDetail{Message: "too short", Location: "body.name", Value: "a"})
	chiJSON := rec.Body.Bytes()

	var humaMap, chiMap map[string]any
	if err := json.Unmarshal(humaJSON, &humaMap); err != nil {
		t.Fatalf("unmarshal huma: %v", err)
	}
	if err := json.Unmarshal(chiJSON, &chiMap); err != nil {
		t.Fatalf("unmarshal chi: %v", err)
	}

	for _, key := range []string{"title", "status", "detail"} {
		if chiMap[key] != humaMap[key] {
			t.Errorf("field %q: got %v, want %v", key, chiMap[key], humaMap[key])
		}
	}

	chiErrors, _ := chiMap["errors"].([]any)
	humaErrors, _ := humaMap["errors"].([]any)
	if len(chiErrors) != len(humaErrors) {
		t.Fatalf("errors length: got %d, want %d", len(chiErrors), len(humaErrors))
	}
	chiErr0, _ := chiErrors[0].(map[string]any)
	humaErr0, _ := humaErrors[0].(map[string]any)
	for _, key := range []string{"message", "location", "value"} {
		if fmt.Sprint(chiErr0[key]) != fmt.Sprint(humaErr0[key]) {
			t.Errorf("errors[0].%s: got %v, want %v", key, chiErr0[key], humaErr0[key])
		}
	}
}

func TestWriteProblem_ParityAcrossStatusCodes(t *testing.T) {
	cases := []struct {
		status   int
		detail   string
		humaFunc func(string, ...error) huma.StatusError
	}{
		{400, "bad request", huma.Error400BadRequest},
		{401, "not authenticated", huma.Error401Unauthorized},
		{403, "forbidden", huma.Error403Forbidden},
		{404, "not found", huma.Error404NotFound},
		{429, "rate limit exceeded", huma.Error429TooManyRequests},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d", tc.status), func(t *testing.T) {
			humaErr := tc.humaFunc(tc.detail)
			humaJSON, _ := json.Marshal(humaErr)

			rec := httptest.NewRecorder()
			writeProblem(rec, tc.status, tc.detail)
			chiJSON := rec.Body.Bytes()

			var humaMap, chiMap map[string]any
			if err := json.Unmarshal(humaJSON, &humaMap); err != nil {
				t.Fatalf("unmarshal huma: %v", err)
			}
			if err := json.Unmarshal(chiJSON, &chiMap); err != nil {
				t.Fatalf("unmarshal chi: %v", err)
			}

			for _, key := range []string{"title", "status", "detail"} {
				if chiMap[key] != humaMap[key] {
					t.Errorf("field %q: got %v, want %v", key, chiMap[key], humaMap[key])
				}
			}

			if len(chiMap) != len(humaMap) {
				t.Errorf("key count: got %d, want %d\n  chi: %v\n  huma: %v",
					len(chiMap), len(humaMap), chiMap, humaMap)
			}
		})
	}
}

func TestWriteProblem_ContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	writeProblem(rec, http.StatusNotFound, "not found")
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

func TestWriteProblemTyped_IncludesType(t *testing.T) {
	rec := httptest.NewRecorder()
	writeProblemTyped(rec, http.StatusForbidden, problemTypeTierLimit, "limit reached")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["type"] != problemTypeTierLimit {
		t.Errorf("type = %v, want %s", body["type"], problemTypeTierLimit)
	}
}

// decodeTestBody stands in for a request body struct with a nested object and
// an array of objects, the shapes whose unknown members need a nested location.
type decodeTestBody struct {
	Name  string `json:"name"`
	Inner struct {
		A int `json:"a"`
	} `json:"inner"`
	Items []struct {
		ID string `json:"id"`
	} `json:"items"`
}

// decodeProblem runs decodeJSON on body and returns its result, the response
// status and the decoded problem body (zero when decodeJSON succeeded).
func decodeProblem(t *testing.T, body string, dst any) (bool, int, huma.ErrorModel) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ok := decodeJSON(rec, r, dst)
	var problem huma.ErrorModel
	if !ok {
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("Content-Type = %q, want application/problem+json", ct)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
			t.Fatalf("decode problem body %q: %v", rec.Body.String(), err)
		}
	}
	return ok, rec.Code, problem
}

func TestDecodeJSON_MalformedInput(t *testing.T) {
	ok, status, problem := decodeProblem(t, "{bad", &struct{}{})
	if ok {
		t.Fatal("decodeJSON accepted malformed JSON")
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	if len(problem.Errors) != 1 || problem.Errors[0].Location != "body" {
		t.Errorf("errors = %+v, want one error at location body", problem.Errors)
	}
}

// TestDecodeJSON_TrailingData verifies that a second JSON value after the body
// is refused rather than ignored.
func TestDecodeJSON_TrailingData(t *testing.T) {
	var dst decodeTestBody
	ok, status, _ := decodeProblem(t, `{"name":"test"} {"name":"other"}`, &dst)
	if ok {
		t.Fatal("decodeJSON accepted a body with a second JSON value")
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestDecodeJSON_ValidInput(t *testing.T) {
	var dst decodeTestBody
	ok, status, problem := decodeProblem(t, `{"name":"test","inner":{"a":1},"items":[{"id":"x"}]}`, &dst)
	if !ok {
		t.Fatalf("decodeJSON refused a valid body: %d %+v", status, problem)
	}
	if dst.Name != "test" || dst.Inner.A != 1 || len(dst.Items) != 1 || dst.Items[0].ID != "x" {
		t.Errorf("decoded %+v", dst)
	}
}

// TestDecodeJSON_UnknownMember verifies that a member the body struct does not
// define is refused with the 422 problem huma writes for a schema with
// additionalProperties false, located with huma's path format.
func TestDecodeJSON_UnknownMember(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantLocation string
	}{
		{name: "misspelled top-level field", body: `{"nme":"test"}`, wantLocation: "body.nme"},
		{name: "field name in another case", body: `{"Name":"test"}`, wantLocation: "body.Name"},
		{name: "nested object member", body: `{"inner":{"b":1}}`, wantLocation: "body.inner.b"},
		{name: "member of an array element", body: `{"items":[{"id":"x"},{"idd":"y"}]}`, wantLocation: "body.items[1].idd"},
		{name: "numeric member name", body: `{"0":"x"}`, wantLocation: "body.0"},
		{name: "schema link inside a nested object", body: `{"inner":{"$schema":"x"}}`, wantLocation: "body.inner.$schema"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst decodeTestBody
			ok, status, problem := decodeProblem(t, tt.body, &dst)
			if ok {
				t.Fatal("decodeJSON accepted a body with an unknown member")
			}
			if status != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want 422", status)
			}
			if problem.Detail != "validation failed" {
				t.Errorf("detail = %q, want %q", problem.Detail, "validation failed")
			}
			if len(problem.Errors) != 1 {
				t.Fatalf("errors = %+v, want exactly one", problem.Errors)
			}
			if got := problem.Errors[0]; got.Location != tt.wantLocation || got.Message != "unexpected property" {
				t.Errorf("error = {message %q, location %q}, want {message %q, location %q}",
					got.Message, got.Location, "unexpected property", tt.wantLocation)
			}
		})
	}
}

// TestDecodeJSON_AcceptsSchemaLink verifies that the top-level "$schema" member,
// which the published request schemas declare as a read-only property, is
// accepted and ignored, as huma-registered operations do.
func TestDecodeJSON_AcceptsSchemaLink(t *testing.T) {
	var dst decodeTestBody
	ok, status, problem := decodeProblem(t, `{"$schema":"https://example.com/schemas/Body.json","name":"test"}`, &dst)
	if !ok {
		t.Fatalf("decodeJSON refused a body with $schema: %d %+v", status, problem)
	}
	if dst.Name != "test" {
		t.Errorf("name = %q, want test", dst.Name)
	}
}

// TestClearableField_Decode verifies that a clearableField tells an omitted
// key, a JSON null and a value apart.
func TestClearableField_Decode(t *testing.T) {
	type body struct {
		GroupID clearableField[string] `json:"group_id,omitempty"`
	}

	tests := []struct {
		name      string
		input     string
		wantSent  bool
		wantValue *string
	}{
		{name: "omitted", input: `{}`, wantSent: false},
		{name: "null", input: `{"group_id":null}`, wantSent: true},
		{name: "value", input: `{"group_id":"g1"}`, wantSent: true, wantValue: new("g1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst body
			if ok, status, problem := decodeProblem(t, tt.input, &dst); !ok {
				t.Fatalf("unexpected error: %d %+v", status, problem)
			}
			if dst.GroupID.Sent != tt.wantSent {
				t.Errorf("Sent = %v, want %v", dst.GroupID.Sent, tt.wantSent)
			}
			switch {
			case tt.wantValue == nil && dst.GroupID.Value != nil:
				t.Errorf("Value = %q, want nil", *dst.GroupID.Value)
			case tt.wantValue != nil && (dst.GroupID.Value == nil || *dst.GroupID.Value != *tt.wantValue):
				t.Errorf("Value = %v, want %q", dst.GroupID.Value, *tt.wantValue)
			}
		})
	}
}

// TestClearableField_DecodeWrongType verifies that a value of the wrong JSON
// type is rejected rather than treated as null.
func TestClearableField_DecodeWrongType(t *testing.T) {
	var dst struct {
		GroupID clearableField[string] `json:"group_id,omitempty"`
	}
	ok, status, _ := decodeProblem(t, `{"group_id":42}`, &dst)
	if ok {
		t.Fatal("decodeJSON accepted a number in a string field")
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
}

func TestWriteList_EmptySlice(t *testing.T) {
	rec := httptest.NewRecorder()
	writeList[string](rec, nil, "")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	items, ok := body["items"].([]any)
	if !ok {
		t.Fatal("items is not an array")
	}
	if len(items) != 0 {
		t.Errorf("items length = %d, want 0", len(items))
	}
	if _, hasCursor := body["next_cursor"]; hasCursor {
		t.Error("next_cursor should be omitted when empty")
	}
}

func TestWriteList_WithCursor(t *testing.T) {
	rec := httptest.NewRecorder()
	writeList(rec, []string{"a", "b"}, "abc123")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["next_cursor"] != "abc123" {
		t.Errorf("next_cursor = %v, want 'abc123'", body["next_cursor"])
	}
}

func TestContractCursorRoundTrip(t *testing.T) {
	type testCursor struct {
		T  string `json:"t"`
		ID string `json:"id"`
	}
	orig := testCursor{T: "2026-01-01T00:00:00Z", ID: "abc-123"}
	encoded := encodePageCursor(orig)
	if encoded == "" {
		t.Fatal("encodePageCursor returned empty")
	}
	var decoded testCursor
	if err := decodePageCursor(encoded, &decoded); err != nil {
		t.Fatalf("decodePageCursor: %v", err)
	}
	if decoded != orig {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestEncodeCursor_NoPadding(t *testing.T) {
	type cur struct {
		T  string `json:"t"`
		ID string `json:"id"`
	}
	encoded := encodePageCursor(cur{T: "2026-01-01T00:00:00Z", ID: "abc"})
	if strings.Contains(encoded, "=") {
		t.Errorf("cursor contains padding: %q", encoded)
	}
}

func TestDecodeCursor_Invalid(t *testing.T) {
	var dst struct{}
	if err := decodePageCursor("not-base64!!!", &dst); err == nil {
		t.Error("expected error for invalid base64")
	}
	if err := decodePageCursor(base64.RawURLEncoding.EncodeToString([]byte("not-json")), &dst); err == nil {
		t.Error("expected error for invalid JSON inside base64")
	}
}

func TestDecodeCursor_AcceptsPaddedFallback(t *testing.T) {
	type cur struct {
		T  string `json:"t"`
		ID string `json:"id"`
	}
	orig := cur{T: "2026-01-01T00:00:00Z", ID: "abc"}
	padded := base64.URLEncoding.EncodeToString(mustJSON(orig))
	var decoded cur
	if err := decodePageCursor(padded, &decoded); err != nil {
		t.Fatalf("decodePageCursor should accept padded: %v", err)
	}
	if decoded != orig {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestCursorSurvivesURLQueryParam(t *testing.T) {
	type cur struct {
		T  string `json:"t"`
		ID string `json:"id"`
	}
	orig := cur{T: "2026-01-01T00:00:00.123456789Z", ID: "abc+def/ghi=jkl"}
	encoded := encodePageCursor(orig)

	// Place cursor in a URL query string, parse it back out, and decode.
	u, err := url.Parse("https://example.com/api?cursor=" + encoded)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	recovered := u.Query().Get("cursor")
	var decoded cur
	if err := decodePageCursor(recovered, &decoded); err != nil {
		t.Fatalf("decodePageCursor after URL round-trip: %v", err)
	}
	if decoded != orig {
		t.Errorf("URL round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestParseLimitParam(t *testing.T) {
	t.Run("missing returns default", func(t *testing.T) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		limit, ok := parseLimitParam(rec, r, 50, 200)
		if !ok || limit != 50 {
			t.Errorf("got (%d, %v), want (50, true)", limit, ok)
		}
	})
	t.Run("valid value", func(t *testing.T) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?limit=25", nil)
		rec := httptest.NewRecorder()
		limit, ok := parseLimitParam(rec, r, 50, 200)
		if !ok || limit != 25 {
			t.Errorf("got (%d, %v), want (25, true)", limit, ok)
		}
	})
	t.Run("exceeds max", func(t *testing.T) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?limit=999", nil)
		rec := httptest.NewRecorder()
		_, ok := parseLimitParam(rec, r, 50, 200)
		if ok {
			t.Error("expected failure for limit > max")
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}
