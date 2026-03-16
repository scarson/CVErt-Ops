// ABOUTME: Unit tests for shared contract helpers.
// ABOUTME: Verifies RFC 9457 output matches huma's ErrorModel format field-for-field.
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestDecodeJSON_MalformedInput(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	detail := decodeJSON(r, &struct{}{})
	if detail == nil {
		t.Fatal("expected error detail for malformed JSON")
	}
	if detail.Location != "body" {
		t.Errorf("location = %q, want 'body'", detail.Location)
	}
}

func TestDecodeJSON_ValidInput(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	var dst struct{ Name string `json:"name"` }
	detail := decodeJSON(r, &dst)
	if detail != nil {
		t.Fatalf("unexpected error: %v", detail)
	}
	if dst.Name != "test" {
		t.Errorf("name = %q, want 'test'", dst.Name)
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

func TestParseLimitParam(t *testing.T) {
	t.Run("missing returns default", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		limit, ok := parseLimitParam(rec, r, 50, 200)
		if !ok || limit != 50 {
			t.Errorf("got (%d, %v), want (50, true)", limit, ok)
		}
	})
	t.Run("valid value", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?limit=25", nil)
		rec := httptest.NewRecorder()
		limit, ok := parseLimitParam(rec, r, 50, 200)
		if !ok || limit != 25 {
			t.Errorf("got (%d, %v), want (25, true)", limit, ok)
		}
	})
	t.Run("exceeds max", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?limit=999", nil)
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
