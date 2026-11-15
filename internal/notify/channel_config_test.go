// ABOUTME: Unit tests for ParseWebhookSettings and ParseEmailSettings, the strict channel config decoders.
// ABOUTME: Covers case-variant and unknown keys, wrong value types, and configs that are not objects.
package notify_test

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"

	"github.com/scarson/cvert-ops/internal/notify"
)

// configErrorWant describes the error a parser must return; the zero value means no error.
type configErrorWant struct {
	fail        bool
	semantic    bool             // error wraps a *jsonv2.SemanticError
	unknownName bool             // that SemanticError reports an unknown member name
	pointer     jsontext.Pointer // that SemanticError's JSONPointer
}

func checkConfigError(t *testing.T, err error, want configErrorWant) {
	t.Helper()
	if !want.fail {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	semErr, ok := errors.AsType[*jsonv2.SemanticError](err)
	if ok != want.semantic {
		t.Fatalf("error %v: wraps *jsonv2.SemanticError = %v, want %v", err, ok, want.semantic)
	}
	if !want.semantic {
		return
	}
	if got := errors.Is(semErr.Err, jsonv2.ErrUnknownName); got != want.unknownName {
		t.Errorf("error %v: unknown-name = %v, want %v", err, got, want.unknownName)
	}
	if semErr.JSONPointer != want.pointer {
		t.Errorf("error %v: pointer = %q, want %q", err, semErr.JSONPointer, want.pointer)
	}
}

func TestParseWebhookSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		raw         string
		wantURL     string
		wantHeaders map[string]string
		wantErr     configErrorWant
	}{
		{
			name:    "minimal",
			raw:     `{"url":"https://h.example/x"}`,
			wantURL: "https://h.example/x",
		},
		{
			name:        "with headers",
			raw:         `{"url":"https://h.example/x","custom_headers":{"X-Team":"secops"}}`,
			wantURL:     "https://h.example/x",
			wantHeaders: map[string]string{"X-Team": "secops"},
		},
		{
			name:    "case variant of url",
			raw:     `{"URL":"https://h.example/x"}`,
			wantErr: configErrorWant{fail: true, semantic: true, unknownName: true, pointer: "/URL"},
		},
		{
			name:    "unknown key",
			raw:     `{"url":"https://h.example/x","note":"x"}`,
			wantErr: configErrorWant{fail: true, semantic: true, unknownName: true, pointer: "/note"},
		},
		{
			name:    "header value not a string",
			raw:     `{"url":"https://h.example/x","custom_headers":{"X-A":1}}`,
			wantErr: configErrorWant{fail: true, semantic: true, pointer: "/custom_headers/X-A"},
		},
		{
			name:    "array",
			raw:     `[]`,
			wantErr: configErrorWant{fail: true},
		},
		{
			name:    "string",
			raw:     `"x"`,
			wantErr: configErrorWant{fail: true},
		},
		{
			name:    "null",
			raw:     `null`,
			wantErr: configErrorWant{fail: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := notify.ParseWebhookSettings([]byte(tc.raw))
			checkConfigError(t, err, tc.wantErr)
			if tc.wantErr.fail {
				return
			}
			if got.URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", got.URL, tc.wantURL)
			}
			if tc.wantHeaders == nil {
				if got.CustomHeaders != nil {
					t.Errorf("CustomHeaders = %v, want nil", got.CustomHeaders)
				}
				return
			}
			if len(got.CustomHeaders) != len(tc.wantHeaders) {
				t.Fatalf("CustomHeaders = %v, want %v", got.CustomHeaders, tc.wantHeaders)
			}
			for k, v := range tc.wantHeaders {
				if got.CustomHeaders[k] != v {
					t.Errorf("CustomHeaders[%q] = %q, want %q", k, got.CustomHeaders[k], v)
				}
			}
		})
	}
}

func TestParseEmailSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		raw            string
		wantRecipients []string
		wantErr        configErrorWant
	}{
		{
			name:           "minimal",
			raw:            `{"recipients":["a@example.com"]}`,
			wantRecipients: []string{"a@example.com"},
		},
		{
			name:    "case variant of recipients",
			raw:     `{"Recipients":["a@example.com"]}`,
			wantErr: configErrorWant{fail: true, semantic: true, unknownName: true, pointer: "/Recipients"},
		},
		{
			name:    "recipients wrong type",
			raw:     `{"recipients":"a@example.com"}`,
			wantErr: configErrorWant{fail: true, semantic: true, pointer: "/recipients"},
		},
		{
			name:    "array",
			raw:     `[]`,
			wantErr: configErrorWant{fail: true},
		},
		{
			name:    "string",
			raw:     `"x"`,
			wantErr: configErrorWant{fail: true},
		},
		{
			name:    "null",
			raw:     `null`,
			wantErr: configErrorWant{fail: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := notify.ParseEmailSettings([]byte(tc.raw))
			checkConfigError(t, err, tc.wantErr)
			if tc.wantErr.fail {
				return
			}
			if len(got.Recipients) != len(tc.wantRecipients) {
				t.Fatalf("Recipients = %v, want %v", got.Recipients, tc.wantRecipients)
			}
			for i, r := range tc.wantRecipients {
				if got.Recipients[i] != r {
					t.Errorf("Recipients[%d] = %q, want %q", i, got.Recipients[i], r)
				}
			}
		})
	}
}
