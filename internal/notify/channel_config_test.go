// ABOUTME: Unit tests for ParseWebhookSettings and ParseEmailSettings, the strict channel config decoders.
// ABOUTME: Covers case-variant and unknown keys, wrong value types, and configs that are not objects.
package notify_test

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
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
			name:    "header value null",
			raw:     `{"url":"https://h.example/x","custom_headers":{"X-A":null}}`,
			wantErr: configErrorWant{fail: true, semantic: true, pointer: "/custom_headers/X-A"},
		},
		{
			name:    "url null",
			raw:     `{"url":null}`,
			wantErr: configErrorWant{fail: true, semantic: true, pointer: "/url"},
		},
		{
			name:    "custom_headers null is no headers",
			raw:     `{"url":"https://h.example/x","custom_headers":null}`,
			wantURL: "https://h.example/x",
		},
		{
			name:    "leading whitespace",
			raw:     ` {"url":"https://h.example/x"}`,
			wantURL: "https://h.example/x",
		},
		{
			name:    "empty input",
			raw:     ``,
			wantErr: configErrorWant{fail: true},
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
			name:    "recipient null",
			raw:     `{"recipients":[null]}`,
			wantErr: configErrorWant{fail: true, semantic: true, pointer: "/recipients/0"},
		},
		{
			name: "recipients null is no recipients",
			raw:  `{"recipients":null}`,
		},
		{
			name:           "leading whitespace",
			raw:            ` {"recipients":["a@example.com"]}`,
			wantRecipients: []string{"a@example.com"},
		},
		{
			name:    "empty input",
			raw:     ``,
			wantErr: configErrorWant{fail: true},
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
			if tc.wantRecipients == nil {
				if got.Recipients != nil {
					t.Errorf("Recipients = %v, want nil", got.Recipients)
				}
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

func TestCheckWebhookSettings(t *testing.T) {
	t.Parallel()
	const url = "https://h.example/x"
	const (
		badName  = "custom_headers name is not a valid header name"
		badValue = "custom_headers value contains a control character"
		caseOnly = "custom_headers names must differ by more than letter case"
	)
	tests := []struct {
		name        string
		settings    notify.WebhookSettings
		wantNoURL   bool
		wantHeader  string // HeaderError.Name
		wantMessage string // HeaderError.Message; empty without wantNoURL means no error
	}{
		{name: "valid", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{
			"X-Team": "secops", "Authorization": "Bearer a\tb", "X-Utf8": "café", "X-Sym!#$%&'*+.^_`|~": "v"}}},
		{name: "no headers", settings: notify.WebhookSettings{URL: url}},
		{name: "url empty", settings: notify.WebhookSettings{}, wantNoURL: true},
		{name: "url blank", settings: notify.WebhookSettings{URL: " \t "}, wantNoURL: true},
		{name: "name empty", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"": "v"}}, wantHeader: "", wantMessage: badName},
		{name: "name with space", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X A": "v"}}, wantHeader: "X A", wantMessage: badName},
		{name: "name with colon", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X:A": "v"}}, wantHeader: "X:A", wantMessage: badName},
		{name: "name with CRLF", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A\r\nX-B": "v"}}, wantHeader: "X-A\r\nX-B", wantMessage: badName},
		{name: "name not ASCII", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-é": "v"}}, wantHeader: "X-é", wantMessage: badName},
		{name: "value with CR", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A": "a\rb"}}, wantHeader: "X-A", wantMessage: badValue},
		{name: "value with LF", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A": "a\nX-B: c"}}, wantHeader: "X-A", wantMessage: badValue},
		{name: "value with NUL", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A": "a\x00b"}}, wantHeader: "X-A", wantMessage: badValue},
		{name: "value with other control", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A": "a\x01b"}}, wantHeader: "X-A", wantMessage: badValue},
		{name: "value with DEL", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A": "a\x7fb"}}, wantHeader: "X-A", wantMessage: badValue},
		{name: "reserved name", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"content-type": "text/plain"}}, wantHeader: "content-type", wantMessage: "custom_headers cannot set Content-Type"},
		{name: "reserved signature name", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-CVErtOps-Signature": "sha256=x"}}, wantHeader: "X-CVErtOps-Signature", wantMessage: "custom_headers cannot set X-Cvertops-Signature"},
		{name: "names differ only in case", settings: notify.WebhookSettings{URL: url, CustomHeaders: map[string]string{"X-A": "1", "x-a": "2"}}, wantHeader: "x-a", wantMessage: caseOnly},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := notify.CheckWebhookSettings(tc.settings)
			switch {
			case tc.wantNoURL:
				if !errors.Is(err, notify.ErrWebhookNoURL) {
					t.Fatalf("error = %v, want ErrWebhookNoURL", err)
				}
			case tc.wantMessage == "":
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			default:
				headerErr, ok := errors.AsType[*notify.HeaderError](err)
				if !ok {
					t.Fatalf("error = %v, want *notify.HeaderError", err)
				}
				if headerErr.Name != tc.wantHeader || headerErr.Message != tc.wantMessage {
					t.Errorf("HeaderError = {Name %q, Message %q}, want {Name %q, Message %q}",
						headerErr.Name, headerErr.Message, tc.wantHeader, tc.wantMessage)
				}
				for _, value := range tc.settings.CustomHeaders {
					if len(value) > 1 && strings.Contains(err.Error(), value) {
						t.Errorf("error %q echoes a header value", err.Error())
					}
				}
			}
		})
	}
}

func TestCheckEmailRecipients(t *testing.T) {
	t.Parallel()
	tooMany := make([]string, 51)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("user%d@example.com", i)
	}
	tests := []struct {
		name        string
		recipients  []string
		wantProblem string // RecipientError.Problem; empty means no error
		wantError   string // RecipientError.Error()
	}{
		{name: "valid", recipients: []string{"a@example.com", "Ops <ops@example.com>"}},
		{name: "fifty", recipients: tooMany[:50]},
		{name: "none", recipients: nil,
			wantProblem: "email config must include at least one recipient", wantError: "email config must include at least one recipient"},
		{name: "empty", recipients: []string{},
			wantProblem: "email config must include at least one recipient", wantError: "email config must include at least one recipient"},
		{name: "too many", recipients: tooMany,
			wantProblem: "email config must not exceed 50 recipients", wantError: "email config must not exceed 50 recipients"},
		{name: "not an address", recipients: []string{"not-an-email"},
			wantProblem: "invalid email recipient", wantError: `invalid email recipient "not-an-email": mail: missing '@' or angle-addr`},
		{name: "duplicate in another case", recipients: []string{"a@example.com", "A@Example.com"},
			wantProblem: "duplicate email recipient", wantError: "duplicate email recipient: a@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := notify.CheckEmailRecipients(tc.recipients)
			if tc.wantProblem == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			recipientErr, ok := errors.AsType[*notify.RecipientError](err)
			if !ok {
				t.Fatalf("error = %v, want *notify.RecipientError", err)
			}
			if recipientErr.Problem != tc.wantProblem || recipientErr.Error() != tc.wantError {
				t.Errorf("RecipientError = {Problem %q, Error %q}, want {Problem %q, Error %q}",
					recipientErr.Problem, recipientErr.Error(), tc.wantProblem, tc.wantError)
			}
			if strings.Contains(recipientErr.Problem, "@") || strings.Contains(recipientErr.Problem, "not-an-email") {
				t.Errorf("Problem %q names a recipient", recipientErr.Problem)
			}
		})
	}
}
