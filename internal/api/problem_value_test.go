// ABOUTME: Tests that huma problem responses never echo request data in errors[].value.
// ABOUTME: Drives the real auth and MFA operations on a throwaway huma API; needs no database.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

// echoSecret is a password that no problem response may contain. It is long
// enough to pass every minLength on the auth bodies, so a request is refused
// only for the defect each case adds.
const echoSecret = "echo-secret-0123456789-abcdefghij"

// newAuthOperationsAPI registers the real auth and MFA operations on a huma API
// built with the production configuration. Every case below is refused by
// huma before an operation handler runs, so the zero Server is never used.
func newAuthOperationsAPI(t *testing.T) http.Handler {
	t.Helper()
	mux := chi.NewMux()
	api := humachi.New(mux, newHumaConfig())
	srv := &Server{}
	registerAuthRoutes(api, srv)
	registerMFARoutes(api, srv)
	return mux
}

// TestProblemResponsesDoNotEchoRequestData verifies that a request huma refuses,
// at 400 for a body it cannot decode or at 422 for a body that fails schema
// validation, gets a problem response that does not contain the password it
// sent. huma puts the raw body, the refused object or the refused field's value
// in errors[].value; any proxy or log that captures problem responses would
// then store the password. Location and message must still name the defect;
// huma reports a missing required member at the location of its parent object.
func TestProblemResponsesDoNotEchoRequestData(t *testing.T) {
	tooLong := echoSecret + strings.Repeat("x", 1024)
	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantLoc    string
	}{
		{"login malformed JSON", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","password":"` + echoSecret + `"`, http.StatusBadRequest, "body"},
		{"login invalid escape in password", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","password":"` + echoSecret + `\q` + echoSecret + `"}`, http.StatusBadRequest, "body"},
		{"login invalid UTF-8 in password", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","password":"` + echoSecret + "\xff" + echoSecret + `"}`, http.StatusBadRequest, "body"},
		{"login duplicate member", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","password":"` + echoSecret + `","password":"` + echoSecret + `"}`, http.StatusBadRequest, "body"},
		{"login unexpected property", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","password":"` + echoSecret + `","extra":1}`, http.StatusUnprocessableEntity, "body.extra"},
		{"login case-variant name", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","Password":"` + echoSecret + `"}`, http.StatusUnprocessableEntity, "body.Password"},
		{"login missing email", http.MethodPost, "/auth/login",
			`{"password":"` + echoSecret + `"}`, http.StatusUnprocessableEntity, "body"},
		{"login password too long", http.MethodPost, "/auth/login",
			`{"email":"a@example.com","password":"` + tooLong + `"}`, http.StatusUnprocessableEntity, "body.password"},
		{"register unexpected property", http.MethodPost, "/auth/register",
			`{"email":"a@example.com","display_name":"A","password":"` + echoSecret + `","extra":1}`, http.StatusUnprocessableEntity, "body.extra"},
		{"change-password malformed JSON", http.MethodPost, "/auth/change-password",
			`{"current_password":"` + echoSecret + `","new_password":"` + echoSecret, http.StatusBadRequest, "body"},
		{"change-password new password too long", http.MethodPost, "/auth/change-password",
			`{"current_password":"` + echoSecret + `","new_password":"` + tooLong + `"}`, http.StatusUnprocessableEntity, "body.new_password"},
		{"reset-password missing token", http.MethodPost, "/auth/reset-password",
			`{"new_password":"` + echoSecret + `"}`, http.StatusUnprocessableEntity, "body"},
		{"MFA recovery-code regeneration unexpected property", http.MethodPost, "/auth/mfa/recovery-codes/regenerate",
			`{"current_password":"` + echoSecret + `","extra":1}`, http.StatusUnprocessableEntity, "body.extra"},
		{"MFA method removal duplicate member", http.MethodDelete, "/auth/mfa/methods/totp",
			`{"current_password":"` + echoSecret + `","current_password":"` + echoSecret + `"}`, http.StatusBadRequest, "body"},
	}
	handler := newAuthOperationsAPI(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			raw := rec.Body.String()
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			// Never print raw: on failure it holds the password.
			if strings.Contains(raw, echoSecret) {
				t.Fatalf("problem response contains the request password")
			}
			var problem huma.ErrorModel
			if err := json.Unmarshal([]byte(raw), &problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			found := false
			for _, e := range problem.Errors {
				if e.Value != nil {
					t.Errorf("error at %s has a value; want none", e.Location)
				}
				if e.Location == tc.wantLoc && e.Message != "" {
					found = true
				}
			}
			if !found {
				t.Errorf("errors = %q, want a message at %s", problemErrorSummary(problem), tc.wantLoc)
			}
		})
	}
}
