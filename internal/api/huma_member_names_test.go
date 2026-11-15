// ABOUTME: Tests that huma-registered request bodies match member names exactly in validation and decoding.
// ABOUTME: Uses a throwaway huma API built with newHumaConfig; needs no database.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

type memberNamesProbeInput struct {
	Body struct {
		Email    string `json:"email" format:"email"`
		Password string `json:"password" minLength:"16"`
	}
}

// memberNamesProbe is a huma API with one POST /probe operation whose handler
// records each body it receives.
type memberNamesProbe struct {
	handler  http.Handler
	received []memberNamesProbeInput
}

func newMemberNamesProbe(t *testing.T) *memberNamesProbe {
	t.Helper()
	p := &memberNamesProbe{}
	mux := chi.NewMux()
	api := humachi.New(mux, newHumaConfig())
	huma.Register(api, huma.Operation{
		OperationID: "member-names-probe",
		Method:      http.MethodPost,
		Path:        "/probe",
	}, func(_ context.Context, in *memberNamesProbeInput) (*struct{}, error) {
		p.received = append(p.received, *in)
		return &struct{}{}, nil
	})
	p.handler = mux
	return p
}

func (p *memberNamesProbe) post(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/probe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	return rec
}

func probeProblem(t *testing.T, rec *httptest.ResponseRecorder) huma.ErrorModel {
	t.Helper()
	var problem huma.ErrorModel
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	return problem
}

func hasProblemError(problem huma.ErrorModel, location, message string) bool {
	for _, e := range problem.Errors {
		if e.Location == location && e.Message == message {
			return true
		}
	}
	return false
}

// TestHumaBodyMemberNamesMatchExactly verifies that huma's schema validation
// matches body member names exactly, as the encoding/json/v2 decoder does. A
// member whose name differs from the schema's only in case must be refused by
// validation, not accepted by it and then dropped by the decoder, which would
// hand the handler an empty value that validation never checked.
func TestHumaBodyMemberNamesMatchExactly(t *testing.T) {
	const email = "names@example.com"
	const password = "aaaaaaaaaaaaaaaa"

	t.Run("case-variant names only", func(t *testing.T) {
		p := newMemberNamesProbe(t)
		rec := p.post(t, `{"Email":"`+email+`","Password":"`+password+`"}`)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if len(p.received) != 0 {
			t.Fatalf("handler called %d times with %+v, want 0", len(p.received), p.received)
		}
		problem := probeProblem(t, rec)
		for _, name := range []string{"Email", "Password"} {
			if !hasProblemError(problem, "body."+name, "unexpected property") {
				t.Errorf("errors = %+v, want unexpected property at body.%s", problem.Errors, name)
			}
		}
	})

	t.Run("case-variant sibling of a valid member", func(t *testing.T) {
		p := newMemberNamesProbe(t)
		rec := p.post(t, `{"email":"`+email+`","password":"`+password+`","PASSWORD":"x"}`)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if len(p.received) != 0 {
			t.Fatalf("handler called %d times, want 0", len(p.received))
		}
		problem := probeProblem(t, rec)
		if !hasProblemError(problem, "body.PASSWORD", "unexpected property") {
			t.Errorf("errors = %+v, want unexpected property at body.PASSWORD", problem.Errors)
		}
	})

	t.Run("exact names", func(t *testing.T) {
		p := newMemberNamesProbe(t)
		rec := p.post(t, `{"email":"`+email+`","password":"`+password+`"}`)
		// The probe operation has no response body, so huma answers 204.
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if len(p.received) != 1 {
			t.Fatalf("handler called %d times, want 1", len(p.received))
		}
		got := p.received[0].Body
		if got.Email != email || got.Password != password {
			t.Errorf("handler received email %q, password %q; want %q, %q", got.Email, got.Password, email, password)
		}
	})
}
