// ABOUTME: Tests for the context logger middleware.
// ABOUTME: Verifies request_id is injected into the slog logger stored in context.
package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"

	logpkg "github.com/scarson/cvert-ops/internal/log"
)

func TestContextLoggerMiddleware_InjectsRequestID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	origDefault := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(origDefault) })

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(contextLoggerMiddleware)
	r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		logpkg.FromContext(r.Context()).Info("hello")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Contains(t, buf.String(), "request_id")
}
