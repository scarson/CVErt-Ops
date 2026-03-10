// ABOUTME: GET /api/v1/admin/doctor handler — runs system health checks and returns results.
// ABOUTME: Requires site admin auth. Returns 200 if all pass, 503 if any fail.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/scarson/cvert-ops/internal/doctor"
)

// doctorHandler runs all doctor checks and returns results as JSON.
func (srv *Server) doctorHandler(w http.ResponseWriter, r *http.Request) {
	checks := doctor.StandardChecks(doctor.StandardChecksConfig{
		DB:                    srv.store.Pool(),
		ExpectedSchemaVersion: srv.expectedSchemaVersion,
		SSOEncryptionKey:      srv.cfg.SSOEncryptionKey,
		JWTSecret:             srv.cfg.JWTSecret,
		SMTPHost:              srv.cfg.SMTPHost,
		SMTPPort:              srv.cfg.SMTPPort,
		SMTPUsername:          srv.cfg.SMTPUsername,
	})

	results := doctor.Run(r.Context(), checks)

	status := "healthy"
	statusCode := http.StatusOK
	if doctor.HasFailures(results) {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}

	resp := map[string]any{
		"status": status,
		"checks": results,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(r.Context(), "doctor: failed to encode response", "error", err)
	}
}
