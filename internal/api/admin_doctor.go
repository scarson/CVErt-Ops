// ABOUTME: GET /api/v1/admin/doctor handler — runs system health checks and returns results.
// ABOUTME: Requires site admin auth. Returns 200 if all pass, 503 if any fail.
package api

import (
	"net/http"

	"github.com/scarson/cvert-ops/internal/doctor"
)

// doctorHandler runs all doctor checks and returns results as JSON.
func (srv *Server) doctorHandler(w http.ResponseWriter, r *http.Request) {
	checks := doctor.StandardChecks(doctor.StandardChecksConfig{
		DB:                       srv.store.Pool(),
		ExpectedSchemaVersion:    srv.expectedSchemaVersion,
		SSOEncryptionKey:         srv.cfg.SSOEncryptionKey,
		SSOEncryptionKeyPrevious: srv.cfg.SSOEncryptionKeyPrevious,
		JWTSecret:                srv.cfg.JWTSecret,
		SMTPHost:                 srv.cfg.SMTPHost,
		SMTPPort:                 srv.cfg.SMTPPort,
		SMTPUsername:             srv.cfg.SMTPUsername,
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

	writeJSON(w, statusCode, resp)
}
