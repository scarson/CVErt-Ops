// ABOUTME: GET /api/v1/admin/doctor handler — runs system health checks and returns results.
// ABOUTME: Requires site admin auth. Returns 200 if all pass, 503 if any fail.
package api

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/scarson/cvert-ops/internal/doctor"
)

// doctorHandler runs all doctor checks and returns results as JSON.
func (srv *Server) doctorHandler(w http.ResponseWriter, r *http.Request) {
	var pool = srv.store.Pool()

	var encKey [32]byte
	if srv.cfg.SSOEncryptionKey != "" {
		decoded, err := hex.DecodeString(srv.cfg.SSOEncryptionKey)
		if err == nil && len(decoded) == 32 {
			copy(encKey[:], decoded)
		}
	}

	smtpHost := srv.cfg.SMTPHost
	if smtpHost == "localhost" && srv.cfg.SMTPUsername == "" {
		smtpHost = ""
	}

	checks := []doctor.Check{
		&doctor.DBConnectivityCheck{DB: pool},
		&doctor.MigrationCheck{DB: pool, ExpectedVersion: srv.expectedSchemaVersion},
		&doctor.DBRoleCheck{DB: pool},
		&doctor.RLSCheck{DB: pool, Tables: doctor.OrgScopedTables()},
		&doctor.EncryptionSentinelCheck{DB: pool, Key: encKey},
		&doctor.JWTCheck{Secret: srv.cfg.JWTSecret},
		&doctor.SMTPCheck{Host: smtpHost, Port: srv.cfg.SMTPPort},
		&doctor.DiskCheck{},
		&doctor.FeedCheck{DB: pool},
	}

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
