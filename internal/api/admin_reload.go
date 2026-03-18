// ABOUTME: Admin endpoint to reload configuration from the secrets file.
// ABOUTME: Cross-platform alternative to SIGHUP for triggering config reload.
package api

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/secure"
)

// adminReloadConfigHandler handles POST /api/v1/admin/reload-config.
// Re-reads the secrets file and atomically updates the config holder via
// config.ReloadConfig, which also calls the feed rescan function on success.
// Does not accept secrets in the request body (avoids leaking secrets in HTTP logs).
func (srv *Server) adminReloadConfigHandler(w http.ResponseWriter, r *http.Request) {
	secretsFile := srv.cfg.SecretsFile
	if secretsFile == "" {
		writeJSON(w, http.StatusOK, map[string]string{"message": "no secrets file configured"})
		return
	}

	if srv.configHolder == nil {
		slog.ErrorContext(r.Context(), "admin reload-config: config holder not initialized")
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Use ReloadConfig for parity with SIGHUP handler (includes rescan).
	oldCfg := srv.configHolder.Load()
	config.ReloadConfig(srv.configHolder, secretsFile, srv.rescanFunc)
	newCfg := srv.configHolder.Load()

	// If the pointer didn't change, reload failed — config was kept.
	if oldCfg == newCfg {
		writeProblem(w, http.StatusBadRequest, "config reload failed: check server logs for details")
		return
	}

	if srv.eventWriter != nil {
		callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
		srv.eventWriter.Write(r.Context(), secure.Event{
			Type:     secure.EventAdminConfigReloaded,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(r.Context()),
			UserID:   &callerID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "config reloaded"})
}
