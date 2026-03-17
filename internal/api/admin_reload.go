// ABOUTME: Admin endpoint to reload configuration from the secrets file.
// ABOUTME: Cross-platform alternative to SIGHUP for triggering config reload.
package api

import (
	"log/slog"
	"net/http"

	"github.com/scarson/cvert-ops/internal/config"
)

// adminReloadConfigHandler handles POST /api/v1/admin/reload-config.
// Re-reads the secrets file and atomically updates the config holder.
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

	newCfg, err := config.LoadFromSecretsFile(secretsFile)
	if err != nil {
		slog.WarnContext(r.Context(), "admin reload-config: invalid secrets file", "error", err)
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}

	srv.configHolder.Store(newCfg)
	slog.InfoContext(r.Context(), "config reloaded via admin API")

	writeJSON(w, http.StatusOK, map[string]string{"message": "config reloaded"})
}
