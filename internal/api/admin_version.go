// ABOUTME: GET /api/v1/admin/version handler — returns build metadata.
// ABOUTME: Requires site admin auth. Fields set via ldflags at build time.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
)

// VersionInfo holds build metadata set via ldflags at compile time.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// versionHandler returns the build metadata as JSON.
func (srv *Server) versionHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{
		"version":    srv.versionInfo.Version,
		"commit":     srv.versionInfo.Commit,
		"build_time": srv.versionInfo.BuildTime,
		"go_version": runtime.Version(),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(r.Context(), "version: failed to encode response", "error", err)
	}
}
