// ABOUTME: GET /api/v1/admin/doctor handler — runs system health checks and returns results.
// ABOUTME: Requires site admin auth. Returns 200 if all pass, 503 if any fail.
package api

import (
	"encoding/hex"
	"net/http"

	"github.com/scarson/cvert-ops/internal/doctor"
)

// doctorHandler runs all doctor checks and returns results as JSON.
func (srv *Server) doctorHandler(w http.ResponseWriter, r *http.Request) {
	ssoKey, ssoErr := srv.ssoEncryptionKey()
	ssoPrev := srv.ssoEncryptionKeyPrevious()

	var ssoKeyHex, ssoPrevHex string
	if ssoErr == nil && ssoKey != [32]byte{} {
		ssoKeyHex = hex.EncodeToString(ssoKey[:])
	}
	if ssoPrev != ([32]byte{}) {
		ssoPrevHex = hex.EncodeToString(ssoPrev[:])
	}

	var jwtPrevStr string
	if prev := srv.jwtPreviousSecretBytes(); prev != nil {
		jwtPrevStr = string(prev)
	}

	checks := doctor.StandardChecks(doctor.StandardChecksConfig{
		DB:                       srv.store.Pool(),
		ExpectedSchemaVersion:    srv.expectedSchemaVersion,
		SSOEncryptionKey:         ssoKeyHex,
		SSOEncryptionKeyPrevious: ssoPrevHex,
		JWTSecret:                string(srv.jwtSecret()),
		JWTSecretPrevious:        jwtPrevStr,
		SMTPHost:                 srv.cfg.SMTPHost,
		SMTPPort:                 srv.cfg.SMTPPort,
		SMTPUsername:             srv.cfg.SMTPUsername,
		CORSAllowedOrigins:       srv.cfg.CORSAllowedOrigins,
		CookieAuth:               true,
		ServerAddr:               "http://" + srv.cfg.ListenAddr,
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
