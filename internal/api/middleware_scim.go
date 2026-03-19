// ABOUTME: SCIM bearer token authentication middleware.
// ABOUTME: Mounted on /scim/v2/* only. Separate from RequireAuthenticated (no human actor).
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/secure"
)

// requireSCIMAuth authenticates SCIM bearer tokens per design doc §2.
// Steps: extract org_id → extract Bearer token → hash → lookup → constant-time
// compare → verify org match → verify enabled → inject context.
func (srv *Server) requireSCIMAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract org_id from URL path.
		orgIDStr := chi.URLParam(r, "org_id")
		orgID, err := uuid.Parse(orgIDStr)
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, "", "invalid org_id")
			return
		}

		// 2. Extract Bearer token.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			srv.fireSCIMEvent(r.Context(), secure.EventSCIMAuthFailed, &orgID)
			writeSCIMError(w, http.StatusUnauthorized, "", "missing or invalid Authorization header")
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")

		// 3. Hash token.
		tokenHash := auth.HashSCIMToken(rawToken)

		// 4. Lookup config (withBypassTx — pre-context).
		cfg, err := srv.store.LookupSCIMConfigByTokenHash(r.Context(), tokenHash)
		if err != nil {
			slog.ErrorContext(r.Context(), "scim auth: lookup", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}

		// 5. Constant-time compare (defense-in-depth against timing).
		if cfg == nil || subtle.ConstantTimeCompare([]byte(cfg.TokenHash), []byte(tokenHash)) != 1 {
			slog.WarnContext(r.Context(), "scim auth failed", "org_id", orgID, "reason", "invalid_token")
			srv.fireSCIMEvent(r.Context(), secure.EventSCIMAuthFailed, &orgID)
			writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
			return
		}

		// 6. Verify org_id match (defense-in-depth).
		if cfg.OrgID != orgID {
			slog.WarnContext(r.Context(), "scim auth failed", "org_id", orgID, "config_org_id", cfg.OrgID, "reason", "org_mismatch")
			srv.fireSCIMEvent(r.Context(), secure.EventSCIMAuthOrgMismatch, &orgID)
			writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
			return
		}

		// 7. Check enabled.
		if !cfg.Enabled {
			slog.WarnContext(r.Context(), "scim auth failed", "org_id", orgID, "reason", "disabled")
			srv.fireSCIMEvent(r.Context(), secure.EventSCIMAuthDisabled, &orgID)
			writeSCIMError(w, http.StatusForbidden, "", "SCIM provisioning is disabled for this organization")
			return
		}

		// 8. Inject context.
		ctx := context.WithValue(r.Context(), ctxOrgID, orgID)
		ctx = context.WithValue(ctx, ctxSCIMConfigID, cfg.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// fireSCIMEvent fires a security event if the event writer is configured.
func (srv *Server) fireSCIMEvent(ctx context.Context, eventType string, orgID *uuid.UUID) {
	if srv.eventWriter != nil {
		severity, ok := secure.Severity(eventType)
		if !ok {
			severity = secure.SeverityWarning
		}
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     eventType,
			Severity: severity,
			ActorIP:  clientIP(ctx),
			OrgID:    orgID,
		})
	}
}

// writeSCIMError writes a SCIM-formatted error response (RFC 7644 §3.12).
func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	resp := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  fmt.Sprintf("%d", status),
		"detail":  detail,
	}
	if scimType != "" {
		resp["scimType"] = scimType
	}
	_ = json.NewEncoder(w).Encode(resp)
}
