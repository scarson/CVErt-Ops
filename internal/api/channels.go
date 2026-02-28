// ABOUTME: HTTP handlers for notification channel CRUD and signing secret rotation.
// ABOUTME: signing_secret is returned only on create and rotate-secret responses — never on GET/LIST/PATCH.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

// ── Request / response types ──────────────────────────────────────────────────

type createChannelBody struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// patchChannelBody uses pointer fields so only supplied keys are updated.
type patchChannelBody struct {
	Name   *string          `json:"name"`
	Config *json.RawMessage `json:"config"`
}

type channelEntry struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"org_id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

// channelCreateEntry extends channelEntry with the signing secret, returned only at creation.
type channelCreateEntry struct {
	channelEntry
	SigningSecret string `json:"signing_secret"`
}

type channelListResponse struct {
	Items []channelEntry `json:"items"`
}

type rotateSecretResponse struct {
	SigningSecret string `json:"signing_secret"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// createChannelHandler handles POST /api/v1/orgs/{org_id}/channels.
// Returns 201 with the channel and its signing_secret (shown only once).
func (srv *Server) createChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req createChannelBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusUnprocessableEntity)
		return
	}
	if req.Type == "" {
		req.Type = "webhook"
	}

	// For webhook channels, validate that config contains a non-empty url.
	if req.Type == "webhook" {
		var cfg map[string]any
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			http.Error(w, "webhook config must include a non-empty url", http.StatusUnprocessableEntity)
			return
		}
		urlVal, ok := cfg["url"].(string)
		if !ok || strings.TrimSpace(urlVal) == "" {
			http.Error(w, "webhook config must include a non-empty url", http.StatusUnprocessableEntity)
			return
		}
	}

	row, secret, err := srv.store.CreateNotificationChannel(r.Context(), orgID, req.Name, req.Type, req.Config)
	if err != nil {
		slog.ErrorContext(r.Context(), "create notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, channelCreateEntry{
		channelEntry: channelEntry{
			ID:        row.ID.String(),
			OrgID:     row.OrgID.String(),
			Name:      row.Name,
			Type:      row.Type,
			Config:    row.Config,
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
			UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
		},
		SigningSecret: secret,
	})
}

// getChannelHandler handles GET /api/v1/orgs/{org_id}/channels/{id}.
func (srv *Server) getChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	row, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, channelEntry{
		ID:        row.ID.String(),
		OrgID:     row.OrgID.String(),
		Name:      row.Name,
		Type:      row.Type,
		Config:    row.Config,
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
	})
}

// listChannelsHandler handles GET /api/v1/orgs/{org_id}/channels.
func (srv *Server) listChannelsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rows, err := srv.store.ListNotificationChannels(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list notification channels", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	items := make([]channelEntry, len(rows))
	for i, row := range rows {
		items[i] = channelEntry{
			ID:        row.ID.String(),
			OrgID:     row.OrgID.String(),
			Name:      row.Name,
			Type:      row.Type,
			Config:    row.Config,
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
			UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, channelListResponse{Items: items})
}

// patchChannelHandler handles PATCH /api/v1/orgs/{org_id}/channels/{id}.
// Only supplied fields are updated; absent fields preserve existing values.
func (srv *Server) patchChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req patchChannelBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Fetch current row to preserve unpatched fields.
	current, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel for patch", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	params := store.UpdateNotificationChannelParams{
		Name:   current.Name,
		Config: current.Config,
	}
	if req.Name != nil {
		params.Name = *req.Name
	}
	if req.Config != nil {
		params.Config = *req.Config
	}

	updated, err := srv.store.UpdateNotificationChannel(r.Context(), orgID, id, params)
	if err != nil {
		slog.ErrorContext(r.Context(), "update notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if updated == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, channelEntry{
		ID:        updated.ID.String(),
		OrgID:     updated.OrgID.String(),
		Name:      updated.Name,
		Type:      updated.Type,
		Config:    updated.Config,
		CreatedAt: updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt: updated.UpdatedAt.Format(time.RFC3339),
	})
}

// deleteChannelHandler handles DELETE /api/v1/orgs/{org_id}/channels/{id}.
// Returns 409 if the channel has active bound rules; 204 on success.
func (srv *Server) deleteChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	hasRules, err := srv.store.ChannelHasActiveBoundRules(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "check channel active bound rules", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if hasRules {
		http.Error(w, "channel has active bound rules", http.StatusConflict)
		return
	}

	if err := srv.store.SoftDeleteNotificationChannel(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "soft delete notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateSecretHandler handles POST /api/v1/orgs/{org_id}/channels/{id}/rotate-secret.
// Promotes the current primary to secondary, generates a new primary, returns it once.
func (srv *Server) rotateSecretHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	secret, err := srv.store.RotateSigningSecret(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "rotate signing secret", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rotateSecretResponse{SigningSecret: secret})
}
