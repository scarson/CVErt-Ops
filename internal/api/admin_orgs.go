// ABOUTME: Site admin organization management API handlers.
// ABOUTME: GET list (paginated), PATCH update (tier/suspend), GET usage counts.
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// adminListOrgsHandler handles GET /api/v1/admin/orgs.
func (srv *Server) adminListOrgsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 || parsed > 200 {
			http.Error(w, "invalid limit (1-200)", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	var afterTime *time.Time
	var afterID *uuid.UUID

	if cursor := r.URL.Query().Get("after_time"); cursor != "" {
		t, err := time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			http.Error(w, "invalid after_time (RFC3339)", http.StatusBadRequest)
			return
		}
		afterTime = &t
	}
	if cursor := r.URL.Query().Get("after_id"); cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			http.Error(w, "invalid after_id (UUID)", http.StatusBadRequest)
			return
		}
		afterID = &id
	}

	// Both cursor fields must be present or absent together.
	if (afterTime == nil) != (afterID == nil) {
		http.Error(w, "after_time and after_id must both be provided or both omitted", http.StatusBadRequest)
		return
	}

	orgs, err := srv.store.AdminListOrgs(r.Context(), afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin list orgs", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hasMore := len(orgs) > limit
	if hasMore {
		orgs = orgs[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"items":    orgs,
		"has_more": hasMore,
	}); err != nil {
		slog.ErrorContext(r.Context(), "admin list orgs: encode", "error", err)
	}
}

// adminPatchOrgHandler handles PATCH /api/v1/admin/orgs/{org_id}.
func (srv *Server) adminPatchOrgHandler(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	var body struct {
		Tier    *string `json:"tier"`
		Suspend *bool   `json:"suspend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Verify org exists.
	org, err := srv.store.AdminGetOrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "organization not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin patch org: get", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if org.DeletedAt.Valid {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}

	if body.Tier != nil {
		valid := map[string]bool{"free": true, "pro": true, "enterprise": true}
		if !valid[*body.Tier] {
			http.Error(w, "invalid tier (free, pro, enterprise)", http.StatusBadRequest)
			return
		}
		if _, err := srv.store.AdminUpdateOrgTier(r.Context(), orgID, *body.Tier); err != nil {
			slog.ErrorContext(r.Context(), "admin patch org: tier", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if body.Suspend != nil {
		if *body.Suspend {
			if _, err := srv.store.AdminSuspendOrg(r.Context(), orgID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					// Already suspended — idempotent.
				} else {
					slog.ErrorContext(r.Context(), "admin patch org: suspend", "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
		} else {
			if _, err := srv.store.AdminUnsuspendOrg(r.Context(), orgID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					// Already unsuspended — idempotent.
				} else {
					slog.ErrorContext(r.Context(), "admin patch org: unsuspend", "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
		}
	}

	// Re-fetch and return updated org.
	updated, err := srv.store.AdminGetOrgByID(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin patch org: re-fetch", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		slog.ErrorContext(r.Context(), "admin patch org: encode", "error", err)
	}
}

// adminOrgUsageHandler handles GET /api/v1/admin/orgs/{org_id}/usage.
func (srv *Server) adminOrgUsageHandler(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "org_id"))
	if err != nil {
		http.Error(w, "invalid org_id", http.StatusBadRequest)
		return
	}

	// Verify org exists.
	org, err := srv.store.AdminGetOrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "organization not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin org usage: get", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if org.DeletedAt.Valid {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}

	usage, err := srv.store.AdminGetOrgUsage(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin org usage", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(usage); err != nil {
		slog.ErrorContext(r.Context(), "admin org usage: encode", "error", err)
	}
}
