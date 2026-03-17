// ABOUTME: Site admin organization management API handlers.
// ABOUTME: GET list (paginated), PATCH update (tier/suspend), GET usage counts.
package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// adminOrgResponse is a JSON-safe representation of an organization for API responses.
type adminOrgResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Tier        string     `json:"tier"`
	SuspendedAt *time.Time `json:"suspended_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

func toAdminOrgResponse(org *generated.Organization) adminOrgResponse {
	resp := adminOrgResponse{
		ID:        org.ID,
		Name:      org.Name,
		Tier:      org.Tier,
		CreatedAt: org.CreatedAt,
	}
	if org.SuspendedAt.Valid {
		t := org.SuspendedAt.Time
		resp.SuspendedAt = &t
	}
	return resp
}

// adminOrgCursor is the opaque cursor for admin org list pagination.
type adminOrgCursor struct {
	T  time.Time `json:"t"`
	ID string    `json:"id"`
}

// adminListOrgsHandler handles GET /api/v1/admin/orgs.
func (srv *Server) adminListOrgsHandler(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimitParam(w, r, 50, 200)
	if !ok {
		return
	}

	var afterTime *time.Time
	var afterID *uuid.UUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur adminOrgCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterTime = &cur.T
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterID = &id
	}

	orgs, err := srv.store.AdminListOrgs(r.Context(), afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin list orgs", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(orgs) > limit {
		orgs = orgs[:limit]
		last := orgs[len(orgs)-1]
		nextCursor = encodePageCursor(adminOrgCursor{T: last.CreatedAt, ID: last.ID.String()})
	}

	writeList(w, orgs, nextCursor)
}

// adminPatchOrgHandler handles PATCH /api/v1/admin/orgs/{org_id}.
func (srv *Server) adminPatchOrgHandler(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "org_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid org_id")
		return
	}

	var body struct {
		Tier    *string `json:"tier"`
		Suspend *bool   `json:"suspend"`
	}
	if errDetail := decodeJSON(r, &body); errDetail != nil {
		writeProblem(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Verify org exists.
	org, err := srv.store.AdminGetOrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin patch org: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if org.DeletedAt.Valid {
		writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}

	if body.Tier != nil {
		valid := map[string]bool{"free": true, "pro": true, "enterprise": true}
		if !valid[*body.Tier] {
			writeProblem(w, http.StatusBadRequest, "invalid tier (free, pro, enterprise)")
			return
		}
		if _, err := srv.store.AdminUpdateOrgTier(r.Context(), orgID, *body.Tier); err != nil {
			slog.ErrorContext(r.Context(), "admin patch org: tier", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
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
					writeProblem(w, http.StatusInternalServerError, "internal error")
					return
				}
			}
		} else {
			if _, err := srv.store.AdminUnsuspendOrg(r.Context(), orgID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					// Already unsuspended — idempotent.
				} else {
					slog.ErrorContext(r.Context(), "admin patch org: unsuspend", "error", err)
					writeProblem(w, http.StatusInternalServerError, "internal error")
					return
				}
			}
		}
	}

	// Re-fetch and return updated org.
	updated, err := srv.store.AdminGetOrgByID(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin patch org: re-fetch", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, toAdminOrgResponse(updated))
}

// adminOrgUsageHandler handles GET /api/v1/admin/orgs/{org_id}/usage.
func (srv *Server) adminOrgUsageHandler(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "org_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid org_id")
		return
	}

	// Verify org exists.
	org, err := srv.store.AdminGetOrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin org usage: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if org.DeletedAt.Valid {
		writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}

	usage, err := srv.store.AdminGetOrgUsage(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin org usage", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, usage)
}
