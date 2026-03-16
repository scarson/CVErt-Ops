// ABOUTME: HTTP handlers for watchlist and watchlist item management.
// ABOUTME: Supports package (ecosystem+name) and CPE item types with validation.
package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/tier"
)

// validEcosystems is the whitelist of supported package ecosystems.
var validEcosystems = map[string]bool{
	"npm": true, "pypi": true, "maven": true, "go": true,
	"cargo": true, "rubygems": true, "nuget": true, "hex": true,
	"pub": true, "swift": true, "cocoapods": true, "packagist": true,
}

// ── Request / response types ──────────────────────────────────────────────────

type createWatchlistBody struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	GroupID     *string `json:"group_id"`
}

// patchWatchlistBody uses double-pointer for group_id to distinguish omit vs null vs value.
// nil outer pointer = key omitted (no change); non-nil outer, nil inner = JSON null (clear);
// non-nil outer, non-nil inner = new UUID.
type patchWatchlistBody struct {
	Name        *string  `json:"name"`
	Description *string  `json:"description"`
	GroupID     **string `json:"group_id"`
}

type watchlistEntry struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	GroupID     *string `json:"group_id,omitempty"`
	ItemCount   int64   `json:"item_count"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}


type createWatchlistItemBody struct {
	ItemType      string  `json:"item_type"`
	Ecosystem     *string `json:"ecosystem"`
	PackageName   *string `json:"package_name"`
	Namespace     *string `json:"namespace"`
	CpeNormalized *string `json:"cpe_normalized"`
}

type watchlistItemEntry struct {
	ID            string  `json:"id"`
	ItemType      string  `json:"item_type"`
	Ecosystem     *string `json:"ecosystem,omitempty"`
	PackageName   *string `json:"package_name,omitempty"`
	Namespace     *string `json:"namespace,omitempty"`
	CpeNormalized *string `json:"cpe_normalized,omitempty"`
	CreatedAt     string  `json:"created_at"`
}


// ── Cursor helpers ────────────────────────────────────────────────────────────

// watchlistCursor is the JSON-encoded keyset cursor for watchlist pagination.
type watchlistCursor struct {
	T  string `json:"t"`  // created_at RFC3339Nano
	ID string `json:"id"` // UUID tiebreaker
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

func watchlistToEntry(r store.WatchlistRow) watchlistEntry {
	e := watchlistEntry{
		ID:        r.ID.String(),
		Name:      r.Name,
		ItemCount: r.ItemCount,
		CreatedAt: r.CreatedAt.Format(time.RFC3339),
		UpdatedAt: r.UpdatedAt.Format(time.RFC3339),
	}
	if r.Description.Valid {
		e.Description = &r.Description.String
	}
	if r.GroupID.Valid {
		s := r.GroupID.UUID.String()
		e.GroupID = &s
	}
	return e
}

func watchlistItemToEntry(item store.WatchlistItemRow) watchlistItemEntry {
	e := watchlistItemEntry{
		ID:        item.ID.String(),
		ItemType:  string(item.ItemType),
		CreatedAt: item.CreatedAt.Format(time.RFC3339),
	}
	if item.Ecosystem.Valid {
		e.Ecosystem = &item.Ecosystem.String
	}
	if item.PackageName.Valid {
		e.PackageName = &item.PackageName.String
	}
	if item.Namespace.Valid {
		e.Namespace = &item.Namespace.String
	}
	if item.CpeNormalized.Valid {
		e.CpeNormalized = &item.CpeNormalized.String
	}
	return e
}

// isUniqueViolation returns true if err (or any wrapped error) is a Postgres unique constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// createWatchlistHandler handles POST /api/v1/orgs/{org_id}/watchlists.
// Requires member+.
func (srv *Server) createWatchlistHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	// Tier gating: check watchlist count limit.
	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		slog.ErrorContext(r.Context(), "tier resolver missing from context")
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	limit := resolver.ResolveInt(tier.LimitWatchlists)
	if limit >= 0 {
		count, err := srv.store.CountWatchlistsByOrg(r.Context(), orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "count watchlists for tier check", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		if count >= int64(limit) {
			srv.auditLog(r, audit.Entry{
				OrgID:      orgID,
				Action:     "create",
				EntityType: "watchlist",
				Success:    false,
				Metadata:   map[string]any{"reason": "tier_limit"},
			})
			writeProblemTyped(w, http.StatusForbidden, problemTypeTierLimit, "watchlist limit reached for current tier")
			return
		}
	}

	var req createWatchlistBody
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, decErr.Message, decErr)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "name is required", Location: "body.name"})
		return
	}

	var groupID uuid.NullUUID
	if req.GroupID != nil {
		id, err := uuid.Parse(*req.GroupID)
		if err != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "invalid group_id", Location: "body.group_id"})
			return
		}
		groupID = uuid.NullUUID{UUID: id, Valid: true}
	}

	var desc sql.NullString
	if req.Description != nil {
		desc = sql.NullString{String: *req.Description, Valid: true}
	}

	row, err := srv.store.CreateWatchlist(r.Context(), orgID, groupID, req.Name, desc)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "watchlist name already exists")
			return
		}
		slog.ErrorContext(r.Context(), "create watchlist", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	wlEntry := watchlistToEntry(*row)
	writeLocation(w, r, row.ID.String())
	writeJSON(w, http.StatusCreated, wlEntry)
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "create",
		EntityType: "watchlist",
		EntityID:   row.ID.String(),
		EntityName: row.Name,
		Success:    true,
		NewState:   wlEntry,
	})
}

// getWatchlistHandler handles GET /api/v1/orgs/{org_id}/watchlists/{id}.
// Requires viewer+.
func (srv *Server) getWatchlistHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	row, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get watchlist", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	writeJSON(w, http.StatusOK, watchlistToEntry(*row))
}

// listWatchlistsHandler handles GET /api/v1/orgs/{org_id}/watchlists.
// Requires viewer+. Cursor-based pagination on (created_at DESC, id DESC).
func (srv *Server) listWatchlistsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	const limit = 20
	var afterTime *time.Time
	var afterID *uuid.UUID

	if c := r.URL.Query().Get("after"); c != "" {
		var cur watchlistCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		t, err := time.Parse(time.RFC3339Nano, cur.T)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterTime = &t
		afterID = &id
	}

	rows, err := srv.store.ListWatchlists(r.Context(), orgID, afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "list watchlists", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		nextCursor = encodePageCursor(watchlistCursor{
			T:  last.CreatedAt.UTC().Format(time.RFC3339Nano),
			ID: last.ID.String(),
		})
	}

	entries := make([]watchlistEntry, 0, len(rows))
	for _, wl := range rows {
		entries = append(entries, watchlistToEntry(wl))
	}
	writeList(w, entries, nextCursor)
}

// updateWatchlistHandler handles PATCH /api/v1/orgs/{org_id}/watchlists/{id}.
// Requires member+. Only updates non-nil fields.
func (srv *Server) updateWatchlistHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	current, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get watchlist for patch", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	oldState := watchlistToEntry(*current)

	var req patchWatchlistBody
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, decErr.Message, decErr)
		return
	}

	p := store.UpdateWatchlistParams{
		Name:        current.Name,
		Description: current.Description,
		GroupID:     current.GroupID,
	}

	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "name cannot be empty", Location: "body.name"})
			return
		}
		p.Name = *req.Name
	}
	if req.Description != nil {
		p.Description = sql.NullString{String: *req.Description, Valid: true}
	}
	if req.GroupID != nil {
		if *req.GroupID == nil {
			p.GroupID = uuid.NullUUID{}
		} else {
			gid, err := uuid.Parse(**req.GroupID)
			if err != nil {
				writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
					&huma.ErrorDetail{Message: "invalid group_id", Location: "body.group_id"})
				return
			}
			p.GroupID = uuid.NullUUID{UUID: gid, Valid: true}
		}
	}

	updated, err := srv.store.UpdateWatchlist(r.Context(), orgID, id, p)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "watchlist name already exists")
			return
		}
		slog.ErrorContext(r.Context(), "update watchlist", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if updated == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	// Re-fetch to include item_count.
	row, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil || row == nil {
		slog.ErrorContext(r.Context(), "re-fetch watchlist after update", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	newEntry := watchlistToEntry(*row)
	writeJSON(w, http.StatusOK, newEntry)
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "watchlist",
		EntityID:   id.String(),
		EntityName: row.Name,
		Success:    true,
		OldState:   oldState,
		NewState:   newEntry,
	})
}

// deleteWatchlistHandler handles DELETE /api/v1/orgs/{org_id}/watchlists/{id}.
// Requires member+. Soft-deletes the watchlist.
func (srv *Server) deleteWatchlistHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Fetch before delete for audit log.
	current, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get watchlist for delete", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	if err := srv.store.DeleteWatchlist(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "delete watchlist", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "delete",
		EntityType: "watchlist",
		EntityID:   id.String(),
		EntityName: current.Name,
		Success:    true,
		OldState:   watchlistToEntry(*current),
	})
	w.WriteHeader(http.StatusNoContent)
}

// createWatchlistItemHandler handles POST /api/v1/orgs/{org_id}/watchlists/{id}/items.
// Requires member+.
func (srv *Server) createWatchlistItemHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	watchlistID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid watchlist id")
		return
	}

	var req createWatchlistItemBody
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, decErr.Message, decErr)
		return
	}

	var p store.CreateWatchlistItemParams
	switch req.ItemType {
	case "package":
		if req.Ecosystem == nil || req.PackageName == nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "ecosystem and package_name are required for package items", Location: "body"})
			return
		}
		eco := strings.ToLower(*req.Ecosystem)
		if !validEcosystems[eco] {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "unknown ecosystem", Location: "body.ecosystem"})
			return
		}
		p = store.CreateWatchlistItemParams{
			ItemType:    store.WatchlistItemType("package"),
			Ecosystem:   &eco,
			PackageName: req.PackageName,
			Namespace:   req.Namespace,
		}
	case "cpe":
		if req.CpeNormalized == nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "cpe_normalized is required for cpe items", Location: "body.cpe_normalized"})
			return
		}
		if !strings.HasPrefix(*req.CpeNormalized, "cpe:2.3:") {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "cpe_normalized must start with cpe:2.3:", Location: "body.cpe_normalized"})
			return
		}
		p = store.CreateWatchlistItemParams{
			ItemType:      store.WatchlistItemType("cpe"),
			CpeNormalized: req.CpeNormalized,
		}
	default:
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "item_type must be 'package' or 'cpe'", Location: "body.item_type"})
		return
	}

	item, err := srv.store.CreateWatchlistItem(r.Context(), orgID, watchlistID, p)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "item already exists in watchlist")
			return
		}
		slog.ErrorContext(r.Context(), "create watchlist item", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeLocation(w, r, item.ID.String())
	writeJSON(w, http.StatusCreated, watchlistItemToEntry(*item))
}

// listWatchlistItemsHandler handles GET /api/v1/orgs/{org_id}/watchlists/{id}/items.
// Requires viewer+. Cursor-based pagination on id ASC.
func (srv *Server) listWatchlistItemsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	watchlistID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid watchlist id")
		return
	}

	const limit = 50
	var itemTypeFilter *store.WatchlistItemType
	var afterID *uuid.UUID

	if it := r.URL.Query().Get("item_type"); it != "" {
		t := store.WatchlistItemType(it)
		itemTypeFilter = &t
	}
	if a := r.URL.Query().Get("after"); a != "" {
		id, err := uuid.Parse(a)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterID = &id
	}

	items, err := srv.store.ListWatchlistItems(r.Context(), orgID, watchlistID, itemTypeFilter, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "list watchlist items", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(items) > limit {
		items = items[:limit]
		nextCursor = items[len(items)-1].ID.String()
	}

	entries := make([]watchlistItemEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, watchlistItemToEntry(item))
	}
	writeList(w, entries, nextCursor)
}

// deleteWatchlistItemHandler handles DELETE /api/v1/orgs/{org_id}/watchlists/{id}/items/{item_id}.
// Requires member+.
func (srv *Server) deleteWatchlistItemHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	watchlistID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid watchlist id")
		return
	}

	itemID, err := uuid.Parse(chi.URLParam(r, "item_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid item id")
		return
	}

	deleted, err := srv.store.DeleteWatchlistItem(r.Context(), orgID, watchlistID, itemID)
	if err != nil {
		slog.ErrorContext(r.Context(), "delete watchlist item", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !deleted {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
