// ABOUTME: HTTP handlers for watchlist and watchlist item management.
// ABOUTME: Supports package (ecosystem+name) and CPE item types with validation.
package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/store"
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

type watchlistListResponse struct {
	Items      []watchlistEntry `json:"items"`
	NextCursor *string          `json:"next_cursor,omitempty"`
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

type watchlistItemsResponse struct {
	Items      []watchlistItemEntry `json:"items"`
	NextCursor *string              `json:"next_cursor,omitempty"`
}

// ── Cursor helpers ────────────────────────────────────────────────────────────

// encodeTimeCursor encodes a (time, uuid) pair as a base64 cursor string.
func encodeTimeCursor(t time.Time, id uuid.UUID) string {
	raw := t.UTC().Format(time.RFC3339Nano) + "|" + id.String()
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// decodeTimeCursor decodes a base64 cursor into a (time, uuid) pair.
func decodeTimeCursor(s string) (time.Time, uuid.UUID, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, fmt.Errorf("decode cursor: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, fmt.Errorf("invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, fmt.Errorf("cursor time: %w", err)
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, fmt.Errorf("cursor id: %w", err)
	}
	return t, id, nil
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
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req createWatchlistBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	var groupID uuid.NullUUID
	if req.GroupID != nil {
		id, err := uuid.Parse(*req.GroupID)
		if err != nil {
			http.Error(w, "invalid group_id", http.StatusBadRequest)
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
			http.Error(w, "watchlist name already exists", http.StatusConflict)
			return
		}
		slog.ErrorContext(r.Context(), "create watchlist", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, watchlistToEntry(*row))
}

// getWatchlistHandler handles GET /api/v1/orgs/{org_id}/watchlists/{id}.
// Requires viewer+.
func (srv *Server) getWatchlistHandler(w http.ResponseWriter, r *http.Request) {
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

	row, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get watchlist", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, watchlistToEntry(*row))
}

// listWatchlistsHandler handles GET /api/v1/orgs/{org_id}/watchlists.
// Requires viewer+. Cursor-based pagination on (created_at DESC, id DESC).
func (srv *Server) listWatchlistsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	const limit = 20
	var afterTime *time.Time
	var afterID *uuid.UUID

	if c := r.URL.Query().Get("after"); c != "" {
		t, id, err := decodeTimeCursor(c)
		if err == nil {
			afterTime = &t
			afterID = &id
		}
	}

	rows, err := srv.store.ListWatchlists(r.Context(), orgID, afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "list watchlists", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var nextCursor *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := encodeTimeCursor(last.CreatedAt, last.ID)
		nextCursor = &c
	}

	entries := make([]watchlistEntry, 0, len(rows))
	for _, wl := range rows {
		entries = append(entries, watchlistToEntry(wl))
	}
	writeJSON(w, http.StatusOK, watchlistListResponse{Items: entries, NextCursor: nextCursor})
}

// updateWatchlistHandler handles PATCH /api/v1/orgs/{org_id}/watchlists/{id}.
// Requires member+. Only updates non-nil fields.
func (srv *Server) updateWatchlistHandler(w http.ResponseWriter, r *http.Request) {
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

	current, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get watchlist for patch", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var req patchWatchlistBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	p := store.UpdateWatchlistParams{
		Name:        current.Name,
		Description: current.Description,
		GroupID:     current.GroupID,
	}

	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			http.Error(w, "name cannot be empty", http.StatusBadRequest)
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
				http.Error(w, "invalid group_id", http.StatusBadRequest)
				return
			}
			p.GroupID = uuid.NullUUID{UUID: gid, Valid: true}
		}
	}

	updated, err := srv.store.UpdateWatchlist(r.Context(), orgID, id, p)
	if err != nil {
		if isUniqueViolation(err) {
			http.Error(w, "watchlist name already exists", http.StatusConflict)
			return
		}
		slog.ErrorContext(r.Context(), "update watchlist", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if updated == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Re-fetch to include item_count.
	row, err := srv.store.GetWatchlist(r.Context(), orgID, id)
	if err != nil || row == nil {
		slog.ErrorContext(r.Context(), "re-fetch watchlist after update", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, watchlistToEntry(*row))
}

// deleteWatchlistHandler handles DELETE /api/v1/orgs/{org_id}/watchlists/{id}.
// Requires member+. Soft-deletes the watchlist.
func (srv *Server) deleteWatchlistHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := srv.store.DeleteWatchlist(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "delete watchlist", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// createWatchlistItemHandler handles POST /api/v1/orgs/{org_id}/watchlists/{id}/items.
// Requires member+.
func (srv *Server) createWatchlistItemHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	watchlistID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid watchlist id", http.StatusBadRequest)
		return
	}

	var req createWatchlistItemBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var p store.CreateWatchlistItemParams
	switch req.ItemType {
	case "package":
		if req.Ecosystem == nil || req.PackageName == nil {
			http.Error(w, "ecosystem and package_name are required for package items", http.StatusUnprocessableEntity)
			return
		}
		eco := strings.ToLower(*req.Ecosystem)
		if !validEcosystems[eco] {
			http.Error(w, "unknown ecosystem", http.StatusUnprocessableEntity)
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
			http.Error(w, "cpe_normalized is required for cpe items", http.StatusUnprocessableEntity)
			return
		}
		if !strings.HasPrefix(*req.CpeNormalized, "cpe:2.3:") {
			http.Error(w, "cpe_normalized must start with cpe:2.3:", http.StatusUnprocessableEntity)
			return
		}
		p = store.CreateWatchlistItemParams{
			ItemType:      store.WatchlistItemType("cpe"),
			CpeNormalized: req.CpeNormalized,
		}
	default:
		http.Error(w, "item_type must be 'package' or 'cpe'", http.StatusUnprocessableEntity)
		return
	}

	item, err := srv.store.CreateWatchlistItem(r.Context(), orgID, watchlistID, p)
	if err != nil {
		if isUniqueViolation(err) {
			http.Error(w, "item already exists in watchlist", http.StatusConflict)
			return
		}
		slog.ErrorContext(r.Context(), "create watchlist item", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, watchlistItemToEntry(*item))
}

// listWatchlistItemsHandler handles GET /api/v1/orgs/{org_id}/watchlists/{id}/items.
// Requires viewer+. Cursor-based pagination on id ASC.
func (srv *Server) listWatchlistItemsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	watchlistID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid watchlist id", http.StatusBadRequest)
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
		if err == nil {
			afterID = &id
		}
	}

	items, err := srv.store.ListWatchlistItems(r.Context(), orgID, watchlistID, itemTypeFilter, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "list watchlist items", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var nextCursor *string
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1].ID.String()
		nextCursor = &last
	}

	entries := make([]watchlistItemEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, watchlistItemToEntry(item))
	}
	writeJSON(w, http.StatusOK, watchlistItemsResponse{Items: entries, NextCursor: nextCursor})
}

// deleteWatchlistItemHandler handles DELETE /api/v1/orgs/{org_id}/watchlists/{id}/items/{item_id}.
// Requires member+.
func (srv *Server) deleteWatchlistItemHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	watchlistID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid watchlist id", http.StatusBadRequest)
		return
	}

	itemID, err := uuid.Parse(chi.URLParam(r, "item_id"))
	if err != nil {
		http.Error(w, "invalid item id", http.StatusBadRequest)
		return
	}

	if err := srv.store.DeleteWatchlistItem(r.Context(), orgID, watchlistID, itemID); err != nil {
		slog.ErrorContext(r.Context(), "delete watchlist item", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
