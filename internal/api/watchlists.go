// ABOUTME: HTTP handlers for watchlist and watchlist item management.
// ABOUTME: Supports package (ecosystem+name), CPE and CVE item types, added singly or replaced as a whole list.
package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/tier"
)

// maxReplaceWatchlistItems is the most items one replace request may name. A CVE item is
// about 50 bytes of JSON, so a list at this cap is about 500 KB and fits the 1 MiB request
// limit. A list of long package or CPE items reaches the request limit first.
const maxReplaceWatchlistItems = 10000

// Length limits on watchlist item fields, matching the column CHECK constraints.
const (
	maxWatchlistPackageNameLen = 255
	maxWatchlistNamespaceLen   = 255
	maxWatchlistCPELen         = 512
	maxWatchlistCVEIDLen       = 32
)

// ── Request / response types ──────────────────────────────────────────────────

type createWatchlistBody struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	GroupID     *string `json:"group_id"`
}

// patchWatchlistBody fields are optional: an omitted field keeps its current
// value, and group_id null removes the watchlist from its group.
type patchWatchlistBody struct {
	Name        *string                `json:"name,omitempty"`
	Description *string                `json:"description,omitempty"`
	GroupID     clearableField[string] `json:"group_id,omitempty"`
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

// createWatchlistItemBody fields beyond item_type apply to one item type each:
// ecosystem, package_name and namespace to package, cpe_normalized to cpe, cve_id to cve.
type createWatchlistItemBody struct {
	ItemType      string  `json:"item_type" enum:"package,cpe,cve"`
	Ecosystem     *string `json:"ecosystem,omitempty"`
	PackageName   *string `json:"package_name,omitempty"`
	Namespace     *string `json:"namespace,omitempty"`
	CpeNormalized *string `json:"cpe_normalized,omitempty"`
	CveID         *string `json:"cve_id,omitempty" doc:"CVE identifier such as CVE-2024-3094. Stored in upper case."`
}

type watchlistItemEntry struct {
	ID            string  `json:"id"`
	ItemType      string  `json:"item_type" enum:"package,cpe,cve"`
	Ecosystem     *string `json:"ecosystem,omitempty"`
	PackageName   *string `json:"package_name,omitempty"`
	Namespace     *string `json:"namespace,omitempty"`
	CpeNormalized *string `json:"cpe_normalized,omitempty"`
	CveID         *string `json:"cve_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

type replaceWatchlistItemsBody struct {
	Items []createWatchlistItemBody `json:"items" maxItems:"10000" doc:"The complete list of items the watchlist should hold. An empty array removes every item."`
}

type watchlistItemsReplaced struct {
	Added     int `json:"added" doc:"Items that were not on the watchlist and were added"`
	Removed   int `json:"removed" doc:"Items that were on the watchlist, not in the request, and were removed"`
	Unchanged int `json:"unchanged" doc:"Items that were already on the watchlist and were left as they are"`
}

// ── Cursor helpers ────────────────────────────────────────────────────────────

// watchlistCursor is the JSON-encoded keyset cursor for watchlist pagination.
type watchlistCursor struct {
	T  string `json:"t"`  // created_at RFC3339Nano
	ID string `json:"id"` // UUID tiebreaker
}

// watchlistItemCursor is the JSON-encoded keyset cursor for watchlist item pagination.
type watchlistItemCursor struct {
	ID string `json:"id"`
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
	if item.CveID.Valid {
		e.CveID = &item.CveID.String
	}
	return e
}

// validWatchlistItemText reports whether s can be stored in a watchlist item text field:
// not blank, within maxLen characters, and without the NUL byte Postgres text rejects.
func validWatchlistItemText(s string, maxLen int) bool {
	return strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= maxLen && !strings.ContainsRune(s, 0)
}

// parseWatchlistItem validates a watchlist item from a request and returns its store
// parameters, or the validation failure. loc is the item's location in the request body.
func parseWatchlistItem(req createWatchlistItemBody, loc string) (store.CreateWatchlistItemParams, *huma.ErrorDetail) {
	invalid := func(message, field string) (store.CreateWatchlistItemParams, *huma.ErrorDetail) {
		return store.CreateWatchlistItemParams{}, &huma.ErrorDetail{Message: message, Location: loc + field}
	}

	switch req.ItemType {
	case "package":
		if req.Ecosystem == nil || req.PackageName == nil {
			return invalid("ecosystem and package_name are required for package items", "")
		}
		if !ecosystem.Valid(*req.Ecosystem) {
			return invalid("unknown ecosystem; valid names: "+strings.Join(ecosystem.Names(), ", "), ".ecosystem")
		}
		if !validWatchlistItemText(*req.PackageName, maxWatchlistPackageNameLen) {
			return invalid(fmt.Sprintf("package_name must be 1 to %d characters", maxWatchlistPackageNameLen), ".package_name")
		}
		namespace := req.Namespace
		if namespace != nil && *namespace == "" {
			namespace = nil
		}
		if namespace != nil && !validWatchlistItemText(*namespace, maxWatchlistNamespaceLen) {
			return invalid(fmt.Sprintf("namespace must be at most %d characters", maxWatchlistNamespaceLen), ".namespace")
		}
		return store.CreateWatchlistItemParams{
			ItemType:    store.WatchlistItemType("package"),
			Ecosystem:   req.Ecosystem,
			PackageName: req.PackageName,
			Namespace:   namespace,
		}, nil
	case "cpe":
		if req.CpeNormalized == nil {
			return invalid("cpe_normalized is required for cpe items", ".cpe_normalized")
		}
		if !strings.HasPrefix(*req.CpeNormalized, "cpe:2.3:") {
			return invalid("cpe_normalized must start with cpe:2.3:", ".cpe_normalized")
		}
		if !validWatchlistItemText(*req.CpeNormalized, maxWatchlistCPELen) {
			return invalid(fmt.Sprintf("cpe_normalized must be at most %d characters", maxWatchlistCPELen), ".cpe_normalized")
		}
		return store.CreateWatchlistItemParams{
			ItemType:      store.WatchlistItemType("cpe"),
			CpeNormalized: req.CpeNormalized,
		}, nil
	case "cve":
		if req.CveID == nil {
			return invalid("cve_id is required for cve items", ".cve_id")
		}
		// cves.cve_id is upper case and the watchlist filter compares it exactly.
		cveID := strings.ToUpper(*req.CveID)
		if len(cveID) > maxWatchlistCVEIDLen || !isValidCVEID(cveID) {
			return invalid("cve_id must be a CVE identifier such as CVE-2024-3094", ".cve_id")
		}
		return store.CreateWatchlistItemParams{
			ItemType: store.WatchlistItemType("cve"),
			CveID:    &cveID,
		}, nil
	default:
		return invalid("item_type must be 'package', 'cpe' or 'cve'", ".item_type")
	}
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
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", decErr)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "name is required", Location: "body.name"})
		return
	}

	var groupID uuid.NullUUID
	if req.GroupID != nil {
		id, ok := srv.resolveWatchlistGroup(w, r, orgID, *req.GroupID)
		if !ok {
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

	if c := r.URL.Query().Get("cursor"); c != "" {
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

// resolveWatchlistGroup parses a watchlist's group_id and checks that it names
// an active group in the org. The foreign key on watchlists.group_id does not
// check the org, because Postgres runs foreign-key checks without RLS. On
// failure it writes the problem response and returns false.
func (srv *Server) resolveWatchlistGroup(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "invalid group_id", Location: "body.group_id"})
		return uuid.Nil, false
	}
	group, err := srv.store.GetGroupIfActive(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "watchlist: get group", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return uuid.Nil, false
	}
	if group == nil {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "group not found", Location: "body.group_id"})
		return uuid.Nil, false
	}
	return id, true
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
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", decErr)
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
	if req.GroupID.Sent {
		if req.GroupID.Value == nil {
			p.GroupID = uuid.NullUUID{}
		} else {
			gid, ok := srv.resolveWatchlistGroup(w, r, orgID, *req.GroupID.Value)
			if !ok {
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
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", decErr)
		return
	}

	p, detail := parseWatchlistItem(req, "body")
	if detail != nil {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", detail)
		return
	}

	// Foreign-key checks run without RLS, so the insert alone would accept another org's
	// watchlist ID, and the row would then occupy that watchlist's unique index.
	owned, err := srv.store.ValidateWatchlistsOwnership(r.Context(), orgID, []uuid.UUID{watchlistID})
	if err != nil {
		slog.ErrorContext(r.Context(), "check watchlist ownership", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !owned {
		writeProblem(w, http.StatusNotFound, "not found")
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

// replaceWatchlistItemsHandler handles PUT /api/v1/orgs/{org_id}/watchlists/{id}/items.
// Requires member+. Makes the watchlist hold exactly the items in the request, in one
// transaction. Items already on the watchlist keep their rows, so repeating a request
// changes nothing. An empty array clears the watchlist. A missing items key is rejected, so
// that a client bug cannot read as a request to clear it.
func (srv *Server) replaceWatchlistItemsHandler(w http.ResponseWriter, r *http.Request) {
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

	var req replaceWatchlistItemsBody
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", decErr)
		return
	}
	if req.Items == nil {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "items is required: send an empty array to clear the watchlist", Location: "body.items"})
		return
	}
	if len(req.Items) > maxReplaceWatchlistItems {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: fmt.Sprintf("items must hold at most %d items", maxReplaceWatchlistItems), Location: "body.items"})
		return
	}

	items := make([]store.CreateWatchlistItemParams, 0, len(req.Items))
	for i, raw := range req.Items {
		item, detail := parseWatchlistItem(raw, fmt.Sprintf("body.items[%d]", i))
		if detail != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", detail)
			return
		}
		items = append(items, item)
	}

	result, err := srv.store.ReplaceWatchlistItems(r.Context(), orgID, watchlistID, items)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "items name the same package more than once with different namespaces")
			return
		}
		slog.ErrorContext(r.Context(), "replace watchlist items", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if result == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	writeJSON(w, http.StatusOK, watchlistItemsReplaced{
		Added:     result.Added,
		Removed:   result.Removed,
		Unchanged: result.Unchanged,
	})
	if result.Added > 0 || result.Removed > 0 {
		srv.auditLog(r, audit.Entry{
			OrgID:      orgID,
			Action:     "update",
			EntityType: "watchlist",
			EntityID:   watchlistID.String(),
			Success:    true,
			Metadata:   map[string]any{"items_added": result.Added, "items_removed": result.Removed},
		})
	}
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
	if a := r.URL.Query().Get("cursor"); a != "" {
		var cur watchlistItemCursor
		if err := decodePageCursor(a, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		id, err := uuid.Parse(cur.ID)
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
		nextCursor = encodePageCursor(watchlistItemCursor{
			ID: items[len(items)-1].ID.String(),
		})
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
