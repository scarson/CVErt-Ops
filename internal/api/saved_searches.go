// ABOUTME: HTTP handlers for saved search CRUD and execution.
// ABOUTME: Supports private and org-shared visibility with RBAC enforcement.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/store"
)

// ── Request / response types ────────────────────────────────────────────────────

type createSavedSearchRequest struct {
	Name      string          `json:"name"`
	QueryJSON json.RawMessage `json:"query_json"`
	NlQuery   *string         `json:"nl_query,omitempty"`
	IsShared  bool            `json:"is_shared"`
}

type patchSavedSearchRequest struct {
	Name      *string          `json:"name,omitempty"`
	QueryJSON *json.RawMessage `json:"query_json,omitempty"`
	NlQuery   *string          `json:"nl_query,omitempty"`
	IsShared  *bool            `json:"is_shared,omitempty"`
}

type savedSearchEntry struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	QueryJSON json.RawMessage `json:"query_json"`
	NlQuery   *string         `json:"nl_query,omitempty"`
	IsShared  bool            `json:"is_shared"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

type savedSearchExecuteResponse struct {
	Items      []CVEItem `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

// savedSearchToEntry converts a store row to an API response entry.
func savedSearchToEntry(row *store.SavedSearchRow) savedSearchEntry {
	entry := savedSearchEntry{
		ID:        row.ID.String(),
		Name:      row.Name,
		QueryJSON: row.QueryJSON,
		IsShared:  row.IsShared,
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
	}
	if row.NlQuery.Valid {
		entry.NlQuery = &row.NlQuery.String
	}
	return entry
}

// validateDSL parses and validates a DSL query JSON blob.
// Returns an error message and HTTP status code if invalid.
func validateDSL(queryJSON json.RawMessage) (string, int) {
	rule, err := dsl.Parse(queryJSON)
	if err != nil {
		return "invalid query_json: " + err.Error(), http.StatusUnprocessableEntity
	}
	valErrs, _, _ := dsl.Validate(rule, false)
	if hasBlockingErrors(valErrs) {
		return "query_json validation failed", http.StatusUnprocessableEntity
	}
	return "", 0
}

// ── Handlers ────────────────────────────────────────────────────────────────────

// createSavedSearchHandler handles POST /api/v1/orgs/{org_id}/saved-searches.
func (srv *Server) createSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	var req createSavedSearchRequest
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}

	if req.Name == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "name is required", Location: "body.name", Value: ""})
		return
	}
	if len(req.Name) > 255 {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "name must not exceed 255 characters", Location: "body.name", Value: req.Name})
		return
	}
	if req.NlQuery != nil && len(*req.NlQuery) > 1000 {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "nl_query must not exceed 1000 characters", Location: "body.nl_query", Value: *req.NlQuery})
		return
	}

	if len(req.QueryJSON) == 0 {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "query_json is required", Location: "body.query_json", Value: ""})
		return
	}

	if errMsg, status := validateDSL(req.QueryJSON); errMsg != "" {
		writeProblemWithErrors(w, status, "validation failed",
			&huma.ErrorDetail{Message: errMsg, Location: "body.query_json"})
		return
	}

	row, err := srv.store.CreateSavedSearch(r.Context(), orgID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: userID, Valid: true},
		Name:      req.Name,
		QueryJSON: req.QueryJSON,
		NlQuery:   req.NlQuery,
		IsShared:  req.IsShared,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "create saved search", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	ssEntry := savedSearchToEntry(row)
	writeLocation(w, r, row.ID.String())
	writeJSON(w, http.StatusCreated, ssEntry)
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "create",
		EntityType: "saved_search",
		EntityID:   row.ID.String(),
		EntityName: row.Name,
		Success:    true,
		NewState:   ssEntry,
	})
}

// listSavedSearchesHandler handles GET /api/v1/orgs/{org_id}/saved-searches.
func (srv *Server) listSavedSearchesHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	visibility := r.URL.Query().Get("visibility")
	if visibility == "" {
		visibility = "all"
	}
	if visibility != "private" && visibility != "shared" && visibility != "all" {
		writeProblem(w, http.StatusBadRequest, "visibility must be private, shared, or all")
		return
	}

	limit, ok := parseLimitParam(w, r, 200, 200)
	if !ok {
		return
	}

	rows, err := srv.store.ListSavedSearches(r.Context(), orgID, userID, visibility, limit)
	if err != nil {
		slog.ErrorContext(r.Context(), "list saved searches", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	entries := make([]savedSearchEntry, 0, len(rows))
	for i := range rows {
		entries = append(entries, savedSearchToEntry(&rows[i]))
	}
	writeList(w, entries, "")
}

// getSavedSearchHandler handles GET /api/v1/orgs/{org_id}/saved-searches/{id}.
func (srv *Server) getSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	row, err := srv.store.GetSavedSearch(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get saved search", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	// Private access control: non-shared searches are only visible to the creator.
	if !row.IsShared && row.UserID.Valid && row.UserID.UUID != userID {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	writeJSON(w, http.StatusOK, savedSearchToEntry(row))
}

// patchSavedSearchHandler handles PATCH /api/v1/orgs/{org_id}/saved-searches/{id}.
func (srv *Server) patchSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
	role, _ := r.Context().Value(ctxRole).(Role)

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Fetch existing search.
	existing, err := srv.store.GetSavedSearch(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get saved search for patch", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if existing == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	oldEntry := savedSearchToEntry(existing)

	// RBAC: private → only creator; shared → creator OR admin+.
	if !canModifySavedSearch(existing, userID, role) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}

	var req patchSavedSearchRequest
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}

	// Apply updates (read-then-write).
	params := store.UpdateSavedSearchParams{
		Name:      existing.Name,
		QueryJSON: existing.QueryJSON,
		IsShared:  existing.IsShared,
	}
	if existing.NlQuery.Valid {
		s := existing.NlQuery.String
		params.NlQuery = &s
	}

	if req.Name != nil {
		if *req.Name == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "name must not be empty", Location: "body.name", Value: ""})
			return
		}
		if len(*req.Name) > 255 {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "name must not exceed 255 characters", Location: "body.name", Value: *req.Name})
			return
		}
		params.Name = *req.Name
	}
	if req.NlQuery != nil && len(*req.NlQuery) > 1000 {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "nl_query must not exceed 1000 characters", Location: "body.nl_query", Value: *req.NlQuery})
		return
	}
	if req.QueryJSON != nil {
		// Validate the provided DSL.
		if errMsg, status := validateDSL(*req.QueryJSON); errMsg != "" {
			writeProblemWithErrors(w, status, "validation failed",
				&huma.ErrorDetail{Message: errMsg, Location: "body.query_json"})
			return
		}
		params.QueryJSON = *req.QueryJSON
	}
	if req.NlQuery != nil {
		params.NlQuery = req.NlQuery
	}
	if req.IsShared != nil {
		params.IsShared = *req.IsShared
	}

	updated, err := srv.store.UpdateSavedSearch(r.Context(), orgID, id, params)
	if err != nil {
		slog.ErrorContext(r.Context(), "update saved search", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if updated == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	newEntry := savedSearchToEntry(updated)
	writeJSON(w, http.StatusOK, newEntry)
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "saved_search",
		EntityID:   id.String(),
		EntityName: updated.Name,
		Success:    true,
		OldState:   oldEntry,
		NewState:   newEntry,
	})
}

// deleteSavedSearchHandler handles DELETE /api/v1/orgs/{org_id}/saved-searches/{id}.
func (srv *Server) deleteSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
	role, _ := r.Context().Value(ctxRole).(Role)

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Fetch to check RBAC.
	existing, err := srv.store.GetSavedSearch(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get saved search for delete", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if existing == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	if !canModifySavedSearch(existing, userID, role) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := srv.store.SoftDeleteSavedSearch(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "soft delete saved search", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "delete",
		EntityType: "saved_search",
		EntityID:   id.String(),
		EntityName: existing.Name,
		Success:    true,
		OldState:   savedSearchToEntry(existing),
	})
	w.WriteHeader(http.StatusNoContent)
}

// executeSavedSearchHandler handles POST /api/v1/orgs/{org_id}/saved-searches/{id}/execute.
func (srv *Server) executeSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	row, err := srv.store.GetSavedSearch(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get saved search for execute", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	// Private access control.
	if !row.IsShared && row.UserID.Valid && row.UserID.UUID != userID {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	// Parse pagination params from query string.
	cursor := r.URL.Query().Get("cursor")
	limit, ok2 := parseLimitParam(w, r, 25, 100)
	if !ok2 {
		return
	}

	// Parse, validate, compile DSL.
	rule, parseErr := dsl.Parse(row.QueryJSON)
	if parseErr != nil {
		slog.ErrorContext(r.Context(), "saved search: dsl parse", "error", parseErr)
		writeProblem(w, http.StatusUnprocessableEntity, "saved search has invalid query")
		return
	}

	valErrs, _, _ := dsl.Validate(rule, false)
	if hasBlockingErrors(valErrs) {
		slog.ErrorContext(r.Context(), "saved search: dsl validation failed", "errors", valErrs)
		writeProblem(w, http.StatusUnprocessableEntity, "saved search has invalid query")
		return
	}

	compiled, compileErr := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if compileErr != nil {
		slog.ErrorContext(r.Context(), "saved search: dsl compile", "error", compileErr)
		writeProblem(w, http.StatusUnprocessableEntity, "saved search has invalid query")
		return
	}

	results, nextCursor, execErr := srv.store.ExecuteDSLQuery(r.Context(), compiled, cursor, limit)
	if execErr != nil {
		slog.ErrorContext(r.Context(), "saved search: execute dsl query", "error", execErr)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	items := make([]CVEItem, len(results))
	for i, c := range results {
		items[i] = cveToItem(c)
	}

	writeJSON(w, http.StatusOK, savedSearchExecuteResponse{
		Items:      items,
		NextCursor: nextCursor,
	})
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

// canModifySavedSearch checks whether the caller can update or delete a saved search.
// Private searches: only the creator. Shared searches: creator OR admin+.
func canModifySavedSearch(search *store.SavedSearchRow, callerID uuid.UUID, callerRole Role) bool {
	isCreator := search.UserID.Valid && search.UserID.UUID == callerID
	if isCreator {
		return true
	}
	if search.IsShared && callerRole >= RoleAdmin {
		return true
	}
	return false
}
