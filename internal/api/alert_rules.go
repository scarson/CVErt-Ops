// ABOUTME: HTTP handlers for alert rule CRUD and DSL validation.
// ABOUTME: Validates and compiles DSL on every create/update; returns 202 when activating scan is queued.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/store"
)

// ── Request / response types ──────────────────────────────────────────────────

type createAlertRuleBody struct {
	Name                     string          `json:"name"`
	Logic                    string          `json:"logic"`
	Conditions               json.RawMessage `json:"conditions"`
	WatchlistIDs             []string        `json:"watchlist_ids"`
	Enabled                  bool            `json:"enabled"`
	FireOnNonMaterialChanges bool            `json:"fire_on_non_material_changes"`
}

// patchAlertRuleBody uses nil-check semantics for all fields.
// json.RawMessage is nil if the key was absent from the PATCH payload.
// Enabled maps to the status state machine: true → activating, false → disabled.
type patchAlertRuleBody struct {
	Name                     *string         `json:"name"`
	Logic                    *string         `json:"logic"`
	Conditions               json.RawMessage `json:"conditions"` // nil = not provided
	WatchlistIDs             *[]string       `json:"watchlist_ids"`
	Enabled                  *bool           `json:"enabled"`
	FireOnNonMaterialChanges *bool           `json:"fire_on_non_material_changes"`
}

type alertRuleEntry struct {
	ID                       string          `json:"id"`
	Name                     string          `json:"name"`
	Logic                    string          `json:"logic"`
	Conditions               json.RawMessage `json:"conditions"`
	WatchlistIDs             []string        `json:"watchlist_ids"`
	HasEPSSCondition         bool            `json:"has_epss_condition"`
	IsEPSSOnly               bool            `json:"is_epss_only"`
	FireOnNonMaterialChanges bool            `json:"fire_on_non_material_changes"`
	Status                   string          `json:"status"`
	CreatedAt                string          `json:"created_at"`
	UpdatedAt                string          `json:"updated_at"`
}

type alertRuleListResponse struct {
	Items      []alertRuleEntry `json:"items"`
	NextCursor *string          `json:"next_cursor,omitempty"`
}

type validateRuleBody struct {
	Logic        string          `json:"logic"`
	Conditions   json.RawMessage `json:"conditions"`
	WatchlistIDs []string        `json:"watchlist_ids"`
}

type validateRuleResponse struct {
	Valid            bool            `json:"valid"`
	Errors           []dslErrorEntry `json:"errors"`
	Warnings         []dslErrorEntry `json:"warnings"`
	IsEPSSOnly       bool            `json:"is_epss_only"`
	HasEPSSCondition bool            `json:"has_epss_condition"`
}

type dslErrorEntry struct {
	Index    int    `json:"index"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

func alertRuleToEntry(r store.AlertRuleRow) alertRuleEntry {
	ids := make([]string, len(r.WatchlistIds))
	for i, id := range r.WatchlistIds {
		ids[i] = id.String()
	}
	return alertRuleEntry{
		ID:                       r.ID.String(),
		Name:                     r.Name,
		Logic:                    r.Logic,
		Conditions:               r.Conditions,
		WatchlistIDs:             ids,
		HasEPSSCondition:         r.HasEpssCondition,
		IsEPSSOnly:               r.IsEpssOnly,
		FireOnNonMaterialChanges: r.FireOnNonMaterialChanges,
		Status:                   r.Status,
		CreatedAt:                r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:                r.UpdatedAt.Format(time.RFC3339),
	}
}

// parseDSL builds a DSL Rule from logic and raw conditions JSON, validates it,
// and returns the rule and compiled metadata. Returns a 422 error if invalid.
// onInvalid is called with the validation errors before returning.
type dslMeta struct {
	hasEPSS    bool
	isEPSSOnly bool
}

func parseDSL(logic string, conditionsJSON json.RawMessage, watchlistCount int) (dsl.Rule, dslMeta, []dsl.ValidationError, error) {
	// Build the full DSL payload for Parse.
	type rulePayload struct {
		Logic      string          `json:"logic"`
		Conditions json.RawMessage `json:"conditions"`
	}
	raw, err := json.Marshal(rulePayload{Logic: logic, Conditions: conditionsJSON})
	if err != nil {
		return dsl.Rule{}, dslMeta{}, nil, err
	}
	rule, err := dsl.Parse(raw)
	if err != nil {
		// Structural parse error — return as a validation error.
		return dsl.Rule{}, dslMeta{}, []dsl.ValidationError{
			{Index: -1, Field: "", Message: err.Error(), Severity: "error"},
		}, nil
	}
	errs, hasEPSS, isEPSSOnly := dsl.Validate(rule, watchlistCount > 0)
	return rule, dslMeta{hasEPSS: hasEPSS, isEPSSOnly: isEPSSOnly}, errs, nil
}

// hasBlockingErrors returns true if any validation error has severity "error".
func hasBlockingErrors(errs []dsl.ValidationError) bool {
	for _, e := range errs {
		if e.Severity == "error" {
			return true
		}
	}
	return false
}

// parseWatchlistUUIDs converts string UUIDs to uuid.UUID slice.
func parseWatchlistUUIDs(ids []string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, len(ids))
	for i, s := range ids {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		result[i] = id
	}
	return result, nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// createAlertRuleHandler handles POST /api/v1/orgs/{org_id}/alert-rules.
// Returns 201 for draft rules, 202 for rules entering activation scan.
func (srv *Server) createAlertRuleHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req createAlertRuleBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	wlUUIDs, err := parseWatchlistUUIDs(req.WatchlistIDs)
	if err != nil {
		http.Error(w, "invalid watchlist_id", http.StatusBadRequest)
		return
	}

	rule, meta, valErrs, err := parseDSL(req.Logic, req.Conditions, len(wlUUIDs))
	if err != nil {
		http.Error(w, "invalid DSL", http.StatusUnprocessableEntity)
		return
	}
	if hasBlockingErrors(valErrs) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"message": "alert rule DSL validation failed",
			"errors":  valErrsToEntries(valErrs),
		})
		return
	}
	_ = rule // rule fields already captured via parseDSL; meta used below

	if len(wlUUIDs) > 0 {
		owned, err := srv.store.ValidateWatchlistsOwnership(r.Context(), orgID, wlUUIDs)
		if err != nil {
			slog.ErrorContext(r.Context(), "validate watchlists ownership", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !owned {
			http.Error(w, "one or more watchlist_ids not found in this org", http.StatusUnprocessableEntity)
			return
		}
	}

	status := "activating"
	if !req.Enabled {
		status = "draft"
	}

	row, err := srv.store.CreateAlertRule(r.Context(), orgID, store.CreateAlertRuleParams{
		Name:                     req.Name,
		Logic:                    req.Logic,
		Conditions:               req.Conditions,
		WatchlistIds:             wlUUIDs,
		HasEpssCondition:         meta.hasEPSS,
		IsEpssOnly:               meta.isEPSSOnly,
		Status:                   status,
		FireOnNonMaterialChanges: req.FireOnNonMaterialChanges,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "create alert rule", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, alertRuleToEntry(*row))
}

// getAlertRuleHandler handles GET /api/v1/orgs/{org_id}/alert-rules/{id}.
func (srv *Server) getAlertRuleHandler(w http.ResponseWriter, r *http.Request) {
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
	row, err := srv.store.GetAlertRule(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get alert rule", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, alertRuleToEntry(*row))
}

// listAlertRulesHandler handles GET /api/v1/orgs/{org_id}/alert-rules.
// Optional ?status= filter; cursor-based pagination on (created_at DESC, id DESC).
func (srv *Server) listAlertRulesHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	const limit = 20
	var statusFilter *string
	var afterTime *time.Time
	var afterID *uuid.UUID

	if s := r.URL.Query().Get("status"); s != "" {
		statusFilter = &s
	}
	if c := r.URL.Query().Get("after"); c != "" {
		t, id, err := decodeTimeCursor(c)
		if err == nil {
			afterTime = &t
			afterID = &id
		}
	}

	rows, err := srv.store.ListAlertRules(r.Context(), orgID, statusFilter, afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "list alert rules", "error", err)
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

	entries := make([]alertRuleEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, alertRuleToEntry(r))
	}
	writeJSON(w, http.StatusOK, alertRuleListResponse{Items: entries, NextCursor: nextCursor})
}

// updateAlertRuleHandler handles PATCH /api/v1/orgs/{org_id}/alert-rules/{id}.
// Applies a state machine based on current status and the type of change:
//   - activating + DSL change → 409 Conflict
//   - activating + metadata only → 200, update fields, keep activating
//   - active + DSL change → 200, re-activate (status=activating, evict cache)
//   - active + metadata only → 200, keep active
//   - error|draft|disabled + enabled=true → 200, re-activate (status=activating)
//   - enabled=false → disabled
func (srv *Server) updateAlertRuleHandler(w http.ResponseWriter, r *http.Request) {
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

	current, err := srv.store.GetAlertRule(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get alert rule for patch", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var req patchAlertRuleBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Determine if DSL/watchlist fields are being changed.
	hasDSLChange := req.Logic != nil || len(req.Conditions) > 0 || req.WatchlistIDs != nil

	// State machine: reject DSL changes while activating.
	if current.Status == "activating" && hasDSLChange {
		http.Error(w, "rule is currently activating; wait for scan to complete before changing DSL", http.StatusConflict)
		return
	}

	// Build effective update values from current, overriding with patch fields.
	name := current.Name
	logic := current.Logic
	conditions := current.Conditions
	wlIDs := current.WatchlistIds
	fireOnNonMaterial := current.FireOnNonMaterialChanges
	hasEPSS := current.HasEpssCondition
	isEPSSOnly := current.IsEpssOnly

	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			http.Error(w, "name cannot be empty", http.StatusBadRequest)
			return
		}
		name = *req.Name
	}
	if req.Logic != nil {
		logic = *req.Logic
	}
	if len(req.Conditions) > 0 {
		conditions = req.Conditions
	}
	if req.WatchlistIDs != nil {
		uuids, err := parseWatchlistUUIDs(*req.WatchlistIDs)
		if err != nil {
			http.Error(w, "invalid watchlist_id", http.StatusBadRequest)
			return
		}
		wlIDs = uuids
	}
	if req.FireOnNonMaterialChanges != nil {
		fireOnNonMaterial = *req.FireOnNonMaterialChanges
	}

	// Re-validate DSL only if DSL fields changed.
	if hasDSLChange {
		_, meta, valErrs, err := parseDSL(logic, conditions, len(wlIDs))
		if err != nil {
			http.Error(w, "invalid DSL", http.StatusUnprocessableEntity)
			return
		}
		if hasBlockingErrors(valErrs) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"message": "alert rule DSL validation failed",
				"errors":  valErrsToEntries(valErrs),
			})
			return
		}
		hasEPSS = meta.hasEPSS
		isEPSSOnly = meta.isEPSSOnly
	}

	// Validate watchlist ownership if watchlist IDs changed.
	if req.WatchlistIDs != nil && len(wlIDs) > 0 {
		owned, err := srv.store.ValidateWatchlistsOwnership(r.Context(), orgID, wlIDs)
		if err != nil {
			slog.ErrorContext(r.Context(), "validate watchlists ownership", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !owned {
			http.Error(w, "one or more watchlist_ids not found in this org", http.StatusUnprocessableEntity)
			return
		}
	}

	// Determine new status via state machine.
	newStatus := current.Status
	needsCacheEvict := false

	switch current.Status {
	case "activating":
		// No DSL change allowed (already rejected above). Metadata-only updates keep activating.
		if req.Enabled != nil && !*req.Enabled {
			newStatus = "disabled"
		}
	case "active":
		if hasDSLChange {
			newStatus = "activating"
			needsCacheEvict = true
		} else if req.Enabled != nil && !*req.Enabled {
			newStatus = "disabled"
			needsCacheEvict = true
		}
	case "error", "draft", "disabled":
		if req.Enabled != nil && *req.Enabled {
			newStatus = "activating"
		}
	}

	row, err := srv.store.UpdateAlertRule(r.Context(), orgID, id, store.UpdateAlertRuleParams{
		Name:                     name,
		Logic:                    logic,
		Conditions:               conditions,
		WatchlistIds:             wlIDs,
		HasEpssCondition:         hasEPSS,
		IsEpssOnly:               isEPSSOnly,
		FireOnNonMaterialChanges: fireOnNonMaterial,
		Status:                   newStatus,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "update alert rule", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if needsCacheEvict && srv.alertCache != nil {
		srv.alertCache.Evict(id)
	}

	writeJSON(w, http.StatusOK, alertRuleToEntry(*row))
}

// deleteAlertRuleHandler handles DELETE /api/v1/orgs/{org_id}/alert-rules/{id}.
func (srv *Server) deleteAlertRuleHandler(w http.ResponseWriter, r *http.Request) {
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
	if err := srv.store.SoftDeleteAlertRule(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "delete alert rule", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if srv.alertCache != nil {
		srv.alertCache.Evict(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateAlertRuleHandler handles POST /api/v1/orgs/{org_id}/alert-rules/validate.
// Returns validation result without saving. Requires viewer+.
func (srv *Server) validateAlertRuleHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req validateRuleBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	_, meta, valErrs, err := parseDSL(req.Logic, req.Conditions, len(req.WatchlistIDs))
	if err != nil {
		writeJSON(w, http.StatusOK, validateRuleResponse{
			Valid:    false,
			Errors:   []dslErrorEntry{{Index: -1, Field: "", Message: "invalid request", Severity: "error"}},
			Warnings: []dslErrorEntry{},
		})
		return
	}

	errs := make([]dslErrorEntry, 0)
	warnings := make([]dslErrorEntry, 0)
	for _, e := range valErrs {
		entry := dslErrorEntry{Index: e.Index, Field: e.Field, Message: e.Message, Severity: e.Severity}
		if e.Severity == "warning" {
			warnings = append(warnings, entry)
		} else {
			errs = append(errs, entry)
		}
	}

	resp := validateRuleResponse{
		Valid:            !hasBlockingErrors(valErrs),
		Errors:           errs,
		Warnings:         warnings,
		IsEPSSOnly:       meta.isEPSSOnly,
		HasEPSSCondition: meta.hasEPSS,
	}
	writeJSON(w, http.StatusOK, resp)
}

// dryRunResponse holds the result of a dry-run evaluation.
type dryRunResponse struct {
	MatchCount          int      `json:"match_count"`
	CandidatesEvaluated int      `json:"candidates_evaluated"`
	Partial             bool     `json:"partial"`
	SampleCVEs          []string `json:"sample_cves"`
}

// dryRunHandler handles POST /api/v1/orgs/{org_id}/alert-rules/{id}/dry-run.
// Evaluates the saved rule against the current CVE corpus without creating
// alert_events rows. Returns match count, sample CVEs, and evaluation metadata.
// Requires viewer+.
func (srv *Server) dryRunHandler(w http.ResponseWriter, r *http.Request) {
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
	if srv.alertEvaluator == nil {
		http.Error(w, "dry-run not available", http.StatusServiceUnavailable)
		return
	}
	result, err := srv.alertEvaluator.DryRun(r.Context(), id, orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "dry-run evaluation", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if result == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sample := result.SampleCVEs
	if sample == nil {
		sample = []string{}
	}
	writeJSON(w, http.StatusOK, dryRunResponse{
		MatchCount:          result.MatchCount,
		CandidatesEvaluated: result.CandidatesEvaluated,
		Partial:             result.Partial,
		SampleCVEs:          sample,
	})
}

// listRuleChannelsHandler handles GET /api/v1/orgs/{org_id}/alert-rules/{id}/channels.
// Returns all non-deleted notification channels bound to the rule.
func (srv *Server) listRuleChannelsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	rows, err := srv.store.ListChannelsForRule(r.Context(), ruleID, orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list channels for rule", "error", err)
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

// bindRuleChannelHandler handles PUT /api/v1/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}.
// Idempotent: binding an already-bound channel is a no-op and returns 204.
func (srv *Server) bindRuleChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	channelID, err := uuid.Parse(chi.URLParam(r, "channel_id"))
	if err != nil {
		http.Error(w, "invalid channel_id", http.StatusBadRequest)
		return
	}

	// Validate the channel exists in this org (cross-org bind prevention).
	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, channelID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel for bind", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ch == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := srv.store.BindChannelToRule(r.Context(), ruleID, channelID, orgID); err != nil {
		slog.ErrorContext(r.Context(), "bind channel to rule", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unbindRuleChannelHandler handles DELETE /api/v1/orgs/{org_id}/alert-rules/{id}/channels/{channel_id}.
// Returns 404 if the binding does not exist; 204 on success.
func (srv *Server) unbindRuleChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	channelID, err := uuid.Parse(chi.URLParam(r, "channel_id"))
	if err != nil {
		http.Error(w, "invalid channel_id", http.StatusBadRequest)
		return
	}

	// Check binding exists before attempting delete (DELETE is a no-op on missing rows).
	exists, err := srv.store.ChannelRuleBindingExists(r.Context(), ruleID, channelID, orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "check channel rule binding", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := srv.store.UnbindChannelFromRule(r.Context(), ruleID, channelID, orgID); err != nil {
		slog.ErrorContext(r.Context(), "unbind channel from rule", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// valErrsToEntries converts DSL ValidationErrors to API-level entries.
func valErrsToEntries(errs []dsl.ValidationError) []dslErrorEntry {
	if len(errs) == 0 {
		return []dslErrorEntry{}
	}
	out := make([]dslErrorEntry, len(errs))
	for i, e := range errs {
		out[i] = dslErrorEntry{Index: e.Index, Field: e.Field, Message: e.Message, Severity: e.Severity}
	}
	return out
}
