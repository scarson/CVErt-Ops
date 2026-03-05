// ABOUTME: HTTP handlers for scheduled digest report CRUD and channel bindings.
// ABOUTME: Mirrors the alert-rules + channels handler patterns.
package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/store"
)

// ── Request / response types ──────────────────────────────────────────────────

type createReportBody struct {
	Name              string   `json:"name"`
	ScheduledTime     string   `json:"scheduled_time"`      // "HH:MM" or "HH:MM:SS"
	Timezone          string   `json:"timezone"`             // IANA timezone
	SeverityThreshold *string  `json:"severity_threshold"`   // nil = all severities
	WatchlistIDs      []string `json:"watchlist_ids"`        // nil = all watchlists
	SendOnEmpty       *bool    `json:"send_on_empty"`
	AISummary         *bool    `json:"ai_summary"`
}

type patchReportBody struct {
	Name              *string   `json:"name"`
	ScheduledTime     *string   `json:"scheduled_time"`
	Timezone          *string   `json:"timezone"`
	SeverityThreshold *string   `json:"severity_threshold"`
	WatchlistIDs      *[]string `json:"watchlist_ids"`
	SendOnEmpty       *bool     `json:"send_on_empty"`
	AISummary         *bool     `json:"ai_summary"`
	Status            *string   `json:"status"`
}

type reportEntry struct {
	ID                string   `json:"id"`
	OrgID             string   `json:"org_id"`
	Name              string   `json:"name"`
	ScheduledTime     string   `json:"scheduled_time"`
	Timezone          string   `json:"timezone"`
	NextRunAt         string   `json:"next_run_at"`
	LastRunAt         *string  `json:"last_run_at,omitempty"`
	SeverityThreshold *string  `json:"severity_threshold,omitempty"`
	WatchlistIDs      []string `json:"watchlist_ids"`
	SendOnEmpty       bool     `json:"send_on_empty"`
	AISummary         bool     `json:"ai_summary"`
	Status            string   `json:"status"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

type reportListResponse struct {
	Items []reportEntry `json:"items"`
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

func reportToEntry(r store.ScheduledReportRow) reportEntry {
	ids := make([]string, len(r.WatchlistIds))
	for i, id := range r.WatchlistIds {
		ids[i] = id.String()
	}
	entry := reportEntry{
		ID:            r.ID.String(),
		OrgID:         r.OrgID.String(),
		Name:          r.Name,
		ScheduledTime: r.ScheduledTime,
		Timezone:      r.Timezone,
		NextRunAt:     r.NextRunAt.Format(time.RFC3339),
		WatchlistIDs:  ids,
		SendOnEmpty:   r.SendOnEmpty,
		AISummary:     r.AiSummary,
		Status:        r.Status,
		CreatedAt:     r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     r.UpdatedAt.Format(time.RFC3339),
	}
	if r.LastRunAt.Valid {
		s := r.LastRunAt.Time.Format(time.RFC3339)
		entry.LastRunAt = &s
	}
	if r.SeverityThreshold.Valid {
		entry.SeverityThreshold = &r.SeverityThreshold.String
	}
	return entry
}

// validSeverityThresholds is the set of allowed severity_threshold values.
var validSeverityThresholds = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// createReportHandler handles POST /api/v1/orgs/{org_id}/reports.
func (srv *Server) createReportHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req createReportBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusUnprocessableEntity)
		return
	}
	if strings.TrimSpace(req.ScheduledTime) == "" {
		http.Error(w, "scheduled_time is required", http.StatusUnprocessableEntity)
		return
	}
	if strings.TrimSpace(req.Timezone) == "" {
		req.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(req.Timezone); err != nil {
		http.Error(w, "invalid timezone", http.StatusUnprocessableEntity)
		return
	}
	if req.SeverityThreshold != nil && !validSeverityThresholds[*req.SeverityThreshold] {
		http.Error(w, "severity_threshold must be critical, high, medium, or low", http.StatusUnprocessableEntity)
		return
	}

	nextRun, err := notify.ComputeNextRunAt(req.ScheduledTime, req.Timezone)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Parse watchlist IDs.
	watchlistIDs := make([]uuid.UUID, len(req.WatchlistIDs))
	for i, s := range req.WatchlistIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			http.Error(w, "invalid watchlist_id: "+s, http.StatusUnprocessableEntity)
			return
		}
		watchlistIDs[i] = id
	}

	params := store.CreateScheduledReportParams{
		Name:          req.Name,
		ScheduledTime: req.ScheduledTime,
		Timezone:      req.Timezone,
		NextRunAt:     nextRun,
		WatchlistIds:  watchlistIDs,
		SendOnEmpty:   req.SendOnEmpty == nil || *req.SendOnEmpty,
		AiSummary:     req.AISummary != nil && *req.AISummary,
		Status:        "active",
	}
	if req.SeverityThreshold != nil {
		params.SeverityThreshold = sql.NullString{String: *req.SeverityThreshold, Valid: true}
	}

	row, err := srv.store.CreateScheduledReport(r.Context(), orgID, params)
	if err != nil {
		slog.ErrorContext(r.Context(), "create scheduled report", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, reportToEntry(*row))
}

// getReportHandler handles GET /api/v1/orgs/{org_id}/reports/{id}.
func (srv *Server) getReportHandler(w http.ResponseWriter, r *http.Request) {
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
	row, err := srv.store.GetScheduledReport(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get scheduled report", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, reportToEntry(*row))
}

// listReportsHandler handles GET /api/v1/orgs/{org_id}/reports.
func (srv *Server) listReportsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rows, err := srv.store.ListScheduledReports(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list scheduled reports", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	items := make([]reportEntry, len(rows))
	for i, row := range rows {
		items[i] = reportToEntry(row)
	}
	writeJSON(w, http.StatusOK, reportListResponse{Items: items})
}

// patchReportHandler handles PATCH /api/v1/orgs/{org_id}/reports/{id}.
func (srv *Server) patchReportHandler(w http.ResponseWriter, r *http.Request) {
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

	var req patchReportBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	current, err := srv.store.GetScheduledReport(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get scheduled report for patch", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	params := store.UpdateScheduledReportParams{
		Name:              current.Name,
		ScheduledTime:     current.ScheduledTime,
		Timezone:          current.Timezone,
		NextRunAt:         current.NextRunAt,
		SeverityThreshold: current.SeverityThreshold,
		WatchlistIds:      current.WatchlistIds,
		SendOnEmpty:       current.SendOnEmpty,
		AiSummary:         current.AiSummary,
		Status:            current.Status,
	}

	recalcNextRun := false

	if req.Name != nil {
		params.Name = *req.Name
	}
	if req.ScheduledTime != nil {
		params.ScheduledTime = *req.ScheduledTime
		recalcNextRun = true
	}
	if req.Timezone != nil {
		if _, err := time.LoadLocation(*req.Timezone); err != nil {
			http.Error(w, "invalid timezone", http.StatusUnprocessableEntity)
			return
		}
		params.Timezone = *req.Timezone
		recalcNextRun = true
	}
	if req.SeverityThreshold != nil {
		if *req.SeverityThreshold == "" {
			// Empty string clears the severity threshold to NULL (no filter).
			params.SeverityThreshold = sql.NullString{}
		} else if !validSeverityThresholds[*req.SeverityThreshold] {
			http.Error(w, "severity_threshold must be critical, high, medium, or low", http.StatusUnprocessableEntity)
			return
		} else {
			params.SeverityThreshold = sql.NullString{String: *req.SeverityThreshold, Valid: true}
		}
	}
	if req.WatchlistIDs != nil {
		ids := make([]uuid.UUID, len(*req.WatchlistIDs))
		for i, s := range *req.WatchlistIDs {
			wID, err := uuid.Parse(s)
			if err != nil {
				http.Error(w, "invalid watchlist_id: "+s, http.StatusUnprocessableEntity)
				return
			}
			ids[i] = wID
		}
		params.WatchlistIds = ids
	}
	if req.SendOnEmpty != nil {
		params.SendOnEmpty = *req.SendOnEmpty
	}
	if req.AISummary != nil {
		params.AiSummary = *req.AISummary
	}
	if req.Status != nil {
		switch *req.Status {
		case "active", "paused":
			// Un-pausing: recalculate next_run_at so the report resumes from now.
			if current.Status == "paused" && *req.Status == "active" {
				recalcNextRun = true
			}
			params.Status = *req.Status
		default:
			http.Error(w, "status must be 'active' or 'paused'", http.StatusUnprocessableEntity)
			return
		}
	}

	if recalcNextRun {
		nextRun, err := notify.ComputeNextRunAt(params.ScheduledTime, params.Timezone)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		params.NextRunAt = nextRun
	}

	updated, err := srv.store.UpdateScheduledReport(r.Context(), orgID, id, params)
	if err != nil {
		slog.ErrorContext(r.Context(), "update scheduled report", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if updated == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, reportToEntry(*updated))
}

// deleteReportHandler handles DELETE /api/v1/orgs/{org_id}/reports/{id}.
func (srv *Server) deleteReportHandler(w http.ResponseWriter, r *http.Request) {
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
	if err := srv.store.SoftDeleteScheduledReport(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "soft delete scheduled report", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bindChannelToReportHandler handles PUT /api/v1/orgs/{org_id}/reports/{id}/channels/{channel_id}.
func (srv *Server) bindChannelToReportHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	reportID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	channelID, err := uuid.Parse(chi.URLParam(r, "channel_id"))
	if err != nil {
		http.Error(w, "invalid channel_id", http.StatusBadRequest)
		return
	}

	// Verify report exists within this org.
	report, err := srv.store.GetScheduledReport(r.Context(), orgID, reportID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get report for bind", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if report == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Verify channel exists within this org.
	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, channelID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for bind", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ch == nil {
		http.Error(w, "channel not found", http.StatusNotFound)
		return
	}

	if err := srv.store.BindChannelToReport(r.Context(), orgID, reportID, channelID); err != nil {
		slog.ErrorContext(r.Context(), "bind channel to report", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unbindChannelFromReportHandler handles DELETE /api/v1/orgs/{org_id}/reports/{id}/channels/{channel_id}.
func (srv *Server) unbindChannelFromReportHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	reportID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	channelID, err := uuid.Parse(chi.URLParam(r, "channel_id"))
	if err != nil {
		http.Error(w, "invalid channel_id", http.StatusBadRequest)
		return
	}
	if err := srv.store.UnbindChannelFromReport(r.Context(), orgID, reportID, channelID); err != nil {
		slog.ErrorContext(r.Context(), "unbind channel from report", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listReportChannelsHandler handles GET /api/v1/orgs/{org_id}/reports/{id}/channels.
func (srv *Server) listReportChannelsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	reportID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	rows, err := srv.store.ListChannelsForReport(r.Context(), orgID, reportID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list channels for report", "error", err)
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
