// ABOUTME: Site admin delivery management API handlers (cross-org).
// ABOUTME: List failed/stale deliveries, retry single, bulk retry.
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// adminListDeliveriesHandler handles GET /api/v1/admin/deliveries.
func (srv *Server) adminListDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	limit, afterTime, afterID, ok := parseKeysetParams(w, r)
	if !ok {
		return
	}

	status := r.URL.Query().Get("status")
	if status != "" {
		valid := map[string]bool{"pending": true, "claimed": true, "delivered": true, "failed": true}
		if !valid[status] {
			http.Error(w, "invalid status filter (pending, claimed, delivered, failed)", http.StatusBadRequest)
			return
		}
	}

	deliveries, err := srv.store.AdminListDeliveries(r.Context(), status, afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin list deliveries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hasMore := len(deliveries) > limit
	if hasMore {
		deliveries = deliveries[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":    deliveries,
		"has_more": hasMore,
	})
}

// adminRetryDeliveryHandler handles POST /api/v1/admin/deliveries/{id}/retry.
func (srv *Server) adminRetryDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid delivery id", http.StatusBadRequest)
		return
	}

	// Check delivery exists.
	delivery, err := srv.store.AdminGetDeliveryByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "delivery not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin retry delivery: lookup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Only retry failed deliveries.
	if delivery.Status != "failed" {
		http.Error(w, "delivery is not in a retryable state (must be 'failed')", http.StatusConflict)
		return
	}

	n, err := srv.store.AdminRetryDelivery(r.Context(), id)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin retry delivery", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "retried",
		"delivery_id":   id.String(),
		"rows_affected": n,
	})
}

// adminBulkRetryDeliveriesHandler handles POST /api/v1/admin/deliveries/retry-failed.
func (srv *Server) adminBulkRetryDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 || parsed > 1000 {
			http.Error(w, "invalid limit (1-1000)", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	// Also accept limit from JSON body.
	if r.ContentLength > 0 {
		var body struct {
			Limit *int `json:"limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if body.Limit != nil {
			if *body.Limit < 1 || *body.Limit > 1000 {
				http.Error(w, "invalid limit (1-1000)", http.StatusBadRequest)
				return
			}
			limit = *body.Limit
		}
	}

	n, err := srv.store.AdminBulkRetryFailed(r.Context(), limit)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin bulk retry deliveries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "retried",
		"rows_affected": n,
	})
}
