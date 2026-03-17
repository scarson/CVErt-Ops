// ABOUTME: Site admin delivery management API handlers (cross-org).
// ABOUTME: List failed/stale deliveries, retry single, bulk retry.
package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// adminDeliveryCursor is the opaque cursor for admin delivery list pagination.
type adminDeliveryCursor struct {
	T  time.Time `json:"t"`
	ID string    `json:"id"`
}

// adminListDeliveriesHandler handles GET /api/v1/admin/deliveries.
func (srv *Server) adminListDeliveriesHandler(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimitParam(w, r, 50, 200)
	if !ok {
		return
	}

	var afterTime *time.Time
	var afterID *uuid.UUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur adminDeliveryCursor
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

	status := r.URL.Query().Get("status")
	if status != "" {
		valid := map[string]bool{"pending": true, "claimed": true, "delivered": true, "failed": true}
		if !valid[status] {
			writeProblem(w, http.StatusBadRequest, "invalid status filter (pending, claimed, delivered, failed)")
			return
		}
	}

	deliveries, err := srv.store.AdminListDeliveries(r.Context(), status, afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin list deliveries", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(deliveries) > limit {
		deliveries = deliveries[:limit]
		last := deliveries[len(deliveries)-1]
		nextCursor = encodePageCursor(adminDeliveryCursor{T: last.CreatedAt, ID: last.ID.String()})
	}

	writeList(w, deliveries, nextCursor)
}

// adminRetryDeliveryHandler handles POST /api/v1/admin/deliveries/{id}/retry.
func (srv *Server) adminRetryDeliveryHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid delivery id")
		return
	}

	// Check delivery exists.
	delivery, err := srv.store.AdminGetDeliveryByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "delivery not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin retry delivery: lookup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Only retry failed deliveries.
	if delivery.Status != "failed" {
		writeProblem(w, http.StatusConflict, "delivery is not in a retryable state (must be 'failed')")
		return
	}

	n, err := srv.store.AdminRetryDelivery(r.Context(), id)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin retry delivery", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
	limit, ok := parseLimitParam(w, r, 100, 1000)
	if !ok {
		return
	}

	// Also accept limit from JSON body.
	if r.ContentLength > 0 {
		var body struct {
			Limit *int `json:"limit"`
		}
		if errDetail := decodeJSON(r, &body); errDetail != nil {
			writeProblem(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if body.Limit != nil {
			if *body.Limit < 1 || *body.Limit > 1000 {
				writeProblem(w, http.StatusBadRequest, "invalid limit (1-1000)")
				return
			}
			limit = *body.Limit
		}
	}

	n, err := srv.store.AdminBulkRetryFailed(r.Context(), limit)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin bulk retry deliveries", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "retried",
		"rows_affected": n,
	})
}
