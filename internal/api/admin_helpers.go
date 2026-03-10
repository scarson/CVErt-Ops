// ABOUTME: Shared helper functions for admin API handlers.
// ABOUTME: Keyset pagination parsing and JSON response writing.
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// parseKeysetParams extracts limit, after_time, and after_id from query parameters.
// Returns (limit, afterTime, afterID, ok). Writes an HTTP error and returns ok=false
// on invalid input.
func parseKeysetParams(w http.ResponseWriter, r *http.Request) (int, *time.Time, *uuid.UUID, bool) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 || parsed > 200 {
			http.Error(w, "invalid limit (1-200)", http.StatusBadRequest)
			return 0, nil, nil, false
		}
		limit = parsed
	}

	var afterTime *time.Time
	var afterID *uuid.UUID

	if cursor := r.URL.Query().Get("after_time"); cursor != "" {
		t, err := time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			http.Error(w, "invalid after_time (RFC3339)", http.StatusBadRequest)
			return 0, nil, nil, false
		}
		afterTime = &t
	}
	if cursor := r.URL.Query().Get("after_id"); cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			http.Error(w, "invalid after_id (UUID)", http.StatusBadRequest)
			return 0, nil, nil, false
		}
		afterID = &id
	}

	// Both cursor fields must be present or absent together.
	if (afterTime == nil) != (afterID == nil) {
		http.Error(w, "after_time and after_id must both be provided or both omitted", http.StatusBadRequest)
		return 0, nil, nil, false
	}

	return limit, afterTime, afterID, true
}
