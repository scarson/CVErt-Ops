// ABOUTME: Shared contract helpers for Chi JSON handlers.
// ABOUTME: Produces RFC 9457 Problem Details using huma's ErrorModel/ErrorDetail types directly.
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: encode failed", "error", err)
	}
}

// writeProblem writes an RFC 9457 Problem Details response using huma's ErrorModel.
// Does NOT set the "type" field — huma omits it via omitempty, so we must too.
func writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	resp := huma.ErrorModel{
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writeProblem: encode failed", "error", err)
	}
}

// writeProblemWithErrors writes an RFC 9457 response with field-level error details.
// Uses huma.ErrorDetail directly — no custom clone types.
func writeProblemWithErrors(w http.ResponseWriter, status int, detail string, errs ...*huma.ErrorDetail) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	resp := huma.ErrorModel{
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Errors: errs,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writeProblemWithErrors: encode failed", "error", err)
	}
}

// writeProblemTyped writes an RFC 9457 response with a custom problem type URI.
// Used for tier-limit failures to distinguish from RBAC 403s.
func writeProblemTyped(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	resp := huma.ErrorModel{
		Type:   problemType,
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("writeProblemTyped: encode failed", "error", err)
	}
}

// Tier-limit problem type URI.
const problemTypeTierLimit = "urn:cvert:error:tier-limit"

// decodeJSON decodes JSON from the request body into dst.
// Returns a *huma.ErrorDetail on malformed JSON, nil on success.
// The caller is responsible for semantic validation after decode.
func decodeJSON(r *http.Request, dst any) *huma.ErrorDetail {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return &huma.ErrorDetail{
			Message:  fmt.Sprintf("invalid JSON: %s", err.Error()),
			Location: "body",
		}
	}
	return nil
}

// listResponse is the standard list envelope for all endpoints.
type listResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// writeList writes a list response in the standard envelope.
func writeList[T any](w http.ResponseWriter, items []T, nextCursor string) {
	// Ensure items is never null in JSON output.
	if items == nil {
		items = []T{}
	}
	writeJSON(w, http.StatusOK, listResponse[T]{
		Items:      items,
		NextCursor: nextCursor,
	})
}

// encodePageCursor encodes cursor fields as opaque base64url JSON (no padding).
// Uses RawURLEncoding to match the existing Huma CVE cursor format in cves.go.
func encodePageCursor(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodePageCursor decodes an opaque base64url JSON cursor into dst.
// Tries RawURLEncoding first (canonical). Falls back to padded URLEncoding
// for cursors issued before the encoding was standardized.
func decodePageCursor(s string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Fallback: try padded URLEncoding for backward compatibility.
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("invalid cursor encoding: %w", err)
		}
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("invalid cursor format: %w", err)
	}
	return nil
}

// parseLimitParam extracts and validates the limit query parameter.
// Returns the default if not specified, or writes a problem response and
// returns 0, false on invalid input.
func parseLimitParam(w http.ResponseWriter, r *http.Request, defaultLimit, maxLimit int) (int, bool) {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return defaultLimit, true
	}
	v, err := strconv.ParseInt(s, 10, 32)
	limit := int(v)
	if err != nil || limit < 1 || limit > maxLimit {
		writeProblem(w, http.StatusBadRequest,
			fmt.Sprintf("invalid limit: must be 1-%d", maxLimit))
		return 0, false
	}
	return limit, true
}

// writeLocation sets the Location header for 201 Created responses.
func writeLocation(w http.ResponseWriter, r *http.Request, pathSuffix string) {
	loc := strings.TrimSuffix(r.URL.Path, "/") + "/" + pathSuffix
	w.Header().Set("Location", loc)
}
