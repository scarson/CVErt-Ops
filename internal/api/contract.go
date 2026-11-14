// ABOUTME: Shared contract helpers for Chi JSON handlers.
// ABOUTME: Produces RFC 9457 Problem Details using huma's ErrorModel/ErrorDetail types directly.
package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/validation"
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

// Sign-in problem type URIs. They let a client tell a mistyped code or
// password (stay on the step) from a missing or expired session (start over),
// which share the 401 status.
const (
	problemTypePendingSessionInvalid = "urn:cvert:error:pending-session-invalid"
	problemTypeInvalidCode           = "urn:cvert:error:invalid-code"
	problemTypeInvalidPassword       = "urn:cvert:error:invalid-password" //nolint:gosec // G101: public problem type URI, not a credential
	problemTypeEnrollmentExpired     = "urn:cvert:error:enrollment-expired"
)

// typedProblem returns an error that huma handlers can return to produce an
// RFC 9457 response with a custom problem type URI.
func typedProblem(status int, problemType, detail string) error {
	return &huma.ErrorModel{
		Type:   problemType,
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	}
}

// decodeJSON decodes the request body into dst and reports whether it succeeded.
// On failure it has already written the problem response: 422 for an object
// member that dst does not define, which the published request schemas forbid
// with additionalProperties false, and 400 for anything else that does not
// decode into dst. Member names match case-sensitively, as in the schemas.
// The caller is responsible for semantic validation after decode.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		err = jsonv2.Unmarshal(withoutSchemaLink(body), dst, jsonv2.RejectUnknownMembers(true))
	}
	if err == nil {
		return true
	}
	if semErr, ok := errors.AsType[*jsonv2.SemanticError](err); ok && errors.Is(semErr.Err, jsonv2.ErrUnknownName) {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{
			Message:  validation.MsgUnexpectedProperty,
			Location: bodyLocation(semErr.JSONPointer),
		})
		return false
	}
	writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", &huma.ErrorDetail{
		Message:  fmt.Sprintf("invalid JSON: %s", err.Error()),
		Location: "body",
	})
	return false
}

// withoutSchemaLink returns body without its top-level "$schema" member. huma
// declares that member, read-only, on every published request schema so that
// editors can find the schema; it carries no request data. A body that is not
// a JSON object is returned unchanged for the decode to report.
func withoutSchemaLink(body []byte) []byte {
	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(body, &members); err != nil {
		return body
	}
	if _, ok := members["$schema"]; !ok {
		return body
	}
	delete(members, "$schema")
	stripped, err := jsonv2.Marshal(members)
	if err != nil {
		return body
	}
	return stripped
}

// bodyLocation renders the JSON Pointer to an unknown member in the location
// format huma uses for validation errors, such as body.items[1].name. The last
// token is the member name; a numeric token before it is an array index,
// because no request struct has numeric member names.
func bodyLocation(ptr jsontext.Pointer) string {
	var b strings.Builder
	b.WriteString("body")
	last := ptr.LastToken()
	for tok := range ptr.Parent().Tokens() {
		if isArrayIndex(tok) {
			b.WriteString("[" + tok + "]")
		} else {
			b.WriteString("." + tok)
		}
	}
	b.WriteString("." + last)
	return b.String()
}

// isArrayIndex reports whether a JSON Pointer token is a base-10 array index.
func isArrayIndex(tok string) bool {
	if tok == "" {
		return false
	}
	for _, c := range tok {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// clearableField is a PATCH request field that can be left unchanged, cleared
// or set. Sent is false when the key is omitted; Value is nil when the key is
// JSON null. A pointer field cannot make this distinction, because
// encoding/json decodes both an omitted key and null to a nil pointer.
type clearableField[T any] struct {
	Sent  bool
	Value *T
}

// UnmarshalJSON records that the key was sent and decodes its value. encoding/json
// calls it only for keys present in the input, including those set to null.
func (f *clearableField[T]) UnmarshalJSON(data []byte) error {
	f.Sent = true
	if bytes.Equal(data, []byte("null")) {
		f.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	f.Value = &v
	return nil
}

// Schema documents the field as its value type or null.
func (clearableField[T]) Schema(r huma.Registry) *huma.Schema {
	s := r.Schema(reflect.TypeFor[T](), true, "")
	s.Nullable = true
	return s
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
