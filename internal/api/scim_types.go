// ABOUTME: SCIM 2.0 request/response types and JSON helpers (RFC 7643/7644).
// ABOUTME: Used by all SCIM chi handlers. Separate from huma types.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SCIMError represents an RFC 7644 §3.12 error response.
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// SCIMUser represents a SCIM 2.0 User resource (RFC 7643 §4.1).
type SCIMUser struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      bool     `json:"active"`
	Meta        SCIMMeta `json:"meta"`
}

// SCIMGroup represents a SCIM 2.0 Group resource (RFC 7643 §4.2).
type SCIMGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMGroupMember `json:"members"`
	Meta        SCIMMeta          `json:"meta"`
}

// SCIMGroupMember represents a member reference within a SCIM Group.
type SCIMGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMListResponse represents a SCIM 2.0 ListResponse (RFC 7644 §3.4.2).
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Resources    []any    `json:"Resources"`
}

// SCIMMeta represents resource metadata in SCIM responses.
type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location"`
}

// SCIMPatchOp represents a SCIM 2.0 PATCH request (RFC 7644 §3.5.2).
type SCIMPatchOp struct {
	Schemas    []string             `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}

// SCIMPatchOperation represents a single operation within a SCIM PATCH request.
type SCIMPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value"`
}

// SCIMFilterExpr represents a parsed SCIM filter expression (attr op value).
type SCIMFilterExpr struct {
	Attr  string
	Op    string
	Value string
}

const scimContentType = "application/scim+json"

// writeSCIMError writes an RFC 7644 §3.12 error response.
func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	e := SCIMError{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:  fmt.Sprintf("%d", status),
		Detail:  detail,
	}
	if scimType != "" {
		e.SCIMType = scimType
	}
	writeSCIMJSON(w, status, e)
}

// writeSCIMJSON writes any value as JSON with Content-Type: application/scim+json.
func writeSCIMJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) //nolint:errcheck // best-effort response write
}

// parseSCIMBool parses a JSON boolean or Entra ID string boolean ("True"/"False").
func parseSCIMBool(v json.RawMessage) (bool, error) {
	// Try native JSON boolean first.
	var b bool
	if err := json.Unmarshal(v, &b); err == nil {
		return b, nil
	}

	// Try string boolean (Entra ID sends "True"/"False").
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		switch strings.ToLower(s) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, fmt.Errorf("invalid boolean string: %q", s)
		}
	}

	return false, fmt.Errorf("cannot parse %s as boolean", string(v))
}

// parseSCIMFilter parses a minimal SCIM filter string (RFC 7644 §3.4.2.2).
// Only the "eq" operator is supported. Compound filters are split on " and ".
func parseSCIMFilter(filter string) ([]SCIMFilterExpr, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil, nil
	}

	parts := strings.Split(filter, " and ")
	exprs := make([]SCIMFilterExpr, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Split into exactly 3 tokens: attr, op, value
		tokens := strings.SplitN(part, " ", 3)
		if len(tokens) != 3 {
			return nil, fmt.Errorf("invalid filter expression: %q", part)
		}

		attr := tokens[0]
		op := strings.ToLower(tokens[1])
		value := tokens[2]

		if op != "eq" {
			return nil, fmt.Errorf("unsupported filter operator: %q", op)
		}

		// Strip surrounding quotes from value if present.
		value = strings.Trim(value, "\"")

		exprs = append(exprs, SCIMFilterExpr{
			Attr:  attr,
			Op:    op,
			Value: value,
		})
	}

	return exprs, nil
}
