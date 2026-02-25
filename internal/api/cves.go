package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// registerCVERoutes wires up the three Phase 1 CVE endpoints on the huma API.
// All endpoints are public read-only — auth middleware is added in Phase 2.
//
//   GET /cves           — paginated search with full filter set
//   GET /cves/{cve_id}  — single CVE detail with child tables
//   GET /cves/{cve_id}/sources — per-source normalized payloads
func registerCVERoutes(api huma.API, s *store.Store) {
	huma.Register(api, huma.Operation{
		OperationID: "list-cves",
		Method:      http.MethodGet,
		Path:        "/cves",
		Summary:     "Search CVEs",
		Description: "Paginated CVE search with full-text search, facet filters, and keyset pagination.",
		Tags:        []string{"CVEs"},
	}, listCVEsHandler(s))

	huma.Register(api, huma.Operation{
		OperationID: "get-cve",
		Method:      http.MethodGet,
		Path:        "/cves/{cve_id}",
		Summary:     "Get CVE detail",
		Description: "Returns the canonical CVE row with affected packages, CPEs, and references.",
		Tags:        []string{"CVEs"},
	}, getCVEHandler(s))

	huma.Register(api, huma.Operation{
		OperationID: "get-cve-sources",
		Method:      http.MethodGet,
		Path:        "/cves/{cve_id}/sources",
		Summary:     "Get CVE source payloads",
		Description: "Returns per-source normalized payloads for a CVE, for cross-source comparison.",
		Tags:        []string{"CVEs"},
	}, getCVESourcesHandler(s))
}

// ── Response types ────────────────────────────────────────────────────────────

// CVEItem is the list-view representation of a CVE (no child tables).
type CVEItem struct {
	CVEID              string    `json:"cve_id"`
	Status             *string   `json:"status,omitempty"`
	DatePublished      *string   `json:"date_published,omitempty"` // RFC3339
	DateModified       string    `json:"date_modified"`            // RFC3339
	DateFirstSeen      string    `json:"date_first_seen"`          // RFC3339
	DescriptionPrimary *string   `json:"description_primary,omitempty"`
	Severity           *string   `json:"severity,omitempty"`
	CVSSv3Score        *float64  `json:"cvss_v3_score,omitempty"`
	CVSSv4Score        *float64  `json:"cvss_v4_score,omitempty"`
	CVSSScoreDiverges  bool      `json:"cvss_score_diverges"`
	CWEIDs             []string  `json:"cwe_ids"`
	ExploitAvailable   bool      `json:"exploit_available"`
	InCISAKEV          bool      `json:"in_cisa_kev"`
	EPSSScore          *float64  `json:"epss_score,omitempty"`
}

// CVEDetail extends CVEItem with child-table data.
type CVEDetail struct {
	CVEItem
	CVSSv3Vector     *string                   `json:"cvss_v3_vector,omitempty"`
	CVSSv4Vector     *string                   `json:"cvss_v4_vector,omitempty"`
	AffectedPackages []AffectedPackageResponse `json:"affected_packages"`
	AffectedCPEs     []AffectedCPEResponse     `json:"affected_cpes"`
	References       []ReferenceResponse        `json:"references"`
}

// AffectedPackageResponse is the API representation of a cve_affected_packages row.
type AffectedPackageResponse struct {
	Ecosystem   string  `json:"ecosystem"`
	PackageName string  `json:"package_name"`
	Namespace   *string `json:"namespace,omitempty"`
	RangeType   *string `json:"range_type,omitempty"`
	Introduced  *string `json:"introduced,omitempty"`
	Fixed       *string `json:"fixed,omitempty"`
}

// AffectedCPEResponse is the API representation of a cve_affected_cpes row.
type AffectedCPEResponse struct {
	CPE           string `json:"cpe"`
	CPENormalized string `json:"cpe_normalized"`
}

// ReferenceResponse is the API representation of a cve_references row.
type ReferenceResponse struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// CVESourceResponse is the API representation of a cve_sources row.
type CVESourceResponse struct {
	SourceName         string          `json:"source_name"`
	SourceID           *string         `json:"source_id,omitempty"`
	NormalizedJSON     json.RawMessage `json:"normalized_json"`
	SourceDateModified *string         `json:"source_date_modified,omitempty"` // RFC3339
	SourceURL          *string         `json:"source_url,omitempty"`
	IngestedAt         string          `json:"ingested_at"` // RFC3339
}

// cveListCursor is the internal JSON structure encoded in the opaque cursor string.
type cveListCursor struct {
	// SortDate is the date_modified_canonical of the last row, encoded as RFC3339.
	SortDate string `json:"d"`
	// CVEID is the cve_id of the last row.
	CVEID string `json:"id"`
}

// encodeCursor base64-encodes the cursor JSON (opaque to API clients).
func encodeCursor(last generated.Cfe) string {
	c := cveListCursor{
		SortDate: last.DateModifiedCanonical.UTC().Format(time.RFC3339Nano),
		CVEID:    last.CveID,
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor base64-decodes the opaque cursor, returning a parsed cursor or nil.
func decodeCursor(s string) (*cveListCursor, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor (base64): %w", err)
	}
	var c cveListCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("invalid cursor (json): %w", err)
	}
	if c.CVEID == "" {
		return nil, fmt.Errorf("invalid cursor: missing cve_id")
	}
	return &c, nil
}

// cfeToItem converts a generated Cfe row to a CVEItem for list responses.
func cfeToItem(c generated.Cfe) CVEItem {
	item := CVEItem{
		CVEID:             c.CveID,
		DateModified:      c.DateModifiedCanonical.UTC().Format(time.RFC3339),
		DateFirstSeen:     c.DateFirstSeen.UTC().Format(time.RFC3339),
		CVSSScoreDiverges: c.CvssScoreDiverges,
		CWEIDs:            c.CweIds,
		ExploitAvailable:  c.ExploitAvailable,
		InCISAKEV:         c.InCisaKev,
	}
	if c.Status.Valid {
		item.Status = &c.Status.String
	}
	if c.DatePublished.Valid {
		s := c.DatePublished.Time.UTC().Format(time.RFC3339)
		item.DatePublished = &s
	}
	if c.DescriptionPrimary.Valid {
		item.DescriptionPrimary = &c.DescriptionPrimary.String
	}
	if c.Severity.Valid {
		item.Severity = &c.Severity.String
	}
	if c.CvssV3Score.Valid {
		item.CVSSv3Score = &c.CvssV3Score.Float64
	}
	if c.CvssV4Score.Valid {
		item.CVSSv4Score = &c.CvssV4Score.Float64
	}
	if c.EpssScore.Valid {
		item.EPSSScore = &c.EpssScore.Float64
	}
	if item.CWEIDs == nil {
		item.CWEIDs = []string{} // never return null for arrays in JSON
	}
	return item
}

// ── GET /cves ─────────────────────────────────────────────────────────────────

// ListCVEsInput defines query parameters for the paginated CVE list.
type ListCVEsInput struct {
	Q            string   `query:"q" doc:"Full-text search query (supports quoted phrases and negation)"`
	Severity     []string `query:"severity" doc:"Filter by severity: critical, high, medium, low, unknown"`
	CVSSMin      *float64 `query:"cvss_min" minimum:"0" maximum:"10" doc:"Minimum CVSS score (prefers v4, falls back to v3)"`
	CVSSMax      *float64 `query:"cvss_max" minimum:"0" maximum:"10" doc:"Maximum CVSS score"`
	DateFrom     *string  `query:"date_from" doc:"Filter CVEs modified on or after this date (ISO 8601)"`
	DateTo       *string  `query:"date_to" doc:"Filter CVEs modified on or before this date (ISO 8601)"`
	CWEID        *string  `query:"cwe_id" doc:"Filter by CWE ID (e.g. CWE-79)"`
	Ecosystem    *string  `query:"ecosystem" doc:"Filter by affected package ecosystem"`
	PackageName  *string  `query:"package_name" doc:"Filter by affected package name (requires ecosystem)"`
	InCISAKEV    *bool    `query:"in_cisa_kev" doc:"Only return CVEs in the CISA Known Exploited Vulnerabilities catalog"`
	ExploitAvail *bool    `query:"exploit_available" doc:"Filter by exploit availability"`
	EPSSMin      *float64 `query:"epss_min" minimum:"0" maximum:"1" doc:"Minimum EPSS score"`
	EPSSMax      *float64 `query:"epss_max" minimum:"0" maximum:"1" doc:"Maximum EPSS score"`
	Cursor       string   `query:"cursor" doc:"Opaque pagination cursor returned in the previous response"`
	Limit        int      `query:"limit" minimum:"1" maximum:"100" default:"25" doc:"Page size (max 100)"`
}

// ListCVEsOutput is the response body for GET /cves.
type ListCVEsOutput struct {
	Body *ListCVEsBody
}

// ListCVEsBody is the JSON body of the list response.
type ListCVEsBody struct {
	Items      []CVEItem `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

func listCVEsHandler(s *store.Store) func(context.Context, *ListCVEsInput) (*ListCVEsOutput, error) {
	return func(ctx context.Context, input *ListCVEsInput) (*ListCVEsOutput, error) {
		// Parse optional cursor.
		cur, err := decodeCursor(input.Cursor)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid cursor", err)
		}

		// Build store search params.
		p := store.SearchParams{
			Q:            input.Q,
			Severity:     input.Severity,
			CVSSMin:      input.CVSSMin,
			CVSSMax:      input.CVSSMax,
			CWEID:        input.CWEID,
			Ecosystem:    input.Ecosystem,
			PackageName:  input.PackageName,
			InCISAKEV:    input.InCISAKEV,
			ExploitAvail: input.ExploitAvail,
			EPSSMin:      input.EPSSMin,
			EPSSMax:      input.EPSSMax,
			Limit:        input.Limit + 1, // fetch one extra to detect next page
		}

		// Parse date range params.
		if input.DateFrom != nil {
			t := parseQueryDate(*input.DateFrom)
			if t == nil {
				return nil, huma.Error400BadRequest("invalid date_from; use ISO 8601 format", nil)
			}
			p.DateFrom = t
		}
		if input.DateTo != nil {
			t := parseQueryDate(*input.DateTo)
			if t == nil {
				return nil, huma.Error400BadRequest("invalid date_to; use ISO 8601 format", nil)
			}
			p.DateTo = t
		}

		// Apply cursor position.
		if cur != nil {
			cursorDate, err := time.Parse(time.RFC3339Nano, cur.SortDate)
			if err != nil {
				cursorDate, err = time.Parse(time.RFC3339, cur.SortDate)
				if err != nil {
					return nil, huma.Error400BadRequest("invalid cursor (bad date)", nil)
				}
			}
			p.CursorDate = &cursorDate
			p.CursorCVEID = cur.CVEID
		}

		rows, err := s.SearchCVEs(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("list cves: %w", err)
		}

		// Detect next page by checking for the extra row.
		hasMore := len(rows) > input.Limit
		if hasMore {
			rows = rows[:input.Limit]
		}

		items := make([]CVEItem, len(rows))
		for i, r := range rows {
			items[i] = cfeToItem(r)
		}

		var nextCursor string
		if hasMore && len(rows) > 0 {
			nextCursor = encodeCursor(rows[len(rows)-1])
		}

		return &ListCVEsOutput{Body: &ListCVEsBody{
			Items:      items,
			NextCursor: nextCursor,
		}}, nil
	}
}

// ── GET /cves/{cve_id} ────────────────────────────────────────────────────────

// GetCVEInput defines path parameters for the single-CVE endpoint.
type GetCVEInput struct {
	CVEID string `path:"cve_id" doc:"CVE identifier (e.g. CVE-2024-12345)"`
}

// GetCVEOutput is the response for GET /cves/{cve_id}.
type GetCVEOutput struct {
	Body *CVEDetail
}

func getCVEHandler(s *store.Store) func(context.Context, *GetCVEInput) (*GetCVEOutput, error) {
	return func(ctx context.Context, input *GetCVEInput) (*GetCVEOutput, error) {
		cve, refs, pkgs, cpes, err := s.GetCVEDetail(ctx, input.CVEID)
		if err != nil {
			return nil, fmt.Errorf("get cve detail: %w", err)
		}
		if cve == nil {
			return nil, huma.Error404NotFound("CVE not found", nil)
		}

		detail := &CVEDetail{
			CVEItem:          cfeToItem(*cve),
			AffectedPackages: make([]AffectedPackageResponse, 0, len(pkgs)),
			AffectedCPEs:     make([]AffectedCPEResponse, 0, len(cpes)),
			References:       make([]ReferenceResponse, 0, len(refs)),
		}

		if cve.CvssV3Vector.Valid {
			detail.CVSSv3Vector = &cve.CvssV3Vector.String
		}
		if cve.CvssV4Vector.Valid {
			detail.CVSSv4Vector = &cve.CvssV4Vector.String
		}

		for _, p := range pkgs {
			r := AffectedPackageResponse{
				Ecosystem:   p.Ecosystem,
				PackageName: p.PackageName,
			}
			if p.Namespace.Valid {
				r.Namespace = &p.Namespace.String
			}
			if p.RangeType.Valid {
				r.RangeType = &p.RangeType.String
			}
			if p.Introduced.Valid {
				r.Introduced = &p.Introduced.String
			}
			if p.Fixed.Valid {
				r.Fixed = &p.Fixed.String
			}
			detail.AffectedPackages = append(detail.AffectedPackages, r)
		}

		for _, c := range cpes {
			detail.AffectedCPEs = append(detail.AffectedCPEs, AffectedCPEResponse{
				CPE:           c.Cpe,
				CPENormalized: c.CpeNormalized,
			})
		}

		for _, ref := range refs {
			tags := ref.Tags
			if tags == nil {
				tags = []string{}
			}
			detail.References = append(detail.References, ReferenceResponse{
				URL:  ref.Url,
				Tags: tags,
			})
		}

		return &GetCVEOutput{Body: detail}, nil
	}
}

// ── GET /cves/{cve_id}/sources ────────────────────────────────────────────────

// GetCVESourcesInput defines path parameters for the sources endpoint.
type GetCVESourcesInput struct {
	CVEID string `path:"cve_id" doc:"CVE identifier"`
}

// GetCVESourcesOutput is the response for GET /cves/{cve_id}/sources.
type GetCVESourcesOutput struct {
	Body *GetCVESourcesBody
}

// GetCVESourcesBody wraps the list of source payloads.
type GetCVESourcesBody struct {
	Sources []CVESourceResponse `json:"sources"`
}

func getCVESourcesHandler(s *store.Store) func(context.Context, *GetCVESourcesInput) (*GetCVESourcesOutput, error) {
	return func(ctx context.Context, input *GetCVESourcesInput) (*GetCVESourcesOutput, error) {
		// Verify the CVE exists first so we can return 404 vs empty list.
		cve, err := s.GetCVE(ctx, input.CVEID)
		if err != nil {
			return nil, fmt.Errorf("get cve: %w", err)
		}
		if cve == nil {
			return nil, huma.Error404NotFound("CVE not found", nil)
		}

		srcs, err := s.GetCVESources(ctx, input.CVEID)
		if err != nil {
			return nil, fmt.Errorf("get sources: %w", err)
		}

		out := make([]CVESourceResponse, 0, len(srcs))
		for _, src := range srcs {
			r := CVESourceResponse{
				SourceName:     src.SourceName,
				NormalizedJSON: src.NormalizedJson,
				IngestedAt:     src.IngestedAt.UTC().Format(time.RFC3339),
			}
			if src.SourceID.Valid {
				r.SourceID = &src.SourceID.String
			}
			if src.SourceDateModified.Valid {
				s := src.SourceDateModified.Time.UTC().Format(time.RFC3339)
				r.SourceDateModified = &s
			}
			if src.SourceUrl.Valid {
				r.SourceURL = &src.SourceUrl.String
			}
			out = append(out, r)
		}

		return &GetCVESourcesOutput{Body: &GetCVESourcesBody{Sources: out}}, nil
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseQueryDate parses a user-supplied date string using common ISO 8601 layouts.
// Returns nil on failure so the caller can return a 400 error.
func parseQueryDate(s string) *time.Time {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}
