// ABOUTME: Inbound webhook endpoint for custom feed data ingestion.
// ABOUTME: Accepts CVE patches via POST, validates, and routes each to merge.Ingest.
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/ingest"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/tier"
)

// maxIngestPatches is the per-request patch limit for the inbound webhook.
const maxIngestPatches = 100

// ingestCVEIDPattern validates CVE IDs in the canonical format CVE-YYYY-NNNNN+.
// Minimum 4 digits in the sequence number per the design doc.
var ingestCVEIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ingestRequest is the JSON body for POST /api/v1/orgs/{org_id}/ingest.
type ingestRequest struct {
	SourceName string        `json:"source_name"`
	Patches    []ingestPatch `json:"patches"`
}

// ingestPatch represents a single CVE patch in the ingest request.
type ingestPatch struct {
	CVEID       string          `json:"cve_id"`
	Description *string         `json:"description,omitempty"`
	Severity    *string         `json:"severity,omitempty"`
	CVSSv3Score *float64        `json:"cvss_v3_score,omitempty"`
	CVSSv3Vec   *string         `json:"cvss_v3_vector,omitempty"`
	CVSSv4Score *float64        `json:"cvss_v4_score,omitempty"`
	CVSSv4Vec   *string         `json:"cvss_v4_vector,omitempty"`
	DatePub     *string         `json:"date_published,omitempty"`
	DateMod     *string         `json:"date_modified,omitempty"`
	References  []ingestRef     `json:"references,omitempty"`
	RawPayload  json.RawMessage `json:"raw_payload,omitempty"`
}

// ingestRef is a reference URL in the ingest request.
type ingestRef struct {
	URL    string   `json:"url"`
	Tags   []string `json:"tags,omitempty"`
}

// ingestResponse is the JSON response for POST /api/v1/orgs/{org_id}/ingest.
type ingestResponse struct {
	Accepted int           `json:"accepted"`
	Rejected int           `json:"rejected"`
	Errors   []ingestError `json:"errors"`
}

// ingestError describes a single patch failure.
type ingestError struct {
	Index int    `json:"index"`
	CVEID string `json:"cve_id"`
	Error string `json:"error"`
}

func (srv *Server) ingestHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate source_name.
	if strings.TrimSpace(req.SourceName) == "" {
		http.Error(w, "source_name is required", http.StatusBadRequest)
		return
	}
	if ingest.IsReservedSourceName(req.SourceName) {
		http.Error(w, fmt.Sprintf("source_name %q is reserved", req.SourceName), http.StatusBadRequest)
		return
	}

	// Validate patch count.
	if len(req.Patches) == 0 {
		http.Error(w, "patches array is required and must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.Patches) > maxIngestPatches {
		http.Error(w, fmt.Sprintf("too many patches: %d exceeds limit of %d", len(req.Patches), maxIngestPatches), http.StatusBadRequest)
		return
	}

	// Rate limit accounting: consume N-1 additional tokens (middleware already consumed 1).
	if n := len(req.Patches); n > 1 {
		ratePerMin := 60
		if resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver); ok {
			ratePerMin = resolver.ResolveInt(tier.LimitAPIRate)
		}
		ratePerSec := rate.Limit(float64(ratePerMin) / 60.0)
		burst := ratePerMin / 6
		if burst < 1 {
			burst = 1
		}
		if !srv.orgRL.AllowN(orgID, ratePerSec, burst, n-1) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// Process each patch independently.
	resp := ingestResponse{Errors: make([]ingestError, 0)}
	for i, p := range req.Patches {
		// Validate CVE ID format.
		if !ingestCVEIDPattern.MatchString(p.CVEID) {
			resp.Rejected++
			resp.Errors = append(resp.Errors, ingestError{
				Index: i,
				CVEID: p.CVEID,
				Error: "cve_id must match CVE-YYYY-NNNNN format",
			})
			continue
		}

		// Convert to CanonicalPatch.
		patch := toCanonicalPatch(p)

		// Call merge.Ingest for each valid patch.
		if err := merge.Ingest(r.Context(), srv.store, patch, req.SourceName); err != nil {
			slog.ErrorContext(r.Context(), "ingest: merge failed",
				"cve_id", p.CVEID, "source", req.SourceName, "error", err)
			resp.Rejected++
			resp.Errors = append(resp.Errors, ingestError{
				Index: i,
				CVEID: p.CVEID,
				Error: "internal processing error",
			})
			continue
		}

		resp.Accepted++
	}

	// Status code: 400 if all rejected, 202 otherwise.
	statusCode := http.StatusAccepted
	if resp.Accepted == 0 {
		statusCode = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

// toCanonicalPatch converts an ingest request patch to a merge-pipeline CanonicalPatch.
func toCanonicalPatch(p ingestPatch) feed.CanonicalPatch {
	cp := feed.CanonicalPatch{
		CVEID:              feed.StripNullBytes(p.CVEID),
		DescriptionPrimary: stripNullBytesPtr(p.Description),
		Severity:           stripNullBytesPtr(p.Severity),
		CVSSv3Score:        p.CVSSv3Score,
		CVSSv3Vector:       stripNullBytesPtr(p.CVSSv3Vec),
		CVSSv4Score:        p.CVSSv4Score,
		CVSSv4Vector:       stripNullBytesPtr(p.CVSSv4Vec),
		RawPayload:         p.RawPayload,
	}

	if p.DatePub != nil {
		cp.DatePublished = feed.ParseTimePtr(*p.DatePub)
	}
	if p.DateMod != nil {
		cp.DateModified = feed.ParseTimePtr(*p.DateMod)
	}

	for _, ref := range p.References {
		u := feed.StripNullBytes(ref.URL)
		if u != "" {
			cp.References = append(cp.References, feed.ReferenceEntry{
				URL:  u,
				Tags: ref.Tags,
			})
		}
	}

	return cp
}

// stripNullBytesPtr sanitizes a string pointer, returning nil for nil input.
func stripNullBytesPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := feed.StripNullBytes(*s)
	return &v
}
