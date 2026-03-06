// ABOUTME: Feed adapter for the Red Hat Security Data API.
// ABOUTME: Two-phase fetch: list recently modified CVEs, then fetch detail for each.
package redhat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
)

const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "redhat"

	// baseURL is the Red Hat Security Data API base endpoint.
	baseURL = "https://access.redhat.com/hydra/rest/securitydata/"

	// listPageSize is the number of CVEs per list page.
	listPageSize = 100
)

// Cursor is the JSON-serializable sync state for the Red Hat adapter.
// Two-phase: first paginate through /cve.json for CVE IDs, then fetch
// /cve/{CVE-ID}.json for each. DetailQueue enables mid-batch resumption.
type Cursor struct {
	AfterDate   string   `json:"after_date"`
	DetailQueue []string `json:"detail_queue,omitempty"`
	Page        int      `json:"page,omitempty"`
}

// Adapter implements feed.Adapter for the Red Hat Security Data API.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	log         *slog.Logger
}

// New creates a Red Hat adapter. Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(500*time.Millisecond), 1),
		log:         slog.Default(),
	}
}

// listEntry represents a single CVE in the Red Hat list endpoint response.
type listEntry struct {
	CVE string `json:"CVE"`
}

// detailRecord represents the full Red Hat CVE detail response.
type detailRecord struct {
	Name            string            `json:"name"`
	ThreatSeverity  string            `json:"threat_severity"`
	PublicDate      string            `json:"public_date"`
	CWE             string            `json:"cwe"`
	CVSS3           *cvss3Info        `json:"cvss3"`
	Details         []string          `json:"details"`
	References      []string          `json:"references"`
	Bugzilla        *bugzillaInfo     `json:"bugzilla"`
	AffectedRelease []affectedRelease `json:"affected_release"`
	PackageState    []packageState    `json:"package_state"`
	Mitigation      *mitigationInfo   `json:"mitigation"`
	UpstreamFix     string            `json:"upstream_fix"`
}

type cvss3Info struct {
	BaseScore     string `json:"cvss3_base_score"`
	ScoringVector string `json:"cvss3_scoring_vector"`
}

type bugzillaInfo struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

type affectedRelease struct {
	ProductName string `json:"product_name"`
	Advisory    string `json:"advisory"`
	CPE         string `json:"cpe"`
	Package     string `json:"package"`
}

type packageState struct {
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	CPE         string `json:"cpe"`
	PackageName string `json:"package_name"`
}

type mitigationInfo struct {
	Value string `json:"value"`
}

// fixStatePriority maps fix state strings to severity rankings.
// Lower number = more severe. States not in the map get priority 0 (worst).
var fixStatePriority = map[string]int{
	"Affected":             1,
	"Will not fix":         2,
	"Fix deferred":         3,
	"Under investigation":  4,
	"Not affected":         5,
}

// parseListResponse decodes the Red Hat CVE list endpoint JSON array.
func parseListResponse(r io.Reader) ([]listEntry, error) {
	var entries []listEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil, fmt.Errorf("redhat: parse list: %w", err)
	}
	return entries, nil
}

// parseDetailResponse decodes a Red Hat CVE detail JSON response.
func parseDetailResponse(r io.Reader) (*detailRecord, error) {
	var detail detailRecord
	if err := json.NewDecoder(r).Decode(&detail); err != nil {
		return nil, fmt.Errorf("redhat: parse detail: %w", err)
	}
	return &detail, nil
}

// detailToPatch converts a Red Hat detail record to a CanonicalPatch.
func detailToPatch(d detailRecord) feed.CanonicalPatch {
	p := feed.CanonicalPatch{
		CVEID:    strings.Clone(feed.StripNullBytes(d.Name)),
		SourceID: SourceName,
	}

	// Description from details[0]
	if len(d.Details) > 0 && d.Details[0] != "" {
		desc := strings.Clone(feed.StripNullBytes(d.Details[0]))
		p.DescriptionPrimary = &desc
	}

	// Date published from public_date
	p.DatePublished = feed.ParseTimePtr(d.PublicDate)

	// CVSS v3: score is a string in the API, needs parsing
	if d.CVSS3 != nil && d.CVSS3.BaseScore != "" {
		score, err := strconv.ParseFloat(d.CVSS3.BaseScore, 64)
		if err == nil {
			p.CVSSv3Score = &score
			vec := strings.Clone(feed.StripNullBytes(d.CVSS3.ScoringVector))
			p.CVSSv3Vector = &vec
		}
	}

	// CWE: may be "CWE-NNN->CWE-MMM" chain format, take first
	if d.CWE != "" {
		cweID := d.CWE
		if idx := strings.Index(cweID, "->"); idx >= 0 {
			cweID = cweID[:idx]
		}
		cleaned := strings.Clone(feed.StripNullBytes(cweID))
		if cleaned != "" {
			p.CWEIDs = []string{cleaned}
		}
	}

	// References: bugzilla.url first, then references[]
	if d.Bugzilla != nil && d.Bugzilla.URL != "" {
		p.References = append(p.References, feed.ReferenceEntry{
			URL: strings.Clone(feed.StripNullBytes(d.Bugzilla.URL)),
		})
	}
	for _, ref := range d.References {
		if ref != "" {
			p.References = append(p.References, feed.ReferenceEntry{
				URL: strings.Clone(feed.StripNullBytes(ref)),
			})
		}
	}

	// Affected CPEs from affected_release[].cpe
	seen := make(map[string]struct{})
	for _, ar := range d.AffectedRelease {
		if ar.CPE == "" {
			continue
		}
		if _, dup := seen[ar.CPE]; dup {
			continue
		}
		seen[ar.CPE] = struct{}{}
		normalized := strings.ToLower(ar.CPE)
		p.AffectedCPEs = append(p.AffectedCPEs, feed.AffectedCPE{
			CPE:           ar.CPE,
			CPENormalized: normalized,
		})
	}

	// Vendor enrichment
	p.VendorEnrichment = buildVendorEnrichment(d)

	return p
}

// buildVendorEnrichment extracts Red Hat-specific metadata.
func buildVendorEnrichment(d detailRecord) *feed.VendorEnrichment {
	enrichment := &feed.VendorEnrichment{}

	// VendorSeverity from threat_severity
	if d.ThreatSeverity != "" {
		sev := strings.Clone(d.ThreatSeverity)
		enrichment.VendorSeverity = &sev
	}

	// VendorFixState: worst-case across all package_state[].fix_state
	if len(d.PackageState) > 0 {
		worst := worstFixState(d.PackageState)
		enrichment.VendorFixState = &worst
	}

	// Enrichment data: bugzilla, affected_release, package_state, mitigation, upstream_fix
	dataMap := make(map[string]any)

	if d.Bugzilla != nil {
		dataMap["bugzilla"] = map[string]any{
			"id":          d.Bugzilla.ID,
			"url":         d.Bugzilla.URL,
			"description": d.Bugzilla.Description,
		}
	}

	if len(d.AffectedRelease) > 0 {
		dataMap["affected_release"] = d.AffectedRelease
	}

	if len(d.PackageState) > 0 {
		dataMap["package_state"] = d.PackageState
	}

	if d.Mitigation != nil && d.Mitigation.Value != "" {
		dataMap["mitigation"] = d.Mitigation.Value
	}

	if d.UpstreamFix != "" {
		dataMap["upstream_fix"] = d.UpstreamFix
	}

	data, err := json.Marshal(dataMap)
	if err == nil {
		enrichment.Data = data
	}

	return enrichment
}

// worstFixState returns the most severe fix state across all package states.
// Priority: Affected > Will not fix > Fix deferred > Under investigation > Not affected.
func worstFixState(states []packageState) string {
	worst := ""
	worstPri := 999

	for _, s := range states {
		pri, known := fixStatePriority[s.FixState]
		if !known {
			// Unknown states are treated as worst-case (more severe than "Affected").
			pri = 0
		}
		if pri < worstPri {
			worstPri = pri
			worst = s.FixState
		}
	}

	return worst
}

// Fetch implements feed.Adapter. Two-phase:
// 1. Paginate through /cve.json?after={date}&per_page=100&page={N} for CVE IDs
// 2. Fetch /cve/{CVE-ID}.json for each CVE in the list
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("redhat: parse cursor: %w", err)
		}
	}

	fetchedAt := time.Now().UTC()

	// If the cursor has a detail queue, resume fetching details
	var cveIDs []string
	fullPage := false

	if len(cur.DetailQueue) > 0 {
		cveIDs = cur.DetailQueue
	} else {
		// Phase 1: fetch list page
		if err := a.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("redhat: rate limit: %w", err)
		}

		page := cur.Page
		if page == 0 {
			page = 1
		}

		listURL := baseURL + "cve.json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return nil, fmt.Errorf("redhat: build list request: %w", err)
		}
		q := req.URL.Query()
		q.Set("per_page", strconv.Itoa(listPageSize))
		q.Set("page", strconv.Itoa(page))
		if cur.AfterDate != "" {
			q.Set("after", cur.AfterDate)
		}
		req.URL.RawQuery = q.Encode()
		req.Header.Set("User-Agent", "CVErt-Ops/1.0 vulnerability intelligence platform")
		req.Header.Set("Accept", "application/json")

		resp, err := a.client.Do(req) //nolint:gosec // URL constructed from constant base
		if err != nil {
			return nil, fmt.Errorf("redhat: fetch list: %w", err)
		}
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("redhat: list HTTP %d", resp.StatusCode)
		}

		entries, err := parseListResponse(resp.Body)
		if err != nil {
			return nil, err
		}

		for _, e := range entries {
			if e.CVE != "" {
				cveIDs = append(cveIDs, e.CVE)
			}
		}

		fullPage = len(entries) >= listPageSize
	}

	// Phase 2: fetch detail for each CVE
	var patches []feed.CanonicalPatch
	for _, cveID := range cveIDs {
		if err := a.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("redhat: rate limit: %w", err)
		}

		detailURL := baseURL + "cve/" + cveID + ".json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, detailURL, nil)
		if err != nil {
			return nil, fmt.Errorf("redhat: build detail request for %s: %w", cveID, err)
		}
		req.Header.Set("User-Agent", "CVErt-Ops/1.0 vulnerability intelligence platform")
		req.Header.Set("Accept", "application/json")

		resp, err := a.client.Do(req) //nolint:gosec // URL constructed from constant base + CVE ID
		if err != nil {
			return nil, fmt.Errorf("redhat: fetch detail %s: %w", cveID, err)
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close() //nolint:errcheck,gosec
			a.log.WarnContext(ctx, "redhat: detail 404, skipping CVE",
				slog.String("cve_id", cveID))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close() //nolint:errcheck,gosec
			return nil, fmt.Errorf("redhat: detail %s HTTP %d", cveID, resp.StatusCode)
		}

		detail, err := parseDetailResponse(resp.Body)
		resp.Body.Close() //nolint:errcheck,gosec
		if err != nil {
			return nil, fmt.Errorf("redhat: parse detail %s: %w", cveID, err)
		}

		patches = append(patches, detailToPatch(*detail))
	}

	// Determine next cursor for pagination
	var nextCursor json.RawMessage
	if fullPage {
		page := cur.Page
		if page == 0 {
			page = 1
		}
		next := Cursor{
			AfterDate: cur.AfterDate,
			Page:      page + 1,
		}
		nextCursor, _ = json.Marshal(next)
	}

	return &feed.FetchResult{
		Patches: patches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  fetchedAt,
		},
		NextCursor: nextCursor,
	}, nil
}
