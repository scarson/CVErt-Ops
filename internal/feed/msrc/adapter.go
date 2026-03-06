// ABOUTME: Feed adapter for the Microsoft Security Response Center (MSRC) API.
// ABOUTME: Fetches CSAF 2.0 advisories, converts to CanonicalPatch with vendor enrichment.
package msrc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/csaf"
)

const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "msrc"

	// baseURL is the MSRC CSAF API base endpoint.
	baseURL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
)

// Cursor is the JSON-serializable sync state for the MSRC adapter.
// Two-phase: first poll /updates for changed release IDs, then fetch CSAF
// documents for each. PendingReleaseIDs tracks releases not yet fetched
// in the current sync cycle.
type Cursor struct {
	LastReleaseDate   string   `json:"last_release_date"`
	PendingReleaseIDs []string `json:"pending_release_ids,omitempty"`
}

// Adapter implements feed.Adapter for the MSRC CSAF feed.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
}

// New creates an MSRC adapter. Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(time.Second), 1),
	}
}

// updateEntry represents a single release in the MSRC /updates response.
type updateEntry struct {
	ID                 string `json:"ID"`
	CurrentReleaseDate string `json:"CurrentReleaseDate"`
}

// updatesResponse is the OData JSON wrapper around the updates list.
type updatesResponse struct {
	Value []updateEntry `json:"value"`
}

// parseUpdates decodes the MSRC /updates OData JSON response.
func parseUpdates(r io.Reader) ([]updateEntry, error) {
	var resp updatesResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("msrc: parse updates: %w", err)
	}
	return resp.Value, nil
}

// parseCSAFDocument parses a raw CSAF JSON byte slice into a csaf.Document.
func parseCSAFDocument(data []byte) (*csaf.Document, error) {
	return csaf.Parse(strings.NewReader(string(data)))
}

// csafToPatches converts a parsed CSAF document into CanonicalPatch values.
func csafToPatches(doc *csaf.Document) []feed.CanonicalPatch {
	lookup := doc.ProductTree.Lookup()
	var patches []feed.CanonicalPatch

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE == "" {
			continue
		}

		p := feed.CanonicalPatch{
			CVEID:    strings.Clone(feed.StripNullBytes(vuln.CVE)),
			SourceID: SourceName,
		}

		// Description from notes[type=description]
		for _, note := range vuln.Notes {
			if note.Type == "description" {
				desc := strings.Clone(feed.StripNullBytes(note.Text))
				p.DescriptionPrimary = &desc
				break
			}
		}

		// CVSS: take the highest v3 score across all product score entries
		var bestV3Score float64
		var bestV3Vector string
		var bestV4Score float64
		var bestV4Vector string

		for _, score := range vuln.Scores {
			if score.CVSSv3 != nil && score.CVSSv3.BaseScore > bestV3Score {
				bestV3Score = score.CVSSv3.BaseScore
				bestV3Vector = score.CVSSv3.VectorString
			}
			if score.CVSSv4 != nil && score.CVSSv4.BaseScore > bestV4Score {
				bestV4Score = score.CVSSv4.BaseScore
				bestV4Vector = score.CVSSv4.VectorString
			}
		}
		if bestV3Score > 0 {
			p.CVSSv3Score = &bestV3Score
			vec := strings.Clone(bestV3Vector)
			p.CVSSv3Vector = &vec
		}
		if bestV4Score > 0 {
			p.CVSSv4Score = &bestV4Score
			vec := strings.Clone(bestV4Vector)
			p.CVSSv4Vector = &vec
		}

		// Dates from tracking metadata
		p.DatePublished = feed.ParseTimePtr(doc.DocumentMeta.Tracking.InitialReleaseDate)
		p.DateModified = feed.ParseTimePtr(doc.DocumentMeta.Tracking.CurrentReleaseDate)

		// References
		for _, ref := range vuln.References {
			if ref.URL == "" {
				continue
			}
			p.References = append(p.References, feed.ReferenceEntry{
				URL: strings.Clone(feed.StripNullBytes(ref.URL)),
			})
		}

		// Affected products via product tree lookup
		seen := make(map[string]struct{})
		for _, pid := range vuln.ProductStatus.KnownAffected {
			name, ok := lookup[pid]
			if !ok {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			normalized := strings.ToLower(name)
			p.AffectedCPEs = append(p.AffectedCPEs, feed.AffectedCPE{
				CPE:           name,
				CPENormalized: normalized,
			})
		}

		// Vendor enrichment
		enrichment := buildVendorEnrichment(vuln, lookup)
		p.VendorEnrichment = enrichment

		patches = append(patches, p)
	}

	return patches
}

// buildVendorEnrichment extracts MSRC-specific metadata from the vulnerability.
func buildVendorEnrichment(vuln csaf.Vulnerability, lookup map[string]string) *feed.VendorEnrichment {
	enrichment := &feed.VendorEnrichment{}

	// VendorSeverity from threats[category=impact]
	for _, threat := range vuln.Threats {
		if threat.Category == "impact" && threat.Details != "" {
			sev := strings.Clone(threat.Details)
			enrichment.VendorSeverity = &sev
			break
		}
	}

	// VendorFixState from remediations[category=vendor_fix] presence
	for _, rem := range vuln.Remediations {
		if rem.Category == "vendor_fix" {
			fixState := "Vendor Fix"
			enrichment.VendorFixState = &fixState
			break
		}
	}

	// Enrichment data: exploitability, kb_articles, remediation_urls, product_statuses
	var exploitability string
	for _, threat := range vuln.Threats {
		if threat.Category == "exploit_status" && threat.Details != "" {
			exploitability = threat.Details
			break
		}
	}

	var kbArticles []string
	var remediationURLs []string
	var productNames []string
	productSeen := make(map[string]struct{})

	for _, rem := range vuln.Remediations {
		if rem.Category == "vendor_fix" && rem.Details != "" {
			kbArticles = append(kbArticles, strings.Clone(rem.Details))
		}
		if rem.URL != "" {
			remediationURLs = append(remediationURLs, strings.Clone(rem.URL))
		}
		for _, pid := range rem.ProductIDs {
			name, ok := lookup[pid]
			if !ok {
				continue
			}
			if _, dup := productSeen[name]; dup {
				continue
			}
			productSeen[name] = struct{}{}
			productNames = append(productNames, name)
		}
	}

	dataMap := map[string]any{
		"exploitability":   exploitability,
		"kb_articles":      kbArticles,
		"remediation_urls": remediationURLs,
		"product_statuses": productNames,
	}

	data, err := json.Marshal(dataMap)
	if err == nil {
		enrichment.Data = data
	}

	return enrichment
}

// Fetch implements feed.Adapter. Two-phase:
// 1. Poll /updates to discover changed release IDs since LastReleaseDate
// 2. Fetch CSAF document for each changed release, parse, convert to patches
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("msrc: parse cursor: %w", err)
		}
	}

	// Phase 1: discover changed release IDs
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("msrc: rate limit: %w", err)
	}

	updatesURL := baseURL + "updates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updatesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("msrc: build updates request: %w", err)
	}
	if cur.LastReleaseDate != "" {
		q := req.URL.Query()
		q.Set("$filter", "CurrentReleaseDate gt datetime'"+cur.LastReleaseDate+"'")
		req.URL.RawQuery = q.Encode()
	}
	req.Header.Set("User-Agent", "CVErt-Ops/1.0 vulnerability intelligence platform")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req) //nolint:gosec // URL is constructed from a constant base
	if err != nil {
		return nil, fmt.Errorf("msrc: fetch updates: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("msrc: updates HTTP %d", resp.StatusCode)
	}

	updates, err := parseUpdates(resp.Body)
	if err != nil {
		return nil, err
	}

	// Determine which release IDs are new (not already at cursor's release date)
	var pendingIDs []string
	var latestDate string
	for _, u := range updates {
		if u.CurrentReleaseDate > latestDate {
			latestDate = u.CurrentReleaseDate
		}
		// If cursor has the same LastReleaseDate, this update is not new
		if cur.LastReleaseDate != "" && u.CurrentReleaseDate <= cur.LastReleaseDate {
			continue
		}
		pendingIDs = append(pendingIDs, u.ID)
	}

	// Short-circuit: no new updates
	if len(pendingIDs) == 0 {
		// Keep cursor date at the latest seen (or current cursor)
		effectiveDate := cur.LastReleaseDate
		if latestDate > effectiveDate {
			effectiveDate = latestDate
		}
		nextCursor := Cursor{LastReleaseDate: effectiveDate}
		nextCursorJSON, _ := json.Marshal(nextCursor)
		return &feed.FetchResult{
			SourceMeta: feed.SourceMeta{
				SourceName: SourceName,
				FetchedAt:  time.Now().UTC(),
			},
			NextCursor: nextCursorJSON,
		}, nil
	}

	// Phase 2: fetch CSAF documents for each pending release ID
	fetchedAt := time.Now().UTC()
	var allPatches []feed.CanonicalPatch

	for _, releaseID := range pendingIDs {
		if err := a.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("msrc: rate limit: %w", err)
		}

		csafURL := baseURL + "csaf/" + releaseID
		csafReq, err := http.NewRequestWithContext(ctx, http.MethodGet, csafURL, nil)
		if err != nil {
			return nil, fmt.Errorf("msrc: build csaf request for %s: %w", releaseID, err)
		}
		csafReq.Header.Set("User-Agent", "CVErt-Ops/1.0 vulnerability intelligence platform")
		csafReq.Header.Set("Accept", "application/json")

		csafResp, err := a.client.Do(csafReq) //nolint:gosec // URL constructed from constant base + release ID
		if err != nil {
			return nil, fmt.Errorf("msrc: fetch csaf %s: %w", releaseID, err)
		}

		if csafResp.StatusCode != http.StatusOK {
			csafResp.Body.Close() //nolint:errcheck,gosec // read-only response body close
			return nil, fmt.Errorf("msrc: csaf %s HTTP %d", releaseID, csafResp.StatusCode)
		}

		body, err := io.ReadAll(csafResp.Body)
		csafResp.Body.Close() //nolint:errcheck,gosec // read-only response body close
		if err != nil {
			return nil, fmt.Errorf("msrc: read csaf %s: %w", releaseID, err)
		}

		doc, err := parseCSAFDocument(body)
		if err != nil {
			return nil, fmt.Errorf("msrc: parse csaf %s: %w", releaseID, err)
		}

		patches := csafToPatches(doc)
		allPatches = append(allPatches, patches...)
	}

	// Update cursor: all pending IDs have been fetched
	effectiveDate := cur.LastReleaseDate
	if latestDate > effectiveDate {
		effectiveDate = latestDate
	}
	nextCursor := Cursor{LastReleaseDate: effectiveDate}
	nextCursorJSON, err := json.Marshal(nextCursor)
	if err != nil {
		return nil, fmt.Errorf("msrc: marshal cursor: %w", err)
	}

	return &feed.FetchResult{
		Patches: allPatches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  fetchedAt,
		},
		NextCursor: nextCursorJSON,
	}, nil
}
