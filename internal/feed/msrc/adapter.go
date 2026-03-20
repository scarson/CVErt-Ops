// ABOUTME: Feed adapter for the Microsoft Security Response Center (MSRC) CSAF feed.
// ABOUTME: Fetches per-CVE CSAF 2.0 advisories via changes.csv, converts to CanonicalPatch with vendor enrichment.
package msrc

import (
	"bytes"
	"context"
	"encoding/csv"
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

	// baseURL is the MSRC CSAF advisories base path.
	baseURL = "https://msrc.microsoft.com/csaf/advisories/"

	// maxChangesSize caps the changes.csv response body to prevent OOM from malformed responses.
	maxChangesSize = 10 << 20 // 10 MB

	// maxCSAFDocSize caps the CSAF response body to prevent OOM from malformed responses.
	maxCSAFDocSize = 1 << 20 // 1 MB
)

// Cursor is the JSON-serializable sync state for the MSRC adapter.
type Cursor struct {
	LastUpdated string `json:"last_updated"`
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
		client:      feed.WrapClientWithUA(client),
		rateLimiter: rate.NewLimiter(rate.Every(time.Second), 1),
	}
}

// changeEntry represents a single row in the MSRC changes.csv file.
type changeEntry struct {
	Path      string
	Timestamp string
}

// parseChangesCSV parses the MSRC changes.csv format: "path","timestamp" per line.
func parseChangesCSV(r io.Reader) ([]changeEntry, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 2
	cr.ReuseRecord = true
	var entries []changeEntry
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("msrc: parse changes.csv: %w", err)
		}
		entries = append(entries, changeEntry{
			Path:      strings.Clone(record[0]),
			Timestamp: strings.Clone(record[1]),
		})
	}
	return entries, nil
}

// parseCSAFDocument parses a raw CSAF JSON byte slice into a csaf.Document.
func parseCSAFDocument(data []byte) (*csaf.Document, error) {
	return csaf.Parse(bytes.NewReader(data))
}

// csafToPatches converts a parsed CSAF document into CanonicalPatch values.
func csafToPatches(doc *csaf.Document) []feed.CanonicalPatch {
	lookup := doc.ProductTree.Lookup()
	var patches []feed.CanonicalPatch

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE == "" {
			continue
		}

		cveID := strings.Clone(feed.StripNullBytes(vuln.CVE))
		p := feed.CanonicalPatch{
			CVEID:    cveID,
			SourceID: cveID,
		}

		// Description from notes[type=description]
		for _, note := range vuln.Notes {
			if note.Type == "description" {
				desc := strings.Clone(feed.StripNullBytes(note.Text))
				p.DescriptionPrimary = &desc
				break
			}
		}

		// CVSS: take the highest v3/v4 score across all product score entries.
		// A score of 0.0 is valid (CVSS "NONE" severity), so we track presence
		// with a bool rather than checking > 0.
		var bestV3Score float64
		var bestV3Vector string
		var hasV3 bool
		var bestV4Score float64
		var bestV4Vector string
		var hasV4 bool

		for _, score := range vuln.Scores {
			if score.CVSSv3 != nil && (!hasV3 || score.CVSSv3.BaseScore > bestV3Score) {
				bestV3Score = score.CVSSv3.BaseScore
				bestV3Vector = score.CVSSv3.VectorString
				hasV3 = true
			}
			if score.CVSSv4 != nil && (!hasV4 || score.CVSSv4.BaseScore > bestV4Score) {
				bestV4Score = score.CVSSv4.BaseScore
				bestV4Vector = score.CVSSv4.VectorString
				hasV4 = true
			}
		}
		if hasV3 {
			p.CVSSv3Score = &bestV3Score
			vec := strings.Clone(feed.StripNullBytes(bestV3Vector))
			p.CVSSv3Vector = &vec
		}
		if hasV4 {
			p.CVSSv4Score = &bestV4Score
			vec := strings.Clone(feed.StripNullBytes(bestV4Vector))
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

		// Affected products via product tree lookup (dedup on normalized key)
		seen := make(map[string]struct{})
		for _, pid := range vuln.ProductStatus.KnownAffected {
			name, ok := lookup[pid]
			if !ok {
				continue
			}
			normalized := strings.ToLower(name)
			if _, dup := seen[normalized]; dup {
				continue
			}
			seen[normalized] = struct{}{}
			cleanName := strings.Clone(feed.StripNullBytes(name))
			p.AffectedCPEs = append(p.AffectedCPEs, feed.AffectedCPE{
				CPE:           cleanName,
				CPENormalized: strings.Clone(feed.StripNullBytes(normalized)),
			})
		}

		// Vendor enrichment
		enrichment := buildVendorEnrichment(vuln, lookup)
		p.VendorEnrichment = enrichment

		if rawBytes, err := json.Marshal(vuln); err == nil {
			p.RawPayload = rawBytes
		}
		patches = append(patches, p)
	}

	return patches
}

// buildVendorEnrichment extracts MSRC-specific metadata from the vulnerability.
// Returns nil if no enrichment data is available.
func buildVendorEnrichment(vuln csaf.Vulnerability, lookup map[string]string) *feed.VendorEnrichment {
	// Check if any enrichment data exists before allocating.
	hasThreats := false
	for _, threat := range vuln.Threats {
		if (threat.Category == "impact" || threat.Category == "exploit_status") && threat.Details != "" {
			hasThreats = true
			break
		}
	}
	hasRemediations := len(vuln.Remediations) > 0

	if !hasThreats && !hasRemediations {
		return nil
	}

	enrichment := &feed.VendorEnrichment{}

	// VendorSeverity from threats[category=impact]
	for _, threat := range vuln.Threats {
		if threat.Category == "impact" && threat.Details != "" {
			sev := strings.Clone(feed.StripNullBytes(threat.Details))
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
	// Only include keys with actual data to avoid junk JSONB.
	dataMap := make(map[string]any)

	for _, threat := range vuln.Threats {
		if threat.Category == "exploit_status" && threat.Details != "" {
			dataMap["exploitability"] = strings.Clone(feed.StripNullBytes(threat.Details))
			break
		}
	}

	var kbArticles []string
	var remediationURLs []string
	var productNames []string
	productSeen := make(map[string]struct{})

	for _, rem := range vuln.Remediations {
		if rem.Category == "vendor_fix" && rem.Details != "" {
			kbArticles = append(kbArticles, strings.Clone(feed.StripNullBytes(rem.Details)))
		}
		if rem.URL != "" {
			remediationURLs = append(remediationURLs, strings.Clone(feed.StripNullBytes(rem.URL)))
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
			productNames = append(productNames, strings.Clone(feed.StripNullBytes(name)))
		}
	}

	if len(kbArticles) > 0 {
		dataMap["kb_articles"] = kbArticles
	}
	if len(remediationURLs) > 0 {
		dataMap["remediation_urls"] = remediationURLs
	}
	if len(productNames) > 0 {
		dataMap["product_statuses"] = productNames
	}

	if len(dataMap) > 0 {
		data, err := json.Marshal(dataMap)
		if err == nil {
			enrichment.Data = data
		}
	}

	return enrichment
}

// Fetch implements feed.Adapter. Two-phase:
// 1. Download changes.csv to discover CSAF files updated since LastUpdated cursor
// 2. Download each pending CSAF file, parse, convert to patches
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("msrc: parse cursor: %w", err)
		}
	}

	// Phase 1: download and parse changes.csv
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("msrc: rate limit: %w", err)
	}

	changesURL := baseURL + "changes.csv"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, changesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("msrc: build changes request: %w", err)
	}
	req.Header.Set("Accept", "text/csv")

	resp, err := a.client.Do(req) //nolint:gosec // URL is constructed from a constant base
	if err != nil {
		return nil, fmt.Errorf("msrc: fetch changes.csv: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec // drain for connection reuse
		return nil, fmt.Errorf("msrc: changes.csv HTTP %d", resp.StatusCode)
	}

	allEntries, err := parseChangesCSV(io.LimitReader(resp.Body, maxChangesSize))
	if err != nil {
		return nil, err
	}

	// Filter entries newer than cursor timestamp
	var pending []changeEntry
	var latestTimestamp string
	for _, entry := range allEntries {
		if entry.Timestamp > latestTimestamp {
			latestTimestamp = entry.Timestamp
		}
		if cur.LastUpdated != "" && entry.Timestamp <= cur.LastUpdated {
			continue
		}
		pending = append(pending, entry)
	}

	// Short-circuit: no pending entries
	if len(pending) == 0 {
		effectiveTimestamp := cur.LastUpdated
		if latestTimestamp > effectiveTimestamp {
			effectiveTimestamp = latestTimestamp
		}
		nextCursor := Cursor{LastUpdated: effectiveTimestamp}
		nextCursorJSON, err := json.Marshal(nextCursor)
		if err != nil {
			return nil, fmt.Errorf("msrc: marshal cursor: %w", err)
		}
		return &feed.FetchResult{
			SourceMeta: feed.SourceMeta{
				SourceName: SourceName,
				FetchedAt:  time.Now().UTC(),
			},
			NextCursor: nextCursorJSON,
			LastPage:   true,
		}, nil
	}

	// Phase 2: fetch CSAF documents for each pending entry
	fetchedAt := time.Now().UTC()
	var allPatches []feed.CanonicalPatch

	for _, entry := range pending {
		if err := a.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("msrc: rate limit: %w", err)
		}

		fileURL := baseURL + entry.Path
		fileReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
		if err != nil {
			return nil, fmt.Errorf("msrc: build csaf request for %s: %w", entry.Path, err)
		}
		fileReq.Header.Set("Accept", "application/json")

		fileResp, err := a.client.Do(fileReq) //nolint:gosec // URL constructed from constant base + CSV path
		if err != nil {
			return nil, fmt.Errorf("msrc: fetch csaf %s: %w", entry.Path, err)
		}

		if fileResp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, fileResp.Body) //nolint:errcheck,gosec // drain for connection reuse
			fileResp.Body.Close()              //nolint:errcheck,gosec // read-only response body close
			return nil, fmt.Errorf("msrc: csaf %s HTTP %d", entry.Path, fileResp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(fileResp.Body, maxCSAFDocSize))
		fileResp.Body.Close() //nolint:errcheck,gosec // read-only response body close
		if err != nil {
			return nil, fmt.Errorf("msrc: read csaf %s: %w", entry.Path, err)
		}

		doc, err := parseCSAFDocument(body)
		if err != nil {
			return nil, fmt.Errorf("msrc: parse csaf %s: %w", entry.Path, err)
		}

		patches := csafToPatches(doc)
		allPatches = append(allPatches, patches...)
	}

	// Update cursor to the latest timestamp seen
	effectiveTimestamp := cur.LastUpdated
	if latestTimestamp > effectiveTimestamp {
		effectiveTimestamp = latestTimestamp
	}
	nextCursor := Cursor{LastUpdated: effectiveTimestamp}
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
		LastPage:   true,
	}, nil
}
