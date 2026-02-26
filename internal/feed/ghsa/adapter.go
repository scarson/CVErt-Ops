// Package ghsa implements the FeedAdapter for the GitHub Security Advisory
// (GHSA) REST API.
//
// GHSA exposes public security advisories at GET https://api.github.com/advisories.
// The adapter uses cursor-based pagination via the Link response header and
// incremental sync via the `updated` date-range filter.
//
// The REST API is preferred over the GHSA GraphQL API for this adapter because:
//   - The response is a top-level JSON array (simpler streaming — no wrapper key
//     to navigate past).
//   - cve_id is a direct top-level field; no parsing of identifiers[] needed.
//   - The vulnerabilities array is inline per-advisory (no nested pagination).
//
// Cursor format: {"since": "2024-01-15T10:00:00Z"}
// Auth: GITHUB_TOKEN environment variable (Bearer token).
//   Unauthenticated: 60 req/hr — unusable for backfill.
//   Authenticated:   5,000 req/hr; adapter uses ≤1 req/sec (safe margin).
//
// Only "reviewed" type advisories are ingested. Unreviewed advisories lack
// structured CVE data and are out of scope for the CVErt Ops corpus.
//
// Alias resolution: cve_id is used as the canonical primary key when non-null.
// The ghsa_id is always stored as source_id in cve_sources. Late-binding PK
// migration is required when a GHSA advisory gains a CVE ID after initial ingest
// (pipeline.go Step 1.5 handles this transparently).
package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
)

const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "ghsa"

	// advisoriesURL is the GitHub REST API endpoint for global security advisories.
	advisoriesURL = "https://api.github.com/advisories"

	// apiVersion is the GitHub API version header value.
	apiVersion = "2022-11-28"

	// overlap is the lookback subtracted from the cursor to guard against
	// eventual-consistency lag (§3.3). Same value as NVD adapter.
	overlap = 15 * time.Minute
)

// Cursor is the JSON-serializable sync state for the GHSA adapter.
type Cursor struct {
	// Since is the lower bound for the `updated>=` filter on the next sync,
	// stored as RFC3339. Applied with a 15-minute lookback overlap on use.
	Since string `json:"since,omitempty"`
}

// Adapter implements feed.Adapter for the GHSA REST API.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	token       string
}

// New creates a GHSA adapter. Reads GITHUB_TOKEN from the environment.
// Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	// 5,000 req/hr authenticated ≈ 1.39 req/sec; cap at 1 req/sec for safety.
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		token:       os.Getenv("GITHUB_TOKEN"),
	}
}

// Fetch pages through all GHSA reviewed advisories updated since the cursor.
// All pages are fetched in a single call; the rate limiter enforces ≤1 req/sec.
//
// On the first run (nil/zero cursor) all reviewed advisories are fetched
// (full backfill). Subsequent runs use a 15-minute lookback overlap on the
// stored since timestamp to catch eventual-consistency stragglers.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("ghsa: parse cursor: %w", err)
		}
	}

	// Apply 15-minute lookback overlap to the since timestamp.
	var sinceStr string
	if cur.Since != "" {
		t, err := time.Parse(time.RFC3339, cur.Since)
		if err != nil {
			return nil, fmt.Errorf("ghsa: parse cursor since: %w", err)
		}
		sinceStr = t.Add(-overlap).UTC().Format(time.RFC3339)
	}

	fetchedAt := time.Now().UTC()
	var patches []feed.CanonicalPatch
	after := "" // Link header cursor; empty = start from first page

	for {
		if err := a.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("ghsa: rate limit: %w", err)
		}

		page, nextAfter, err := a.fetchPage(ctx, sinceStr, after)
		if err != nil {
			return nil, err
		}
		patches = append(patches, page...)

		if nextAfter == "" {
			break // no more pages
		}
		after = nextAfter
	}

	newCursorJSON, err := json.Marshal(Cursor{Since: fetchedAt.Format(time.RFC3339)})
	if err != nil {
		return nil, fmt.Errorf("ghsa: marshal cursor: %w", err)
	}

	return &feed.FetchResult{
		Patches: patches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  fetchedAt,
		},
		NextCursor: newCursorJSON,
	}, nil
}

// fetchPage fetches one page of advisories and returns the parsed patches and
// the next page cursor (empty string if no more pages exist).
func (a *Adapter) fetchPage(ctx context.Context, since, after string) ([]feed.CanonicalPatch, string, error) {
	q := url.Values{}
	q.Set("per_page", "100")
	q.Set("sort", "updated")
	q.Set("direction", "asc") // ascending so cursor advances monotonically
	q.Set("type", "reviewed") // only reviewed advisories have structured CVE data
	if since != "" {
		// GitHub search date range syntax: `updated=>=TIMESTAMP`.
		// url.Values.Encode() percent-encodes the `>=` operator correctly.
		q.Set("updated", ">="+since)
	}
	if after != "" {
		q.Set("after", after)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, advisoriesURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("ghsa: build request: %w", err)
	}

	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	resp, err := a.client.Do(req) //nolint:gosec // G107: URL is a constant
	if err != nil {
		return nil, "", fmt.Errorf("ghsa: do request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("ghsa: HTTP %d from %s", resp.StatusCode, advisoriesURL)
	}

	// Extract the next-page cursor from the Link header before reading the body.
	nextAfter := parseLinkHeader(resp.Header.Get("Link"))

	// Stream the top-level JSON array. The GHSA REST response is a raw array
	// (unlike NVD which wraps in an object). Open '[' directly, then More() loop.
	dec := json.NewDecoder(resp.Body)
	t, err := dec.Token()
	if err != nil {
		return nil, "", fmt.Errorf("ghsa: read array open: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return nil, "", fmt.Errorf("ghsa: expected '[', got %v", t)
	}

	var patches []feed.CanonicalPatch
	for dec.More() {
		var rec ghsaAdvisory
		if err := dec.Decode(&rec); err != nil {
			// Skip malformed individual records; do not abort the whole page.
			continue
		}
		patch := parseAdvisory(rec)
		if patch != nil {
			patches = append(patches, *patch)
		}
	}

	return patches, nextAfter, nil
}

// parseLinkHeader extracts the `after` cursor value from the GitHub Link header.
// Returns "" when no rel="next" link is present (last page).
//
// GitHub Link header format (RFC 5988):
//
//	<https://api.github.com/advisories?after=Y3Vyc29y...&per_page=100>; rel="next"
func parseLinkHeader(header string) string {
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		urlPart, relPart, found := strings.Cut(part, ";")
		if !found {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(relPart), `rel="next"`) {
			continue
		}
		rawURL := strings.Trim(strings.TrimSpace(urlPart), "<>")
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		return u.Query().Get("after")
	}
	return ""
}

// --- GHSA advisory JSON types ---

// ghsaAdvisory represents a GHSA REST API advisory record.
// Fields are pointer types where the API may return null.
type ghsaAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           *string             `json:"cve_id"`    // null when no CVE assigned
	Summary         string              `json:"summary"`   // max 1024 chars
	Description     *string             `json:"description"` // max 65535 chars, may contain null bytes
	Severity        string              `json:"severity"`  // "critical","high","medium","low","unknown"
	PublishedAt     string              `json:"published_at"`
	UpdatedAt       string              `json:"updated_at"`
	WithdrawnAt     *string             `json:"withdrawn_at"` // null when not withdrawn
	CVSS            *ghsaCVSSEntry      `json:"cvss"`
	CVSSSeverities  *ghsaCVSSSeverities `json:"cvss_severities"`
	CWEs            []ghsaCWE           `json:"cwes"`
	Vulnerabilities []ghsaVulnerability `json:"vulnerabilities"`
	References      []ghsaReference     `json:"references"`
	Identifiers     []ghsaIdentifier    `json:"identifiers"`
	HTMLURL         string              `json:"html_url"`
}

// ghsaCVSSEntry holds a CVSS score and vector string.
type ghsaCVSSEntry struct {
	Score        float64 `json:"score"`
	VectorString string  `json:"vector_string"`
}

// ghsaCVSSSeverities holds per-version CVSS entries.
// Prefer this over the top-level cvss field when available.
type ghsaCVSSSeverities struct {
	CVSSv3 *ghsaCVSSEntry `json:"cvss_v3"`
	CVSSv4 *ghsaCVSSEntry `json:"cvss_v4"`
}

// ghsaCWE holds a CWE entry from the cwes array.
type ghsaCWE struct {
	CWEID string `json:"cwe_id"` // e.g., "CWE-79"
	Name  string `json:"name"`
}

// ghsaVulnerability describes an affected package and its version range.
type ghsaVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange *string `json:"vulnerable_version_range"` // e.g., ">= 1.0, < 1.2.3"
	FirstPatchedVersion    *string `json:"first_patched_version"`    // e.g., "1.2.3"
}

// ghsaReference is a single URL reference.
type ghsaReference struct {
	URL string `json:"url"`
}

// ghsaIdentifier is an entry in the identifiers array (type/value pair).
type ghsaIdentifier struct {
	Type  string `json:"type"`  // "GHSA" or "CVE"
	Value string `json:"value"` // the ID value
}

// parseAdvisory converts a GHSA advisory record to a CanonicalPatch.
// Returns nil for records without a GHSA ID (malformed).
func parseAdvisory(rec ghsaAdvisory) *feed.CanonicalPatch {
	nativeID := strings.Clone(feed.StripNullBytes(rec.GHSAID))
	if nativeID == "" {
		return nil
	}

	// Alias resolution: collect CVE IDs from the top-level cve_id field and
	// from the identifiers array. ResolveCanonicalID picks the first CVE match.
	var aliases []string
	if rec.CVEID != nil && *rec.CVEID != "" {
		aliases = append(aliases, strings.Clone(feed.StripNullBytes(*rec.CVEID)))
	}
	for _, id := range rec.Identifiers {
		if strings.EqualFold(id.Type, "CVE") {
			if v := strings.Clone(feed.StripNullBytes(id.Value)); v != "" {
				aliases = append(aliases, v)
			}
		}
	}
	canonicalID := feed.ResolveCanonicalID(nativeID, aliases)

	patch := &feed.CanonicalPatch{
		CVEID:    canonicalID,
		SourceID: nativeID, // always the native GHSA ID
	}

	// Withdrawn: non-null withdrawn_at → tombstone.
	// IsWithdrawn signals the merge pipeline to NULL out CVSS/EPSS scores.
	if rec.WithdrawnAt != nil && *rec.WithdrawnAt != "" {
		patch.IsWithdrawn = true
		patch.Status = "withdrawn"
	}

	patch.DatePublished = feed.ParseTimePtr(rec.PublishedAt)
	patch.DateModified = feed.ParseTimePtr(rec.UpdatedAt)

	// Description: prefer description (longer) over summary.
	// GHSA descriptions may contain null bytes — strip before DB write.
	var desc string
	if rec.Description != nil {
		desc = strings.Clone(feed.StripNullBytes(*rec.Description))
	}
	if desc == "" {
		desc = strings.Clone(feed.StripNullBytes(rec.Summary))
	}
	if desc != "" {
		patch.DescriptionPrimary = &desc
	}

	// Severity: normalize to uppercase; drop "unknown".
	if sev := strings.ToLower(rec.Severity); sev != "" && sev != "unknown" {
		s := strings.ToUpper(strings.Clone(feed.StripNullBytes(rec.Severity)))
		patch.Severity = &s
	}

	// CVSS: prefer cvss_severities (explicit V3/V4 split) over top-level cvss.
	if cs := rec.CVSSSeverities; cs != nil {
		if v4 := cs.CVSSv4; v4 != nil && v4.Score > 0 {
			score := v4.Score
			patch.CVSSv4Score = &score
			if vec := strings.Clone(feed.StripNullBytes(v4.VectorString)); vec != "" {
				patch.CVSSv4Vector = &vec
			}
		}
		if v3 := cs.CVSSv3; v3 != nil && v3.Score > 0 {
			score := v3.Score
			patch.CVSSv3Score = &score
			if vec := strings.Clone(feed.StripNullBytes(v3.VectorString)); vec != "" {
				patch.CVSSv3Vector = &vec
			}
		}
	}
	// Fallback: top-level cvss (no version distinction — treat as V3).
	if patch.CVSSv3Score == nil && rec.CVSS != nil && rec.CVSS.Score > 0 {
		score := rec.CVSS.Score
		patch.CVSSv3Score = &score
		if vec := strings.Clone(feed.StripNullBytes(rec.CVSS.VectorString)); vec != "" {
			patch.CVSSv3Vector = &vec
		}
	}

	// CWE IDs.
	for _, cwe := range rec.CWEs {
		if id := strings.Clone(feed.StripNullBytes(cwe.CWEID)); id != "" {
			patch.CWEIDs = append(patch.CWEIDs, id)
		}
	}

	// Affected packages. GHSA provides version ranges as a free-form string
	// (e.g., ">= 1.0, < 1.2.3") and first_patched_version as the fix boundary.
	// We synthesize OSV-style events from first_patched_version when available.
	for _, v := range rec.Vulnerabilities {
		eco := strings.Clone(feed.StripNullBytes(v.Package.Ecosystem))
		pkg := strings.Clone(feed.StripNullBytes(v.Package.Name))
		if eco == "" || pkg == "" {
			continue
		}

		var fixed string
		if v.FirstPatchedVersion != nil {
			fixed = strings.Clone(feed.StripNullBytes(*v.FirstPatchedVersion))
		}

		// Build synthetic OSV-format events for schema compatibility.
		var eventsJSON json.RawMessage
		if fixed != "" {
			type event struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed       string `json:"fixed,omitempty"`
			}
			if b, err := json.Marshal([]event{{Introduced: "0"}, {Fixed: fixed}}); err == nil {
				eventsJSON = b
			}
		}

		patch.AffectedPackages = append(patch.AffectedPackages, feed.AffectedPackage{
			Ecosystem:   eco,
			PackageName: pkg,
			RangeType:   "ECOSYSTEM",
			Introduced:  "0",
			Fixed:       fixed,
			Events:      eventsJSON,
		})
	}

	// References. Include the advisory HTML URL first (tagged ADVISORY), then
	// any additional references from the references array.
	if u := strings.Clone(feed.StripNullBytes(rec.HTMLURL)); u != "" {
		patch.References = append(patch.References, feed.ReferenceEntry{
			URL:  u,
			Tags: []string{"ADVISORY"},
		})
	}
	for _, ref := range rec.References {
		u := strings.Clone(feed.StripNullBytes(ref.URL))
		if u == "" {
			continue
		}
		patch.References = append(patch.References, feed.ReferenceEntry{URL: u})
	}

	return patch
}
