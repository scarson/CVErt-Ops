// ABOUTME: Feed adapter for the NVD (National Vulnerability Database) API 2.0.
// ABOUTME: Fetches CVEs via sliding time windows with streaming JSON parse, converts to CanonicalPatch.
//
// TODO(attribution): NVD notice required in UI per NVD ToU —
// "This product uses the NVD API but is not endorsed or certified by the NVD."
//
// Key implementation requirements (PLAN.md §3.2):
//   - Dynamic rate limiting: 6s/req without NVD_API_KEY, 0.6s/req with key
//   - Auth header: req.Header.Set("apiKey", key) — case-sensitive lowercase 'a'
//   - Timestamp query params via url.Values.Encode() to percent-encode '+' as '%2B'
//   - 15-minute lookback overlap to catch eventual-consistency stragglers
//   - Cursor upper bound from response JSON `timestamp` field (not time.Now())
//   - 120-day window hard limit: chunk time ranges into sequential ≤120-day windows
//   - Per-page cursor (startIndex) persisted so partial-window failures are resumable
//   - Streaming parse: Token()/More() loop on "vulnerabilities" nested array
//   - strings.Clone on all extracted fields from large NVD pages (>5 MB typical)
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
)

const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "nvd"

	// apiURL is the NVD CVE API 2.0 base endpoint.
	apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// resultsPerPage is the NVD maximum page size.
	resultsPerPage = 2000

	// windowMax is the NVD hard limit on date-range query width.
	windowMax = 120 * 24 * time.Hour

	// overlapDuration is the 15-minute lookback to catch eventual-consistency stragglers.
	overlapDuration = 15 * time.Minute

	// nvdEpoch is the earliest date to use when starting a full history backfill.
	// NVD's CVE data begins in 2002.
	nvdEpoch = "2002-01-01"
)

// Cursor is the JSON-serializable sync state for the NVD adapter.
// It persists both the date-window position AND the intra-window page offset
// so that partial-window failures are resumable from the exact page.
type Cursor struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	StartIndex  int       `json:"start_index"`
}

// Adapter implements feed.Adapter for the NVD API 2.0.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	apiKey      string
}

// New creates an NVD adapter. The API key is read from NVD_API_KEY env var.
// Rate limiting is configured accordingly: 6s/req without key, 0.6s/req with key.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	apiKey := os.Getenv("NVD_API_KEY")
	var limiter *rate.Limiter
	if apiKey != "" {
		// 50 requests per 30 seconds = 1 per 0.6s
		limiter = rate.NewLimiter(rate.Every(600*time.Millisecond), 1)
	} else {
		// 5 requests per 30 seconds = 1 per 6s
		limiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
	}
	return &Adapter{
		client:      feed.WrapClientWithUA(client),
		rateLimiter: limiter,
		apiKey:      apiKey,
	}
}

// Fetch fetches one page of CVEs from the NVD API. It uses the cursor to
// determine the current date window and page offset. On each successful page,
// it returns a non-nil NextCursor pointing to the next page or window.
// When all windows up to now are exhausted, NextCursor is a "caught up" cursor
// and LastPage is true.
//
// The ingest handler ends a run on an empty page, and NVD has no modifications in
// its earliest windows, so Fetch walks past empty windows to the next page with
// data. Each request passes through the rate limiter, and the walk ends because
// every window starts later than the one before it.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	cur, err := parseCursor(cursorJSON)
	if err != nil {
		return nil, fmt.Errorf("nvd: parse cursor: %w", err)
	}

	for {
		patches, nextCursor, lastPage, err := a.fetchPage(ctx, cur)
		if err != nil {
			return nil, err
		}
		if len(patches) == 0 && !lastPage {
			cur = *nextCursor
			continue
		}

		nextCursorJSON, err := json.Marshal(nextCursor)
		if err != nil {
			return nil, fmt.Errorf("nvd: marshal next cursor: %w", err)
		}
		return &feed.FetchResult{
			Patches: patches,
			SourceMeta: feed.SourceMeta{
				SourceName: SourceName,
				FetchedAt:  time.Now().UTC(),
			},
			NextCursor: nextCursorJSON,
			LastPage:   lastPage,
		}, nil
	}
}

// fetchPage requests the page cur points at and returns its patches, the cursor
// after it, and whether it is the final page of this run.
func (a *Adapter) fetchPage(ctx context.Context, cur Cursor) ([]feed.CanonicalPatch, *Cursor, bool, error) {
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, nil, false, fmt.Errorf("nvd: rate limit: %w", err)
	}

	resp, nvdTimestamp, err := a.doRequest(ctx, cur)
	if err != nil {
		return nil, nil, false, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck,gosec // drain for connection reuse
		return nil, nil, false, fmt.Errorf("nvd: HTTP %d for window [%s, %s] startIndex=%d",
			resp.StatusCode,
			cur.WindowStart.Format(time.RFC3339),
			cur.WindowEnd.Format(time.RFC3339),
			cur.StartIndex,
		)
	}

	const maxNVDResponseSize = 50 << 20 // 50 MB
	patches, totalResults, responseTimestamp, err := parseNVDResponse(io.LimitReader(resp.Body, maxNVDResponseSize))
	if err != nil {
		return nil, nil, false, fmt.Errorf("nvd: parse response: %w", err)
	}

	// Prefer response-body timestamp over HTTP Date header for clock-skew safety.
	// Fall back to nvdTimestamp (from Date header) then time.Now().
	effectiveNow := responseTimestamp
	if effectiveNow.IsZero() {
		effectiveNow = nvdTimestamp
	}
	if effectiveNow.IsZero() {
		effectiveNow = time.Now().UTC()
	}

	nextCursor, lastPage := computeNextCursor(cur, totalResults, effectiveNow)
	return patches, nextCursor, lastPage, nil
}

// doRequest builds and executes the NVD API request for the given cursor.
// Returns the response, the NVD Date response header (for clock-skew safety),
// and any error.
func (a *Adapter) doRequest(ctx context.Context, cur Cursor) (*http.Response, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("nvd: build request: %w", err)
	}

	// Case-sensitive apiKey header — not "ApiKey", "API-Key", or "X-API-Key".
	if a.apiKey != "" {
		req.Header.Set("apiKey", a.apiKey) //nolint:canonicalheader // NVD requires lowercase 'a'
	}

	// Build query parameters via url.Values to percent-encode '+' as '%2B'.
	// Direct string concatenation sends literal '+' which NVD reads as a space → 400.
	q := req.URL.Query()
	q.Set("resultsPerPage", fmt.Sprintf("%d", resultsPerPage))
	q.Set("startIndex", fmt.Sprintf("%d", cur.StartIndex))

	// Timestamp format: use 'Z' suffix to avoid '+' encoding entirely.
	// NVD docs accept both "+00:00" and "Z" for UTC; 'Z' is simpler and safe.
	if !cur.WindowStart.IsZero() {
		q.Set("lastModStartDate", cur.WindowStart.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	if !cur.WindowEnd.IsZero() {
		q.Set("lastModEndDate", cur.WindowEnd.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	req.URL.RawQuery = q.Encode()

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is a hardcoded constant
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("nvd: request: %w", err)
	}

	// Parse Date response header for clock-skew-safe upper bound.
	var nvdTime time.Time
	if dateStr := resp.Header.Get("Date"); dateStr != "" {
		nvdTime = feed.ParseTime(dateStr)
	}

	return resp, nvdTime, nil
}

// parseCursor decodes cursor JSON or returns a zero-value cursor for the first run.
// A zero-value cursor triggers a full-history backfill starting from nvdEpoch.
func parseCursor(raw json.RawMessage) (Cursor, error) {
	if len(raw) == 0 {
		return zeroValueCursor(), nil
	}
	var cur Cursor
	if err := json.Unmarshal(raw, &cur); err != nil {
		return Cursor{}, err
	}
	if cur.WindowStart.IsZero() {
		return zeroValueCursor(), nil
	}
	return cur, nil
}

// zeroValueCursor creates the initial cursor for a full-history backfill.
func zeroValueCursor() Cursor {
	epoch, _ := time.Parse("2006-01-02", nvdEpoch)
	now := time.Now().UTC()
	windowEnd := epoch.Add(windowMax)
	if windowEnd.After(now) {
		windowEnd = now
	}
	return Cursor{
		WindowStart: epoch,
		WindowEnd:   windowEnd,
		StartIndex:  0,
	}
}

// computeNextCursor determines the cursor for the next Fetch call.
// Returns a "caught up" cursor (not nil) when all windows up to effectiveNow
// have been processed, so the handler always has a valid cursor to persist.
func computeNextCursor(cur Cursor, totalResults int, effectiveNow time.Time) (*Cursor, bool) {
	nextStartIndex := cur.StartIndex + resultsPerPage

	if nextStartIndex < totalResults {
		// More pages in the current window.
		return &Cursor{
			WindowStart: cur.WindowStart,
			WindowEnd:   cur.WindowEnd,
			StartIndex:  nextStartIndex,
		}, false
	}

	// Current window exhausted — compute the next window.
	// Apply 15-minute overlap to catch eventual-consistency stragglers.
	nextWindowStart := cur.WindowEnd.Add(-overlapDuration)
	if effectiveNow.Sub(cur.WindowEnd) <= overlapDuration {
		// All windows processed. effectiveNow advances on every response, so it is
		// usually slightly past WindowEnd here; a further window would only re-read
		// this one. Return a "caught up" cursor so the handler persists a valid
		// checkpoint instead of regressing to the previous page. The next run starts
		// from it, so modifications after WindowEnd are still read.
		return &Cursor{
			WindowStart: cur.WindowEnd.Add(-overlapDuration),
			WindowEnd:   effectiveNow,
			StartIndex:  0,
		}, true
	}

	nextWindowEnd := nextWindowStart.Add(windowMax)
	if nextWindowEnd.After(effectiveNow) {
		nextWindowEnd = effectiveNow
	}

	return &Cursor{
		WindowStart: nextWindowStart,
		WindowEnd:   nextWindowEnd,
		StartIndex:  0,
	}, false
}

// --- NVD response JSON types ---

// nvdMetaFields holds the non-vulnerability fields from the NVD response.
type nvdMetaFields struct {
	TotalResults int    `json:"totalResults"`
	Timestamp    string `json:"timestamp"`
}

// nvdVulnWrapper wraps the per-CVE object in the vulnerabilities array.
type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

// nvdCVE is the per-CVE object in the NVD API 2.0 response.
type nvdCVE struct {
	ID             string           `json:"id"`
	VulnStatus     string           `json:"vulnStatus"`
	Published      string           `json:"published"`
	LastModified   string           `json:"lastModified"`
	Descriptions   []nvdDescription `json:"descriptions"`
	Metrics        nvdMetrics       `json:"metrics"`
	Weaknesses     []nvdWeakness    `json:"weaknesses"`
	Configurations []nvdConfig      `json:"configurations"`
	References     []nvdReference   `json:"references"`
	// SourceIdentifier names the CVE's CNA, which is one of the sources in Affected.
	SourceIdentifier string `json:"sourceIdentifier"`
	// Affected stays raw so that malformed data costs the product data and not
	// the whole CVE: see cnaAffected.
	Affected json.RawMessage `json:"affected,omitempty"`
}

// nvdAffected is one element of cve.affected[]: a source and that source's copy
// of a CVE 5 affected[] array.
type nvdAffected struct {
	Source       string          `json:"source"`
	AffectedData json.RawMessage `json:"affectedData"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// nvdMetrics holds all CVSS metric arrays. NVD may return v3.0, v3.1, and/or v4.0.
// Each is an array; the first element is typically the NVD-assigned score.
type nvdMetrics struct {
	CVSSV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSV40 []nvdCVSSMetric `json:"cvssMetricV40"`
}

type nvdCVSSMetric struct {
	Source   string      `json:"source"`
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// parseNVDResponse streams the NVD API response, collecting patches and metadata.
// It navigates the top-level JSON object via Token() and processes the
// "vulnerabilities" array one record at a time (never buffering the full array).
func parseNVDResponse(body interface{ Read([]byte) (int, error) }) (
	patches []feed.CanonicalPatch,
	totalResults int,
	responseTimestamp time.Time,
	err error,
) {
	dec := json.NewDecoder(body)

	// Consume opening '{'.
	if _, err = dec.Token(); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("opening brace: %w", err)
	}

	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, 0, time.Time{}, fmt.Errorf("read key: %w", err)
		}
		keyStr, ok := key.(string)
		if !ok {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, 0, time.Time{}, fmt.Errorf("discard non-string key value: %w", err)
			}
			continue
		}

		switch keyStr {
		case "totalResults":
			if err := dec.Decode(&totalResults); err != nil {
				return nil, 0, time.Time{}, fmt.Errorf("decode totalResults: %w", err)
			}

		case "timestamp":
			var ts string
			if err := dec.Decode(&ts); err != nil {
				return nil, 0, time.Time{}, fmt.Errorf("decode timestamp: %w", err)
			}
			responseTimestamp = feed.ParseTime(ts)

		case "vulnerabilities":
			// Consume opening '['.
			if _, err := dec.Token(); err != nil {
				return nil, 0, time.Time{}, fmt.Errorf("vulnerabilities '[': %w", err)
			}
			for dec.More() {
				var wrapper nvdVulnWrapper
				if err := dec.Decode(&wrapper); err != nil {
					var syntaxErr *json.SyntaxError
					if errors.As(err, &syntaxErr) {
						slog.Warn("JSON syntax error in feed stream, stopping parse",
							"feed", SourceName, "error", err)
						return patches, totalResults, responseTimestamp, nil
					}
					slog.Warn("skipping malformed record in feed stream",
						"feed", SourceName, "error", err)
					continue
				}
				if p := cveToCanonical(wrapper.CVE); p != nil {
					if rawBytes, err := json.Marshal(wrapper); err == nil {
						p.RawPayload = rawBytes
					}
					patches = append(patches, *p)
				}
			}
			// Consume closing ']'.
			if _, err := dec.Token(); err != nil {
				return nil, 0, time.Time{}, fmt.Errorf("vulnerabilities ']': %w", err)
			}

		default:
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, 0, time.Time{}, fmt.Errorf("discard %q: %w", keyStr, err)
			}
		}
	}

	return patches, totalResults, responseTimestamp, nil
}

// cveToCanonical converts an NVD CVE record to a CanonicalPatch.
// Returns nil for records with no CVE ID.
func cveToCanonical(cve nvdCVE) *feed.CanonicalPatch {
	if cve.ID == "" {
		return nil
	}

	patch := &feed.CanonicalPatch{
		CVEID:    strings.Clone(feed.StripNullBytes(cve.ID)),
		SourceID: strings.Clone(feed.StripNullBytes(cve.ID)),
		Status:   strings.Clone(feed.StripNullBytes(cve.VulnStatus)),
	}

	if strings.EqualFold(cve.VulnStatus, "Rejected") {
		patch.IsWithdrawn = true
	}

	patch.DatePublished = feed.ParseTimePtr(cve.Published)
	patch.DateModified = feed.ParseTimePtr(cve.LastModified)

	// English description (first match).
	for _, d := range cve.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			s := strings.Clone(feed.StripNullBytes(d.Value))
			patch.DescriptionPrimary = &s
			break
		}
	}

	// CWE IDs from weaknesses (deduplicated).
	seen := make(map[string]struct{})
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(strings.ToUpper(d.Value), "CWE-") {
				id := strings.Clone(feed.StripNullBytes(d.Value))
				if _, ok := seen[id]; !ok {
					seen[id] = struct{}{}
					patch.CWEIDs = append(patch.CWEIDs, id)
				}
			}
		}
	}

	// References.
	for _, ref := range cve.References {
		if ref.URL == "" {
			continue
		}
		patch.References = append(patch.References, feed.ReferenceEntry{
			URL:  strings.Clone(feed.StripNullBytes(ref.URL)),
			Tags: feed.CloneStrings(ref.Tags),
		})
	}

	// CPEs from configurations. AffectedCPEs holds each criteria string once and
	// includes vulnerable: false entries, because it is a material_hash input and
	// what CPE watchlist items match. CPEMatches holds every entry with its range.
	cpeSeen := make(map[string]struct{})
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				if match.Criteria == "" {
					continue
				}
				normalized := strings.ToLower(strings.Clone(feed.StripNullBytes(match.Criteria)))
				patch.CPEMatches = append(patch.CPEMatches, feed.CPEMatch{
					CPE:                   strings.Clone(feed.StripNullBytes(match.Criteria)),
					CPENormalized:         normalized,
					VersionStartIncluding: strings.Clone(feed.StripNullBytes(match.VersionStartIncluding)),
					VersionStartExcluding: strings.Clone(feed.StripNullBytes(match.VersionStartExcluding)),
					VersionEndIncluding:   strings.Clone(feed.StripNullBytes(match.VersionEndIncluding)),
					VersionEndExcluding:   strings.Clone(feed.StripNullBytes(match.VersionEndExcluding)),
					Vulnerable:            match.Vulnerable,
				})
				if _, ok := cpeSeen[normalized]; ok {
					continue
				}
				cpeSeen[normalized] = struct{}{}
				patch.AffectedCPEs = append(patch.AffectedCPEs, feed.AffectedCPE{
					CPE:           strings.Clone(feed.StripNullBytes(match.Criteria)),
					CPENormalized: normalized,
				})
			}
		}
	}

	patch.CNAAffected = cnaAffected(cve)

	// CVSS: prefer v3.1 over v3.0; add v4.0 if available.
	// NVD source "nvd@nist.gov" is preferred; use first entry if no NVD source.
	applyNVDCVSS(patch, cve.Metrics)

	return patch
}

// cnaAffected returns the CNA's product and version data that NVD relays in
// cve.affected[], which is present before NVD analyses a CVE. The element whose
// source is the CVE's sourceIdentifier is the CNA's own; other elements come from
// other organisations and are skipped.
func cnaAffected(cve nvdCVE) []feed.CNAAffected {
	if len(cve.Affected) == 0 || cve.SourceIdentifier == "" {
		return nil
	}
	var relayed []nvdAffected
	if err := json.Unmarshal(cve.Affected, &relayed); err != nil {
		slog.Warn("skipping malformed affected array", "feed", SourceName, "cve_id", cve.ID, "error", err)
		return nil
	}
	var entries []feed.CNAAffected
	for _, r := range relayed {
		if r.Source == cve.SourceIdentifier {
			entries = append(entries, feed.ParseCNAAffected(r.AffectedData, cve.ID)...)
		}
	}
	return entries
}

// applyNVDCVSS sets CVSS fields on patch, preferring v3.1 over v3.0 and the
// NVD's own score (source "nvd@nist.gov") over vendor-provided scores.
func applyNVDCVSS(patch *feed.CanonicalPatch, m nvdMetrics) {
	// v3.1 — prefer NVD source, fall back to first entry.
	if len(m.CVSSV31) > 0 && patch.CVSSv3Score == nil {
		entry := pickPreferred(m.CVSSV31)
		if entry != nil {
			score := entry.CVSSData.BaseScore
			vec := strings.Clone(entry.CVSSData.VectorString)
			sev := strings.ToUpper(strings.Clone(entry.CVSSData.BaseSeverity))
			patch.CVSSv3Score = &score
			patch.CVSSv3Vector = &vec
			if sev != "" {
				patch.Severity = &sev
			}
		}
	}
	// v3.0 fallback if no v3.1.
	if len(m.CVSSV30) > 0 && patch.CVSSv3Score == nil {
		entry := pickPreferred(m.CVSSV30)
		if entry != nil {
			score := entry.CVSSData.BaseScore
			vec := strings.Clone(entry.CVSSData.VectorString)
			sev := strings.ToUpper(strings.Clone(entry.CVSSData.BaseSeverity))
			patch.CVSSv3Score = &score
			patch.CVSSv3Vector = &vec
			if sev != "" {
				patch.Severity = &sev
			}
		}
	}
	// v4.0 — always include if present.
	if len(m.CVSSV40) > 0 && patch.CVSSv4Score == nil {
		entry := pickPreferred(m.CVSSV40)
		if entry != nil {
			score := entry.CVSSData.BaseScore
			vec := strings.Clone(entry.CVSSData.VectorString)
			sev := strings.ToUpper(strings.Clone(entry.CVSSData.BaseSeverity))
			patch.CVSSv4Score = &score
			patch.CVSSv4Vector = &vec
			if sev != "" && patch.Severity == nil {
				patch.Severity = &sev
			}
		}
	}
}

// pickPreferred returns the NVD-authored metric entry if present,
// otherwise the first entry in the slice.
func pickPreferred(entries []nvdCVSSMetric) *nvdCVSSMetric {
	for i := range entries {
		if entries[i].Source == "nvd@nist.gov" {
			return &entries[i]
		}
	}
	if len(entries) > 0 {
		return &entries[0]
	}
	return nil
}
