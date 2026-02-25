// Package mitre implements the FeedAdapter for the MITRE CVE 5.0 bulk feed.
// The adapter downloads the cvelistV5 ZIP archive from GitHub, streams it to a
// temporary file, and parses each CVE JSON entry.
//
// Cursor format: {"last_modified": "2024-01-15T10:00:00Z"}
// The feed handler persists SourceMeta.FetchedAt as the new cursor value after
// each successful run. On the next run, the cursor is used to pre-filter ZIP
// entries via FileHeader.Modified, skipping unchanged files (~2000× I/O reduction
// for incremental syncs on a 100,000+ entry archive).
package mitre

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
)

const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "mitre"

	// bulkZIPURL is the GitHub archive of the cvelistV5 main branch.
	bulkZIPURL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
)

// Cursor is the JSON-serializable sync state for the MITRE adapter.
// The feed handler stores this in feed_sync_state.cursor_json after each run.
type Cursor struct {
	LastModified time.Time `json:"last_modified"`
}

// Adapter implements feed.FeedAdapter for the MITRE CVE bulk feed.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
}

// New creates a MITRE adapter. The provided http.Client is used for all
// requests. Pass nil to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	// Single-file download per run — use a generous limiter as GitHub courtesy.
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
	}
}

// Fetch downloads the cvelistV5 ZIP, streams it to a temp file, and parses
// all entries modified after the cursor's LastModified timestamp (or all entries
// on the first run when cursor is nil/zero).
//
// MITRE publishes a single flat archive — there is no pagination.
// NextCursor is always nil. The feed handler should save:
//
//	Cursor{LastModified: result.SourceMeta.FetchedAt}
//
// to feed_sync_state.cursor_json after a successful run.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("mitre: parse cursor: %w", err)
		}
	}

	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("mitre: rate limit: %w", err)
	}

	// Stream the ZIP to a temp file — archive/zip.NewReader requires io.ReaderAt.
	tmpFile, err := downloadToTemp(ctx, a.client, bulkZIPURL)
	if err != nil {
		return nil, fmt.Errorf("mitre: download zip: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }() //nolint:gosec // G703: path from os.CreateTemp
	defer tmpFile.Close()                             //nolint:errcheck

	info, err := tmpFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("mitre: stat temp file: %w", err)
	}

	zr, err := zip.NewReader(tmpFile, info.Size())
	if err != nil {
		return nil, fmt.Errorf("mitre: open zip: %w", err)
	}

	fetchedAt := time.Now().UTC()
	var patches []feed.CanonicalPatch

	for _, entry := range zr.File {
		if !isCVEEntry(entry.Name) {
			continue
		}
		// FileHeader.Modified pre-filter: skip unchanged entries on incremental syncs.
		// entry.Modified is embedded from zip.FileHeader and available without
		// opening the entry (no I/O cost).
		if !cur.LastModified.IsZero() && !entry.Modified.After(cur.LastModified) {
			continue
		}

		patch, err := parseEntry(entry)
		if err != nil || patch == nil {
			// Skip malformed or empty entries; do not abort the whole run.
			continue
		}
		patches = append(patches, *patch)
	}

	// Return the new cursor so the handler can persist it to feed_sync_state.
	newCursorJSON, err := json.Marshal(Cursor{LastModified: fetchedAt})
	if err != nil {
		return nil, fmt.Errorf("mitre: marshal cursor: %w", err)
	}

	return &feed.FetchResult{
		Patches: patches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  fetchedAt,
		},
		// Single-archive feed — no pagination, but NextCursor carries the new
		// last-modified timestamp for the handler to persist as the next-run cursor.
		// The handler MUST NOT call Fetch again in a tight loop.
		NextCursor: newCursorJSON,
	}, nil
}

// isCVEEntry returns true if the ZIP entry path is a CVE JSON file.
// The cvelistV5 archive contains paths like:
//
//	cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json
func isCVEEntry(name string) bool {
	return strings.HasSuffix(name, ".json") &&
		strings.Contains(name, "/cves/") &&
		strings.Contains(name, "CVE-")
}

// downloadToTemp streams the HTTP response body to a temp file for ZIP reading.
// The caller must defer os.Remove(f.Name()) and f.Close().
func downloadToTemp(ctx context.Context, client *http.Client, url string) (*os.File, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req) //nolint:gosec // G704: URL is a hardcoded constant
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.CreateTemp("", "cvert-mitre-*.zip")
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp, not user input
		return nil, fmt.Errorf("copy to temp: %w", err)
	}

	// Rewind for zip.NewReader.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp, not user input
		return nil, fmt.Errorf("seek temp file: %w", err)
	}
	return f, nil
}

// parseEntry opens a ZIP entry, decodes the CVE 5.0 JSON, and returns a patch.
// Uses explicit rc.Close() — never defer inside a loop body (FD exhaustion).
func parseEntry(entry *zip.File) (*feed.CanonicalPatch, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	patch, err := parseCVE5(rc)
	_ = rc.Close() // explicit close per iteration — NEVER defer inside loop
	return patch, err
}

// --- CVE 5.0 JSON types ---

type cve5Root struct {
	CVEMetadata cve5Metadata   `json:"cveMetadata"`
	Containers  cve5Containers `json:"containers"`
}

type cve5Metadata struct {
	CVEID         string `json:"cveId"`
	State         string `json:"state"`
	DatePublished string `json:"datePublished"`
	DateUpdated   string `json:"dateUpdated"`
}

type cve5Containers struct {
	CNA cve5CNA   `json:"cna"`
	ADP []cve5ADP `json:"adp"`
}

type cve5CNA struct {
	Descriptions []cve5Description `json:"descriptions"`
	Affected     []cve5Affected    `json:"affected"`
	References   []cve5Reference   `json:"references"`
	ProblemTypes []cve5ProblemType `json:"problemTypes"`
	Metrics      []cve5MetricEntry `json:"metrics"`
}

type cve5ADP struct {
	Metrics []cve5MetricEntry `json:"metrics"`
}

type cve5Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cve5Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type cve5Affected struct {
	CPEs []string `json:"cpes"`
	// Versions is polymorphic across CVE 5.0 history; not parsed into CanonicalPatch.
	Versions json.RawMessage `json:"versions"`
}

type cve5ProblemType struct {
	Descriptions []cve5PTDesc `json:"descriptions"`
}

type cve5PTDesc struct {
	Type  string `json:"type"`
	CWEID string `json:"cweId"`
	Lang  string `json:"lang"`
}

// cve5MetricEntry holds one element of the metrics array.
// Each element is an object with exactly one CVSS version key populated.
type cve5MetricEntry struct {
	CVSSV31 *cve5CVSSv3 `json:"cvssV3_1"`
	CVSSV30 *cve5CVSSv3 `json:"cvssV3_0"`
	CVSSV40 *cve5CVSSv4 `json:"cvssV4_0"`
}

type cve5CVSSv3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type cve5CVSSv4 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

// parseCVE5 decodes a single CVE 5.0 JSON file from r.
func parseCVE5(r io.Reader) (*feed.CanonicalPatch, error) {
	var root cve5Root
	if err := json.NewDecoder(r).Decode(&root); err != nil {
		return nil, err
	}

	meta := root.CVEMetadata
	if meta.CVEID == "" {
		return nil, nil // skip entries without a CVE ID (e.g., delta manifest files)
	}

	patch := &feed.CanonicalPatch{
		CVEID:    strings.Clone(feed.StripNullBytes(meta.CVEID)),
		SourceID: strings.Clone(feed.StripNullBytes(meta.CVEID)),
		Status:   strings.Clone(feed.StripNullBytes(meta.State)),
	}

	if strings.EqualFold(meta.State, "REJECTED") {
		patch.IsWithdrawn = true
	}

	patch.DatePublished = feed.ParseTimePtr(meta.DatePublished)
	patch.DateModified = feed.ParseTimePtr(meta.DateUpdated)

	cna := root.Containers.CNA

	// English description (first match).
	for _, d := range cna.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			s := strings.Clone(feed.StripNullBytes(d.Value))
			patch.DescriptionPrimary = &s
			break
		}
	}

	// CWE IDs from CNA problemTypes (deduplicated).
	seen := make(map[string]struct{})
	for _, pt := range cna.ProblemTypes {
		for _, d := range pt.Descriptions {
			if strings.EqualFold(d.Type, "CWE") && d.CWEID != "" {
				id := strings.Clone(feed.StripNullBytes(d.CWEID))
				if _, ok := seen[id]; !ok {
					seen[id] = struct{}{}
					patch.CWEIDs = append(patch.CWEIDs, id)
				}
			}
		}
	}

	// References.
	for _, ref := range cna.References {
		if ref.URL == "" {
			continue
		}
		patch.References = append(patch.References, feed.ReferenceEntry{
			URL:  strings.Clone(feed.StripNullBytes(ref.URL)),
			Tags: cloneStrings(ref.Tags),
		})
	}

	// CPEs from affected[].cpes (deduplicated by normalized form).
	cpeSeen := make(map[string]struct{})
	for _, aff := range cna.Affected {
		for _, cpeStr := range aff.CPEs {
			normalized := strings.ToLower(strings.Clone(feed.StripNullBytes(cpeStr)))
			if _, ok := cpeSeen[normalized]; ok {
				continue
			}
			cpeSeen[normalized] = struct{}{}
			patch.AffectedCPEs = append(patch.AffectedCPEs, feed.AffectedCPE{
				CPE:           strings.Clone(feed.StripNullBytes(cpeStr)),
				CPENormalized: normalized,
			})
		}
	}

	// CVSS: prefer CNA metrics, fall back to first ADP that has scores.
	applyCVSS(patch, cna.Metrics)
	if patch.CVSSv3Score == nil && patch.CVSSv4Score == nil {
		for _, adp := range root.Containers.ADP {
			applyCVSS(patch, adp.Metrics)
			if patch.CVSSv3Score != nil || patch.CVSSv4Score != nil {
				break
			}
		}
	}

	return patch, nil
}

// applyCVSS sets CVSS v3/v4 fields on patch from the given metrics slice.
// Prefers cvssV3_1 over cvssV3_0; does not overwrite already-set scores.
func applyCVSS(patch *feed.CanonicalPatch, metrics []cve5MetricEntry) {
	for _, m := range metrics {
		if patch.CVSSv3Score == nil {
			var v3 *cve5CVSSv3
			switch {
			case m.CVSSV31 != nil && m.CVSSV31.BaseScore > 0:
				v3 = m.CVSSV31
			case m.CVSSV30 != nil && m.CVSSV30.BaseScore > 0:
				v3 = m.CVSSV30
			}
			if v3 != nil {
				score := v3.BaseScore
				vec := strings.Clone(v3.VectorString)
				sev := strings.ToUpper(strings.Clone(v3.BaseSeverity))
				patch.CVSSv3Score = &score
				patch.CVSSv3Vector = &vec
				if sev != "" {
					patch.Severity = &sev
				}
			}
		}
		if patch.CVSSv4Score == nil && m.CVSSV40 != nil && m.CVSSV40.BaseScore > 0 {
			score := m.CVSSV40.BaseScore
			vec := strings.Clone(m.CVSSV40.VectorString)
			sev := strings.ToUpper(strings.Clone(m.CVSSV40.BaseSeverity))
			patch.CVSSv4Score = &score
			patch.CVSSv4Vector = &vec
			if sev != "" && patch.Severity == nil {
				patch.Severity = &sev
			}
		}
		if patch.CVSSv3Score != nil && patch.CVSSv4Score != nil {
			break
		}
	}
}

// cloneStrings returns a new slice with all strings cloned.
func cloneStrings(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.Clone(s)
	}
	return out
}
