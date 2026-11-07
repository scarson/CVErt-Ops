// ABOUTME: Feed adapter for the MITRE CVE 5.0 bulk feed (cvelistV5 ZIP from GitHub).
// ABOUTME: Downloads ZIP archive, pre-filters by modified time, parses CVE 5.0 JSON entries in pages.
//
// Cursor format: feed.ArchiveCursor. Between passes it is
// {"last_modified": "2024-01-15T10:00:00Z"}, the download time of the archive
// that began the last completed pass; entries whose FileHeader.Modified is not
// after it are skipped without being opened. During a pass the cursor also holds
// the pass start time and the last entry name read, so a pass larger than one
// worker job continues in the next job.
package mitre

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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

// Adapter implements feed.Adapter for the MITRE CVE bulk feed. One Adapter
// serves one feed run: it keeps the downloaded archive between the pages of the
// run, and Close removes it.
type Adapter struct {
	pager *feed.ArchivePager
}

// New creates a MITRE adapter. The provided http.Client is used for all
// requests. Pass nil to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	return &Adapter{pager: &feed.ArchivePager{
		Client: feed.WrapClientWithUA(client),
		// One archive download per run — a generous limiter as GitHub courtesy.
		RateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
		URL:         bulkZIPURL,
		TempPattern: "cvert-mitre-*.zip",
		SourceName:  SourceName,
		PageSize:    feed.ArchivePageSize,
		IsEntry:     isCVEEntry,
		Parse:       parseEntry,
	}}
}

// Fetch returns the next page of cvelistV5 entries modified after the cursor's
// LastModified, or of every entry on a first run. The first page of a pass, and
// the first page in each later job of the pass, downloads the archive.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	return a.pager.Fetch(ctx, cursorJSON)
}

// Close removes the archive downloaded for this run, if a pass is still open.
func (a *Adapter) Close() error {
	return a.pager.Close()
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

// parseEntry opens a ZIP entry, decodes the CVE 5.0 JSON, and returns a patch.
// Uses explicit rc.Close() — never defer inside a loop body (FD exhaustion).
func parseEntry(entry *zip.File) (*feed.CanonicalPatch, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(rc)
	_ = rc.Close() // explicit close per iteration — NEVER defer inside loop
	if err != nil {
		return nil, err
	}
	patch, err := parseCVE5(bytes.NewReader(raw))
	if err != nil || patch == nil {
		return patch, err
	}
	patch.RawPayload = raw
	return patch, nil
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
	Affected     json.RawMessage   `json:"affected"`
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

// cve5AffectedCPEs reads only the CPE list from an affected[] entry.
// feed.ParseCNAAffected reads the product and version fields from the same array.
type cve5AffectedCPEs struct {
	CPEs []string `json:"cpes"`
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
			Tags: feed.CloneStrings(ref.Tags),
		})
	}

	// CPEs from affected[].cpes (deduplicated by normalized form).
	var affectedCPEs []cve5AffectedCPEs
	if len(cna.Affected) > 0 {
		if err := json.Unmarshal(cna.Affected, &affectedCPEs); err != nil {
			slog.Warn("skipping malformed CNA CPE list", "feed", SourceName, "cve_id", meta.CVEID, "error", err)
		}
	}
	cpeSeen := make(map[string]struct{})
	for _, aff := range affectedCPEs {
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

	// CNA product and version data, as the CNA sent it.
	patch.CNAAffected = feed.ParseCNAAffected(cna.Affected, patch.CVEID)

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
			case m.CVSSV31 != nil && m.CVSSV31.BaseScore >= 0:
				v3 = m.CVSSV31
			case m.CVSSV30 != nil && m.CVSSV30.BaseScore >= 0:
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
		if patch.CVSSv4Score == nil && m.CVSSV40 != nil && m.CVSSV40.BaseScore >= 0 {
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
