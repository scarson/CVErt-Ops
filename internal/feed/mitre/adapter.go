// ABOUTME: Feed adapter for the MITRE CVE 5.0 bulk feed (cvelistV5 ZIP from GitHub).
// ABOUTME: Walks the records updated since the cursor in pages that resume across jobs, and parses CVE 5.0 JSON.
//
// Every entry in the GitHub archive carries the same modified time, the commit
// time, so a record's cveMetadata.dateUpdated is what shows it changed. A walk
// returns the records updated after Cursor.LastModified in CVE ID order, one
// page per Fetch. Within a job the adapter downloads the archive once and keeps
// it between pages; a later job downloads the then-current archive and resumes
// after Cursor.After.
package mitre

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
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
// The feed handler stores this in feed_sync_state.cursor_json after each page.
type Cursor struct {
	// LastModified selects the records a walk returns: those whose
	// cveMetadata.dateUpdated is after it. The zero time selects every record.
	LastModified time.Time `json:"last_modified"`
	// After is the CVE ID of the last record a walk in progress has returned.
	After string `json:"after,omitempty"`
	// Snapshot is the latest dateUpdated in the archive a walk in progress
	// started on. It is zero when no walk is in progress.
	Snapshot time.Time `json:"snapshot,omitzero"`
}

const (
	// rescanWindow is how far before a walk's Snapshot the next walk starts.
	// dateUpdated is stamped upstream, not when the record reaches the archive,
	// so a record can reach the archive after one with a later dateUpdated. On
	// the real archive about 5 to 50 records a day fall in one hour, and
	// merging them again changes nothing.
	rescanWindow = time.Hour

	// defaultPageSize is the number of records one Fetch returns. At the 13
	// merges a second seen on a real backfill a page takes about 77 seconds,
	// so a job's first page, which also downloads the archive (about 66
	// seconds) and reads every record's dateUpdated (about 27 seconds), still
	// fits within the ingest handler's three-minute page reserve.
	defaultPageSize = 1000
)

// Adapter implements feed.FeedAdapter for the MITRE CVE bulk feed. An Adapter
// serves one job: it keeps the archive it downloads until the walk reaches its
// last page, Close is called, or the context of the downloading Fetch ends.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	pageSize    int
	log         *slog.Logger

	mu      sync.Mutex
	archive *archive
}

// New creates a MITRE adapter. The provided http.Client is used for all
// requests. Pass nil to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	// Single-file download per run — use a generous limiter as GitHub courtesy.
	return &Adapter{
		client:      feed.WrapClientWithUA(client),
		rateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
		pageSize:    defaultPageSize,
		log:         slog.Default(),
	}
}

// Close removes the downloaded archive, if the adapter holds one.
func (a *Adapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseLocked()
}

// releaseLocked removes the held archive. The caller holds a.mu.
func (a *Adapter) releaseLocked() {
	if a.archive != nil {
		a.archive.remove()
		a.archive = nil
	}
}

// Fetch returns the next page of records updated after cursor.LastModified,
// in CVE ID order after cursor.After. A nil cursor starts a walk of every record.
//
// The first page of a walk records the archive's latest dateUpdated as the
// cursor's Snapshot. The last page returns a cursor whose LastModified is that
// Snapshot less rescanWindow. A record that changes after the walk has passed
// it, or a new record that sorts before the walk's position, has a later
// dateUpdated than anything in the archive the walk started on, so the next
// walk returns it.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("mitre: parse cursor: %w", err)
		}
	}
	// A position belongs to a walk; without the walk's Snapshot, start a new one.
	if cur.Snapshot.IsZero() {
		cur.After = ""
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.archive == nil {
		if err := a.download(ctx); err != nil {
			return nil, err
		}
	}
	ar := a.archive
	if !ar.covers(cur) {
		if err := ar.selectRecords(ctx, a.log, cur.LastModified, cur.After); err != nil {
			return nil, fmt.Errorf("mitre: select records: %w", err)
		}
	}
	snapshot := cur.Snapshot
	if snapshot.IsZero() {
		// The selection just read every record in the archive.
		snapshot = ar.latest
	}

	i := ar.firstAfter(cur.After)
	last := cur.After
	patches := make([]feed.CanonicalPatch, 0, min(a.pageSize, len(ar.selected)-i))
	for ; i < len(ar.selected) && len(patches) < a.pageSize; i++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("mitre: read records: %w", err)
		}
		rec := ar.selected[i]
		last = rec.cveID
		patch, err := parseEntry(rec.file)
		if err != nil {
			a.log.WarnContext(ctx, "skipping unreadable CVE record", "feed", SourceName, "entry", rec.file.Name, "error", err)
			continue
		}
		if patch == nil {
			continue
		}
		patches = append(patches, *patch)
	}

	lastPage := i >= len(ar.selected)
	next := Cursor{LastModified: cur.LastModified, After: last, Snapshot: snapshot}
	if lastPage {
		next = Cursor{LastModified: cur.LastModified}
		if !snapshot.IsZero() {
			next.LastModified = snapshot.Add(-rescanWindow)
		}
		a.releaseLocked()
	}
	nextJSON, err := json.Marshal(next)
	if err != nil {
		return nil, fmt.Errorf("mitre: marshal cursor: %w", err)
	}

	return &feed.FetchResult{
		Patches: patches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  time.Now().UTC(),
		},
		NextCursor: nextJSON,
		LastPage:   lastPage,
	}, nil
}

// download fetches the archive to a temp file and holds it until the walk
// ends, Close is called, or ctx ends. The caller holds a.mu.
func (a *Adapter) download(ctx context.Context) error {
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("mitre: rate limit: %w", err)
	}
	// Stream the ZIP to a temp file — archive/zip.NewReader requires io.ReaderAt.
	tmpFile, err := feed.DownloadToTemp(ctx, a.client, bulkZIPURL, "cvert-mitre-*.zip", feed.MaxDownloadSize)
	if err != nil {
		return fmt.Errorf("mitre: download zip: %w", err)
	}
	ar, err := openArchive(tmpFile)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // G703: path from os.CreateTemp
		return fmt.Errorf("mitre: %w", err)
	}
	// The ingest handler does not close adapters; the job context ends with the job.
	ar.stopRelease = context.AfterFunc(ctx, func() { a.releaseArchive(ar) })
	a.archive = ar
	return nil
}

// releaseArchive removes ar if the adapter still holds it.
func (a *Adapter) releaseArchive(ar *archive) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.archive == ar {
		a.releaseLocked()
	}
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
