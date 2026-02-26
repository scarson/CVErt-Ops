// Package osv implements the FeedAdapter for the OSV (Open Source
// Vulnerabilities) bulk feed from the Google Cloud Storage bucket.
//
// OSV publishes a single all.zip archive containing all advisories across all
// ecosystems. Each advisory is a JSON file conforming to the OSV schema v1:
// https://ossf.github.io/osv-schema/
//
// Cursor format: {"last_modified": "2024-01-15T10:00:00Z"}
// The adapter pre-filters ZIP entries via FileHeader.Modified and only parses
// entries newer than the cursor (same pattern as the MITRE adapter).
//
// Alias resolution: if aliases[] contains a CVE ID, it becomes the canonical
// cve_id. The native OSV/GHSA/RUSTSEC ID becomes source_id. The merge pipeline
// performs late-binding PK migration when needed (§3.2).
package osv

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
	SourceName = "osv"

	// bulkZIPURL is the OSV GCS all-ecosystems bulk archive.
	bulkZIPURL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
)

// Cursor is the JSON-serializable sync state for the OSV adapter.
type Cursor struct {
	LastModified time.Time `json:"last_modified"`
}

// Adapter implements feed.Adapter for the OSV bulk feed.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
}

// New creates an OSV adapter. Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	// Single bulk archive per run; 1 req/5s is a generous rate limit.
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
	}
}

// Fetch downloads the OSV all.zip, streams it to a temp file, and parses all
// advisory entries modified after the cursor's LastModified timestamp.
// On the first run (nil/zero cursor) all entries are parsed (full backfill).
//
// NextCursor carries the new last-modified timestamp for the handler to persist.
// The handler MUST NOT call Fetch again in a tight loop — re-invocation is via
// scheduling.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("osv: parse cursor: %w", err)
		}
	}

	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("osv: rate limit: %w", err)
	}

	tmpFile, err := downloadToTemp(ctx, a.client, bulkZIPURL)
	if err != nil {
		return nil, fmt.Errorf("osv: download zip: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }() //nolint:gosec // G703: path from os.CreateTemp
	defer tmpFile.Close()                             //nolint:errcheck

	info, err := tmpFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("osv: stat temp file: %w", err)
	}

	zr, err := zip.NewReader(tmpFile, info.Size())
	if err != nil {
		return nil, fmt.Errorf("osv: open zip: %w", err)
	}

	fetchedAt := time.Now().UTC()
	var patches []feed.CanonicalPatch

	for _, entry := range zr.File {
		if !isAdvisoryEntry(entry.Name) {
			continue
		}
		// FileHeader.Modified pre-filter: skip unchanged entries on incremental syncs.
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

	newCursorJSON, err := json.Marshal(Cursor{LastModified: fetchedAt})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal cursor: %w", err)
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

// isAdvisoryEntry returns true if the ZIP entry is an OSV advisory JSON file.
// The all.zip structure is: ECOSYSTEM/ADVISORY_ID.json
func isAdvisoryEntry(name string) bool {
	return strings.HasSuffix(name, ".json")
}

// downloadToTemp streams an HTTP response body to a temp file for ZIP reading.
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

	f, err := os.CreateTemp("", "cvert-osv-*.zip")
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

// parseEntry opens a ZIP entry, decodes the OSV advisory JSON, and returns a
// patch. Uses explicit rc.Close() — never defer inside a loop body (FD exhaustion).
func parseEntry(entry *zip.File) (*feed.CanonicalPatch, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	patch, err := parseAdvisory(rc)
	_ = rc.Close() // explicit close per iteration — NEVER defer inside loop
	return patch, err
}

// --- OSV advisory JSON types ---

// osvAdvisory represents an OSV schema v1 advisory record.
type osvAdvisory struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Published string          `json:"published"`
	Modified  string          `json:"modified"`
	Withdrawn string          `json:"withdrawn"` // non-empty = withdrawn; absent on active advisories
	Summary   string          `json:"summary"`
	Details   string          `json:"details"`
	Affected  []osvAffected   `json:"affected"`
	Severity  []osvSeverity   `json:"severity"`
	References []osvReference `json:"references"`
}

// osvAffected describes a package + version ranges affected by the advisory.
type osvAffected struct {
	Package osvPackage        `json:"package"`
	Ranges  []osvRange        `json:"ranges"`
	// Versions is a flat list of affected versions (string slice or similar).
	// Not mapped to CanonicalPatch; range-based data is preferred.
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvRange describes version ranges. The `type` determines the range semantics
// (SEMVER, ECOSYSTEM, GIT). Events is a raw JSON array because each element
// is a single-key object ({introduced}, {fixed}, or {last_affected}).
type osvRange struct {
	Type   string          `json:"type"`
	Events json.RawMessage `json:"events"` // polymorphic per event type
}

// osvSeverity holds a CVSS score entry. The `score` field is the full CVSS
// vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
// OSV does not provide a separate numeric base score — it is encoded in the
// vector and computed by the consumer. We store the vector and leave the
// numeric score nil; NVD/MITRE provide the authoritative numeric scores.
type osvSeverity struct {
	Type  string `json:"type"`  // "CVSS_V3", "CVSS_V4", "CVSS_V2"
	Score string `json:"score"` // full CVSS vector string
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// parseAdvisory decodes a single OSV advisory JSON file from r.
func parseAdvisory(r io.Reader) (*feed.CanonicalPatch, error) {
	var adv osvAdvisory
	if err := json.NewDecoder(r).Decode(&adv); err != nil {
		return nil, err
	}

	nativeID := strings.Clone(feed.StripNullBytes(adv.ID))
	if nativeID == "" {
		return nil, nil // skip entries without an ID
	}

	// Alias resolution: if aliases contains a CVE ID, use it as the canonical
	// primary key. The native advisory ID becomes source_id. The merge pipeline
	// will perform late-binding PK migration if necessary (§3.2).
	aliases := make([]string, 0, len(adv.Aliases))
	for _, a := range adv.Aliases {
		aliases = append(aliases, strings.Clone(feed.StripNullBytes(a)))
	}
	canonicalID := feed.ResolveCanonicalID(nativeID, aliases)

	patch := &feed.CanonicalPatch{
		CVEID:    canonicalID,
		SourceID: nativeID, // always the native OSV ID (GHSA-xxx, RUSTSEC-xxx, etc.)
	}

	// Withdrawn: non-empty withdrawn field → tombstone.
	// Also set Status so cves.status reflects withdrawal when OSV is the sole source.
	// The merge pipeline's TombstoneCVE step NULLs out all CVSS/EPSS scores when
	// IsWithdrawn is true — IsWithdrawn is the canonical tombstone signal.
	if adv.Withdrawn != "" {
		patch.IsWithdrawn = true
		patch.Status = "withdrawn"
	}

	patch.DatePublished = feed.ParseTimePtr(adv.Published)
	patch.DateModified = feed.ParseTimePtr(adv.Modified)

	// Description: prefer details (longer) over summary.
	desc := strings.Clone(feed.StripNullBytes(adv.Details))
	if desc == "" {
		desc = strings.Clone(feed.StripNullBytes(adv.Summary))
	}
	if desc != "" {
		patch.DescriptionPrimary = &desc
	}

	// Affected packages — extract from each affected[].ranges[] entry.
	for _, aff := range adv.Affected {
		eco := strings.Clone(feed.StripNullBytes(aff.Package.Ecosystem))
		pkg := strings.Clone(feed.StripNullBytes(aff.Package.Name))
		if eco == "" || pkg == "" {
			continue
		}
		for _, rng := range aff.Ranges {
			p := extractPackageRange(eco, pkg, rng)
			if p != nil {
				patch.AffectedPackages = append(patch.AffectedPackages, *p)
			}
		}
	}

	// CVSS vectors from severity[]. OSV provides the vector string only; no
	// numeric score. Store the vector for completeness; NVD/MITRE provide scores.
	for _, sev := range adv.Severity {
		vec := strings.Clone(feed.StripNullBytes(sev.Score))
		if vec == "" {
			continue
		}
		switch strings.ToUpper(sev.Type) {
		case "CVSS_V3":
			if patch.CVSSv3Vector == nil {
				patch.CVSSv3Vector = &vec
			}
		case "CVSS_V4":
			if patch.CVSSv4Vector == nil {
				patch.CVSSv4Vector = &vec
			}
		}
	}

	// References.
	for _, ref := range adv.References {
		if ref.URL == "" {
			continue
		}
		url := strings.Clone(feed.StripNullBytes(ref.URL))
		var tags []string
		if t := strings.Clone(feed.StripNullBytes(ref.Type)); t != "" {
			tags = []string{t}
		}
		patch.References = append(patch.References, feed.ReferenceEntry{
			URL:  url,
			Tags: tags,
		})
	}

	return patch, nil
}

// extractPackageRange converts an OSV range to an AffectedPackage.
// Returns nil for range types that don't map to package version ranges
// (e.g., GIT ranges with commit hashes only).
func extractPackageRange(ecosystem, pkgName string, rng osvRange) *feed.AffectedPackage {
	rangeType := strings.Clone(feed.StripNullBytes(rng.Type))

	// Parse the events array. Each element is a single-key object:
	// {"introduced": "1.0.0"}, {"fixed": "1.2.3"}, or {"last_affected": "1.2.2"}
	var introduced, fixed, lastAffected string
	if len(rng.Events) > 0 {
		var events []json.RawMessage
		if err := json.Unmarshal(rng.Events, &events); err == nil {
			for _, ev := range events {
				var obj map[string]string
				if err := json.Unmarshal(ev, &obj); err != nil {
					continue
				}
				if v, ok := obj["introduced"]; ok {
					introduced = strings.Clone(feed.StripNullBytes(v))
				}
				if v, ok := obj["fixed"]; ok {
					fixed = strings.Clone(feed.StripNullBytes(v))
				}
				if v, ok := obj["last_affected"]; ok {
					lastAffected = strings.Clone(feed.StripNullBytes(v))
				}
			}
		}
	}

	return &feed.AffectedPackage{
		Ecosystem:    ecosystem,
		PackageName:  pkgName,
		RangeType:    rangeType,
		Introduced:   introduced,
		Fixed:        fixed,
		LastAffected: lastAffected,
		Events:       rng.Events, // preserve raw events for completeness
	}
}
