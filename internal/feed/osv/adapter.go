// ABOUTME: Feed adapter for the OSV (Open Source Vulnerabilities) bulk feed.
// ABOUTME: Downloads all.zip from GCS, pre-filters by modified time, resolves CVE aliases.
//
// OSV publishes a single all.zip archive containing all advisories across all
// ecosystems. Each advisory is a JSON file conforming to the OSV schema v1:
// https://ossf.github.io/osv-schema/
//
// Cursor format: feed.ArchiveCursor. Between passes it is
// {"last_modified": "2024-01-15T10:00:00Z"}, and the adapter pre-filters ZIP
// entries via FileHeader.Modified, parsing only entries newer than it. During a
// pass the cursor also holds the latest entry time of the archive the pass
// started on and the last entry name read, so a pass larger than one worker job
// continues in the next job.
//
// all.zip stamps every entry with the same zero MS-DOS time, so the pre-filter
// selects every entry and each pass reads the whole archive.
//
// Alias resolution: if aliases[] contains a CVE ID, it becomes the canonical
// cve_id. The native OSV/GHSA/RUSTSEC ID becomes source_id. The merge pipeline
// performs late-binding PK migration when needed (§3.2).
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
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

// Adapter implements feed.Adapter for the OSV bulk feed. One Adapter serves one
// feed run: it keeps the downloaded archive between the pages of the run, and
// Close removes it.
type Adapter struct {
	pager *feed.ArchivePager
}

// New creates an OSV adapter. Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	return &Adapter{pager: &feed.ArchivePager{
		Client: feed.WrapClientWithUA(client),
		// One bulk archive download per run; 1 req/5s is a generous rate limit.
		RateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
		URL:         bulkZIPURL,
		TempPattern: "cvert-osv-*.zip",
		SourceName:  SourceName,
		PageSize:    feed.ArchivePageSize,
		IsEntry:     isAdvisoryEntry,
		Parse:       parseEntry,
	}}
}

// Fetch returns the next page of advisories modified after the cursor's
// LastModified, or of every advisory on a first run (full backfill). The first
// page of a pass, and the first page in each later job of the pass, downloads
// all.zip.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	return a.pager.Fetch(ctx, cursorJSON)
}

// Close removes the archive downloaded for this run, if a pass is still open.
func (a *Adapter) Close() error {
	return a.pager.Close()
}

// isAdvisoryEntry returns true if the ZIP entry is an OSV advisory JSON file.
// The all.zip structure is: ECOSYSTEM/ADVISORY_ID.json
func isAdvisoryEntry(name string) bool {
	return strings.HasSuffix(name, ".json")
}

// parseEntry opens a ZIP entry, decodes the OSV advisory JSON, and returns a
// patch. Uses explicit rc.Close() — never defer inside a loop body (FD exhaustion).
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
	patch, err := parseAdvisory(bytes.NewReader(raw))
	if err != nil || patch == nil {
		return patch, err
	}
	patch.RawPayload = raw
	return patch, nil
}

// --- OSV advisory JSON types ---

// osvAdvisory represents an OSV schema v1 advisory record.
type osvAdvisory struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Published  string         `json:"published"`
	Modified   string         `json:"modified"`
	Withdrawn  string         `json:"withdrawn"` // non-empty = withdrawn; absent on active advisories
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Affected   []osvAffected  `json:"affected"`
	Severity   []osvSeverity  `json:"severity"`
	References []osvReference `json:"references"`
}

// osvAffected describes a package + version ranges affected by the advisory.
type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
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
			pkgs := extractPackageRanges(eco, pkg, rng)
			patch.AffectedPackages = append(patch.AffectedPackages, pkgs...)
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

// extractPackageRanges converts an OSV range to one or more AffectedPackage entries.
// Each introduced/fixed or introduced/last_affected event pair produces a separate entry.
// Returns nil for ranges with no parseable events.
func extractPackageRanges(ecosystem, pkgName string, rng osvRange) []feed.AffectedPackage {
	rangeType := strings.Clone(feed.StripNullBytes(rng.Type))

	if len(rng.Events) == 0 {
		return nil
	}

	// Parse the events array. Each element is a single-key object:
	// {"introduced": "1.0.0"}, {"fixed": "1.2.3"}, or {"last_affected": "1.2.2"}
	var events []json.RawMessage
	if err := json.Unmarshal(rng.Events, &events); err != nil {
		return nil
	}

	// Walk through events collecting introduced/fixed pairs. Each "introduced"
	// starts a new range; subsequent "fixed" or "last_affected" closes it.
	var result []feed.AffectedPackage
	var introduced string
	for _, ev := range events {
		var obj map[string]string
		if err := json.Unmarshal(ev, &obj); err != nil {
			continue
		}
		if v, ok := obj["introduced"]; ok {
			// If there's a pending introduced without a closing event, flush it.
			if introduced != "" {
				result = append(result, feed.AffectedPackage{
					Ecosystem:   ecosystem,
					PackageName: pkgName,
					RangeType:   rangeType,
					Introduced:  introduced,
					Events:      rng.Events,
				})
			}
			introduced = strings.Clone(feed.StripNullBytes(v))
		}
		if v, ok := obj["fixed"]; ok {
			result = append(result, feed.AffectedPackage{
				Ecosystem:   ecosystem,
				PackageName: pkgName,
				RangeType:   rangeType,
				Introduced:  introduced,
				Fixed:       strings.Clone(feed.StripNullBytes(v)),
				Events:      rng.Events,
			})
			introduced = ""
		}
		if v, ok := obj["last_affected"]; ok {
			result = append(result, feed.AffectedPackage{
				Ecosystem:    ecosystem,
				PackageName:  pkgName,
				RangeType:    rangeType,
				Introduced:   introduced,
				LastAffected: strings.Clone(feed.StripNullBytes(v)),
				Events:       rng.Events,
			})
			introduced = ""
		}
	}
	// Flush trailing introduced with no closing event.
	if introduced != "" {
		result = append(result, feed.AffectedPackage{
			Ecosystem:   ecosystem,
			PackageName: pkgName,
			RangeType:   rangeType,
			Introduced:  introduced,
			Events:      rng.Events,
		})
	}
	return result
}
