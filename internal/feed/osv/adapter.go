// ABOUTME: Feed adapter for the OSV (Open Source Vulnerabilities) bucket: all.zip backfill, modified_id.csv increments.
// ABOUTME: Pages both kinds of run so they resume across worker jobs, and resolves CVE aliases.
//
// OSV publishes its data in the osv-vulnerabilities GCS bucket
// (https://google.github.io/osv.dev/data/): all.zip with every advisory across
// all ecosystems, one JSON object per advisory at <ecosystem>/<id>.json, and
// modified_id.csv, which lists "<modified time>,<ecosystem>/<id>" for every
// advisory, newest first. Each advisory conforms to the OSV schema v1:
// https://ossf.github.io/osv-schema/
//
// A first run (zero cursor) is a backfill: it reads all.zip in entry-name
// order, one page per Fetch, downloading the archive once per job. all.zip
// stamps every entry with the same zero MS-DOS time, so its entry times cannot
// say what changed. Later runs therefore read modified_id.csv up to the cursor
// and fetch only the advisories listed as changed. See Cursor for how both
// kinds of run resume.
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
	"fmt"
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

	// bucketURL is the base URL of the osv-vulnerabilities bucket.
	bucketURL = "https://osv-vulnerabilities.storage.googleapis.com/"

	// bulkZIPURL is the OSV GCS all-ecosystems bulk archive.
	bulkZIPURL = bucketURL + "all.zip"

	// modifiedIDsURL lists every advisory as "<modified time>,<ecosystem>/<id>",
	// newest first.
	modifiedIDsURL = bucketURL + "modified_id.csv"
)

// Adapter implements feed.Adapter for the OSV bucket. One Adapter serves one
// feed run: it keeps a downloaded archive between the pages of a backfill, and
// Close removes it.
type Adapter struct {
	client *http.Client
	pager  *feed.ArchivePager
	// listLimiter paces reads of modified_id.csv, one per page.
	listLimiter *rate.Limiter
	// recordLimiter paces single-advisory fetches on an incremental run.
	recordLimiter *rate.Limiter
}

// New creates an OSV adapter. Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	client = feed.WrapClientWithUA(client)
	return &Adapter{
		client: client,
		pager: &feed.ArchivePager{
			Client: client,
			// One bulk archive download per job; 1 req/5s is a generous rate limit.
			RateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			URL:         bulkZIPURL,
			TempPattern: "cvert-osv-*.zip",
			SourceName:  SourceName,
			PageSize:    feed.ArchivePageSize,
			IsEntry:     isAdvisoryEntry,
			Parse:       parseEntry,
		},
		listLimiter: rate.NewLimiter(rate.Every(time.Second), 1),
		// 20 advisories a second fetches a 1,000-advisory page in 50 seconds,
		// faster than the page merges, and is light load on a public bucket.
		recordLimiter: rate.NewLimiter(rate.Every(50*time.Millisecond), 1),
	}
}

// Fetch returns the next page of a backfill when the cursor has no
// LastModified, and the next page of advisories changed since LastModified
// otherwise.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("osv: parse cursor: %w", err)
		}
	}
	var (
		patches []feed.CanonicalPatch
		next    Cursor
		done    bool
		err     error
	)
	if cur.LastModified.IsZero() {
		patches, next, done, err = a.backfillPage(ctx, cur)
	} else {
		patches, next, done, err = a.changesPage(ctx, cur)
	}
	if err != nil {
		return nil, err
	}
	nextJSON, err := json.Marshal(next)
	if err != nil {
		return nil, fmt.Errorf("osv: marshal cursor: %w", err)
	}
	return &feed.FetchResult{
		Patches:    patches,
		SourceMeta: feed.SourceMeta{SourceName: SourceName, FetchedAt: time.Now().UTC()},
		NextCursor: nextJSON,
		LastPage:   done,
	}, nil
}

// Close removes the archive downloaded for this run, if a backfill is still open.
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
	return parseRecord(raw)
}

// parseRecord decodes one advisory's JSON into a patch carrying the raw JSON.
// A nil patch with a nil error means the advisory has no ID.
func parseRecord(raw []byte) (*feed.CanonicalPatch, error) {
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
