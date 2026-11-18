// ABOUTME: Converts a CVE 5 affected[] array into CNAAffected values for the feeds that carry CNA data.
// ABOUTME: The MITRE feed holds the array directly and the NVD feed relays it, in the same CVE 5 shape.
package feed

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

type cve5AffectedEntry struct {
	Vendor        string          `json:"vendor"`
	Product       string          `json:"product"`
	PackageName   string          `json:"packageName"`
	CollectionURL string          `json:"collectionURL"`
	PackageURL    string          `json:"packageURL"`
	DefaultStatus string          `json:"defaultStatus"`
	Versions      json.RawMessage `json:"versions"`
}

type cve5Version struct {
	Version         string              `json:"version"`
	LessThan        string              `json:"lessThan"`
	LessThanOrEqual string              `json:"lessThanOrEqual"`
	Status          string              `json:"status"`
	VersionType     string              `json:"versionType"`
	Changes         []cve5VersionChange `json:"changes"`
}

type cve5VersionChange struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

// ParseCNAAffected converts a raw CVE 5 affected[] array. Malformed data costs
// only the part that is malformed, so the rest of the CVE record still merges.
// An entry whose versions do not decode also loses its default status: that
// status describes versions the list does not mention, so with the list gone it
// would call every version unaffected.
func ParseCNAAffected(raw json.RawMessage, cveID string) []CNAAffected {
	if len(raw) == 0 {
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		slog.Warn("skipping malformed CNA affected array", "cve_id", cveID, "error", err)
		return nil
	}
	var out []CNAAffected
	for _, rawEntry := range entries {
		var e cve5AffectedEntry
		if err := json.Unmarshal(rawEntry, &e); err != nil {
			slog.Warn("skipping malformed CNA affected entry", "cve_id", cveID, "error", err)
			continue
		}
		versions, err := parseCNAVersions(e.Versions)
		defaultStatus := cleanCNAString(e.DefaultStatus)
		if err != nil {
			slog.Warn("skipping malformed CNA versions", "cve_id", cveID, "error", err)
			defaultStatus = ""
		}
		entry := CNAAffected{
			Vendor:        cleanCNAString(e.Vendor),
			Product:       cleanCNAString(e.Product),
			PackageName:   cleanCNAString(e.PackageName),
			CollectionURL: cleanCNAString(e.CollectionURL),
			// Mapped as sent: removing a NUL first could turn a refused URL into
			// another package's identity, and FromPurl refuses control characters.
			PackageKey:    ecosystem.PackageKey(e.PackageURL),
			DefaultStatus: defaultStatus,
			Versions:      versions,
		}
		if entry.Vendor == "" && entry.Product == "" && entry.PackageName == "" && entry.PackageKey == "" && len(entry.Versions) == 0 {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func parseCNAVersions(raw json.RawMessage) ([]CNAVersion, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var versions []cve5Version
	if err := json.Unmarshal(raw, &versions); err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, nil
	}
	out := make([]CNAVersion, 0, len(versions))
	for _, v := range versions {
		version := CNAVersion{
			Version:         cleanCNAString(v.Version),
			LessThan:        cleanCNAString(v.LessThan),
			LessThanOrEqual: cleanCNAString(v.LessThanOrEqual),
			Status:          cleanCNAString(v.Status),
			VersionType:     cleanCNAString(v.VersionType),
		}
		for _, c := range v.Changes {
			version.Changes = append(version.Changes, CNAVersionChange{
				At:     cleanCNAString(c.At),
				Status: cleanCNAString(c.Status),
			})
		}
		out = append(out, version)
	}
	return out, nil
}

// cleanCNAString removes NUL, which Postgres rejects in text and in jsonb even
// when escaped, and detaches the string from the decode buffer.
func cleanCNAString(s string) string {
	return strings.Clone(StripNullBytes(s))
}
