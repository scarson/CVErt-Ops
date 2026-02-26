// Package kev implements the FeedAdapter for the CISA Known Exploited
// Vulnerabilities (KEV) catalog.
//
// KEV is a flag-setter: its primary write is in_cisa_kev = true on the canonical
// cves row. Per PLAN.md §5.1, CISA KEV is the authoritative source for the
// exploit-known flag. Description and CVSS data from KEV is stored in cve_sources
// but defers to NVD/MITRE at resolution time.
//
// Cursor format: {"catalog_version": "2024.09.03", "date_released": "..."}
// Short-circuits processing when catalogVersion is unchanged.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
)

const (
	// SourceName is the canonical feed name stored in cve_sources.
	SourceName = "kev"

	// feedURL is the CISA KEV JSON catalog endpoint.
	feedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Cursor is the JSON-serializable sync state for the KEV adapter.
type Cursor struct {
	CatalogVersion string `json:"catalog_version"`
	DateReleased   string `json:"date_released"`
}

// Adapter implements feed.FeedAdapter for the CISA KEV catalog.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
}

// New creates a KEV adapter. Pass nil client to use http.DefaultClient.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	// Daily fetch at most; 1 request per 5 seconds is a generous rate limit.
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
	}
}

// Fetch downloads the KEV catalog and returns CanonicalPatches with
// InCISAKEV = true. Returns an empty Patches slice when catalogVersion
// is unchanged from the stored cursor (nothing new to process).
//
// NextCursor is always nil — KEV is a single-file, non-paginated feed.
// The caller persists Cursor{CatalogVersion, DateReleased} after each run.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("kev: parse cursor: %w", err)
		}
	}

	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("kev: rate limit: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("kev: build request: %w", err)
	}
	req.Header.Set("User-Agent", "CVErt-Ops/1.0 vulnerability intelligence platform")

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is a hardcoded constant
	if err != nil {
		return nil, fmt.Errorf("kev: fetch: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: HTTP %d", resp.StatusCode)
	}

	fetchedAt := time.Now().UTC()

	patches, newCatalogVersion, newDateReleased, err := parseKEV(resp.Body, cur.CatalogVersion)
	if err != nil {
		return nil, fmt.Errorf("kev: parse feed: %w", err)
	}

	// Marshal the new cursor so the handler can persist it to feed_sync_state.
	// We always return a non-nil NextCursor for KEV so the handler knows what to save;
	// the caller must not call Fetch again immediately — it re-enqueues via scheduling.
	nextCursor := Cursor{
		CatalogVersion: newCatalogVersion,
		DateReleased:   newDateReleased,
	}
	nextCursorJSON, err := json.Marshal(nextCursor)
	if err != nil {
		return nil, fmt.Errorf("kev: marshal cursor: %w", err)
	}

	return &feed.FetchResult{
		Patches: patches,
		SourceMeta: feed.SourceMeta{
			SourceName: SourceName,
			FetchedAt:  fetchedAt,
		},
		// Single-file feed — no pagination, but NextCursor carries the new catalog
		// version for the handler to persist as the next-run cursor. The handler
		// MUST NOT call Fetch again in a tight loop; re-invocation is via scheduling.
		NextCursor: nextCursorJSON,
	}, nil
}

// kevRecord represents a single KEV catalog entry.
type kevRecord struct {
	CVEID                      string          `json:"cveID"`
	VendorProject              string          `json:"vendorProject"`
	Product                    string          `json:"product"`
	VulnerabilityName          string          `json:"vulnerabilityName"`
	DateAdded                  string          `json:"dateAdded"`
	ShortDescription           string          `json:"shortDescription"`
	RequiredAction             string          `json:"requiredAction"`
	DueDate                    string          `json:"dueDate"`
	KnownRansomwareCampaignUse string          `json:"knownRansomwareCampaignUse"`
	Notes                      string          `json:"notes"`
	CWEs                       json.RawMessage `json:"cwes"` // absent, null, or []string
}

// parseKEV streams the KEV JSON feed, returns patches and the catalog metadata.
// If storedVersion matches the incoming catalogVersion, returns nil patches
// (short-circuit: nothing changed).
//
//nolint:cyclop // streaming JSON navigation is inherently branchy
func parseKEV(body interface{ Read([]byte) (int, error) }, storedVersion string) (
	patches []feed.CanonicalPatch,
	catalogVersion string,
	dateReleased string,
	err error,
) {
	dec := json.NewDecoder(body)

	// The top-level structure is a JSON object. Navigate it by consuming tokens
	// looking for the keys we need.
	//
	// Order of keys in the CISA feed:
	//   title, catalogVersion, dateReleased, count, vulnerabilities
	//
	// We must handle them in streaming order; do not assume key order.

	// Consume opening '{'
	if _, err = dec.Token(); err != nil {
		return nil, "", "", fmt.Errorf("consume opening brace: %w", err)
	}

	var (
		inVulnArray bool
		gotVersion  bool
		gotReleased bool
	)

	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, "", "", fmt.Errorf("read key token: %w", err)
		}

		keyStr, ok := key.(string)
		if !ok {
			// Non-string key — consume the value and continue.
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, "", "", fmt.Errorf("discard value: %w", err)
			}
			continue
		}

		switch keyStr {
		case "catalogVersion":
			if err := dec.Decode(&catalogVersion); err != nil {
				return nil, "", "", fmt.Errorf("decode catalogVersion: %w", err)
			}
			gotVersion = true

		case "dateReleased":
			if err := dec.Decode(&dateReleased); err != nil {
				return nil, "", "", fmt.Errorf("decode dateReleased: %w", err)
			}
			gotReleased = true

		case "vulnerabilities":
			inVulnArray = true
			// Consume opening '['.
			if _, err := dec.Token(); err != nil {
				return nil, "", "", fmt.Errorf("consume vulnerabilities '[': %w", err)
			}

			// Short-circuit: if catalogVersion matched and we already have it,
			// skip the array. Otherwise stream records.
			if gotVersion && catalogVersion == storedVersion {
				// Drain the array tokens so the decoder doesn't break.
				var discard json.RawMessage
				for dec.More() {
					if err := dec.Decode(&discard); err != nil {
						return nil, "", "", fmt.Errorf("drain skipped array: %w", err)
					}
				}
			} else {
				for dec.More() {
					var rec kevRecord
					if err := dec.Decode(&rec); err != nil {
						return nil, "", "", fmt.Errorf("decode record: %w", err)
					}
					if p := recordToPatch(rec); p != nil {
						patches = append(patches, *p)
					}
				}
			}

			// Consume closing ']'.
			if _, err := dec.Token(); err != nil {
				return nil, "", "", fmt.Errorf("consume vulnerabilities ']': %w", err)
			}
			_ = inVulnArray // mark navigated

		default:
			// Unknown key: discard value.
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, "", "", fmt.Errorf("discard unknown key %q: %w", keyStr, err)
			}
		}
	}

	_ = gotVersion
	_ = gotReleased

	return patches, catalogVersion, dateReleased, nil
}

// recordToPatch converts a KEV record to a CanonicalPatch.
func recordToPatch(rec kevRecord) *feed.CanonicalPatch {
	if rec.CVEID == "" {
		return nil
	}

	cveID := strings.Clone(feed.StripNullBytes(rec.CVEID))
	kevTrue := true

	patch := &feed.CanonicalPatch{
		CVEID:        cveID,
		SourceID:     cveID,
		InCISAKEV:    &kevTrue,
		ExploitAvailable: &kevTrue, // KEV entries have known exploits
	}

	// DatePublished from KEV's dateAdded (best available published date for KEV-only CVEs).
	if t := feed.ParseTimePtr(rec.DateAdded); t != nil {
		patch.DatePublished = t
		patch.DateModified = t
	}

	// Description: shortDescription may be empty on older records.
	if desc := strings.Clone(feed.StripNullBytes(rec.ShortDescription)); desc != "" {
		patch.DescriptionPrimary = &desc
	}

	// CWE IDs from the cwes field (absent on pre-2023 entries, null-safe).
	patch.CWEIDs = extractCWEs(rec.CWEs)

	return patch
}

// extractCWEs parses the polymorphic cwes field.
// The field may be absent (nil raw message), null, or []string.
func extractCWEs(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if cleaned := strings.Clone(feed.StripNullBytes(id)); cleaned != "" {
			out = append(out, cleaned)
		}
	}
	return out
}
