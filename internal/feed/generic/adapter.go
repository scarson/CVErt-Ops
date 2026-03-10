// ABOUTME: Config-driven generic feed adapter implementing feed.Adapter.
// ABOUTME: Fetches JSON/CSAF from configurable URLs with gjson field mapping, pagination, and auth.
package generic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/csaf"
)

// maxResponseSize caps body reads to prevent OOM from malicious/oversized responses.
const maxResponseSize = 50 << 20 // 50 MB

// linkNextRe extracts the URL from a Link header with rel="next".
var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// cursor tracks pagination state between Fetch calls.
type cursor struct {
	// Page is the 1-based page number for offset pagination.
	Page int `json:"page,omitempty"`
	// CursorValue is the opaque cursor string for cursor pagination.
	CursorValue string `json:"cursor_value,omitempty"`
	// NextURL is the absolute URL for link-header pagination.
	NextURL string `json:"next_url,omitempty"`
}

// Adapter implements feed.Adapter for config-driven generic feeds.
type Adapter struct {
	cfg         *Config
	client      *http.Client
	rateLimiter *rate.Limiter
}

// NewAdapter creates a generic feed adapter from a parsed config.
// Pass nil client to use a default client with the configured timeout.
func NewAdapter(cfg *Config, client *http.Client) *Adapter {
	timeout := 30 * time.Second
	if d, err := time.ParseDuration(cfg.Timeout); err == nil && d > 0 {
		timeout = d
	}

	if client == nil {
		client = &http.Client{Timeout: timeout}
	} else {
		// Shallow copy to avoid mutating the caller's client.
		c := *client
		if c.Timeout == 0 {
			c.Timeout = timeout
		}
		client = &c
	}

	rl := float64(1)
	if cfg.RateLimit > 0 {
		rl = cfg.RateLimit
	}

	return &Adapter{
		cfg:         cfg,
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Limit(rl), 1),
	}
}

// SourceName returns the config name, used as the source identifier in merge.Ingest.
func (a *Adapter) SourceName() string {
	return a.cfg.Name
}

// Fetch retrieves one page of CVE data from the configured URL. It implements
// feed.Adapter. The cursor encodes pagination state; pass nil for the first page.
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	if a.cfg.Format == "csaf" {
		return a.fetchCSAF(ctx)
	}
	return a.fetchJSON(ctx, cursorJSON)
}

func (a *Adapter) fetchJSON(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
	var cur cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("generic %s: parse cursor: %w", a.cfg.Name, err)
		}
	}

	// Wait for rate limiter.
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("generic %s: rate limit: %w", a.cfg.Name, err)
	}

	// Build request URL with pagination params.
	reqURL := a.buildURL(&cur)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("generic %s: build request: %w", a.cfg.Name, err)
	}
	a.applyAuth(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic %s: fetch: %w", a.cfg.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("generic %s: HTTP %d from %s", a.cfg.Name, resp.StatusCode, reqURL)
	}

	// Reject non-JSON responses early to avoid silent parse failures.
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "json") {
		return nil, fmt.Errorf("generic %s: unexpected content-type %q from %s", a.cfg.Name, ct, reqURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("generic %s: read body: %w", a.cfg.Name, err)
	}

	// Extract the array of records using the configured gjson root path.
	rootResult := gjson.GetBytes(body, a.cfg.Mapping.Root)
	if !rootResult.Exists() || !rootResult.IsArray() {
		// Empty/missing array is not an error — just no results.
		nextCur, _ := json.Marshal(cur)
		return &feed.FetchResult{
			Patches:    nil,
			SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
			NextCursor: nextCur,
			LastPage:   true,
		}, nil
	}

	var patches []feed.CanonicalPatch
	rootResult.ForEach(func(_, record gjson.Result) bool {
		p := a.mapRecord(record)
		if p.CVEID != "" {
			patches = append(patches, p)
		}
		return true
	})

	// Determine pagination state.
	lastPage, nextCur := a.nextPage(body, resp.Header, &cur, len(patches))

	nextCurJSON, _ := json.Marshal(nextCur)
	return &feed.FetchResult{
		Patches:    patches,
		SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
		NextCursor: nextCurJSON,
		LastPage:   lastPage,
	}, nil
}

// buildURL constructs the request URL with pagination query parameters.
func (a *Adapter) buildURL(cur *cursor) string {
	switch a.cfg.Pagination.Type {
	case "link-header":
		if cur.NextURL != "" {
			return cur.NextURL
		}
		return a.cfg.URL

	case "offset":
		page := cur.Page
		if page == 0 {
			page = 1
		}
		sep := "?"
		if strings.Contains(a.cfg.URL, "?") {
			sep = "&"
		}
		u := a.cfg.URL
		if a.cfg.Pagination.PageParam != "" {
			u += fmt.Sprintf("%s%s=%d", sep, a.cfg.Pagination.PageParam, page)
			sep = "&"
		}
		if a.cfg.Pagination.SizeParam != "" && a.cfg.Pagination.PageSize > 0 {
			u += fmt.Sprintf("%s%s=%d", sep, a.cfg.Pagination.SizeParam, a.cfg.Pagination.PageSize)
		}
		return u

	case "cursor":
		if cur.CursorValue == "" {
			return a.cfg.URL
		}
		sep := "?"
		if strings.Contains(a.cfg.URL, "?") {
			sep = "&"
		}
		return a.cfg.URL + fmt.Sprintf("%s%s=%s", sep, a.cfg.Pagination.CursorParam, cur.CursorValue)

	default:
		return a.cfg.URL
	}
}

// nextPage computes whether this is the last page and the cursor for the next Fetch call.
func (a *Adapter) nextPage(body []byte, headers http.Header, cur *cursor, patchCount int) (lastPage bool, next cursor) {
	switch a.cfg.Pagination.Type {
	case "offset":
		next.Page = cur.Page + 1
		if next.Page <= 1 {
			next.Page = 2
		}
		// Last page when result count < page_size.
		if a.cfg.Pagination.PageSize > 0 && patchCount < a.cfg.Pagination.PageSize {
			return true, next
		}
		return false, next

	case "cursor":
		nextVal := gjson.GetBytes(body, a.cfg.Pagination.CursorPath).String()
		if nextVal == "" {
			return true, cursor{}
		}
		return false, cursor{CursorValue: nextVal}

	case "link-header":
		link := headers.Get("Link")
		if m := linkNextRe.FindStringSubmatch(link); len(m) > 1 {
			return false, cursor{NextURL: m[1]}
		}
		return true, cursor{}

	default:
		// "none" or unset — single request.
		return true, cursor{}
	}
}

// mapRecord converts a single gjson Result (one array element) to a CanonicalPatch.
func (a *Adapter) mapRecord(record gjson.Result) feed.CanonicalPatch {
	raw := record.Raw
	p := feed.CanonicalPatch{
		CVEID: sanitizeString(gjson.Get(raw, a.cfg.Mapping.Fields["cve_id"]).String()),
	}

	if path, ok := a.cfg.Mapping.Fields["description"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			s := sanitizeString(v.String())
			p.DescriptionPrimary = &s
		}
	}

	if path, ok := a.cfg.Mapping.Fields["severity"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			s := sanitizeString(v.String())
			p.Severity = &s
		}
	}

	if path, ok := a.cfg.Mapping.Fields["cvss_v3_score"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			f := v.Float()
			p.CVSSv3Score = &f
		}
	}

	if path, ok := a.cfg.Mapping.Fields["cvss_v3_vector"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			s := sanitizeString(v.String())
			p.CVSSv3Vector = &s
		}
	}

	if path, ok := a.cfg.Mapping.Fields["cvss_v4_score"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			f := v.Float()
			p.CVSSv4Score = &f
		}
	}

	if path, ok := a.cfg.Mapping.Fields["cvss_v4_vector"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			s := sanitizeString(v.String())
			p.CVSSv4Vector = &s
		}
	}

	if path, ok := a.cfg.Mapping.Fields["date_published"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			if t := parseTime(v.String()); t != nil {
				p.DatePublished = t
			}
		}
	}

	if path, ok := a.cfg.Mapping.Fields["date_modified"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			if t := parseTime(v.String()); t != nil {
				p.DateModified = t
			}
		}
	}

	if path, ok := a.cfg.Mapping.Fields["references"]; ok {
		if v := gjson.Get(raw, path); v.Exists() && v.IsArray() {
			v.ForEach(func(_, item gjson.Result) bool {
				url := sanitizeString(item.String())
				if url != "" {
					p.References = append(p.References, feed.ReferenceEntry{URL: url})
				}
				return true
			})
		}
	}

	if path, ok := a.cfg.Mapping.Fields["raw_payload"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			rp := json.RawMessage(v.Raw)
			p.RawPayload = rp
		}
	}

	return p
}

// applyAuth sets authentication headers on the request based on config.
func (a *Adapter) applyAuth(req *http.Request) {
	switch a.cfg.Auth.Type {
	case "bearer":
		token := os.Getenv(a.cfg.Auth.TokenEnv)
		if token == "" {
			if a.cfg.Auth.TokenEnv != "" {
				slog.Warn("generic feed: auth env var not set, sending request without auth",
					"feed", a.cfg.Name, "env_var", a.cfg.Auth.TokenEnv)
			}
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)

	case "basic":
		user := os.Getenv(a.cfg.Auth.UsernameEnv)
		pass := os.Getenv(a.cfg.Auth.PasswordEnv)
		if user == "" && pass == "" {
			slog.Warn("generic feed: auth env vars not set, sending request without auth",
				"feed", a.cfg.Name)
			return
		}
		req.SetBasicAuth(user, pass)

	case "header":
		value := os.Getenv(a.cfg.Auth.HeaderValueEnv)
		if value == "" {
			if a.cfg.Auth.HeaderValueEnv != "" {
				slog.Warn("generic feed: auth env var not set, sending request without auth",
					"feed", a.cfg.Name, "env_var", a.cfg.Auth.HeaderValueEnv)
			}
			return
		}
		req.Header.Set(a.cfg.Auth.HeaderName, value)
	}
}

// fetchCSAF fetches a CSAF document and converts it to CanonicalPatches using
// the shared CSAF parser (reused from the MSRC adapter).
func (a *Adapter) fetchCSAF(ctx context.Context) (*feed.FetchResult, error) {
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("generic %s: rate limit: %w", a.cfg.Name, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("generic %s: build request: %w", a.cfg.Name, err)
	}
	a.applyAuth(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic %s: fetch: %w", a.cfg.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("generic %s: HTTP %d", a.cfg.Name, resp.StatusCode)
	}

	doc, err := csaf.Parse(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("generic %s: parse CSAF: %w", a.cfg.Name, err)
	}

	patches := csafToPatches(doc)
	cursorJSON, _ := json.Marshal(cursor{})

	return &feed.FetchResult{
		Patches:    patches,
		SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
		NextCursor: cursorJSON,
		LastPage:   true, // CSAF is always single-document.
	}, nil
}

// csafToPatches converts a parsed CSAF document to CanonicalPatch values.
func csafToPatches(doc *csaf.Document) []feed.CanonicalPatch {
	var patches []feed.CanonicalPatch
	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE == "" {
			continue
		}
		p := feed.CanonicalPatch{CVEID: vuln.CVE}

		// Description from notes.
		for _, note := range vuln.Notes {
			if note.Type == "description" || note.Type == "summary" {
				desc := sanitizeString(note.Text)
				p.DescriptionPrimary = &desc
				break
			}
		}

		// CVSS scores.
		if len(vuln.Scores) > 0 {
			s := vuln.Scores[0]
			if s.CVSSv3 != nil {
				score := s.CVSSv3.BaseScore
				p.CVSSv3Score = &score
				vec := s.CVSSv3.VectorString
				if vec != "" {
					p.CVSSv3Vector = &vec
				}
			}
			if s.CVSSv4 != nil {
				score := s.CVSSv4.BaseScore
				p.CVSSv4Score = &score
				vec := s.CVSSv4.VectorString
				if vec != "" {
					p.CVSSv4Vector = &vec
				}
			}
		}

		// References.
		for _, ref := range vuln.References {
			if ref.URL != "" {
				p.References = append(p.References, feed.ReferenceEntry{URL: ref.URL})
			}
		}

		// Dates from tracking.
		if doc.DocumentMeta.Tracking.InitialReleaseDate != "" {
			if t := parseTime(doc.DocumentMeta.Tracking.InitialReleaseDate); t != nil {
				p.DatePublished = t
			}
		}
		if doc.DocumentMeta.Tracking.CurrentReleaseDate != "" {
			if t := parseTime(doc.DocumentMeta.Tracking.CurrentReleaseDate); t != nil {
				p.DateModified = t
			}
		}

		// Raw payload: the whole vulnerability JSON.
		if raw, err := json.Marshal(vuln); err == nil {
			p.RawPayload = raw
		}

		patches = append(patches, p)
	}
	return patches
}

// sanitizeString removes null bytes from a string (Postgres TEXT rejects \x00).
func sanitizeString(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// parseTime attempts to parse a time string using common formats.
func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Sanitize null bytes from timestamps too.
	s = sanitizeString(s)

	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return &t
		}
	}
	return nil
}

// ensure Adapter implements feed.Adapter.
var _ feed.Adapter = (*Adapter)(nil)
