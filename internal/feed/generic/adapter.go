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
	"net/url"
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

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL from admin-configured feed YAML, not user input
	if err != nil {
		return nil, fmt.Errorf("generic %s: fetch: %w", a.cfg.Name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("generic %s: HTTP %d from %s", a.cfg.Name, resp.StatusCode, reqURL)
	}

	// Reject non-JSON responses early to avoid silent parse failures.
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "json") {
		return nil, fmt.Errorf("generic %s: unexpected content-type %q from %s", a.cfg.Name, ct, reqURL)
	}

	// Simple root paths (no dots) use streaming JSON parse to avoid buffering
	// the full response body. Nested root paths require the buffered gjson approach.
	// Also fall back to buffered when cursor pagination uses a nested cursor path,
	// since the streaming path can only read sibling keys at the root level.
	canStream := !strings.Contains(a.cfg.Mapping.Root, ".")
	if canStream && a.cfg.Pagination.Type == "cursor" && strings.Contains(a.cfg.Pagination.CursorPath, ".") {
		canStream = false
	}
	if canStream {
		return a.fetchJSONStream(ctx, resp, &cur)
	}
	return a.fetchJSONBuffered(ctx, resp, &cur)
}

// fetchJSONBuffered reads the entire response body and uses gjson to extract records.
// Used for nested root paths (e.g. "data.items") that require full-body access.
func (a *Adapter) fetchJSONBuffered(_ context.Context, resp *http.Response, cur *cursor) (*feed.FetchResult, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("generic %s: read body: %w", a.cfg.Name, err)
	}

	// Extract the array of records using the configured gjson root path.
	rootResult := gjson.GetBytes(body, a.cfg.Mapping.Root)
	if !rootResult.Exists() || !rootResult.IsArray() {
		// Empty/missing array is not an error — just no results.
		nextCur, _ := json.Marshal(*cur)
		return &feed.FetchResult{
			Patches:    nil,
			SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
			NextCursor: nextCur,
			LastPage:   true,
		}, nil
	}

	var patches []feed.CanonicalPatch
	var rawCount int
	rootResult.ForEach(func(_, record gjson.Result) bool {
		rawCount++
		p := a.mapRecord(record)
		if p.CVEID != "" {
			patches = append(patches, p)
		}
		return true
	})

	// Determine pagination state using raw record count (before CVE ID filtering)
	// so that filtered-out records don't cause premature last-page detection.
	lastPage, nextCur := a.nextPage(body, resp.Header, cur, rawCount)

	nextCurJSON, _ := json.Marshal(nextCur)
	return &feed.FetchResult{
		Patches:    patches,
		SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
		NextCursor: nextCurJSON,
		LastPage:   lastPage,
	}, nil
}

// fetchJSONStream parses the response using json.Decoder to avoid buffering the full
// body. It streams through a top-level JSON object, processing the array at the
// configured root key element-by-element.
func (a *Adapter) fetchJSONStream(_ context.Context, resp *http.Response, cur *cursor) (*feed.FetchResult, error) {
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize))

	// Expect opening '{' of top-level object.
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("generic %s: stream: read opening token: %w", a.cfg.Name, err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("generic %s: stream: expected '{', got %v", a.cfg.Name, tok)
	}

	// Determine if cursor path is a simple sibling key (no dots) that we can
	// read during streaming.
	cursorKey := ""
	if a.cfg.Pagination.Type == "cursor" && !strings.Contains(a.cfg.Pagination.CursorPath, ".") {
		cursorKey = a.cfg.Pagination.CursorPath
	}

	var patches []feed.CanonicalPatch
	var rawCount int
	var nextCursorValue string
	foundRoot := false

	// Iterate over top-level keys.
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("generic %s: stream: read key: %w", a.cfg.Name, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("generic %s: stream: expected string key, got %T", a.cfg.Name, keyTok)
		}

		switch {
		case key == a.cfg.Mapping.Root:
			foundRoot = true
			// Consume '[' opening the array.
			arrTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("generic %s: stream: read array open: %w", a.cfg.Name, err)
			}
			if delim, ok := arrTok.(json.Delim); !ok || delim != '[' {
				return nil, fmt.Errorf("generic %s: stream: expected '[' for root array, got %v", a.cfg.Name, arrTok)
			}

			for dec.More() {
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return nil, fmt.Errorf("generic %s: stream: decode record: %w", a.cfg.Name, err)
				}
				rawCount++
				record := gjson.ParseBytes(raw)
				p := a.mapRecord(record)
				if p.CVEID != "" {
					patches = append(patches, p)
				}
			}

			// Consume ']' closing the array.
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("generic %s: stream: read array close: %w", a.cfg.Name, err)
			}

		case cursorKey != "" && key == cursorKey:
			// Read the cursor value — decode as RawMessage then coerce to string
			// so numeric cursors (e.g. 42) work the same as the buffered gjson path.
			var rawVal json.RawMessage
			if err := dec.Decode(&rawVal); err != nil {
				return nil, fmt.Errorf("generic %s: stream: decode cursor value: %w", a.cfg.Name, err)
			}
			nextCursorValue = gjson.ParseBytes(rawVal).String()

		default:
			// Skip unknown keys.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("generic %s: stream: skip key %q: %w", a.cfg.Name, key, err)
			}
		}
	}

	if !foundRoot {
		// Root key not found — return empty results.
		nextCurJSON, _ := json.Marshal(*cur)
		return &feed.FetchResult{
			Patches:    nil,
			SourceMeta: feed.SourceMeta{SourceName: a.cfg.Name, FetchedAt: time.Now().UTC()},
			NextCursor: nextCurJSON,
			LastPage:   true,
		}, nil
	}

	lastPage, nextCur := a.nextPageFromStream(nextCursorValue, resp.Header, cur, rawCount)

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
		return a.cfg.URL + fmt.Sprintf("%s%s=%s", sep, a.cfg.Pagination.CursorParam, url.QueryEscape(cur.CursorValue))

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

// nextPageFromStream computes pagination state using a cursor value extracted
// during streaming (instead of from the buffered body). For offset and
// link-header pagination, delegates to the same logic as nextPage. For cursor
// pagination with a nested CursorPath (dots), returns lastPage=true since the
// streaming path cannot read nested cursor values.
func (a *Adapter) nextPageFromStream(nextCursorValue string, headers http.Header, cur *cursor, patchCount int) (lastPage bool, next cursor) {
	switch a.cfg.Pagination.Type {
	case "offset":
		next.Page = cur.Page + 1
		if next.Page <= 1 {
			next.Page = 2
		}
		if a.cfg.Pagination.PageSize > 0 && patchCount < a.cfg.Pagination.PageSize {
			return true, next
		}
		return false, next

	case "cursor":
		if strings.Contains(a.cfg.Pagination.CursorPath, ".") {
			// Nested cursor path — streaming couldn't extract it.
			return true, cursor{}
		}
		if nextCursorValue == "" {
			return true, cursor{}
		}
		return false, cursor{CursorValue: nextCursorValue}

	case "link-header":
		link := headers.Get("Link")
		if m := linkNextRe.FindStringSubmatch(link); len(m) > 1 {
			return false, cursor{NextURL: m[1]}
		}
		return true, cursor{}

	default:
		return true, cursor{}
	}
}

// mapRecord converts a single gjson Result (one array element) to a CanonicalPatch.
func (a *Adapter) mapRecord(record gjson.Result) feed.CanonicalPatch {
	raw := record.Raw
	p := feed.CanonicalPatch{
		CVEID: feed.StripNullBytes(gjson.Get(raw, a.cfg.Mapping.Fields["cve_id"]).String()),
	}

	if path, ok := a.cfg.Mapping.Fields["description"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			s := feed.StripNullBytes(v.String())
			p.DescriptionPrimary = &s
		}
	}

	if path, ok := a.cfg.Mapping.Fields["severity"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			s := feed.StripNullBytes(v.String())
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
			s := feed.StripNullBytes(v.String())
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
			s := feed.StripNullBytes(v.String())
			p.CVSSv4Vector = &s
		}
	}

	if path, ok := a.cfg.Mapping.Fields["date_published"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			if t := feed.ParseTimePtr(v.String()); t != nil {
				p.DatePublished = t
			}
		}
	}

	if path, ok := a.cfg.Mapping.Fields["date_modified"]; ok {
		if v := gjson.Get(raw, path); v.Exists() {
			if t := feed.ParseTimePtr(v.String()); t != nil {
				p.DateModified = t
			}
		}
	}

	if path, ok := a.cfg.Mapping.Fields["references"]; ok {
		if v := gjson.Get(raw, path); v.Exists() && v.IsArray() {
			v.ForEach(func(_, item gjson.Result) bool {
				url := feed.StripNullBytes(item.String())
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
				slog.Warn("generic feed: auth env var not set, sending request without auth", //nolint:gosec // G706: values from admin config, not user input
					"feed", a.cfg.Name, "env_var", a.cfg.Auth.TokenEnv)
			}
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)

	case "basic":
		user := os.Getenv(a.cfg.Auth.UsernameEnv)
		pass := os.Getenv(a.cfg.Auth.PasswordEnv)
		if user == "" && pass == "" {
			slog.Warn("generic feed: auth env vars not set, sending request without auth", //nolint:gosec // G706: values from admin config, not user input
				"feed", a.cfg.Name)
			return
		}
		req.SetBasicAuth(user, pass)

	case "header":
		value := os.Getenv(a.cfg.Auth.HeaderValueEnv)
		if value == "" {
			if a.cfg.Auth.HeaderValueEnv != "" {
				slog.Warn("generic feed: auth env var not set, sending request without auth", //nolint:gosec // G706: values from admin config, not user input
					"feed", a.cfg.Name, "env_var", a.cfg.Auth.HeaderValueEnv)
			}
			return
		}
		req.Header.Set(a.cfg.Auth.HeaderName, value)
	}
}

// fetchCSAF fetches a CSAF document and converts it to CanonicalPatches using
// the shared CSAF parser.
func (a *Adapter) fetchCSAF(ctx context.Context) (*feed.FetchResult, error) {
	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("generic %s: rate limit: %w", a.cfg.Name, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("generic %s: build request: %w", a.cfg.Name, err)
	}
	a.applyAuth(req)

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL from admin-configured feed YAML, not user input
	if err != nil {
		return nil, fmt.Errorf("generic %s: fetch: %w", a.cfg.Name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

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
		p := feed.CanonicalPatch{CVEID: feed.StripNullBytes(vuln.CVE)}

		// Description from notes.
		for _, note := range vuln.Notes {
			if note.Type == "description" || note.Type == "summary" {
				desc := feed.StripNullBytes(note.Text)
				p.DescriptionPrimary = &desc
				break
			}
		}

		// CVSS scores — iterate all score entries, keep the highest per version.
		var bestV3Score float64
		var bestV3Vector string
		var hasV3 bool
		var bestV4Score float64
		var bestV4Vector string
		var hasV4 bool
		for _, s := range vuln.Scores {
			if s.CVSSv3 != nil && (!hasV3 || s.CVSSv3.BaseScore > bestV3Score) {
				bestV3Score = s.CVSSv3.BaseScore
				bestV3Vector = s.CVSSv3.VectorString
				hasV3 = true
			}
			if s.CVSSv4 != nil && (!hasV4 || s.CVSSv4.BaseScore > bestV4Score) {
				bestV4Score = s.CVSSv4.BaseScore
				bestV4Vector = s.CVSSv4.VectorString
				hasV4 = true
			}
		}
		if hasV3 {
			p.CVSSv3Score = &bestV3Score
			vec := feed.StripNullBytes(bestV3Vector)
			if vec != "" {
				p.CVSSv3Vector = &vec
			}
		}
		if hasV4 {
			p.CVSSv4Score = &bestV4Score
			vec := feed.StripNullBytes(bestV4Vector)
			if vec != "" {
				p.CVSSv4Vector = &vec
			}
		}

		// References.
		for _, ref := range vuln.References {
			u := feed.StripNullBytes(ref.URL)
			if u != "" {
				p.References = append(p.References, feed.ReferenceEntry{URL: u})
			}
		}

		// Dates from tracking.
		if doc.DocumentMeta.Tracking.InitialReleaseDate != "" {
			if t := feed.ParseTimePtr(doc.DocumentMeta.Tracking.InitialReleaseDate); t != nil {
				p.DatePublished = t
			}
		}
		if doc.DocumentMeta.Tracking.CurrentReleaseDate != "" {
			if t := feed.ParseTimePtr(doc.DocumentMeta.Tracking.CurrentReleaseDate); t != nil {
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

// ensure Adapter implements feed.Adapter.
var _ feed.Adapter = (*Adapter)(nil)
