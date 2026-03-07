package feed

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// timeLayouts is the ordered list of timestamp formats encountered in CVE feeds.
// Never call time.Parse(time.RFC3339, val) directly on feed data — upstream
// sources are inconsistent about timezone suffixes and sub-second precision.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02",
	time.RFC1123,
	time.RFC1123Z,
}

// ParseTime parses a feed timestamp using a multi-layout fallback. Returns a
// zero time.Time (not an error) on failure so callers can use nil-pointer
// semantics with a simple zero check.
func ParseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// ParseTimePtr is like ParseTime but returns nil for zero/empty input.
func ParseTimePtr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t := ParseTime(s)
	if t.IsZero() {
		return nil
	}
	return &t
}

// StripNullBytes removes null bytes (\x00) from a string. Postgres TEXT and
// JSONB columns reject null bytes (implementation-pitfalls.md §2.10).
func StripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// StripNullBytesJSON removes null bytes from a JSON byte slice.
func StripNullBytesJSON(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte{0}, []byte{})
}

// cveIDPattern matches CVE IDs in the canonical format CVE-YYYY-NNNNN+.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// ResolveCanonicalID returns a CVE ID from the aliases slice if one is present,
// otherwise returns nativeID unchanged. This is required for OSV and GHSA records
// where the native ID (GHSA-*, PYSEC-*, etc.) is an alias and the CVE ID should
// be used as the canonical primary key to prevent split-brain records.
//
// The nativeID is returned as-is when no CVE alias is found (the record will be
// stored under its own ID and merged if a CVE alias is discovered later via
// late-binding PK migration).
// DefaultUserAgent is the standard User-Agent string for all feed HTTP requests.
const DefaultUserAgent = "CVErt-Ops/1.0 vulnerability intelligence platform"

// UserAgentTransport wraps an http.RoundTripper to set the User-Agent header
// on every request that doesn't already have one.
type UserAgentTransport struct {
	Base      http.RoundTripper
	UserAgent string
}

func (t *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.UserAgent)
	}
	return t.Base.RoundTrip(req)
}

// WrapClientWithUA returns a shallow copy of client with a UserAgentTransport
// applied. Safe to call multiple times (idempotent — checks if already wrapped).
func WrapClientWithUA(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	// Shallow copy so the original isn't mutated.
	c := *client
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	// Idempotent: don't double-wrap.
	if _, ok := base.(*UserAgentTransport); ok {
		return &c
	}
	c.Transport = &UserAgentTransport{
		Base:      base,
		UserAgent: DefaultUserAgent,
	}
	return &c
}

// DrainAndClose drains remaining response body bytes (for HTTP connection reuse)
// and closes the body. Safe to call on nil.
func DrainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

// CloneStrings returns a new slice with all strings copied via strings.Clone.
// Returns nil for nil input.
func CloneStrings(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.Clone(s)
	}
	return out
}

// DownloadToTemp streams an HTTP response body to a temp file for ZIP reading.
// The caller must defer os.Remove(f.Name()) and f.Close().
// The tempPattern parameter is passed directly to os.CreateTemp (e.g., "cvert-mitre-*.zip").
func DownloadToTemp(ctx context.Context, client *http.Client, url, tempPattern string) (*os.File, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req) //nolint:gosec // G704: URL comes from hardcoded adapter constants
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed: download %s: HTTP %d", url, resp.StatusCode)
	}

	f, err := os.CreateTemp("", tempPattern)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp, not user input
		return nil, fmt.Errorf("feed: copy to temp: %w", err)
	}

	// Rewind for zip.NewReader.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp, not user input
		return nil, fmt.Errorf("feed: seek temp file: %w", err)
	}
	return f, nil
}

func ResolveCanonicalID(nativeID string, aliases []string) string {
	// Sort aliases so the result is deterministic when multiple CVE IDs exist.
	sorted := make([]string, len(aliases))
	copy(sorted, aliases)
	sort.Strings(sorted)

	for _, alias := range sorted {
		if cveIDPattern.MatchString(alias) {
			return alias
		}
	}
	return nativeID
}
