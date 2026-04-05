// ABOUTME: Test helpers for serving golden fixture files and rewriting adapter URLs.
// ABOUTME: Used by feed adapter golden file tests to replay captured API responses offline.
package testutil

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// NewGoldenServer creates an httptest.Server that serves files from the given
// directory. The server is automatically closed when the test completes.
// Fixture files are served at their filename path (e.g., /page-001.json).
func NewGoldenServer(t *testing.T, fixtureDir string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.FileServer(http.Dir(fixtureDir)))
	t.Cleanup(srv.Close)
	return srv
}

// URLRewriteTransport intercepts HTTP requests targeting a specific base URL
// and rewrites them to point at a test server instead. The path and query
// string are preserved. This lets adapter golden file tests use the adapter's
// real Fetch method with hardcoded URLs, redirecting traffic to a local
// httptest server serving fixture files.
type URLRewriteTransport struct {
	// OriginalBase is the prefix to match and replace (e.g., "https://services.nvd.nist.gov").
	OriginalBase string
	// RewriteBase is the replacement prefix (e.g., "http://127.0.0.1:12345").
	RewriteBase string
	// Inner is the underlying transport to use after rewriting.
	Inner http.RoundTripper
}

// NewURLRewriteTransport creates a URLRewriteTransport.
func NewURLRewriteTransport(originalBase, rewriteBase string, inner http.RoundTripper) *URLRewriteTransport {
	return &URLRewriteTransport{
		OriginalBase: originalBase,
		RewriteBase:  rewriteBase,
		Inner:        inner,
	}
}

// RoundTrip rewrites matching request URLs and delegates to the inner transport.
func (t *URLRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqURL := req.URL.String()
	if suffix, found := strings.CutPrefix(reqURL, t.OriginalBase); found {
		// Rewrite the URL: replace the base, keep the path and query.
		newURL := t.RewriteBase + suffix
		parsed, err := url.Parse(newURL)
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.URL = parsed
		req.Host = parsed.Host
	}
	return t.Inner.RoundTrip(req)
}
