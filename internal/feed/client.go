// ABOUTME: Constructs the SSRF-safe HTTP client for feed fetching with body size limits.
// ABOUTME: Transport composition: safeurl (inner, SSRF) -> maxBodyTransport (outer, size cap).
package feed

import (
	"io"
	"net/http"
	"time"

	"github.com/doyensec/safeurl"
)

// DefaultMaxBodyBytes is the default maximum response body size for feed downloads.
// 512 MB accommodates bulk feed archives (MITRE, OSV) while preventing unbounded reads.
const DefaultMaxBodyBytes int64 = 512 << 20 // 512 MiB

// maxBodyTransport wraps an http.RoundTripper and limits response body size
// to prevent unbounded memory/disk consumption from malicious or corrupt feeds.
type maxBodyTransport struct {
	inner    http.RoundTripper
	maxBytes int64
}

// limitedReadCloser preserves the original body's Close while limiting reads.
type limitedReadCloser struct {
	io.Reader
	io.Closer
}

func (t *maxBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = limitedReadCloser{
		Reader: io.LimitReader(resp.Body, t.maxBytes),
		Closer: resp.Body,
	}
	return resp, nil
}

// BuildFeedClient returns an SSRF-safe *http.Client for feed fetching.
// Transport composition: safeurl.Transport (inner) → maxBodyTransport (outer).
// maxBodyBytes caps the response body size; pass 0 to use DefaultMaxBodyBytes.
func BuildFeedClient(timeout time.Duration, maxBodyBytes int64) (*http.Client, error) {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}

	cfg := safeurl.GetConfigBuilder().
		SetTimeout(timeout).
		Build()
	inner := safeurl.Client(cfg).Client

	inner.Transport = &maxBodyTransport{
		inner:    inner.Transport,
		maxBytes: maxBodyBytes,
	}

	return inner, nil
}
