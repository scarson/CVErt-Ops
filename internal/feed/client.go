// ABOUTME: Constructs the SSRF-safe HTTP client for feed fetching with body size limits.
// ABOUTME: Transport composition: safeurl (inner, SSRF) -> maxBodyTransport (outer, size cap).
package feed

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/doyensec/safeurl"
)

// DefaultMaxBodyBytes is the default maximum response body size for feed downloads.
// The bulk archives pass through it whole: OSV's all.zip was 2.9 GB and MITRE's
// cvelistV5 archive 0.7 GB on 2026-11-10, so the cap leaves room for growth
// while still bounding a runaway response.
const DefaultMaxBodyBytes int64 = 8 << 30 // 8 GiB

// ErrBodyTooLarge reports a response body longer than the feed client's cap.
var ErrBodyTooLarge = errors.New("feed: response body exceeds the size limit")

// maxBodyTransport wraps an http.RoundTripper and limits response body size
// to prevent unbounded memory/disk consumption from malicious or corrupt feeds.
type maxBodyTransport struct {
	inner    http.RoundTripper
	maxBytes int64
}

// limitedBody reads at most remaining bytes and then fails with
// ErrBodyTooLarge if the body has more. A body cut short must not read as a
// complete one: a truncated archive would otherwise fail later as a corrupt
// file, far from the cause.
type limitedBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 {
			return 0, ErrBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error { return b.body.Close() }

func (t *maxBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{body: resp.Body, remaining: t.maxBytes}
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
