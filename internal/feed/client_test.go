// ABOUTME: Tests for the SSRF-safe feed client construction.
// ABOUTME: Verifies SSRF blocking, body size limiting, and client configuration.
package feed

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildFeedClient_BlocksPrivateIPs(t *testing.T) {
	t.Parallel()

	// Start a local httptest server (binds to 127.0.0.1).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := BuildFeedClient(10*time.Second, 0)
	require.NoError(t, err)

	// safeurl must block requests to 127.0.0.1 (private IP).
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, sendErr := client.Do(req) //nolint:bodyclose,gosec // G704: test framework URL, not user input; error expected before response
	require.Error(t, sendErr, "safeurl client must block requests to private IPs")
}

func TestBuildFeedClient_Timeout(t *testing.T) {
	t.Parallel()

	client, err := BuildFeedClient(5*time.Minute, 0)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, client.Timeout)
}

func TestBuildFeedClient_DefaultBodyLimit(t *testing.T) {
	t.Parallel()

	client, err := BuildFeedClient(10*time.Second, 0)
	require.NoError(t, err)

	// Verify the transport chain includes maxBodyTransport.
	mbt, ok := client.Transport.(*maxBodyTransport)
	require.True(t, ok, "outer transport must be maxBodyTransport")
	assert.Equal(t, DefaultMaxBodyBytes, mbt.maxBytes)
}

func TestBuildFeedClient_CustomBodyLimit(t *testing.T) {
	t.Parallel()

	client, err := BuildFeedClient(10*time.Second, 1024)
	require.NoError(t, err)

	mbt, ok := client.Transport.(*maxBodyTransport)
	require.True(t, ok, "outer transport must be maxBodyTransport")
	assert.Equal(t, int64(1024), mbt.maxBytes)
}

// limitedClient returns a client for srv whose responses are capped at maxBytes.
func limitedClient(srv *httptest.Server, maxBytes int64) *http.Client {
	return &http.Client{
		Transport: &maxBodyTransport{
			inner:    srv.Client().Transport,
			maxBytes: maxBytes,
		},
	}
}

// bodyServer serves size bytes of "x".
func bodyServer(t *testing.T, size int) *httptest.Server {
	t.Helper()
	body := strings.Repeat("x", size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body)) //nolint:errcheck,gosec // G104: test handler, discard errors irrelevant
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMaxBodyTransport_LimitsResponseBody(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		size    int
		wantErr bool
	}{
		"under the limit":   {size: 255},
		"exactly the limit": {size: 256},
		"one byte over":     {size: 257, wantErr: true},
		"far over":          {size: 2048, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := bodyServer(t, tc.size)
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			resp, err := limitedClient(srv, 256).Do(req) //nolint:gosec // G704: test framework URL, not user input
			require.NoError(t, err)
			defer resp.Body.Close() //nolint:errcheck

			body, err := io.ReadAll(resp.Body)
			if tc.wantErr {
				// A body cut short at the limit must not read as a complete one:
				// a truncated archive would otherwise fail later as a corrupt file.
				require.ErrorIs(t, err, ErrBodyTooLarge)
				return
			}
			require.NoError(t, err)
			assert.Len(t, body, tc.size)
		})
	}
}

func TestDownloadToTemp_ReportsBodyOverTransportLimit(t *testing.T) {
	t.Parallel()

	srv := bodyServer(t, 2048)
	f, err := DownloadToTemp(context.Background(), limitedClient(srv, 256), srv.URL, "cvert-test-*.zip", MaxDownloadSize)
	if f != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp
	}
	require.ErrorIs(t, err, ErrBodyTooLarge)
}

// The bulk archives pass through the feed client whole: OSV's all.zip was
// 2,934,025,989 bytes and MITRE's cvelistV5 archive 724,684,107 bytes on
// 2026-11-10.
func TestDefaultMaxBodyBytes_FitsBulkArchives(t *testing.T) {
	t.Parallel()
	const osvAllZip = 2_934_025_989
	assert.GreaterOrEqual(t, DefaultMaxBodyBytes, int64(2*osvAllZip),
		"the default cap must leave room for the OSV archive to grow")
}
