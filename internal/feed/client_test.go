// ABOUTME: Tests for the SSRF-safe feed client construction.
// ABOUTME: Verifies SSRF blocking, body size limiting, and client configuration.
package feed

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
	_, sendErr := client.Do(req) //nolint:bodyclose // error expected before response
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

func TestMaxBodyTransport_LimitsResponseBody(t *testing.T) {
	t.Parallel()

	// Create a server that returns a large response.
	largeBody := strings.Repeat("x", 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody)) //nolint:errcheck
	}))
	defer srv.Close()

	// Wrap the test client's transport with maxBodyTransport (limit 256 bytes).
	inner := srv.Client()
	limited := &http.Client{
		Transport: &maxBodyTransport{
			inner:    inner.Transport,
			maxBytes: 256,
		},
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := limited.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Len(t, body, 256, "response body should be truncated to maxBytes")
}
