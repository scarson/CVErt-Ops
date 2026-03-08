// ABOUTME: Tests for the SPA fallback handler that serves the embedded frontend.
// ABOUTME: Verifies static files are served, unknown paths return index.html, and cache headers are correct.

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPAHandler_ServesStaticFile(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html":          {Data: []byte("<html>app</html>")},
		"assets/index-abc.js": {Data: []byte("console.log('app')")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-abc.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	assert.Equal(t, "console.log('app')", string(body))
}

func TestSPAHandler_FallsBackToIndexHTML(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/cves/CVE-2024-1234", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	assert.Equal(t, "<html>app</html>", string(body))
}

func TestSPAHandler_CacheHeaders_HashedAsset(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html":          {Data: []byte("<html>app</html>")},
		"assets/index-abc.js": {Data: []byte("js")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-abc.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=31536000")
	assert.Contains(t, rec.Header().Get("Cache-Control"), "immutable")
}

func TestSPAHandler_CacheHeaders_IndexHTML(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
}
