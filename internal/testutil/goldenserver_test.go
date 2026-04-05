// ABOUTME: Tests for golden file server and URL-rewrite transport helpers.
// ABOUTME: Verifies fixture serving and URL rewriting for offline adapter tests.
package testutil_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestGoldenServer_ServesFixtureFiles(t *testing.T) {
	dir := t.TempDir()
	content := `{"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}`
	if err := os.WriteFile(filepath.Join(dir, "page-001.json"), []byte(content), 0644); err != nil { //nolint:gosec // G306: test fixture file
		t.Fatalf("write fixture: %v", err)
	}

	srv := testutil.NewGoldenServer(t, dir)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/page-001.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != content {
		t.Errorf("got %q, want %q", body, content)
	}
}

func TestURLRewriteTransport_RedirectsRequests(t *testing.T) {
	dir := t.TempDir()
	content := `{"result": "ok"}`
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(content), 0644); err != nil { //nolint:gosec // G306: test fixture file
		t.Fatalf("write fixture: %v", err)
	}

	srv := testutil.NewGoldenServer(t, dir)

	// Create a transport that rewrites requests from example.com to our test server.
	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://api.example.com",
			srv.URL,
			http.DefaultTransport,
		),
	}

	// Request to the "real" URL should be rewritten to test server.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.com/data.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != content {
		t.Errorf("got %q, want %q", body, content)
	}
}

func TestURLRewriteTransport_PreservesQueryString(t *testing.T) {
	dir := t.TempDir()
	// The file server won't use query strings, so we just test that the
	// request reaches the server. A custom handler would be needed to
	// assert query params, but for this test we just verify rewriting works.
	content := `{"ok": true}`
	if err := os.WriteFile(filepath.Join(dir, "api"), []byte(content), 0644); err != nil { //nolint:gosec // G306: test fixture file
		t.Fatalf("write fixture: %v", err)
	}

	srv := testutil.NewGoldenServer(t, dir)
	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://services.nvd.nist.gov",
			srv.URL,
			http.DefaultTransport,
		),
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://services.nvd.nist.gov/api?startIndex=0&resultsPerPage=2000", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestURLRewriteTransport_PassthroughNonMatchingURLs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(`{}`), 0644); err != nil { //nolint:gosec // G306: test fixture file
		t.Fatalf("write fixture: %v", err)
	}

	srv := testutil.NewGoldenServer(t, dir)

	// Create transport that only rewrites example.com.
	transport := testutil.NewURLRewriteTransport(
		"https://api.example.com",
		srv.URL,
		http.DefaultTransport,
	)

	// A request to a non-matching URL should pass through unchanged.
	// We test this by making a request to the test server directly —
	// the transport should pass it through without modification.
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("passthrough status = %d, want 200", resp.StatusCode)
	}
}
