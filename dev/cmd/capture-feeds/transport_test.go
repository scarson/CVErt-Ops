// ABOUTME: Tests for the recording HTTP transport that saves request/response pairs to disk.
// ABOUTME: Verifies streaming body tee, sequential numbering, write failure propagation.
package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordingTransport_SavesRequestAndResponse(t *testing.T) {
	// Set up a test server that returns known content.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}`))
	}))
	defer ts.Close()

	outDir := t.TempDir()
	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: outDir,
	}
	client := &http.Client{Transport: rt}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v2/cves?startIndex=0", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}

	// The response body must still be readable by the caller (adapter).
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:gosec // G104: test cleanup
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "CVE-2024-0001") {
		t.Fatalf("body missing expected CVE: %s", body)
	}

	// Verify the meta file was written.
	metaPath := filepath.Join(outDir, "0001.meta.json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("meta file not found: %v", err)
	}
	meta := string(metaBytes)
	if !strings.Contains(meta, "/api/v2/cves") {
		t.Errorf("meta missing URL: %s", meta)
	}
	if !strings.Contains(meta, "200") {
		t.Errorf("meta missing status code: %s", meta)
	}

	// Verify the body file was written with the same content.
	bodyPath := filepath.Join(outDir, "0001.body")
	savedBody, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatalf("body file not found: %v", err)
	}
	if string(savedBody) != string(body) {
		t.Errorf("saved body doesn't match: got %q, want %q", savedBody, body)
	}
}

func TestRecordingTransport_SequentialNumbering(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	outDir := t.TempDir()
	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: outDir,
	}
	client := &http.Client{Transport: rt}

	for i := 0; i < 3; i++ {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close() //nolint:gosec // G104: test cleanup
	}

	// Should have 0001, 0002, 0003 files.
	for _, n := range []string{"0001", "0002", "0003"} {
		if _, err := os.Stat(filepath.Join(outDir, n+".meta.json")); err != nil {
			t.Errorf("missing meta file %s: %v", n, err)
		}
		if _, err := os.Stat(filepath.Join(outDir, n+".body")); err != nil {
			t.Errorf("missing body file %s: %v", n, err)
		}
	}
}

func TestRecordingTransport_WriteFailureFailsRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	tmp := t.TempDir()
	notDir := filepath.Join(tmp, "not-a-directory")
	if err := os.WriteFile(notDir, []byte("x"), 0644); err != nil { //nolint:gosec // G306: test helper file
		t.Fatalf("seed blocking file: %v", err)
	}

	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: notDir,
	}
	client := &http.Client{Transport: rt}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err == nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close() //nolint:gosec // G104: test cleanup
		}
		t.Fatal("expected capture write failure to return an error")
	}
}

func TestRecordingTransport_StreamingBodyTee(t *testing.T) {
	// Verifies that the adapter can stream-read the body (e.g., json.Decoder)
	// while the transport simultaneously writes to disk.
	largePayload := strings.Repeat(`{"id":"CVE-0000-0000"},`, 10000)
	largePayload = `[` + largePayload[:len(largePayload)-1] + `]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(largePayload))
	}))
	defer ts.Close()

	outDir := t.TempDir()
	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: outDir,
	}
	client := &http.Client{Transport: rt}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: test server URL is not user-controlled
	if err != nil {
		t.Fatal(err)
	}

	// Read body in small chunks (simulating json.Decoder behavior).
	buf := make([]byte, 1024)
	var totalRead int
	for {
		n, err := resp.Body.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read chunk: %v", err)
		}
	}
	resp.Body.Close() //nolint:gosec // G104: test cleanup

	if totalRead != len(largePayload) {
		t.Errorf("total read %d, want %d", totalRead, len(largePayload))
	}

	// Saved body must match exactly.
	saved, err := os.ReadFile(filepath.Join(outDir, "0001.body"))
	if err != nil {
		t.Fatalf("read saved body: %v", err)
	}
	if len(saved) != len(largePayload) {
		t.Errorf("saved body length %d, want %d", len(saved), len(largePayload))
	}
}
