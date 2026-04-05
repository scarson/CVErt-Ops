// ABOUTME: HTTP recording transport that saves request/response pairs to disk.
// ABOUTME: Used by the capture-feeds CLI to snapshot live feed API responses for test fixture generation.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// RecordingTransport wraps an http.RoundTripper and saves every request/response
// pair to disk. The caller (adapter) reads the response normally — a TeeReader
// copies bytes to disk as they flow through. This supports streaming parsers
// (json.Decoder with Token/More) without buffering the entire response in memory.
type RecordingTransport struct {
	Inner  http.RoundTripper
	OutDir string

	mu  sync.Mutex
	seq int
}

// responseMeta is the JSON structure saved alongside each response body.
type responseMeta struct {
	Sequence   int         `json:"sequence"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
}

func (rt *RecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.Inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	rt.mu.Lock()
	rt.seq++
	n := rt.seq
	rt.mu.Unlock()

	prefix := filepath.Join(rt.OutDir, fmt.Sprintf("%04d", n))

	// Save metadata.
	meta := responseMeta{
		Sequence:   n,
		Method:     req.Method,
		URL:        req.URL.String(),
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup on marshal error
		return nil, fmt.Errorf("marshal response metadata: %w", err)
	}
	if err := os.WriteFile(prefix+".meta.json", metaJSON, 0644); err != nil { //nolint:gosec // G306: dev tool output files
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup on write error
		return nil, fmt.Errorf("write response metadata: %w", err)
	}

	// TeeReader: adapter reads from resp.Body, copy flows to bodyFile.
	bodyFile, err := os.Create(prefix + ".body") //nolint:gosec // G703: dev tool writes to user-specified output dir
	if err != nil {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup on create error
		return nil, fmt.Errorf("create response body file: %w", err)
	}

	origBody := resp.Body
	resp.Body = &teeBody{
		Reader:   io.TeeReader(origBody, bodyFile),
		origBody: origBody,
		bodyFile: bodyFile,
	}

	return resp, nil
}

// teeBody wraps a TeeReader so that closing the body also closes the
// underlying response body and the output file.
type teeBody struct {
	Reader   io.Reader
	origBody io.ReadCloser
	bodyFile *os.File
}

func (tb *teeBody) Read(p []byte) (int, error) {
	return tb.Reader.Read(p)
}

func (tb *teeBody) Close() error {
	// Drain any unread bytes so the body file is complete.
	io.Copy(io.Discard, tb.Reader) //nolint:errcheck,gosec // drain complete, close is best-effort
	tb.bodyFile.Close()            //nolint:errcheck,gosec // best-effort cleanup
	return tb.origBody.Close()
}
