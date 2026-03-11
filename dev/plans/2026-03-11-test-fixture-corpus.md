# Test Fixture Corpus Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a curated, version-controlled test fixture corpus from real feed API responses, enabling deterministic golden-file adapter tests and offline dev environment seeding without hitting live APIs.

**Architecture:** A three-phase approach: (1) capture tool records raw HTTP responses from each feed source via a recording HTTP transport, (2) a Claude agent filters the captured data locally to select ~30-50 CVEs covering an edge case matrix, (3) extraction tooling pulls the selected CVEs into per-adapter `testdata/` fixture files. Golden file tests and a seed corpus helper complete the integration.

**Tech Stack:** Go 1.26, `net/http` (recording transport), `encoding/json`, `archive/zip`, `compress/gzip`, `encoding/csv`, `httptest` (golden file tests), testcontainers (seed corpus integration tests)

---

## Context

**Problem:** All 9 feed adapters use hand-crafted inline JSON in tests. No recorded API responses exist anywhere. This means:
- Tests can't detect upstream API schema drift (health review Finding 23)
- No pre-seeded corpus for dev/integration testing
- Every clean launch either starts empty or hits live APIs

**Feeds by format:**

| Format | Adapters | Capture method |
|--------|----------|---------------|
| JSON API (paginated) | NVD, GHSA, Red Hat, MSRC | Recording HTTP transport + adapter pagination |
| ZIP archive | MITRE, OSV | Direct download (single file) |
| gzip CSV | EPSS | Direct download (single file) |
| JSON (single file) | KEV | Direct download (single file) |

**Excluded:** The `generic` adapter is config-driven with user-defined URLs. It has no fixed upstream to capture from. Generic adapter tests continue to use hand-crafted fixtures.

**Relationship to health review remediation plan:** This plan implements the test infrastructure needed for Finding 23 (Task 5A) in `dev/plans/2026-03-10-health-review-remediation.md`. Once this plan is complete, Task 5A becomes "done."

---

## Data Storage

**Bulk captured data** is stored OUTSIDE the repository at:

```
D:\Code\CVErt-Ops\data\feed-snapshots\
```

Bash-compatible path: `/d/Code/CVErt-Ops/data/feed-snapshots/`

This directory is NOT in the git repo and does NOT need a `.gitignore` entry. It contains multi-GB raw API responses used only for fixture generation. The curated fixtures extracted FROM this data are small and stored IN the repo at `internal/feed/<adapter>/testdata/golden/`.

---

## Adapter URL Constants Reference

These hardcoded constants are needed by the capture CLI (Task 3), extraction tool (Task 7), and golden file test URL-rewrite transports (Tasks 9-10). Every adapter reads its URL from a package-level `const`:

| Adapter | Package | Const name | URL |
|---------|---------|-----------|-----|
| NVD | `internal/feed/nvd` | `apiURL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| GHSA | `internal/feed/ghsa` | `advisoriesURL` | `https://api.github.com/advisories` |
| KEV | `internal/feed/kev` | `feedURL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| MITRE | `internal/feed/mitre` | `bulkZIPURL` | `https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip` |
| OSV | `internal/feed/osv` | `bulkZIPURL` | `https://osv-vulnerabilities.storage.googleapis.com/all.zip` |
| EPSS | `internal/feed/epss` | `feedURL` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` |
| MSRC | `internal/feed/msrc` | `baseURL` | `https://api.msrc.microsoft.com/cvrf/v3.0/` (+ `/updates` and `/csaf/{id}`) |
| Red Hat | `internal/feed/redhat` | `baseURL` | `https://access.redhat.com/hydra/rest/securitydata/` (+ `/cve.json` and `/cve/{id}.json`) |

---

## NVD Response Envelope Structure

The extraction tool (Task 7) and golden file tests (Tasks 9-10) need to create valid NVD API response JSON. The adapter's `parseNVDResponse` function expects this structure:

```json
{
  "resultsPerPage": 2000,
  "startIndex": 0,
  "totalResults": 42,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-03-11T10:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-3094",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2024-03-29T17:15:21.420",
        "lastModified": "2024-04-19T01:15:39.467",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {"lang": "en", "value": "..."}
        ],
        "metrics": {
          "cvssMetricV31": [...],
          "cvssMetricV40": [...]
        },
        "weaknesses": [...],
        "configurations": [...],
        "references": [...]
      }
    }
  ]
}
```

The streaming parser navigates: root object → `"vulnerabilities"` key → array → individual `{"cve": {...}}` objects. The `totalResults`, `startIndex`, and `resultsPerPage` fields drive pagination logic in `computeNextCursor`. The `timestamp` field is used for clock-skew safety.

---

## Phase A: Capture Infrastructure

### Task 1: Create the data directory structure

**Files:** None in the repo.

**Step 1: Create the snapshot directory structure**

```bash
mkdir -p /d/Code/CVErt-Ops/data/feed-snapshots/{nvd,mitre,ghsa,osv,kev,epss,msrc,redhat}
```

**Step 2: Commit** — Nothing to commit. The data directory is outside the repo.

---

### Task 2: Recording HTTP transport

The recording transport wraps `http.RoundTripper` to save every HTTP request/response to disk while transparently passing data through to the adapter. This lets us reuse the adapters' existing pagination, rate limiting, and auth logic — we just record what flows through.

**How the transport chain works:** The capture CLI creates `&http.Client{Transport: &RecordingTransport{Inner: http.DefaultTransport}}`. The adapter constructor calls `feed.WrapClientWithUA(client)` which shallow-copies the client and wraps the transport: `UserAgentTransport{Base: RecordingTransport{Inner: http.DefaultTransport}}`. On each request, the chain is: UserAgentTransport (adds header) → RecordingTransport (saves to disk) → http.DefaultTransport (makes real request). This is correct — the recording happens transparently.

**Files:**
- Create: `dev/cmd/capture-feeds/transport.go`
- Create: `dev/cmd/capture-feeds/transport_test.go`

**Step 1: Write the failing test**

```go
// dev/cmd/capture-feeds/transport_test.go
package main

import (
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}`))
	}))
	defer ts.Close()

	outDir := t.TempDir()
	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: outDir,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(ts.URL + "/api/v2/cves?startIndex=0")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}

	// The response body must still be readable by the caller (adapter).
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	outDir := t.TempDir()
	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: outDir,
	}
	client := &http.Client{Transport: rt}

	for i := 0; i < 3; i++ {
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
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

func TestRecordingTransport_StreamingBodyTee(t *testing.T) {
	// Verifies that the adapter can stream-read the body (e.g., json.Decoder)
	// while the transport simultaneously writes to disk.
	largePayload := strings.Repeat(`{"id":"CVE-0000-0000"},`, 10000)
	largePayload = `[` + largePayload[:len(largePayload)-1] + `]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largePayload))
	}))
	defer ts.Close()

	outDir := t.TempDir()
	rt := &RecordingTransport{
		Inner:  http.DefaultTransport,
		OutDir: outDir,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(ts.URL)
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
	resp.Body.Close()

	if totalRead != len(largePayload) {
		t.Errorf("total read %d, want %d", totalRead, len(largePayload))
	}

	// Saved body must match exactly.
	saved, _ := os.ReadFile(filepath.Join(outDir, "0001.body"))
	if len(saved) != len(largePayload) {
		t.Errorf("saved body length %d, want %d", len(saved), len(largePayload))
	}
}
```

**Step 2: Run tests to verify they fail**

```bash
go test ./dev/cmd/capture-feeds/... -run TestRecordingTransport -v
```
Expected: FAIL — `RecordingTransport` undefined.

**Step 3: Implement the recording transport**

```go
// dev/cmd/capture-feeds/transport.go
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
		return resp, nil // non-fatal: still return the response
	}
	if err := os.WriteFile(prefix+".meta.json", metaJSON, 0644); err != nil {
		return resp, nil
	}

	// TeeReader: adapter reads from resp.Body, copy flows to bodyFile.
	bodyFile, err := os.Create(prefix + ".body")
	if err != nil {
		return resp, nil
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
	io.Copy(io.Discard, tb.Reader) //nolint:errcheck
	tb.bodyFile.Close()
	return tb.origBody.Close()
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./dev/cmd/capture-feeds/... -run TestRecordingTransport -v
```
Expected: PASS — all 3 tests green.

**Step 5: Commit**

```bash
git add dev/cmd/capture-feeds/transport.go dev/cmd/capture-feeds/transport_test.go
git commit -m "chore: add recording HTTP transport for feed snapshot capture"
```

---

### Task 3: Capture CLI

The capture CLI runs each feed adapter against its real upstream API, using the recording transport to save all HTTP responses to disk. For single-file feeds (KEV, EPSS, MITRE ZIP, OSV ZIP), it downloads directly without the recording transport.

**Files:**
- Create: `dev/cmd/capture-feeds/main.go`

**Important:** This is a dev-only tool, not production code. It is NOT compiled into the main binary. It's run as `go run ./dev/cmd/capture-feeds/...`.

**Step 1: Write the capture CLI**

No TDD for this — it's a CLI tool that talks to live APIs. We tested the recording transport in Task 2. The CLI itself is integration-only.

```go
// dev/cmd/capture-feeds/main.go
// ABOUTME: Dev CLI to capture raw HTTP responses from all feed sources.
// ABOUTME: Saves responses to a configurable directory for offline test fixture generation.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/ghsa"
	"github.com/scarson/cvert-ops/internal/feed/kev"
	"github.com/scarson/cvert-ops/internal/feed/mitre"
	"github.com/scarson/cvert-ops/internal/feed/msrc"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/feed/osv"
	"github.com/scarson/cvert-ops/internal/feed/redhat"
)

// defaultDataDir is the default location for captured feed snapshots.
// Override with --output flag.
const defaultDataDir = "D:/Code/CVErt-Ops/data/feed-snapshots"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: capture-feeds <feed|all> [--output DIR]\n")
		fmt.Fprintf(os.Stderr, "Feeds: nvd, mitre, ghsa, osv, kev, epss, msrc, redhat, all\n")
		fmt.Fprintf(os.Stderr, "Default output: %s\n", defaultDataDir)
		os.Exit(1)
	}

	feedName := os.Args[1]
	outDir := defaultDataDir
	for i, arg := range os.Args {
		if arg == "--output" && i+1 < len(os.Args) {
			outDir = os.Args[i+1]
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	feeds := []string{feedName}
	if feedName == "all" {
		// Order: single-file feeds first (fast), then paginated feeds (slow).
		feeds = []string{"kev", "epss", "mitre", "osv", "ghsa", "msrc", "redhat", "nvd"}
	}

	for _, f := range feeds {
		if err := captureFeed(ctx, f, outDir); err != nil {
			slog.Error("capture failed", "feed", f, "error", err)
			// Continue to next feed — don't abort entire run.
		}
	}
}

func captureFeed(ctx context.Context, feedName, baseDir string) error {
	feedDir := filepath.Join(baseDir, feedName)
	if err := os.MkdirAll(feedDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", feedDir, err)
	}

	switch feedName {
	case "kev":
		return captureDirectDownload(ctx, feedDir,
			"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			"catalog.json")
	case "epss":
		return captureDirectDownload(ctx, feedDir,
			"https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
			"scores.csv.gz")
	case "mitre":
		return captureDirectDownload(ctx, feedDir,
			"https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip",
			"cvelistV5.zip")
	case "osv":
		return captureDirectDownload(ctx, feedDir,
			"https://osv-vulnerabilities.storage.googleapis.com/all.zip",
			"all.zip")
	case "nvd":
		return captureWithAdapter(ctx, feedDir, nvd.New(recordingClient(feedDir)))
	case "ghsa":
		return captureWithAdapter(ctx, feedDir, ghsa.New(recordingClient(feedDir)))
	case "msrc":
		return captureWithAdapter(ctx, feedDir, msrc.New(recordingClient(feedDir)))
	case "redhat":
		return captureWithAdapter(ctx, feedDir, redhat.New(recordingClient(feedDir)))
	default:
		return fmt.Errorf("unknown feed: %s", feedName)
	}
}

// recordingClient returns an HTTP client with a recording transport that saves
// all request/response pairs to the given directory.
func recordingClient(outDir string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &RecordingTransport{
			Inner:  http.DefaultTransport,
			OutDir: outDir,
		},
	}
}

// captureDirectDownload fetches a single URL and saves it to disk.
func captureDirectDownload(ctx context.Context, dir, url, filename string) error {
	slog.Info("downloading", "url", url, "dest", filepath.Join(dir, filename))
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", feed.DefaultUserAgent)

	client := &http.Client{Timeout: 30 * time.Minute} // ZIP files can be large
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	outPath := filepath.Join(dir, filename)
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	slog.Info("downloaded", "file", outPath, "bytes", n, "elapsed", time.Since(start).Round(time.Second))
	return nil
}

// captureWithAdapter runs a feed.Adapter with a recording transport, paginating
// until LastPage. All HTTP responses are saved to disk by the transport.
func captureWithAdapter(ctx context.Context, dir string, adapter feed.Adapter) error {
	slog.Info("capturing with adapter", "dir", dir)
	start := time.Now()
	var totalPatches, totalPages int

	var cursor json.RawMessage // nil = first page
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		result, err := adapter.Fetch(ctx, cursor)
		if err != nil {
			return fmt.Errorf("fetch page %d: %w", totalPages+1, err)
		}

		totalPages++
		totalPatches += len(result.Patches)
		slog.Info("fetched page",
			"page", totalPages,
			"patches", len(result.Patches),
			"total_patches", totalPatches,
			"last_page", result.LastPage,
		)

		cursor = result.NextCursor
		if result.LastPage {
			break
		}
	}

	slog.Info("capture complete",
		"dir", dir,
		"pages", totalPages,
		"patches", totalPatches,
		"elapsed", time.Since(start).Round(time.Second),
	)
	return nil
}
```

**Step 2: Verify it compiles**

```bash
go build ./dev/cmd/capture-feeds/...
```
Expected: compiles without errors. Do NOT run it yet — we'll run it in Phase B.

**Step 3: Commit**

```bash
git add dev/cmd/capture-feeds/main.go
git commit -m "chore: add capture-feeds CLI for snapshotting feed API responses"
```

---

## Phase B: Data Capture (Operational — Not a Code Task)

### Task 4: Run the full capture

**This is a manual operational step.** Sam runs the capture CLI. It takes ~2 hours total (NVD is the bottleneck at ~1.5 hours with API key).

**Prerequisites:**
- `NVD_API_KEY` env var set
- `GITHUB_TOKEN` env var set (for GHSA — without it, rate limit is 60 req/hr, unusable)
- Internet access
- ~10 GB free disk space on `D:` drive

**Step 1: Run the capture**

```bash
# NVD_API_KEY and GITHUB_TOKEN should already be in .env and loaded into env.
# Run all feeds — single-file feeds first (minutes), then paginated feeds (hours).
go run ./dev/cmd/capture-feeds/... all
```

The default output directory is `D:/Code/CVErt-Ops/data/feed-snapshots/`. Override with `--output` if needed.

**Expected timing:**
- KEV: ~5 seconds (2 MB JSON)
- EPSS: ~10 seconds (15 MB gzip CSV)
- MITRE: ~5-10 minutes (1.5 GB ZIP)
- OSV: ~3-5 minutes (500 MB ZIP)
- GHSA: ~10-20 minutes (paginated, ~2000 pages at 1 req/sec)
- MSRC: ~15-30 minutes (updates + CSAF docs)
- Red Hat: ~20-40 minutes (list pages + detail fetches)
- NVD: ~1.5 hours (125 pages at 0.6s/req with API key)

**Step 2: Verify the capture**

```bash
du -sh /d/Code/CVErt-Ops/data/feed-snapshots/*
ls /d/Code/CVErt-Ops/data/feed-snapshots/nvd/*.meta.json | wc -l   # ~125 pages
ls /d/Code/CVErt-Ops/data/feed-snapshots/ghsa/*.meta.json | wc -l   # ~2000+ pages
ls /d/Code/CVErt-Ops/data/feed-snapshots/kev/catalog.json            # single file
ls /d/Code/CVErt-Ops/data/feed-snapshots/epss/scores.csv.gz          # single file
```

**Step 3: Decompress EPSS for agent analysis**

The Task 6 selection agent needs to filter the EPSS CSV. Decompress it for easier analysis:

```bash
gunzip -k /d/Code/CVErt-Ops/data/feed-snapshots/epss/scores.csv.gz
# Produces scores.csv alongside scores.csv.gz
```

**Step 4: Record the capture timestamp**

Create `D:\Code\CVErt-Ops\data\feed-snapshots\CAPTURE-INFO.md`:
```markdown
# Feed Snapshot Capture Info
**Date:** YYYY-MM-DD
**NVD API key:** yes
**Total pages captured:** (fill in)
**Approximate total size:** (fill in)
```

---

## Phase C: CVE Selection (Agent Research Task)

### Task 5: Define the edge case matrix

**Files:**
- Create: `dev/plans/test-fixture-edge-case-matrix.md`

This is a reference document the selection agent reads. It defines what categories of CVEs we need and how the agent should find them.

**Step 1: Write the matrix document**

Write the following content VERBATIM to `dev/plans/test-fixture-edge-case-matrix.md`:

```markdown
# Test Fixture Edge Case Matrix

This document defines the CVE categories needed for the test fixture corpus.
The selection agent reads this document, then filters captured feed data locally
to find real CVEs matching each category.

## Target: 30-50 CVEs total

Many CVEs will cover multiple categories. Prefer CVEs that hit 2+ categories
simultaneously — this maximizes coverage with fewer fixtures.

## Categories

### Data Completeness
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| C1 | Complete, well-formed | Happy path parsing | Any CVE with all fields populated |
| C2 | Missing CVSS entirely | Null/absent score handling | NVD pages: CVE with no `cvssMetricV31` or `cvssMetricV40` block |
| C3 | CVSS v4.0 present | v4 parsing path | NVD pages: CVE with `cvssMetricV40` block |
| C4 | CVSS v4.0 only (no v3) | v4 fallback when v3 absent | NVD pages: `cvssMetricV40` present, no `cvssMetricV31` or `cvssMetricV30` |
| C5 | Multiple CWE IDs | CWE array handling | NVD pages: `weaknesses` array with 2+ entries |
| C6 | No description | Empty/null description | NVD pages: empty `descriptions` array or status=RESERVED |
| C7 | Multiple references (10+) | Large reference array | NVD pages: `references` array length >= 10 |
| C8 | CPE data present | AffectedCPEs parsing | NVD pages: `configurations` block populated |
| C9 | Unicode in description | String handling edge case | NVD pages: description containing non-ASCII characters |

### Status Edge Cases
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| S1 | Rejected status | Alert evaluation status filter | NVD pages: `vulnStatus: "Rejected"` |
| S2 | RESERVED status | Incomplete CVE handling | MITRE ZIP: CVE with `state: "RESERVED"` |
| S3 | Disputed | Dispute flag handling | NVD pages: description containing `** DISPUTED **` |
| S4 | Withdrawn GHSA | Withdrawn status | GHSA pages: `withdrawn_at` non-null |

### Cross-Feed Overlap
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| X1 | In NVD + GHSA + OSV | Multi-source merge | Cross-reference: CVE ID appears in NVD pages AND GHSA pages AND OSV ZIP |
| X2 | In NVD + KEV | KEV flag + merge | Cross-reference: CVE ID in NVD pages AND KEV catalog |
| X3 | In NVD + MSRC | CSAF parsing + merge | Cross-reference: CVE ID in NVD pages AND MSRC CSAF docs |
| X4 | In NVD + Red Hat | Vendor enrichment + merge | Cross-reference: CVE ID in NVD pages AND Red Hat details |
| X5 | In NVD + GHSA + OSV + KEV | Maximum overlap | Cross-reference across all four |

### Feed-Specific Edge Cases
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| F1 | GHSA without CVE ID | Alias resolution, native ID as PK | GHSA pages: advisory where `cve_id` is null |
| F2 | OSV with non-CVE primary ID | Alias resolution, RUSTSEC/PYSEC as source_id | OSV ZIP: entry with ID like `RUSTSEC-*` and CVE in `aliases` |
| F3 | MSRC CSAF document | CSAF 2.0 parsing | MSRC captured CSAF doc (any) |
| F4 | Red Hat with fix available | Vendor enrichment fix_state | Red Hat details: `fix_state` non-empty |
| F5 | KEV entry with action required | KEV vendor enrichment | KEV catalog: entry with `requiredAction` field |

### EPSS Scoring
| ID | Category | What it tests | How to find in captured data |
|----|----------|--------------|----------------------------|
| E1 | High EPSS (>0.9) | EPSS evaluator threshold | EPSS CSV: sort by score descending, take top entries |
| E2 | Very low EPSS (<0.01) | Boundary behavior | EPSS CSV: entries with score < 0.01 |
| E3 | EPSS score = 0 | Zero-value handling | EPSS CSV: entry with score exactly 0 (if any exist) |

## Output Format

The agent produces a manifest file at `D:/Code/CVErt-Ops/data/feed-snapshots/manifest.json`:

```json
{
  "generated": "2026-03-11T14:30:00Z",
  "capture_date": "2026-03-11",
  "cves": [
    {
      "cve_id": "CVE-2024-3094",
      "categories": ["X1", "X2", "X5", "E1"],
      "feeds": ["nvd", "mitre", "ghsa", "osv", "kev", "epss"],
      "why": "xz backdoor — maximum cross-feed overlap, KEV-listed, high EPSS"
    }
  ],
  "category_coverage": {
    "C1": ["CVE-2024-3094"],
    "C2": ["CVE-..."]
  }
}
```

## Verification

After selection, every category MUST have at least one CVE. The agent should
print a coverage summary showing any gaps and attempt to fill them.
```

**Step 2: Commit**

```bash
git add dev/plans/test-fixture-edge-case-matrix.md
git commit -m "docs: add edge case matrix for test fixture CVE selection"
```

---

### Task 6: Run the CVE selection agent

**This is an agent research task.** A Claude agent reads the captured feed data locally and produces the manifest.

**Agent instructions (to be provided when launching the agent):**

```
You are selecting real CVEs from captured feed data to build a test fixture corpus.

READ FIRST:
- dev/plans/test-fixture-edge-case-matrix.md (defines all categories and how to find candidates)
- dev/plans/2026-03-11-test-fixture-corpus.md (overall plan context)

CAPTURED DATA LOCATIONS (all under D:/Code/CVErt-Ops/data/feed-snapshots/):
- nvd/*.body — NVD JSON response pages (one per file, raw NVD API JSON)
- nvd/*.meta.json — metadata for each NVD page (URL, status code, headers)
- kev/catalog.json — full KEV catalog (single JSON file)
- epss/scores.csv — EPSS scores (decompressed CSV, ~250k rows)
- ghsa/*.body — GHSA JSON response pages (one per file, JSON arrays of advisories)
- ghsa/*.meta.json — metadata for each GHSA page
- mitre/cvelistV5.zip — MITRE CVE list ZIP archive (~250k CVE JSON files)
- osv/all.zip — OSV bulk archive ZIP (entries per ecosystem)
- msrc/*.body — MSRC HTTP responses (updates list + CSAF documents)
- msrc/*.meta.json — metadata showing which URLs were fetched
- redhat/*.body — Red Hat HTTP responses (list pages + detail responses)
- redhat/*.meta.json — metadata showing which URLs were fetched

YOUR TASK:
1. Start with single-file feeds (KEV catalog, EPSS CSV) — these are quick to scan
   and give you a baseline set of CVE IDs to cross-reference.

2. Build cross-reference sets:
   - Read KEV catalog → extract all CVE IDs (set K)
   - Read EPSS CSV → extract high/low EPSS CVE IDs (sets E_high, E_low)
   - Scan NVD pages → for each CVE, note its properties (status, CVSS, CWEs, etc.)
   - Scan GHSA pages → extract CVE IDs and check for null cve_id advisories
   - For MITRE ZIP: use `unzip -l` to list entries, `unzip -p <zip> <entry>` to
     read specific CVE files without extracting the entire archive
   - For OSV ZIP: same approach — `unzip -l` then `unzip -p` for specific entries

3. Find CVEs matching each edge case category per the matrix.
   Prefer CVEs that cover multiple categories simultaneously.

4. Target 30-50 CVEs total. Every category must have at least one CVE.

5. Output the manifest to D:/Code/CVErt-Ops/data/feed-snapshots/manifest.json
   in the format specified in the matrix document.

6. ALSO copy the manifest into the repo for version control:
   cp D:/Code/CVErt-Ops/data/feed-snapshots/manifest.json dev/plans/test-fixture-manifest.json

7. Print a coverage summary showing which CVE covers which categories,
   and flag any categories with zero coverage.

IMPORTANT CONSTRAINTS:
- Do NOT hit any external APIs. All data is local.
- NVD body files are raw NVD API JSON responses. Search them with grep for
  CVE IDs, vulnStatus values, etc. Use `python -m json.tool` or `jq` if
  available for structured queries.
- EPSS CSV format: line 1 is a comment (#model_version:...,score_date:...),
  line 2 is the header (cve,epss,percentile), lines 3+ are data.
- For MSRC/Red Hat: the *.meta.json files show the URL that was fetched.
  Use this to identify which *.body files are updates lists vs CSAF docs
  (MSRC) or list pages vs detail pages (Red Hat).
- VERIFY every claim. If you say a CVE has CVSS v4.0, show the evidence
  from the captured data. Do not rely on training data for CVE specifics.
```

**Step 1: Launch the agent**

Launch a general-purpose agent with the instructions above.

**Step 2: Review the manifest**

After the agent completes, review `dev/plans/test-fixture-manifest.json`:
- Every category should have coverage
- Cross-reference CVEs should appear in multiple feeds
- Total should be 30-50 CVEs

**Step 3: Commit the manifest**

```bash
git add dev/plans/test-fixture-manifest.json
git commit -m "docs: add curated CVE manifest for test fixture corpus"
```

---

## Phase D: Fixture Extraction

### Task 7: Write the fixture extraction tool

This tool reads the manifest, finds each selected CVE in the captured data, and extracts just those entries into per-adapter `testdata/golden/` directories as compact fixture files.

**Files:**
- Create: `dev/cmd/extract-fixtures/main.go`

**CLI interface:**

```bash
go run ./dev/cmd/extract-fixtures/... \
  --manifest D:/Code/CVErt-Ops/data/feed-snapshots/manifest.json \
  --snapshots D:/Code/CVErt-Ops/data/feed-snapshots \
  --output .
```

The `--output .` means fixture files are written relative to the project root, at `internal/feed/<adapter>/testdata/golden/`.

**Output locations:**
```
internal/feed/nvd/testdata/golden/       — NVD fixture pages
internal/feed/ghsa/testdata/golden/      — GHSA fixture pages
internal/feed/kev/testdata/golden/       — filtered KEV catalog
internal/feed/epss/testdata/golden/      — filtered EPSS CSV (gzip compressed)
internal/feed/mitre/testdata/golden/     — curated MITRE ZIP
internal/feed/osv/testdata/golden/       — curated OSV ZIP
internal/feed/msrc/testdata/golden/      — MSRC fixtures (updates list + CSAF docs)
internal/feed/redhat/testdata/golden/    — Red Hat fixtures (list page + detail responses)
```

**Per-feed extraction logic:**

**NVD:** Scan each `nvd/*.body` file for CVE entries matching manifest CVE IDs. Extract matching `{"cve": {...}}` objects and group them into 1-2 synthetic response pages. Each page must be a valid NVD response envelope (see "NVD Response Envelope Structure" section above). Set `totalResults` to the actual number of CVEs in the page. Set `startIndex` to 0 for the first page, `resultsPerPage` to the count. Save as `page-001.json`, `page-002.json`.

**GHSA:** Scan each `ghsa/*.body` file for advisories matching manifest CVE IDs (match on `cve_id` field) or GHSA IDs specified in the manifest. Also include any advisories where `cve_id` is null (for category F1). Extract matching advisories into a JSON array. Save as `page-001.json`. The adapter expects a JSON array at the top level `[{advisory}, ...]`.

**KEV:** Read `kev/catalog.json`. Filter the `vulnerabilities` array to only entries whose `cveID` matches a manifest CVE ID. Preserve the catalog wrapper (`{catalogVersion, dateReleased, count, vulnerabilities: [...]}`, updating `count`). Save as `catalog.json`.

**EPSS:** Read `epss/scores.csv`. Copy line 1 (comment with model_version/score_date) and line 2 (header). Filter data rows to only CVE IDs in the manifest. Gzip-compress the result. Save as `scores.csv.gz`.

**MITRE:** Open `mitre/cvelistV5.zip`. For each manifest CVE ID, find the matching ZIP entry (path pattern: `cvelistV5-main/cves/YYYY/NNNxxx/CVE-YYYY-NNNNNNN.json`). Extract matching entries into a new, smaller ZIP with the same internal directory structure. Save as `cvelistV5.zip`.

**OSV:** Open `osv/all.zip`. For each manifest CVE ID, search for entries where the filename contains the CVE ID OR where the JSON content's `aliases` array contains the CVE ID. Extract matching entries into a new ZIP. Save as `all.zip`.

**MSRC:** Read `msrc/*.meta.json` to identify which body files are the updates list (URL contains `/updates`) vs CSAF documents (URL contains `/csaf/`). From the updates list, extract entries for releases that contain manifest CVE IDs. Copy the corresponding CSAF body files. Save as: `updates.json` (filtered updates list) and `csaf/<releaseID>.json` (CSAF documents).

**Red Hat:** Read `redhat/*.meta.json` to identify which body files are list pages (URL contains `/cve.json`) vs detail pages (URL contains `/cve/CVE-`). From detail pages, copy those whose URL contains a manifest CVE ID. Create a minimal list page referencing just those CVEs. Save as: `list.json` (synthetic list page) and `detail/<CVE-ID>.json` (detail responses).

**The extraction tool should print a summary:**
```
NVD:     extracted 35/42 CVEs into 2 pages
GHSA:    extracted 18/42 CVEs into 1 page (+ 2 GHSA-only advisories)
KEV:     extracted 8/42 CVEs
EPSS:    extracted 42/42 CVEs
MITRE:   extracted 40/42 CVEs
OSV:     extracted 22/42 CVEs
MSRC:    extracted 5/42 CVEs in 3 CSAF documents
Red Hat: extracted 7/42 CVEs
Missing from NVD: CVE-xxxx-yyyy, CVE-xxxx-zzzz (not in captured data — may be too new/old)
```

**Manifest Go struct** (for unmarshaling — the agent MUST use this in `dev/cmd/extract-fixtures/main.go`, `package main`):

```go
type Manifest struct {
	Generated    string        `json:"generated"`
	CaptureDate  string        `json:"capture_date"`
	CVEs         []ManifestCVE `json:"cves"`
	// CategoryCoverage is informational only — not needed by the extraction tool.
}

type ManifestCVE struct {
	CVEID      string   `json:"cve_id"`
	Categories []string `json:"categories"`
	Feeds      []string `json:"feeds"`
	Why        string   `json:"why"`
}
```

**Step 1: Implement the extraction tool**

The implementing agent should:
1. Use the `Manifest` struct above to unmarshal the manifest JSON
2. Read the "NVD Response Envelope Structure" section (above) for NVD page format
3. Read the "Adapter URL Constants Reference" section (above) for URL patterns
4. Implement each feed's extraction logic as described in the per-feed sections above
5. Include ABOUTME comments per project convention
6. For NVD body files: each `nvd/*.body` file is a full NVD API JSON response (see envelope structure). Use `json.Decoder` with `Token()`/`More()` to stream-parse the `vulnerabilities` array, extracting `{"cve": {...}}` objects where `cve.id` matches a manifest CVE ID

**Step 2: Run the extraction**

```bash
go run ./dev/cmd/extract-fixtures/... \
  --manifest D:/Code/CVErt-Ops/data/feed-snapshots/manifest.json \
  --snapshots D:/Code/CVErt-Ops/data/feed-snapshots \
  --output .
```

**Step 3: Verify the fixtures**

```bash
# Check that fixture files exist for each adapter
ls internal/feed/nvd/testdata/golden/
ls internal/feed/ghsa/testdata/golden/
ls internal/feed/kev/testdata/golden/
ls internal/feed/epss/testdata/golden/
ls internal/feed/mitre/testdata/golden/
ls internal/feed/osv/testdata/golden/
ls internal/feed/msrc/testdata/golden/
ls internal/feed/redhat/testdata/golden/

# Verify NVD fixture is valid JSON
python -m json.tool internal/feed/nvd/testdata/golden/page-001.json > /dev/null

# Verify total CVE count matches manifest
grep -o "CVE-[0-9]*-[0-9]*" internal/feed/nvd/testdata/golden/*.json | sort -u | wc -l
```

**Step 4: Commit the fixtures**

```bash
git add internal/feed/*/testdata/golden/
git commit -m "test: add golden file test fixtures from captured feed data"
```

---

## Phase E: Golden File Tests

### Task 8: URL-rewrite transport and golden file test helper

Each adapter has hardcoded upstream URLs. Golden file tests need a transport that intercepts requests to those URLs and redirects them to an httptest server serving fixture files. This task creates the shared infrastructure.

**Files:**
- Create: `internal/testutil/goldenserver.go`
- Create: `internal/testutil/goldenserver_test.go`

**Step 1: Write the failing test**

```go
// internal/testutil/goldenserver_test.go
package testutil_test

import (
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
	os.WriteFile(filepath.Join(dir, "page-001.json"), []byte(content), 0644)

	srv := testutil.NewGoldenServer(t, dir)

	resp, err := http.Get(srv.URL + "/page-001.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != content {
		t.Errorf("got %q, want %q", body, content)
	}
}

func TestURLRewriteTransport_RedirectsRequests(t *testing.T) {
	dir := t.TempDir()
	content := `{"result": "ok"}`
	os.WriteFile(filepath.Join(dir, "data.json"), []byte(content), 0644)

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
	resp, err := client.Get("https://api.example.com/data.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != content {
		t.Errorf("got %q, want %q", body, content)
	}
}
```

**Step 2: Run to verify it fails**

```bash
go test ./internal/testutil/... -run "TestGoldenServer|TestURLRewrite" -v
```
Expected: FAIL — `NewGoldenServer` and `NewURLRewriteTransport` undefined.

**Step 3: Implement the helpers**

```go
// internal/testutil/goldenserver.go
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

func (t *URLRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqURL := req.URL.String()
	if strings.HasPrefix(reqURL, t.OriginalBase) {
		// Rewrite the URL: replace the base, keep the path and query.
		newURL := t.RewriteBase + strings.TrimPrefix(reqURL, t.OriginalBase)
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
```

**Step 4: Run to verify it passes**

```bash
go test ./internal/testutil/... -run "TestGoldenServer|TestURLRewrite" -v
```
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/testutil/goldenserver.go internal/testutil/goldenserver_test.go
git commit -m "test: add golden file server and URL-rewrite transport helpers"
```

---

### Task 9: NVD golden file test (template for all adapters)

This task creates the golden file test for the NVD adapter. It serves as the template for other adapters.

**Files:**
- Create: `internal/feed/nvd/golden_test.go`

**How URL rewriting works for NVD:** The NVD adapter sends requests to `https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000&...`. The URLRewriteTransport rewrites `https://services.nvd.nist.gov` to `http://127.0.0.1:PORT`. The test server receives `GET /rest/json/cves/2.0?startIndex=0&...`. We serve a custom handler that ignores the query params and returns the fixture page sequentially (first request → page-001.json, second → page-002.json, etc.).

**Step 1: Write the golden file test**

```go
// internal/feed/nvd/golden_test.go
package nvd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestFetch_GoldenFiles runs the NVD adapter against captured real API responses.
// This catches upstream schema drift that hand-crafted test fixtures would miss.
func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Skipf("golden fixtures not found at %s (run extract-fixtures to generate): %v", goldenDir, err)
	}

	// Collect page files, sorted by name.
	var pages []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			pages = append(pages, filepath.Join(goldenDir, e.Name()))
		}
	}
	if len(pages) == 0 {
		t.Skipf("no .json fixture files in %s", goldenDir)
	}
	sort.Strings(pages)

	// IMPORTANT: If we got here, fixtures exist. The test must NOT skip from
	// this point — a skip would silently hide failures.

	// Serve pages sequentially: first fetch → first page, second → second page, etc.
	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(requestCount.Add(1)) - 1
		if idx >= len(pages) {
			http.Error(w, "no more fixture pages", http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(pages[idx])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The Date header provides effectiveNow for cursor pagination.
		// The NVD adapter uses effectiveNow from the response `timestamp` field
		// first, falling back to the Date header. Since the fixture's timestamp
		// field lacks a timezone suffix ("2026-03-11T10:00:00.000"), ParseTime
		// can't parse it — so effectiveNow comes from this Date header instead.
		// This MUST match the cursor's WindowEnd so computeNextCursor returns
		// LastPage=true after the first window.
		w.Header().Set("Date", "Tue, 11 Mar 2026 10:00:00 GMT")
		w.Write(data)
	}))
	t.Cleanup(srv.Close)

	// Rewrite NVD API URL to our test server.
	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://services.nvd.nist.gov",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := nvd.New(client)
	// Note: without NVD_API_KEY env var, the adapter rate-limits to 1 req/6s.
	// With just 1 fixture page, this adds ~6s to the test — acceptable.

	// IMPORTANT: Do NOT call Fetch with nil cursor — nil triggers a full-history
	// backfill from 2002 to now, creating ~73 time windows. Instead, construct a
	// cursor whose window covers a recent range so the adapter finishes in 1-2 pages.
	//
	// The Date header in the test server is "Tue, 11 Mar 2026 10:00:00 GMT", which
	// becomes effectiveNow. Set WindowStart/WindowEnd so that after all fixture
	// pages are consumed, the window end reaches effectiveNow → LastPage=true.
	//
	// The NVD adapter's windowMax is 120 days. Set a window that ends at or near
	// effectiveNow so computeNextCursor returns LastPage=true after the first window.
	// Window must be <= 120 days (NVD windowMax). Set WindowEnd close to
	// effectiveNow so computeNextCursor returns LastPage=true after one page.
	initialCursor, _ := json.Marshal(nvd.Cursor{
		WindowStart: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC), // matches Date header (~100 days)
		StartIndex:  0,
	})

	// Paginate until LastPage, collecting all patches.
	var allPatches []feed.CanonicalPatch
	cursor := json.RawMessage(initialCursor)
	for {
		result, err := adapter.Fetch(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Fetch failed: %v", err)
		}
		allPatches = append(allPatches, result.Patches...)
		if result.LastPage {
			break
		}
		cursor = result.NextCursor
	}

	if len(allPatches) == 0 {
		t.Fatal("expected patches from golden file, got 0")
	}

	// Verify each patch has required fields.
	for i, p := range allPatches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
	}

	t.Logf("parsed %d patches from golden files across %d request(s)",
		len(allPatches), requestCount.Load())
}
```

**Step 2: Run to verify it works (after fixtures exist from Task 7)**

```bash
go test ./internal/feed/nvd/... -run TestFetch_GoldenFiles -v
```

**IMPORTANT:** Verify the test output does NOT say `SKIP`. If it skips, the fixtures are missing — go back to Task 7.

**Step 3: Commit**

```bash
git add internal/feed/nvd/golden_test.go
git commit -m "test: add NVD golden file test against captured API responses"
```

---

### Task 10A: KEV golden file test

**Files:** Create `internal/feed/kev/golden_test.go`

**URL rewrite:** Rewrite `https://www.cisa.gov` → test server. The adapter GETs the full catalog URL. Serve `catalog.json` for any request.

**Test pattern:** Same as Task 9 but simpler — KEV is single-page, always returns `LastPage: true`. Verify patches include `InCISAKEV: true` and have `VendorEnrichment` set.

**Commit:** `test: add KEV golden file test`

### Task 10B: GHSA golden file test

**Files:** Create `internal/feed/ghsa/golden_test.go`

**URL rewrite:** Rewrite `https://api.github.com` → test server. The adapter paginates via Link headers. For a single-page fixture (most likely), the test handler simply omits the Link header → the adapter sees no `after` cursor → sets `LastPage: true`. If multiple fixture pages are needed, include `Link: <https://api.github.com/advisories?after=page2>; rel="next"` on all but the last response. The adapter extracts just the `after` query param value (not the full URL) and builds a new request to `advisoriesURL` with that param — the URL rewrite transport handles the redirect.

**Important:** The GHSA adapter expects a JSON array `[{advisory}, ...]` at the top level, NOT wrapped in an object. The adapter also requires `GITHUB_TOKEN` env var for the auth header — without it, the adapter still works but sends no Authorization header.

**Verify:** At least one advisory has `cve_id: null` (category F1). At least one has a CVE ID populated.

**Commit:** `test: add GHSA golden file test`

### Task 10C: MITRE golden file test

**Files:** Create `internal/feed/mitre/golden_test.go`

**URL rewrite:** Rewrite `https://github.com` → test server. Serve `cvelistV5.zip` for any request. The adapter downloads the ZIP to a temp file, then iterates entries.

**Verify:** Patches parsed from the ZIP. At least one RESERVED-status CVE present (category S2).

**Commit:** `test: add MITRE golden file test`

### Task 10D: OSV golden file test

**Files:** Create `internal/feed/osv/golden_test.go`

**URL rewrite:** Rewrite `https://osv-vulnerabilities.storage.googleapis.com` → test server. Serve `all.zip`. Same pattern as MITRE.

**Verify:** At least one patch has alias resolution (SourceID is not a CVE ID, CVEID is from aliases).

**Commit:** `test: add OSV golden file test`

### Task 10E: EPSS golden file test

**Files:** Create `internal/feed/epss/golden_test.go`

**EPSS is different** — it uses `Apply()` not `Fetch()`, and writes directly to the database. The golden file test should:
1. Serve `scores.csv.gz` via httptest
2. Create a test database (testcontainer)
3. Seed a few CVEs that appear in the fixture CSV (insert minimal CVE rows via direct SQL — the Apply method needs `cves` rows to exist for the `UPDATE ... WHERE epss_score IS DISTINCT FROM` pattern)
4. Create the EPSS adapter with a URL-rewriting client: `epss.New(&http.Client{Transport: testutil.NewURLRewriteTransport("https://epss.empiricalsecurity.com", srv.URL, http.DefaultTransport)})`
5. Call `adapter.Apply(ctx, db.DB(), nil)` — this downloads from the test server and applies scores
6. Query the database to verify EPSS scores were applied to the seeded CVEs

**URL rewrite:** Rewrite `https://epss.empiricalsecurity.com` → test server.

**Commit:** `test: add EPSS golden file test`

### Task 10F: MSRC golden file test

**Files:** Create `internal/feed/msrc/golden_test.go`

**URL rewrite:** Rewrite `https://api.msrc.microsoft.com` → test server. The adapter makes two types of requests:
1. `GET /cvrf/v3.0/updates?$filter=...` → serve `updates.json`
2. `GET /cvrf/v3.0/csaf/{releaseID}` → serve `csaf/<releaseID>.json`

The test server handler must route based on the request path.

**Verify:** VendorEnrichment populated on patches from CSAF documents.

**Commit:** `test: add MSRC golden file test`

### Task 10G: Red Hat golden file test

**Files:** Create `internal/feed/redhat/golden_test.go`

**URL rewrite:** Rewrite `https://access.redhat.com` → test server. The adapter makes two types of requests:
1. `GET /hydra/rest/securitydata/cve.json?after=...&page=...` → serve `list.json`
2. `GET /hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json` → serve `detail/<CVE-ID>.json`

The test server handler must route based on path: `/cve.json` → list, `/cve/CVE-*` → detail.

**Verify:** VendorEnrichment populated with vendor severity and fix state.

**Commit:** `test: add Red Hat golden file test`

---

### Task 10H: Verify full test suite

**After all golden file tests are committed:**

```bash
go test ./internal/feed/... -v -count=1
```

Verify:
1. All golden file tests RUN (not SKIP) for adapters with fixtures
2. All existing inline-JSON tests still pass
3. No compilation errors or import cycles

```bash
go test ./... -count=1
```

Verify the full test suite passes (or at least doesn't have new failures).

**Commit:** Nothing to commit — this is a verification step.

---

## Phase F: Seed Corpus Helper

### Task 11: Seed corpus integration helper

A test helper that runs all adapters against their golden fixtures, through the merge pipeline, into a test database. This gives integration tests a realistic, deterministic CVE corpus.

**Files:**
- Create: `internal/testutil/seedcorpus.go`
- Create: `internal/testutil/seedcorpus_test.go`

**Design:**

```go
// SeedStats reports what SeedCorpus populated.
type SeedStats struct {
	TotalCVEs  int      // total unique CVEs ingested across all feeds
	FeedsSeeded int     // number of feeds that had golden fixtures
	FeedNames  []string // names of feeds that were seeded (e.g., "nvd", "kev")
}
```

- `SeedCorpus(t *testing.T, db *TestDB) SeedStats` runs each adapter against its `testdata/golden/` fixtures
- Feeds patches through the real merge pipeline (not direct DB inserts)
- After seeding, the test DB contains the curated CVE set with proper source records, search index entries, and vendor enrichment
- Skips adapters whose `testdata/golden/` directory doesn't exist (graceful degradation)
- EPSS is handled separately: parse the CSV fixture and call the EPSS apply logic after CVEs are seeded from other feeds

**Key function signatures the implementing agent needs:**

The merge pipeline entry point is `merge.Ingest`. Its signature:
```go
func Ingest(ctx context.Context, s *store.Store, patch feed.CanonicalPatch, sourceName string) error
```
Note: it takes a **single** `CanonicalPatch`, NOT a slice. Loop over patches and call `Ingest` once per patch.

For EPSS, the adapter uses `Apply` (not `Fetch`):
```go
func (a *Adapter) Apply(ctx context.Context, db *sql.DB, cursorJSON json.RawMessage) (json.RawMessage, error)
```
Note: `Apply` takes `*sql.DB`, NOT `*store.Store`. Use `store.DB()` to get the underlying `*sql.DB`. `Apply` internally downloads the CSV from the upstream URL — so the EPSS adapter MUST be created with a URL-rewriting client (same pattern as other adapters) to redirect to the test server serving the golden `scores.csv.gz` fixture.

**Step 1: Write the failing test**

```go
// internal/testutil/seedcorpus_test.go
package testutil_test

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSeedCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}

	db := testutil.NewTestDB(t)

	stats := testutil.SeedCorpus(t, db)

	if stats.TotalCVEs == 0 {
		t.Fatal("SeedCorpus produced 0 CVEs")
	}
	if stats.FeedsSeeded == 0 {
		t.Fatal("SeedCorpus seeded 0 feeds")
	}

	t.Logf("seeded %d CVEs from %d feeds (%v)", stats.TotalCVEs, stats.FeedsSeeded, stats.FeedNames)
}
```

**Step 2: Implement**

The implementing agent should:
1. For each adapter (except EPSS) with `testdata/golden/`:
   a. Create an httptest server serving the golden fixtures (use `testutil.NewGoldenServer` for simple feeds, custom handler for paginated feeds like NVD/GHSA)
   b. Create the adapter with a URL-rewriting client: `adapter.New(&http.Client{Transport: testutil.NewURLRewriteTransport(originalURL, srv.URL, http.DefaultTransport)})`
   c. Call `Fetch()` in a loop until `result.LastPage == true`, collecting patches
   d. For each patch, call `merge.Ingest(ctx, store, patch, "source_name")` — one call per patch, NOT a batch
2. After all feed adapters are ingested, apply EPSS:
   a. Create EPSS adapter with URL-rewriting client pointing to test server serving `scores.csv.gz`
   b. Call `adapter.Apply(ctx, store.DB(), nil)` — uses `*sql.DB` from `store.DB()`, NOT `*store.Store`
3. Return `SeedStats{TotalCVEs, FeedsSeeded, FeedNames}`
4. The URL rewrite base per adapter (the `OriginalBase` parameter for `NewURLRewriteTransport`) — see the **Appendix: Adapter URL Rewrite Patterns** section at the end of this document for exact values per adapter (e.g., NVD = `https://services.nvd.nist.gov`, GHSA = `https://api.github.com`, etc.)

**Step 3: Test and commit**

```bash
go test ./internal/testutil/... -run TestSeedCorpus -v -count=1
```

Verify the test RUNS (not skips) and seeds a non-zero number of CVEs.

```bash
git add internal/testutil/seedcorpus.go internal/testutil/seedcorpus_test.go
git commit -m "test: add SeedCorpus helper for deterministic test data from golden fixtures"
```

---

## Phase G: Final Verification and Documentation

### Task 12: Full test suite verification

```bash
go test ./... -count=1
```

All tests should pass. If any golden file tests skip, the fixtures are missing — go back to Phase D.

### Task 13: Document the refresh process

Add a `## Refresh Process` section to this plan document (not a separate file):

The refresh process is:
1. Re-run the capture: `go run ./dev/cmd/capture-feeds/... all`
2. Re-run the selection agent (Task 6 instructions) against new captures
3. Re-run extraction: `go run ./dev/cmd/extract-fixtures/...`
4. Run all adapter tests: `go test ./internal/feed/...`
5. If tests pass, commit the updated fixtures
6. If tests fail, investigate — the upstream schema may have changed

**When to refresh:**
- When an adapter test breaks in a way suggesting upstream schema change
- When adding a new edge case category to the matrix
- When adding a new feed adapter

**Adding a new feed adapter:**
1. Add a capture case to `dev/cmd/capture-feeds/main.go`
2. Add extraction logic to `dev/cmd/extract-fixtures/main.go`
3. Add a `golden_test.go` to the new adapter package
4. Re-run capture and extraction to populate fixtures

---

## Dependency Graph

```
Task 1 (dirs) ─────────────┐
Task 2 (recording transport)┤
                             ├─→ Task 3 (capture CLI) ─→ Task 4 (run capture, manual)
Task 5 (edge case matrix) ──┘                                     │
                                                                   ↓
                                                Task 6 (agent selects CVEs)
                                                                   │
                                                                   ↓
                                                Task 7 (extraction tool)
                                                                   │
                                                                   ↓
                           Task 8 (golden helpers) ──→ Task 9 (NVD golden test)
                                                       │
                                                       ├─→ Tasks 10A-10G (parallel, one per adapter)
                                                       │
                                                       └─→ Task 10H (verify all tests)
                                                                   │
                                                                   ↓
                                                       Task 11 (seed corpus helper)
                                                                   │
                                                                   ↓
                                                       Task 12 (verify full suite)
                                                                   │
                                                                   ↓
                                                       Task 13 (refresh docs)
```

**Parallelizable tasks:**
- Tasks 1, 2, 5 are independent (can run in parallel)
- Tasks 10A-10G (per-adapter golden tests) — each adapter is independent
- Task 11 can start as soon as Task 9 + at least Task 10A are done

---

## Appendix: Adapter URL Rewrite Patterns

Quick reference for implementing golden file tests (Tasks 9, 10A-10G).

### NVD
- **Rewrite:** `https://services.nvd.nist.gov` → test server
- **Request pattern:** `GET /rest/json/cves/2.0?startIndex=N&resultsPerPage=2000&lastModStartDate=...&lastModEndDate=...`
- **Test handler:** Serve pages sequentially (ignore query params), include `Date` header
- **Fixture naming:** `page-001.json`, `page-002.json`

### GHSA
- **Rewrite:** `https://api.github.com` → test server
- **Request pattern:** `GET /advisories?per_page=100&sort=updated&direction=asc&updated=...`
- **Test handler:** Serve pages sequentially, include `Link: <URL>; rel="next"` header pointing to test server for all but last page
- **Fixture naming:** `page-001.json` (JSON array of advisories)

### KEV
- **Rewrite:** `https://www.cisa.gov` → test server
- **Request pattern:** `GET /sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Test handler:** Serve `catalog.json` for any request
- **Fixture naming:** `catalog.json`

### MITRE
- **Rewrite:** `https://github.com` → test server
- **Request pattern:** `GET /CVEProject/cvelistV5/archive/refs/heads/main.zip`
- **Test handler:** Serve `cvelistV5.zip` for any request
- **Fixture naming:** `cvelistV5.zip`

### OSV
- **Rewrite:** `https://osv-vulnerabilities.storage.googleapis.com` → test server
- **Request pattern:** `GET /all.zip`
- **Test handler:** Serve `all.zip` for any request
- **Fixture naming:** `all.zip`

### EPSS
- **Rewrite:** `https://epss.empiricalsecurity.com` → test server
- **Request pattern:** `GET /epss_scores-current.csv.gz` (may follow redirect)
- **Test handler:** Serve `scores.csv.gz` for any request
- **Fixture naming:** `scores.csv.gz`
- **Note:** EPSS uses `Apply()` not `Fetch()` — test pattern differs (needs DB)

### MSRC
- **Rewrite:** `https://api.msrc.microsoft.com` → test server
- **Request patterns:**
  - `GET /cvrf/v3.0/updates?$filter=...` → serve `updates.json`
  - `GET /cvrf/v3.0/csaf/{releaseID}` → serve `csaf/{releaseID}.json`
- **Test handler:** Route by path prefix (`/cvrf/v3.0/updates` vs `/cvrf/v3.0/csaf/`)
- **Fixture naming:** `updates.json`, `csaf/<id>.json`

### Red Hat
- **Rewrite:** `https://access.redhat.com` → test server
- **Request patterns:**
  - `GET /hydra/rest/securitydata/cve.json?after=...&page=...` → serve `list.json`
  - `GET /hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json` → serve `detail/CVE-YYYY-NNNN.json`
- **Test handler:** Route by path: `/cve.json` → list, `/cve/CVE-*` → detail lookup
- **Fixture naming:** `list.json`, `detail/CVE-YYYY-NNNN.json`
