// ABOUTME: Unit tests for the NVD feed adapter's pure parse/convert functions.
// ABOUTME: Covers cursor parsing, cursor advancement, streaming response parsing, CVE conversion, and CVSS selection.
package nvd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestParseCursor(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns zero value cursor", func(t *testing.T) {
		t.Parallel()
		cur, err := parseCursor(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cur.WindowStart.IsZero() {
			t.Fatal("WindowStart should not be zero for zero-value cursor")
		}
		if cur.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0", cur.StartIndex)
		}
	})

	t.Run("empty input returns zero value cursor", func(t *testing.T) {
		t.Parallel()
		cur, err := parseCursor(json.RawMessage{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cur.WindowStart.IsZero() {
			t.Fatal("WindowStart should not be zero for zero-value cursor")
		}
		if cur.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0", cur.StartIndex)
		}
	})

	t.Run("valid cursor JSON parsed correctly", func(t *testing.T) {
		t.Parallel()
		raw := json.RawMessage(`{
			"window_start": "2024-01-15T00:00:00Z",
			"window_end":   "2024-05-14T00:00:00Z",
			"start_index":  4000
		}`)
		cur, err := parseCursor(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantStart := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		if !cur.WindowStart.Equal(wantStart) {
			t.Fatalf("WindowStart = %v, want %v", cur.WindowStart, wantStart)
		}
		wantEnd := time.Date(2024, 5, 14, 0, 0, 0, 0, time.UTC)
		if !cur.WindowEnd.Equal(wantEnd) {
			t.Fatalf("WindowEnd = %v, want %v", cur.WindowEnd, wantEnd)
		}
		if cur.StartIndex != 4000 {
			t.Fatalf("StartIndex = %d, want 4000", cur.StartIndex)
		}
	})

	t.Run("zero WindowStart in JSON falls back to zero value cursor", func(t *testing.T) {
		t.Parallel()
		raw := json.RawMessage(`{
			"window_start": "0001-01-01T00:00:00Z",
			"window_end":   "2024-05-14T00:00:00Z",
			"start_index":  100
		}`)
		cur, err := parseCursor(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should fall back to zero-value cursor (epoch 2002).
		if cur.WindowStart.IsZero() {
			t.Fatal("WindowStart should not be zero for zero-value cursor")
		}
		if cur.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0 (zero-value cursor resets it)", cur.StartIndex)
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		t.Parallel()
		raw := json.RawMessage(`{not valid json}`)
		_, err := parseCursor(raw)
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}

func TestComputeNextCursor(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("more pages in current window", func(t *testing.T) {
		t.Parallel()
		cur := Cursor{
			WindowStart: baseTime.Add(-48 * time.Hour),
			WindowEnd:   baseTime,
			StartIndex:  0,
		}
		next, lastPage := computeNextCursor(cur, 5000, baseTime.Add(time.Hour))
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if lastPage {
			t.Error("expected lastPage=false for mid-window pagination")
		}
		if next.StartIndex != resultsPerPage {
			t.Fatalf("StartIndex = %d, want %d", next.StartIndex, resultsPerPage)
		}
		if !next.WindowStart.Equal(cur.WindowStart) {
			t.Fatalf("WindowStart changed: got %v, want %v", next.WindowStart, cur.WindowStart)
		}
		if !next.WindowEnd.Equal(cur.WindowEnd) {
			t.Fatalf("WindowEnd changed: got %v, want %v", next.WindowEnd, cur.WindowEnd)
		}
	})

	t.Run("window exhausted next window available", func(t *testing.T) {
		t.Parallel()
		windowStart := baseTime.Add(-48 * time.Hour)
		windowEnd := baseTime
		effectiveNow := baseTime.Add(72 * time.Hour)

		cur := Cursor{
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
			StartIndex:  0,
		}
		next, lastPage := computeNextCursor(cur, 100, effectiveNow)
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if lastPage {
			t.Error("expected lastPage=false when more windows available")
		}
		if next.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0 for new window", next.StartIndex)
		}
		// 15-minute overlap applied.
		wantStart := windowEnd.Add(-overlapDuration)
		if !next.WindowStart.Equal(wantStart) {
			t.Fatalf("WindowStart = %v, want %v (with overlap)", next.WindowStart, wantStart)
		}
	})

	t.Run("window exhausted reached effectiveNow returns caught-up cursor", func(t *testing.T) {
		t.Parallel()
		cur := Cursor{
			WindowStart: baseTime.Add(-48 * time.Hour),
			WindowEnd:   baseTime,
			StartIndex:  0,
		}
		// effectiveNow is at or before the window end — no more windows.
		// Should still return a non-nil "caught up" cursor for persistence.
		next, lastPage := computeNextCursor(cur, 100, baseTime)
		if next == nil {
			t.Fatal("expected non-nil caught-up cursor")
		}
		if !lastPage {
			t.Error("expected lastPage=true when all windows exhausted")
		}
		// Caught-up cursor starts from WindowEnd minus overlap.
		wantStart := baseTime.Add(-overlapDuration)
		if !next.WindowStart.Equal(wantStart) {
			t.Errorf("WindowStart = %v, want %v", next.WindowStart, wantStart)
		}
		if !next.WindowEnd.Equal(baseTime) {
			t.Errorf("WindowEnd = %v, want %v", next.WindowEnd, baseTime)
		}
		if next.StartIndex != 0 {
			t.Errorf("StartIndex = %d, want 0", next.StartIndex)
		}
	})

	t.Run("window end within the overlap of effectiveNow returns caught-up cursor", func(t *testing.T) {
		t.Parallel()
		cur := Cursor{
			WindowStart: baseTime.Add(-48 * time.Hour),
			WindowEnd:   baseTime,
		}
		effectiveNow := baseTime.Add(2 * time.Second)
		next, lastPage := computeNextCursor(cur, 100, effectiveNow)
		if !lastPage {
			t.Error("expected lastPage=true: a next window would only re-read this one")
		}
		if !next.WindowStart.Equal(baseTime.Add(-overlapDuration)) {
			t.Errorf("WindowStart = %v, want %v", next.WindowStart, baseTime.Add(-overlapDuration))
		}
		// The next run starts here, so modifications after baseTime are not skipped.
		if !next.WindowEnd.Equal(effectiveNow) {
			t.Errorf("WindowEnd = %v, want %v", next.WindowEnd, effectiveNow)
		}
	})

	t.Run("15 minute overlap applied to next window start", func(t *testing.T) {
		t.Parallel()
		windowEnd := baseTime
		effectiveNow := baseTime.Add(200 * 24 * time.Hour)

		cur := Cursor{
			WindowStart: baseTime.Add(-10 * 24 * time.Hour),
			WindowEnd:   windowEnd,
			StartIndex:  0,
		}
		next, lastPage := computeNextCursor(cur, 0, effectiveNow)
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if lastPage {
			t.Error("expected lastPage=false when more windows available")
		}
		wantStart := windowEnd.Add(-overlapDuration)
		if !next.WindowStart.Equal(wantStart) {
			t.Fatalf("WindowStart = %v, want %v (overlap)", next.WindowStart, wantStart)
		}
	})

	t.Run("next window end capped to effectiveNow", func(t *testing.T) {
		t.Parallel()
		windowEnd := baseTime
		// effectiveNow is less than windowMax from the next window start,
		// so end should be capped.
		effectiveNow := baseTime.Add(24 * time.Hour)

		cur := Cursor{
			WindowStart: baseTime.Add(-10 * 24 * time.Hour),
			WindowEnd:   windowEnd,
			StartIndex:  0,
		}
		next, lastPage := computeNextCursor(cur, 0, effectiveNow)
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if lastPage {
			t.Error("expected lastPage=false when more windows available")
		}
		if !next.WindowEnd.Equal(effectiveNow) {
			t.Fatalf("WindowEnd = %v, want %v (capped to effectiveNow)", next.WindowEnd, effectiveNow)
		}
	})
}

// CaughtUp says the first full walk has reached the present, which the version
// check endpoint reads as NVD data being complete. Once set it stays set.
func TestComputeNextCursor_CaughtUp(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	window := func(caughtUp bool) Cursor {
		return Cursor{WindowStart: baseTime.Add(-48 * time.Hour), WindowEnd: baseTime, CaughtUp: caughtUp}
	}

	t.Run("partway through a window", func(t *testing.T) {
		t.Parallel()
		next, lastPage := computeNextCursor(window(false), 5000, baseTime.Add(time.Hour))
		if lastPage || next.CaughtUp {
			t.Errorf("lastPage = %v, CaughtUp = %v, want both false", lastPage, next.CaughtUp)
		}
	})

	t.Run("next window of a first walk", func(t *testing.T) {
		t.Parallel()
		next, lastPage := computeNextCursor(window(false), 100, baseTime.Add(72*time.Hour))
		if lastPage || next.CaughtUp {
			t.Errorf("lastPage = %v, CaughtUp = %v, want both false", lastPage, next.CaughtUp)
		}
	})

	t.Run("all windows processed", func(t *testing.T) {
		t.Parallel()
		next, lastPage := computeNextCursor(window(false), 100, baseTime)
		if !lastPage || !next.CaughtUp {
			t.Errorf("lastPage = %v, CaughtUp = %v, want both true", lastPage, next.CaughtUp)
		}
	})

	t.Run("more pages keep CaughtUp", func(t *testing.T) {
		t.Parallel()
		next, _ := computeNextCursor(window(true), 5000, baseTime.Add(time.Hour))
		if !next.CaughtUp {
			t.Error("CaughtUp = false after the more-pages path, want true")
		}
	})

	t.Run("next window keeps CaughtUp", func(t *testing.T) {
		t.Parallel()
		next, lastPage := computeNextCursor(window(true), 100, baseTime.Add(72*time.Hour))
		if lastPage {
			t.Fatal("lastPage = true, want the next-window path")
		}
		if !next.CaughtUp {
			t.Error("CaughtUp = false after the next-window path, want true")
		}
	})
}

func TestCursorCaughtUpJSON(t *testing.T) {
	t.Parallel()

	start := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	b, err := json.Marshal(Cursor{WindowStart: start, WindowEnd: start.Add(time.Hour), CaughtUp: true})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["caught_up"] != true {
		t.Errorf("JSON = %s, want caught_up true", b)
	}
	cur, err := parseCursor(b)
	if err != nil {
		t.Fatalf("parseCursor: %v", err)
	}
	if !cur.CaughtUp {
		t.Error("parseCursor lost caught_up")
	}

	b, err = json.Marshal(Cursor{WindowStart: start, WindowEnd: start.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "caught_up") {
		t.Errorf("JSON = %s, want caught_up omitted while false", b)
	}
	if zeroValueCursor().CaughtUp {
		t.Error("a cleared cursor starts caught up, want false")
	}
}

func TestParseNVDResponse(t *testing.T) {
	t.Parallel()

	t.Run("valid response with metadata and vulnerabilities", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 2,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2024-0001",
						"vulnStatus": "Analyzed",
						"published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-02-01T00:00:00.000",
						"descriptions": [
							{"lang": "en", "value": "A test vuln"}
						]
					}
				},
				{
					"cve": {
						"id": "CVE-2024-0002",
						"vulnStatus": "Modified",
						"published": "2024-03-01T00:00:00.000",
						"lastModified": "2024-04-01T00:00:00.000",
						"descriptions": [
							{"lang": "en", "value": "Another vuln"}
						]
					}
				}
			]
		}`
		patches, total, ts, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 2 {
			t.Fatalf("totalResults = %d, want 2", total)
		}
		if ts.IsZero() {
			t.Fatal("timestamp should not be zero")
		}
		if len(patches) != 2 {
			t.Fatalf("len(patches) = %d, want 2", len(patches))
		}
		if patches[0].CVEID != "CVE-2024-0001" {
			t.Fatalf("patches[0].CVEID = %q, want CVE-2024-0001", patches[0].CVEID)
		}
		if patches[1].CVEID != "CVE-2024-0002" {
			t.Fatalf("patches[1].CVEID = %q, want CVE-2024-0002", patches[1].CVEID)
		}
	})

	t.Run("empty vulnerabilities array", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 0,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": []
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 0 {
			t.Fatalf("totalResults = %d, want 0", total)
		}
		if len(patches) != 0 {
			t.Fatalf("len(patches) = %d, want 0", len(patches))
		}
	})

	t.Run("response with only metadata no vulnerabilities key", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 42,
			"timestamp": "2024-06-01T12:00:00.000"
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 42 {
			t.Fatalf("totalResults = %d, want 42", total)
		}
		if len(patches) != 0 {
			t.Fatalf("len(patches) = %d, want 0", len(patches))
		}
	})

	t.Run("empty body returns error", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := parseNVDResponse(strings.NewReader(""))
		if err == nil {
			t.Fatal("expected error for empty body, got nil")
		}
	})

	t.Run("unknown keys discarded without error", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 1,
			"timestamp": "2024-06-01T12:00:00.000",
			"unknownField": "should be ignored",
			"anotherUnknown": 42,
			"nestedUnknown": {"key": "value"},
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2024-9001",
						"vulnStatus": "Analyzed",
						"descriptions": [{"lang": "en", "value": "Test vuln"}]
					}
				}
			]
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 1 {
			t.Fatalf("totalResults = %d, want 1", total)
		}
		if len(patches) != 1 {
			t.Fatalf("len(patches) = %d, want 1", len(patches))
		}
		if patches[0].CVEID != "CVE-2024-9001" {
			t.Fatalf("patches[0].CVEID = %q, want CVE-2024-9001", patches[0].CVEID)
		}
	})

	t.Run("malformed individual records skipped", func(t *testing.T) {
		// Not parallel: captures global slog.Default.

		var buf bytes.Buffer
		origHandler := slog.Default().Handler()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

		body := `{
			"totalResults": 3,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2024-0001",
						"vulnStatus": "Analyzed",
						"descriptions": [{"lang": "en", "value": "Good record"}]
					}
				},
				"this is not a valid json object",
				{
					"cve": {
						"id": "CVE-2024-0003",
						"vulnStatus": "Modified",
						"descriptions": [{"lang": "en", "value": "After bad record"}]
					}
				}
			]
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 3 {
			t.Fatalf("totalResults = %d, want 3", total)
		}
		// The malformed string record is skipped; we get the two valid CVEs.
		if len(patches) != 2 {
			t.Fatalf("len(patches) = %d, want 2 (malformed record skipped)", len(patches))
		}
		if patches[0].CVEID != "CVE-2024-0001" {
			t.Fatalf("patches[0].CVEID = %q, want CVE-2024-0001", patches[0].CVEID)
		}
		if patches[1].CVEID != "CVE-2024-0003" {
			t.Fatalf("patches[1].CVEID = %q, want CVE-2024-0003", patches[1].CVEID)
		}
		if !strings.Contains(buf.String(), "skipping malformed record") {
			t.Errorf("expected warning log about skipped record, got: %s", buf.String())
		}
	})

	t.Run("body that ends inside a record returns an error", func(t *testing.T) {
		t.Parallel()
		// A connection closed mid-page: the decoder's error is sticky, so a
		// skip-and-continue loop would spin on the unread record forever.
		body := `{
			"totalResults": 2,
			"vulnerabilities": [
				{"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "Good record"}]}},
				{"cve": {"id": "CVE-2024-00`
		type result struct {
			patches []feed.CanonicalPatch
			err     error
		}
		done := make(chan result, 1)
		go func() {
			patches, _, _, err := parseNVDResponse(strings.NewReader(body))
			done <- result{patches, err}
		}()
		select {
		case r := <-done:
			if !errors.Is(r.err, io.ErrUnexpectedEOF) {
				t.Fatalf("err = %v, want io.ErrUnexpectedEOF", r.err)
			}
			if r.patches != nil {
				t.Fatalf("patches = %d, want none from a truncated page", len(r.patches))
			}
		case <-time.After(5 * time.Second):
			t.Fatal("parseNVDResponse did not return on a truncated body")
		}
	})

	t.Run("syntax error stops stream with partial results", func(t *testing.T) {
		// Not parallel: captures global slog.Default.

		var buf bytes.Buffer
		origHandler := slog.Default().Handler()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

		body := `{
			"totalResults": 3,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2024-0001",
						"vulnStatus": "Analyzed",
						"descriptions": [{"lang": "en", "value": "Good record"}]
					}
				},
				{INVALID_JSON},
				{
					"cve": {
						"id": "CVE-2024-0003",
						"vulnStatus": "Modified",
						"descriptions": [{"lang": "en", "value": "After bad record"}]
					}
				}
			]
		}`
		patches, _, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("expected no error (syntax error breaks loop, returns partial), got: %v", err)
		}
		if len(patches) != 1 {
			t.Fatalf("len(patches) = %d, want 1 (only first record before syntax error)", len(patches))
		}
		if patches[0].CVEID != "CVE-2024-0001" {
			t.Errorf("patches[0].CVEID = %q, want CVE-2024-0001", patches[0].CVEID)
		}
		if !strings.Contains(buf.String(), "syntax error") {
			t.Errorf("expected warning log about syntax error, got: %s", buf.String())
		}
	})
}

func TestCveToCanonical(t *testing.T) {
	t.Parallel()

	t.Run("normal record with all fields", func(t *testing.T) {
		t.Parallel()
		cve := nvdCVE{
			ID:           "CVE-2024-1234",
			VulnStatus:   "Analyzed",
			Published:    "2024-01-15T10:00:00.000",
			LastModified: "2024-02-20T14:30:00.000",
			Descriptions: []nvdDescription{
				{Lang: "en", Value: "Buffer overflow in example"},
				{Lang: "es", Value: "Desbordamiento de búfer en ejemplo"},
			},
			Weaknesses: []nvdWeakness{
				{Description: []nvdDescription{
					{Lang: "en", Value: "CWE-120"},
				}},
			},
			Configurations: []nvdConfig{
				{Nodes: []nvdNode{
					{CPEMatch: []nvdCPEMatch{
						{Criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", Vulnerable: true},
					}},
				}},
			},
			References: []nvdReference{
				{URL: "https://example.com/advisory", Tags: []string{"Vendor Advisory"}},
			},
			Metrics: nvdMetrics{
				CVSSV31: []nvdCVSSMetric{
					{
						Source: "nvd@nist.gov",
						CVSSData: nvdCVSSData{
							Version:      "3.1",
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							BaseScore:    9.8,
							BaseSeverity: "Critical",
						},
					},
				},
			},
		}

		p := cveToCanonical(cve)
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.CVEID != "CVE-2024-1234" {
			t.Fatalf("CVEID = %q, want CVE-2024-1234", p.CVEID)
		}
		if p.SourceID != "CVE-2024-1234" {
			t.Fatalf("SourceID = %q, want CVE-2024-1234", p.SourceID)
		}
		if p.Status != "Analyzed" {
			t.Fatalf("Status = %q, want Analyzed", p.Status)
		}
		if p.IsWithdrawn {
			t.Fatal("IsWithdrawn should be false for Analyzed status")
		}
		if p.DatePublished == nil {
			t.Fatal("DatePublished should not be nil")
		}
		if p.DateModified == nil {
			t.Fatal("DateModified should not be nil")
		}
		if p.DescriptionPrimary == nil || *p.DescriptionPrimary != "Buffer overflow in example" {
			t.Fatalf("DescriptionPrimary = %v, want 'Buffer overflow in example'", p.DescriptionPrimary)
		}
		if len(p.CWEIDs) != 1 || p.CWEIDs[0] != "CWE-120" {
			t.Fatalf("CWEIDs = %v, want [CWE-120]", p.CWEIDs)
		}
		if len(p.AffectedCPEs) != 1 {
			t.Fatalf("len(AffectedCPEs) = %d, want 1", len(p.AffectedCPEs))
		}
		if p.AffectedCPEs[0].CPE != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
			t.Fatalf("CPE = %q, unexpected", p.AffectedCPEs[0].CPE)
		}
		if len(p.References) != 1 || p.References[0].URL != "https://example.com/advisory" {
			t.Fatalf("References = %v, unexpected", p.References)
		}
		if p.CVSSv3Score == nil || *p.CVSSv3Score != 9.8 {
			t.Fatalf("CVSSv3Score = %v, want 9.8", p.CVSSv3Score)
		}
		if p.CVSSv3Vector == nil || *p.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
			t.Fatalf("CVSSv3Vector = %v, unexpected", p.CVSSv3Vector)
		}
		if p.Severity == nil || *p.Severity != "CRITICAL" {
			t.Fatalf("Severity = %v, want CRITICAL", p.Severity)
		}
	})

	t.Run("empty ID returns nil", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{ID: ""})
		if p != nil {
			t.Fatalf("expected nil for empty ID, got %+v", p)
		}
	})

	t.Run("rejected status sets IsWithdrawn", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID:         "CVE-2024-9999",
			VulnStatus: "Rejected",
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if !p.IsWithdrawn {
			t.Fatal("IsWithdrawn should be true for Rejected status")
		}
	})

	t.Run("english description selected non-english skipped", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5000",
			Descriptions: []nvdDescription{
				{Lang: "es", Value: "Una vulnerabilidad critica"},
				{Lang: "en", Value: "English description"},
				{Lang: "fr", Value: "Description en francais"},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.DescriptionPrimary == nil {
			t.Fatal("DescriptionPrimary should not be nil")
		}
		if *p.DescriptionPrimary != "English description" {
			t.Fatalf("DescriptionPrimary = %q, want 'English description'", *p.DescriptionPrimary)
		}
	})

	t.Run("CWE deduplication and prefix filtering", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5001",
			Weaknesses: []nvdWeakness{
				{Description: []nvdDescription{
					{Lang: "en", Value: "CWE-79"},
					{Lang: "en", Value: "NVD-CWE-Other"},
				}},
				{Description: []nvdDescription{
					{Lang: "en", Value: "CWE-79"},
					{Lang: "en", Value: "CWE-89"},
				}},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		// CWE-79 appears twice, NVD-CWE-Other should be excluded (no CWE- prefix).
		if len(p.CWEIDs) != 2 {
			t.Fatalf("len(CWEIDs) = %d, want 2, got %v", len(p.CWEIDs), p.CWEIDs)
		}
		cweSet := make(map[string]bool)
		for _, id := range p.CWEIDs {
			cweSet[id] = true
		}
		if !cweSet["CWE-79"] {
			t.Fatal("CWE-79 should be present")
		}
		if !cweSet["CWE-89"] {
			t.Fatal("CWE-89 should be present")
		}
	})

	t.Run("CPE deduplication by normalized form", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5002",
			Configurations: []nvdConfig{
				{Nodes: []nvdNode{
					{CPEMatch: []nvdCPEMatch{
						{Criteria: "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"},
						{Criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
						{Criteria: "cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		// First two CPEs normalize to the same lowercase string, so deduplicated.
		if len(p.AffectedCPEs) != 2 {
			t.Fatalf("len(AffectedCPEs) = %d, want 2, got %v", len(p.AffectedCPEs), p.AffectedCPEs)
		}
	})

	t.Run("references with empty URL skipped", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5003",
			References: []nvdReference{
				{URL: "https://example.com/valid"},
				{URL: ""},
				{URL: "https://example.com/also-valid"},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(p.References) != 2 {
			t.Fatalf("len(References) = %d, want 2", len(p.References))
		}
		if p.References[0].URL != "https://example.com/valid" {
			t.Fatalf("References[0].URL = %q, unexpected", p.References[0].URL)
		}
		if p.References[1].URL != "https://example.com/also-valid" {
			t.Fatalf("References[1].URL = %q, unexpected", p.References[1].URL)
		}
	})

	t.Run("no english description yields nil DescriptionPrimary", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5004",
			Descriptions: []nvdDescription{
				{Lang: "es", Value: "Solo español"},
				{Lang: "fr", Value: "Seulement français"},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.DescriptionPrimary != nil {
			t.Errorf("DescriptionPrimary = %q, want nil (no english descriptions)", *p.DescriptionPrimary)
		}
	})

	t.Run("multiple english descriptions selects first", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5005",
			Descriptions: []nvdDescription{
				{Lang: "en", Value: "First English"},
				{Lang: "en", Value: "Second English"},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.DescriptionPrimary == nil {
			t.Fatal("DescriptionPrimary should not be nil")
		}
		if *p.DescriptionPrimary != "First English" {
			t.Errorf("DescriptionPrimary = %q, want %q", *p.DescriptionPrimary, "First English")
		}
	})

	t.Run("CPE normalized to lowercase", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5006",
			Configurations: []nvdConfig{
				{Nodes: []nvdNode{
					{CPEMatch: []nvdCPEMatch{
						{Criteria: "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(p.AffectedCPEs) != 1 {
			t.Fatalf("len(AffectedCPEs) = %d, want 1", len(p.AffectedCPEs))
		}
		// Original case preserved in CPE field.
		if p.AffectedCPEs[0].CPE != "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*" {
			t.Errorf("CPE = %q, want original case preserved", p.AffectedCPEs[0].CPE)
		}
		// Normalized form is lowercase.
		if p.AffectedCPEs[0].CPENormalized != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
			t.Errorf("CPENormalized = %q, want lowercase", p.AffectedCPEs[0].CPENormalized)
		}
	})
}

func TestCveToCanonical_MalformedAffectedKeepsTheCVE(t *testing.T) {
	t.Parallel()

	for _, affected := range []string{`"not an array"`, `[{"source": 7}]`} {
		p := cveToCanonical(nvdCVE{
			ID:               "CVE-2024-5008",
			SourceIdentifier: "cna@example.com",
			Affected:         json.RawMessage(affected),
		})
		if p == nil || p.CVEID != "CVE-2024-5008" {
			t.Fatalf("affected %s: patch = %+v, want the CVE kept", affected, p)
		}
		if len(p.CNAAffected) != 0 {
			t.Errorf("affected %s: CNAAffected = %+v, want none", affected, p.CNAAffected)
		}
	}
}

func TestCveToCanonical_CPEMatchesStripNullBytes(t *testing.T) {
	t.Parallel()

	p := cveToCanonical(nvdCVE{
		ID: "CVE-2024-5007",
		Configurations: []nvdConfig{{Nodes: []nvdNode{{CPEMatch: []nvdCPEMatch{{
			Criteria:              "cpe:2.3:a:vendor:\x00product:*:*:*:*:*:*:*:*",
			VersionStartIncluding: "1.\x000",
			VersionStartExcluding: "1.\x001",
			VersionEndIncluding:   "2.\x000",
			VersionEndExcluding:   "2.\x001",
			Vulnerable:            true,
		}}}}}},
	})

	want := feed.CPEMatch{
		CPE:                   "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
		CPENormalized:         "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "1.0",
		VersionStartExcluding: "1.1",
		VersionEndIncluding:   "2.0",
		VersionEndExcluding:   "2.1",
		Vulnerable:            true,
	}
	if len(p.CPEMatches) != 1 || p.CPEMatches[0] != want {
		t.Errorf("CPEMatches = %+v, want [%+v]", p.CPEMatches, want)
	}
}

func TestCveToCanonical_NullByteStripping(t *testing.T) {
	t.Parallel()

	cve := nvdCVE{
		ID:           "CVE-2024\x00-5555",
		VulnStatus:   "Ana\x00lyzed",
		Published:    "2024-01-15T10:00:00.000",
		LastModified: "2024-02-20T14:30:00.000",
		Descriptions: []nvdDescription{
			{Lang: "en", Value: "Buffer\x00 overflow in example"},
		},
		Weaknesses: []nvdWeakness{
			{Description: []nvdDescription{
				{Lang: "en", Value: "CWE-\x00120"},
			}},
		},
		References: []nvdReference{
			{URL: "https://example\x00.com/advisory", Tags: []string{"Vendor Advisory"}},
		},
		Configurations: []nvdConfig{
			{Nodes: []nvdNode{
				{CPEMatch: []nvdCPEMatch{
					{Criteria: "cpe:2.3:a:\x00vendor:product:1.0:*:*:*:*:*:*:*", Vulnerable: true},
				}},
			}},
		},
	}

	p := cveToCanonical(cve)
	if p == nil {
		t.Fatal("expected non-nil patch")
	}

	if strings.Contains(p.CVEID, "\x00") {
		t.Errorf("CVEID contains null byte: %q", p.CVEID)
	}
	if p.CVEID != "CVE-2024-5555" {
		t.Errorf("CVEID = %q, want %q", p.CVEID, "CVE-2024-5555")
	}

	if strings.Contains(p.SourceID, "\x00") {
		t.Errorf("SourceID contains null byte: %q", p.SourceID)
	}

	if strings.Contains(p.Status, "\x00") {
		t.Errorf("Status contains null byte: %q", p.Status)
	}
	if p.Status != "Analyzed" {
		t.Errorf("Status = %q, want %q", p.Status, "Analyzed")
	}

	if p.DescriptionPrimary == nil {
		t.Fatal("DescriptionPrimary is nil")
	}
	if strings.Contains(*p.DescriptionPrimary, "\x00") {
		t.Errorf("DescriptionPrimary contains null byte: %q", *p.DescriptionPrimary)
	}
	if *p.DescriptionPrimary != "Buffer overflow in example" {
		t.Errorf("DescriptionPrimary = %q, want %q", *p.DescriptionPrimary, "Buffer overflow in example")
	}

	if len(p.CWEIDs) != 1 {
		t.Fatalf("CWEIDs len = %d, want 1", len(p.CWEIDs))
	}
	if strings.Contains(p.CWEIDs[0], "\x00") {
		t.Errorf("CWEIDs[0] contains null byte: %q", p.CWEIDs[0])
	}
	if p.CWEIDs[0] != "CWE-120" {
		t.Errorf("CWEIDs[0] = %q, want %q", p.CWEIDs[0], "CWE-120")
	}

	if len(p.References) != 1 {
		t.Fatalf("References len = %d, want 1", len(p.References))
	}
	if strings.Contains(p.References[0].URL, "\x00") {
		t.Errorf("References[0].URL contains null byte: %q", p.References[0].URL)
	}
	if p.References[0].URL != "https://example.com/advisory" {
		t.Errorf("References[0].URL = %q, want %q", p.References[0].URL, "https://example.com/advisory")
	}

	if len(p.AffectedCPEs) != 1 {
		t.Fatalf("AffectedCPEs len = %d, want 1", len(p.AffectedCPEs))
	}
	if strings.Contains(p.AffectedCPEs[0].CPE, "\x00") {
		t.Errorf("AffectedCPEs[0].CPE contains null byte: %q", p.AffectedCPEs[0].CPE)
	}
	if p.AffectedCPEs[0].CPE != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
		t.Errorf("AffectedCPEs[0].CPE = %q, want %q", p.AffectedCPEs[0].CPE, "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	}
	if strings.Contains(p.AffectedCPEs[0].CPENormalized, "\x00") {
		t.Errorf("AffectedCPEs[0].CPENormalized contains null byte: %q", p.AffectedCPEs[0].CPENormalized)
	}
}

func TestApplyNVDCVSS(t *testing.T) {
	t.Parallel()

	t.Run("v31 preferred over v30", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 7.5, BaseSeverity: "High"},
				},
			},
			CVSSV30: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.0", VectorString: "CVSS:3.0/AV:N", BaseScore: 6.0, BaseSeverity: "Medium"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
			t.Fatalf("CVSSv3Score = %v, want 7.5 (v3.1 preferred)", patch.CVSSv3Score)
		}
		if patch.CVSSv3Vector == nil || *patch.CVSSv3Vector != "CVSS:3.1/AV:N" {
			t.Fatalf("CVSSv3Vector = %v, want CVSS:3.1/AV:N", patch.CVSSv3Vector)
		}
	})

	t.Run("v30 fallback when no v31", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV30: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.0", VectorString: "CVSS:3.0/AV:L", BaseScore: 5.5, BaseSeverity: "Medium"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 5.5 {
			t.Fatalf("CVSSv3Score = %v, want 5.5 (v3.0 fallback)", patch.CVSSv3Score)
		}
	})

	t.Run("v40 set independently", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 9.8, BaseSeverity: "Critical"},
				},
			},
			CVSSV40: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "4.0", VectorString: "CVSS:4.0/AV:N", BaseScore: 8.7, BaseSeverity: "High"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 9.8 {
			t.Fatalf("CVSSv3Score = %v, want 9.8", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 8.7 {
			t.Fatalf("CVSSv4Score = %v, want 8.7", patch.CVSSv4Score)
		}
		if patch.CVSSv4Vector == nil || *patch.CVSSv4Vector != "CVSS:4.0/AV:N" {
			t.Fatalf("CVSSv4Vector = %v, want CVSS:4.0/AV:N", patch.CVSSv4Vector)
		}
		// Severity comes from v3.1 (set first), not overridden by v4.0.
		if patch.Severity == nil || *patch.Severity != "CRITICAL" {
			t.Fatalf("Severity = %v, want CRITICAL (from v3.1, not overridden by v4.0)", patch.Severity)
		}
	})

	t.Run("v40 severity only set when Severity is nil", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 7.5, BaseSeverity: "High"},
				},
			},
			CVSSV40: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "4.0", VectorString: "CVSS:4.0/AV:N", BaseScore: 8.0, BaseSeverity: "Critical"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		// Severity set by v3.1 first; v4.0 should NOT overwrite.
		if patch.Severity == nil || *patch.Severity != "HIGH" {
			t.Fatalf("Severity = %v, want HIGH (v3.1 set first, v4.0 must not overwrite)", patch.Severity)
		}
	})

	t.Run("severity empty string not set", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 5.0, BaseSeverity: ""},
				},
			},
			CVSSV40: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "4.0", VectorString: "CVSS:4.0/AV:N", BaseScore: 6.0, BaseSeverity: ""},
				},
			},
		}
		applyNVDCVSS(patch, m)
		// Both severity strings are empty — Severity should remain nil.
		if patch.Severity != nil {
			t.Fatalf("Severity = %v, want nil (empty severity strings should not be set)", patch.Severity)
		}
		// Scores should still be set.
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 5.0 {
			t.Fatalf("CVSSv3Score = %v, want 5.0", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 6.0 {
			t.Fatalf("CVSSv4Score = %v, want 6.0", patch.CVSSv4Score)
		}
	})

	t.Run("nvd source preferred via pickPreferred", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "vendor@example.com",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:L", BaseScore: 4.0, BaseSeverity: "Medium"},
				},
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 7.5, BaseSeverity: "High"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
			t.Fatalf("CVSSv3Score = %v, want 7.5 (NVD source preferred)", patch.CVSSv3Score)
		}
	})
}

func TestPickPreferred(t *testing.T) {
	t.Parallel()

	t.Run("nvd source entry returned when present", func(t *testing.T) {
		t.Parallel()
		entries := []nvdCVSSMetric{
			{Source: "vendor@example.com", CVSSData: nvdCVSSData{BaseScore: 4.0}},
			{Source: "nvd@nist.gov", CVSSData: nvdCVSSData{BaseScore: 7.5}},
			{Source: "other@example.com", CVSSData: nvdCVSSData{BaseScore: 5.0}},
		}
		got := pickPreferred(entries)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got.Source != "nvd@nist.gov" {
			t.Fatalf("Source = %q, want nvd@nist.gov", got.Source)
		}
		if got.CVSSData.BaseScore != 7.5 {
			t.Fatalf("BaseScore = %v, want 7.5", got.CVSSData.BaseScore)
		}
	})

	t.Run("first entry returned when no nvd source", func(t *testing.T) {
		t.Parallel()
		entries := []nvdCVSSMetric{
			{Source: "vendor@example.com", CVSSData: nvdCVSSData{BaseScore: 4.0}},
			{Source: "other@example.com", CVSSData: nvdCVSSData{BaseScore: 5.0}},
		}
		got := pickPreferred(entries)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got.Source != "vendor@example.com" {
			t.Fatalf("Source = %q, want vendor@example.com (first entry)", got.Source)
		}
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		t.Parallel()
		got := pickPreferred(nil)
		if got != nil {
			t.Fatalf("expected nil for empty slice, got %+v", got)
		}
		got = pickPreferred([]nvdCVSSMetric{})
		if got != nil {
			t.Fatalf("expected nil for zero-length slice, got %+v", got)
		}
	})
}

// --- Fetch-level integration tests (httptest + redirectTransport) ---

// redirectTransport intercepts outbound requests and rewrites their scheme/host
// to point at the httptest server. This lets us test Fetch end-to-end without
// modifying the hardcoded apiURL const.
type redirectTransport struct {
	targetURL string
	inner     http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(rt.targetURL)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return rt.inner.RoundTrip(req)
}

// validNVDResponse is a minimal NVD API 2.0 response for Fetch tests.
const validNVDResponse = `{
	"resultsPerPage": 2,
	"startIndex": 0,
	"totalResults": 2,
	"format": "NVD_CVE",
	"version": "2.0",
	"timestamp": "2025-06-01T12:00:00.000",
	"vulnerabilities": [
		{
			"cve": {
				"id": "CVE-2025-1001",
				"vulnStatus": "Analyzed",
				"published": "2025-05-01T00:00:00.000",
				"lastModified": "2025-05-15T00:00:00.000",
				"descriptions": [
					{"lang": "en", "value": "Buffer overflow in example service"}
				],
				"metrics": {
					"cvssMetricV31": [
						{
							"source": "nvd@nist.gov",
							"cvssData": {
								"version": "3.1",
								"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								"baseScore": 9.8,
								"baseSeverity": "CRITICAL"
							}
						}
					]
				}
			}
		},
		{
			"cve": {
				"id": "CVE-2025-1002",
				"vulnStatus": "Modified",
				"published": "2025-04-01T00:00:00.000",
				"lastModified": "2025-05-20T00:00:00.000",
				"descriptions": [
					{"lang": "en", "value": "SQL injection in admin panel"}
				]
			}
		}
	]
}`

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	var capturedQuery url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Sun, 01 Jun 2025 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validNVDResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Patches) != 2 {
		t.Fatalf("len(Patches) = %d, want 2", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2025-1001" {
		t.Errorf("Patches[0].CVEID = %q, want CVE-2025-1001", result.Patches[0].CVEID)
	}
	if result.Patches[1].CVEID != "CVE-2025-1002" {
		t.Errorf("Patches[1].CVEID = %q, want CVE-2025-1002", result.Patches[1].CVEID)
	}

	if result.SourceMeta.SourceName != "nvd" {
		t.Errorf("SourceName = %q, want %q", result.SourceMeta.SourceName, "nvd")
	}

	// Verify query parameters were sent.
	if capturedQuery.Get("resultsPerPage") == "" {
		t.Error("expected resultsPerPage query param")
	}
	if capturedQuery.Get("startIndex") == "" {
		t.Error("expected startIndex query param")
	}

	// NVD is paginated with sliding windows — first fetch is not the last page.
	if result.LastPage {
		t.Error("LastPage should be false — NVD has more windows to fetch")
	}
	for i, p := range result.Patches {
		if p.RawPayload == nil {
			t.Errorf("Patches[%d].RawPayload is nil", i)
		} else if !json.Valid(p.RawPayload) {
			t.Errorf("Patches[%d].RawPayload is not valid JSON", i)
		} else if !bytes.Contains(p.RawPayload, []byte(p.CVEID)) {
			t.Errorf("Patches[%d].RawPayload does not contain CVE ID %q", i, p.CVEID)
		}
	}
}

func TestFetch_WithCursor(t *testing.T) {
	t.Parallel()

	var capturedQuery url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Sun, 01 Jun 2025 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validNVDResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	windowStart := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2025, 5, 30, 0, 0, 0, 0, time.UTC)
	cursorJSON, _ := json.Marshal(Cursor{
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
		StartIndex:  2000,
	})

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the date params were sent on the request.
	startDate := capturedQuery.Get("lastModStartDate")
	if startDate == "" {
		t.Fatal("expected lastModStartDate query param")
	}
	endDate := capturedQuery.Get("lastModEndDate")
	if endDate == "" {
		t.Fatal("expected lastModEndDate query param")
	}

	// Verify startIndex from the cursor was forwarded.
	if capturedQuery.Get("startIndex") != "2000" {
		t.Errorf("startIndex = %q, want %q", capturedQuery.Get("startIndex"), "2000")
	}

	// We should still get patches from the response.
	if len(result.Patches) != 2 {
		t.Fatalf("len(Patches) = %d, want 2", len(result.Patches))
	}
}

func TestFetch_LastPage(t *testing.T) {
	t.Parallel()

	// Serve the standard response with timestamp "2025-06-01T12:00:00.000".
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Sun, 01 Jun 2025 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validNVDResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	// Set the cursor's WindowEnd equal to effectiveNow (the response timestamp).
	// This means all windows are exhausted — computeNextCursor returns a caught-up cursor.
	windowStart := time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	cursorJSON, _ := json.Marshal(Cursor{
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
		StartIndex:  0,
	})

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.LastPage {
		t.Error("LastPage should be true when window end reaches effectiveNow")
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor should be non-nil (caught-up cursor) on last page")
	}
	// Verify the caught-up cursor is valid JSON with expected shape.
	var caughtUp Cursor
	if err := json.Unmarshal(result.NextCursor, &caughtUp); err != nil {
		t.Fatalf("unmarshal caught-up cursor: %v", err)
	}
	if caughtUp.StartIndex != 0 {
		t.Errorf("caught-up cursor StartIndex = %d, want 0", caughtUp.StartIndex)
	}
	if len(result.Patches) != 2 {
		t.Fatalf("len(Patches) = %d, want 2", len(result.Patches))
	}
}

const emptyNVDResponse = `{"totalResults":0,"timestamp":"2025-06-01T12:00:00.000","vulnerabilities":[]}`

// newScriptedAdapter returns an adapter whose server answers each request with
// respond(n), n counting from 1, and a function reporting the lastModStartDate
// values it received.
func newScriptedAdapter(t *testing.T, respond func(n int) string) (*Adapter, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var starts []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		starts = append(starts, r.URL.Query().Get("lastModStartDate"))
		n := len(starts)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respond(n)))
	}))
	t.Cleanup(ts.Close)

	adapter := &Adapter{
		client:      &http.Client{Transport: &redirectTransport{targetURL: ts.URL, inner: http.DefaultTransport}},
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}
	return adapter, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), starts...)
	}
}

// The handler ends a run on an empty page, and NVD has no modifications in its
// earliest windows, so Fetch walks past empty windows to the next page with data.
func TestFetch_WalksPastEmptyWindows(t *testing.T) {
	t.Parallel()

	adapter, starts := newScriptedAdapter(t, func(n int) string {
		if n <= 2 {
			return emptyNVDResponse
		}
		return validNVDResponse
	})
	cursorJSON, _ := json.Marshal(Cursor{
		WindowStart: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
	})

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(result.Patches) != 2 {
		t.Fatalf("len(Patches) = %d, want 2", len(result.Patches))
	}
	if result.LastPage {
		t.Error("LastPage = true, want false: later windows remain")
	}
	got := starts()
	if len(got) != 3 {
		t.Fatalf("requests = %d, want 3: %v", len(got), got)
	}
	if got[0] >= got[1] || got[1] >= got[2] {
		t.Errorf("window starts do not advance: %v", got)
	}
}

// Walking past empty windows must carry CaughtUp, or a later run would report
// NVD data as incomplete again.
func TestFetch_WalkPastEmptyWindowsKeepsCaughtUp(t *testing.T) {
	t.Parallel()

	adapter, _ := newScriptedAdapter(t, func(n int) string {
		if n <= 2 {
			return emptyNVDResponse
		}
		return validNVDResponse
	})
	cursorJSON, err := json.Marshal(Cursor{
		WindowStart: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
		CaughtUp:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The final page sets CaughtUp whatever the input says, so the carry is only
	// tested while the result comes from a page before it.
	if result.LastPage {
		t.Fatal("LastPage = true, want a page before the end of the walk")
	}
	var next Cursor
	if err := json.Unmarshal(result.NextCursor, &next); err != nil {
		t.Fatalf("NextCursor: %v", err)
	}
	if !next.CaughtUp {
		t.Errorf("NextCursor = %s, want caught_up true", result.NextCursor)
	}
}

func TestFetch_FirstWalkEndsCaughtUp(t *testing.T) {
	t.Parallel()

	adapter, _ := newScriptedAdapter(t, func(int) string { return emptyNVDResponse })
	cursorJSON, err := json.Marshal(Cursor{
		WindowStart: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !result.LastPage {
		t.Fatal("LastPage = false, want true")
	}
	var next Cursor
	if err := json.Unmarshal(result.NextCursor, &next); err != nil {
		t.Fatalf("NextCursor: %v", err)
	}
	if !next.CaughtUp {
		t.Errorf("NextCursor = %s, want caught_up true at the end of the walk", result.NextCursor)
	}
}

func TestFetch_AllWindowsEmptyEndsOnLastPage(t *testing.T) {
	t.Parallel()

	adapter, starts := newScriptedAdapter(t, func(int) string { return emptyNVDResponse })
	cursorJSON, _ := json.Marshal(Cursor{
		WindowStart: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
	})

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !result.LastPage {
		t.Error("LastPage = false, want true: every window up to now is empty")
	}
	if len(result.Patches) != 0 {
		t.Errorf("len(Patches) = %d, want 0", len(result.Patches))
	}
	if len(starts()) < 2 {
		t.Errorf("requests = %d, want the walk to continue past the first window", len(starts()))
	}
}

// NVD's timestamp advances on every response, so a window ending at the previous
// response's timestamp is always slightly behind. The run must still end, or it
// loops for as long as anything was modified in the last 15 minutes.
func TestFetch_RunEndsWhenResponseTimestampAdvances(t *testing.T) {
	t.Parallel()

	start := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	adapter, _ := newScriptedAdapter(t, func(n int) string {
		timestamp := start.Add(time.Duration(n) * 2 * time.Second).Format("2006-01-02T15:04:05.000")
		return strings.Replace(validNVDResponse, "2025-06-01T12:00:00.000", timestamp, 1)
	})
	cursor, _ := json.Marshal(Cursor{
		WindowStart: start.Add(-48 * time.Hour),
		WindowEnd:   start.Add(-time.Hour),
	})

	const maxCalls = 5
	for call := 1; ; call++ {
		if call > maxCalls {
			t.Fatalf("no LastPage after %d calls", maxCalls)
		}
		result, err := adapter.Fetch(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if result.LastPage {
			return
		}
		cursor = result.NextCursor
	}
}

func TestFetch_HTTPError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error = %q, want it to contain 'HTTP 403'", err.Error())
	}
}

func TestFetch_InvalidCursor(t *testing.T) {
	t.Parallel()

	// No httptest server needed — Fetch should fail on cursor parse before making a request.
	adapter := &Adapter{
		client:      http.DefaultClient,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	_, err := adapter.Fetch(context.Background(), json.RawMessage(`{not valid json}`))
	if err == nil {
		t.Fatal("expected error for invalid cursor JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse cursor") {
		t.Errorf("error = %q, want it to contain 'parse cursor'", err.Error())
	}
}

func TestFetch_ZeroWindowOmitsDateParams(t *testing.T) {
	t.Parallel()

	var capturedQuery url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Sun, 01 Jun 2025 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validNVDResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	// Construct a cursor with zero WindowStart and WindowEnd.
	cursorJSON, _ := json.Marshal(Cursor{
		WindowStart: time.Time{},
		WindowEnd:   time.Time{},
		StartIndex:  0,
	})

	// parseCursor with zero WindowStart falls back to zeroValueCursor,
	// which sets non-zero dates. Verify they are present as non-zero.
	_, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The zeroValueCursor sets both window fields, so date params are present.
	if capturedQuery.Get("lastModStartDate") == "" {
		t.Error("expected lastModStartDate query param (zeroValueCursor sets it)")
	}
	if capturedQuery.Get("lastModEndDate") == "" {
		t.Error("expected lastModEndDate query param (zeroValueCursor sets it)")
	}
}

func TestFetch_NoDateResponseHeader(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Deliberately omit Date header.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validNVDResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	// Fetch should succeed even without a Date header; effectiveNow falls back
	// to the response timestamp or time.Now().
	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Patches) != 2 {
		t.Fatalf("len(Patches) = %d, want 2", len(result.Patches))
	}
}

func TestFetch_APIKeyHeader(t *testing.T) {
	t.Parallel()

	var capturedAPIKey string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get("apiKey") //nolint:canonicalheader // NVD requires lowercase 'a'
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Sun, 01 Jun 2025 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validNVDResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	// Construct the adapter directly to inject a test API key without env vars.
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
		apiKey:      "test-api-key-12345",
	}

	_, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedAPIKey != "test-api-key-12345" {
		t.Errorf("apiKey header = %q, want %q", capturedAPIKey, "test-api-key-12345")
	}
}

func TestFetch_DateResponseHeader(t *testing.T) {
	t.Parallel()

	// Serve a response with no "timestamp" field in JSON body, so
	// Fetch must fall back to the HTTP Date header for effectiveNow.
	noTimestampResponse := `{
		"resultsPerPage": 1,
		"startIndex": 0,
		"totalResults": 1,
		"format": "NVD_CVE",
		"version": "2.0",
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2025-3001",
					"vulnStatus": "Analyzed",
					"published": "2025-05-01T00:00:00.000",
					"lastModified": "2025-05-15T00:00:00.000",
					"descriptions": [
						{"lang": "en", "value": "Test vuln"}
					]
				}
			}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Sun, 01 Jun 2025 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(noTimestampResponse))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Inf, 1),
	}

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Patches) != 1 {
		t.Fatalf("len(Patches) = %d, want 1", len(result.Patches))
	}
	// NextCursor should be computed using the Date header as effectiveNow.
	// Since zeroValueCursor creates a window starting at 2002-01-01 and totalResults=1
	// (exhausted in one page), the next cursor should advance to a new window.
	// If Date header was not parsed, effectiveNow would be time.Now(), which also
	// produces a valid next cursor — the key check is that Fetch succeeded.
	if result.Patches[0].CVEID != "CVE-2025-3001" {
		t.Errorf("Patches[0].CVEID = %q, want CVE-2025-3001", result.Patches[0].CVEID)
	}
}
