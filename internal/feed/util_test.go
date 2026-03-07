package feed

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ── ParseTime ─────────────────────────────────────────────────────────────────

func TestParseTimeRFC3339Nano(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15T10:30:00.123456789Z")
	want := time.Date(2024, 3, 15, 10, 30, 0, 123456789, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ParseTime(RFC3339Nano) = %v, want %v", got, want)
	}
}

func TestParseTimeRFC3339(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15T10:30:00Z")
	want := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ParseTime(RFC3339) = %v, want %v", got, want)
	}
}

func TestParseTimeNoTimezone(t *testing.T) {
	t.Parallel()

	// Feeds sometimes omit the timezone suffix; we must still parse it.
	got := ParseTime("2024-03-15T10:30:00")
	if got.IsZero() {
		t.Fatal("ParseTime(no-tz) returned zero time")
	}
	if got.Year() != 2024 || got.Month() != 3 || got.Day() != 15 {
		t.Errorf("ParseTime(no-tz) = %v: wrong date", got)
	}
}

func TestParseTimeDateOnly(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15")
	if got.IsZero() {
		t.Fatal("ParseTime(date-only) returned zero time")
	}
	if got.Year() != 2024 || got.Month() != 3 || got.Day() != 15 {
		t.Errorf("ParseTime(date-only) = %v: wrong date", got)
	}
}

func TestParseTimeInvalidReturnsZero(t *testing.T) {
	t.Parallel()

	got := ParseTime("not-a-date")
	if !got.IsZero() {
		t.Errorf("ParseTime(invalid) = %v, want zero", got)
	}
}

func TestParseTimeEmptyReturnsZero(t *testing.T) {
	t.Parallel()

	got := ParseTime("")
	if !got.IsZero() {
		t.Errorf("ParseTime(\"\") = %v, want zero", got)
	}
}

func TestParseTimeReturnsUTC(t *testing.T) {
	t.Parallel()

	got := ParseTime("2024-03-15T10:30:00Z")
	if got.Location() != time.UTC {
		t.Errorf("ParseTime returned location %v, want UTC", got.Location())
	}
}

// ── ParseTimePtr ──────────────────────────────────────────────────────────────

func TestParseTimePtrNilOnEmpty(t *testing.T) {
	t.Parallel()

	if got := ParseTimePtr(""); got != nil {
		t.Errorf("ParseTimePtr(\"\") = %v, want nil", got)
	}
}

func TestParseTimePtrNilOnInvalid(t *testing.T) {
	t.Parallel()

	if got := ParseTimePtr("not-a-date"); got != nil {
		t.Errorf("ParseTimePtr(invalid) = %v, want nil", got)
	}
}

func TestParseTimePtrNonNilOnValid(t *testing.T) {
	t.Parallel()

	got := ParseTimePtr("2024-03-15T10:30:00Z")
	if got == nil {
		t.Fatal("ParseTimePtr(valid) = nil, want non-nil")
	}
	if got.Year() != 2024 {
		t.Errorf("ParseTimePtr year = %d, want 2024", got.Year())
	}
}

// ── StripNullBytes ────────────────────────────────────────────────────────────

func TestStripNullBytesRemovesNulls(t *testing.T) {
	t.Parallel()

	input := "hello\x00world\x00"
	got := StripNullBytes(input)
	want := "helloworld"
	if got != want {
		t.Errorf("StripNullBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestStripNullBytesNoOpOnCleanString(t *testing.T) {
	t.Parallel()

	input := "no null bytes here"
	if got := StripNullBytes(input); got != input {
		t.Errorf("StripNullBytes(%q) = %q, want unchanged", input, got)
	}
}

func TestStripNullBytesJSONRemovesNulls(t *testing.T) {
	t.Parallel()

	input := []byte(`{"k":"v` + "\x00" + `alue"}`)
	got := StripNullBytesJSON(input)
	for _, b := range got {
		if b == 0 {
			t.Errorf("StripNullBytesJSON left a null byte in output")
		}
	}
}

// ── ResolveCanonicalID ────────────────────────────────────────────────────────

func TestResolveCanonicalIDReturnsAlias(t *testing.T) {
	t.Parallel()

	// GHSA record with a CVE alias — CVE ID should be returned.
	got := ResolveCanonicalID("GHSA-1234-5678-9012", []string{"CVE-2024-12345"})
	if got != "CVE-2024-12345" {
		t.Errorf("ResolveCanonicalID = %q, want %q", got, "CVE-2024-12345")
	}
}

func TestResolveCanonicalIDNoAlias(t *testing.T) {
	t.Parallel()

	// No CVE alias: native ID is returned unchanged.
	got := ResolveCanonicalID("GHSA-1234-5678-9012", []string{"PYSEC-2024-123"})
	if got != "GHSA-1234-5678-9012" {
		t.Errorf("ResolveCanonicalID = %q, want %q", got, "GHSA-1234-5678-9012")
	}
}

func TestResolveCanonicalIDEmptyAliases(t *testing.T) {
	t.Parallel()

	got := ResolveCanonicalID("GHSA-1234-5678-9012", nil)
	if got != "GHSA-1234-5678-9012" {
		t.Errorf("ResolveCanonicalID(nil aliases) = %q, want native ID", got)
	}
}

func TestResolveCanonicalIDFirstCVEAlias(t *testing.T) {
	t.Parallel()

	// Multiple aliases; the first CVE match should be returned.
	got := ResolveCanonicalID("GHSA-xxxx", []string{"PYSEC-1", "CVE-2024-00001", "CVE-2024-00002"})
	if got != "CVE-2024-00001" {
		t.Errorf("ResolveCanonicalID = %q, want first CVE alias", got)
	}
}

func TestResolveCanonicalIDNativeIsAlreadyCVE(t *testing.T) {
	t.Parallel()

	// When the native ID is itself a CVE ID, still check aliases for the
	// canonical form — but if none found, return nativeID.
	got := ResolveCanonicalID("CVE-2024-99999", []string{"GHSA-xxxx"})
	if got != "CVE-2024-99999" {
		t.Errorf("ResolveCanonicalID = %q, want native CVE ID", got)
	}
}

func TestResolveCanonicalIDMalformedCVEAlias(t *testing.T) {
	t.Parallel()

	// Malformed CVE IDs should not match the cveIDPattern regex.
	// "CVE-abc" has no year digits; "CVE-2024" has no sequence number.
	tests := []struct {
		name    string
		aliases []string
	}{
		{"no digits in year", []string{"CVE-abc-1234"}},
		{"missing sequence", []string{"CVE-2024"}},
		{"extra prefix", []string{"XCVE-2024-12345"}},
		{"lowercase cve prefix", []string{"cve-2024-12345"}},
		{"spaces in alias", []string{"CVE -2024-12345"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveCanonicalID("GHSA-xxxx", tc.aliases)
			if got != "GHSA-xxxx" {
				t.Errorf("ResolveCanonicalID(%v) = %q, want native ID (malformed CVE should not match)", tc.aliases, got)
			}
		})
	}
}

func TestResolveCanonicalIDWhitespaceAlias(t *testing.T) {
	t.Parallel()

	// Aliases with leading/trailing whitespace should not match the strict
	// CVE ID regex pattern (no trimming is performed).
	got := ResolveCanonicalID("GHSA-xxxx", []string{" CVE-2024-12345 "})
	if got != "GHSA-xxxx" {
		t.Errorf("ResolveCanonicalID = %q, want native ID (whitespace-padded CVE should not match regex)", got)
	}

	// But a clean CVE alias after a whitespace-padded one should match.
	got = ResolveCanonicalID("GHSA-xxxx", []string{" CVE-2024-11111 ", "CVE-2024-22222"})
	if got != "CVE-2024-22222" {
		t.Errorf("ResolveCanonicalID = %q, want %q (first clean CVE alias)", got, "CVE-2024-22222")
	}
}

// ── CanonicalPatch VendorEnrichment ──────────────────────────────────────────

// ── CloneStrings ──────────────────────────────────────────────────────────────

func TestCloneStrings_NilReturnsNil(t *testing.T) {
	t.Parallel()

	result := CloneStrings(nil)
	if result != nil {
		t.Errorf("CloneStrings(nil) = %v, want nil", result)
	}
}

func TestCloneStrings_EmptyReturnsEmpty(t *testing.T) {
	t.Parallel()

	result := CloneStrings([]string{})
	if result == nil {
		t.Fatal("CloneStrings([]string{}) = nil, want non-nil empty slice")
	}
	if len(result) != 0 {
		t.Errorf("len(CloneStrings([]string{})) = %d, want 0", len(result))
	}
}

func TestCloneStrings_IndependentCopy(t *testing.T) {
	t.Parallel()

	input := []string{"alpha", "beta", "gamma"}
	result := CloneStrings(input)

	if len(result) != 3 {
		t.Fatalf("len = %d, want 3", len(result))
	}
	for i, want := range []string{"alpha", "beta", "gamma"} {
		if result[i] != want {
			t.Errorf("result[%d] = %q, want %q", i, result[i], want)
		}
	}

	// Verify it's a true copy: mutating input doesn't affect result.
	input[0] = "mutated"
	if result[0] == "mutated" {
		t.Error("CloneStrings did not create independent copy; mutating input affected result")
	}
}

// ── DownloadToTemp ────────────────────────────────────────────────────────────

func TestDownloadToTemp_Success(t *testing.T) {
	t.Parallel()

	payload := "hello from test server"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payload)
	}))
	defer srv.Close()

	f, err := DownloadToTemp(t.Context(), srv.Client(), srv.URL, "cvert-test-*.dat") //nolint:gosec // G704: test URL
	if err != nil {
		t.Fatalf("DownloadToTemp error: %v", err)
	}
	defer os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp
	defer f.Close()           //nolint:errcheck

	// File should be seeked to start — read should give us the full payload.
	got, err := os.ReadFile(f.Name()) //nolint:gosec // G304: path from os.CreateTemp
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if string(got) != payload {
		t.Errorf("file content = %q, want %q", got, payload)
	}
}

func TestDownloadToTemp_HTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f, err := DownloadToTemp(t.Context(), srv.Client(), srv.URL, "cvert-test-*.dat") //nolint:gosec // G704: test URL
	if err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Fatal("expected error for HTTP 500, got nil")
	}
	if f != nil {
		t.Error("expected nil file on error")
	}
}

// ── UserAgentTransport ────────────────────────────────────────────────────────

func TestUserAgentTransport_SetsUA(t *testing.T) {
	t.Parallel()

	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &UserAgentTransport{
			Base:      http.DefaultTransport,
			UserAgent: "TestAgent/1.0",
		},
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil) //nolint:gosec // G704: test URL
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	resp.Body.Close() //nolint:errcheck

	if gotUA != "TestAgent/1.0" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "TestAgent/1.0")
	}
}

func TestUserAgentTransport_DoesNotOverride(t *testing.T) {
	t.Parallel()

	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &UserAgentTransport{
			Base:      http.DefaultTransport,
			UserAgent: "TestAgent/1.0",
		},
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil) //nolint:gosec // G704: test URL
	req.Header.Set("User-Agent", "CustomAgent/2.0")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	resp.Body.Close() //nolint:errcheck

	if gotUA != "CustomAgent/2.0" {
		t.Errorf("User-Agent = %q, want %q (should not be overridden)", gotUA, "CustomAgent/2.0")
	}
}

// ── WrapClientWithUA ──────────────────────────────────────────────────────────

func TestWrapClientWithUA_OriginalUnmutated(t *testing.T) {
	t.Parallel()

	original := &http.Client{Timeout: 30 * time.Second}
	wrapped := WrapClientWithUA(original)

	if wrapped == original {
		t.Error("WrapClientWithUA returned same pointer, want shallow copy")
	}
	if original.Transport != nil {
		t.Error("original client Transport was mutated")
	}
}

func TestWrapClientWithUA_SetsUA(t *testing.T) {
	t.Parallel()

	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	client := WrapClientWithUA(srv.Client())

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil) //nolint:gosec // G704: test URL
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	resp.Body.Close() //nolint:errcheck

	if gotUA != DefaultUserAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, DefaultUserAgent)
	}
}

func TestWrapClientWithUA_Idempotent(t *testing.T) {
	t.Parallel()

	client := &http.Client{}
	wrapped1 := WrapClientWithUA(client)
	wrapped2 := WrapClientWithUA(wrapped1)

	// Double-wrapping should not nest transports.
	_, ok := wrapped2.Transport.(*UserAgentTransport)
	if !ok {
		t.Fatal("expected UserAgentTransport after double wrap")
	}
	inner := wrapped2.Transport.(*UserAgentTransport).Base
	if _, nested := inner.(*UserAgentTransport); nested {
		t.Error("double-wrapping nested UserAgentTransport — should be idempotent")
	}
}

// ── DrainAndClose ─────────────────────────────────────────────────────────────

func TestDrainAndClose_DrainsAndCloses(t *testing.T) {
	t.Parallel()

	body := &trackingReadCloser{data: []byte("remaining data")}
	DrainAndClose(body)

	if !body.closed {
		t.Error("DrainAndClose did not close the body")
	}
	if !body.drained {
		t.Error("DrainAndClose did not drain the body")
	}
}

func TestDrainAndClose_NilSafe(t *testing.T) {
	t.Parallel()

	// Should not panic on nil.
	DrainAndClose(nil)
}

// trackingReadCloser records whether it was read from and closed.
type trackingReadCloser struct {
	data    []byte
	offset  int
	drained bool
	closed  bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		r.drained = true
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	if r.offset >= len(r.data) {
		r.drained = true
	}
	return n, nil
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestCanonicalPatch_VendorEnrichmentRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("nil vendor enrichment omitted from JSON", func(t *testing.T) {
		t.Parallel()
		p := CanonicalPatch{CVEID: "CVE-2025-0001"}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(data), "vendor_enrichment") {
			t.Errorf("nil VendorEnrichment should be omitted, got %s", data)
		}
	})

	t.Run("populated vendor enrichment round-trips", func(t *testing.T) {
		t.Parallel()
		sev := "Critical"
		p := CanonicalPatch{
			CVEID: "CVE-2025-0002",
			VendorEnrichment: &VendorEnrichment{
				VendorSeverity: &sev,
				Data:           json.RawMessage(`{"kb":"KB12345"}`),
			},
		}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded CanonicalPatch
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.VendorEnrichment == nil {
			t.Fatal("VendorEnrichment should not be nil after round-trip")
		}
		if decoded.VendorEnrichment.VendorSeverity == nil || *decoded.VendorEnrichment.VendorSeverity != "Critical" {
			t.Errorf("VendorSeverity = %v, want Critical", decoded.VendorEnrichment.VendorSeverity)
		}
	})
}
