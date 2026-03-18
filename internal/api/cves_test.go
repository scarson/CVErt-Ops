package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── cursor encode/decode ──────────────────────────────────────────────────────

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()

	// Build a synthetic CVE row with a known date and ID.
	ts := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	row := generated.CVE{
		CveID:                 "CVE-2024-99999",
		DateModifiedCanonical: ts,
	}

	encoded := encodeCursor(row)
	if encoded == "" {
		t.Fatal("encodeCursor returned empty string")
	}

	decoded, err := decodeCursor(encoded)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if decoded == nil {
		t.Fatal("decodeCursor returned nil")
	}
	if decoded.CVEID != "CVE-2024-99999" {
		t.Errorf("CVEID = %q, want %q", decoded.CVEID, "CVE-2024-99999")
	}

	// SortDate must round-trip back to the same instant.
	parsed, err := time.Parse(time.RFC3339Nano, decoded.SortDate)
	if err != nil {
		t.Fatalf("parse SortDate %q: %v", decoded.SortDate, err)
	}
	if !parsed.UTC().Equal(ts) {
		t.Errorf("SortDate round-trip: got %v, want %v", parsed.UTC(), ts)
	}
}

func TestDecodeCursorEmpty(t *testing.T) {
	t.Parallel()

	cur, err := decodeCursor("")
	if err != nil {
		t.Fatalf("decodeCursor(\"\") should return nil,nil; got error %v", err)
	}
	if cur != nil {
		t.Errorf("decodeCursor(\"\") = %+v, want nil", cur)
	}
}

func TestDecodeCursorInvalidBase64(t *testing.T) {
	t.Parallel()

	_, err := decodeCursor("!!!not-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestDecodeCursorMissingCVEID(t *testing.T) {
	t.Parallel()

	// Valid base64 of JSON with no cve_id.
	_, err := decodeCursor("e30") // base64url of "{}"
	if err == nil {
		t.Error("expected error for cursor missing cve_id, got nil")
	}
}

// ── nilIfEmpty ────────────────────────────────────────────────────────────────

func TestNilIfEmpty(t *testing.T) {
	t.Parallel()

	if got := nilIfEmpty(""); got != nil {
		t.Errorf("nilIfEmpty(\"\") = %v, want nil", got)
	}

	s := "hello"
	got := nilIfEmpty(s)
	if got == nil {
		t.Fatal("nilIfEmpty(non-empty) returned nil")
	}
	if *got != s {
		t.Errorf("nilIfEmpty(%q) = %q, want %q", s, *got, s)
	}
}

// ── parseQueryDate ────────────────────────────────────────────────────────────

func TestParseQueryDate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantUTC time.Time
	}{
		{
			name:    "RFC3339",
			input:   "2026-02-25T12:00:00Z",
			wantUTC: time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		},
		{
			name:    "date only",
			input:   "2026-02-25",
			wantUTC: time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "invalid",
			input:   "not-a-date",
			wantNil: true,
		},
		{
			name:    "empty",
			input:   "",
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseQueryDate(tc.input)
			if tc.wantNil {
				if got != nil {
					t.Errorf("parseQueryDate(%q) = %v, want nil", tc.input, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseQueryDate(%q) = nil, want %v", tc.input, tc.wantUTC)
			}
			if !got.UTC().Equal(tc.wantUTC) {
				t.Errorf("parseQueryDate(%q) = %v, want %v", tc.input, got.UTC(), tc.wantUTC)
			}
		})
	}
}

// ── ListCVEsInput.resolveOptionalFilters ─────────────────────────────────────

// TestResolveOptionalFilters tests the filter parsing logic directly via the
// internal helper, avoiding the need to implement the full huma.Context interface.
func TestResolveOptionalFilters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		params      map[string]string
		wantErrs    int
		wantCVSSMin *float64
		wantCVSSMax *float64
		wantEPSSMin *float64
		wantEPSSMax *float64
		wantKEV     *bool
		wantExploit *bool
	}{
		{
			name:   "all empty — no filters",
			params: map[string]string{},
		},
		{
			name:        "valid cvss_min",
			params:      map[string]string{"cvss_min": "7.5"},
			wantCVSSMin: floatPtr(7.5),
		},
		{
			name:        "cvss_min zero is valid",
			params:      map[string]string{"cvss_min": "0"},
			wantCVSSMin: floatPtr(0),
		},
		{
			name:        "valid epss_max",
			params:      map[string]string{"epss_max": "0.95"},
			wantEPSSMax: floatPtr(0.95),
		},
		{
			name:     "cvss_min out of range",
			params:   map[string]string{"cvss_min": "11"},
			wantErrs: 1,
		},
		{
			name:     "epss_min negative",
			params:   map[string]string{"epss_min": "-0.1"},
			wantErrs: 1,
		},
		{
			name:     "cvss_max not a number",
			params:   map[string]string{"cvss_max": "high"},
			wantErrs: 1,
		},
		{
			name:    "in_cisa_kev true",
			params:  map[string]string{"in_cisa_kev": "true"},
			wantKEV: boolPtr(true),
		},
		{
			name:    "in_cisa_kev false — false is a valid filter value",
			params:  map[string]string{"in_cisa_kev": "false"},
			wantKEV: boolPtr(false),
		},
		{
			name:        "exploit_available true",
			params:      map[string]string{"exploit_available": "true"},
			wantExploit: boolPtr(true),
		},
		{
			name:        "multiple valid params",
			params:      map[string]string{"cvss_min": "5", "cvss_max": "9", "in_cisa_kev": "true"},
			wantCVSSMin: floatPtr(5),
			wantCVSSMax: floatPtr(9),
			wantKEV:     boolPtr(true),
		},
		{
			name:    "in_cisa_kev TRUE (uppercase) — must not silently coerce to false",
			params:  map[string]string{"in_cisa_kev": "TRUE"},
			wantKEV: boolPtr(true),
		},
		{
			name:    "in_cisa_kev FALSE (uppercase) — case-insensitive comparison",
			params:  map[string]string{"in_cisa_kev": "FALSE"},
			wantKEV: boolPtr(false),
		},
		{
			name:        "exploit_available TRUE (uppercase)",
			params:      map[string]string{"exploit_available": "TRUE"},
			wantExploit: boolPtr(true),
		},
		{
			name:    "in_cisa_kev True (mixed case) — EqualFold accepts any casing",
			params:  map[string]string{"in_cisa_kev": "True"},
			wantKEV: boolPtr(true),
		},
		{
			name:     "in_cisa_kev yes — invalid boolean value",
			params:   map[string]string{"in_cisa_kev": "yes"},
			wantErrs: 1,
		},
		{
			name:     "in_cisa_kev 1 — invalid boolean value",
			params:   map[string]string{"in_cisa_kev": "1"},
			wantErrs: 1,
		},
		{
			name:        "exploit_available True (mixed case)",
			params:      map[string]string{"exploit_available": "True"},
			wantExploit: boolPtr(true),
		},
		{
			name:     "exploit_available yes — invalid boolean value",
			params:   map[string]string{"exploit_available": "yes"},
			wantErrs: 1,
		},
		{
			name:     "exploit_available 1 — invalid boolean value",
			params:   map[string]string{"exploit_available": "1"},
			wantErrs: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := &ListCVEsInput{}
			// Simulate huma binding the string fields.
			input.InCISAKEV = tc.params["in_cisa_kev"]
			input.ExploitAvail = tc.params["exploit_available"]

			queryFn := func(name string) string { return tc.params[name] }
			errs := input.resolveOptionalFilters(queryFn)

			if len(errs) != tc.wantErrs {
				t.Errorf("resolveOptionalFilters errors: got %d, want %d — %v", len(errs), tc.wantErrs, errs)
			}
			if tc.wantErrs > 0 {
				return
			}

			checkFloatPtr(t, "CVSSMin", input.CVSSMin, tc.wantCVSSMin)
			checkFloatPtr(t, "CVSSMax", input.CVSSMax, tc.wantCVSSMax)
			checkFloatPtr(t, "EPSSMin", input.EPSSMin, tc.wantEPSSMin)
			checkFloatPtr(t, "EPSSMax", input.EPSSMax, tc.wantEPSSMax)
			checkBoolPtr(t, "inCISAKEVBool", input.inCISAKEVBool, tc.wantKEV)
			checkBoolPtr(t, "exploitAvailBool", input.exploitAvailBool, tc.wantExploit)
		})
	}
}

// ── cveToItem ─────────────────────────────────────────────────────────────────

func TestCVEToItemMinimal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	row := generated.CVE{
		CveID:                 "CVE-2024-12345",
		DateModifiedCanonical: now,
		DateFirstSeen:         now,
		// All optional fields left as zero (invalid sql.Null*).
	}
	item := cveToItem(row)

	if item.CVEID != "CVE-2024-12345" {
		t.Errorf("CVEID = %q, want %q", item.CVEID, "CVE-2024-12345")
	}
	if item.Status != nil {
		t.Errorf("Status = %v, want nil (null NullString)", item.Status)
	}
	if item.DatePublished != nil {
		t.Errorf("DatePublished = %v, want nil (null NullTime)", item.DatePublished)
	}
	if item.DescriptionPrimary != nil {
		t.Errorf("DescriptionPrimary = %v, want nil (null NullString)", item.DescriptionPrimary)
	}
	if item.Severity != nil {
		t.Errorf("Severity = %v, want nil (null NullString)", item.Severity)
	}
	if item.CVSSv3Score != nil {
		t.Errorf("CVSSv3Score = %v, want nil (null NullFloat64)", item.CVSSv3Score)
	}
	if item.CVSSv4Score != nil {
		t.Errorf("CVSSv4Score = %v, want nil (null NullFloat64)", item.CVSSv4Score)
	}
	if item.EPSSScore != nil {
		t.Errorf("EPSSScore = %v, want nil (null NullFloat64)", item.EPSSScore)
	}
}

func TestCVEToItemNilCWEIDsBecomesEmptySlice(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	row := generated.CVE{
		CveID:                 "CVE-2024-99999",
		DateModifiedCanonical: now,
		DateFirstSeen:         now,
		CweIds:                nil, // database may return nil for empty array
	}
	item := cveToItem(row)
	if item.CWEIDs == nil {
		t.Error("CWEIDs should be an empty slice, not nil (avoids JSON null)")
	}
}

func TestCVEToItemOptionalFieldsSet(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	cvssScore := 9.8
	epssScore := 0.97
	row := generated.CVE{
		CveID:                 "CVE-2024-54321",
		DateModifiedCanonical: now,
		DateFirstSeen:         now,
		Status:                sql.NullString{String: "Published", Valid: true},
		DatePublished:         sql.NullTime{Time: now, Valid: true},
		DescriptionPrimary:    sql.NullString{String: "A critical bug", Valid: true},
		Severity:              sql.NullString{String: "CRITICAL", Valid: true},
		CvssV3Score:           sql.NullFloat64{Float64: cvssScore, Valid: true},
		CvssV4Score:           sql.NullFloat64{Float64: 9.5, Valid: true},
		EpssScore:             sql.NullFloat64{Float64: epssScore, Valid: true},
		InCisaKev:             true,
		ExploitAvailable:      true,
		CvssScoreDiverges:     true,
		CweIds:                []string{"CWE-79"},
	}
	item := cveToItem(row)

	if item.Status == nil || *item.Status != "Published" {
		t.Errorf("Status = %v, want %q", item.Status, "Published")
	}
	if item.DatePublished == nil {
		t.Error("DatePublished should not be nil when valid")
	}
	if item.DescriptionPrimary == nil || *item.DescriptionPrimary != "A critical bug" {
		t.Errorf("DescriptionPrimary = %v, want %q", item.DescriptionPrimary, "A critical bug")
	}
	if item.Severity == nil || *item.Severity != "CRITICAL" {
		t.Errorf("Severity = %v, want %q", item.Severity, "CRITICAL")
	}
	if item.CVSSv3Score == nil || *item.CVSSv3Score != cvssScore {
		t.Errorf("CVSSv3Score = %v, want %v", item.CVSSv3Score, cvssScore)
	}
	if item.EPSSScore == nil || *item.EPSSScore != epssScore {
		t.Errorf("EPSSScore = %v, want %v", item.EPSSScore, epssScore)
	}
	if !item.InCISAKEV {
		t.Error("InCISAKEV should be true")
	}
	if !item.ExploitAvailable {
		t.Error("ExploitAvailable should be true")
	}
	if !item.CVSSScoreDiverges {
		t.Error("CVSSScoreDiverges should be true")
	}
}

func TestCVEToItemTimestampsRFC3339(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	row := generated.CVE{
		CveID:                 "CVE-2024-11111",
		DateModifiedCanonical: ts,
		DateFirstSeen:         ts,
	}
	item := cveToItem(row)

	// Should be RFC3339 formatted, not RFC3339Nano or custom.
	want := "2026-02-25T12:00:00Z"
	if item.DateModified != want {
		t.Errorf("DateModified = %q, want %q", item.DateModified, want)
	}
	if item.DateFirstSeen != want {
		t.Errorf("DateFirstSeen = %q, want %q", item.DateFirstSeen, want)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func floatPtr(f float64) *float64 { return &f }
func boolPtr(b bool) *bool        { return &b }

func checkFloatPtr(t *testing.T, name string, got, want *float64) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("%s: got %v, want nil", name, *got)
		}
		return
	}
	if got == nil {
		t.Errorf("%s: got nil, want %v", name, *want)
		return
	}
	if *got != *want {
		t.Errorf("%s: got %v, want %v", name, *got, *want)
	}
}

func checkBoolPtr(t *testing.T, name string, got, want *bool) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("%s: got %v, want nil", name, *got)
		}
		return
	}
	if got == nil {
		t.Errorf("%s: got nil, want %v", name, *want)
		return
	}
	if *got != *want {
		t.Errorf("%s: got %v, want %v", name, *got, *want)
	}
}

// ── HTTP-level CVE handler tests ──────────────────────────────────────────

// newCVETestServer builds a Server + httptest.Server backed by a real TestDB.
// Returns the test server and a JWT access token for an authenticated user.
func newCVETestServer(t *testing.T, db *testutil.TestDB) (*httptest.Server, string) {
	t.Helper()
	_, ts := newRegisterServer(t, db, "open")
	ctx := context.Background()
	_ = doRegister(t, ctx, ts, "cve-test@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "cve-test@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec // test
	return ts, token
}

// cveListResponse mirrors the JSON response from GET /api/v1/cves.
type cveListResponse struct {
	Items      []json.RawMessage `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// cveDetailResponse mirrors the JSON response from GET /api/v1/cves/{cve_id}.
type cveDetailResponse struct {
	CVEID            string            `json:"cve_id"`
	Status           *string           `json:"status,omitempty"`
	Severity         *string           `json:"severity,omitempty"`
	AffectedPackages []json.RawMessage `json:"affected_packages"`
	AffectedCPEs     []json.RawMessage `json:"affected_cpes"`
	References       []json.RawMessage `json:"references"`
	CWEIDs           []string          `json:"cwe_ids"`
}

// cveSourcesResponse mirrors the JSON response from GET /api/v1/cves/{cve_id}/sources.
type cveSourcesResponse struct {
	Sources []json.RawMessage `json:"sources"`
}

// TestListCVEs_EmptyDB verifies that GET /cves returns 200 with an empty items
// array when no CVEs exist in the database.
func TestListCVEs_EmptyDB(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cves: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body cveListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Items == nil {
		t.Error("items should be an empty array, not null")
	}
	if len(body.Items) != 0 {
		t.Errorf("items length = %d, want 0", len(body.Items))
	}
	if body.NextCursor != "" {
		t.Errorf("next_cursor = %q, want empty", body.NextCursor)
	}
}

// TestListCVEs_WithSeededData verifies that GET /cves returns seeded CVEs
// with correct JSON shape and default ordering (date_modified desc).
func TestListCVEs_WithSeededData(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	// Seed CVEs with distinct modification dates so ordering is deterministic.
	earlier := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	db.SeedTestCVE(t, "CVE-2026-0001", "HIGH", &testutil.SeedCVEOpts{
		DateModifiedCanonical: &earlier,
	})
	db.SeedTestCVE(t, "CVE-2026-0002", "CRITICAL", &testutil.SeedCVEOpts{
		DateModifiedCanonical: &later,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cves: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body cveListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("items length = %d, want 2", len(body.Items))
	}

	// Verify ordering: most recently modified first.
	var first, second struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.Unmarshal(body.Items[0], &first); err != nil {
		t.Fatalf("unmarshal first item: %v", err)
	}
	if err := json.Unmarshal(body.Items[1], &second); err != nil {
		t.Fatalf("unmarshal second item: %v", err)
	}
	if first.CVEID != "CVE-2026-0002" {
		t.Errorf("first item cve_id = %q, want %q (most recent)", first.CVEID, "CVE-2026-0002")
	}
	if second.CVEID != "CVE-2026-0001" {
		t.Errorf("second item cve_id = %q, want %q", second.CVEID, "CVE-2026-0001")
	}
}

// TestListCVEs_SeverityFilter verifies that the severity query parameter filters results.
func TestListCVEs_SeverityFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2026-1001", "CRITICAL", nil)
	db.SeedTestCVE(t, "CVE-2026-1002", "LOW", nil)
	db.SeedTestCVE(t, "CVE-2026-1003", "CRITICAL", nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves?severity=CRITICAL", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves?severity=CRITICAL: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cves?severity=CRITICAL: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body cveListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("items length = %d, want 2 (CRITICAL only)", len(body.Items))
	}

	// Verify all returned items are CRITICAL.
	for i, raw := range body.Items {
		var item struct {
			Severity *string `json:"severity"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatalf("unmarshal item[%d]: %v", i, err)
		}
		if item.Severity == nil || *item.Severity != "CRITICAL" {
			t.Errorf("item[%d] severity = %v, want CRITICAL", i, item.Severity)
		}
	}
}

// TestListCVEs_ResponseShape verifies the JSON structure of list response items
// includes all expected fields.
func TestListCVEs_ResponseShape(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	cvss := 9.1
	epss := 0.85
	db.SeedTestCVE(t, "CVE-2026-2001", "HIGH", &testutil.SeedCVEOpts{
		CvssV3Score:      &cvss,
		EpssScore:        &epss,
		ExploitAvailable: true,
		InCisaKev:        true,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cves: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body cveListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items length = %d, want 1", len(body.Items))
	}

	// Decode into a generic map to verify field presence.
	var item map[string]interface{}
	if err := json.Unmarshal(body.Items[0], &item); err != nil {
		t.Fatalf("unmarshal item: %v", err)
	}

	requiredFields := []string{
		"cve_id", "date_modified", "date_first_seen",
		"cwe_ids", "cvss_score_diverges", "exploit_available", "in_cisa_kev",
	}
	for _, f := range requiredFields {
		if _, ok := item[f]; !ok {
			t.Errorf("response item missing required field %q", f)
		}
	}

	// Verify the seeded values appear correctly.
	if id, _ := item["cve_id"].(string); id != "CVE-2026-2001" {
		t.Errorf("cve_id = %q, want %q", id, "CVE-2026-2001")
	}
	if exploit, _ := item["exploit_available"].(bool); !exploit {
		t.Error("exploit_available should be true")
	}
	if kev, _ := item["in_cisa_kev"].(bool); !kev {
		t.Error("in_cisa_kev should be true")
	}

	// CWE IDs should be a JSON array (not null).
	cweRaw, ok := item["cwe_ids"]
	if !ok {
		t.Fatal("cwe_ids missing")
	}
	if cweRaw == nil {
		t.Error("cwe_ids should be [] not null")
	}
}

// TestGetCVE_Exists verifies that GET /cves/{cve_id} returns 200 with the
// correct CVE detail including child-table arrays.
func TestGetCVE_Exists(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2026-3001", "MEDIUM", nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves/CVE-2026-3001", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves/CVE-2026-3001: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cves/CVE-2026-3001: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var detail cveDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if detail.CVEID != "CVE-2026-3001" {
		t.Errorf("cve_id = %q, want %q", detail.CVEID, "CVE-2026-3001")
	}
	if detail.Severity == nil || *detail.Severity != "MEDIUM" {
		t.Errorf("severity = %v, want MEDIUM", detail.Severity)
	}

	// Child-table arrays should be present (empty, not null).
	if detail.AffectedPackages == nil {
		t.Error("affected_packages should be [] not null")
	}
	if detail.AffectedCPEs == nil {
		t.Error("affected_cpes should be [] not null")
	}
	if detail.References == nil {
		t.Error("references should be [] not null")
	}
	if detail.CWEIDs == nil {
		t.Error("cwe_ids should be [] not null")
	}
}

// TestGetCVE_NotFound verifies that GET /cves/{cve_id} returns 404 for a
// nonexistent CVE ID.
func TestGetCVE_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves/CVE-9999-99999", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves/CVE-9999-99999: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /cves/CVE-9999-99999: got status %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestGetCVESources_Exists verifies that GET /cves/{cve_id}/sources returns 200
// for an existing CVE (with an empty sources array when no sources are seeded).
func TestGetCVESources_Exists(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2026-4001", "LOW", nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves/CVE-2026-4001/sources", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves/CVE-2026-4001/sources: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cves/CVE-2026-4001/sources: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body cveSourcesResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Sources == nil {
		t.Error("sources should be [] not null")
	}
}

// TestGetCVESources_NotFound verifies that GET /cves/{cve_id}/sources returns
// 404 for a nonexistent CVE ID.
func TestGetCVESources_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves/CVE-9999-88888/sources", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves/CVE-9999-88888/sources: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /cves/CVE-9999-88888/sources: got status %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestListCVEs_Pagination verifies that the keyset cursor pagination works
// end-to-end via HTTP: a small limit produces a next_cursor, and fetching
// with that cursor returns the remaining rows.
func TestListCVEs_Pagination(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	// Seed 3 CVEs with distinct timestamps.
	for i, id := range []string{"CVE-2026-5001", "CVE-2026-5002", "CVE-2026-5003"} {
		seedTime := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC)
		db.SeedTestCVE(t, id, "MEDIUM", &testutil.SeedCVEOpts{
			DateModifiedCanonical: &seedTime,
		})
	}

	// Page 1: limit=2, should get 2 items + next_cursor.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves?limit=2", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves?limit=2: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page 1: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var page1 cveListResponse
	if err := json.NewDecoder(resp.Body).Decode(&page1); err != nil {
		t.Fatalf("decode page 1: %v", err)
	}
	if len(page1.Items) != 2 {
		t.Fatalf("page 1 items = %d, want 2", len(page1.Items))
	}
	if page1.NextCursor == "" {
		t.Fatal("page 1 next_cursor should not be empty when more rows exist")
	}

	// Page 2: use cursor, should get 1 item + no next_cursor.
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves?limit=2&cursor="+page1.NextCursor, nil)
	req2.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request page 2: %v", err)
	}
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves page 2: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("page 2: got status %d, want %d", resp2.StatusCode, http.StatusOK)
	}

	var page2 cveListResponse
	if err := json.NewDecoder(resp2.Body).Decode(&page2); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(page2.Items) != 1 {
		t.Errorf("page 2 items = %d, want 1", len(page2.Items))
	}
	if page2.NextCursor != "" {
		t.Errorf("page 2 next_cursor = %q, want empty (last page)", page2.NextCursor)
	}
}

// TestListCVEs_InvalidCursor verifies that a malformed cursor returns 400.
func TestListCVEs_InvalidCursor(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, token := newCVETestServer(t, db)
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves?cursor=not-valid-base64!!!", nil)
	req.Header.Set("Cookie", "access_token="+token)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves with bad cursor: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad cursor: got status %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// TestListCVEs_Unauthenticated verifies that CVE list returns 401 without auth.
func TestListCVEs_Unauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, _ := newCVETestServer(t, db)
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves (no auth): %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated: got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestGetCVE_Unauthenticated verifies that CVE detail returns 401 without auth.
func TestGetCVE_Unauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ts, _ := newCVETestServer(t, db)
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves/CVE-2026-0001", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /cves/CVE-2026-0001 (no auth): %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated: got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
