// ABOUTME: Integration tests for AI-powered NL search and CVE summarization handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB with a mock LLM client.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/ai"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newAITestServer creates a Server with AI config and mock LLM client.
func newAITestServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:                  "aitestsecret",
		RegistrationMode:           "open",
		Argon2MaxConcurrent:        5,
		AIQuotaEnabled:             true,
		AINLSearchLimitFree:        10,
		AINLSearchLimitPro:         100,
		AINLSearchLimitEnterprise:  1000,
		AISummarizeLimitFree:       5,
		AISummarizeLimitPro:        50,
		AISummarizeLimitEnterprise: 500,
		AICacheNLSearchTTL:         1 * time.Hour,
		AICacheSummarizeTTL:        24 * time.Hour,
		GeminiModel:                "gemini-2.0-flash",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.SetAIDeps(ai.NewMockClient())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// doNLSearch performs a POST to the NL search endpoint.
func doNLSearch(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/ai/nl-search", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("nl-search request: %v", err)
	}
	return resp
}

// doSummarize performs a POST to the summarize endpoint.
func doSummarize(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, cveID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/ai/summarize/"+cveID, nil)
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("summarize request: %v", err)
	}
	return resp
}

func TestNLSearchHandler_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed CVEs that will match the mock's "severity in [critical, high]" DSL.
	db.SeedTestCVE(t, "CVE-2024-0001", "critical", nil)
	db.SeedTestCVE(t, "CVE-2024-0002", "high", nil)
	db.SeedTestCVE(t, "CVE-2024-0003", "low", nil) // should not match

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nlsearch@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlsearch@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	body := `{"query":"critical CVEs"}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck,gosec
		t.Fatalf("nl-search: got %d, want 200; body: %s", resp.StatusCode, errBody)
	}

	var result struct {
		InterpretedQuery json.RawMessage `json:"interpreted_query"`
		Results          []CVEItem       `json:"results"`
		NextCursor       string          `json:"next_cursor"`
		Model            string          `json:"model"`
		Cached           bool            `json:"cached"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.InterpretedQuery == nil {
		t.Error("interpreted_query should not be nil")
	}
	// The mock returns severity in [critical, high], so we expect 2 results.
	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
	if result.Model == "" {
		t.Error("model should not be empty")
	}
	if result.Cached {
		t.Error("first request should not be cached")
	}
}

func TestNLSearchHandler_QueryTooLong(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nllong@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nllong@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	longQuery := strings.Repeat("a", 1001)
	body := `{"query":"` + longQuery + `"}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("nl-search long query: got %d, want 422", resp.StatusCode)
	}
}

func TestNLSearchHandler_EmptyQuery(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nlempty@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlempty@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	body := `{"query":""}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("nl-search empty query: got %d, want 422", resp.StatusCode)
	}
}

func TestNLSearchHandler_QuotaDenied(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nlquota@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlquota@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Seed a CVE so the DSL query returns something for the first 10 calls.
	db.SeedTestCVE(t, "CVE-2024-0010", "critical", nil)

	// Exhaust the quota (limit is 10 for free tier).
	for i := 0; i < 10; i++ {
		body := `{"query":"critical CVEs"}`
		resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
	}

	// The 11th request should be denied.
	body := `{"query":"critical CVEs"}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("nl-search quota exceeded: got %d, want 429", resp.StatusCode)
	}

	// Verify Retry-After header is present.
	if resp.Header.Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

func TestNLSearchHandler_CacheHit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-0020", "critical", nil)

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nlcache@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlcache@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	body := `{"query":"critical vulnerabilities"}`

	// First request — cache miss.
	resp1 := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp1.Body.Close() //nolint:errcheck,gosec
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first nl-search: got %d, want 200", resp1.StatusCode)
	}
	var result1 struct {
		Cached bool `json:"cached"`
	}
	json.NewDecoder(resp1.Body).Decode(&result1) //nolint:errcheck,gosec
	if result1.Cached {
		t.Error("first request should not be cached")
	}

	// Second request with same query — cache hit.
	resp2 := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second nl-search: got %d, want 200", resp2.StatusCode)
	}
	var result2 struct {
		Cached bool `json:"cached"`
	}
	json.NewDecoder(resp2.Body).Decode(&result2) //nolint:errcheck,gosec
	if !result2.Cached {
		t.Error("second request should be cached")
	}
}

func TestSummarizeHandler_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-1001", "critical", &testutil.SeedCVEOpts{
		DescriptionPrimary: "A critical buffer overflow in libfoo.",
	})

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summ@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summ@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-1001")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck,gosec
		t.Fatalf("summarize: got %d, want 200; body: %s", resp.StatusCode, errBody)
	}

	var result struct {
		CVEID   string `json:"cve_id"`
		Summary string `json:"summary"`
		Model   string `json:"model"`
		Cached  bool   `json:"cached"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.CVEID != "CVE-2024-1001" {
		t.Errorf("cve_id = %q, want CVE-2024-1001", result.CVEID)
	}
	if result.Summary == "" {
		t.Error("summary should not be empty")
	}
	if !strings.Contains(result.Summary, "CVE-2024-1001") {
		t.Errorf("summary should mention the CVE ID, got: %s", result.Summary)
	}
	if result.Model == "" {
		t.Error("model should not be empty")
	}
	if result.Cached {
		t.Error("first request should not be cached")
	}
}

func TestSummarizeHandler_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summ404@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summ404@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-9999-9999")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("summarize not found: got %d, want 404", resp.StatusCode)
	}
}

func TestSummarizeHandler_QuotaDenied(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-2001", "high", nil)

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summquota@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summquota@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Exhaust the quota (limit is 5 for free tier summarize).
	for i := 0; i < 5; i++ {
		resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-2001")
		resp.Body.Close() //nolint:errcheck,gosec
	}

	// The 6th request should be denied.
	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-2001")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("summarize quota exceeded: got %d, want 429", resp.StatusCode)
	}

	if resp.Header.Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

// ── Unit tests for helper functions ──────────────────────────────────────────

func TestIsValidCVEID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  bool
	}{
		{"CVE-2024-0001", true},
		{"CVE-2024-12345", true},
		{"CVE-1999-9999", true},
		{"CVE-2024-123456789", true}, // long serial
		{"CVE-2024-123", false},      // too short (3 digits)
		{"cve-2024-0001", false},     // lowercase
		{"CVE-20240001", false},      // missing dash
		{"CVE-2024-ABCD", false},     // non-numeric serial
		{"CVE-24-0001", false},       // two-digit year
		{"GHSA-xxxx-yyyy", false},    // not a CVE
		{"", false},
		{"CVE-", false},
		{"CVE-2024-", false},
	}
	for _, tc := range cases {
		if got := isValidCVEID(tc.input); got != tc.want {
			t.Errorf("isValidCVEID(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestTruncateForLog(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},                                    // under limit
		{"exactly10!", 10, "exactly10!"},                          // at limit
		{"this is too long", 10, "this is to...(truncated)"},      // over limit
		{"", 5, ""},                                               // empty string
		{"abcdef", 3, "abc...(truncated)"},                        // small limit
	}
	for _, tc := range cases {
		if got := truncateForLog(tc.input, tc.maxLen); got != tc.want {
			t.Errorf("truncateForLog(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
		}
	}
}

// ── Summarize: invalid CVE ID format ─────────────────────────────────────────

func TestSummarizeHandler_InvalidCVEID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summbadid@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summbadid@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	badIDs := []string{
		"not-a-cve",
		"GHSA-1234-5678",
		"CVE-2024-123", // too short serial
		"cve-2024-0001", // lowercase
	}
	for _, badID := range badIDs {
		resp := doSummarize(t, ctx, ts, token, reg.OrgID, badID)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("summarize(%q): got %d, want 400", badID, resp.StatusCode)
		}
		resp.Body.Close() //nolint:errcheck,gosec
	}
}

// ── Token counts persisted in ai_request_log on success ──────────────────────

func TestNLSearchHandler_TokenCountsPersisted(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-5001", "critical", nil)

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nltokens@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nltokens@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	body := `{"query":"critical CVEs"}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nl-search: got %d, want 200", resp.StatusCode)
	}

	// Verify token counts were persisted in ai_request_log.
	var inputTokens, outputTokens int
	err := db.DB().QueryRowContext(ctx,
		`SELECT input_tokens, output_tokens FROM ai_request_log
		 WHERE feature = 'nl_search' AND status = 'success'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&inputTokens, &outputTokens)
	if err != nil {
		t.Fatalf("query ai_request_log: %v", err)
	}
	// MockClient.GenerateStructured returns InputTokens=10, OutputTokens=20.
	if inputTokens != 10 {
		t.Errorf("input_tokens = %d, want 10", inputTokens)
	}
	if outputTokens != 20 {
		t.Errorf("output_tokens = %d, want 20", outputTokens)
	}
}

func TestSummarizeHandler_CacheHit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-3001", "medium", &testutil.SeedCVEOpts{
		DescriptionPrimary: "A medium-severity issue in barlib.",
		MaterialHash:       "stable-hash-for-cache-test",
	})

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summcache@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summcache@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// First request — cache miss.
	resp1 := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-3001")
	defer resp1.Body.Close() //nolint:errcheck,gosec
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first summarize: got %d, want 200", resp1.StatusCode)
	}
	var result1 struct {
		Cached bool `json:"cached"`
	}
	json.NewDecoder(resp1.Body).Decode(&result1) //nolint:errcheck,gosec
	if result1.Cached {
		t.Error("first request should not be cached")
	}

	// Second request — cache hit.
	resp2 := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-3001")
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second summarize: got %d, want 200", resp2.StatusCode)
	}
	var result2 struct {
		Cached bool `json:"cached"`
	}
	json.NewDecoder(resp2.Body).Decode(&result2) //nolint:errcheck,gosec
	if !result2.Cached {
		t.Error("second request should be cached")
	}
}
