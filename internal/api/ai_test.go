// ABOUTME: Integration tests for AI-powered NL search and CVE summarization handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB with a mock LLM client.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/ai"
	"github.com/scarson/cvert-ops/internal/config"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
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

	srv, ts := newAITestServer(t, db)
	// Use a small AI quota so we exhaust it well before the org rate limiter's
	// burst window (free tier = 10 burst). With quota=3 we only need 4 requests.
	srv.cfg.AINLSearchLimitFree = 3
	reg := doRegister(t, ctx, ts, "nlquota@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlquota@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Seed a CVE so the DSL query returns something.
	db.SeedTestCVE(t, "CVE-2024-0010", "critical", nil)

	// Exhaust the quota (limit is 3 for this test).
	// Each query must be unique to avoid cache hits (cache hits are free).
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"query":"quota test query %d"}`, i)
		resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
	}

	// The 4th request should be denied.
	body := `{"query":"quota test query overflow"}`
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

	// Seed 6 unique CVEs to avoid cache hits (cache hits are free, don't consume quota).
	for i := 0; i < 6; i++ {
		db.SeedTestCVE(t, fmt.Sprintf("CVE-2024-%04d", 2001+i), "high", nil)
	}

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summquota@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summquota@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Exhaust the quota (limit is 5 for free tier summarize).
	// Each request uses a unique CVE to ensure cache miss.
	for i := 0; i < 5; i++ {
		resp := doSummarize(t, ctx, ts, token, reg.OrgID, fmt.Sprintf("CVE-2024-%04d", 2001+i))
		resp.Body.Close() //nolint:errcheck,gosec
	}

	// The 6th request (unique CVE, cache miss) should be denied.
	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-2006")
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

// newAITestServerWithLLM creates a Server with a custom LLM client (e.g. error-injecting mock).
func newAITestServerWithLLM(t *testing.T, db *testutil.TestDB, llm ai.LLMClient) (*Server, *httptest.Server) {
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
	srv.SetAIDeps(llm)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// ── LLM failure path tests ──────────────────────────────────────────────────

func TestNLSearchHandler_LLMFailure(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	errMock := ai.NewMockClient()
	errMock.Err = fmt.Errorf("simulated LLM outage")

	_, ts := newAITestServerWithLLM(t, db, errMock)
	reg := doRegister(t, ctx, ts, "nlllmfail@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlllmfail@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	body := `{"query":"critical CVEs"}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nl-search LLM failure: got %d, want 503", resp.StatusCode)
	}

	// Verify the error was logged in ai_request_log with status='error'.
	var status, errorType string
	err := db.DB().QueryRowContext(ctx,
		`SELECT status, error_type FROM ai_request_log
		 WHERE feature = 'nl_search'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&status, &errorType)
	if err != nil {
		t.Fatalf("query ai_request_log: %v", err)
	}
	if status != "error" {
		t.Errorf("ai_request_log status = %q, want 'error'", status)
	}
	if errorType != "llm_failure" {
		t.Errorf("ai_request_log error_type = %q, want 'llm_failure'", errorType)
	}
}

func TestSummarizeHandler_LLMFailure(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-6001", "critical", nil)

	errMock := ai.NewMockClient()
	errMock.Err = fmt.Errorf("simulated LLM outage")

	_, ts := newAITestServerWithLLM(t, db, errMock)
	reg := doRegister(t, ctx, ts, "summllmfail@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summllmfail@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-6001")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("summarize LLM failure: got %d, want 503", resp.StatusCode)
	}

	// Verify the error was logged in ai_request_log with status='error'.
	var status, errorType string
	err := db.DB().QueryRowContext(ctx,
		`SELECT status, error_type FROM ai_request_log
		 WHERE feature = 'summarize'
		 ORDER BY created_at DESC LIMIT 1`,
	).Scan(&status, &errorType)
	if err != nil {
		t.Fatalf("query ai_request_log: %v", err)
	}
	if status != "error" {
		t.Errorf("ai_request_log status = %q, want 'error'", status)
	}
	if errorType != "llm_failure" {
		t.Errorf("ai_request_log error_type = %q, want 'llm_failure'", errorType)
	}
}

// ── Unauthenticated access tests ─────────────────────────────────────────────

func TestNLSearchHandler_Unauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)

	// Register to get a valid org ID, but don't send the auth cookie.
	reg := doRegister(t, ctx, ts, "nlnoauth@example.com", "test-password-1234")

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+reg.OrgID+"/ai/nl-search",
		bytes.NewBufferString(`{"query":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	// No Cookie header — unauthenticated.

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("nl-search unauthenticated: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nl-search unauthenticated: got %d, want 401", resp.StatusCode)
	}
}

func TestSummarizeHandler_Unauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "summnoauth@example.com", "test-password-1234")

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+reg.OrgID+"/ai/summarize/CVE-2024-0001", nil)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	// No Cookie header — unauthenticated.

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("summarize unauthenticated: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("summarize unauthenticated: got %d, want 401", resp.StatusCode)
	}
}

// ── Boundary: exactly 1000-char query is accepted ────────────────────────────

func TestNLSearchHandler_1000CharQueryAccepted(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-7001", "critical", nil)

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nl1000@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nl1000@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Exactly 1000 characters — should be accepted.
	query1000 := strings.Repeat("a", 1000)
	body := `{"query":"` + query1000 + `"}`
	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nl-search 1000-char query: got %d, want 200", resp.StatusCode)
	}
}

// ── parseIntParam unit tests ─────────────────────────────────────────────────

func TestParseIntParam(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		input      string
		defaultVal int
		min        int
		max        int
		want       int
	}{
		{"empty returns default", "", 25, 1, 100, 25},
		{"valid in range", "50", 25, 1, 100, 50},
		{"at min boundary", "1", 25, 1, 100, 1},
		{"at max boundary", "100", 25, 1, 100, 100},
		{"below min clamped", "0", 25, 1, 100, 1},
		{"above max clamped", "101", 25, 1, 100, 100},
		{"negative clamped to min", "-5", 25, 1, 100, 1},
		{"non-numeric returns default", "abc", 25, 1, 100, 25},
		{"float returns default", "3.14", 25, 1, 100, 25},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIntParam(tc.input, tc.defaultVal, tc.min, tc.max)
			if got != tc.want {
				t.Errorf("parseIntParam(%q, %d, %d, %d) = %d, want %d",
					tc.input, tc.defaultVal, tc.min, tc.max, got, tc.want)
			}
		})
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

// ── Malformed JSON + nil LLM + quota-disabled tests ─────────────────────────

func TestNLSearchHandler_MalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "nlbadjson@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlbadjson@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, `{invalid json`)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got %d, want 400", resp.StatusCode)
	}
}

func TestNLSearchHandler_NilLLM(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create server WITHOUT calling SetAIDeps — llm remains nil.
	_, ts := newAITestServerWithLLM(t, db, nil)
	reg := doRegister(t, ctx, ts, "nlnilllm@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlnilllm@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, `{"query":"test"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil LLM: got %d, want 503", resp.StatusCode)
	}
}

func TestSummarizeHandler_NilLLM(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8001", "critical", nil)

	_, ts := newAITestServerWithLLM(t, db, nil)
	reg := doRegister(t, ctx, ts, "summnilllm@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summnilllm@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-8001")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil LLM summarize: got %d, want 503", resp.StatusCode)
	}
}

func TestNLSearchHandler_QuotaDisabled(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8002", "critical", nil)

	// Create server with quota disabled.
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "aitestsecret",
		RegistrationMode:    "open",
		Argon2MaxConcurrent: 5,
		AIQuotaEnabled:      false,
		GeminiModel:         "gemini-2.0-flash",
		AICacheNLSearchTTL:  1 * time.Hour,
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.SetAIDeps(ai.NewMockClient())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	reg := doRegister(t, ctx, ts, "nlnoquota@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "nlnoquota@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doNLSearch(t, ctx, ts, token, reg.OrgID, `{"query":"critical CVEs"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("quota disabled: got %d, want 200", resp.StatusCode)
	}
}

func TestSummarizeHandler_QuotaDisabled(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8003", "high", nil)

	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:            "aitestsecret",
		RegistrationMode:     "open",
		Argon2MaxConcurrent:  5,
		AIQuotaEnabled:       false,
		GeminiModel:          "gemini-2.0-flash",
		AICacheSummarizeTTL:  24 * time.Hour,
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.SetAIDeps(ai.NewMockClient())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	reg := doRegister(t, ctx, ts, "summnoquota@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "summnoquota@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doSummarize(t, ctx, ts, token, reg.OrgID, "CVE-2024-8003")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("summarize quota disabled: got %d, want 200", resp.StatusCode)
	}
}

// ── orgID fail-closed: non-UUID org_id in URL → 400 ─────────────────────────

func TestAIHandlers_InvalidOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "ai-badorgid@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ai-badorgid@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	_ = reg // only needed for registration side effect

	t.Run("NLSearch", func(t *testing.T) {
		resp := doNLSearch(t, ctx, ts, token, "not-a-uuid", `{"query":"test"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("nl-search invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})

	t.Run("Summarize", func(t *testing.T) {
		resp := doSummarize(t, ctx, ts, token, "not-a-uuid", "CVE-2024-0001")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("summarize invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
}

// ── Cross-org tenant isolation: user in org A cannot access org B's AI ───────

func TestAIHandlers_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9901", "critical", nil)

	_, ts := newAITestServer(t, db)

	// User A: first registered user gets auto-created org.
	regA := doRegister(t, ctx, ts, "ai-orgA@example.com", "test-password-1234")

	loginA := doLogin(t, ctx, ts, "ai-orgA@example.com", "test-password-1234")
	defer loginA.Body.Close() //nolint:errcheck,gosec
	tokenA := cookieValue(loginA, "access_token")

	// User B: second user must create their own org explicitly
	// (BootstrapFirstUserOrg only fires for the first registration).
	doRegister(t, ctx, ts, "ai-orgB@example.com", "test-password-1234")
	loginB := doLogin(t, ctx, ts, "ai-orgB@example.com", "test-password-1234")
	defer loginB.Body.Close() //nolint:errcheck,gosec
	tokenB := cookieValue(loginB, "access_token")

	orgBResp := doCreateOrg(t, ctx, ts, tokenB, "AI Org B")
	defer orgBResp.Body.Close() //nolint:errcheck,gosec
	if orgBResp.StatusCode != http.StatusCreated {
		t.Fatalf("create org B: got %d, want 201", orgBResp.StatusCode)
	}
	var orgB struct {
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(orgBResp.Body).Decode(&orgB); err != nil {
		t.Fatalf("decode org B: %v", err)
	}

	// User A tries to access org B's AI endpoints → 403.
	t.Run("NLSearch", func(t *testing.T) {
		resp := doNLSearch(t, ctx, ts, tokenA, orgB.OrgID, `{"query":"test"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org nl-search: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("Summarize", func(t *testing.T) {
		resp := doSummarize(t, ctx, ts, tokenA, orgB.OrgID, "CVE-2024-9901")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org summarize: got %d, want 403", resp.StatusCode)
		}
	})

	// Sanity: User A accessing own org works.
	t.Run("OwnOrgWorks", func(t *testing.T) {
		resp := doNLSearch(t, ctx, ts, tokenA, regA.OrgID, `{"query":"test"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode == http.StatusForbidden {
			t.Error("own-org nl-search should not be 403")
		}
	})

	_ = tokenB // used only for org creation
}

// ── buildSummaryInput sanitizes description ──────────────────────────────────

func TestBuildSummaryInput_SanitizesDescription(t *testing.T) {
	t.Parallel()
	cve := &generated.Cfe{ //nolint:exhaustruct // test: only relevant fields set
		CveID: "CVE-2024-0001",
	}
	cve.DescriptionPrimary.Valid = true
	cve.DescriptionPrimary.String = "Vuln in [lib](https://evil.com/exfil) <script>alert(1)</script>"

	input := buildSummaryInput(cve)

	// Markdown link URL and HTML tags should be stripped by Sanitize().
	if strings.Contains(input.Description, "evil.com") {
		t.Errorf("description should have markdown URLs stripped, got: %s", input.Description)
	}
	if strings.Contains(input.Description, "<script>") {
		t.Errorf("description should have HTML tags stripped, got: %s", input.Description)
	}
	// Preserved text content.
	if !strings.Contains(input.Description, "Vuln in lib") {
		t.Errorf("description should preserve text, got: %s", input.Description)
	}
}

func TestBuildSummaryInput_NullFields(t *testing.T) {
	t.Parallel()
	// All NullXxx fields are zero-valued (not valid).
	cve := &generated.Cfe{ //nolint:exhaustruct // test: only relevant fields set
		CveID: "CVE-2024-0002",
	}

	input := buildSummaryInput(cve)

	if input.CVEID != "CVE-2024-0002" {
		t.Errorf("CVEID = %q, want CVE-2024-0002", input.CVEID)
	}
	if input.Description != "" {
		t.Errorf("Description should be empty for null, got %q", input.Description)
	}
	if input.Severity != "" {
		t.Errorf("Severity should be empty for null, got %q", input.Severity)
	}
	if input.CVSSV3Score != nil {
		t.Errorf("CVSSV3Score should be nil for null, got %v", input.CVSSV3Score)
	}
	if input.CVSSV4Score != nil {
		t.Errorf("CVSSV4Score should be nil for null, got %v", input.CVSSV4Score)
	}
	if input.EPSSScore != nil {
		t.Errorf("EPSSScore should be nil for null, got %v", input.EPSSScore)
	}
	if input.CWEIDs != nil {
		t.Errorf("CWEIDs should be nil for null, got %v", input.CWEIDs)
	}
}

func TestNLSearchHandler_ProTierQuota(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-0099", "critical", nil)

	_, ts := newAITestServer(t, db)
	reg := doRegister(t, ctx, ts, "aipro@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "aipro@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Upgrade to pro tier — NL search limit should be 100, not 10.
	orgID, _ := uuid.Parse(reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "pro"); err != nil {
		t.Fatalf("set pro tier: %v", err)
	}

	// Send 11 requests (exceeds free=10, within pro=100). All should succeed.
	for i := 0; i < 11; i++ {
		body := fmt.Sprintf(`{"query":"pro tier query %d"}`, i)
		resp := doNLSearch(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d returned 429 — pro tier should allow 100 requests/day", i)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, resp.StatusCode)
		}
	}
}
