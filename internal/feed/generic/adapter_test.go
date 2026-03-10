// ABOUTME: Tests for the config-driven generic feed adapter.
// ABOUTME: Covers JSON mapping, pagination, auth, rate limiting, error handling, and CSAF format.
package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Task 4: Core JSON Mapping (Design doc test cases #1, #2, #3, #12, #13) ---

func TestAdapter_SimpleFlatArray(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [
			{"cve": "CVE-2026-0001", "summary": "Test vuln", "cvss_score": 8.1, "risk": "HIGH", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}
		]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "test-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, // fast for tests
		Timeout:   "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":        "cve",
				"description":   "summary",
				"cvss_v3_score":  "cvss_score",
				"severity":      "risk",
				"cvss_v3_vector": "vector",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)

	p := result.Patches[0]
	assert.Equal(t, "CVE-2026-0001", p.CVEID)
	assert.Equal(t, "Test vuln", *p.DescriptionPrimary)
	assert.Equal(t, 8.1, *p.CVSSv3Score)
	assert.Equal(t, "HIGH", *p.Severity)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", *p.CVSSv3Vector)
	assert.Equal(t, "test-feed", result.SourceMeta.SourceName)
	assert.True(t, result.LastPage, "single-page fetch should set LastPage")
}

func TestAdapter_NestedEnvelope(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data": {"results": [
			{"id": "CVE-2026-0002", "text": "Nested vuln", "scoring": {"cvss": 7.5}}
		]}}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "nested-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "data.results",
			Fields: map[string]string{
				"cve_id":       "id",
				"description":  "text",
				"cvss_v3_score": "scoring.cvss",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)
	assert.Equal(t, "CVE-2026-0002", result.Patches[0].CVEID)
	assert.Equal(t, "Nested vuln", *result.Patches[0].DescriptionPrimary)
	assert.Equal(t, 7.5, *result.Patches[0].CVSSv3Score)
}

func TestAdapter_SparseFields(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"vulns": [{"cve": "CVE-2026-0003", "desc": "Sparse"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "sparse-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "vulns",
			Fields: map[string]string{
				"cve_id":      "cve",
				"description": "desc",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)

	p := result.Patches[0]
	assert.Equal(t, "CVE-2026-0003", p.CVEID)
	assert.Equal(t, "Sparse", *p.DescriptionPrimary)
	assert.Nil(t, p.CVSSv3Score, "unmapped fields must be nil")
	assert.Nil(t, p.CVSSv3Vector)
	assert.Nil(t, p.Severity)
}

func TestAdapter_CVSS00Preserved(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-0004", "score": 0.0}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "zero-cvss-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":       "cve",
				"cvss_v3_score": "score",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)
	require.NotNil(t, result.Patches[0].CVSSv3Score, "CVSS 0.0 must not be nil")
	assert.Equal(t, 0.0, *result.Patches[0].CVSSv3Score)
}

func TestAdapter_NullByteSanitized(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Embed a literal null byte in the description.
		fmt.Fprint(w, "{\"items\": [{\"cve\": \"CVE-2026-0005\", \"desc\": \"has\\u0000null\"}]}")
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "nullbyte-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":      "cve",
				"description": "desc",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)
	assert.NotContains(t, *result.Patches[0].DescriptionPrimary, "\x00",
		"null bytes must be stripped")
	assert.Equal(t, "hasnull", *result.Patches[0].DescriptionPrimary)
}

func TestAdapter_DateFields(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-0006", "pub": "2026-01-15T00:00:00Z", "mod": "2026-03-01T12:30:00Z"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "date-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":         "cve",
				"date_published": "pub",
				"date_modified":  "mod",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)

	p := result.Patches[0]
	require.NotNil(t, p.DatePublished)
	assert.Equal(t, 2026, p.DatePublished.Year())
	assert.Equal(t, time.January, p.DatePublished.Month())
	assert.Equal(t, 15, p.DatePublished.Day())
	require.NotNil(t, p.DateModified)
}

func TestAdapter_ReferencesArray(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-0007", "links": [{"url": "https://a.com"}, {"url": "https://b.com"}]}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "ref-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":     "cve",
				"references": "links.#.url",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)
	assert.Len(t, result.Patches[0].References, 2)
	assert.Equal(t, "https://a.com", result.Patches[0].References[0].URL)
	assert.Equal(t, "https://b.com", result.Patches[0].References[1].URL)
}

func TestAdapter_RawPayload(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-0008", "extra": "data"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "raw-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":      "cve",
				"raw_payload": "@this",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1)
	assert.NotNil(t, result.Patches[0].RawPayload)
	assert.Contains(t, string(result.Patches[0].RawPayload), "CVE-2026-0008")
}

// --- Task 8: CSAF Format (Design doc test case #4) ---

func TestAdapter_CSAFFormat(t *testing.T) {
	t.Parallel()

	csafDoc := `{
		"document": {
			"title": "Test Advisory",
			"type": "csaf_security_advisory",
			"tracking": {
				"id": "ADV-2026-001",
				"initial_release_date": "2026-01-10T00:00:00Z",
				"current_release_date": "2026-03-05T12:00:00Z"
			}
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2026-9001",
				"notes": [{"type": "description", "text": "CSAF test vuln"}],
				"scores": [{
					"cvss_v3": {
						"version": "3.1",
						"baseScore": 7.8,
						"vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
					}
				}],
				"references": [
					{"url": "https://example.com/advisory/1", "summary": "Advisory"}
				]
			},
			{
				"cve": "CVE-2026-9002",
				"notes": [{"type": "summary", "text": "Second vuln"}],
				"scores": []
			}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, csafDoc)
	}))
	defer srv.Close()

	cfg := &Config{
		Name:      "csaf-feed",
		URL:       srv.URL,
		Format:    "csaf",
		RateLimit: 100,
		Timeout:   "5s",
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 2)
	assert.True(t, result.LastPage, "CSAF is always single-document")
	assert.Equal(t, "csaf-feed", result.SourceMeta.SourceName)

	// First vulnerability: full fields.
	p1 := result.Patches[0]
	assert.Equal(t, "CVE-2026-9001", p1.CVEID)
	require.NotNil(t, p1.DescriptionPrimary)
	assert.Equal(t, "CSAF test vuln", *p1.DescriptionPrimary)
	require.NotNil(t, p1.CVSSv3Score)
	assert.Equal(t, 7.8, *p1.CVSSv3Score)
	require.NotNil(t, p1.CVSSv3Vector)
	assert.Equal(t, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", *p1.CVSSv3Vector)
	assert.Len(t, p1.References, 1)
	assert.Equal(t, "https://example.com/advisory/1", p1.References[0].URL)
	require.NotNil(t, p1.DatePublished)
	assert.Equal(t, 2026, p1.DatePublished.Year())
	require.NotNil(t, p1.DateModified)
	assert.NotNil(t, p1.RawPayload, "CSAF vulns should have raw payload")

	// Second vulnerability: sparse — no CVSS, description from "summary" note type.
	p2 := result.Patches[1]
	assert.Equal(t, "CVE-2026-9002", p2.CVEID)
	require.NotNil(t, p2.DescriptionPrimary)
	assert.Equal(t, "Second vuln", *p2.DescriptionPrimary)
	assert.Nil(t, p2.CVSSv3Score, "no scores → nil CVSS")
	assert.Nil(t, p2.CVSSv3Vector)
}

func TestAdapter_EmptyCVEIDSkipped(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "", "desc": "no id"}, {"cve": "CVE-2026-0009", "desc": "has id"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "skip-empty-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root: "items",
			Fields: map[string]string{
				"cve_id":      "cve",
				"description": "desc",
			},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Patches, 1, "records with empty CVE ID should be filtered out")
	assert.Equal(t, "CVE-2026-0009", result.Patches[0].CVEID)
}

// --- Task 5: Pagination (Design doc test cases #5, #6, #15) ---

func TestAdapter_OffsetPagination(t *testing.T) {
	t.Parallel()

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		page := r.URL.Query().Get("page")
		perPage := r.URL.Query().Get("per_page")
		assert.Equal(t, "5", perPage, "size param should be sent")

		var items []map[string]any
		switch page {
		case "", "1":
			for i := 0; i < 5; i++ {
				items = append(items, map[string]any{"cve": fmt.Sprintf("CVE-2026-1%03d", i)})
			}
		case "2":
			for i := 0; i < 5; i++ {
				items = append(items, map[string]any{"cve": fmt.Sprintf("CVE-2026-2%03d", i)})
			}
		case "3":
			// Last page — fewer than page_size items.
			for i := 0; i < 3; i++ {
				items = append(items, map[string]any{"cve": fmt.Sprintf("CVE-2026-3%03d", i)})
			}
		default:
			t.Fatalf("unexpected page: %s", page)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "offset-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Pagination: PaginationConfig{
			Type:      "offset",
			PageParam: "page",
			SizeParam: "per_page",
			PageSize:  5,
		},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	ctx := context.Background()

	// Page 1
	r1, err := adapter.Fetch(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, r1.Patches, 5)
	assert.False(t, r1.LastPage)

	// Page 2
	r2, err := adapter.Fetch(ctx, r1.NextCursor)
	require.NoError(t, err)
	assert.Len(t, r2.Patches, 5)
	assert.False(t, r2.LastPage)

	// Page 3 (last — fewer than page_size)
	r3, err := adapter.Fetch(ctx, r2.NextCursor)
	require.NoError(t, err)
	assert.Len(t, r3.Patches, 3)
	assert.True(t, r3.LastPage)

	assert.Equal(t, 3, callCount)
}

func TestAdapter_CursorPagination(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		w.Header().Set("Content-Type", "application/json")
		switch after {
		case "":
			fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-4001"}], "meta": {"next": "cursor-abc"}}`)
		case "cursor-abc":
			fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-4002"}], "meta": {"next": ""}}`)
		default:
			t.Fatalf("unexpected cursor: %s", after)
		}
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "cursor-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Pagination: PaginationConfig{
			Type:        "cursor",
			CursorParam: "after",
			CursorPath:  "meta.next",
		},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	ctx := context.Background()

	r1, err := adapter.Fetch(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, r1.Patches, 1)
	assert.False(t, r1.LastPage)

	r2, err := adapter.Fetch(ctx, r1.NextCursor)
	require.NoError(t, err)
	assert.Len(t, r2.Patches, 1)
	assert.True(t, r2.LastPage, "empty cursor path value means last page")
}

func TestAdapter_LinkHeaderPagination(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		if strings.HasSuffix(path, "/page2") {
			// No Link header on last page.
			fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-5002"}]}`)
			return
		}
		// First page — include Link header with next.
		w.Header().Set("Link", fmt.Sprintf(`<%s/page2>; rel="next"`, srvURL))
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-5001"}]}`)
	}))
	srvURL = srv.URL
	defer srv.Close()

	cfg := &Config{
		Name: "link-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Pagination: PaginationConfig{Type: "link-header"},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	ctx := context.Background()

	r1, err := adapter.Fetch(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, r1.Patches, 1)
	assert.Equal(t, "CVE-2026-5001", r1.Patches[0].CVEID)
	assert.False(t, r1.LastPage)

	r2, err := adapter.Fetch(ctx, r1.NextCursor)
	require.NoError(t, err)
	assert.Len(t, r2.Patches, 1)
	assert.Equal(t, "CVE-2026-5002", r2.Patches[0].CVEID)
	assert.True(t, r2.LastPage, "no Link rel=next means last page")
}

// --- Task 6: Auth (Design doc test cases #7, #8) ---

func TestAdapter_BearerAuth(t *testing.T) {
	t.Setenv("TEST_BEARER_TOKEN", "secret-token-123")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-6001"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "bearer-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Auth: AuthConfig{Type: "bearer", TokenEnv: "TEST_BEARER_TOKEN"},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	_, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "Bearer secret-token-123", gotAuth)
}

func TestAdapter_BasicAuth(t *testing.T) {
	t.Setenv("TEST_USER", "admin")
	t.Setenv("TEST_PASS", "secret")

	var gotUser, gotPass string
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-6002"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "basic-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Auth: AuthConfig{Type: "basic", UsernameEnv: "TEST_USER", PasswordEnv: "TEST_PASS"},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	_, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, gotOK)
	assert.Equal(t, "admin", gotUser)
	assert.Equal(t, "secret", gotPass)
}

func TestAdapter_HeaderAuth(t *testing.T) {
	t.Setenv("TEST_API_KEY", "key-xyz")

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-6003"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "header-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Auth: AuthConfig{Type: "header", HeaderName: "X-API-Key", HeaderValueEnv: "TEST_API_KEY"},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	_, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "key-xyz", gotHeader)
}

func TestAdapter_AuthEnvVarUnset(t *testing.T) {
	// Deliberately do NOT set any env var. No t.Parallel() — shares env/slog state.

	// Capture slog output so the expected WARN doesn't leak to test output.
	var logBuf bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"cve": "CVE-2026-6004"}]}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "noauth-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Auth: AuthConfig{Type: "bearer", TokenEnv: "NONEXISTENT_TOKEN_VAR_12345"},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err, "missing auth env var should not cause error")
	assert.Empty(t, gotAuth, "no auth header should be sent when env var is unset")
	assert.Len(t, result.Patches, 1)
	assert.Contains(t, logBuf.String(), "auth env var not set",
		"should log a warning when auth env var is missing")
}

// --- Task 7: Rate Limiting & Error Handling (Design doc test cases #10, #11) ---

func TestAdapter_RateLimiting(t *testing.T) {
	t.Parallel()

	requestTimes := []time.Time{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.Header().Set("Content-Type", "application/json")
		// Return a page with items to keep paginating.
		page := r.URL.Query().Get("page")
		switch page {
		case "", "1":
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"cve": "CVE-2026-7001"}, {"cve": "CVE-2026-7002"}},
			})
		case "2":
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"cve": "CVE-2026-7003"}},
			})
		}
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "ratelimit-feed", URL: srv.URL, Format: "json",
		RateLimit: 2, // 2 req/sec → at least 500ms between requests
		Timeout:   "5s",
		Pagination: PaginationConfig{
			Type:      "offset",
			PageParam: "page",
			SizeParam: "per_page",
			PageSize:  2,
		},
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	ctx := context.Background()

	r1, err := adapter.Fetch(ctx, nil)
	require.NoError(t, err)
	assert.False(t, r1.LastPage)

	r2, err := adapter.Fetch(ctx, r1.NextCursor)
	require.NoError(t, err)
	assert.True(t, r2.LastPage)

	require.Len(t, requestTimes, 2)
	gap := requestTimes[1].Sub(requestTimes[0])
	// With rate=2/sec, gap should be >= 400ms (allowing some slack).
	assert.GreaterOrEqual(t, gap.Milliseconds(), int64(400),
		"requests should be rate-limited, gap was %v", gap)
}

func TestAdapter_URLUnreachable(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Name: "unreachable-feed", URL: "http://192.0.2.1:1", Format: "json",
		RateLimit: 100, Timeout: "1s",
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, nil)
	_, err := adapter.Fetch(context.Background(), nil)
	assert.Error(t, err, "unreachable URL should return error")
}

func TestAdapter_NonJSONResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>not json</html>")
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "html-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	_, err := adapter.Fetch(context.Background(), nil)
	assert.Error(t, err, "non-JSON response should cause error")
}

func TestAdapter_HTTP500(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "error-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	_, err := adapter.Fetch(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestAdapter_EmptyResultArray(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": []}`)
	}))
	defer srv.Close()

	cfg := &Config{
		Name: "empty-feed", URL: srv.URL, Format: "json",
		RateLimit: 100, Timeout: "5s",
		Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "cve"},
		},
	}
	adapter := NewAdapter(cfg, srv.Client())
	result, err := adapter.Fetch(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, result.Patches)
	assert.True(t, result.LastPage)
}
