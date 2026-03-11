// ABOUTME: Tests for YAML config parsing and validation of generic feed adapter configurations.
// ABOUTME: Covers valid YAML parsing, required field validation, reserved name rejection, and cron validation.
package generic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig_ValidYAML(t *testing.T) {
	t.Parallel()

	raw := `
name: internal-scanner
url: "https://vulnscanner.internal/api/v1/findings"
schedule: "0 */4 * * *"
auth:
  type: bearer
  token_env: "INTERNAL_SCANNER_TOKEN"
format: json
rate_limit: 2
timeout: 30s
pagination:
  type: offset
  page_param: "page"
  size_param: "per_page"
  page_size: 100
mapping:
  root: "findings"
  fields:
    cve_id: "cve"
    description: "summary"
    severity: "risk_level"
    cvss_v3_score: "cvss_score"
`
	cfg, err := ParseConfig([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, "internal-scanner", cfg.Name)
	assert.Equal(t, "https://vulnscanner.internal/api/v1/findings", cfg.URL)
	assert.Equal(t, "0 */4 * * *", cfg.Schedule)
	assert.Equal(t, "bearer", cfg.Auth.Type)
	assert.Equal(t, "INTERNAL_SCANNER_TOKEN", cfg.Auth.TokenEnv)
	assert.Equal(t, "json", cfg.Format)
	assert.Equal(t, float64(2), cfg.RateLimit)
	assert.Equal(t, "offset", cfg.Pagination.Type)
	assert.Equal(t, "page", cfg.Pagination.PageParam)
	assert.Equal(t, "per_page", cfg.Pagination.SizeParam)
	assert.Equal(t, 100, cfg.Pagination.PageSize)
	assert.Equal(t, "findings", cfg.Mapping.Root)
	assert.Equal(t, "cve", cfg.Mapping.Fields["cve_id"])
	assert.Equal(t, "summary", cfg.Mapping.Fields["description"])
	assert.Equal(t, "risk_level", cfg.Mapping.Fields["severity"])
	assert.Equal(t, "cvss_score", cfg.Mapping.Fields["cvss_v3_score"])
}

func TestParseConfig_Defaults(t *testing.T) {
	t.Parallel()

	raw := `
name: minimal-feed
url: "https://example.com/feed"
format: json
mapping:
  root: "items"
  fields:
    cve_id: "id"
`
	cfg, err := ParseConfig([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, float64(1), cfg.RateLimit, "default rate_limit should be 1")
	assert.Equal(t, "30s", cfg.Timeout, "default timeout should be 30s")
	assert.Equal(t, "none", cfg.Auth.Type, "default auth type should be none")
	assert.Equal(t, "none", cfg.Pagination.Type, "default pagination type should be none")
}

func TestValidateConfig_MissingName(t *testing.T) {
	t.Parallel()
	cfg := &Config{URL: "http://example.com", Format: "json", Mapping: MappingConfig{
		Root:   "items",
		Fields: map[string]string{"cve_id": "id"},
	}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidateConfig_MissingURL(t *testing.T) {
	t.Parallel()
	cfg := &Config{Name: "test-feed", Format: "json", Mapping: MappingConfig{
		Root:   "items",
		Fields: map[string]string{"cve_id": "id"},
	}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "url")
}

func TestValidateConfig_MissingFormat(t *testing.T) {
	t.Parallel()
	cfg := &Config{Name: "test-feed", URL: "http://example.com", Mapping: MappingConfig{
		Root:   "items",
		Fields: map[string]string{"cve_id": "id"},
	}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestValidateConfig_InvalidFormat(t *testing.T) {
	t.Parallel()
	cfg := &Config{Name: "test-feed", URL: "http://example.com", Format: "xml", Mapping: MappingConfig{
		Root:   "items",
		Fields: map[string]string{"cve_id": "id"},
	}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestValidateConfig_MissingMappingRoot(t *testing.T) {
	t.Parallel()
	cfg := &Config{Name: "test-feed", URL: "http://example.com", Format: "json", Mapping: MappingConfig{
		Fields: map[string]string{"cve_id": "id"},
	}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mapping.root")
}

func TestValidateConfig_MissingCVEIDField(t *testing.T) {
	t.Parallel()
	cfg := &Config{Name: "test-feed", URL: "http://example.com", Format: "json", Mapping: MappingConfig{
		Root:   "items",
		Fields: map[string]string{"description": "desc"},
	}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cve_id")
}

func TestValidateConfig_CSAFFormatSkipsMappingValidation(t *testing.T) {
	t.Parallel()
	cfg := &Config{Name: "test-csaf", URL: "http://example.com", Format: "csaf"}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidateConfig_ReservedName(t *testing.T) {
	t.Parallel()
	reservedNames := []string{"nvd", "mitre", "kev", "ghsa", "osv", "epss", "msrc", "redhat"}
	for _, name := range reservedNames {
		cfg := &Config{Name: name, URL: "http://example.com", Format: "json", Mapping: MappingConfig{
			Root:   "items",
			Fields: map[string]string{"cve_id": "id"},
		}}
		err := cfg.Validate()
		assert.Error(t, err, "reserved name %q should be rejected", name)
		assert.Contains(t, err.Error(), "reserved")
	}
}

func TestValidateConfig_InvalidCronSchedule(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Name: "test-feed", URL: "http://example.com", Format: "json",
		Schedule: "not-a-cron",
		Mapping:  MappingConfig{Root: "items", Fields: map[string]string{"cve_id": "id"}},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "schedule")
}

func TestValidateConfig_ValidCronSchedules(t *testing.T) {
	t.Parallel()
	validCrons := []string{
		"0 */4 * * *",
		"*/15 * * * *",
		"0 0 * * 0",
		"30 2 * * 1-5",
		"0 0 1 * *",
	}
	for _, cron := range validCrons {
		cfg := &Config{
			Name: "test-feed", URL: "http://example.com", Format: "json",
			Schedule: cron,
			Mapping:  MappingConfig{Root: "items", Fields: map[string]string{"cve_id": "id"}},
		}
		err := cfg.Validate()
		assert.NoError(t, err, "valid cron %q should be accepted", cron)
	}
}

func TestValidateConfig_EmptyScheduleAllowed(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Name: "test-feed", URL: "http://example.com", Format: "json",
		Mapping: MappingConfig{Root: "items", Fields: map[string]string{"cve_id": "id"}},
	}
	err := cfg.Validate()
	assert.NoError(t, err, "empty schedule should be allowed (webhook-only feeds)")
}

func TestValidateConfig_InvalidPaginationType(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Name: "test-feed", URL: "http://example.com", Format: "json",
		Pagination: PaginationConfig{Type: "graphql"},
		Mapping:    MappingConfig{Root: "items", Fields: map[string]string{"cve_id": "id"}},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pagination")
}

func TestValidateConfig_InvalidAuthType(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Name: "test-feed", URL: "http://example.com", Format: "json",
		Auth:    AuthConfig{Type: "oauth2"},
		Mapping: MappingConfig{Root: "items", Fields: map[string]string{"cve_id": "id"}},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth")
}

func TestValidateConfig_CollectsMultipleErrors(t *testing.T) {
	t.Parallel()
	cfg := &Config{} // missing everything
	err := cfg.Validate()
	assert.Error(t, err)
	errStr := err.Error()
	// Should mention multiple missing fields
	assert.True(t, strings.Contains(errStr, "name") && strings.Contains(errStr, "url"),
		"should report multiple validation errors, got: %s", errStr)
}

func TestLoadDir_MixedValidAndInvalid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Valid config
	validYAML := `
name: good-feed
url: "https://example.com/feed"
format: json
mapping:
  root: "items"
  fields:
    cve_id: "id"
`
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// Invalid config (missing required fields)
	invalidYAML := `
url: "https://example.com/feed"
format: json
`
	if err := os.WriteFile(filepath.Join(dir, "bad.yml"), []byte(invalidYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-YAML file (should be ignored)
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	configs, errs := LoadDir(dir)
	assert.Len(t, configs, 1)
	assert.Equal(t, "good-feed", configs[0].Name)
	assert.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "bad.yml")
}

func TestLoadDir_EmptyDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configs, errs := LoadDir(dir)
	assert.Empty(t, configs)
	assert.Empty(t, errs)
}

func TestLoadDir_NonexistentDirectory(t *testing.T) {
	t.Parallel()
	configs, errs := LoadDir("/nonexistent/path")
	assert.Empty(t, configs)
	assert.Len(t, errs, 1)
}

func TestLoader_Rescan(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	validYAML := `
name: rescan-feed
url: "https://example.com/feed"
format: json
mapping:
  root: "items"
  fields:
    cve_id: "id"
`
	if err := os.WriteFile(filepath.Join(dir, "feed.yaml"), []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(dir)
	configs, errs := loader.Rescan()
	assert.Len(t, configs, 1)
	assert.Equal(t, "rescan-feed", configs[0].Name)
	assert.Empty(t, errs)
}
