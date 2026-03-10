// ABOUTME: YAML configuration format and validation for config-driven generic feed adapters.
// ABOUTME: Parsed from files in CVERTOPS_FEEDS_DIR; validated at startup and by validate-feeds CLI.
package generic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scarson/cvert-ops/internal/ingest"
	"go.yaml.in/yaml/v4"
)

// Config defines the YAML configuration for a single generic feed.
type Config struct {
	Name       string           `yaml:"name"`
	URL        string           `yaml:"url"`
	Schedule   string           `yaml:"schedule"`
	Auth       AuthConfig       `yaml:"auth"`
	Format     string           `yaml:"format"`     // "json" or "csaf"
	RateLimit  float64          `yaml:"rate_limit"`  // requests/second, default 1
	Timeout    string           `yaml:"timeout"`     // duration string, default "30s"
	Pagination PaginationConfig `yaml:"pagination"`
	Mapping    MappingConfig    `yaml:"mapping"`
}

// AuthConfig describes how to authenticate requests to the feed URL.
type AuthConfig struct {
	Type           string `yaml:"type"`             // none | bearer | basic | header
	TokenEnv       string `yaml:"token_env"`        // env var for bearer token
	UsernameEnv    string `yaml:"username_env"`      // env var for basic auth username
	PasswordEnv    string `yaml:"password_env"`      // env var for basic auth password
	HeaderName     string `yaml:"header_name"`       // custom header name
	HeaderValueEnv string `yaml:"header_value_env"`  // env var for custom header value
}

// PaginationConfig describes how to paginate through feed results.
type PaginationConfig struct {
	Type        string `yaml:"type"`         // none | offset | cursor | link-header
	PageParam   string `yaml:"page_param"`   // offset: query param for page number
	SizeParam   string `yaml:"size_param"`   // offset: query param for page size
	PageSize    int    `yaml:"page_size"`    // offset: items per page
	CursorParam string `yaml:"cursor_param"` // cursor: query param for cursor value
	CursorPath  string `yaml:"cursor_path"`  // cursor: gjson path to next cursor in response
}

// MappingConfig describes how to extract CVE data from the feed response.
type MappingConfig struct {
	Root   string            `yaml:"root"`   // gjson path to the array of records
	Fields map[string]string `yaml:"fields"` // canonical field name → gjson path
}

// ParseConfig parses a YAML byte slice into a Config, applying defaults.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{
		RateLimit: 1,
		Timeout:   "30s",
		Auth:      AuthConfig{Type: "none"},
		Pagination: PaginationConfig{Type: "none"},
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return cfg, nil
}

// Validate checks that all required fields are present and values are valid.
// Returns an error describing all validation failures.
func (c *Config) Validate() error {
	var errs []string

	if c.Name == "" {
		errs = append(errs, "name is required")
	}
	if c.URL == "" {
		errs = append(errs, "url is required")
	}

	// Format validation.
	switch c.Format {
	case "json", "csaf":
		// ok
	case "":
		errs = append(errs, "format is required (json or csaf)")
	default:
		errs = append(errs, fmt.Sprintf("format must be json or csaf, got %q", c.Format))
	}

	// Mapping validation — required for json, not for csaf.
	if c.Format != "csaf" {
		if c.Mapping.Root == "" {
			errs = append(errs, "mapping.root is required for json format")
		}
		if c.Mapping.Fields == nil || c.Mapping.Fields["cve_id"] == "" {
			errs = append(errs, "mapping.fields.cve_id is required for json format")
		}
	}

	// Reserved name check.
	if c.Name != "" && ingest.IsReservedSourceName(c.Name) {
		errs = append(errs, fmt.Sprintf("name %q is reserved (built-in feed name)", c.Name))
	}

	// Cron schedule validation (if provided).
	if c.Schedule != "" {
		if err := validateCron(c.Schedule); err != nil {
			errs = append(errs, fmt.Sprintf("schedule: %v", err))
		}
	}

	// Auth type validation.
	switch c.Auth.Type {
	case "none", "bearer", "basic", "header", "":
		// ok
	default:
		errs = append(errs, fmt.Sprintf("auth.type must be none, bearer, basic, or header, got %q", c.Auth.Type))
	}

	// Pagination type validation.
	switch c.Pagination.Type {
	case "none", "offset", "cursor", "link-header", "":
		// ok
	default:
		errs = append(errs, fmt.Sprintf("pagination.type must be none, offset, cursor, or link-header, got %q", c.Pagination.Type))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

// validateCron performs basic validation of a 5-field cron expression.
// Accepts standard 5-field cron: minute hour day-of-month month day-of-week.
func validateCron(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("expected 5 fields, got %d", len(fields))
	}
	// Basic check: each field contains only valid cron characters.
	for i, field := range fields {
		for _, ch := range field {
			if !((ch >= '0' && ch <= '9') || ch == '*' || ch == '/' || ch == '-' || ch == ',') {
				return fmt.Errorf("field %d contains invalid character %q", i+1, string(ch))
			}
		}
	}
	return nil
}

// LoadDir scans a directory for *.yaml and *.yml files, parses and validates
// each one. Returns valid configs and accumulated errors separately. Invalid
// configs produce errors but do not prevent valid ones from loading.
func LoadDir(dir string) ([]Config, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("read feeds directory %q: %w", dir, err)}
	}

	var configs []Config
	var errs []error

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}

		cfg, err := ParseConfig(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}

		if err := cfg.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}

		configs = append(configs, *cfg)
	}

	return configs, errs
}

// Loader wraps a feeds directory path and provides Rescan for SIGHUP integration.
type Loader struct {
	dir string
}

// NewLoader creates a Loader for the given feeds directory.
func NewLoader(dir string) *Loader {
	return &Loader{dir: dir}
}

// Rescan re-reads and re-validates all feed configs from the directory.
// Intended for future SIGHUP integration (Secure pillar, Phase 8E).
func (l *Loader) Rescan() ([]Config, []error) {
	return LoadDir(l.dir)
}
