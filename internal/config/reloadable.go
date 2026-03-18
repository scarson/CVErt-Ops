// ABOUTME: Hot-reloadable configuration fields updated by SIGHUP or admin API.
// ABOUTME: Stored behind atomic.Pointer — readers never block, writers swap atomically.
package config

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// ReloadableConfig holds only the fields that can be updated at runtime
// without restarting the process.
type ReloadableConfig struct {
	JWTSecret            []byte
	JWTSecretPrevious    []byte
	SSOEncryptionKey     [32]byte
	SSOEncryptionKeyPrev [32]byte
	LogLevel             string
	SMTPHost             string
	SMTPPort             int
	SMTPFrom             string
	SMTPUsername         string
	SMTPPassword         string
	SMTPTLS              bool
	SIEMSyslogAddr       string // e.g., "udp://splunk:514"; empty = disabled
	SIEMSyslogFormat     string // "json" (default) or "cef"
}

// Holder provides atomic access to hot-reloadable configuration.
type Holder struct {
	ptr atomic.Pointer[ReloadableConfig]
}

// NewHolder creates a Holder seeded with the given initial config.
func NewHolder(initial *ReloadableConfig) *Holder {
	h := &Holder{}
	h.ptr.Store(initial)
	return h
}

// Load returns the current ReloadableConfig snapshot. Safe for concurrent use.
func (h *Holder) Load() *ReloadableConfig {
	return h.ptr.Load()
}

// Store atomically replaces the current config with cfg. Safe for concurrent use.
func (h *Holder) Store(cfg *ReloadableConfig) {
	h.ptr.Store(cfg)
}

// LoadFromSecretsFile parses a secrets file (one KEY=VALUE per line) and returns
// a ReloadableConfig. Comments (#) and blank lines are skipped. Returns an error
// on invalid values so the caller can keep the previous config.
func LoadFromSecretsFile(path string, baseline *ReloadableConfig) (*ReloadableConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open secrets file: %w", err)
	}
	defer func() { _ = f.Close() }()

	kv := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}

	// Start from a copy of the baseline so absent fields keep their current values.
	var rc *ReloadableConfig
	if baseline != nil {
		base := *baseline
		rc = &base
	} else {
		rc = &ReloadableConfig{}
	}

	// JWT secrets.
	if v, ok := kv["JWT_SECRET"]; ok && v != "" {
		if len(v) < 32 {
			return nil, fmt.Errorf("JWT_SECRET must be at least 32 bytes, got %d", len(v))
		}
		rc.JWTSecret = []byte(v)
	}
	if v, ok := kv["JWT_SECRET_PREVIOUS"]; ok && v != "" {
		if len(v) < 32 {
			return nil, fmt.Errorf("JWT_SECRET_PREVIOUS must be at least 32 bytes, got %d", len(v))
		}
		rc.JWTSecretPrevious = []byte(v)
	}

	// SSO encryption keys (hex-encoded, must decode to exactly 32 bytes).
	if v, ok := kv["SSO_ENCRYPTION_KEY"]; ok && v != "" {
		key, err := decodeHexKey(v, "SSO_ENCRYPTION_KEY")
		if err != nil {
			return nil, err
		}
		rc.SSOEncryptionKey = key
	}
	if v, ok := kv["SSO_ENCRYPTION_KEY_PREVIOUS"]; ok && v != "" {
		key, err := decodeHexKey(v, "SSO_ENCRYPTION_KEY_PREVIOUS")
		if err != nil {
			return nil, err
		}
		rc.SSOEncryptionKeyPrev = key
	}

	// String fields — only overwrite when present in the file.
	if v, ok := kv["LOG_LEVEL"]; ok {
		rc.LogLevel = v
	}
	if v, ok := kv["SMTP_HOST"]; ok {
		rc.SMTPHost = v
	}
	if v, ok := kv["SMTP_FROM"]; ok {
		rc.SMTPFrom = v
	}
	if v, ok := kv["SMTP_USERNAME"]; ok {
		rc.SMTPUsername = v
	}
	if v, ok := kv["SMTP_PASSWORD"]; ok {
		rc.SMTPPassword = v
	}
	if v, ok := kv["SIEM_SYSLOG_ADDR"]; ok {
		rc.SIEMSyslogAddr = v
	}

	// SMTP port.
	if v, ok := kv["SMTP_PORT"]; ok && v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("SMTP_PORT must be a valid integer: %w", err)
		}
		rc.SMTPPort = port
	}

	// SMTP TLS.
	if v, ok := kv["SMTP_TLS"]; ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("SMTP_TLS must be true or false: %w", err)
		}
		rc.SMTPTLS = b
	}

	// SIEM syslog format.
	if v, ok := kv["SIEM_SYSLOG_FORMAT"]; ok && v != "" {
		if v != "json" && v != "cef" {
			return nil, fmt.Errorf("SIEM_SYSLOG_FORMAT must be \"json\" or \"cef\", got %q", v)
		}
		rc.SIEMSyslogFormat = v
	}

	return rc, nil
}

// LoadFromConfig creates an initial ReloadableConfig from the startup Config.
// Called once at startup to seed the ConfigHolder.
func LoadFromConfig(cfg *Config) *ReloadableConfig {
	rc := &ReloadableConfig{
		JWTSecret:         []byte(cfg.JWTSecret),
		JWTSecretPrevious: []byte(cfg.JWTSecretPrevious),
		LogLevel:          cfg.LogLevel,
		SMTPHost:          cfg.SMTPHost,
		SMTPPort:          cfg.SMTPPort,
		SMTPFrom:          cfg.SMTPFrom,
		SMTPUsername:      cfg.SMTPUsername,
		SMTPPassword:      cfg.SMTPPassword,
		SMTPTLS:           cfg.SMTPTLS,
		SIEMSyslogAddr:    cfg.SIEMSyslogAddr,
		SIEMSyslogFormat:  cfg.SIEMSyslogFormat,
	}

	// Decode hex SSO keys from Config (best-effort; invalid keys stay zeroed).
	if key, err := decodeHexKey(cfg.SSOEncryptionKey, "SSO_ENCRYPTION_KEY"); err == nil {
		rc.SSOEncryptionKey = key
	}
	if key, err := decodeHexKey(cfg.SSOEncryptionKeyPrevious, "SSO_ENCRYPTION_KEY_PREVIOUS"); err == nil {
		rc.SSOEncryptionKeyPrev = key
	}

	return rc
}

// decodeHexKey decodes a hex string into a [32]byte. Returns an error if the
// string is not valid hex or does not decode to exactly 32 bytes.
func decodeHexKey(s, fieldName string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("%s must be valid hex: %w", fieldName, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%s must be exactly 32 bytes (64 hex chars), got %d bytes", fieldName, len(b))
	}
	copy(out[:], b)
	return out, nil
}
