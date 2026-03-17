// ABOUTME: Tests for hot-reloadable configuration loading and atomic access.
// ABOUTME: Covers secrets file parsing, validation, concurrent access safety.
package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadFromSecretsFile_ValidFile(t *testing.T) {
	// Build a valid 32-byte hex key (64 hex chars).
	ssoKey := strings.Repeat("ab", 32)
	ssoPrevKey := strings.Repeat("cd", 32)

	content := strings.Join([]string{
		"JWT_SECRET=this-is-a-secret-that-is-at-least-32-bytes-long",
		"JWT_SECRET_PREVIOUS=another-secret-that-is-at-least-32-bytes",
		"SSO_ENCRYPTION_KEY=" + ssoKey,
		"SSO_ENCRYPTION_KEY_PREVIOUS=" + ssoPrevKey,
		"LOG_LEVEL=debug",
		"SMTP_HOST=mail.example.com",
		"SMTP_PORT=587",
		"SMTP_FROM=alerts@example.com",
		"SMTP_USERNAME=user",
		"SMTP_PASSWORD=pass",
		"SMTP_TLS=true",
		"SIEM_SYSLOG_ADDR=udp://splunk:514",
		"SIEM_SYSLOG_FORMAT=cef",
	}, "\n")

	path := writeTemp(t, content)
	rc, err := LoadFromSecretsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(rc.JWTSecret) != "this-is-a-secret-that-is-at-least-32-bytes-long" {
		t.Errorf("JWTSecret = %q", rc.JWTSecret)
	}
	if string(rc.JWTSecretPrevious) != "another-secret-that-is-at-least-32-bytes" {
		t.Errorf("JWTSecretPrevious = %q", rc.JWTSecretPrevious)
	}

	wantSSO, _ := hex.DecodeString(ssoKey)
	if rc.SSOEncryptionKey != [32]byte(wantSSO) {
		t.Errorf("SSOEncryptionKey mismatch")
	}
	wantSSOPrev, _ := hex.DecodeString(ssoPrevKey)
	if rc.SSOEncryptionKeyPrev != [32]byte(wantSSOPrev) {
		t.Errorf("SSOEncryptionKeyPrev mismatch")
	}

	if rc.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", rc.LogLevel, "debug")
	}
	if rc.SMTPHost != "mail.example.com" {
		t.Errorf("SMTPHost = %q", rc.SMTPHost)
	}
	if rc.SMTPPort != 587 {
		t.Errorf("SMTPPort = %d, want 587", rc.SMTPPort)
	}
	if rc.SMTPFrom != "alerts@example.com" {
		t.Errorf("SMTPFrom = %q", rc.SMTPFrom)
	}
	if rc.SMTPUsername != "user" {
		t.Errorf("SMTPUsername = %q", rc.SMTPUsername)
	}
	if rc.SMTPPassword != "pass" {
		t.Errorf("SMTPPassword = %q", rc.SMTPPassword)
	}
	if !rc.SMTPTLS {
		t.Error("SMTPTLS = false, want true")
	}
	if rc.SIEMSyslogAddr != "udp://splunk:514" {
		t.Errorf("SIEMSyslogAddr = %q", rc.SIEMSyslogAddr)
	}
	if rc.SIEMSyslogFormat != "cef" {
		t.Errorf("SIEMSyslogFormat = %q", rc.SIEMSyslogFormat)
	}
}

func TestLoadFromSecretsFile_InvalidJWTSecret(t *testing.T) {
	content := "JWT_SECRET=short"
	path := writeTemp(t, content)

	_, err := LoadFromSecretsFile(path)
	if err == nil {
		t.Fatal("expected error for short JWT secret")
	}
	if !strings.Contains(err.Error(), "JWT_SECRET") {
		t.Errorf("error should mention JWT_SECRET: %v", err)
	}
}

func TestLoadFromSecretsFile_InvalidSSOKey(t *testing.T) {
	// Not valid hex — odd length.
	content := "SSO_ENCRYPTION_KEY=not-valid-hex-at-all"
	path := writeTemp(t, content)

	_, err := LoadFromSecretsFile(path)
	if err == nil {
		t.Fatal("expected error for invalid SSO key")
	}
	if !strings.Contains(err.Error(), "SSO_ENCRYPTION_KEY") {
		t.Errorf("error should mention SSO_ENCRYPTION_KEY: %v", err)
	}
}

func TestLoadFromSecretsFile_SSOKeyWrongLength(t *testing.T) {
	// Valid hex but only 16 bytes (32 hex chars), not 32 bytes.
	content := "SSO_ENCRYPTION_KEY=" + strings.Repeat("ab", 16)
	path := writeTemp(t, content)

	_, err := LoadFromSecretsFile(path)
	if err == nil {
		t.Fatal("expected error for wrong-length SSO key")
	}
}

func TestLoadFromSecretsFile_CommentsAndBlankLines(t *testing.T) {
	content := strings.Join([]string{
		"# This is a comment",
		"",
		"  ",
		"LOG_LEVEL=warn",
		"  # Another comment",
		"SMTP_HOST=mx.test",
	}, "\n")

	path := writeTemp(t, content)
	rc, err := LoadFromSecretsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", rc.LogLevel, "warn")
	}
	if rc.SMTPHost != "mx.test" {
		t.Errorf("SMTPHost = %q, want %q", rc.SMTPHost, "mx.test")
	}
}

func TestLoadFromSecretsFile_InvalidSIEMFormat(t *testing.T) {
	content := "SIEM_SYSLOG_FORMAT=xml"
	path := writeTemp(t, content)

	_, err := LoadFromSecretsFile(path)
	if err == nil {
		t.Fatal("expected error for invalid SIEM format")
	}
	if !strings.Contains(err.Error(), "SIEM_SYSLOG_FORMAT") {
		t.Errorf("error should mention SIEM_SYSLOG_FORMAT: %v", err)
	}
}

func TestLoadFromSecretsFile_InvalidSMTPPort(t *testing.T) {
	content := "SMTP_PORT=notanumber"
	path := writeTemp(t, content)

	_, err := LoadFromSecretsFile(path)
	if err == nil {
		t.Fatal("expected error for invalid SMTP port")
	}
}

func TestLoadFromSecretsFile_EmptyFile(t *testing.T) {
	path := writeTemp(t, "")
	rc, err := LoadFromSecretsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All fields should be zero values.
	if rc.LogLevel != "" {
		t.Errorf("LogLevel = %q, want empty", rc.LogLevel)
	}
}

func TestLoadFromSecretsFile_MissingFile(t *testing.T) {
	_, err := LoadFromSecretsFile("/nonexistent/file/path")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFromConfig(t *testing.T) {
	cfg := &Config{ //nolint:gosec // G101: test fixture values, not real credentials
		JWTSecret:                "my-jwt-secret-that-is-long-enough",
		JWTSecretPrevious:        "old-jwt-secret-that-is-long-enough",
		SSOEncryptionKey:         strings.Repeat("ab", 32),
		SSOEncryptionKeyPrevious: strings.Repeat("cd", 32),
		LogLevel:                 "info",
		SMTPHost:                 "smtp.test",
		SMTPPort:                 25,
		SMTPFrom:                 "noreply@test",
		SMTPUsername:             "user",
		SMTPPassword:             "pass",
		SMTPTLS:                  true,
	}

	rc := LoadFromConfig(cfg)
	if string(rc.JWTSecret) != cfg.JWTSecret {
		t.Errorf("JWTSecret mismatch")
	}
	if string(rc.JWTSecretPrevious) != cfg.JWTSecretPrevious {
		t.Errorf("JWTSecretPrevious mismatch")
	}
	if rc.LogLevel != "info" {
		t.Errorf("LogLevel = %q", rc.LogLevel)
	}
	if rc.SMTPHost != "smtp.test" {
		t.Errorf("SMTPHost = %q", rc.SMTPHost)
	}
	if rc.SMTPPort != 25 {
		t.Errorf("SMTPPort = %d", rc.SMTPPort)
	}
	if rc.SMTPFrom != "noreply@test" {
		t.Errorf("SMTPFrom = %q", rc.SMTPFrom)
	}
	if !rc.SMTPTLS {
		t.Error("SMTPTLS should be true")
	}
}

func TestLoadFromConfig_SSOKeyDecoding(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	cfg := &Config{
		JWTSecret:        "placeholder-secret-32-bytes-long!",
		SSOEncryptionKey: hexKey,
	}
	rc := LoadFromConfig(cfg)

	wantBytes, _ := hex.DecodeString(hexKey)
	if rc.SSOEncryptionKey != [32]byte(wantBytes) {
		t.Error("SSOEncryptionKey not decoded correctly from Config")
	}
}

func TestConfigHolder_LoadStoreAtomic(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info"}
	h := NewHolder(initial)

	got := h.Load()
	if got.LogLevel != "info" {
		t.Errorf("Load() = %q, want %q", got.LogLevel, "info")
	}

	updated := &ReloadableConfig{LogLevel: "debug"}
	h.Store(updated)

	got = h.Load()
	if got.LogLevel != "debug" {
		t.Errorf("after Store, Load() = %q, want %q", got.LogLevel, "debug")
	}
}

func TestConfigHolder_ConcurrentLoadStore(t *testing.T) {
	initial := &ReloadableConfig{LogLevel: "info", SMTPPort: 25}
	h := NewHolder(initial)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				// Writer.
				h.Store(&ReloadableConfig{
					LogLevel: "debug",
					SMTPPort: 587,
				})
			} else {
				// Reader — must see a consistent snapshot (never partial).
				cfg := h.Load()
				// LogLevel and SMTPPort must be from the same config.
				if cfg.LogLevel == "info" && cfg.SMTPPort != 25 {
					t.Errorf("inconsistent snapshot: LogLevel=%q SMTPPort=%d", cfg.LogLevel, cfg.SMTPPort)
				}
				if cfg.LogLevel == "debug" && cfg.SMTPPort != 587 {
					t.Errorf("inconsistent snapshot: LogLevel=%q SMTPPort=%d", cfg.LogLevel, cfg.SMTPPort)
				}
			}
		}(i)
	}
	wg.Wait()
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
