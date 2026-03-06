// ABOUTME: Unit tests for validateConfig — JWT secret length and HTTPS enforcement.
// ABOUTME: Pure unit tests with no network or Postgres dependency.
package main

import (
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
)

func TestValidateConfig_JWTSecretTooShort(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields
		JWTSecret:   "short",
		AppEnv:      "development",
		ExternalURL: "http://localhost:8080",
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for short JWT secret")
	}
	if !strings.Contains(err.Error(), "JWT_SECRET") {
		t.Errorf("error = %q, want mention of JWT_SECRET", err)
	}
}

func TestValidateConfig_JWTSecretMinLength(t *testing.T) {
	t.Parallel()
	secret32 := strings.Repeat("a", 32)
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields
		JWTSecret:   secret32,
		AppEnv:      "development",
		ExternalURL: "http://localhost:8080",
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig with 32-byte secret: %v", err)
	}
}

func TestValidateConfig_HTTPSRequiredInProduction(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields
		JWTSecret:   strings.Repeat("a", 32),
		AppEnv:      "production",
		ExternalURL: "http://app.example.com",
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for HTTP in production")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error = %q, want mention of https://", err)
	}
}

func TestValidateConfig_HTTPSAcceptedInProduction(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields
		JWTSecret:   strings.Repeat("a", 32),
		AppEnv:      "production",
		ExternalURL: "https://app.example.com",
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig with HTTPS in production: %v", err)
	}
}

func TestValidateConfig_DevModeHTTPBypass(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields
		JWTSecret:   strings.Repeat("a", 32),
		AppEnv:      "development",
		ExternalURL: "http://localhost:8080",
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig dev mode with HTTP: %v", err)
	}
}
