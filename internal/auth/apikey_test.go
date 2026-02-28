// ABOUTME: Tests for API key generation and hashing.
// ABOUTME: Covers prefix, hash length, uniqueness, and HashAPIKey consistency.
package auth_test

import (
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/auth"
)

func TestGenerateAPIKey(t *testing.T) {
	t.Parallel()
	rawKey, hash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(rawKey, "cvo_") {
		t.Errorf("key missing cvo_ prefix, got %q", rawKey)
	}
	if len(hash) != 64 {
		t.Errorf("hash should be 64 hex chars (sha256), got %d", len(hash))
	}
}

func TestHashAPIKey(t *testing.T) {
	t.Parallel()
	rawKey, hash1, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	hash2 := auth.HashAPIKey(rawKey)
	if hash1 != hash2 {
		t.Error("HashAPIKey(rawKey) should match hash from GenerateAPIKey")
	}
}

func TestGenerateAPIKeyUnique(t *testing.T) {
	t.Parallel()
	rawKey1, _, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate 1: %v", err)
	}
	rawKey2, _, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate 2: %v", err)
	}
	if rawKey1 == rawKey2 {
		t.Error("two generated keys should differ")
	}
}


