// ABOUTME: Tests for SCIM bearer token generation and hashing.
// ABOUTME: Verifies token format, deterministic hashing, and uniqueness.
package auth

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateSCIMToken(t *testing.T) {
	t.Parallel()

	raw, hash, prefix, err := GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken() error = %v", err)
	}

	// Token starts with the SCIM prefix.
	if !strings.HasPrefix(raw, SCIMTokenPrefix) {
		t.Errorf("raw token %q does not start with %q", raw, SCIMTokenPrefix)
	}

	// Length: 11 (prefix "cvert_scim_") + 64 (hex of 32 bytes) = 75.
	if len(raw) != 75 {
		t.Errorf("raw token length = %d, want 75", len(raw))
	}

	// Hash is 64 hex chars (sha256).
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Errorf("hash is not valid hex: %v", err)
	}

	// Prefix is the first 8 chars of the raw token.
	if prefix != raw[:8] {
		t.Errorf("prefix = %q, want %q", prefix, raw[:8])
	}
}

func TestHashSCIMToken(t *testing.T) {
	t.Parallel()

	token := "cvert_scim_deadbeef" //nolint:gosec // G101 false positive: test fixture, not a credential

	// Deterministic: same input produces same output.
	h1 := HashSCIMToken(token)
	h2 := HashSCIMToken(token)
	if h1 != h2 {
		t.Errorf("HashSCIMToken not deterministic: %q != %q", h1, h2)
	}

	// Output is 64 hex chars.
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64", len(h1))
	}
	if _, err := hex.DecodeString(h1); err != nil {
		t.Errorf("hash is not valid hex: %v", err)
	}
}

func TestGenerateSCIMToken_Uniqueness(t *testing.T) {
	t.Parallel()

	raw1, hash1, _, err := GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken() #1 error = %v", err)
	}

	raw2, hash2, _, err := GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken() #2 error = %v", err)
	}

	if raw1 == raw2 {
		t.Error("two generated tokens have the same raw value")
	}
	if hash1 == hash2 {
		t.Error("two generated tokens have the same hash")
	}
}
