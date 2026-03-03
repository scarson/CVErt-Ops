// ABOUTME: Tests for argon2id password hashing and verification.
// ABOUTME: Covers correct password, wrong password, and hash uniqueness.
package auth_test

import (
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/auth"
)

func TestHashPassword(t *testing.T) {
	t.Parallel()
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" {
		t.Error("hash is empty")
	}

	ok, err := auth.VerifyPassword("correct-horse-battery-staple", hash)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("correct password should verify")
	}
}

func TestHashPasswordWrongPassword(t *testing.T) {
	t.Parallel()
	hash, err := auth.HashPassword("real-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := auth.VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Error("wrong password should not verify")
	}
}

func TestHashPasswordUnique(t *testing.T) {
	t.Parallel()
	hash1, err := auth.HashPassword("same-password")
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	hash2, err := auth.HashPassword("same-password")
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (different salts)")
	}
}

func TestHashPasswordOWASPParameters(t *testing.T) {
	t.Parallel()
	hash, err := auth.HashPassword("test-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// PHC format: $argon2id$v=19$m=M,t=T,p=P$salt$key
	// OWASP parameters: m=19456, t=2, p=1
	if !strings.Contains(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash does not contain OWASP parameters, got %q", hash)
	}
}

func TestVerifyPasswordMalformedHash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not PHC format", "plaintext-hash"},
		{"wrong algorithm", "$bcrypt$v=19$m=19456,t=2,p=1$c2FsdA$a2V5"},
		{"too few parts", "$argon2id$v=19$m=19456,t=2,p=1"},
		{"bad params", "$argon2id$v=19$garbage$c2FsdA$a2V5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := auth.VerifyPassword("password", tc.hash)
			if err == nil {
				t.Error("expected error for malformed hash, got nil")
			}
		})
	}
}
