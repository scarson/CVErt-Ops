// ABOUTME: Tests for argon2id password hashing and verification.
// ABOUTME: Covers correct password, wrong password, and hash uniqueness.
package auth_test

import (
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
