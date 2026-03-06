// ABOUTME: Tests for AES-256-GCM authenticated encryption.
// ABOUTME: Covers round-trip, nonce uniqueness, tamper detection, wrong key, empty plaintext, and short ciphertext.
package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestAESGCM_RoundTrip(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	plaintext := []byte("secret webhook signing key 🔑")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestAESGCM_UniqueNonce(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	plaintext := []byte("same input")

	ct1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	ct2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestAESGCM_TamperedCiphertext(t *testing.T) {
	t.Parallel()
	key := testKey(t)

	ciphertext, err := Encrypt(key, []byte("tamper me"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the ciphertext body (after the nonce).
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xff

	_, err = Decrypt(key, tampered)
	if err == nil {
		t.Error("Decrypt succeeded on tampered ciphertext, want error")
	}
}

func TestAESGCM_WrongKey(t *testing.T) {
	t.Parallel()
	key1 := testKey(t)
	key2 := testKey(t)

	ciphertext, err := Encrypt(key1, []byte("wrong key test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(key2, ciphertext)
	if err == nil {
		t.Error("Decrypt succeeded with wrong key, want error")
	}
}

func TestAESGCM_EmptyPlaintext(t *testing.T) {
	t.Parallel()
	key := testKey(t)

	ciphertext, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	got, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestAESGCM_ShortCiphertext(t *testing.T) {
	t.Parallel()
	// Key length is enforced at compile time via [32]byte. Verify that
	// ciphertext too short to contain a nonce is rejected at runtime.
	key := testKey(t)

	_, err := Decrypt(key, []byte("short"))
	if err == nil {
		t.Error("Decrypt succeeded on too-short ciphertext, want error")
	}
}
