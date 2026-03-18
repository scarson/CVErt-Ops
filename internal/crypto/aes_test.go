// ABOUTME: Tests for AES-256-GCM authenticated encryption.
// ABOUTME: Covers round-trip, nonce uniqueness, tamper detection, wrong key, empty plaintext, and short ciphertext.
package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
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

// ── DecryptWithFallback ─────────────────────────────────────────────────────

func TestDecryptWithFallback_CurrentKeyWorks(t *testing.T) {
	t.Parallel()
	currentKey := testKey(t)
	previousKey := testKey(t)
	plaintext := []byte("current key decryption")

	ciphertext, err := Encrypt(currentKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := DecryptWithFallback(currentKey, previousKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithFallback: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptWithFallback_PreviousKeyWorks(t *testing.T) {
	t.Parallel()
	oldKey := testKey(t)
	newKey := testKey(t)
	plaintext := []byte("encrypted with old key")

	ciphertext, err := Encrypt(oldKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// newKey as current fails GCM auth; oldKey as previous succeeds.
	got, err := DecryptWithFallback(newKey, oldKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithFallback: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptWithFallback_BothKeysWrong(t *testing.T) {
	t.Parallel()
	keyA := testKey(t)
	keyB := testKey(t)
	keyC := testKey(t)
	plaintext := []byte("neither key works")

	ciphertext, err := Encrypt(keyA, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = DecryptWithFallback(keyB, keyC, ciphertext)
	if err == nil {
		t.Error("DecryptWithFallback succeeded with both wrong keys, want error")
	}
}

func TestDecryptWithFallback_NoPreviousKey(t *testing.T) {
	t.Parallel()
	currentKey := testKey(t)
	var zeroKey [32]byte
	plaintext := []byte("no previous key")

	ciphertext, err := Encrypt(currentKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Zero previous key → only current key tried.
	got, err := DecryptWithFallback(currentKey, zeroKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithFallback: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptWithFallback_TruncatedCiphertext_NoFallback(t *testing.T) {
	t.Parallel()
	// Data too short for a nonce (< 12 bytes). This is a structural error,
	// not a GCM auth failure. Fallback to previous key should NOT be attempted.
	currentKey := [32]byte{1}
	previousKey := [32]byte{2}
	shortData := []byte("short")

	_, err := DecryptWithFallback(currentKey, previousKey, shortData)
	if err == nil {
		t.Fatal("DecryptWithFallback succeeded on truncated ciphertext, want error")
	}
	if !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("expected 'ciphertext too short' error, got: %v", err)
	}
	// Fallback should NOT have been attempted, so "both keys failed" should be absent.
	if strings.Contains(err.Error(), "both keys failed") {
		t.Errorf("fallback was attempted on structural error; got: %v", err)
	}
}

func TestDecryptWithFallback_NoPreviousKeyCurrentFails(t *testing.T) {
	t.Parallel()
	keyA := testKey(t)
	keyB := testKey(t)
	var zeroKey [32]byte

	ciphertext, err := Encrypt(keyA, []byte("no previous key fails"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Wrong current key, zero previous → returns error without panic.
	_, err = DecryptWithFallback(keyB, zeroKey, ciphertext)
	if err == nil {
		t.Error("DecryptWithFallback succeeded with wrong current and zero previous, want error")
	}
}
