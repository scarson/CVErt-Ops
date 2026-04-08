// ABOUTME: AES-256-GCM authenticated encryption for storing secrets at rest.
// ABOUTME: Nonce-prepended ciphertext format: nonce (12 bytes) || ciphertext.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

// DecryptWithFallback tries decrypting with currentKey first. If GCM
// authentication fails and previousKey is non-zero, it retries with
// previousKey. This supports seamless encryption key rotation.
// Structural errors (truncated ciphertext, invalid key) fail immediately
// without attempting fallback. The aad (additional authenticated data) is
// passed through to GCM and must match the value used during encryption.
func DecryptWithFallback(currentKey, previousKey [32]byte, data []byte, aad []byte) ([]byte, error) {
	plaintext, err := Decrypt(currentKey, data, aad)
	if err == nil {
		return plaintext, nil
	}

	// Only fall back on GCM authentication failure (wrong key).
	// Structural errors (truncated ciphertext, invalid key) fail fast.
	if previousKey != [32]byte{} && isGCMAuthError(err) {
		plaintext, err2 := Decrypt(previousKey, data, aad)
		if err2 == nil {
			return plaintext, nil
		}
		return nil, fmt.Errorf("decrypt with both keys failed: current: %w, previous: %v", err, err2)
	}

	return nil, err
}

// isGCMAuthError returns true if the error is a GCM authentication tag mismatch,
// which indicates the ciphertext was encrypted with a different key.
func isGCMAuthError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "gcm decrypt:")
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns nonce || ciphertext. The aad (additional authenticated data) is
// mixed into the GCM authentication tag, binding the ciphertext to a context
// (e.g., an org_id or user_id). Pass nil for context-free encryption.
func Encrypt(key [32]byte, plaintext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm new: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation: %w", err)
	}

	// Seal appends ciphertext to nonce, so result is nonce || ciphertext.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt decrypts AES-256-GCM ciphertext produced by Encrypt.
// Expects nonce (12 bytes) || ciphertext. The aad must match the value
// used during encryption; a mismatch causes an authentication failure.
func Decrypt(key [32]byte, data []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm new: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, need at least %d", len(data), nonceSize)
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}

	return plaintext, nil
}
