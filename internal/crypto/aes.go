// ABOUTME: AES-256-GCM authenticated encryption for storing secrets at rest.
// ABOUTME: Nonce-prepended ciphertext format: nonce (12 bytes) || ciphertext.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// DecryptWithFallback tries decrypting with currentKey first. If GCM
// authentication fails and previousKey is non-zero, it retries with
// previousKey. This supports seamless encryption key rotation.
func DecryptWithFallback(currentKey, previousKey [32]byte, data []byte) ([]byte, error) {
	plaintext, err := Decrypt(currentKey, data)
	if err == nil {
		return plaintext, nil
	}

	if previousKey != [32]byte{} {
		plaintext, err2 := Decrypt(previousKey, data)
		if err2 == nil {
			return plaintext, nil
		}
		return nil, fmt.Errorf("decrypt with both keys failed: current: %w, previous: %v", err, err2)
	}

	return nil, err
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns nonce || ciphertext.
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext produced by Encrypt.
// Expects nonce (12 bytes) || ciphertext.
func Decrypt(key [32]byte, data []byte) ([]byte, error) {
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}

	return plaintext, nil
}
