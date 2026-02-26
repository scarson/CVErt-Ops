// ABOUTME: API key generation and hashing for machine-to-machine authentication.
// ABOUTME: Keys are opaque strings (cvo_ prefix + random bytes). Only sha256 stored.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// APIKeyPrefix is the human-readable prefix on all CVErt Ops API keys.
const APIKeyPrefix = "cvo_"

// GenerateAPIKey creates a new API key. Returns the raw key (shown to user once),
// the sha256 hex hash (stored in DB), and any error.
func GenerateAPIKey() (rawKey, keyHash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate api key: %w", err)
	}
	rawKey = APIKeyPrefix + hex.EncodeToString(b)
	keyHash = HashAPIKey(rawKey)
	return rawKey, keyHash, nil
}

// HashAPIKey returns the sha256 hex hash of rawKey.
// Use subtle.ConstantTimeCompare when comparing against stored hashes.
func HashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}
