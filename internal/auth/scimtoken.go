// ABOUTME: SCIM bearer token generation and hashing.
// ABOUTME: Tokens use "cvert_scim_" prefix (distinct from API key "cvo_" prefix).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SCIMTokenPrefix is the human-readable prefix on all SCIM bearer tokens.
const SCIMTokenPrefix = "cvert_scim_" //nolint:gosec // G101 false positive: prefix format constant, not a credential

// GenerateSCIMToken creates a new SCIM bearer token.
// Returns: raw token (shown once), sha256 hex hash (stored), display prefix (first 8 chars).
func GenerateSCIMToken() (rawToken, tokenHash, tokenPrefix string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate scim token: %w", err)
	}
	rawToken = SCIMTokenPrefix + hex.EncodeToString(b)
	tokenHash = HashSCIMToken(rawToken)
	tokenPrefix = rawToken[:8]
	return rawToken, tokenHash, tokenPrefix, nil
}

// HashSCIMToken returns the sha256 hex hash of a raw SCIM token.
// Use subtle.ConstantTimeCompare when comparing against stored hashes.
func HashSCIMToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}
