// ABOUTME: Argon2id password hashing per PLAN.md §7.1 OWASP parameters.
// ABOUTME: Callers must acquire the argon2 semaphore (on api.Server) before calling.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 19456 // KiB (19 MiB)
	argon2Iterations  = 2
	argon2Parallelism = 1
	argon2SaltLen     = 16
	argon2KeyLen      = 32
)

// HashPassword hashes password using argon2id. Returns a PHC-format string.
// The caller is responsible for acquiring the argon2 concurrency semaphore.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)
	hash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Iterations, argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return hash, nil
}

// VerifyPassword checks password against a PHC-format argon2id hash.
// Returns (false, nil) for wrong password — never returns an error for a valid hash.
func VerifyPassword(password, hash string) (bool, error) {
	// Parse: $argon2id$v=19$m=M,t=T,p=P$salt$key
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	expectedKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode key: %w", err)
	}

	actualKey := argon2.IDKey([]byte(password), salt, t, m, uint8(p), uint32(len(expectedKey))) //nolint:gosec // G115: p is from our own hash format, bounded by uint32 parse
	return subtle.ConstantTimeCompare(expectedKey, actualKey) == 1, nil
}
