// ABOUTME: JWT issuance and parsing for CVErt Ops access and refresh tokens.
// ABOUTME: Always enforces HS256 algorithm and expiration — never call jwt.Parse directly.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaims holds the claims embedded in an access token.
type AccessClaims struct {
	jwt.RegisteredClaims
	// UserID is the authenticated user's UUID. The json:"sub" tag intentionally
	// shadows RegisteredClaims.Subject so that "sub" serializes as a UUID string
	// rather than a plain string. Go's encoding/json picks the outermost field
	// when embedded struct tags collide.
	UserID uuid.UUID `json:"sub"`
	// TokenVersion must match users.token_version for the refresh flow to succeed.
	TokenVersion int `json:"tv"`
}

// IssueAccessToken creates a signed HS256 JWT access token.
// ttl should be ≤15 minutes per PLAN.md §7.1.
func IssueAccessToken(secret []byte, userID uuid.UUID, tokenVersion int, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:       userID,
		TokenVersion: tokenVersion,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// ParseAccessToken validates and parses an HS256 access token using dual-key
// verification for zero-downtime secret rotation. It tries activeSecret first.
// On signature failure only (not expiry or claims errors), it retries with
// previousSecret if non-nil. Signing always uses activeSecret via IssueAccessToken.
func ParseAccessToken(tokenStr string, activeSecret []byte, previousSecret []byte) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
		return activeSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		return claims, nil
	}

	// Only try previous key on signature error — not expiry, not claims.
	if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		fallbackClaims := &AccessClaims{}
		_, err2 := jwt.ParseWithClaims(tokenStr, fallbackClaims, func(_ *jwt.Token) (any, error) {
			return previousSecret, nil
		},
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithExpirationRequired(),
		)
		if err2 == nil {
			return fallbackClaims, nil
		}
		return nil, fmt.Errorf("parse access token: %w", err2)
	}

	return nil, fmt.Errorf("parse access token: %w", err)
}

// RefreshClaims holds the claims embedded in a refresh token.
type RefreshClaims struct {
	jwt.RegisteredClaims
	// UserID shadows RegisteredClaims.Subject (same json:"sub" tag) so that
	// "sub" serializes as a UUID. See AccessClaims.UserID for details.
	UserID uuid.UUID `json:"sub"`
	// TokenVersion must match users.token_version; mismatch means logout-all was called.
	TokenVersion int `json:"tv"`
	// JTI is the typed UUID form of the token's unique identifier (jti_id claim).
	// RegisteredClaims.ID carries the same value as the standard string "jti" claim.
	JTI uuid.UUID `json:"jti_id"`
}

// IssueRefreshToken creates a signed HS256 refresh token with a unique JTI.
func IssueRefreshToken(secret []byte, userID uuid.UUID, tokenVersion int, jti uuid.UUID, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:       userID,
		TokenVersion: tokenVersion,
		JTI:          jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign refresh token: %w", err)
	}
	return signed, nil
}

// ParseRefreshToken validates and parses an HS256 refresh token using dual-key
// verification for zero-downtime secret rotation. It tries activeSecret first.
// On signature failure only (not expiry or claims errors), it retries with
// previousSecret if non-nil.
func ParseRefreshToken(tokenStr string, activeSecret []byte, previousSecret []byte) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
		return activeSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		return claims, nil
	}

	// Only try previous key on signature error — not expiry, not claims.
	if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		fallbackClaims := &RefreshClaims{}
		_, err2 := jwt.ParseWithClaims(tokenStr, fallbackClaims, func(_ *jwt.Token) (any, error) {
			return previousSecret, nil
		},
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithExpirationRequired(),
		)
		if err2 == nil {
			return fallbackClaims, nil
		}
		return nil, fmt.Errorf("parse refresh token: %w", err2)
	}

	return nil, fmt.Errorf("parse refresh token: %w", err)
}
