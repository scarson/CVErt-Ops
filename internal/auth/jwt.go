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

// parseTokenWithRotation tries activeSecret first; on signature error only
// (not expiry or claims errors), retries with previousSecret if non-nil.
// newClaims must return a fresh zero-value claims struct for each parse attempt,
// because jwt.ParseWithClaims populates the struct in-place.
func parseTokenWithRotation[T jwt.Claims](
	tokenStr string,
	newClaims func() T,
	activeSecret, previousSecret []byte,
	label string,
) (T, error) {
	claims := newClaims()
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
		return activeSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err == nil {
		return claims, nil
	}

	if previousSecret != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		fallback := newClaims()
		_, err2 := jwt.ParseWithClaims(tokenStr, fallback, func(_ *jwt.Token) (any, error) {
			return previousSecret, nil
		},
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithExpirationRequired(),
		)
		if err2 == nil {
			return fallback, nil
		}
		var zero T
		return zero, fmt.Errorf("parse %s token: %w", label, err2)
	}

	var zero T
	return zero, fmt.Errorf("parse %s token: %w", label, err)
}

// Token type constants for the "typ" claim. Each token type includes this claim
// so parsers can reject tokens of the wrong type — e.g., a pending MFA token
// must not be accepted as a full access token.
const (
	TokenTypeAccess     = "access"
	TokenTypeRefresh    = "refresh"
	TokenTypePending    = "pending"
	TokenTypeEnrollment = "enrollment"
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
	// Typ identifies this as an access token. Checked by ParseAccessToken.
	TokenType string `json:"token_type"`
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
		TokenType:    TokenTypeAccess,
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
	claims, err := parseTokenWithRotation(tokenStr, func() *AccessClaims { return &AccessClaims{} }, activeSecret, previousSecret, "access")
	if err != nil {
		return nil, err
	}
	// Reject non-access tokens. Tokens issued before the typ claim was added
	// have Typ=="" — accept those for backward compatibility during rollout.
	if claims.TokenType != "" && claims.TokenType != TokenTypeAccess {
		return nil, fmt.Errorf("parse access token: wrong token type %q", claims.TokenType)
	}
	return claims, nil
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
	// TokenType identifies this as a refresh token.
	TokenType string `json:"token_type"`
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
		TokenType:    TokenTypeRefresh,
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
	return parseTokenWithRotation(tokenStr, func() *RefreshClaims { return &RefreshClaims{} }, activeSecret, previousSecret, "refresh")
}

// MFARequiredReason describes why MFA is required for a user.
type MFARequiredReason struct {
	Source  string `json:"source"             doc:"Reason source (site_admin, org_owner, org_policy, per_member, db_error)"`
	OrgName string `json:"org_name,omitempty" doc:"Org name (for org_policy and per_member reasons)"`
}

// PendingClaims holds the claims for a restricted session token issued when
// additional authentication steps (MFA challenge, password reset) are required
// before granting full access.
type PendingClaims struct {
	jwt.RegisteredClaims
	// UserID shadows RegisteredClaims.Subject (same json:"sub" tag) so that
	// "sub" serializes as a UUID. See AccessClaims.UserID for details.
	UserID uuid.UUID `json:"sub"`
	// TokenVersion must match users.token_version for the token to remain valid.
	TokenVersion int `json:"tv"`
	// Pending lists the requirements that must be satisfied (e.g. "mfa_challenge", "password_reset").
	Pending []string `json:"pending"`
	// Methods lists the available MFA methods when Pending contains "mfa_challenge".
	Methods []string `json:"methods,omitempty"`
	// Reasons lists why MFA is required (populated when pending contains
	// "mfa_enrollment_required" or "mfa_challenge" with a mandate).
	Reasons []MFARequiredReason `json:"reasons,omitempty"`
	// TokenType identifies this as a pending/restricted token.
	TokenType string `json:"token_type"`
}

// IssuePendingToken creates a signed HS256 JWT for a restricted session that
// requires additional authentication steps before granting full access.
func IssuePendingToken(secret []byte, userID uuid.UUID, tokenVersion int, pending, methods []string, reasons []MFARequiredReason, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := PendingClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:       userID,
		TokenVersion: tokenVersion,
		Pending:      pending,
		Methods:      methods,
		Reasons:      reasons,
		TokenType:    TokenTypePending,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign pending token: %w", err)
	}
	return signed, nil
}

// ParsePendingToken validates and parses an HS256 pending session token using
// dual-key verification for zero-downtime secret rotation. It tries activeSecret
// first. On signature failure only (not expiry or claims errors), it retries with
// previousSecret if non-nil.
func ParsePendingToken(tokenStr string, activeSecret []byte, previousSecret []byte) (*PendingClaims, error) {
	return parseTokenWithRotation(tokenStr, func() *PendingClaims { return &PendingClaims{} }, activeSecret, previousSecret, "pending")
}

// EnrollmentClaims holds the claims for a short-lived MFA enrollment token.
// Contains an encrypted TOTP secret that is provisional until the user
// confirms enrollment with a valid code.
type EnrollmentClaims struct {
	jwt.RegisteredClaims
	UserID    uuid.UUID `json:"sub"`
	SecretEnc []byte    `json:"sec"` // AES-256-GCM encrypted TOTP secret
	TokenType string    `json:"token_type"`
}

// IssueEnrollmentToken creates a short-lived JWT containing the encrypted TOTP
// secret. The secret is NOT stored in the DB until the user confirms enrollment.
func IssueEnrollmentToken(secret []byte, userID uuid.UUID, secretEnc []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := EnrollmentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:    userID,
		SecretEnc: secretEnc,
		TokenType: TokenTypeEnrollment,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign enrollment token: %w", err)
	}
	return signed, nil
}

// ParseEnrollmentToken validates and parses an HS256 MFA enrollment token using
// dual-key verification for zero-downtime secret rotation. It tries activeSecret
// first. On signature failure only (not expiry or claims errors), it retries with
// previousSecret if non-nil.
func ParseEnrollmentToken(tokenStr string, activeSecret []byte, previousSecret []byte) (*EnrollmentClaims, error) {
	return parseTokenWithRotation(tokenStr, func() *EnrollmentClaims { return &EnrollmentClaims{} }, activeSecret, previousSecret, "enrollment")
}
