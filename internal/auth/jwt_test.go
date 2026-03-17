// ABOUTME: Tests for JWT issuance and parsing with required security constraints.
// ABOUTME: Covers algorithm pinning, expiry enforcement, and token_version embedding.
package auth_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
)

func TestJWTRoundTrip(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := auth.ParseAccessToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.TokenVersion != 1 {
		t.Errorf("TokenVersion = %d, want 1", claims.TokenVersion)
	}
}

func TestJWTRejectsExpired(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, -1*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParseAccessToken(tokenStr, secret)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestJWTRejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Replace the header to claim RS256 — WithValidMethods(["HS256"]) must reject this.
	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "." + parts[2]

	_, err = auth.ParseAccessToken(tampered, secret)
	if err == nil {
		t.Error("expected error for RS256 algorithm, got nil")
	}
}

func TestJWTRejectsAlgNone(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Replace header with alg:none — a classic JWT bypass attack.
	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "."

	_, err = auth.ParseAccessToken(tampered, secret)
	if err == nil {
		t.Error("expected error for alg:none token, got nil")
	}
}

func TestJWTRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	wrongSecret := []byte("wrong-secret-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(secret, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParseAccessToken(tokenStr, wrongSecret)
	if err == nil {
		t.Error("expected error for wrong secret, got nil")
	}
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(secret, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	claims, err := auth.ParseRefreshToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParseRefreshToken: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.JTI != jti {
		t.Errorf("JTI = %v, want %v", claims.JTI, jti)
	}
	if claims.TokenVersion != 1 {
		t.Errorf("TokenVersion = %d, want 1", claims.TokenVersion)
	}
}

func TestRefreshTokenRejectsExpired(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(secret, userID, 1, jti, -1*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParseRefreshToken(tokenStr, secret)
	if err == nil {
		t.Error("expected error for expired refresh token, got nil")
	}
}

func TestRefreshTokenRejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(secret, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "." + parts[2]

	_, err = auth.ParseRefreshToken(tampered, secret)
	if err == nil {
		t.Error("expected error for RS256 algorithm on refresh token, got nil")
	}
}

func TestRefreshTokenRejectsAlgNone(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(secret, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "."

	_, err = auth.ParseRefreshToken(tampered, secret)
	if err == nil {
		t.Error("expected error for alg:none refresh token, got nil")
	}
}

func TestRefreshTokenRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	wrongSecret := []byte("wrong-secret-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(secret, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParseRefreshToken(tokenStr, wrongSecret)
	if err == nil {
		t.Error("expected error for wrong secret on refresh token, got nil")
	}
}

func TestPendingTokenRoundTrip(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tokenVersion := 5
	pending := []string{"mfa_challenge", "password_reset"}
	methods := []string{"totp", "email_otp"}
	ttl := 5 * time.Minute

	tokenStr, err := auth.IssuePendingToken(secret, userID, tokenVersion, pending, methods, ttl)
	if err != nil {
		t.Fatalf("IssuePendingToken: %v", err)
	}

	claims, err := auth.ParsePendingToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParsePendingToken: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.TokenVersion != tokenVersion {
		t.Errorf("TokenVersion = %d, want %d", claims.TokenVersion, tokenVersion)
	}
	if len(claims.Pending) != len(pending) {
		t.Fatalf("Pending length = %d, want %d", len(claims.Pending), len(pending))
	}
	for i, p := range pending {
		if claims.Pending[i] != p {
			t.Errorf("Pending[%d] = %q, want %q", i, claims.Pending[i], p)
		}
	}
	if len(claims.Methods) != len(methods) {
		t.Fatalf("Methods length = %d, want %d", len(claims.Methods), len(methods))
	}
	for i, m := range methods {
		if claims.Methods[i] != m {
			t.Errorf("Methods[%d] = %q, want %q", i, claims.Methods[i], m)
		}
	}
}

func TestPendingTokenNilPendingAndMethods(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssuePendingToken(secret, userID, 1, nil, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssuePendingToken: %v", err)
	}

	claims, err := auth.ParsePendingToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParsePendingToken: %v", err)
	}

	if claims.Pending != nil {
		t.Errorf("Pending = %v, want nil", claims.Pending)
	}
	if claims.Methods != nil {
		t.Errorf("Methods = %v, want nil", claims.Methods)
	}
}

func TestPendingTokenEmptyPending(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssuePendingToken(secret, userID, 1, []string{}, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssuePendingToken: %v", err)
	}

	claims, err := auth.ParsePendingToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParsePendingToken: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestPendingTokenRejectsExpired(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssuePendingToken(secret, userID, 1, []string{"mfa_challenge"}, nil, -1*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParsePendingToken(tokenStr, secret)
	if err == nil {
		t.Error("expected error for expired pending token, got nil")
	}
}

func TestPendingTokenRejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssuePendingToken(secret, userID, 1, []string{"mfa_challenge"}, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "." + parts[2]

	_, err = auth.ParsePendingToken(tampered, secret)
	if err == nil {
		t.Error("expected error for RS256 algorithm on pending token, got nil")
	}
}

func TestPendingTokenRejectsAlgNone(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssuePendingToken(secret, userID, 1, []string{"mfa_challenge"}, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "."

	_, err = auth.ParsePendingToken(tampered, secret)
	if err == nil {
		t.Error("expected error for alg:none pending token, got nil")
	}
}

func TestPendingTokenRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-32-bytes-minimum-aaaa")
	wrongSecret := []byte("wrong-secret-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssuePendingToken(secret, userID, 1, []string{"mfa_challenge"}, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParsePendingToken(tokenStr, wrongSecret)
	if err == nil {
		t.Error("expected error for wrong secret on pending token, got nil")
	}
}
