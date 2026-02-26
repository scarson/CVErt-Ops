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
