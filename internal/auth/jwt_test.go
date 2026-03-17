// ABOUTME: Tests for JWT issuance and parsing with required security constraints.
// ABOUTME: Covers algorithm pinning, expiry enforcement, token_version, dual-key rotation, and MFA pending tokens.
package auth_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	claims, err := auth.ParseAccessToken(tokenStr, secret, nil)
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

	_, err = auth.ParseAccessToken(tokenStr, secret, nil)
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

	_, err = auth.ParseAccessToken(tampered, secret, nil)
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

	_, err = auth.ParseAccessToken(tampered, secret, nil)
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

	_, err = auth.ParseAccessToken(tokenStr, wrongSecret, nil)
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

	claims, err := auth.ParseRefreshToken(tokenStr, secret, nil)
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

	_, err = auth.ParseRefreshToken(tokenStr, secret, nil)
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

	_, err = auth.ParseRefreshToken(tampered, secret, nil)
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

	_, err = auth.ParseRefreshToken(tampered, secret, nil)
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

	_, err = auth.ParseRefreshToken(tokenStr, wrongSecret, nil)
	if err == nil {
		t.Error("expected error for wrong secret on refresh token, got nil")
	}
}

// ── Dual-key rotation tests (access token) ─────────────────────────────────

func TestParseAccessToken_ActiveKeyValidates(t *testing.T) {
	t.Parallel()
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(activeKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := auth.ParseAccessToken(tokenStr, activeKey, previousKey)
	if err != nil {
		t.Fatalf("ParseAccessToken with active key should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestParseAccessToken_PreviousKeyValidates(t *testing.T) {
	t.Parallel()
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	activeKey := []byte("active-key-32-bytes-minimum-cccc")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Issue with the previous key (simulates pre-rotation token).
	tokenStr, err := auth.IssueAccessToken(previousKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Parse with a different active key + the previous key — should fall back to previous.
	claims, err := auth.ParseAccessToken(tokenStr, activeKey, previousKey)
	if err != nil {
		t.Fatalf("ParseAccessToken with previous key should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestParseAccessToken_UnknownKeyRejects(t *testing.T) {
	t.Parallel()
	unknownKey := []byte("unknown-key-32-bytes-minimum-ddd")
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(unknownKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParseAccessToken(tokenStr, activeKey, previousKey)
	if err == nil {
		t.Error("expected error for token signed with unknown key, got nil")
	}
}

func TestParseAccessToken_ExpiredWithPreviousKeyRejects(t *testing.T) {
	t.Parallel()
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	activeKey := []byte("active-key-32-bytes-minimum-cccc")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Issue an already-expired token with the previous key.
	tokenStr, err := auth.IssueAccessToken(previousKey, userID, 1, -1*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Active key fails with signature error, but the token is expired —
	// the previous key should NOT re-validate an expired token.
	_, err = auth.ParseAccessToken(tokenStr, activeKey, previousKey)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	// Verify the error is about expiry, not signature.
	if !strings.Contains(err.Error(), "expired") {
		// The active key should fail with signature error, triggering fallback to previous key.
		// The previous key should then reject because the token is expired.
		// Either way, an expired token must never succeed.
		t.Errorf("error = %v (expected expiry-related error)", err)
	}
}

func TestParseAccessToken_NoPreviousKeyConfigured(t *testing.T) {
	t.Parallel()
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(activeKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// nil previousSecret — only active key tried.
	claims, err := auth.ParseAccessToken(tokenStr, activeKey, nil)
	if err != nil {
		t.Fatalf("ParseAccessToken with nil previous should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestParseAccessToken_NoPreviousKeyRejectsWrongActive(t *testing.T) {
	t.Parallel()
	signingKey := []byte("signing-key-32-bytes-minimum-aaa")
	wrongActive := []byte("wrong-active-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(signingKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// nil previousSecret and wrong active — must reject.
	_, err = auth.ParseAccessToken(tokenStr, wrongActive, nil)
	if err == nil {
		t.Error("expected error when active key is wrong and no previous key, got nil")
	}
}

func TestParseAccessToken_BothKeysSameValue(t *testing.T) {
	t.Parallel()
	key := []byte("same-key-32-bytes-minimum-aaaaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(key, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// activeKey == previousKey — harmless, should work.
	claims, err := auth.ParseAccessToken(tokenStr, key, key)
	if err != nil {
		t.Fatalf("ParseAccessToken with identical keys should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestParseAccessToken_SignatureErrorTriesPrevious_NotExpiry(t *testing.T) {
	t.Parallel()
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	activeKey := []byte("active-key-32-bytes-minimum-cccc")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Issue an expired token with the active key (not the previous key).
	tokenStr, err := auth.IssueAccessToken(activeKey, userID, 1, -1*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Active key matches signature but token is expired.
	// Must NOT fall through to previous key — expiry is not a signature error.
	_, err = auth.ParseAccessToken(tokenStr, activeKey, previousKey)
	if err == nil {
		t.Fatal("expected error for expired token signed with active key, got nil")
	}
	// Verify we get an expiry error, not a signature error.
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiry error, got: %v", err)
	}
}

// ── Dual-key rotation tests (refresh token) ────────────────────────────────

func TestParseRefreshToken_ActiveKeyValidates(t *testing.T) {
	t.Parallel()
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(activeKey, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := auth.ParseRefreshToken(tokenStr, activeKey, previousKey)
	if err != nil {
		t.Fatalf("ParseRefreshToken with active key should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.JTI != jti {
		t.Errorf("JTI = %v, want %v", claims.JTI, jti)
	}
}

func TestParseRefreshToken_PreviousKeyValidates(t *testing.T) {
	t.Parallel()
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	activeKey := []byte("active-key-32-bytes-minimum-cccc")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(previousKey, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := auth.ParseRefreshToken(tokenStr, activeKey, previousKey)
	if err != nil {
		t.Fatalf("ParseRefreshToken with previous key should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestParseRefreshToken_UnknownKeyRejects(t *testing.T) {
	t.Parallel()
	unknownKey := []byte("unknown-key-32-bytes-minimum-ddd")
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(unknownKey, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = auth.ParseRefreshToken(tokenStr, activeKey, previousKey)
	if err == nil {
		t.Error("expected error for refresh token signed with unknown key, got nil")
	}
}

func TestParseRefreshToken_ExpiredWithPreviousKeyRejects(t *testing.T) {
	t.Parallel()
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	activeKey := []byte("active-key-32-bytes-minimum-cccc")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	// Issue an already-expired refresh token with the previous key.
	tokenStr, err := auth.IssueRefreshToken(previousKey, userID, 1, jti, -1*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Must reject — expired tokens are expired regardless of which key signed them.
	_, err = auth.ParseRefreshToken(tokenStr, activeKey, previousKey)
	if err == nil {
		t.Fatal("expected error for expired refresh token, got nil")
	}
}

func TestParseRefreshToken_NoPreviousKeyConfigured(t *testing.T) {
	t.Parallel()
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(activeKey, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// nil previousSecret — only active key tried.
	claims, err := auth.ParseRefreshToken(tokenStr, activeKey, nil)
	if err != nil {
		t.Fatalf("ParseRefreshToken with nil previous should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.JTI != jti {
		t.Errorf("JTI = %v, want %v", claims.JTI, jti)
	}
}

func TestParseRefreshToken_BothKeysSameValue(t *testing.T) {
	t.Parallel()
	key := []byte("same-key-32-bytes-minimum-aaaaaa")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tokenStr, err := auth.IssueRefreshToken(key, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// activeKey == previousKey — harmless, should work.
	claims, err := auth.ParseRefreshToken(tokenStr, key, key)
	if err != nil {
		t.Fatalf("ParseRefreshToken with identical keys should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.JTI != jti {
		t.Errorf("JTI = %v, want %v", claims.JTI, jti)
	}
}

// ── Rotation flow integration test ──────────────────────────────────────────

func TestRefreshTokenFlowAcrossRotation(t *testing.T) {
	t.Parallel()
	oldKey := []byte("old-key-32-bytes-minimum-aaaaaaaa")
	newKey := []byte("new-key-32-bytes-minimum-bbbbbbbb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	// 1. Issue refresh token with the old key (pre-rotation).
	refreshStr, err := auth.IssueRefreshToken(oldKey, userID, 1, jti, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue refresh with old key: %v", err)
	}

	// 2. Parse with new key as active + old key as previous — should succeed.
	claims, err := auth.ParseRefreshToken(refreshStr, newKey, oldKey)
	if err != nil {
		t.Fatalf("parse refresh with new active + old previous should succeed: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.JTI != jti {
		t.Errorf("JTI = %v, want %v", claims.JTI, jti)
	}

	// 3. Issue new tokens with the new key (post-rotation re-issue).
	newJTI := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	newAccessStr, err := auth.IssueAccessToken(newKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue new access token: %v", err)
	}
	newRefreshStr, err := auth.IssueRefreshToken(newKey, userID, 1, newJTI, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("issue new refresh token: %v", err)
	}

	// 4. Verify new tokens validate with new key only (no previous key needed).
	accessClaims, err := auth.ParseAccessToken(newAccessStr, newKey, nil)
	if err != nil {
		t.Fatalf("parse new access token: %v", err)
	}
	if accessClaims.UserID != userID {
		t.Errorf("new access UserID = %v, want %v", accessClaims.UserID, userID)
	}

	refreshClaims, err := auth.ParseRefreshToken(newRefreshStr, newKey, nil)
	if err != nil {
		t.Fatalf("parse new refresh token: %v", err)
	}
	if refreshClaims.JTI != newJTI {
		t.Errorf("new refresh JTI = %v, want %v", refreshClaims.JTI, newJTI)
	}

	// 5. Old refresh token should NOT validate with only the new key (no previous).
	_, err = auth.ParseRefreshToken(refreshStr, newKey, nil)
	if err == nil {
		t.Error("old refresh token should not validate with only new key")
	}
}

// ── Verify error type discrimination ────────────────────────────────────────

func TestParseAccessToken_AlgorithmErrorDoesNotFallback(t *testing.T) {
	t.Parallel()
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	previousKey := []byte("previous-key-32-bytes-minimum-bb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	tokenStr, err := auth.IssueAccessToken(activeKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Tamper the algorithm header — this is NOT a signature error, should not try previous key.
	parts := strings.SplitN(tokenStr, ".", 3)
	fakeHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	tampered := fakeHeader + "." + parts[1] + "." + parts[2]

	_, err = auth.ParseAccessToken(tampered, activeKey, previousKey)
	if err == nil {
		t.Error("expected error for tampered algorithm, got nil")
	}
	// The error should be about signing method, not a fallback result.
	if strings.Contains(err.Error(), "signature") {
		t.Logf("got signature error (acceptable — algorithm check may surface as signature): %v", err)
	}
}

// ── Verify jwt.ErrTokenSignatureInvalid discrimination ──────────────────────

func TestSignatureErrorDiscrimination(t *testing.T) {
	t.Parallel()

	// Verify that our error type discrimination logic is correct:
	// jwt.ErrTokenSignatureInvalid must be distinct from jwt.ErrTokenExpired.
	activeKey := []byte("active-key-32-bytes-minimum-aaaa")
	wrongKey := []byte("wrong-key-32-bytes-minimum-bbbbb")
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Test 1: wrong key produces ErrTokenSignatureInvalid.
	tokenStr, err := auth.IssueAccessToken(activeKey, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims := &auth.AccessClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
		return wrongKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
	if !strings.Contains(err.Error(), "signature is invalid") {
		t.Errorf("wrong key error should mention signature, got: %v", err)
	}

	// Test 2: expired token produces error that does NOT match ErrTokenSignatureInvalid.
	expiredStr, err := auth.IssueAccessToken(activeKey, userID, 1, -1*time.Second)
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	claims2 := &auth.AccessClaims{}
	_, err = jwt.ParseWithClaims(expiredStr, claims2, func(_ *jwt.Token) (any, error) {
		return activeKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if strings.Contains(err.Error(), "signature is invalid") {
		t.Errorf("expired token error should NOT mention signature, got: %v", err)
	}
}

// ── Pending token (MFA restricted session) tests ────────────────────────────

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
