// ABOUTME: Integration tests for password reset token store methods.
// ABOUTME: Uses testutil.NewTestDB which starts a real Postgres container with migrations.
package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCreateAndGetPasswordResetToken(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "reset@example.com", "Reset User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("test-token-123"))
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := s.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	got, err := s.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetPasswordResetTokenByHash: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil token, got nil")
	}
	if got.UserID != user.ID {
		t.Errorf("UserID = %v, want %v", got.UserID, user.ID)
	}
}

func TestGetPasswordResetToken_Expired(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "expired@example.com", "Expired User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("expired-token"))
	expiresAt := time.Now().Add(-1 * time.Hour) // already expired

	if err := s.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	got, err := s.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetPasswordResetTokenByHash: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for expired token, got %+v", got)
	}
}

func TestGetPasswordResetToken_Used(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "used@example.com", "Used User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("used-token"))
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := s.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Get the token to find its ID, then mark it used.
	tok, err := s.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetPasswordResetTokenByHash: %v", err)
	}
	if tok == nil {
		t.Fatal("expected non-nil token before marking used")
	}

	if err := s.MarkPasswordResetTokenUsed(ctx, tok.ID); err != nil {
		t.Fatalf("MarkPasswordResetTokenUsed: %v", err)
	}

	// Retrieval should now return nil (used tokens are excluded).
	got, err := s.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetPasswordResetTokenByHash after used: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for used token, got %+v", got)
	}
}

func TestMarkPasswordResetTokenUsed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mark@example.com", "Mark User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("mark-token"))
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := s.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	tok, err := s.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil || tok == nil {
		t.Fatalf("GetPasswordResetTokenByHash: err=%v, tok=%v", err, tok)
	}

	if err := s.MarkPasswordResetTokenUsed(ctx, tok.ID); err != nil {
		t.Fatalf("MarkPasswordResetTokenUsed: %v", err)
	}

	// Verify token is no longer retrievable.
	got, err := s.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetPasswordResetTokenByHash: %v", err)
	}
	if got != nil {
		t.Error("expected nil after marking used")
	}
}

func TestCountRecentPasswordResetTokens(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "count@example.com", "Count User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	since := time.Now().Add(-1 * time.Minute)

	// Create 3 tokens.
	for i := range 3 {
		h := sha256.Sum256([]byte("count-token-" + string(rune('a'+i))))
		if err := s.CreatePasswordResetToken(ctx, user.ID, h[:], time.Now().Add(1*time.Hour)); err != nil {
			t.Fatalf("CreatePasswordResetToken[%d]: %v", i, err)
		}
	}

	count, err := s.CountRecentPasswordResetTokens(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CountRecentPasswordResetTokens: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestDeleteExpiredPasswordResetTokens(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "delete@example.com", "Delete User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create an expired token.
	expiredHash := sha256.Sum256([]byte("delete-expired"))
	if err := s.CreatePasswordResetToken(ctx, user.ID, expiredHash[:], time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatalf("CreatePasswordResetToken (expired): %v", err)
	}

	// Create a valid token.
	validHash := sha256.Sum256([]byte("delete-valid"))
	if err := s.CreatePasswordResetToken(ctx, user.ID, validHash[:], time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("CreatePasswordResetToken (valid): %v", err)
	}

	// Delete expired.
	if err := s.DeleteExpiredPasswordResetTokens(ctx); err != nil {
		t.Fatalf("DeleteExpiredPasswordResetTokens: %v", err)
	}

	// Verify: valid token still exists, no tokens created since (both would show as 1).
	since := time.Now().Add(-5 * time.Minute)
	count, err := s.CountRecentPasswordResetTokens(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CountRecentPasswordResetTokens: %v", err)
	}
	// Only the valid token should remain.
	if count != 1 {
		t.Errorf("count after delete = %d, want 1", count)
	}
}
