// ABOUTME: Integration tests for email verification token store methods.
// ABOUTME: Uses testutil.NewTestDB which starts a real Postgres container with migrations.
package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCreateAndGetEmailVerificationToken(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "verify@example.com", "Verify User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("verify-token-123"))
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := s.CreateEmailVerificationToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	got, err := s.GetEmailVerificationTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetEmailVerificationTokenByHash: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil token, got nil")
	}
	if got.UserID != user.ID {
		t.Errorf("UserID = %v, want %v", got.UserID, user.ID)
	}
}

func TestGetEmailVerificationToken_Expired(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "verify-exp@example.com", "Expired User", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := sha256.Sum256([]byte("expired-verify-token"))
	if err := s.CreateEmailVerificationToken(ctx, user.ID, tokenHash[:], time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	got, err := s.GetEmailVerificationTokenByHash(ctx, tokenHash[:])
	if err != nil {
		t.Fatalf("GetEmailVerificationTokenByHash: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for expired token, got %+v", got)
	}
}

func TestSetEmailVerified(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "set-verified@example.com", "Set Verified", "$argon2id$stub", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Verify starts as false.
	u, err := s.GetUserByID(ctx, user.ID)
	if err != nil || u == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.EmailVerified {
		t.Error("expected email_verified = false initially")
	}

	// Set verified.
	if err := s.SetEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("SetEmailVerified: %v", err)
	}

	// Verify it flipped.
	u, err = s.GetUserByID(ctx, user.ID)
	if err != nil || u == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !u.EmailVerified {
		t.Error("expected email_verified = true after SetEmailVerified")
	}
}
