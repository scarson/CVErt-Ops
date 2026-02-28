// ABOUTME: Integration tests for user auth store methods (CreateUser, GetUserByEmail, etc.).
// ABOUTME: Uses testutil.NewTestDB which starts a real Postgres container with migrations.
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCreateAndGetUser(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "alice@example.com", "Alice", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "alice@example.com")
	}
	if user.DisplayName != "Alice" {
		t.Errorf("DisplayName = %q, want %q", user.DisplayName, "Alice")
	}

	got, err := s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByEmail returned nil for existing user")
	}
	if got.ID != user.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, user.ID)
	}
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	got, err := s.GetUserByEmail(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent user, got %+v", got)
	}
}

func TestIncrementTokenVersion(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "bob@example.com", "Bob", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.TokenVersion != 1 {
		t.Errorf("initial TokenVersion = %d, want 1", user.TokenVersion)
	}

	newVersion, err := s.IncrementTokenVersion(ctx, user.ID)
	if err != nil {
		t.Fatalf("IncrementTokenVersion: %v", err)
	}
	if newVersion != 2 {
		t.Errorf("token_version after increment = %d, want 2", newVersion)
	}
}

func TestUpsertUserIdentity(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "carol@example.com", "Carol", "", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	err = s.UpsertUserIdentity(ctx, user.ID, "github", "gh-12345", "carol@github.com")
	if err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	got, err := s.GetUserByProviderID(ctx, "github", "gh-12345")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByProviderID returned nil")
	}
	if got.ID != user.ID {
		t.Errorf("user ID mismatch: got %v, want %v", got.ID, user.ID)
	}

	// Update email via second upsert — should not error
	err = s.UpsertUserIdentity(ctx, user.ID, "github", "gh-12345", "carol2@github.com")
	if err != nil {
		t.Fatalf("UpsertUserIdentity update: %v", err)
	}
}

func TestGetUserByProviderID_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	got, err := s.GetUserByProviderID(ctx, "github", "nonexistent-id")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent provider ID, got %+v", got)
	}
}

func TestRefreshTokenCRUD(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "dave@example.com", "Dave", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	jti := uuid.New()
	expires := time.Now().Add(7 * 24 * time.Hour)
	err = s.CreateRefreshToken(ctx, jti, user.ID, 1, expires)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	rt, err := s.GetRefreshToken(ctx, jti)
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if rt == nil {
		t.Fatal("GetRefreshToken returned nil for existing token")
	}
	if rt.UserID != user.ID {
		t.Errorf("UserID mismatch: got %v, want %v", rt.UserID, user.ID)
	}
	if rt.UsedAt.Valid {
		t.Error("UsedAt should be null initially")
	}

	// Create the replacement token first — replaced_by_jti is a FK to refresh_tokens(jti).
	// In the real auth flow: issue new token, then mark old as used pointing at the new one.
	newJTI := uuid.New()
	if err = s.CreateRefreshToken(ctx, newJTI, user.ID, 1, expires); err != nil {
		t.Fatalf("CreateRefreshToken (replacement): %v", err)
	}
	err = s.MarkRefreshTokenUsed(ctx, jti, newJTI)
	if err != nil {
		t.Fatalf("MarkRefreshTokenUsed: %v", err)
	}

	rt2, err := s.GetRefreshToken(ctx, jti)
	if err != nil {
		t.Fatalf("GetRefreshToken after mark: %v", err)
	}
	if !rt2.UsedAt.Valid {
		t.Error("UsedAt should be set after MarkRefreshTokenUsed")
	}
	if rt2.ReplacedByJti.UUID != newJTI {
		t.Errorf("ReplacedByJti = %v, want %v", rt2.ReplacedByJti.UUID, newJTI)
	}
}

func TestGetRefreshToken_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	rt, err := s.GetRefreshToken(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if rt != nil {
		t.Errorf("expected nil for non-existent token, got %+v", rt)
	}
}
