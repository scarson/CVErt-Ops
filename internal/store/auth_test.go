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

func TestGetUserByID(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "getbyid@example.com", "GetByID", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByID returned nil for existing user")
	}
	if got.Email != "getbyid@example.com" {
		t.Errorf("Email = %q, want getbyid@example.com", got.Email)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	got, err := s.GetUserByID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent user, got %+v", got)
	}
}

func TestCountUsers(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	n0, err := s.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers (empty): %v", err)
	}
	if n0 != 0 {
		t.Errorf("CountUsers on empty DB = %d, want 0", n0)
	}

	_, _ = s.CreateUser(ctx, "count1@example.com", "Count1", "", 0)
	_, _ = s.CreateUser(ctx, "count2@example.com", "Count2", "", 0)

	n2, err := s.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n2 != 2 {
		t.Errorf("CountUsers = %d, want 2", n2)
	}
}

func TestUpdateLastLogin(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "lastlogin@example.com", "LastLogin", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.LastLoginAt.Valid {
		t.Error("LastLoginAt should be null initially")
	}

	if err := s.UpdateLastLogin(ctx, user.ID); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}

	got, _ := s.GetUserByID(ctx, user.ID)
	if !got.LastLoginAt.Valid {
		t.Error("LastLoginAt should be set after UpdateLastLogin")
	}
}

func TestUpdatePasswordHash(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "pwchange@example.com", "PwChange", "$argon2id$old", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	oldVersion := user.TokenVersion

	if err := s.UpdatePasswordHash(ctx, user.ID, "$argon2id$new", 2); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}

	got, _ := s.GetUserByID(ctx, user.ID)
	if !got.PasswordHash.Valid || got.PasswordHash.String != "$argon2id$new" {
		t.Errorf("PasswordHash = %v, want $argon2id$new", got.PasswordHash)
	}
	if got.PasswordHashVersion != 2 {
		t.Errorf("PasswordHashVersion = %d, want 2", got.PasswordHashVersion)
	}
	// UpdatePasswordHash bumps token_version to invalidate sessions.
	if got.TokenVersion <= oldVersion {
		t.Errorf("TokenVersion = %d, expected > %d (should bump on password change)", got.TokenVersion, oldVersion)
	}
}

func TestUpsertUserIdentity_ConflictDifferentUser(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user1, _ := s.CreateUser(ctx, "ident1@example.com", "IdentUser1", "", 0)
	user2, _ := s.CreateUser(ctx, "ident2@example.com", "IdentUser2", "", 0)

	// Link provider_user_id to user1.
	err := s.UpsertUserIdentity(ctx, user1.ID, "github", "gh-conflict-99", "ident1@github.com")
	if err != nil {
		t.Fatalf("UpsertUserIdentity (first): %v", err)
	}

	// Upserting the same provider_user_id for a different user updates email only
	// (ON CONFLICT (provider, provider_user_id) DO UPDATE SET email).
	// The user_id is NOT changed because it's not in the SET clause.
	err = s.UpsertUserIdentity(ctx, user2.ID, "github", "gh-conflict-99", "ident2@github.com")
	if err != nil {
		t.Fatalf("UpsertUserIdentity (conflict): %v", err)
	}

	// The identity should still resolve to user1 (user_id not changed by upsert).
	got, err := s.GetUserByProviderID(ctx, "github", "gh-conflict-99")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByProviderID returned nil")
	}
	if got.ID != user1.ID {
		t.Errorf("identity resolved to user %v, want %v (user_id should not change on conflict)", got.ID, user1.ID)
	}
}

func TestDeleteExpiredRefreshTokens(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, _ := s.CreateUser(ctx, "expire@example.com", "ExpireUser", "", 0)

	// Create a token that expired over 60 seconds ago.
	expiredJTI := uuid.New()
	err := s.CreateRefreshToken(ctx, expiredJTI, user.ID, 1, time.Now().Add(-2*time.Minute))
	if err != nil {
		t.Fatalf("CreateRefreshToken (expired): %v", err)
	}

	// Create a token that expires in the future.
	activeJTI := uuid.New()
	err = s.CreateRefreshToken(ctx, activeJTI, user.ID, 1, time.Now().Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateRefreshToken (active): %v", err)
	}

	n, err := s.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredRefreshTokens: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d tokens, want 1", n)
	}

	// The active token should still exist.
	rt, _ := s.GetRefreshToken(ctx, activeJTI)
	if rt == nil {
		t.Error("active token should not have been deleted")
	}

	// The expired token should be gone.
	rt2, _ := s.GetRefreshToken(ctx, expiredJTI)
	if rt2 != nil {
		t.Error("expired token should have been deleted")
	}
}

func TestSetFirstSiteAdmin(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user1, err := s.CreateUser(ctx, "admin1@example.com", "Admin1", "", 0)
	if err != nil {
		t.Fatalf("CreateUser (first): %v", err)
	}
	user2, err := s.CreateUser(ctx, "admin2@example.com", "Admin2", "", 0)
	if err != nil {
		t.Fatalf("CreateUser (second): %v", err)
	}

	// Neither user is admin initially.
	isAdmin, err := s.IsSiteAdmin(ctx, user1.ID)
	if err != nil {
		t.Fatalf("IsSiteAdmin: %v", err)
	}
	if isAdmin {
		t.Error("user1 should not be site admin initially")
	}

	// Promote first user.
	if err := s.SetFirstSiteAdmin(ctx, user1.ID); err != nil {
		t.Fatalf("SetFirstSiteAdmin (user1): %v", err)
	}
	isAdmin, err = s.IsSiteAdmin(ctx, user1.ID)
	if err != nil {
		t.Fatalf("IsSiteAdmin after promotion: %v", err)
	}
	if !isAdmin {
		t.Error("user1 should be site admin after SetFirstSiteAdmin")
	}

	// Second call for a different user is a no-op (admin already exists).
	if err := s.SetFirstSiteAdmin(ctx, user2.ID); err != nil {
		t.Fatalf("SetFirstSiteAdmin (user2): %v", err)
	}
	isAdmin2, err := s.IsSiteAdmin(ctx, user2.ID)
	if err != nil {
		t.Fatalf("IsSiteAdmin (user2): %v", err)
	}
	if isAdmin2 {
		t.Error("user2 should NOT be site admin — first admin already exists")
	}

	// user1 should still be admin.
	isAdmin, err = s.IsSiteAdmin(ctx, user1.ID)
	if err != nil {
		t.Fatalf("IsSiteAdmin (user1 recheck): %v", err)
	}
	if !isAdmin {
		t.Error("user1 should still be site admin")
	}
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	_, err := s.CreateUser(ctx, "dupemail@example.com", "User1", "", 0)
	if err != nil {
		t.Fatalf("CreateUser (first): %v", err)
	}

	_, err = s.CreateUser(ctx, "dupemail@example.com", "User2", "", 0)
	if err == nil {
		t.Error("expected error on duplicate email, got nil")
	}
}
