// ABOUTME: Integration tests for store/apikey.go — API key CRUD.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestLookupAPIKey_ValidKey(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "KeyOrg1")
	user, _ := s.CreateUser(ctx, "keyuser1@example.com", "KeyUser1", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")

	hash := "validhash_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "CI Key", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key == nil {
		t.Fatal("CreateAPIKey returned nil")
	}

	got, err := s.LookupAPIKey(ctx, hash)
	if err != nil {
		t.Fatalf("LookupAPIKey: %v", err)
	}
	if got == nil {
		t.Fatal("LookupAPIKey returned nil for valid key")
	}
	if got.ID != key.ID {
		t.Errorf("key ID mismatch: got %v, want %v", got.ID, key.ID)
	}
}

func TestLookupAPIKey_RevokedKey(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "KeyOrg2")
	user, _ := s.CreateUser(ctx, "keyuser2@example.com", "KeyUser2", "", 0)

	hash := "revokedhash_" + uuid.New().String()
	key, _ := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "Revoked Key", "member", sql.NullTime{})

	if err := s.RevokeAPIKey(ctx, org.ID, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	got, err := s.LookupAPIKey(ctx, hash)
	if err != nil {
		t.Fatalf("LookupAPIKey(revoked): %v", err)
	}
	if got != nil {
		t.Error("LookupAPIKey should return nil for revoked key")
	}
}

func TestLookupAPIKey_ExpiredKey(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "KeyOrg3")
	user, _ := s.CreateUser(ctx, "keyuser3@example.com", "KeyUser3", "", 0)

	hash := "expiredhash_" + uuid.New().String()
	pastExpiry := sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true}
	_, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "Expired Key", "member", pastExpiry)
	if err != nil {
		t.Fatalf("CreateAPIKey(expired): %v", err)
	}

	got, err := s.LookupAPIKey(ctx, hash)
	if err != nil {
		t.Fatalf("LookupAPIKey(expired): %v", err)
	}
	if got != nil {
		t.Error("LookupAPIKey should return nil for expired key")
	}
}

func TestLookupAPIKey_NeverExpiresKey(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "KeyOrg4")
	user, _ := s.CreateUser(ctx, "keyuser4@example.com", "KeyUser4", "", 0)

	hash := "neverexpires_" + uuid.New().String()
	// expires_at = NULL means never expires.
	key, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "Never Expires", "admin", sql.NullTime{})
	if err != nil {
		t.Fatalf("CreateAPIKey(never expires): %v", err)
	}

	got, err := s.LookupAPIKey(ctx, hash)
	if err != nil {
		t.Fatalf("LookupAPIKey(never expires): %v", err)
	}
	if got == nil {
		t.Fatal("LookupAPIKey should return key with NULL expires_at")
	}
	if got.ID != key.ID {
		t.Errorf("key ID mismatch: got %v, want %v", got.ID, key.ID)
	}
	if got.ExpiresAt.Valid {
		t.Error("ExpiresAt should be null for never-expires key")
	}
}

func TestCreateAndListAPIKeys(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "KeyOrg5")
	user, _ := s.CreateUser(ctx, "keyuser5@example.com", "KeyUser5", "", 0)

	hash1 := "listhash1_" + uuid.New().String()
	hash2 := "listhash2_" + uuid.New().String()
	_, _ = s.CreateAPIKey(ctx, org.ID, user.ID, hash1, "Key One", "member", sql.NullTime{})
	_, _ = s.CreateAPIKey(ctx, org.ID, user.ID, hash2, "Key Two", "admin", sql.NullTime{})

	keys, err := s.ListOrgAPIKeys(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgAPIKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("ListOrgAPIKeys returned %d keys, want 2", len(keys))
	}
	// ListOrgAPIKeys orders by created_at DESC — Key Two was inserted last.
	if keys[0].Name != "Key Two" {
		t.Errorf("expected Key Two first (newest), got %q", keys[0].Name)
	}
	if keys[1].Name != "Key One" {
		t.Errorf("expected Key One second (oldest), got %q", keys[1].Name)
	}
}

func TestRevokeAPIKey_WrongOrg(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "KeyOrg6a")
	org2, _ := s.CreateOrg(ctx, "KeyOrg6b")
	user, _ := s.CreateUser(ctx, "keyuser6@example.com", "KeyUser6", "", 0)

	hash := "wrongorg_" + uuid.New().String()
	key, _ := s.CreateAPIKey(ctx, org1.ID, user.ID, hash, "Cross Org Key", "member", sql.NullTime{})

	// Revoke with wrong org — should silently do nothing.
	if err := s.RevokeAPIKey(ctx, org2.ID, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey(wrong org): %v", err)
	}

	// Key should still be active.
	got, err := s.LookupAPIKey(ctx, hash)
	if err != nil {
		t.Fatalf("LookupAPIKey after wrong-org revoke: %v", err)
	}
	if got == nil {
		t.Error("key should still be active after wrong-org revoke attempt")
	}
}
