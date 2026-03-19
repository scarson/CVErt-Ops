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

	org := s.MustCreateOrg(t, ctx, "KeyOrg1")
	user := s.MustCreateUser(t, ctx, "keyuser1@example.com", "KeyUser1", "", 0)
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

	org := s.MustCreateOrg(t, ctx, "KeyOrg2")
	user := s.MustCreateUser(t, ctx, "keyuser2@example.com", "KeyUser2", "", 0)

	hash := "revokedhash_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "Revoked Key", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("setup: CreateAPIKey: %v", err)
	}

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

	org := s.MustCreateOrg(t, ctx, "KeyOrg3")
	user := s.MustCreateUser(t, ctx, "keyuser3@example.com", "KeyUser3", "", 0)

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

	org := s.MustCreateOrg(t, ctx, "KeyOrg4")
	user := s.MustCreateUser(t, ctx, "keyuser4@example.com", "KeyUser4", "", 0)

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

	org := s.MustCreateOrg(t, ctx, "KeyOrg5")
	user := s.MustCreateUser(t, ctx, "keyuser5@example.com", "KeyUser5", "", 0)

	hash1 := "listhash1_" + uuid.New().String()
	hash2 := "listhash2_" + uuid.New().String()
	if _, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash1, "Key One", "member", sql.NullTime{}); err != nil {
		t.Fatalf("setup: CreateAPIKey(Key One): %v", err)
	}
	if _, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash2, "Key Two", "admin", sql.NullTime{}); err != nil {
		t.Fatalf("setup: CreateAPIKey(Key Two): %v", err)
	}

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

	org1 := s.MustCreateOrg(t, ctx, "KeyOrg6a")
	org2 := s.MustCreateOrg(t, ctx, "KeyOrg6b")
	user := s.MustCreateUser(t, ctx, "keyuser6@example.com", "KeyUser6", "", 0)

	hash := "wrongorg_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org1.ID, user.ID, hash, "Cross Org Key", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("setup: CreateAPIKey: %v", err)
	}

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

func TestRevokeAPIKey_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "KeyOrg7")
	user := s.MustCreateUser(t, ctx, "keyuser7@example.com", "KeyUser7", "", 0)

	hash := "doublerevoke_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "Double Revoke", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("setup: CreateAPIKey: %v", err)
	}

	// Revoke once.
	if err := s.RevokeAPIKey(ctx, org.ID, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey (first): %v", err)
	}

	// Revoke again — should not error (idempotent: UPDATE sets revoked_at = now() again).
	if err := s.RevokeAPIKey(ctx, org.ID, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey (second): %v", err)
	}

	// Key should still be revoked.
	got, err := s.LookupAPIKey(ctx, hash)
	if err != nil {
		t.Fatalf("LookupAPIKey(double revoke): %v", err)
	}
	if got != nil {
		t.Error("key should still be revoked after double revoke")
	}
}

func TestListOrgAPIKeys_Empty(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "KeyOrg8")

	keys, err := s.ListOrgAPIKeys(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgAPIKeys (empty): %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListOrgAPIKeys on empty org = %d keys, want 0", len(keys))
	}
}

func TestGetOrgAPIKey(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "KeyOrg9")
	user := s.MustCreateUser(t, ctx, "keyuser9@example.com", "KeyUser9", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")

	hash := "getorgkey_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "GetMe", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("setup: CreateAPIKey: %v", err)
	}

	got, err := s.GetOrgAPIKey(ctx, org.ID, key.ID)
	if err != nil {
		t.Fatalf("GetOrgAPIKey: %v", err)
	}
	if got == nil {
		t.Fatal("GetOrgAPIKey returned nil for existing key")
	}
	if got.Name != "GetMe" {
		t.Errorf("Name = %q, want GetMe", got.Name)
	}
}

func TestGetOrgAPIKey_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "KeyOrg10")

	got, err := s.GetOrgAPIKey(ctx, org.ID, uuid.New())
	if err != nil {
		t.Fatalf("GetOrgAPIKey(not found): %v", err)
	}
	if got != nil {
		t.Error("GetOrgAPIKey should return nil for non-existent key")
	}
}

func TestGetOrgAPIKey_WrongOrg(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "KeyOrg11a")
	org2 := s.MustCreateOrg(t, ctx, "KeyOrg11b")
	user := s.MustCreateUser(t, ctx, "keyuser11@example.com", "KeyUser11", "", 0)

	hash := "crossorgget_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org1.ID, user.ID, hash, "CrossOrgGet", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("setup: CreateAPIKey: %v", err)
	}

	// GetOrgAPIKey with wrong org should return nil.
	got, err := s.GetOrgAPIKey(ctx, org2.ID, key.ID)
	if err != nil {
		t.Fatalf("GetOrgAPIKey(wrong org): %v", err)
	}
	if got != nil {
		t.Error("GetOrgAPIKey with wrong org should return nil")
	}
}

func TestUpdateAPIKeyLastUsed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "KeyOrg12")
	user := s.MustCreateUser(t, ctx, "keyuser12@example.com", "KeyUser12", "", 0)

	hash := "lastused_" + uuid.New().String()
	key, err := s.CreateAPIKey(ctx, org.ID, user.ID, hash, "LastUsed Key", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("setup: CreateAPIKey: %v", err)
	}

	// last_used_at should be null initially.
	got, err := s.GetOrgAPIKey(ctx, org.ID, key.ID)
	if err != nil {
		t.Fatalf("GetOrgAPIKey: %v", err)
	}
	if got.LastUsedAt.Valid {
		t.Error("LastUsedAt should be null initially")
	}

	if err := s.UpdateAPIKeyLastUsed(ctx, key.ID); err != nil {
		t.Fatalf("UpdateAPIKeyLastUsed: %v", err)
	}

	got2, err := s.GetOrgAPIKey(ctx, org.ID, key.ID)
	if err != nil {
		t.Fatalf("GetOrgAPIKey(after update): %v", err)
	}
	if !got2.LastUsedAt.Valid {
		t.Error("LastUsedAt should be set after UpdateAPIKeyLastUsed")
	}
}

func TestLookupAPIKey_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	got, err := s.LookupAPIKey(ctx, "nonexistent-hash-"+uuid.New().String())
	if err != nil {
		t.Fatalf("LookupAPIKey: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent hash, got %+v", got)
	}
}
