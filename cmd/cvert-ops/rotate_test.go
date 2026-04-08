// ABOUTME: Tests for the rotate-encryption-key command's core re-encryption logic.
// ABOUTME: Verifies key rotation, missing-key rejection, and empty-table no-op behavior.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestRotateEncryptionKey_ReEncryptsAllValues(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	pool := db.Pool()

	// Generate two 32-byte keys.
	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	// Create an org for the SSO connection (FK constraint).
	org, err := db.CreateOrg(ctx, "rotate-test-org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	orgID := org.ID

	// Encrypt a secret with the old key, bound to the org.
	secret := []byte("my-client-secret")
	enc, err := crypto.Encrypt(oldKey, secret, orgID[:])
	if err != nil {
		t.Fatalf("encrypt with old key: %v", err)
	}

	// Insert an SSO connection with the old-key-encrypted secret.
	_, err = pool.Exec(ctx,
		`INSERT INTO sso_connections (org_id, display_name, issuer_url, client_id, client_secret_enc)
		 VALUES ($1, 'Test IDP', 'https://idp.example.com', 'client123', $2)`,
		orgID, enc,
	)
	if err != nil {
		t.Fatalf("insert sso_connection: %v", err)
	}

	// Run the rotation logic.
	count, err := rotateEncryptionKeys(ctx, pool, newKey, oldKey)
	if err != nil {
		t.Fatalf("rotateEncryptionKeys: %v", err)
	}
	if count != 1 {
		t.Errorf("re-encrypted count = %d, want 1", count)
	}

	// Verify the value now decrypts with the new key only.
	var reEncrypted []byte
	err = pool.QueryRow(ctx,
		`SELECT client_secret_enc FROM sso_connections WHERE org_id = $1`, orgID,
	).Scan(&reEncrypted)
	if err != nil {
		t.Fatalf("read re-encrypted value: %v", err)
	}

	plaintext, err := crypto.Decrypt(newKey, reEncrypted, orgID[:])
	if err != nil {
		t.Fatalf("decrypt with new key failed: %v", err)
	}
	if string(plaintext) != string(secret) {
		t.Errorf("plaintext = %q, want %q", plaintext, secret)
	}

	// Verify old key alone no longer works.
	_, err = crypto.Decrypt(oldKey, reEncrypted, orgID[:])
	if err == nil {
		t.Error("decrypt with old key should fail on re-encrypted data, but succeeded")
	}
}

func TestRotateEncryptionKey_RefusesWithoutPreviousKey(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	pool := db.Pool()

	newKey := generateTestKey(t)
	var zeroKey [32]byte

	_, err := rotateEncryptionKeys(context.Background(), pool, newKey, zeroKey)
	if err == nil {
		t.Fatal("expected error when previous key is zero, got nil")
	}
}

func TestRotateEncryptionKey_NoSSO_IsNoOp(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	pool := db.Pool()

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)

	count, err := rotateEncryptionKeys(context.Background(), pool, newKey, oldKey)
	if err != nil {
		t.Fatalf("rotateEncryptionKeys: %v", err)
	}
	if count != 0 {
		t.Errorf("re-encrypted count = %d, want 0", count)
	}
}

func TestParseHexKey_Valid(t *testing.T) {
	t.Parallel()
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	hexStr := hex.EncodeToString(keyBytes)

	got, err := parseHexKey(hexStr, "TEST_KEY")
	if err != nil {
		t.Fatalf("parseHexKey: %v", err)
	}
	if got != [32]byte(keyBytes) {
		t.Error("parsed key does not match input")
	}
}

func TestParseHexKey_InvalidHex(t *testing.T) {
	t.Parallel()
	_, err := parseHexKey("not-valid-hex!", "TEST_KEY")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParseHexKey_WrongLength(t *testing.T) {
	t.Parallel()
	_, err := parseHexKey("abcd", "TEST_KEY")
	if err == nil {
		t.Error("expected error for wrong length")
	}
}

// generateTestKey produces a random 32-byte AES key for testing.
func generateTestKey(t *testing.T) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}
