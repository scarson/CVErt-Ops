// ABOUTME: Integration tests for MFA credential store methods.
// ABOUTME: Uses testutil.NewTestDB which starts a real Postgres container with migrations.
package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestMFA_CreateAndRetrieve(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-create@example.com", "MFA Create", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	secret := []byte("encrypted-totp-secret")
	cred, err := s.CreateMFACredential(ctx, user.ID, "totp", secret)
	if err != nil {
		t.Fatalf("CreateMFACredential: %v", err)
	}
	if cred.UserID != user.ID {
		t.Errorf("UserID = %v, want %v", cred.UserID, user.ID)
	}
	if cred.Method != "totp" {
		t.Errorf("Method = %q, want %q", cred.Method, "totp")
	}
	if string(cred.SecretEnc) != string(secret) {
		t.Errorf("SecretEnc = %q, want %q", cred.SecretEnc, secret)
	}
	if cred.ID == uuid.Nil {
		t.Error("ID should be set")
	}
	if cred.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	// Retrieve by user and method.
	got, err := s.GetMFACredentialByUserAndMethod(ctx, user.ID, "totp")
	if err != nil {
		t.Fatalf("GetMFACredentialByUserAndMethod: %v", err)
	}
	if got == nil {
		t.Fatal("GetMFACredentialByUserAndMethod returned nil")
	}
	if got.ID != cred.ID {
		t.Errorf("ID = %v, want %v", got.ID, cred.ID)
	}

	// Retrieve all by user.
	creds, err := s.GetMFACredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMFACredentialsByUserID: %v", err)
	}
	if len(creds) != 1 {
		t.Errorf("len(creds) = %d, want 1", len(creds))
	}
}

func TestMFA_UniqueConstraint(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-unique@example.com", "MFA Unique", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret1"))
	if err != nil {
		t.Fatalf("CreateMFACredential (first): %v", err)
	}

	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret2"))
	if err == nil {
		t.Error("expected error on duplicate (user_id, method), got nil")
	}
}

func TestMFA_CheckConstraints(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-check@example.com", "MFA Check", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// email_otp with non-nil secret_enc should fail (mfa_cred_email_null constraint).
	_, err = s.CreateMFACredential(ctx, user.ID, "email_otp", []byte("should-fail"))
	if err == nil {
		t.Error("expected error inserting email_otp with non-nil secret_enc, got nil")
	}

	// totp with nil secret_enc should fail (mfa_cred_totp_secret constraint).
	_, err = s.CreateMFACredential(ctx, user.ID, "totp", nil)
	if err == nil {
		t.Error("expected error inserting totp with nil secret_enc, got nil")
	}

	// email_otp with nil secret_enc should succeed.
	cred, err := s.CreateMFACredential(ctx, user.ID, "email_otp", nil)
	if err != nil {
		t.Fatalf("CreateMFACredential (email_otp, nil secret): %v", err)
	}
	if cred.Method != "email_otp" {
		t.Errorf("Method = %q, want %q", cred.Method, "email_otp")
	}
}

func TestMFA_UpdateLastUsed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-update@example.com", "MFA Update", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cred, err := s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential: %v", err)
	}
	if cred.LastUsedAt.Valid {
		t.Error("LastUsedAt should be null initially")
	}
	if cred.LastUsedStep.Valid {
		t.Error("LastUsedStep should be null initially")
	}

	step := sql.NullInt64{Int64: 12345, Valid: true}
	if err := s.UpdateMFACredentialLastUsed(ctx, cred.ID, step); err != nil {
		t.Fatalf("UpdateMFACredentialLastUsed: %v", err)
	}

	got, err := s.GetMFACredentialByUserAndMethod(ctx, user.ID, "totp")
	if err != nil {
		t.Fatalf("GetMFACredentialByUserAndMethod: %v", err)
	}
	if !got.LastUsedAt.Valid {
		t.Error("LastUsedAt should be set after update")
	}
	if !got.LastUsedStep.Valid || got.LastUsedStep.Int64 != 12345 {
		t.Errorf("LastUsedStep = %v, want 12345", got.LastUsedStep)
	}
}

func TestMFA_DeleteSingleMethod(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-delsingle@example.com", "MFA DelSingle", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential (totp): %v", err)
	}
	_, err = s.CreateMFACredential(ctx, user.ID, "email_otp", nil)
	if err != nil {
		t.Fatalf("CreateMFACredential (email_otp): %v", err)
	}

	n, err := s.DeleteMFACredential(ctx, user.ID, "totp")
	if err != nil {
		t.Fatalf("DeleteMFACredential: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d rows, want 1", n)
	}

	// email_otp should remain.
	creds, err := s.GetMFACredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMFACredentialsByUserID: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("len(creds) = %d, want 1", len(creds))
	}
	if creds[0].Method != "email_otp" {
		t.Errorf("remaining Method = %q, want %q", creds[0].Method, "email_otp")
	}
}

func TestMFA_DeleteAllCredentials(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-delall@example.com", "MFA DelAll", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential (totp): %v", err)
	}
	_, err = s.CreateMFACredential(ctx, user.ID, "email_otp", nil)
	if err != nil {
		t.Fatalf("CreateMFACredential (email_otp): %v", err)
	}

	n, err := s.DeleteAllMFACredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteAllMFACredentials: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d rows, want 2", n)
	}

	creds, err := s.GetMFACredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMFACredentialsByUserID: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("len(creds) = %d, want 0", len(creds))
	}
}

func TestMFA_UserHasMFACredentials(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-has@example.com", "MFA Has", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// No credentials yet.
	has, err := s.UserHasMFACredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFACredentials: %v", err)
	}
	if has {
		t.Error("expected false when no credentials exist")
	}

	// Add a credential.
	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential: %v", err)
	}

	has, err = s.UserHasMFACredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFACredentials: %v", err)
	}
	if !has {
		t.Error("expected true when credentials exist")
	}
}

func TestMFA_CascadeOnUserDelete(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-cascade@example.com", "MFA Cascade", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential: %v", err)
	}

	// Delete the user via raw SQL (no store method for hard delete).
	_, err = s.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	if err != nil {
		t.Fatalf("DELETE user: %v", err)
	}

	// Credentials should be gone via CASCADE.
	creds, err := s.GetMFACredentialsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMFACredentialsByUserID: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("len(creds) = %d after user delete, want 0", len(creds))
	}
}
