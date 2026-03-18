// ABOUTME: Integration tests for MFA credential, recovery code, challenge, and requirement store methods.
// ABOUTME: Uses testutil.NewTestDB which starts a real Postgres container with migrations.
package store_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
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

func TestMFA_CountCredentials(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "mfa-count@example.com", "MFA Count", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Zero credentials.
	n, err := s.CountMFACredentialsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountMFACredentialsByUser: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}

	// Add two credentials.
	_, err = s.CreateMFACredential(ctx, user.ID, "totp", []byte("secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential (totp): %v", err)
	}
	_, err = s.CreateMFACredential(ctx, user.ID, "email_otp", nil)
	if err != nil {
		t.Fatalf("CreateMFACredential (email_otp): %v", err)
	}

	n, err = s.CountMFACredentialsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountMFACredentialsByUser: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
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

// --- Recovery Code Tests ---

func TestRecoveryCode_Generate10Codes(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-gen@example.com", "RC Gen", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codes, err := s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("len(codes) = %d, want 10", len(codes))
	}

	// Verify format: xxxxx-xxxxx with a-z0-9.
	pat := regexp.MustCompile(`^[a-z0-9]{5}-[a-z0-9]{5}$`)
	seen := make(map[string]bool)
	for _, code := range codes {
		if !pat.MatchString(code) {
			t.Errorf("code %q does not match xxxxx-xxxxx pattern", code)
		}
		if seen[code] {
			t.Errorf("duplicate code: %q", code)
		}
		seen[code] = true
	}

	// Verify DB count.
	count, err := s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if count != 10 {
		t.Errorf("count = %d, want 10", count)
	}
}

func TestRecoveryCode_VerifyValid(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-verify@example.com", "RC Verify", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codes, err := s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	ok, remaining, err := s.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if !ok {
		t.Error("expected verification to succeed")
	}
	if remaining != 9 {
		t.Errorf("remaining = %d, want 9", remaining)
	}
}

func TestRecoveryCode_VerifyUsedCode(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-used@example.com", "RC Used", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codes, err := s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	// Use the code once.
	ok, _, err := s.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (first): %v", err)
	}
	if !ok {
		t.Fatal("first verification should succeed")
	}

	// Second attempt with the same code should fail.
	ok, remaining, err := s.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (second): %v", err)
	}
	if ok {
		t.Error("expected used code verification to fail")
	}
	if remaining != 9 {
		t.Errorf("remaining = %d, want 9", remaining)
	}
}

func TestRecoveryCode_VerifyWrongCode(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-wrong@example.com", "RC Wrong", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	ok, remaining, err := s.VerifyRecoveryCode(ctx, user.ID, "zzzzz-zzzzz")
	if err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if ok {
		t.Error("expected wrong code verification to fail")
	}
	if remaining != 10 {
		t.Errorf("remaining = %d, want 10", remaining)
	}
}

func TestRecoveryCode_VerifyCaseDashVariation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-case@example.com", "RC Case", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codes, err := s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	// Verify with uppercase and no dash — should match the same hash.
	code := codes[0]
	uppercaseNoDash := strings.ToUpper(strings.ReplaceAll(code, "-", ""))

	ok, remaining, err := s.VerifyRecoveryCode(ctx, user.ID, uppercaseNoDash)
	if err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if !ok {
		t.Errorf("expected uppercase/no-dash %q to match code %q", uppercaseNoDash, code)
	}
	if remaining != 9 {
		t.Errorf("remaining = %d, want 9", remaining)
	}
}

func TestRecoveryCode_ConcurrentConsumption(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-concurrent@example.com", "RC Concurrent", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codes, err := s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	code := codes[0]
	barrier := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]bool, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier
			ok, _, _ := s.VerifyRecoveryCode(ctx, user.ID, code)
			results[idx] = ok
		}(i)
	}
	close(barrier)
	wg.Wait()

	// Exactly one should succeed.
	if results[0] == results[1] {
		t.Errorf("concurrent consumption: both results = %v, expected exactly one true", results[0])
	}

	// 9 codes should remain.
	count, err := s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if count != 9 {
		t.Errorf("remaining count = %d, want 9", count)
	}
}

func TestRecoveryCode_Regenerate(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-regen@example.com", "RC Regen", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	oldCodes, err := s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	// Use one old code.
	ok, _, err := s.VerifyRecoveryCode(ctx, user.ID, oldCodes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if !ok {
		t.Fatal("expected old code to work before regeneration")
	}

	// Regenerate.
	newCodes, err := s.RegenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(newCodes) != 10 {
		t.Fatalf("len(newCodes) = %d, want 10", len(newCodes))
	}

	// Old codes (unused ones) should no longer work.
	ok, _, err = s.VerifyRecoveryCode(ctx, user.ID, oldCodes[1])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (old): %v", err)
	}
	if ok {
		t.Error("expected old code to fail after regeneration")
	}

	// New codes should work.
	ok, remaining, err := s.VerifyRecoveryCode(ctx, user.ID, newCodes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (new): %v", err)
	}
	if !ok {
		t.Error("expected new code to work after regeneration")
	}
	if remaining != 9 {
		t.Errorf("remaining = %d, want 9", remaining)
	}

	// Total unused should be 9.
	count, err := s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if count != 9 {
		t.Errorf("count = %d, want 9", count)
	}
}

func TestRecoveryCode_CascadeOnUserDelete(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-cascade@example.com", "RC Cascade", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	// Delete the user via raw SQL.
	_, err = s.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	if err != nil {
		t.Fatalf("DELETE user: %v", err)
	}

	// Recovery codes should be gone via CASCADE.
	count, err := s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d after user delete, want 0", count)
	}
}

func TestRecoveryCode_DeleteAll(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "rc-delall@example.com", "RC DelAll", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = s.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	count, err := s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes (before): %v", err)
	}
	if count != 10 {
		t.Fatalf("count = %d before delete, want 10", count)
	}

	err = s.DeleteAllRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteAllRecoveryCodes: %v", err)
	}

	count, err = s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes (after): %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d after delete, want 0", count)
	}
}

// --- MFA Challenge Tests ---

// hashCode returns the SHA-256 hex digest of a string (matches store's hashing for email OTP).
func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

func TestMFAChallenge_CreateAndVerifyEmailOTP(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-happy@example.com", "OTP Happy", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	code := "123456"
	codeHash := hashCode(code)
	expiresAt := time.Now().Add(10 * time.Minute)

	err = s.CreateEmailOTPChallenge(ctx, user.ID, codeHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}

	ok, _, err := s.VerifyEmailOTPChallenge(ctx, user.ID, codeHash, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge: %v", err)
	}
	if !ok {
		t.Error("expected verification to succeed")
	}
}

func TestMFAChallenge_SingleActiveCode(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-single@example.com", "OTP Single", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	code1 := hashCode("111111")
	code2 := hashCode("222222")
	expiresAt := time.Now().Add(10 * time.Minute)

	err = s.CreateEmailOTPChallenge(ctx, user.ID, code1, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge (first): %v", err)
	}

	// Creating a second challenge should delete the first.
	err = s.CreateEmailOTPChallenge(ctx, user.ID, code2, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge (second): %v", err)
	}

	// Old code should fail.
	ok, _, err := s.VerifyEmailOTPChallenge(ctx, user.ID, code1, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (old): %v", err)
	}
	if ok {
		t.Error("expected old code to fail after new code created")
	}

	// New code should succeed.
	ok, _, err = s.VerifyEmailOTPChallenge(ctx, user.ID, code2, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (new): %v", err)
	}
	if !ok {
		t.Error("expected new code to succeed")
	}
}

func TestMFAChallenge_ExpiredCode(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-expired@example.com", "OTP Expired", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	code := hashCode("123456")
	// Already expired.
	expiresAt := time.Now().Add(-1 * time.Minute)

	err = s.CreateEmailOTPChallenge(ctx, user.ID, code, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}

	ok, _, err := s.VerifyEmailOTPChallenge(ctx, user.ID, code, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge: %v", err)
	}
	if ok {
		t.Error("expected expired code verification to fail")
	}
}

func TestMFAChallenge_AttemptExhaustion(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-exhaust@example.com", "OTP Exhaust", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	correctHash := hashCode("123456")
	wrongHash := hashCode("000000")
	expiresAt := time.Now().Add(10 * time.Minute)

	err = s.CreateEmailOTPChallenge(ctx, user.ID, correctHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}

	// 3 wrong attempts (maxAttempts=3).
	for i := 0; i < 3; i++ {
		ok, _, err := s.VerifyEmailOTPChallenge(ctx, user.ID, wrongHash, 3)
		if err != nil {
			t.Fatalf("VerifyEmailOTPChallenge (wrong %d): %v", i+1, err)
		}
		if ok {
			t.Errorf("wrong attempt %d should fail", i+1)
		}
	}

	// Now even the correct code should fail — challenge deleted after max attempts.
	ok, _, err := s.VerifyEmailOTPChallenge(ctx, user.ID, correctHash, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (correct after exhaust): %v", err)
	}
	if ok {
		t.Error("expected correct code to fail after attempt exhaustion")
	}
}

func TestStore_VerifyEmailOTP_ExhaustedReturnsBool(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-exhaust-bool@example.com", "OTP Exhaust Bool", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	correctHash := hashCode("123456")
	wrongHash := hashCode("000000")
	expiresAt := time.Now().Add(10 * time.Minute)

	err = s.CreateEmailOTPChallenge(ctx, user.ID, correctHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}

	// First two wrong attempts (maxAttempts=3) — not yet exhausted.
	for i := 0; i < 2; i++ {
		matched, exhausted, err := s.VerifyEmailOTPChallenge(ctx, user.ID, wrongHash, 3)
		if err != nil {
			t.Fatalf("VerifyEmailOTPChallenge (wrong %d): %v", i+1, err)
		}
		if matched {
			t.Errorf("wrong attempt %d should not match", i+1)
		}
		if exhausted {
			t.Errorf("wrong attempt %d should not be exhausted yet", i+1)
		}
	}

	// Third wrong attempt — should be exhausted.
	matched, exhausted, err := s.VerifyEmailOTPChallenge(ctx, user.ID, wrongHash, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (final wrong): %v", err)
	}
	if matched {
		t.Error("final wrong attempt should not match")
	}
	if !exhausted {
		t.Error("final wrong attempt should return exhausted=true")
	}

	// After exhaustion, correct code should fail (challenge deleted) and not be exhausted
	// (no challenge to exhaust).
	matched, exhausted, err = s.VerifyEmailOTPChallenge(ctx, user.ID, correctHash, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (correct after exhaust): %v", err)
	}
	if matched {
		t.Error("expected correct code to fail after attempt exhaustion")
	}
	if exhausted {
		t.Error("expected exhausted=false when no challenge exists")
	}
}

func TestMFAChallenge_RateLimiting(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-rate@example.com", "OTP Rate", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	since := time.Now().Add(-1 * time.Hour)
	expiresAt := time.Now().Add(10 * time.Minute)

	// No challenges yet.
	count, err := s.CountRecentEmailOTPChallenges(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CountRecentEmailOTPChallenges: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}

	// Create a few challenges.
	for i := 0; i < 3; i++ {
		err = s.CreateEmailOTPChallenge(ctx, user.ID, hashCode("code"+string(rune('0'+i))), expiresAt)
		if err != nil {
			t.Fatalf("CreateEmailOTPChallenge (%d): %v", i, err)
		}
	}

	// Count should reflect all created (CreateEmailOTPChallenge deletes previous email_otp,
	// but only active ones — the deleted ones are gone). Since each create deletes existing
	// email_otp challenges first, only 1 should remain.
	count, err = s.CountRecentEmailOTPChallenges(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CountRecentEmailOTPChallenges: %v", err)
	}
	// Only 1 active email_otp challenge should exist (each create deletes previous).
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	// A window in the far future should yield 0.
	futureCount, err := s.CountRecentEmailOTPChallenges(ctx, user.ID, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("CountRecentEmailOTPChallenges (future): %v", err)
	}
	if futureCount != 0 {
		t.Errorf("futureCount = %d, want 0", futureCount)
	}
}

func TestMFAChallenge_RememberDeviceToken(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-remember@example.com", "OTP Remember", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := hashCode("random-device-token")
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	err = s.CreateRememberDeviceToken(ctx, user.ID, tokenHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateRememberDeviceToken: %v", err)
	}

	// Validate succeeds.
	ok, err := s.ValidateRememberDeviceToken(ctx, user.ID, tokenHash)
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken: %v", err)
	}
	if !ok {
		t.Error("expected token validation to succeed")
	}

	// Delete and revalidate.
	err = s.DeleteRememberDeviceTokens(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteRememberDeviceTokens: %v", err)
	}

	ok, err = s.ValidateRememberDeviceToken(ctx, user.ID, tokenHash)
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken (after delete): %v", err)
	}
	if ok {
		t.Error("expected token validation to fail after deletion")
	}
}

func TestMFAChallenge_ExpiredRememberDevice(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-remember-exp@example.com", "OTP RememberExp", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenHash := hashCode("expired-device-token")
	expiresAt := time.Now().Add(-1 * time.Minute) // Already expired.

	err = s.CreateRememberDeviceToken(ctx, user.ID, tokenHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateRememberDeviceToken: %v", err)
	}

	ok, err := s.ValidateRememberDeviceToken(ctx, user.ID, tokenHash)
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken: %v", err)
	}
	if ok {
		t.Error("expected expired token validation to fail")
	}
}

func TestMFAChallenge_DeleteExpired(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-cleanup@example.com", "OTP Cleanup", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create an expired challenge.
	expiredHash := hashCode("expired-code")
	err = s.CreateEmailOTPChallenge(ctx, user.ID, expiredHash, time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge (expired): %v", err)
	}

	// Create a valid challenge (different user to avoid single-active-code deletion).
	user2, err := s.CreateUser(ctx, "otp-cleanup2@example.com", "OTP Cleanup2", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (2): %v", err)
	}
	validHash := hashCode("valid-code")
	err = s.CreateEmailOTPChallenge(ctx, user2.ID, validHash, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge (valid): %v", err)
	}

	// Run cleanup.
	deleted, err := s.DeleteExpiredChallenges(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredChallenges: %v", err)
	}
	if deleted < 1 {
		t.Errorf("deleted = %d, want >= 1", deleted)
	}

	// Valid challenge should still be verifiable.
	ok, _, err := s.VerifyEmailOTPChallenge(ctx, user2.ID, validHash, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (valid after cleanup): %v", err)
	}
	if !ok {
		t.Error("expected valid challenge to survive cleanup")
	}
}

func TestMFAChallenge_ConcurrentVerification(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-concurrent@example.com", "OTP Concurrent", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codeHash := hashCode("123456")
	expiresAt := time.Now().Add(10 * time.Minute)

	err = s.CreateEmailOTPChallenge(ctx, user.ID, codeHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}

	barrier := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]bool, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier
			ok, _, verifyErr := s.VerifyEmailOTPChallenge(ctx, user.ID, codeHash, 3)
			if verifyErr != nil {
				t.Errorf("goroutine %d: VerifyEmailOTPChallenge: %v", idx, verifyErr)
				return
			}
			results[idx] = ok
		}(i)
	}
	close(barrier)
	wg.Wait()

	successCount := 0
	for _, ok := range results {
		if ok {
			successCount++
		}
	}
	if successCount != 1 {
		t.Errorf("concurrent verification: %d successes, want exactly 1 (results: %v)", successCount, results)
	}
}

func TestMFAChallenge_DeleteAllUserChallenges(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-delall@example.com", "OTP DelAll", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create both an email OTP challenge and a remember-device token.
	err = s.CreateEmailOTPChallenge(ctx, user.ID, hashCode("123456"), time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}
	err = s.CreateRememberDeviceToken(ctx, user.ID, hashCode("device-token"), time.Now().Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateRememberDeviceToken: %v", err)
	}

	// Delete all challenges for the user.
	err = s.DeleteAllUserChallenges(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteAllUserChallenges: %v", err)
	}

	// Email OTP should fail (no challenge).
	ok, _, err := s.VerifyEmailOTPChallenge(ctx, user.ID, hashCode("123456"), 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge: %v", err)
	}
	if ok {
		t.Error("expected email OTP verification to fail after DeleteAllUserChallenges")
	}

	// Remember-device token should fail.
	ok, err = s.ValidateRememberDeviceToken(ctx, user.ID, hashCode("device-token"))
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken: %v", err)
	}
	if ok {
		t.Error("expected remember-device validation to fail after DeleteAllUserChallenges")
	}
}

func TestMFAChallenge_DeleteExpiredRememberDevice(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "otp-exprd@example.com", "OTP ExpRD", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create an expired remember-device token.
	err = s.CreateRememberDeviceToken(ctx, user.ID, hashCode("expired-rd"), time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("CreateRememberDeviceToken (expired): %v", err)
	}

	// Create a valid remember-device token (different user to avoid interference).
	user2, err := s.CreateUser(ctx, "otp-exprd2@example.com", "OTP ExpRD2", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (2): %v", err)
	}
	err = s.CreateRememberDeviceToken(ctx, user2.ID, hashCode("valid-rd"), time.Now().Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateRememberDeviceToken (valid): %v", err)
	}

	// Run cleanup.
	deleted, err := s.DeleteExpiredChallenges(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredChallenges: %v", err)
	}
	if deleted < 1 {
		t.Errorf("deleted = %d, want >= 1", deleted)
	}

	// Valid token should survive cleanup.
	ok, err := s.ValidateRememberDeviceToken(ctx, user2.ID, hashCode("valid-rd"))
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken (valid after cleanup): %v", err)
	}
	if !ok {
		t.Error("expected valid remember-device token to survive cleanup")
	}
}

func TestMFAChallenge_RememberDeviceCrossUserIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	userA, err := s.CreateUser(ctx, "rd-iso-a@example.com", "RD Iso A", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser A: %v", err)
	}
	userB, err := s.CreateUser(ctx, "rd-iso-b@example.com", "RD Iso B", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser B: %v", err)
	}

	tokenHash := hashCode("shared-device-token")
	err = s.CreateRememberDeviceToken(ctx, userA.ID, tokenHash, time.Now().Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateRememberDeviceToken for A: %v", err)
	}

	// User A can validate their own token.
	ok, err := s.ValidateRememberDeviceToken(ctx, userA.ID, tokenHash)
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken (A): %v", err)
	}
	if !ok {
		t.Error("expected user A to validate their own token")
	}

	// User B cannot validate user A's token.
	ok, err = s.ValidateRememberDeviceToken(ctx, userB.ID, tokenHash)
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken (B): %v", err)
	}
	if ok {
		t.Error("expected user B to NOT validate user A's token — cross-user isolation failure")
	}
}

// --- MFA Requirement Tests ---

func TestMFARequirement_CreateAndRetrieve(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	// Setup: create org, user, membership.
	org, err := tdb.CreateOrg(ctx, "MFA Req Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-create@example.com", "MFA Req Create", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-req-admin@example.com", "MFA Req Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	// Create requirement.
	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	// Retrieve requirements for org.
	reqs, err := tdb.GetMFARequirementsByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetMFARequirementsByOrg: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("len(reqs) = %d, want 1", len(reqs))
	}
	if reqs[0].UserID != user.ID {
		t.Errorf("UserID = %v, want %v", reqs[0].UserID, user.ID)
	}
	if reqs[0].OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", reqs[0].OrgID, org.ID)
	}
	if !reqs[0].RequiredBy.Valid || reqs[0].RequiredBy.UUID != admin.ID {
		t.Errorf("RequiredBy = %v, want %v", reqs[0].RequiredBy, admin.ID)
	}
	if reqs[0].CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestMFARequirement_IdempotentCreate(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Req Idempotent Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-idem@example.com", "MFA Req Idem", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-req-idem-admin@example.com", "MFA Req Idem Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	// First create.
	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement (first): %v", err)
	}

	// Second create — ON CONFLICT DO NOTHING, should not error.
	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement (second): %v, expected no error on duplicate", err)
	}

	// Still only one row.
	reqs, err := tdb.GetMFARequirementsByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetMFARequirementsByOrg: %v", err)
	}
	if len(reqs) != 1 {
		t.Errorf("len(reqs) = %d, want 1 (idempotent create should not duplicate)", len(reqs))
	}
}

func TestMFARequirement_Delete(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Req Del Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-del@example.com", "MFA Req Del", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-req-del-admin@example.com", "MFA Req Del Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	// Delete.
	err = tdb.DeleteMFARequirement(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("DeleteMFARequirement: %v", err)
	}

	// Verify gone.
	reqs, err := tdb.GetMFARequirementsByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetMFARequirementsByOrg: %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("len(reqs) = %d, want 0 after delete", len(reqs))
	}
}

func TestMFARequirement_CascadeOnMembershipRemoval(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Req Cascade Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-cascade@example.com", "MFA Req Cascade", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-req-cascade-admin@example.com", "MFA Req Cascade Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	// Remove user from org — composite FK CASCADE should delete the requirement.
	if err := tdb.RemoveOrgMember(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("RemoveOrgMember: %v", err)
	}

	// Requirement should be gone.
	reqs, err := tdb.GetMFARequirementsByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetMFARequirementsByOrg: %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("len(reqs) = %d after membership removal, want 0 (CASCADE)", len(reqs))
	}
}

func TestMFARequirement_RLSCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs with users via superuser.
	orgA, err := tdb.CreateOrg(ctx, "MFA Req RLS Org A")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	orgB, err := tdb.CreateOrg(ctx, "MFA Req RLS Org B")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}
	userA, err := tdb.CreateUser(ctx, "mfa-req-rls-a@example.com", "MFA RLS A", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser A: %v", err)
	}
	userB, err := tdb.CreateUser(ctx, "mfa-req-rls-b@example.com", "MFA RLS B", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser B: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgA.ID, userA.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember A: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgB.ID, userB.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember B: %v", err)
	}

	admin, err := tdb.CreateUser(ctx, "mfa-req-rls-admin@example.com", "MFA RLS Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	// Create requirements in both orgs via superuser.
	err = tdb.CreateMFARequirement(ctx, orgA.ID, userA.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement A: %v", err)
	}
	err = tdb.CreateMFARequirement(ctx, orgB.ID, userB.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement B: %v", err)
	}

	// Query via NOBYPASSRLS connection scoped to Org A — should not see Org B's data.
	gotA, err := tdb.AppStore.GetMFARequirementsByOrg(ctx, orgA.ID)
	if err != nil {
		t.Fatalf("AppStore.GetMFARequirementsByOrg(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("expected 1 requirement for orgA via AppStore, got %d — RLS isolation failure", len(gotA))
	} else if gotA[0].UserID != userA.ID {
		t.Errorf("expected userA, got %v", gotA[0].UserID)
	}

	// Query via NOBYPASSRLS connection scoped to Org B.
	gotB, err := tdb.AppStore.GetMFARequirementsByOrg(ctx, orgB.ID)
	if err != nil {
		t.Fatalf("AppStore.GetMFARequirementsByOrg(orgB): %v", err)
	}
	if len(gotB) != 1 {
		t.Errorf("expected 1 requirement for orgB via AppStore, got %d — RLS isolation failure", len(gotB))
	} else if gotB[0].UserID != userB.ID {
		t.Errorf("expected userB, got %v", gotB[0].UserID)
	}
}

func TestMFARequirement_UserHasMFARequirementBypass(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Req Bypass Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-bypass@example.com", "MFA Req Bypass", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-req-bypass-admin@example.com", "MFA Req Bypass Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	// No requirement yet.
	has, err := tdb.UserHasMFARequirement(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFARequirement: %v", err)
	}
	if has {
		t.Error("expected false when no requirement exists")
	}

	// Add requirement.
	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	// Now should be true — queried without org context (bypass).
	has, err = tdb.UserHasMFARequirement(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFARequirement: %v", err)
	}
	if !has {
		t.Error("expected true when requirement exists")
	}
}

func TestMFARequirement_UserInMFARequiredOrgBypass(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Req AllOrg")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-allorg@example.com", "MFA Req AllOrg", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// mfa_required_all defaults to false.
	inReq, err := tdb.UserInMFARequiredOrg(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserInMFARequiredOrg: %v", err)
	}
	if inReq {
		t.Error("expected false when org has mfa_required_all=false")
	}

	// Set mfa_required_all=true via raw SQL.
	_, err = tdb.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", org.ID)
	if err != nil {
		t.Fatalf("UPDATE mfa_required_all: %v", err)
	}

	inReq, err = tdb.UserInMFARequiredOrg(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserInMFARequiredOrg: %v", err)
	}
	if !inReq {
		t.Error("expected true when org has mfa_required_all=true")
	}
}

func TestMFARequirement_NoRequirementAfterOrgLeave(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Req Leave Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-req-leave@example.com", "MFA Req Leave", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-req-leave-admin@example.com", "MFA Req Leave Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	// Confirm requirement exists (bypass check).
	has, err := tdb.UserHasMFARequirement(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFARequirement (before leave): %v", err)
	}
	if !has {
		t.Fatal("expected requirement to exist before org leave")
	}

	// Remove user from org.
	if err := tdb.RemoveOrgMember(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("RemoveOrgMember: %v", err)
	}

	// Requirement should be gone (composite FK CASCADE).
	has, err = tdb.UserHasMFARequirement(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFARequirement (after leave): %v", err)
	}
	if has {
		t.Error("expected false after user removed from org — CASCADE should clean up requirement")
	}
}

// --- UserMFARequired (3-layer mandate check) Tests ---

func TestUserMFARequired_SiteAdminRequired(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "mfa-mandate-siteadmin@example.com", "MFA Mandate SiteAdmin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: true, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, true, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if !required {
		t.Error("expected MFA required for site admin with RequiredSiteAdmins=true")
	}
}

func TestUserMFARequired_OrgOwnerRequired(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Mandate Owner Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-owner@example.com", "MFA Mandate Owner", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "owner"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: true}
	required, err := tdb.UserMFARequired(ctx, user.ID, false, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if !required {
		t.Error("expected MFA required for org owner with RequiredOrgOwners=true")
	}
}

func TestUserMFARequired_OrgWideMFARequired(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Mandate OrgWide")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-orgwide@example.com", "MFA Mandate OrgWide", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// Set mfa_required_all=true.
	_, err = tdb.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", org.ID)
	if err != nil {
		t.Fatalf("UPDATE mfa_required_all: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, false, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if !required {
		t.Error("expected MFA required for member of org with mfa_required_all=true")
	}
}

func TestUserMFARequired_PerMemberRequirement(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Mandate PerMember Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-permember@example.com", "MFA Mandate PerMember", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-mandate-permember-admin@example.com", "MFA Mandate PerMember Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	// Create per-member requirement.
	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, false, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if !required {
		t.Error("expected MFA required for user with per-member requirement")
	}
}

func TestUserMFARequired_NoneRequired(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Mandate None Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-none@example.com", "MFA Mandate None", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, false, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if required {
		t.Error("expected MFA not required when no layers match")
	}
}

func TestUserMFARequired_SiteAdminFlagFalse(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Mandate AdminFalse Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-adminfalse@example.com", "MFA Mandate AdminFalse", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	admin, err := tdb.CreateUser(ctx, "mfa-mandate-adminfalse-admin@example.com", "MFA Mandate AdminFalse Admin", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (admin): %v", err)
	}

	// Site admin but RequiredSiteAdmins=false; per-member requirement exists → should still be required.
	err = tdb.CreateMFARequirement(ctx, org.ID, user.ID, admin.ID)
	if err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, true, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if !required {
		t.Error("expected MFA required via per-member layer even when RequiredSiteAdmins=false")
	}
}

func TestUserMFARequired_SiteAdminNotRequiredWhenConfigOff(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "MFA Mandate AdminOff Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-adminoff@example.com", "MFA Mandate AdminOff", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// isSiteAdmin=true but RequiredSiteAdmins=false, NO other layers active.
	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, true, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if required {
		t.Error("expected MFA NOT required for site admin when RequiredSiteAdmins=false and no other layers match")
	}
}

func TestUserMFARequired_MultipleOrgsOneMFARequired(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	orgA, err := tdb.CreateOrg(ctx, "MFA Mandate MultiOrg A")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	orgB, err := tdb.CreateOrg(ctx, "MFA Mandate MultiOrg B")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "mfa-mandate-multi@example.com", "MFA Mandate Multi", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgA.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember A: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgB.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember B: %v", err)
	}

	// Only orgB requires MFA.
	_, err = tdb.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", orgB.ID)
	if err != nil {
		t.Fatalf("UPDATE mfa_required_all: %v", err)
	}

	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: false}
	required, err := tdb.UserMFARequired(ctx, user.ID, false, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if !required {
		t.Error("expected MFA required when any org requires MFA")
	}
}

func TestUpdateOrgMFASettings(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := s.CreateOrg(ctx, "MFA Settings Org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// Verify defaults.
	if org.MfaRequiredAll {
		t.Error("MfaRequiredAll default should be false")
	}
	if !org.MfaRememberDeviceAllowed {
		t.Error("MfaRememberDeviceAllowed default should be true")
	}

	t.Run("update all settings", func(t *testing.T) {
		updated, err := s.UpdateOrgMFASettings(ctx, org.ID, true, true, 14)
		if err != nil {
			t.Fatalf("UpdateOrgMFASettings: %v", err)
		}
		if updated == nil {
			t.Fatal("UpdateOrgMFASettings returned nil")
		}
		if !updated.MfaRequiredAll {
			t.Error("MfaRequiredAll should be true")
		}
		if !updated.MfaRememberDeviceAllowed {
			t.Error("MfaRememberDeviceAllowed should be true")
		}
		if updated.MfaRememberDeviceDays != 14 {
			t.Errorf("MfaRememberDeviceDays = %d, want 14", updated.MfaRememberDeviceDays)
		}
	})

	t.Run("non-existent org returns nil", func(t *testing.T) {
		result, err := s.UpdateOrgMFASettings(ctx, uuid.New(), true, true, 7)
		if err != nil {
			t.Fatalf("UpdateOrgMFASettings(not found): %v", err)
		}
		if result != nil {
			t.Error("expected nil for non-existent org")
		}
	})
}

func TestStore_ResetUserMFA(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, "reset-mfa@example.com", "Reset MFA", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Record initial token_version.
	initialUser, err := s.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	initialVersion := initialUser.TokenVersion

	// Enroll TOTP credential.
	if _, err := s.CreateMFACredential(ctx, user.ID, "totp", []byte("encrypted-secret")); err != nil {
		t.Fatalf("CreateMFACredential: %v", err)
	}

	// Generate recovery codes.
	if _, err := s.GenerateRecoveryCodes(ctx, user.ID); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	// Create an email OTP challenge.
	codeHash := sha256.Sum256([]byte("123456"))
	if err := s.CreateEmailOTPChallenge(ctx, user.ID, hex.EncodeToString(codeHash[:]), time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("CreateEmailOTPChallenge: %v", err)
	}

	// Create a remember-device token.
	tokenHash := sha256.Sum256([]byte("device-token"))
	if err := s.CreateRememberDeviceToken(ctx, user.ID, hex.EncodeToString(tokenHash[:]), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("CreateRememberDeviceToken: %v", err)
	}

	// Verify setup: user should have MFA state.
	hasCreds, err := s.UserHasMFACredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFACredentials: %v", err)
	}
	if !hasCreds {
		t.Fatal("expected user to have MFA credentials before reset")
	}
	unusedCodes, err := s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if unusedCodes == 0 {
		t.Fatal("expected user to have recovery codes before reset")
	}

	// Call ResetUserMFA.
	newVersion, err := s.ResetUserMFA(ctx, user.ID)
	if err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}

	// Assert: token_version incremented by 1.
	if newVersion != initialVersion+1 {
		t.Errorf("token_version = %d, want %d", newVersion, initialVersion+1)
	}

	// Assert: no credentials.
	hasCreds, err = s.UserHasMFACredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserHasMFACredentials after reset: %v", err)
	}
	if hasCreds {
		t.Error("expected no MFA credentials after reset")
	}

	// Assert: no recovery codes.
	unusedCodes, err = s.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes after reset: %v", err)
	}
	if unusedCodes != 0 {
		t.Errorf("expected 0 recovery codes after reset, got %d", unusedCodes)
	}

	// Assert: no challenges (email OTP + remember device both gone).
	valid, err := s.ValidateRememberDeviceToken(ctx, user.ID, hex.EncodeToString(tokenHash[:]))
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken after reset: %v", err)
	}
	if valid {
		t.Error("expected remember-device token to be deleted after reset")
	}
}

// ── Direct store method tests (P11 Task 3) ──────────────────────────────────

func TestStore_VerifyAndUpdateTOTPStep_Direct(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "totp-step-direct@example.com", "TOTP Step", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, err = tdb.CreateMFACredential(ctx, user.ID, "totp", []byte("encrypted-secret"))
	if err != nil {
		t.Fatalf("CreateMFACredential: %v", err)
	}

	// Fresh step — should succeed.
	ok, err := tdb.VerifyAndUpdateTOTPStep(ctx, user.ID, 100)
	if err != nil {
		t.Fatalf("VerifyAndUpdateTOTPStep(100): %v", err)
	}
	if !ok {
		t.Fatal("expected fresh step 100 to return true")
	}

	// Same step — replay, should fail.
	ok, err = tdb.VerifyAndUpdateTOTPStep(ctx, user.ID, 100)
	if err != nil {
		t.Fatalf("VerifyAndUpdateTOTPStep(100 replay): %v", err)
	}
	if ok {
		t.Fatal("expected replay step 100 to return false")
	}

	// Lower step — replay, should fail.
	ok, err = tdb.VerifyAndUpdateTOTPStep(ctx, user.ID, 50)
	if err != nil {
		t.Fatalf("VerifyAndUpdateTOTPStep(50 lower): %v", err)
	}
	if ok {
		t.Fatal("expected lower step 50 to return false")
	}

	// Higher step — should succeed.
	ok, err = tdb.VerifyAndUpdateTOTPStep(ctx, user.ID, 101)
	if err != nil {
		t.Fatalf("VerifyAndUpdateTOTPStep(101): %v", err)
	}
	if !ok {
		t.Fatal("expected higher step 101 to return true")
	}
}

func TestStore_UserMFARequiredOrgNames_Direct(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "orgnames-direct@example.com", "OrgNames", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	org, err := tdb.CreateOrg(ctx, "TestOrg")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// Set mfa_required_all=true via UpdateOrgMFASettings.
	_, err = tdb.UpdateOrgMFASettings(ctx, org.ID, true, true, 30)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings: %v", err)
	}

	names, err := tdb.UserMFARequiredOrgNames(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserMFARequiredOrgNames: %v", err)
	}
	if len(names) != 1 || names[0] != "TestOrg" {
		t.Errorf("UserMFARequiredOrgNames = %v, want [TestOrg]", names)
	}

	// Add second org without MFA requirement.
	org2, err := tdb.CreateOrg(ctx, "OtherOrg")
	if err != nil {
		t.Fatalf("CreateOrg (2): %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org2.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember (2): %v", err)
	}

	names, err = tdb.UserMFARequiredOrgNames(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserMFARequiredOrgNames (2): %v", err)
	}
	if len(names) != 1 || names[0] != "TestOrg" {
		t.Errorf("UserMFARequiredOrgNames = %v, want [TestOrg]", names)
	}
}

func TestStore_UserMFARequirementOrgNames_Direct(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "reqnames-direct@example.com", "ReqNames", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	owner, err := tdb.CreateUser(ctx, "reqnames-owner@example.com", "ReqOwner", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser (owner): %v", err)
	}
	org, err := tdb.CreateOrg(ctx, "ReqOrg")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org.ID, owner.ID, "owner"); err != nil {
		t.Fatalf("CreateOrgMember (owner): %v", err)
	}

	// Create per-member requirement.
	if err := tdb.CreateMFARequirement(ctx, org.ID, user.ID, owner.ID); err != nil {
		t.Fatalf("CreateMFARequirement: %v", err)
	}

	names, err := tdb.UserMFARequirementOrgNames(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserMFARequirementOrgNames: %v", err)
	}
	if len(names) != 1 || names[0] != "ReqOrg" {
		t.Errorf("UserMFARequirementOrgNames = %v, want [ReqOrg]", names)
	}

	// Add second org without per-member requirement — should still just have ReqOrg.
	org2, err := tdb.CreateOrg(ctx, "NoReqOrg")
	if err != nil {
		t.Fatalf("CreateOrg (2): %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, org2.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember (2): %v", err)
	}

	names, err = tdb.UserMFARequirementOrgNames(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserMFARequirementOrgNames (2): %v", err)
	}
	if len(names) != 1 || names[0] != "ReqOrg" {
		t.Errorf("UserMFARequirementOrgNames = %v, want [ReqOrg]", names)
	}
}

func TestStore_AllUserOrgsAllowRememberDevice_Direct(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "remember-direct@example.com", "Remember", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	orgA, err := tdb.CreateOrg(ctx, "RememberOrgA")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgA.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember A: %v", err)
	}

	// Default org: remember_device_allowed defaults to true.
	allowed, err := tdb.AllUserOrgsAllowRememberDevice(ctx, user.ID)
	if err != nil {
		t.Fatalf("AllUserOrgsAllowRememberDevice: %v", err)
	}
	if !allowed {
		t.Error("expected remember device to be allowed with default org settings")
	}

	// Add second org with remember_device_allowed=false.
	orgB, err := tdb.CreateOrg(ctx, "RememberOrgB")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgB.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember B: %v", err)
	}
	_, err = tdb.UpdateOrgMFASettings(ctx, orgB.ID, false, false, 30)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings B: %v", err)
	}

	// Most-restrictive wins: one org says false → result is false.
	allowed, err = tdb.AllUserOrgsAllowRememberDevice(ctx, user.ID)
	if err != nil {
		t.Fatalf("AllUserOrgsAllowRememberDevice (2): %v", err)
	}
	if allowed {
		t.Error("expected remember device disallowed when one org has it off")
	}
}

func TestStore_MinRememberDeviceDays_Direct(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "mindays-direct@example.com", "MinDays", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	orgA, err := tdb.CreateOrg(ctx, "MinDaysOrgA")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgA.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember A: %v", err)
	}
	// Set orgA to 30 days.
	_, err = tdb.UpdateOrgMFASettings(ctx, orgA.ID, false, true, 30)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings A: %v", err)
	}

	days, err := tdb.MinRememberDeviceDays(ctx, user.ID)
	if err != nil {
		t.Fatalf("MinRememberDeviceDays: %v", err)
	}
	if days != 30 {
		t.Errorf("MinRememberDeviceDays = %d, want 30", days)
	}

	// Add second org with 14 days — MIN should return 14.
	orgB, err := tdb.CreateOrg(ctx, "MinDaysOrgB")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgB.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember B: %v", err)
	}
	_, err = tdb.UpdateOrgMFASettings(ctx, orgB.ID, false, true, 14)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings B: %v", err)
	}

	days, err = tdb.MinRememberDeviceDays(ctx, user.ID)
	if err != nil {
		t.Fatalf("MinRememberDeviceDays (2): %v", err)
	}
	if days != 14 {
		t.Errorf("MinRememberDeviceDays = %d, want 14", days)
	}
}

func TestStore_RememberDevice_MultiOrg_MostRestrictive(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "multiorg-remember@example.com", "MultiRemember", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	orgA, err := tdb.CreateOrg(ctx, "MultiRemA")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	orgB, err := tdb.CreateOrg(ctx, "MultiRemB")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgA.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember A: %v", err)
	}
	if err := tdb.CreateOrgMember(ctx, orgB.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember B: %v", err)
	}

	// Org A: allowed=true, days=30. Org B: allowed=true, days=14.
	_, err = tdb.UpdateOrgMFASettings(ctx, orgA.ID, false, true, 30)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings A: %v", err)
	}
	_, err = tdb.UpdateOrgMFASettings(ctx, orgB.ID, false, true, 14)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings B: %v", err)
	}

	allowed, err := tdb.AllUserOrgsAllowRememberDevice(ctx, user.ID)
	if err != nil {
		t.Fatalf("AllUserOrgsAllowRememberDevice: %v", err)
	}
	if !allowed {
		t.Error("expected remember device allowed when both orgs allow it")
	}
	days, err := tdb.MinRememberDeviceDays(ctx, user.ID)
	if err != nil {
		t.Fatalf("MinRememberDeviceDays: %v", err)
	}
	if days != 14 {
		t.Errorf("MinRememberDeviceDays = %d, want 14", days)
	}

	// Update Org B to disallow remember device.
	_, err = tdb.UpdateOrgMFASettings(ctx, orgB.ID, false, false, 14)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings B (disable): %v", err)
	}

	allowed, err = tdb.AllUserOrgsAllowRememberDevice(ctx, user.ID)
	if err != nil {
		t.Fatalf("AllUserOrgsAllowRememberDevice (2): %v", err)
	}
	if allowed {
		t.Error("expected remember device disallowed when one org has it off")
	}
	days, err = tdb.MinRememberDeviceDays(ctx, user.ID)
	if err != nil {
		t.Fatalf("MinRememberDeviceDays (2): %v", err)
	}
	if days != 14 {
		t.Errorf("MinRememberDeviceDays = %d, want 14", days)
	}
}

func TestStore_UserMFARequired_RequiredOrgOwners_NonOwner(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := tdb.CreateOrg(ctx, "NonOwnerOrg")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	user, err := tdb.CreateUser(ctx, "nonowner-mfa@example.com", "NonOwner", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Add user as member, NOT owner.
	if err := tdb.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// RequiredOrgOwners=true but user is not an owner — should return false.
	cfg := store.MFAConfig{RequiredSiteAdmins: false, RequiredOrgOwners: true}
	required, err := tdb.UserMFARequired(ctx, user.ID, false, cfg)
	if err != nil {
		t.Fatalf("UserMFARequired: %v", err)
	}
	if required {
		t.Error("expected MFA NOT required for non-owner with RequiredOrgOwners=true")
	}
}

func TestStore_RecoveryCode_GenerateAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := tdb.CreateUser(ctx, "rc-roundtrip@example.com", "RC Roundtrip", "$argon2id$stub", 2)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	codes, err := tdb.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	// Verify first code.
	ok, remaining, err := tdb.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (first): %v", err)
	}
	if !ok {
		t.Fatal("expected first code verification to succeed")
	}
	if remaining != 9 {
		t.Errorf("remaining after first = %d, want 9", remaining)
	}

	// Verify second code.
	ok, remaining, err = tdb.VerifyRecoveryCode(ctx, user.ID, codes[1])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (second): %v", err)
	}
	if !ok {
		t.Fatal("expected second code verification to succeed")
	}
	if remaining != 8 {
		t.Errorf("remaining after second = %d, want 8", remaining)
	}

	// Verify invalid code.
	ok, remaining, err = tdb.VerifyRecoveryCode(ctx, user.ID, "xxxxx-xxxxx")
	if err != nil {
		t.Fatalf("VerifyRecoveryCode (invalid): %v", err)
	}
	if ok {
		t.Fatal("expected invalid code verification to fail")
	}
	if remaining != 8 {
		t.Errorf("remaining after invalid = %d, want 8", remaining)
	}
}

func TestStore_UpdateOrgMFASettings_OrgNotFound(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	// Non-existent org — should return (nil, nil).
	result, err := tdb.UpdateOrgMFASettings(ctx, uuid.New(), true, true, 30)
	if err != nil {
		t.Fatalf("UpdateOrgMFASettings: unexpected error %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for non-existent org, got %+v", result)
	}
}
