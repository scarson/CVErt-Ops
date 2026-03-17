// ABOUTME: Integration tests for MFA credential and recovery code store methods.
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

	ok, err := s.VerifyEmailOTPChallenge(ctx, user.ID, codeHash, 3)
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
	ok, err := s.VerifyEmailOTPChallenge(ctx, user.ID, code1, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (old): %v", err)
	}
	if ok {
		t.Error("expected old code to fail after new code created")
	}

	// New code should succeed.
	ok, err = s.VerifyEmailOTPChallenge(ctx, user.ID, code2, 3)
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

	ok, err := s.VerifyEmailOTPChallenge(ctx, user.ID, code, 3)
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
		ok, err := s.VerifyEmailOTPChallenge(ctx, user.ID, wrongHash, 3)
		if err != nil {
			t.Fatalf("VerifyEmailOTPChallenge (wrong %d): %v", i+1, err)
		}
		if ok {
			t.Errorf("wrong attempt %d should fail", i+1)
		}
	}

	// Now even the correct code should fail — challenge deleted after max attempts.
	ok, err := s.VerifyEmailOTPChallenge(ctx, user.ID, correctHash, 3)
	if err != nil {
		t.Fatalf("VerifyEmailOTPChallenge (correct after exhaust): %v", err)
	}
	if ok {
		t.Error("expected correct code to fail after attempt exhaustion")
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
	ok, err := s.VerifyEmailOTPChallenge(ctx, user2.ID, validHash, 3)
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
			ok, verifyErr := s.VerifyEmailOTPChallenge(ctx, user.ID, codeHash, 3)
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
