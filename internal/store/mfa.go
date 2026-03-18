// ABOUTME: Store methods for MFA credential, recovery code, challenge, and requirement operations.
// ABOUTME: Credentials/recovery/challenges use withBypassTx (global); requirements use withOrgTx (RLS).
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateMFACredential inserts a new MFA credential for the given user and method.
// secretEnc should be the encrypted TOTP secret (non-nil for TOTP, nil for email_otp).
func (s *Store) CreateMFACredential(ctx context.Context, userID uuid.UUID, method string, secretEnc []byte) (*generated.MfaCredential, error) {
	var row generated.MfaCredential
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateMFACredential(ctx, generated.CreateMFACredentialParams{
			UserID:    userID,
			Method:    method,
			SecretEnc: secretEnc,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create mfa credential: %w", err)
	}
	return &row, nil
}

// GetMFACredentialsByUserID returns all MFA credentials for a user, ordered by created_at.
func (s *Store) GetMFACredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]generated.MfaCredential, error) {
	var rows []generated.MfaCredential
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rows, err = q.GetMFACredentialsByUserID(ctx, userID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("get mfa credentials by user: %w", err)
	}
	return rows, nil
}

// GetMFACredentialByUserAndMethod returns the credential for a specific user+method,
// or (nil, nil) if not found.
func (s *Store) GetMFACredentialByUserAndMethod(ctx context.Context, userID uuid.UUID, method string) (*generated.MfaCredential, error) {
	var row generated.MfaCredential
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.GetMFACredentialByUserAndMethod(ctx, generated.GetMFACredentialByUserAndMethodParams{
			UserID: userID,
			Method: method,
		})
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mfa credential by user and method: %w", err)
	}
	return &row, nil
}

// UpdateMFACredentialLastUsed records the last used TOTP step counter and timestamp.
func (s *Store) UpdateMFACredentialLastUsed(ctx context.Context, id uuid.UUID, lastUsedStep sql.NullInt64) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpdateMFACredentialLastUsed(ctx, generated.UpdateMFACredentialLastUsedParams{
			ID:           id,
			LastUsedStep: lastUsedStep,
		})
	})
}

// VerifyAndUpdateTOTPStep atomically checks and updates the TOTP last_used_step.
// Uses FOR UPDATE to prevent concurrent replay. Returns true if the step
// is fresh (not replayed). The maxStep parameter should be currentStep + skew
// to account for the TOTP validation window.
func (s *Store) VerifyAndUpdateTOTPStep(ctx context.Context, userID uuid.UUID, maxStep int64) (bool, error) {
	var ok bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		cred, err := q.GetMFACredentialByUserAndMethodForUpdate(ctx, generated.GetMFACredentialByUserAndMethodForUpdateParams{
			UserID: userID,
			Method: "totp",
		})
		if err != nil {
			return err
		}
		if cred.LastUsedStep.Valid && cred.LastUsedStep.Int64 >= maxStep {
			ok = false
			return nil
		}
		if err := q.UpdateMFACredentialLastUsed(ctx, generated.UpdateMFACredentialLastUsedParams{
			ID:           cred.ID,
			LastUsedStep: sql.NullInt64{Int64: maxStep, Valid: true},
		}); err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("verify totp step: %w", err)
	}
	return ok, nil
}

// DeleteMFACredential removes a single MFA credential by user and method.
// Returns the number of rows deleted.
func (s *Store) DeleteMFACredential(ctx context.Context, userID uuid.UUID, method string) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.DeleteMFACredential(ctx, generated.DeleteMFACredentialParams{
			UserID: userID,
			Method: method,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("delete mfa credential: %w", err)
	}
	return n, nil
}

// DeleteAllMFACredentials removes all MFA credentials for a user.
// Returns the number of rows deleted.
func (s *Store) DeleteAllMFACredentials(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.DeleteAllMFACredentials(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("delete all mfa credentials: %w", err)
	}
	return n, nil
}

// UserHasMFACredentials returns true if the user has any enrolled MFA methods.
func (s *Store) UserHasMFACredentials(ctx context.Context, userID uuid.UUID) (bool, error) {
	var has bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		has, err = q.UserHasMFACredentials(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("user has mfa credentials: %w", err)
	}
	return has, nil
}

// CountMFACredentialsByUser returns the number of enrolled MFA methods for a user.
func (s *Store) CountMFACredentialsByUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountMFACredentialsByUser(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count mfa credentials by user: %w", err)
	}
	return n, nil
}

// recoveryCodeCount is the number of recovery codes generated per user.
const recoveryCodeCount = 10

// generateRecoveryCode produces a single recovery code in xxxxx-xxxxx format (a-z0-9).
func generateRecoveryCode() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[idx.Int64()]
	}
	return string(b[:5]) + "-" + string(b[5:]), nil
}

// hashRecoveryCode returns the SHA-256 hex digest of a normalized recovery code.
// Normalization: lowercase, strip dashes — so users can type codes in any format.
func hashRecoveryCode(code string) string {
	normalized := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// GenerateRecoveryCodes creates 10 one-time recovery codes for the user.
// Returns the plaintext codes (shown to the user once); only hashes are stored.
func (s *Store) GenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		codes[i] = code
	}

	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		for _, code := range codes {
			err := q.CreateMFARecoveryCode(ctx, generated.CreateMFARecoveryCodeParams{
				UserID:   userID,
				CodeHash: hashRecoveryCode(code),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("generate recovery codes: %w", err)
	}
	return codes, nil
}

// VerifyRecoveryCode checks a recovery code and marks it used if valid.
// Returns (success, remaining_unused_count, error).
// Uses SELECT FOR UPDATE SKIP LOCKED to prevent concurrent double-consumption.
func (s *Store) VerifyRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) {
	var ok bool
	var remaining int64

	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		h := hashRecoveryCode(code)

		row, err := q.GetUnusedRecoveryCodeByHashForUpdate(ctx, generated.GetUnusedRecoveryCodeByHashForUpdateParams{
			UserID:   userID,
			CodeHash: h,
		})
		if errors.Is(err, sql.ErrNoRows) {
			// Code not found or already used; count remaining and return.
			remaining, err = q.CountUnusedRecoveryCodes(ctx, userID)
			if err != nil {
				return err
			}
			ok = false
			return nil
		}
		if err != nil {
			return err
		}

		// Mark the code as consumed.
		if err := q.MarkRecoveryCodeUsed(ctx, row.ID); err != nil {
			return err
		}

		remaining, err = q.CountUnusedRecoveryCodes(ctx, userID)
		if err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil {
		return false, 0, fmt.Errorf("verify recovery code: %w", err)
	}
	return ok, int(remaining), nil
}

// RegenerateRecoveryCodes deletes all existing codes and generates a fresh set.
// Returns the new plaintext codes.
func (s *Store) RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		codes[i] = code
	}

	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		if _, err := q.DeleteAllRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		for _, code := range codes {
			err := q.CreateMFARecoveryCode(ctx, generated.CreateMFARecoveryCodeParams{
				UserID:   userID,
				CodeHash: hashRecoveryCode(code),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("regenerate recovery codes: %w", err)
	}
	return codes, nil
}

// DeleteAllRecoveryCodes removes all recovery codes for a user.
func (s *Store) DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		_, err := q.DeleteAllRecoveryCodes(ctx, userID)
		return err
	})
}

// CountUnusedRecoveryCodes returns the number of unused recovery codes for a user.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountUnusedRecoveryCodes(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count unused recovery codes: %w", err)
	}
	return n, nil
}

// ResetUserMFA atomically removes all MFA state for a user and increments
// token_version to invalidate all sessions. All operations run in a single
// transaction to prevent inconsistent intermediate states.
func (s *Store) ResetUserMFA(ctx context.Context, userID uuid.UUID) (int32, error) {
	var newVersion int32
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		if _, err := q.DeleteAllMFACredentials(ctx, userID); err != nil {
			return err
		}
		if _, err := q.DeleteAllRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		if _, err := q.DeleteAllUserChallenges(ctx, userID); err != nil {
			return err
		}
		var err error
		newVersion, err = q.IncrementTokenVersion(ctx, userID)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("reset user mfa: %w", err)
	}
	return newVersion, nil
}

// --- MFA Challenge Operations (Email OTP + Remember Device) ---

// CreateEmailOTPChallenge stores a new email OTP challenge for the user.
// Deletes any existing email OTP challenge first to enforce single-active-code.
func (s *Store) CreateEmailOTPChallenge(ctx context.Context, userID uuid.UUID, codeHash string, expiresAt time.Time) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		if _, err := q.DeleteEmailOTPChallenges(ctx, userID); err != nil {
			return err
		}
		_, err := q.CreateMFAChallenge(ctx, generated.CreateMFAChallengeParams{
			UserID:        userID,
			ChallengeType: "email_otp",
			TokenHash:     codeHash,
			ExpiresAt:     expiresAt,
		})
		return err
	})
}

// VerifyEmailOTPChallenge atomically looks up the active email OTP challenge,
// increments attempts, checks the hash, and deletes on success or exhaustion.
// Returns matched=true if the code was correct, exhausted=true if max attempts
// were reached (challenge deleted).
func (s *Store) VerifyEmailOTPChallenge(ctx context.Context, userID uuid.UUID, codeHash string, maxAttempts int32) (matched bool, exhausted bool, err error) {
	err = s.withBypassTx(ctx, func(q *generated.Queries) error {
		challenge, err := q.GetActiveEmailOTPChallengeForUpdate(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}

		attempts, err := q.IncrementChallengeAttempts(ctx, challenge.ID)
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(challenge.TokenHash), []byte(codeHash)) == 1 {
			// Correct code — delete the challenge and report success.
			if err := q.DeleteChallenge(ctx, challenge.ID); err != nil {
				return err
			}
			matched = true
			return nil
		}

		// Wrong code — delete if max attempts reached.
		if attempts >= maxAttempts {
			if err := q.DeleteChallenge(ctx, challenge.ID); err != nil {
				return err
			}
			exhausted = true
		}
		return nil
	})
	if err != nil {
		return false, false, fmt.Errorf("verify email otp challenge: %w", err)
	}
	return matched, exhausted, nil
}

// CreateRememberDeviceToken stores a remember-device token for the user.
func (s *Store) CreateRememberDeviceToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		_, err := q.CreateMFAChallenge(ctx, generated.CreateMFAChallengeParams{
			UserID:        userID,
			ChallengeType: "remember_device",
			TokenHash:     tokenHash,
			ExpiresAt:     expiresAt,
		})
		return err
	})
}

// ValidateRememberDeviceToken checks whether a valid (non-expired) remember-device
// token exists for the given user and token hash.
func (s *Store) ValidateRememberDeviceToken(ctx context.Context, userID uuid.UUID, tokenHash string) (bool, error) {
	var valid bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		_, err := q.GetRememberDeviceToken(ctx, generated.GetRememberDeviceTokenParams{
			UserID:    userID,
			TokenHash: tokenHash,
		})
		if errors.Is(err, sql.ErrNoRows) {
			valid = false
			return nil
		}
		if err != nil {
			return err
		}
		valid = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("validate remember device token: %w", err)
	}
	return valid, nil
}

// DeleteRememberDeviceTokens removes all remember-device tokens for a user.
func (s *Store) DeleteRememberDeviceTokens(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		_, err := q.DeleteRememberDeviceTokens(ctx, userID)
		return err
	})
}

// DeleteAllUserChallenges removes all challenges (email OTP + remember-device) for a user.
func (s *Store) DeleteAllUserChallenges(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		_, err := q.DeleteAllUserChallenges(ctx, userID)
		return err
	})
}

// CountRecentEmailOTPChallenges returns the number of email OTP challenges created
// after the given timestamp, for rate limiting.
func (s *Store) CountRecentEmailOTPChallenges(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountRecentEmailOTPChallenges(ctx, generated.CountRecentEmailOTPChallengesParams{
			UserID:    userID,
			CreatedAt: since,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count recent email otp challenges: %w", err)
	}
	return n, nil
}

// DeleteExpiredChallenges removes all challenges past their expiry time.
// Returns the number of rows deleted.
func (s *Store) DeleteExpiredChallenges(ctx context.Context) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.DeleteExpiredChallenges(ctx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("delete expired challenges: %w", err)
	}
	return n, nil
}

// --- MFA Requirement Operations (Org-Scoped, RLS) ---

// CreateMFARequirement adds a per-member MFA mandate within an org.
// Idempotent: ON CONFLICT DO NOTHING if the requirement already exists.
func (s *Store) CreateMFARequirement(ctx context.Context, orgID, userID, requiredByID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.CreateMFARequirement(ctx, generated.CreateMFARequirementParams{
			OrgID:      orgID,
			UserID:     userID,
			RequiredBy: uuid.NullUUID{UUID: requiredByID, Valid: true},
		})
	})
}

// DeleteMFARequirement removes the MFA mandate for a user in an org.
func (s *Store) DeleteMFARequirement(ctx context.Context, orgID, userID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		_, err := q.DeleteMFARequirement(ctx, generated.DeleteMFARequirementParams{
			OrgID:  orgID,
			UserID: userID,
		})
		return err
	})
}

// GetMFARequirementsByOrg returns all MFA requirements for an org, ordered by created_at.
func (s *Store) GetMFARequirementsByOrg(ctx context.Context, orgID uuid.UUID) ([]generated.MfaRequirement, error) {
	var rows []generated.MfaRequirement
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.GetMFARequirementsByOrg(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("get mfa requirements by org: %w", err)
	}
	return rows, nil
}

// UserHasMFARequirement checks whether a user has an MFA requirement in any org.
// Uses withBypassTx for login-time cross-org checks.
func (s *Store) UserHasMFARequirement(ctx context.Context, userID uuid.UUID) (bool, error) {
	var has bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		has, err = q.UserHasMFARequirement(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("user has mfa requirement: %w", err)
	}
	return has, nil
}

// UserInMFARequiredOrg checks whether a user belongs to any org with mfa_required_all=true.
// Uses withBypassTx for login-time cross-org checks.
func (s *Store) UserInMFARequiredOrg(ctx context.Context, userID uuid.UUID) (bool, error) {
	var required bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		required, err = q.UserInMFARequiredOrg(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("user in mfa required org: %w", err)
	}
	return required, nil
}

// MFAConfig holds the site-level config fields needed for the mandate check.
type MFAConfig struct {
	RequiredSiteAdmins bool
	RequiredOrgOwners  bool
}

// UserMFARequired checks all three enforcement layers to determine if this user
// must have MFA. Runs at login time under withBypassTx (cross-org queries).
// The isSiteAdmin flag is passed in by the caller — this function does not query
// the users table.
func (s *Store) UserMFARequired(ctx context.Context, userID uuid.UUID, isSiteAdmin bool, cfg MFAConfig) (bool, error) {
	// Layer 1: site config — site admins must have MFA.
	if cfg.RequiredSiteAdmins && isSiteAdmin {
		return true, nil
	}

	// Layer 2a: site config — org owners must have MFA.
	if cfg.RequiredOrgOwners {
		isOwner, err := s.IsOrgOwner(ctx, userID)
		if err != nil {
			return false, fmt.Errorf("check org owner: %w", err)
		}
		if isOwner {
			return true, nil
		}
	}

	// Layer 2b: org-wide MFA requirement.
	inRequiredOrg, err := s.UserInMFARequiredOrg(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("check org-wide mfa: %w", err)
	}
	if inRequiredOrg {
		return true, nil
	}

	// Layer 3: per-member MFA requirement.
	hasReq, err := s.UserHasMFARequirement(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("check per-member mfa: %w", err)
	}
	return hasReq, nil
}

// IsOrgOwner checks whether a user has the 'owner' role in any org.
func (s *Store) IsOrgOwner(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isOwner bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		isOwner, err = q.IsOrgOwner(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("is org owner: %w", err)
	}
	return isOwner, nil
}

// AllUserOrgsAllowRememberDevice checks whether all orgs the user belongs to
// allow remember-device tokens. If any org disallows, returns false.
func (s *Store) AllUserOrgsAllowRememberDevice(ctx context.Context, userID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		allowed, err = q.AllUserOrgsAllowRememberDevice(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("all orgs allow remember device: %w", err)
	}
	return allowed, nil
}

// MinRememberDeviceDays returns the minimum remember-device retention days
// across all orgs the user belongs to. Uses most-restrictive org setting.
func (s *Store) MinRememberDeviceDays(ctx context.Context, userID uuid.UUID) (int32, error) {
	var days int32
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		days, err = q.MinRememberDeviceDays(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("min remember device days: %w", err)
	}
	return days, nil
}
