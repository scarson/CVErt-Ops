# Bug Hunt Report -- Phase 11: MFA (TOTP + Email OTP + Recovery Codes)

## Scope

Analyzed all 28 primary source files for Phase 11 MFA implementation plus adjacent auth/store/crypto code. Read the design doc first, then read every source file in scope -- store layer, API handlers, middleware, JWT, config, notifications, security events, worker, and migration -- before reasoning about correctness.

## Bugs

### 1. Stale token_version in reissued pending token after forced password change

**Location:** internal/api/auth.go:903-904
**Severity:** significant
**Evidence:** When changePasswordHandler runs in restricted mode with remaining pending items (the password_reset followed by mfa_enrollment_required case), it calls UpdatePasswordHash (line 858) which atomically increments token_version in the DB. Then on line 903-904, it reissues the pending token using pendingClaims.TokenVersion -- the OLD value from before the increment.

The reissued pending token tv claim no longer matches users.token_version in the DB. Currently resolveEnrollmentUserID does not validate token_version, so the enrollment step silently proceeds with a stale version. The design doc explicitly states: tv is validated on every step completion; mismatch means reject, force re-login. The implementation contradicts this contract.

**Impact:** The pending token has a stale token_version that does not match the DB. Currently enrollment still works because resolveEnrollmentUserID skips the tv check, but this is a latent correctness bug. If token_version validation is added to the enrollment path (as the design intends), users in the password_reset + mfa_enrollment_required flow would be locked out after changing their password.

**Fix:** After UpdatePasswordHash, re-read the user (or use the returned token version) and pass the new value to IssuePendingToken.

### 2. Incomplete restricted enrollment session -- no full auth tokens on completion

**Location:** internal/api/auth_mfa.go:1216-1236
**Severity:** significant
**Evidence:** clearEnrollmentPending is called when MFA enrollment completes during a restricted session. When all pending items are cleared (e.g., mfa_enrollment_required was the only pending step), the function only clears the pending token cookie and returns -- it never issues full access/refresh tokens. The code acknowledges the problem in a comment.

A user who completes MFA enrollment as their only pending step leaves the flow with no authentication cookies -- they must log in again despite having just proven their identity.

**Impact:** Users completing mfa_enrollment_required as the sole pending step must log in again after enrollment. Poor UX and inconsistent with the mfaVerifyHandler path, which issues full tokens when all pending items are cleared.

**Fix:** Pass the user ID (available from the pending claims) to look up the user object and call issueFullAuthTokens, consistent with how mfaVerifyHandler handles the empty-remaining case.

### 3. Email OTP challenge exhaustion event never emitted

**Location:** internal/api/auth_mfa.go (the verifyEmailOTP call path, lines 191-192 and 408-413) and internal/store/mfa.go:325-364
**Severity:** minor
**Evidence:** The design doc specifies a mfa.challenge_exhausted security event (severity: warning) when 3 failed email OTP attempts invalidated the challenge. The constant EventMFAChallengeExhausted is defined in internal/secure/events.go:25 and registered in the severity map. However, it is never emitted by any handler.

The root cause is that VerifyEmailOTPChallenge in store/mfa.go returns only (bool, error). When max attempts are reached, it deletes the challenge and returns false, nil -- indistinguishable from a normal wrong-code failure. The handler has no way to detect exhaustion vs. a simple mismatch, so it always emits EventMFAVerifyFailed instead.

**Impact:** Security audit gap. Admins monitoring for brute-force MFA attacks will not see the mfa.challenge_exhausted event. The event type exists in the codebase but is dead code.

**Fix:** Have VerifyEmailOTPChallenge return a third value (e.g., exhausted bool) to distinguish exhaustion. Then emit EventMFAChallengeExhausted in the handler when appropriate.

### 4. TOTP replay prevention uses integer division without accounting for skew window

**Location:** internal/api/auth_mfa.go:395-398
**Severity:** minor
**Evidence:** The replay prevention checks cred.LastUsedStep.Int64 >= currentStep where currentStep = now.Unix() / 30. The TOTP validation with Skew: 1 accepts codes from time steps currentStep-1, currentStep, and currentStep+1. If a user submits a code for step currentStep+1 (valid due to skew tolerance), it is accepted, and lastUsedStep is set to currentStep (not currentStep+1). The same code for step currentStep+1 could then be replayed on the next request if now is still in the same 30-second window, because currentStep has not changed and lastUsedStep == currentStep would not block the replay of a code generated for step currentStep+1.

The code stores currentStep as the last_used_step, but the actual accepted step might be currentStep-1 or currentStep+1 due to skew.

**Impact:** Within a narrow window (~30 seconds), a TOTP code generated for a future time step (within skew) could potentially be replayed. The window is small and practical exploitation is unlikely, but the replay prevention does not match the design intent.

**Fix:** Store currentStep+1 (the highest possible accepted step) to guarantee no replay within the acceptance window.

### 5. Admin MFA reset deletes remember-device tokens twice

**Location:** internal/api/admin_mfa.go:63-74
**Severity:** minor
**Evidence:** adminResetMFAHandler calls DeleteAllUserChallenges (line 65) which executes DELETE FROM mfa_challenges WHERE user_id = target -- removing ALL challenges including remember_device tokens. Then on line 70, it separately calls DeleteRememberDeviceTokens. The second call always deletes 0 rows because the first call already removed them.

**Impact:** Redundant DB operation. No data corruption, but the second call is dead code.

## Design Concerns

### Token version validation inconsistency across pending token consumers

The mfaVerifyHandler validates token_version against the DB (line 182-183), but resolveEnrollmentUserID does not. The changePasswordHandler validates the pending token expected step but not its token_version against the DB. This inconsistency means the security guarantee of token_version (detecting admin-forced session invalidation during active challenges) has gaps. The enrollment path is particularly concerning because a pending enrollment token can survive an admin IncrementTokenVersion action, defeating the purpose of session invalidation.

### Non-atomic MFA admin reset

The adminResetMFAHandler performs 5 sequential store operations (delete credentials, delete recovery codes, delete challenges, delete device tokens, increment token version) without a single transaction wrapping them all. If the process crashes between operations, the user could be in an inconsistent state -- e.g., credentials deleted but token_version not incremented, leaving active sessions with MFA bypassed. Each store method uses its own withBypassTx call, so each is individually atomic, but the aggregate operation is not.

### Rate limiting gap on email OTP during enrollment

The mfaEmailOTPSetupHandler applies the same MFAEmailOTPMaxPerHour rate limit as the login challenge flow. The enrollment path shares the same counter as the login challenge path, meaning legitimate login challenges could be blocked by enrollment spam (or vice versa).
