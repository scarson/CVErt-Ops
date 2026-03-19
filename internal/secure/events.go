// ABOUTME: Central registry of security event type constants for the security event pipeline.
// ABOUTME: Used by security event writers, Prometheus metric labels, and admin API filters.
package secure

// Security event type constants. These are the canonical values stored in
// security_events.event_type and used as Prometheus metric labels.
const (
	EventAuthLoginFailed           = "auth.login_failed"
	EventAuthLoginSuccess          = "auth.login_success"
	EventAuthAccountLocked         = "auth.account_locked"
	EventAuthAccountUnlocked       = "auth.account_unlocked"
	EventAuthPasswordResetReq      = "auth.password_reset_requested"
	EventAuthPasswordChanged       = "auth.password_changed"
	EventAuthTokenReuseDetected    = "auth.token_reuse_detected"          //nolint:gosec // G101 false positive: event type label, not a credential
	EventAuthAPIKeyCreated         = "auth.api_key_created"               //nolint:gosec // G101 false positive: event type label, not a credential
	EventAuthAPIKeyUsedAfterRevoke = "auth.api_key_used_after_revocation" //nolint:gosec // G101 false positive: event type label, not a credential
	EventAdminUserDisabled         = "admin.user_disabled"
	EventAdminConfigReloaded       = "admin.config_reloaded"
	EventAdminBulkRetryTriggered   = "admin.bulk_retry_triggered"

	// MFA authentication events
	EventMFAChallengeRequested   = "mfa.challenge_requested"
	EventMFAVerifySuccess        = "mfa.verify_success"
	EventMFAVerifyFailed         = "mfa.verify_failed"
	EventMFAChallengeExhausted   = "mfa.challenge_exhausted"
	EventMFAEmailOTPRateLimited  = "mfa.email_otp_rate_limited"
	EventMFARememberDeviceIssued = "mfa.remember_device_issued"
	EventMFARememberDeviceUsed   = "mfa.remember_device_used"

	// Recovery code events
	EventMFARecoveryCodesGenerated = "mfa.recovery_codes_generated"
	EventMFARecoveryCodeUsed       = "mfa.recovery_code_used"
	EventMFARecoveryCodeFailed     = "mfa.recovery_code_failed"

	// Enrollment/management events
	EventMFAMethodEnrolled    = "mfa.method_enrolled"
	EventMFAMethodRemoved     = "mfa.method_removed"
	EventMFAAllMethodsRemoved = "mfa.all_methods_removed"
	EventMFAEnrollmentFailed  = "mfa.enrollment_failed"
	EventMFADisableBlocked    = "mfa.disable_blocked"

	// Admin action events
	EventMFAAdminReset                    = "mfa.admin_reset"
	EventMFAAdminRequireMember            = "mfa.admin_require_member"
	EventMFAAdminUnrequireMember          = "mfa.admin_unrequire_member"
	EventMFAOrgRequireAllEnabled          = "mfa.org_require_all_enabled"
	EventMFAOrgRequireAllDisabled         = "mfa.org_require_all_disabled"
	EventAuthPasswordResetForced          = "auth.password_reset_forced"
	EventAuthPasswordResetForcedCompleted = "auth.password_reset_forced_completed"

	// SCIM provisioning events
	EventSCIMAuthFailed      = "scim.auth_failed"
	EventSCIMAuthOrgMismatch = "scim.auth_org_mismatch"
	EventSCIMAuthDisabled    = "scim.auth_disabled"
	EventSCIMRateLimited     = "scim.rate_limited"
)

// Severity levels for security events.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// eventSeverity maps each event type to its default severity level.
var eventSeverity = map[string]string{
	EventAuthLoginFailed:                  SeverityInfo,
	EventAuthLoginSuccess:                 SeverityInfo,
	EventAuthAccountLocked:                SeverityWarning,
	EventAuthAccountUnlocked:              SeverityInfo,
	EventAuthPasswordResetReq:             SeverityInfo,
	EventAuthPasswordChanged:              SeverityInfo,
	EventAuthTokenReuseDetected:           SeverityCritical,
	EventAuthAPIKeyCreated:                SeverityInfo,
	EventAuthAPIKeyUsedAfterRevoke:        SeverityWarning,
	EventAdminUserDisabled:                SeverityWarning,
	EventAdminConfigReloaded:              SeverityInfo,
	EventAdminBulkRetryTriggered:          SeverityInfo,
	EventMFAChallengeRequested:            SeverityInfo,
	EventMFAVerifySuccess:                 SeverityInfo,
	EventMFAVerifyFailed:                  SeverityWarning,
	EventMFAChallengeExhausted:            SeverityWarning,
	EventMFAEmailOTPRateLimited:           SeverityWarning,
	EventMFARememberDeviceIssued:          SeverityInfo,
	EventMFARememberDeviceUsed:            SeverityInfo,
	EventMFARecoveryCodesGenerated:        SeverityInfo,
	EventMFARecoveryCodeUsed:              SeverityWarning,
	EventMFARecoveryCodeFailed:            SeverityWarning,
	EventMFAMethodEnrolled:                SeverityInfo,
	EventMFAMethodRemoved:                 SeverityInfo,
	EventMFAAllMethodsRemoved:             SeverityWarning,
	EventMFAEnrollmentFailed:              SeverityWarning,
	EventMFADisableBlocked:                SeverityWarning,
	EventMFAAdminReset:                    SeverityCritical,
	EventMFAAdminRequireMember:            SeverityInfo,
	EventMFAAdminUnrequireMember:          SeverityInfo,
	EventMFAOrgRequireAllEnabled:          SeverityInfo,
	EventMFAOrgRequireAllDisabled:         SeverityWarning,
	EventAuthPasswordResetForced:          SeverityCritical,
	EventAuthPasswordResetForcedCompleted: SeverityInfo,
	EventSCIMAuthFailed:                   SeverityWarning,
	EventSCIMAuthOrgMismatch:              SeverityCritical,
	EventSCIMAuthDisabled:                 SeverityWarning,
	EventSCIMRateLimited:                  SeverityWarning,
}

// Severity returns the default severity level for the given event type.
func Severity(eventType string) (string, bool) {
	s, ok := eventSeverity[eventType]
	return s, ok
}
