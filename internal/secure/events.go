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
	EventAuthTokenReuseDetected    = "auth.token_reuse_detected"
	EventAuthAPIKeyCreated         = "auth.api_key_created"
	EventAuthAPIKeyUsedAfterRevoke = "auth.api_key_used_after_revocation"
	EventAdminUserDisabled         = "admin.user_disabled"
	EventAdminConfigReloaded       = "admin.config_reloaded"
	EventAdminBulkRetryTriggered   = "admin.bulk_retry_triggered"
)

// Severity levels for security events.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// eventSeverity maps each event type to its default severity level.
var eventSeverity = map[string]string{
	EventAuthLoginFailed:           SeverityInfo,
	EventAuthLoginSuccess:          SeverityInfo,
	EventAuthAccountLocked:         SeverityWarning,
	EventAuthAccountUnlocked:       SeverityInfo,
	EventAuthPasswordResetReq:      SeverityInfo,
	EventAuthPasswordChanged:       SeverityInfo,
	EventAuthTokenReuseDetected:    SeverityCritical,
	EventAuthAPIKeyCreated:         SeverityInfo,
	EventAuthAPIKeyUsedAfterRevoke: SeverityWarning,
	EventAdminUserDisabled:         SeverityWarning,
	EventAdminConfigReloaded:       SeverityInfo,
	EventAdminBulkRetryTriggered:   SeverityInfo,
}

// Severity returns the default severity level for the given event type.
func Severity(eventType string) (string, bool) {
	s, ok := eventSeverity[eventType]
	return s, ok
}
