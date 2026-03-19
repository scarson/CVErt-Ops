// ABOUTME: Tests for security event constants — verifies EventSeverity map is exhaustive.
// ABOUTME: Catches any new event constant added without a corresponding severity entry.
package secure

import "testing"

func TestEventSeverityMapIsExhaustive(t *testing.T) {
	t.Parallel()
	allEvents := []string{
		EventAuthLoginFailed,
		EventAuthLoginSuccess,
		EventAuthAccountLocked,
		EventAuthAccountUnlocked,
		EventAuthPasswordResetReq,
		EventAuthPasswordChanged,
		EventAuthTokenReuseDetected,
		EventAuthAPIKeyCreated,
		EventAuthAPIKeyUsedAfterRevoke,
		EventAdminUserDisabled,
		EventAdminConfigReloaded,
		EventAdminBulkRetryTriggered,
		// MFA authentication events
		EventMFAChallengeRequested,
		EventMFAVerifySuccess,
		EventMFAVerifyFailed,
		EventMFAChallengeExhausted,
		EventMFAEmailOTPRateLimited,
		EventMFARememberDeviceIssued,
		EventMFARememberDeviceUsed,
		// Recovery code events
		EventMFARecoveryCodesGenerated,
		EventMFARecoveryCodeUsed,
		EventMFARecoveryCodeFailed,
		// Enrollment/management events
		EventMFAMethodEnrolled,
		EventMFAMethodRemoved,
		EventMFAAllMethodsRemoved,
		EventMFAEnrollmentFailed,
		EventMFADisableBlocked,
		// Admin action events
		EventMFAAdminReset,
		EventMFAAdminRequireMember,
		EventMFAAdminUnrequireMember,
		EventMFAOrgRequireAllEnabled,
		EventMFAOrgRequireAllDisabled,
		EventAuthPasswordResetForced,
		EventAuthPasswordResetForcedCompleted,
		// SCIM provisioning events
		EventSCIMAuthFailed,
		EventSCIMAuthOrgMismatch,
		EventSCIMAuthDisabled,
		EventSCIMTokenCreated,
		EventSCIMTokenRotated,
		EventSCIMUserProvisioned,
		EventSCIMUserDeprovisioned,
		EventSCIMSoleOwnerProtected,
		EventSCIMExemptSuppressed,
		EventSCIMRateLimited,
	}
	for _, e := range allEvents {
		if _, ok := Severity(e); !ok {
			t.Errorf("Severity() missing entry for %q", e)
		}
	}
	// Verify no extra entries in the map that don't correspond to constants.
	if len(eventSeverity) != len(allEvents) {
		t.Errorf("eventSeverity has %d entries, but there are %d event constants", len(eventSeverity), len(allEvents))
	}
}

func TestEventSeverityValues(t *testing.T) {
	t.Parallel()
	validSeverities := map[string]bool{
		SeverityInfo:     true,
		SeverityWarning:  true,
		SeverityCritical: true,
	}
	for event, severity := range eventSeverity {
		if !validSeverities[severity] {
			t.Errorf("Severity(%q) = %q, not a valid severity level", event, severity)
		}
	}
}
