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
	}
	for _, e := range allEvents {
		if _, ok := EventSeverity[e]; !ok {
			t.Errorf("EventSeverity missing entry for %q", e)
		}
	}
	// Verify no extra entries in the map that don't correspond to constants.
	if len(EventSeverity) != len(allEvents) {
		t.Errorf("EventSeverity has %d entries, but there are %d event constants", len(EventSeverity), len(allEvents))
	}
}

func TestEventSeverityValues(t *testing.T) {
	t.Parallel()
	validSeverities := map[string]bool{
		SeverityInfo:     true,
		SeverityWarning:  true,
		SeverityCritical: true,
	}
	for event, severity := range EventSeverity {
		if !validSeverities[severity] {
			t.Errorf("EventSeverity[%q] = %q, not a valid severity level", event, severity)
		}
	}
}
