// ABOUTME: Test helpers for notify integration tests — org, alert rule, and channel setup.
// ABOUTME: Mirrors the helpers in internal/store/*_test.go for the notify_test package.
package notify_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// mustCreateAlertRule creates an alert rule or fatals the test.
func mustCreateAlertRule(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) *store.AlertRuleRow {
	t.Helper()
	r, err := s.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       name,
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		Status:     "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule(%q): %v", name, err)
	}
	return r
}

// mustCreateNotificationChannel creates a webhook notification channel or fatals the test.
func mustCreateNotificationChannel(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) (uuid.UUID, string) {
	t.Helper()
	cfg, _ := json.Marshal(map[string]string{"url": "https://example.com/hook"})
	row, secret, err := s.CreateNotificationChannel(ctx, orgID, name, "webhook", json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("CreateNotificationChannel(%q): %v", name, err)
	}
	return row.ID, secret
}
