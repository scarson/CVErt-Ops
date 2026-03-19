// ABOUTME: Integration tests for store/alert_rule_channel.go — rule ↔ channel bind/unbind.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestBindChannelToRule_Idempotent(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrg1")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "BindRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "BindChan")

	// First bind.
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule (first): %v", err)
	}

	// Second bind must not error (ON CONFLICT DO NOTHING).
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule (second, idempotent): %v", err)
	}

	// Exactly one row in DB.
	channels, err := s.ListChannelsForRule(ctx, rule.ID, org.ID)
	if err != nil {
		t.Fatalf("ListChannelsForRule: %v", err)
	}
	if len(channels) != 1 {
		t.Errorf("expected 1 bound channel after two idempotent binds, got %d", len(channels))
	}
}

func TestUnbindChannelFromRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrg2")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "UnbindRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "UnbindChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// Confirm it's bound.
	channels, err := s.ListChannelsForRule(ctx, rule.ID, org.ID)
	if err != nil {
		t.Fatalf("ListChannelsForRule (before unbind): %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("expected 1 channel before unbind, got %d", len(channels))
	}

	if err := s.UnbindChannelFromRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("UnbindChannelFromRule: %v", err)
	}

	// Confirm it's gone.
	channels, err = s.ListChannelsForRule(ctx, rule.ID, org.ID)
	if err != nil {
		t.Fatalf("ListChannelsForRule (after unbind): %v", err)
	}
	if len(channels) != 0 {
		t.Errorf("expected 0 channels after unbind, got %d", len(channels))
	}
}

func TestListChannelsForRule_ExcludesSoftDeletedChannels(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrg3")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "SoftDeleteRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "SoftDeleteChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// Soft-delete the channel.
	if err := s.SoftDeleteNotificationChannel(ctx, org.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel: %v", err)
	}

	// The binding row remains but the JOIN on nc.deleted_at IS NULL must filter it out.
	channels, err := s.ListChannelsForRule(ctx, rule.ID, org.ID)
	if err != nil {
		t.Fatalf("ListChannelsForRule (after soft-delete): %v", err)
	}
	if len(channels) != 0 {
		t.Errorf("expected 0 channels after channel soft-delete, got %d", len(channels))
	}
}

func TestListActiveChannelsForFanout_IncludesSecrets(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrg4")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FanoutRule")
	chanID, createdSecret := mustCreateNotificationChannel(t, s, ctx, org.ID, "FanoutChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	rows, err := s.ListActiveChannelsForFanout(ctx, rule.ID, org.ID)
	if err != nil {
		t.Fatalf("ListActiveChannelsForFanout: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 fanout row, got %d", len(rows))
	}

	got := rows[0]
	if got.ID != chanID {
		t.Errorf("ID = %v, want %v", got.ID, chanID)
	}
	if !got.SigningSecret.Valid || got.SigningSecret.String == "" {
		t.Error("SigningSecret is empty in fanout row")
	}
	if got.SigningSecret.String != createdSecret {
		t.Errorf("SigningSecret = %q, want %q", got.SigningSecret.String, createdSecret)
	}
	if got.SigningSecretSecondary.Valid {
		t.Error("SigningSecretSecondary should be NULL on a new channel")
	}
}

func TestListChannelsForRule_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "ARCOrg6a")
	org2 := s.MustCreateOrg(t, ctx, "ARCOrg6b")
	rule := mustCreateAlertRule(t, s, ctx, org1.ID, "CrossOrgRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "CrossOrgChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org1.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// org2 must not see org1's bindings.
	channels, err := s.ListChannelsForRule(ctx, rule.ID, org2.ID)
	if err != nil {
		t.Fatalf("ListChannelsForRule(wrong org): %v", err)
	}
	if len(channels) != 0 {
		t.Errorf("expected 0 channels for wrong org, got %d", len(channels))
	}
}

func TestListActiveChannelsForFanout_ExcludesSoftDeletedChannels(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrg7")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FanoutSoftDeleteRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "FanoutSoftDeleteChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// Soft-delete the channel.
	if err := s.SoftDeleteNotificationChannel(ctx, org.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel: %v", err)
	}

	// Fanout must exclude the soft-deleted channel.
	rows, err := s.ListActiveChannelsForFanout(ctx, rule.ID, org.ID)
	if err != nil {
		t.Fatalf("ListActiveChannelsForFanout (after soft-delete): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 fanout rows after channel soft-delete, got %d", len(rows))
	}
}

func TestChannelRuleBindingExists(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrg5")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ExistsRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ExistsChan")

	// Before binding: must not exist.
	exists, err := s.ChannelRuleBindingExists(ctx, rule.ID, chanID, org.ID)
	if err != nil {
		t.Fatalf("ChannelRuleBindingExists (before bind): %v", err)
	}
	if exists {
		t.Error("expected false before binding")
	}

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// After binding: must exist.
	exists, err = s.ChannelRuleBindingExists(ctx, rule.ID, chanID, org.ID)
	if err != nil {
		t.Fatalf("ChannelRuleBindingExists (after bind): %v", err)
	}
	if !exists {
		t.Error("expected true after binding")
	}
}

func TestBindChannelToRule_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "ARCIsoBindA")
	org2 := s.MustCreateOrg(t, ctx, "ARCIsoBindB")
	rule := mustCreateAlertRule(t, s, ctx, org1.ID, "IsoBindRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "IsoBindChan")

	// org2 must not be able to bind org1's channel to org1's rule.
	err := s.BindChannelToRule(ctx, rule.ID, chanID, org2.ID)
	// RLS should cause a FK violation or silently fail. Either an error or no binding is acceptable.
	if err == nil {
		// If no error, the binding must not exist in org1.
		exists, checkErr := s.ChannelRuleBindingExists(ctx, rule.ID, chanID, org1.ID)
		if checkErr != nil {
			t.Fatalf("ChannelRuleBindingExists: %v", checkErr)
		}
		if exists {
			t.Error("cross-org bind should not create a binding visible to org1")
		}
	}
}

func TestUnbindChannelFromRule_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "ARCIsoUnbindA")
	org2 := s.MustCreateOrg(t, ctx, "ARCIsoUnbindB")
	rule := mustCreateAlertRule(t, s, ctx, org1.ID, "IsoUnbindRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "IsoUnbindChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org1.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// org2 must not be able to unbind org1's binding (silent no-op).
	if err := s.UnbindChannelFromRule(ctx, rule.ID, chanID, org2.ID); err != nil {
		t.Fatalf("UnbindChannelFromRule(wrong org): %v", err)
	}

	// Verify the binding still exists in org1.
	exists, err := s.ChannelRuleBindingExists(ctx, rule.ID, chanID, org1.ID)
	if err != nil {
		t.Fatalf("ChannelRuleBindingExists: %v", err)
	}
	if !exists {
		t.Error("binding should still exist after cross-org unbind attempt")
	}
}

func TestListActiveChannelsForFanout_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "ARCIsoFanoutA")
	org2 := s.MustCreateOrg(t, ctx, "ARCIsoFanoutB")
	rule := mustCreateAlertRule(t, s, ctx, org1.ID, "IsoFanoutRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "IsoFanoutChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org1.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// Verify org1 sees the channel.
	rows, err := s.ListActiveChannelsForFanout(ctx, rule.ID, org1.ID)
	if err != nil {
		t.Fatalf("ListActiveChannelsForFanout(org1): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("org1 should see 1 fanout channel, got %d", len(rows))
	}

	// org2 must not see org1's channels (SQL WHERE filters by orgID).
	rows, err = s.ListActiveChannelsForFanout(ctx, rule.ID, org2.ID)
	if err != nil {
		t.Fatalf("ListActiveChannelsForFanout(wrong org): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 fanout channels for wrong org, got %d", len(rows))
	}
}

func TestChannelRuleBindingExists_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "ARCIsoExistsA")
	org2 := s.MustCreateOrg(t, ctx, "ARCIsoExistsB")
	rule := mustCreateAlertRule(t, s, ctx, org1.ID, "IsoExistsRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "IsoExistsChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org1.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// org2 must not see org1's binding.
	exists, err := s.ChannelRuleBindingExists(ctx, rule.ID, chanID, org2.ID)
	if err != nil {
		t.Fatalf("ChannelRuleBindingExists(wrong org): %v", err)
	}
	if exists {
		t.Error("ChannelRuleBindingExists with wrong org should return false")
	}
}

func TestUnbindChannelFromRule_NoOp(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ARCOrgUnbindNoOp")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "UnbindNoOpRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "UnbindNoOpChan")

	// Unbinding something that was never bound should not error.
	if err := s.UnbindChannelFromRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("UnbindChannelFromRule(never bound): %v", err)
	}
}
