// ABOUTME: Integration tests for store/notification_channel.go — channel CRUD and secret rotation.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// webhookConfig returns a minimal valid webhook config JSON for test channels.
func webhookConfig(url string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"url": url})
	return b
}

// mustCreateNotificationChannel creates a notification channel or fatals the test.
func mustCreateNotificationChannel(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) (uuid.UUID, string) {
	t.Helper()
	row, secret, err := s.CreateNotificationChannel(ctx, orgID, name, "webhook", webhookConfig("https://example.com/hook"))
	if err != nil {
		t.Fatalf("CreateNotificationChannel(%q): %v", name, err)
	}
	return row.ID, secret
}

func TestCreateNotificationChannel_SecretGenerated(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg1")

	row, secret, err := s.CreateNotificationChannel(ctx, org.ID, "MyChannel", "webhook", webhookConfig("https://example.com/hook"))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	if row == nil {
		t.Fatal("CreateNotificationChannel returned nil row")
	}
	if row.Name != "MyChannel" {
		t.Errorf("Name = %q, want MyChannel", row.Name)
	}
	if row.Type != "webhook" {
		t.Errorf("Type = %q, want webhook", row.Type)
	}

	// Secret must be non-empty and valid hex.
	if secret == "" {
		t.Fatal("secret is empty")
	}
	b, err := hex.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret is not valid hex: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("secret decoded length = %d, want 32 bytes", len(b))
	}

	// GetNotificationChannel must NOT return the signing secret.
	got, err := s.GetNotificationChannel(ctx, org.ID, row.ID)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if got == nil {
		t.Fatal("GetNotificationChannel returned nil for existing channel")
	}
	if got.ID != row.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, row.ID)
	}
	// The GetNotificationChannelRow struct has no signing_secret field — verified at compile time.
	// Confirm the OrgID is set correctly.
	if got.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", got.OrgID, org.ID)
	}
}

func TestGetNotificationChannelForDelivery_IncludesSecrets(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg2")
	chanID, createdSecret := mustCreateNotificationChannel(t, s, ctx, org.ID, "DeliveryChannel")

	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery: %v", err)
	}
	if got == nil {
		t.Fatal("GetNotificationChannelForDelivery returned nil for existing channel")
	}
	if !got.SigningSecret.Valid || got.SigningSecret.String == "" {
		t.Error("SigningSecret is empty in delivery row")
	}
	if got.SigningSecret.String != createdSecret {
		t.Errorf("SigningSecret = %q, want %q", got.SigningSecret.String, createdSecret)
	}
	if got.SigningSecretSecondary.Valid {
		t.Error("SigningSecretSecondary should be NULL on a new channel")
	}
}

func TestSoftDeleteNotificationChannel(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg3")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ToDelete")

	// Verify it shows up in the list before deletion.
	list, err := s.ListNotificationChannels(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListNotificationChannels (before delete): %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list before delete: got %d channels, want 1", len(list))
	}

	if err := s.SoftDeleteNotificationChannel(ctx, org.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel: %v", err)
	}

	// GetNotificationChannel should return nil after soft-delete.
	got, err := s.GetNotificationChannel(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannel (after delete): %v", err)
	}
	if got != nil {
		t.Error("GetNotificationChannel should return nil for soft-deleted channel")
	}

	// Channel should be gone from the list.
	list, err = s.ListNotificationChannels(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListNotificationChannels (after delete): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("list after delete: got %d channels, want 0", len(list))
	}
}

func TestRotateSigningSecret_MovesSecrets(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg4")
	chanID, originalSecret := mustCreateNotificationChannel(t, s, ctx, org.ID, "RotateChannel")

	// Rotate: old primary → secondary, new primary returned.
	newPrimary, err := s.RotateSigningSecret(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("RotateSigningSecret: %v", err)
	}
	if newPrimary == "" {
		t.Fatal("RotateSigningSecret returned empty secret")
	}
	if newPrimary == originalSecret {
		t.Error("new primary should differ from the original secret")
	}

	// Verify via GetNotificationChannelForDelivery that rotation was applied correctly.
	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery after rotate: %v", err)
	}
	if got == nil {
		t.Fatal("GetNotificationChannelForDelivery returned nil after rotate")
	}
	if got.SigningSecret.String != newPrimary {
		t.Errorf("primary after rotate = %q, want %q", got.SigningSecret.String, newPrimary)
	}
	if !got.SigningSecretSecondary.Valid {
		t.Fatal("secondary should be set after rotation")
	}
	if got.SigningSecretSecondary.String != originalSecret {
		t.Errorf("secondary after rotate = %q, want original %q", got.SigningSecretSecondary.String, originalSecret)
	}
}

func TestUpdateNotificationChannel(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg5")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "Original")

	updated, err := s.UpdateNotificationChannel(ctx, org.ID, chanID, store.UpdateNotificationChannelParams{
		Name:   "Renamed",
		Config: webhookConfig("https://example.com/new-hook"),
	})
	if err != nil {
		t.Fatalf("UpdateNotificationChannel: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateNotificationChannel returned nil")
	}
	if updated.Name != "Renamed" {
		t.Errorf("Name = %q, want Renamed", updated.Name)
	}
}

func TestChannelHasActiveBoundRules_NoRules(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg6")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "Unbound")

	has, err := s.ChannelHasActiveBoundRules(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundRules: %v", err)
	}
	if has {
		t.Error("expected false for channel with no bound rules")
	}
}

func TestClearSecondarySecret(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg8")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ClearSecondaryChannel")

	// Rotate to populate the secondary secret.
	_, err := s.RotateSigningSecret(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("RotateSigningSecret: %v", err)
	}

	// Verify secondary is non-null after rotation.
	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery after rotate: %v", err)
	}
	if got == nil {
		t.Fatal("GetNotificationChannelForDelivery returned nil after rotate")
	}
	if !got.SigningSecretSecondary.Valid {
		t.Fatal("secondary should be set after rotation")
	}

	// Clear the secondary secret.
	if err := s.ClearSecondarySecret(ctx, org.ID, chanID); err != nil {
		t.Fatalf("ClearSecondarySecret: %v", err)
	}

	// Verify secondary is NULL after clearing.
	got, err = s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery after clear: %v", err)
	}
	if got == nil {
		t.Fatal("GetNotificationChannelForDelivery returned nil after clear")
	}
	if got.SigningSecretSecondary.Valid {
		t.Error("secondary should be NULL after ClearSecondarySecret")
	}
}

func TestChannelHasActiveBoundRules_WithActiveRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrg9")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "BoundChannel")

	// Create an alert rule and set it to active.
	rule, err := s.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:       "ActiveBoundRule",
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		Status:     "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if err := s.SetAlertRuleStatus(ctx, org.ID, rule.ID, "active"); err != nil {
		t.Fatalf("SetAlertRuleStatus: %v", err)
	}

	// Bind the channel to the rule via raw SQL (no store method yet for this binding).
	_, err = s.DB().ExecContext(ctx,
		`INSERT INTO alert_rule_channels (rule_id, channel_id, org_id) VALUES ($1, $2, $3)`,
		rule.ID, chanID, org.ID)
	if err != nil {
		t.Fatalf("INSERT alert_rule_channels: %v", err)
	}

	has, err := s.ChannelHasActiveBoundRules(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundRules: %v", err)
	}
	if !has {
		t.Error("expected true for channel bound to an active rule")
	}
}

func TestGetNotificationChannel_WrongOrgReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCOrg7a")
	org2, _ := s.CreateOrg(ctx, "NCOrg7b")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1Channel")

	got, err := s.GetNotificationChannel(ctx, org2.ID, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannel(wrong org): %v", err)
	}
	if got != nil {
		t.Error("GetNotificationChannel with wrong org should return nil")
	}
}

func TestListNotificationChannels_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCIsoListA")
	org2, _ := s.CreateOrg(ctx, "NCIsoListB")
	mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1OnlyChan")

	// org2 must not see org1's channels.
	list, err := s.ListNotificationChannels(ctx, org2.ID)
	if err != nil {
		t.Fatalf("ListNotificationChannels(wrong org): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 channels for wrong org, got %d", len(list))
	}
}

func TestUpdateNotificationChannel_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCIsoUpdateA")
	org2, _ := s.CreateOrg(ctx, "NCIsoUpdateB")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1UpdateChan")

	// org2 must not be able to update org1's channel.
	result, err := s.UpdateNotificationChannel(ctx, org2.ID, chanID, store.UpdateNotificationChannelParams{
		Name:   "Hijacked",
		Config: webhookConfig("https://evil.com/hook"),
	})
	if err != nil {
		t.Fatalf("UpdateNotificationChannel(wrong org): %v", err)
	}
	if result != nil {
		t.Error("UpdateNotificationChannel with wrong org should return nil")
	}

	// Verify the channel name is unchanged.
	got, err := s.GetNotificationChannel(ctx, org1.ID, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if got == nil {
		t.Fatal("channel should still exist in org1")
	}
	if got.Name != "Org1UpdateChan" {
		t.Errorf("Name = %q, want Org1UpdateChan (should be unchanged)", got.Name)
	}
}

func TestSoftDeleteNotificationChannel_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCIsoDelA")
	org2, _ := s.CreateOrg(ctx, "NCIsoDelB")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1DeleteChan")

	// org2 must not be able to delete org1's channel (silent no-op).
	if err := s.SoftDeleteNotificationChannel(ctx, org2.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel(wrong org): %v", err)
	}

	// Verify the channel still exists in org1.
	got, err := s.GetNotificationChannel(ctx, org1.ID, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if got == nil {
		t.Error("channel should still exist in org1 after cross-org delete attempt")
	}
}

func TestRotateSigningSecret_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCIsoRotateA")
	org2, _ := s.CreateOrg(ctx, "NCIsoRotateB")
	chanID, originalSecret := mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1RotateChan")

	// org2 must not be able to rotate org1's secret.
	result, err := s.RotateSigningSecret(ctx, org2.ID, chanID)
	if err != nil {
		t.Fatalf("RotateSigningSecret(wrong org): %v", err)
	}
	if result != "" {
		t.Error("RotateSigningSecret with wrong org should return empty string")
	}

	// Verify the secret is unchanged.
	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery: %v", err)
	}
	if got == nil {
		t.Fatal("channel should still exist")
	}
	if got.SigningSecret.String != originalSecret {
		t.Error("signing secret should be unchanged after cross-org rotate attempt")
	}
}

func TestClearSecondarySecret_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCIsoClearA")
	org2, _ := s.CreateOrg(ctx, "NCIsoClearB")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1ClearChan")

	// Rotate to populate secondary.
	if _, err := s.RotateSigningSecret(ctx, org1.ID, chanID); err != nil {
		t.Fatalf("RotateSigningSecret: %v", err)
	}

	// org2 must not be able to clear org1's secondary secret.
	if err := s.ClearSecondarySecret(ctx, org2.ID, chanID); err != nil {
		t.Fatalf("ClearSecondarySecret(wrong org): %v", err)
	}

	// Verify the secondary secret is still present.
	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery: %v", err)
	}
	if got == nil {
		t.Fatal("channel should still exist")
	}
	if !got.SigningSecretSecondary.Valid {
		t.Error("secondary secret should still be set after cross-org clear attempt")
	}
}

func TestChannelHasActiveBoundRules_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "NCIsoHasRulesA")
	org2, _ := s.CreateOrg(ctx, "NCIsoHasRulesB")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "Org1HasRulesChan")

	// Create an active rule and bind the channel in org1.
	rule, err := s.CreateAlertRule(ctx, org1.ID, store.CreateAlertRuleParams{
		Name:       "IsoHasRulesRule",
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		Status:     "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if err := s.SetAlertRuleStatus(ctx, org1.ID, rule.ID, "active"); err != nil {
		t.Fatalf("SetAlertRuleStatus: %v", err)
	}
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org1.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// org2 must not see org1's bindings.
	has, err := s.ChannelHasActiveBoundRules(ctx, org2.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundRules(wrong org): %v", err)
	}
	if has {
		t.Error("ChannelHasActiveBoundRules with wrong org should return false")
	}
}

func TestGetNotificationChannelForDelivery_NotFoundReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Non-existent ID should return (nil, nil).
	got, err := s.GetNotificationChannelForDelivery(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery(nonexistent): %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent channel ID")
	}
}

func TestGetNotificationChannelForDelivery_SoftDeletedReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCIsoBypassSDOrg")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "BypassSoftDeleteChan")

	if err := s.SoftDeleteNotificationChannel(ctx, org.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel: %v", err)
	}

	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery(soft-deleted): %v", err)
	}
	if got != nil {
		t.Error("expected nil for soft-deleted channel")
	}
}

func TestGetNotificationChannelForDelivery_BypassRLSWorks(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCIsoBypassOrg")
	chanID, createdSecret := mustCreateNotificationChannel(t, s, ctx, org.ID, "BypassChan")

	// GetNotificationChannelForDelivery uses bypassTx — no orgID required.
	got, err := s.GetNotificationChannelForDelivery(ctx, chanID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil channel from bypass path")
	}
	if got.SigningSecret.String != createdSecret {
		t.Errorf("signing secret mismatch: got %q, want %q", got.SigningSecret.String, createdSecret)
	}
}

func TestCreateNotificationChannel_EmailType_NoSecret(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "NCOrgEmail1")

	emailCfg, _ := json.Marshal(map[string]any{
		"recipients": []string{"test@example.com"},
	})
	row, secret, err := s.CreateNotificationChannel(ctx, org.ID, "EmailChan", "email", emailCfg)
	if err != nil {
		t.Fatalf("CreateNotificationChannel(email): %v", err)
	}
	if row == nil {
		t.Fatal("CreateNotificationChannel returned nil row for email")
	}
	if row.Type != "email" {
		t.Errorf("Type = %q, want email", row.Type)
	}
	if secret != "" {
		t.Errorf("email channel should return empty secret, got %q", secret)
	}

	// Verify signing_secret is NULL in DB.
	got, err := s.GetNotificationChannelForDelivery(ctx, row.ID)
	if err != nil {
		t.Fatalf("GetNotificationChannelForDelivery: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil channel")
	}
	if got.SigningSecret.Valid {
		t.Error("email channel should have NULL signing_secret")
	}
}
