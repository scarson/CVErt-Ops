// ABOUTME: Integration tests for store/report_channel.go — report ↔ channel M:M binding ops.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestBindChannelToReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg1")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "BindReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "BindChan")

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}

	// Idempotent: second bind should not error.
	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport (idempotent): %v", err)
	}

	exists, err := s.ReportChannelBindingExists(ctx, org.ID, report.ID, chanID)
	if err != nil {
		t.Fatalf("ReportChannelBindingExists: %v", err)
	}
	if !exists {
		t.Error("expected binding to exist")
	}
}

func TestUnbindChannelFromReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg2")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "UnbindReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "UnbindChan")

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}
	if err := s.UnbindChannelFromReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("UnbindChannelFromReport: %v", err)
	}

	exists, err := s.ReportChannelBindingExists(ctx, org.ID, report.ID, chanID)
	if err != nil {
		t.Fatalf("ReportChannelBindingExists: %v", err)
	}
	if exists {
		t.Error("expected binding to not exist after unbind")
	}
}

func TestListChannelsForReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg3")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "ListReport")
	chanID1, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ListChan1")
	chanID2, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ListChan2")

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID1); err != nil {
		t.Fatalf("BindChannelToReport 1: %v", err)
	}
	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID2); err != nil {
		t.Fatalf("BindChannelToReport 2: %v", err)
	}

	list, err := s.ListChannelsForReport(ctx, org.ID, report.ID)
	if err != nil {
		t.Fatalf("ListChannelsForReport: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 channels, got %d", len(list))
	}
}

func TestListChannelsForReport_ExcludesDeleted(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg4")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "DelChanReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "DelChan")

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}
	// Soft-delete the channel.
	if err := s.SoftDeleteNotificationChannel(ctx, org.ID, chanID); err != nil {
		t.Fatalf("SoftDeleteNotificationChannel: %v", err)
	}

	list, err := s.ListChannelsForReport(ctx, org.ID, report.ID)
	if err != nil {
		t.Fatalf("ListChannelsForReport: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 channels after soft-delete, got %d", len(list))
	}
}

func TestListActiveChannelsForDigest(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg5")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "DigestReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "DigestChan")

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}

	list, err := s.ListActiveChannelsForDigest(ctx, org.ID, report.ID)
	if err != nil {
		t.Fatalf("ListActiveChannelsForDigest: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(list))
	}
	if list[0].ID != chanID {
		t.Errorf("channel ID = %v, want %v", list[0].ID, chanID)
	}
	// Config should be valid JSON.
	if !json.Valid(list[0].Config) {
		t.Error("config is not valid JSON")
	}
}

func TestReportChannelBindingExists_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg6")

	exists, err := s.ReportChannelBindingExists(ctx, org.ID, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("ReportChannelBindingExists: %v", err)
	}
	if exists {
		t.Error("expected false for nonexistent binding")
	}
}

func TestChannelHasActiveBoundReports_NoBoundReports(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg7")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "NoBoundChan")

	has, err := s.ChannelHasActiveBoundReports(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundReports: %v", err)
	}
	if has {
		t.Error("expected false for channel with no bound reports")
	}
}

func TestChannelHasActiveBoundReports_WithActiveReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg8")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "ActiveReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ActiveChan")

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}

	has, err := s.ChannelHasActiveBoundReports(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundReports: %v", err)
	}
	if !has {
		t.Error("expected true for channel bound to an active report")
	}
}

func TestReportChannel_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "RCIsoA")
	org2 := s.MustCreateOrg(t, ctx, "RCIsoB")
	report := mustCreateScheduledReport(t, s, ctx, org1.ID, "IsoReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org1.ID, "IsoChan")

	if err := s.BindChannelToReport(ctx, org1.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}

	// org2 cannot see org1's report channels.
	list, err := s.ListChannelsForReport(ctx, org2.ID, report.ID)
	if err != nil {
		t.Fatalf("ListChannelsForReport(wrong org): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 channels for wrong org, got %d", len(list))
	}

	// org2 cannot check binding existence for org1's report.
	exists, err := s.ReportChannelBindingExists(ctx, org2.ID, report.ID, chanID)
	if err != nil {
		t.Fatalf("ReportChannelBindingExists(wrong org): %v", err)
	}
	if exists {
		t.Error("binding should not be visible to wrong org")
	}

	// org2 unbind is a no-op (binding unaffected).
	if err := s.UnbindChannelFromReport(ctx, org2.ID, report.ID, chanID); err != nil {
		t.Fatalf("UnbindChannelFromReport(wrong org): %v", err)
	}
	exists, err = s.ReportChannelBindingExists(ctx, org1.ID, report.ID, chanID)
	if err != nil {
		t.Fatalf("ReportChannelBindingExists after cross-org unbind: %v", err)
	}
	if !exists {
		t.Error("binding should still exist after cross-org unbind attempt")
	}

	// org2 bind attempt — different org_id in join table, should not affect org1.
	if err := s.BindChannelToReport(ctx, org2.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport(wrong org): %v", err)
	}
	// org1 should still have exactly 1 binding visible.
	list, err = s.ListChannelsForReport(ctx, org1.ID, report.ID)
	if err != nil {
		t.Fatalf("ListChannelsForReport(org1): %v", err)
	}
	if len(list) != 1 {
		t.Errorf("org1 should still see 1 channel, got %d", len(list))
	}
}

func TestChannelHasActiveBoundReports_PausedAndDeletedExcluded(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCPausedDelOrg")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "PausedDelChan")

	// Create a paused report and bind the channel.
	pausedReport, err := s.CreateScheduledReport(ctx, org.ID, store.CreateScheduledReportParams{
		Name:          "PausedReport",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(24 * time.Hour),
		SendOnEmpty:   true,
		Status:        "paused",
	})
	if err != nil {
		t.Fatalf("CreateScheduledReport(paused): %v", err)
	}
	if err := s.BindChannelToReport(ctx, org.ID, pausedReport.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport(paused): %v", err)
	}

	// Paused report → should return false.
	has, err := s.ChannelHasActiveBoundReports(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundReports(paused): %v", err)
	}
	if has {
		t.Error("paused report should not count as active binding")
	}

	// Create an active report, bind, then soft-delete it.
	activeReport := mustCreateScheduledReport(t, s, ctx, org.ID, "ActiveThenDeleted")
	if err := s.BindChannelToReport(ctx, org.ID, activeReport.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport(active): %v", err)
	}
	if err := s.SoftDeleteScheduledReport(ctx, org.ID, activeReport.ID); err != nil {
		t.Fatalf("SoftDeleteScheduledReport: %v", err)
	}

	// Soft-deleted report → should return false.
	has, err = s.ChannelHasActiveBoundReports(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBoundReports(soft-deleted): %v", err)
	}
	if has {
		t.Error("soft-deleted report should not count as active binding")
	}
}

func TestChannelHasActiveBindings_ShortCircuitOnRules(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCShortOrg")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "ShortCircuitChan")

	// Bind to an active rule (not a report).
	rule, err := s.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:       "ShortCircuitRule",
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
	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// ChannelHasActiveBindings must return true (rules=true short-circuits).
	has, err := s.ChannelHasActiveBindings(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBindings(rules only): %v", err)
	}
	if !has {
		t.Error("expected true when channel has active rule binding (short-circuit)")
	}
}

func TestListActiveChannelsForDigest_IncludesSecrets(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCSecretOrg")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "SecretReport")
	chanID, secret := mustCreateNotificationChannel(t, s, ctx, org.ID, "SecretChan")

	// Rotate to populate secondary secret.
	newSecret, err := s.RotateSigningSecret(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("RotateSigningSecret: %v", err)
	}

	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}

	list, err := s.ListActiveChannelsForDigest(ctx, org.ID, report.ID)
	if err != nil {
		t.Fatalf("ListActiveChannelsForDigest: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(list))
	}

	// Primary secret must match the rotated value.
	if !list[0].SigningSecret.Valid || list[0].SigningSecret.String != newSecret {
		t.Errorf("primary signing_secret = %v, want %q", list[0].SigningSecret, newSecret)
	}
	// Secondary secret must be the original.
	if !list[0].SigningSecretSecondary.Valid || list[0].SigningSecretSecondary.String != secret {
		t.Errorf("secondary signing_secret = %v, want %q", list[0].SigningSecretSecondary, secret)
	}
}

func TestChannelHasActiveBindings_BothRulesAndReports(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RCOrg9")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "UnifiedChan")

	// No bindings: should be false.
	has, err := s.ChannelHasActiveBindings(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBindings (no bindings): %v", err)
	}
	if has {
		t.Error("expected false with no bindings")
	}

	// Bind to an active report: should be true.
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "UnifiedReport")
	if err := s.BindChannelToReport(ctx, org.ID, report.ID, chanID); err != nil {
		t.Fatalf("BindChannelToReport: %v", err)
	}

	has, err = s.ChannelHasActiveBindings(ctx, org.ID, chanID)
	if err != nil {
		t.Fatalf("ChannelHasActiveBindings (with report): %v", err)
	}
	if !has {
		t.Error("expected true with active report binding")
	}
}
