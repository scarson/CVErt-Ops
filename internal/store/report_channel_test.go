// ABOUTME: Integration tests for store/report_channel.go — report ↔ channel M:M binding ops.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestBindChannelToReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "RCOrg1")
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

	org, _ := s.CreateOrg(ctx, "RCOrg2")
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

	org, _ := s.CreateOrg(ctx, "RCOrg3")
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

	org, _ := s.CreateOrg(ctx, "RCOrg4")
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

	org, _ := s.CreateOrg(ctx, "RCOrg5")
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

	org, _ := s.CreateOrg(ctx, "RCOrg6")

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

	org, _ := s.CreateOrg(ctx, "RCOrg7")
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

	org, _ := s.CreateOrg(ctx, "RCOrg8")
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

func TestChannelHasActiveBindings_BothRulesAndReports(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "RCOrg9")
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
