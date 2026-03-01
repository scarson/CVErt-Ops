// ABOUTME: Integration tests for store/scheduled_report.go — scheduled report CRUD + runner ops.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// mustCreateScheduledReport creates a scheduled report or fatals the test.
func mustCreateScheduledReport(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) *store.ScheduledReportRow {
	t.Helper()
	row, err := s.CreateScheduledReport(ctx, orgID, store.CreateScheduledReportParams{
		Name:          name,
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(24 * time.Hour),
		SendOnEmpty:   true,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateScheduledReport(%q): %v", name, err)
	}
	return row
}

func TestCreateScheduledReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg1")

	nextRun := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
	row, err := s.CreateScheduledReport(ctx, org.ID, store.CreateScheduledReportParams{
		Name:              "Daily Digest",
		ScheduledTime:     "08:00:00",
		Timezone:          "America/New_York",
		NextRunAt:         nextRun,
		SeverityThreshold: sql.NullString{String: "high", Valid: true},
		WatchlistIds:      []uuid.UUID{uuid.New()},
		SendOnEmpty:       false,
		AiSummary:         true,
		Status:            "active",
	})
	if err != nil {
		t.Fatalf("CreateScheduledReport: %v", err)
	}
	if row == nil {
		t.Fatal("CreateScheduledReport returned nil row")
	}
	if row.Name != "Daily Digest" {
		t.Errorf("Name = %q, want Daily Digest", row.Name)
	}
	if row.Timezone != "America/New_York" {
		t.Errorf("Timezone = %q, want America/New_York", row.Timezone)
	}
	if !row.SeverityThreshold.Valid || row.SeverityThreshold.String != "high" {
		t.Errorf("SeverityThreshold = %v, want high", row.SeverityThreshold)
	}
	if row.SendOnEmpty {
		t.Error("SendOnEmpty should be false")
	}
	if !row.AiSummary {
		t.Error("AiSummary should be true")
	}
	if row.Status != "active" {
		t.Errorf("Status = %q, want active", row.Status)
	}
}

func TestGetScheduledReport_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg2")

	got, err := s.GetScheduledReport(ctx, org.ID, uuid.New())
	if err != nil {
		t.Fatalf("GetScheduledReport: %v", err)
	}
	if got != nil {
		t.Error("GetScheduledReport should return nil for nonexistent report")
	}
}

func TestGetScheduledReport_Found(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg3")
	created := mustCreateScheduledReport(t, s, ctx, org.ID, "MyReport")

	got, err := s.GetScheduledReport(ctx, org.ID, created.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport: %v", err)
	}
	if got == nil {
		t.Fatal("GetScheduledReport returned nil for existing report")
	}
	if got.Name != "MyReport" {
		t.Errorf("Name = %q, want MyReport", got.Name)
	}
}

func TestListScheduledReports(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg4")

	mustCreateScheduledReport(t, s, ctx, org.ID, "Report-A")
	mustCreateScheduledReport(t, s, ctx, org.ID, "Report-B")

	list, err := s.ListScheduledReports(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListScheduledReports: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(list))
	}
	// Ordered by created_at DESC — Report-B should be first.
	if list[0].Name != "Report-B" {
		t.Errorf("first report = %q, want Report-B", list[0].Name)
	}
}

func TestSoftDeleteScheduledReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg5")
	created := mustCreateScheduledReport(t, s, ctx, org.ID, "ToDelete")

	if err := s.SoftDeleteScheduledReport(ctx, org.ID, created.ID); err != nil {
		t.Fatalf("SoftDeleteScheduledReport: %v", err)
	}

	// Get should return nil after soft-delete.
	got, err := s.GetScheduledReport(ctx, org.ID, created.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport after delete: %v", err)
	}
	if got != nil {
		t.Error("soft-deleted report should not be returned by Get")
	}

	// List should exclude soft-deleted reports.
	list, err := s.ListScheduledReports(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListScheduledReports after delete: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("soft-deleted report still in list, got %d", len(list))
	}
}

func TestClaimDueReports(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg6")

	// Create a report due now.
	dueReport, err := s.CreateScheduledReport(ctx, org.ID, store.CreateScheduledReportParams{
		Name:          "Due Now",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(-1 * time.Hour), // past due
		SendOnEmpty:   true,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("create due report: %v", err)
	}

	// Create a report not yet due.
	_, err = s.CreateScheduledReport(ctx, org.ID, store.CreateScheduledReportParams{
		Name:          "Future Report",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(24 * time.Hour), // future
		SendOnEmpty:   true,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("create future report: %v", err)
	}

	// Create a paused report that's past due (should not be claimed).
	_, err = s.CreateScheduledReport(ctx, org.ID, store.CreateScheduledReportParams{
		Name:          "Paused Report",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(-1 * time.Hour),
		SendOnEmpty:   true,
		Status:        "paused",
	})
	if err != nil {
		t.Fatalf("create paused report: %v", err)
	}

	// Claim: should only get the active due report.
	claimed, err := s.ClaimDueReports(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimDueReports: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("expected 1 claimed report, got %d", len(claimed))
	}
	if claimed[0].ID != dueReport.ID {
		t.Errorf("claimed report ID = %v, want %v", claimed[0].ID, dueReport.ID)
	}
}

func TestAdvanceReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ReportOrg7")
	created := mustCreateScheduledReport(t, s, ctx, org.ID, "ToAdvance")

	lastRun := time.Now().Truncate(time.Microsecond)
	nextRun := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)

	if err := s.AdvanceReport(ctx, created.ID, lastRun, nextRun); err != nil {
		t.Fatalf("AdvanceReport: %v", err)
	}

	got, err := s.GetScheduledReport(ctx, org.ID, created.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport after advance: %v", err)
	}
	if got == nil {
		t.Fatal("report not found after advance")
	}
	if !got.LastRunAt.Valid {
		t.Fatal("LastRunAt should be set after advance")
	}
	if !got.LastRunAt.Time.Equal(lastRun) {
		t.Errorf("LastRunAt = %v, want %v", got.LastRunAt.Time, lastRun)
	}
	if !got.NextRunAt.Equal(nextRun) {
		t.Errorf("NextRunAt = %v, want %v", got.NextRunAt, nextRun)
	}
}

func TestGetAlertRuleName_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	name, err := s.GetAlertRuleName(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetAlertRuleName: %v", err)
	}
	if name != "" {
		t.Errorf("expected empty string for nonexistent rule, got %q", name)
	}
}
