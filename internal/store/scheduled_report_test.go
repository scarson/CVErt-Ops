// ABOUTME: Integration tests for store/scheduled_report.go — scheduled report CRUD + runner ops.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	org := s.MustCreateOrg(t, ctx, "ReportOrg1")

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

	org := s.MustCreateOrg(t, ctx, "ReportOrg2")

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

	org := s.MustCreateOrg(t, ctx, "ReportOrg3")
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

	org := s.MustCreateOrg(t, ctx, "ReportOrg4")

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

	org := s.MustCreateOrg(t, ctx, "ReportOrg5")
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

func TestRunDueDigest_ClaimsActiveDueReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportOrg6")

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

	// Run: should only claim the active due report.
	var ran []uuid.UUID
	record := func(run *store.DigestRun) error {
		ran = append(ran, run.Report.ID)
		return nil
	}
	claimed, err := s.RunDueDigest(ctx, nil, record)
	if err != nil {
		t.Fatalf("RunDueDigest: %v", err)
	}
	if claimed == nil {
		t.Fatal("RunDueDigest claimed no report, want the active due report")
	}
	if claimed.ID != dueReport.ID {
		t.Errorf("claimed report ID = %v, want %v", claimed.ID, dueReport.ID)
	}
	if len(ran) != 1 || ran[0] != dueReport.ID {
		t.Errorf("run called with reports %v, want [%v]", ran, dueReport.ID)
	}

	// The run did not advance the report, so it is still due; skipping it
	// leaves nothing to claim.
	claimed, err = s.RunDueDigest(ctx, []uuid.UUID{dueReport.ID}, record)
	if err != nil {
		t.Fatalf("RunDueDigest with skip: %v", err)
	}
	if claimed != nil {
		t.Errorf("claimed report %v with the due report skipped, want none", claimed.ID)
	}
	if len(ran) != 1 {
		t.Errorf("run called %d times, want 1", len(ran))
	}
}

// mustCreateDueScheduledReport creates an active scheduled report whose
// next_run_at is an hour in the past, or fatals the test.
func mustCreateDueScheduledReport(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) *store.ScheduledReportRow {
	t.Helper()
	row, err := s.CreateScheduledReport(ctx, orgID, store.CreateScheduledReportParams{
		Name:          name,
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(-1 * time.Hour),
		SendOnEmpty:   true,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateScheduledReport(%q): %v", name, err)
	}
	return row
}

func TestRunDueDigest_SkipsReportHeldByAnotherRun(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportHeldOrg")
	due := mustCreateDueScheduledReport(t, s, ctx, org.ID, "HeldReport")

	// The inner run uses another connection while the outer run holds the row.
	var inner *store.ScheduledReportRow
	outer, err := s.RunDueDigest(ctx, nil, func(*store.DigestRun) error {
		var err error
		inner, err = s.RunDueDigest(ctx, nil, func(*store.DigestRun) error { return nil })
		return err
	})
	if err != nil {
		t.Fatalf("RunDueDigest: %v", err)
	}
	if outer == nil || outer.ID != due.ID {
		t.Fatalf("outer run claimed %v, want report %v", outer, due.ID)
	}
	if inner != nil {
		t.Errorf("inner run claimed report %v while the outer run held it, want none", inner.ID)
	}
}

func TestRunDueDigest_RollsBackWhenRunFails(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportRollbackOrg")
	due := mustCreateDueScheduledReport(t, s, ctx, org.ID, "RollbackReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "RollbackChan")

	runErr := errors.New("digest run failed")
	claimed, err := s.RunDueDigest(ctx, nil, func(run *store.DigestRun) error {
		if err := run.InsertDelivery(ctx, chanID, json.RawMessage(`{"cves":[]}`)); err != nil {
			return err
		}
		if err := run.Advance(ctx, time.Now(), time.Now().Add(24*time.Hour), nil); err != nil {
			return err
		}
		return runErr
	})
	if !errors.Is(err, runErr) {
		t.Fatalf("RunDueDigest error = %v, want %v", err, runErr)
	}
	if claimed == nil || claimed.ID != due.ID {
		t.Fatalf("RunDueDigest claimed %v, want report %v", claimed, due.ID)
	}

	var deliveries int
	if err := s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM notification_deliveries WHERE report_id = $1", due.ID).Scan(&deliveries); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if deliveries != 0 {
		t.Errorf("delivery count = %d after a failed run, want 0", deliveries)
	}
	got, err := s.GetScheduledReport(ctx, org.ID, due.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport: %v", err)
	}
	if got.LastRunAt.Valid {
		t.Errorf("LastRunAt = %v after a failed run, want unset", got.LastRunAt.Time)
	}
	if !got.NextRunAt.Equal(due.NextRunAt) {
		t.Errorf("NextRunAt = %v after a failed run, want %v", got.NextRunAt, due.NextRunAt)
	}
}

// mustAdvanceDueReport runs the due report's digest and advances it with the
// given values, or fatals the test.
func mustAdvanceDueReport(t *testing.T, s *testutil.TestDB, ctx context.Context, reportID uuid.UUID, lastRun, nextRun time.Time, sent []store.DigestSentCVE) {
	t.Helper()
	claimed, err := s.RunDueDigest(ctx, nil, func(run *store.DigestRun) error {
		return run.Advance(ctx, lastRun, nextRun, sent)
	})
	if err != nil {
		t.Fatalf("RunDueDigest: %v", err)
	}
	if claimed == nil || claimed.ID != reportID {
		t.Fatalf("RunDueDigest claimed %v, want report %v", claimed, reportID)
	}
}

func TestDigestRun_Advance(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportOrg7")
	created := mustCreateDueScheduledReport(t, s, ctx, org.ID, "ToAdvance")

	lastRun := time.Now().Truncate(time.Microsecond)
	nextRun := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)

	sent := []store.DigestSentCVE{
		{CVEID: "CVE-2025-0001", DateModifiedCanonical: lastRun.Add(-time.Minute)},
	}

	mustAdvanceDueReport(t, s, ctx, created.ID, lastRun, nextRun, sent)

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
	var gotSent []store.DigestSentCVE
	if err := json.Unmarshal(got.RescanSentCves, &gotSent); err != nil {
		t.Fatalf("unmarshal rescan_sent_cves %s: %v", got.RescanSentCves, err)
	}
	if len(gotSent) != 1 || gotSent[0].CVEID != sent[0].CVEID ||
		!gotSent[0].DateModifiedCanonical.Equal(sent[0].DateModifiedCanonical) {
		t.Errorf("rescan_sent_cves = %+v, want %+v", gotSent, sent)
	}
}

func TestDigestRun_AdvanceNilSentStoresEmptyArray(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportOrgNilSent")
	created := mustCreateDueScheduledReport(t, s, ctx, org.ID, "ToAdvanceNilSent")

	mustAdvanceDueReport(t, s, ctx, created.ID, time.Now(), time.Now().Add(24*time.Hour), nil)
	got, err := s.GetScheduledReport(ctx, org.ID, created.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport after advance: %v", err)
	}
	if string(got.RescanSentCves) != "[]" {
		t.Errorf("rescan_sent_cves = %s, want []", got.RescanSentCves)
	}
}

func TestUpdateScheduledReport(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportUpdateOrg")
	created := mustCreateScheduledReport(t, s, ctx, org.ID, "BeforeUpdate")

	// Update name, timezone, severity_threshold, send_on_empty, ai_summary, status.
	nextRun := time.Now().Add(48 * time.Hour).Truncate(time.Microsecond)
	updated, err := s.UpdateScheduledReport(ctx, org.ID, created.ID, store.UpdateScheduledReportParams{
		Name:              "AfterUpdate",
		ScheduledTime:     "14:30:00",
		Timezone:          "Europe/London",
		NextRunAt:         nextRun,
		SeverityThreshold: sql.NullString{String: "medium", Valid: true},
		SendOnEmpty:       false,
		AiSummary:         true,
		Status:            "paused",
	})
	if err != nil {
		t.Fatalf("UpdateScheduledReport: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateScheduledReport returned nil")
	}
	if updated.Name != "AfterUpdate" {
		t.Errorf("Name = %q, want AfterUpdate", updated.Name)
	}
	if updated.Timezone != "Europe/London" {
		t.Errorf("Timezone = %q, want Europe/London", updated.Timezone)
	}
	if !updated.SeverityThreshold.Valid || updated.SeverityThreshold.String != "medium" {
		t.Errorf("SeverityThreshold = %v, want medium", updated.SeverityThreshold)
	}
	if updated.SendOnEmpty {
		t.Error("SendOnEmpty should be false after update")
	}
	if !updated.AiSummary {
		t.Error("AiSummary should be true after update")
	}
	if updated.Status != "paused" {
		t.Errorf("Status = %q, want paused", updated.Status)
	}
}

func TestUpdateScheduledReport_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportUpdateNFOrg")

	result, err := s.UpdateScheduledReport(ctx, org.ID, uuid.New(), store.UpdateScheduledReportParams{
		Name:          "Ghost",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     time.Now().Add(24 * time.Hour),
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("UpdateScheduledReport: %v", err)
	}
	if result != nil {
		t.Error("expected nil for nonexistent report update")
	}
}

func TestGetScheduledReportName(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReportNameOrg")
	created := mustCreateScheduledReport(t, s, ctx, org.ID, "NamedReport")

	name, err := s.GetScheduledReportName(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetScheduledReportName: %v", err)
	}
	if name != "NamedReport" {
		t.Errorf("GetScheduledReportName = %q, want NamedReport", name)
	}
}

func TestGetScheduledReportName_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	name, err := s.GetScheduledReportName(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetScheduledReportName: %v", err)
	}
	if name != "" {
		t.Errorf("expected empty string for nonexistent report, got %q", name)
	}
}

func TestScheduledReport_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "SRIsoA")
	org2 := s.MustCreateOrg(t, ctx, "SRIsoB")
	report := mustCreateScheduledReport(t, s, ctx, org1.ID, "Org1Report")

	// Get with wrong org → nil.
	got, err := s.GetScheduledReport(ctx, org2.ID, report.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport(wrong org): %v", err)
	}
	if got != nil {
		t.Error("GetScheduledReport with wrong org should return nil")
	}

	// List with wrong org → empty.
	list, err := s.ListScheduledReports(ctx, org2.ID)
	if err != nil {
		t.Fatalf("ListScheduledReports(wrong org): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 reports for wrong org, got %d", len(list))
	}

	// Update with wrong org → nil (no-op).
	updated, err := s.UpdateScheduledReport(ctx, org2.ID, report.ID, store.UpdateScheduledReportParams{
		Name:          "Hijacked",
		ScheduledTime: "12:00:00",
		Timezone:      "UTC",
		NextRunAt:     report.NextRunAt,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("UpdateScheduledReport(wrong org): %v", err)
	}
	if updated != nil {
		t.Error("UpdateScheduledReport with wrong org should return nil")
	}
	// Verify name unchanged.
	got, err = s.GetScheduledReport(ctx, org1.ID, report.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport after cross-org update: %v", err)
	}
	if got == nil {
		t.Fatal("report should still exist in org1")
	}
	if got.Name != "Org1Report" {
		t.Errorf("Name = %q, want Org1Report (should be unchanged)", got.Name)
	}

	// SoftDelete with wrong org → no-op.
	if err := s.SoftDeleteScheduledReport(ctx, org2.ID, report.ID); err != nil {
		t.Fatalf("SoftDeleteScheduledReport(wrong org): %v", err)
	}
	got, err = s.GetScheduledReport(ctx, org1.ID, report.ID)
	if err != nil {
		t.Fatalf("GetScheduledReport after cross-org delete: %v", err)
	}
	if got == nil {
		t.Error("report should still exist in org1 after cross-org delete attempt")
	}
}

func TestUpdateScheduledReport_SoftDeleted(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "SRUpdDelOrg")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "DeletedReport")

	if err := s.SoftDeleteScheduledReport(ctx, org.ID, report.ID); err != nil {
		t.Fatalf("SoftDeleteScheduledReport: %v", err)
	}

	// Update on soft-deleted report → nil.
	result, err := s.UpdateScheduledReport(ctx, org.ID, report.ID, store.UpdateScheduledReportParams{
		Name:          "Revived",
		ScheduledTime: "08:00:00",
		Timezone:      "UTC",
		NextRunAt:     report.NextRunAt,
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("UpdateScheduledReport(soft-deleted): %v", err)
	}
	if result != nil {
		t.Error("expected nil for soft-deleted report update")
	}
}

func TestGetAlertRuleName_Found(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "RuleNameOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "NamedRule")

	name, err := s.GetAlertRuleName(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetAlertRuleName: %v", err)
	}
	if name != "NamedRule" {
		t.Errorf("GetAlertRuleName = %q, want NamedRule", name)
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
