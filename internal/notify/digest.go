// ABOUTME: Digest runner: claims due reports, queries matching CVEs, fans out to channels.
// ABOUTME: Runs as a synchronous ticker in the worker select loop — all DB, no outbound HTTP.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/scarson/cvert-ops/internal/store"
)

// severityRank maps severity strings to numeric rank for threshold expansion.
var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// expandSeverityThreshold returns all severities at or above the given threshold.
// Returns nil if threshold is empty (all severities).
func expandSeverityThreshold(threshold string) []string {
	if threshold == "" {
		return nil
	}
	minRank, ok := severityRank[threshold]
	if !ok {
		return nil
	}
	var result []string
	for sev, rank := range severityRank {
		if rank >= minRank {
			result = append(result, sev)
		}
	}
	sort.Strings(result) // deterministic order for testing
	return result
}

// ComputeNextRunAt calculates the next occurrence of scheduledTime (format "HH:MM:SS")
// in the given timezone that is strictly after now. Returns UTC.
func ComputeNextRunAt(scheduledTime string, timezone string) (time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	h, m, s, err := parseTimeOfDay(scheduledTime)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now().In(loc)
	candidate := time.Date(now.Year(), now.Month(), now.Day(), h, m, s, 0, loc)
	if !candidate.After(now) {
		candidate = candidate.AddDate(0, 0, 1)
	}
	return candidate.UTC(), nil
}

// advanceNextRunAt advances next_run_at by one day in the report's timezone.
// Uses AddDate for DST correctness — never adds 24*time.Hour.
func advanceNextRunAt(currentNextRun time.Time, timezone string) (time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	inTZ := currentNextRun.In(loc)
	next := inTZ.AddDate(0, 0, 1)
	return next.UTC(), nil
}

// parseTimeOfDay parses "HH:MM" or "HH:MM:SS" and returns (hour, min, sec).
func parseTimeOfDay(s string) (int, int, int, error) {
	t, err := time.Parse("15:04:05", s)
	if err != nil {
		t, err = time.Parse("15:04", s)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("scheduled_time must be HH:MM or HH:MM:SS, got %q", s)
		}
	}
	return t.Hour(), t.Minute(), t.Second(), nil
}

// runDigest claims due reports and executes each one.
func (w *Worker) runDigest(ctx context.Context) {
	reports, err := w.store.ClaimDueReports(ctx, 10)
	if err != nil {
		w.log.Error("claim due reports", "err", err)
		return
	}
	for _, report := range reports {
		if err := w.executeDigestReport(ctx, report); err != nil {
			w.log.Error("execute digest report", "report_id", report.ID, "err", err)
		}
	}
}

// executeDigestReport processes a single digest report:
// 1. Compute since-time from COALESCE(last_run_at, created_at)
// 2. Expand severity threshold
// 3. Query matching CVEs
// 4. List active channels for the report
// 5. Insert delivery row per channel
// 6. Advance next_run_at
func (w *Worker) executeDigestReport(ctx context.Context, report store.ScheduledReportRow) error {
	// Determine the "since" cutoff — new CVEs since last run or since creation.
	since := report.CreatedAt
	if report.LastRunAt.Valid {
		since = report.LastRunAt.Time
	}

	// Expand severity threshold.
	var severities []string
	if report.SeverityThreshold.Valid {
		severities = expandSeverityThreshold(report.SeverityThreshold.String)
	}

	// Query matching CVEs.
	cves, err := w.store.DigestCVEs(ctx, since, severities)
	if err != nil {
		return fmt.Errorf("query digest CVEs: %w", err)
	}

	// Skip if no CVEs and send_on_empty is false.
	if len(cves) == 0 && !report.SendOnEmpty {
		// Still advance so we don't re-query the same window.
		return w.advanceReport(ctx, report)
	}

	// Build the payload as a JSON array of cveSnapshot objects.
	snaps := make([]cveSnapshot, len(cves))
	for i, row := range cves {
		var sev *string
		if row.Severity.Valid {
			sev = &row.Severity.String
		}
		snaps[i] = cveSnapshot{
			CVEID:        row.CveID,
			Severity:     sev,
			Description:  row.DescriptionPrimary.String,
			ExploitAvail: row.ExploitAvailable,
			InCISAKEV:    row.InCisaKev,
		}
		if row.CvssV3Score.Valid {
			snaps[i].CVSSV3Score = &row.CvssV3Score.Float64
		}
		if row.CvssV4Score.Valid {
			snaps[i].CVSSV4Score = &row.CvssV4Score.Float64
		}
		if row.EpssScore.Valid {
			snaps[i].EPSSScore = &row.EpssScore.Float64
		}
	}
	payload, err := json.Marshal(snaps)
	if err != nil {
		return fmt.Errorf("marshal digest payload: %w", err)
	}

	// List active channels for this report.
	channels, err := w.store.ListChannelsForReport(ctx, report.OrgID, report.ID)
	if err != nil {
		return fmt.Errorf("list channels for report: %w", err)
	}

	// Insert a delivery row per channel.
	for _, ch := range channels {
		if err := w.store.InsertDigestDelivery(ctx, report.OrgID, report.ID, ch.ID, payload); err != nil {
			w.log.Error("insert digest delivery", "report_id", report.ID, "channel_id", ch.ID, "err", err)
		}
	}

	return w.advanceReport(ctx, report)
}

// advanceReport updates last_run_at and advances next_run_at by one day.
func (w *Worker) advanceReport(ctx context.Context, report store.ScheduledReportRow) error {
	now := time.Now().UTC()
	nextRun, err := advanceNextRunAt(report.NextRunAt, report.Timezone)
	if err != nil {
		return fmt.Errorf("advance next_run_at: %w", err)
	}
	// If the computed next run is still in the past (missed runs), skip forward.
	for !nextRun.After(now) {
		nextRun, err = advanceNextRunAt(nextRun, report.Timezone)
		if err != nil {
			return fmt.Errorf("skip-forward next_run_at: %w", err)
		}
	}
	return w.store.AdvanceReport(ctx, report.ID, now, nextRun)
}
