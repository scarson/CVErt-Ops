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

// digestRescanWindow is how far behind the stored cursor each digest scan starts.
// date_modified_canonical is stamped by the merge worker's clock before its
// transaction commits, so a CVE can become visible after a digest's scan while
// carrying a timestamp earlier than the cursor that digest records. The window
// lets the next digest pick such CVEs up; the report's rescan_sent_cves keeps the
// versions already sent out of it (implementation-pitfalls.md NOTIFY-21).
const digestRescanWindow = 2 * time.Minute

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
// 3. Query matching CVEs from digestRescanWindow before since, minus versions already sent
// 4. List active channels for the report
// 5. Insert delivery row per channel
// 6. Advance last_run_at, next_run_at, and the sent versions in the re-scan window
func (w *Worker) executeDigestReport(ctx context.Context, report store.ScheduledReportRow) error {
	// Determine the "since" cutoff — new CVEs since last run or since creation.
	since := report.CreatedAt
	if report.LastRunAt.Valid {
		since = report.LastRunAt.Time
	}

	// A malformed list only costs repeats in this digest, so it must not stop the report.
	var sent []store.DigestSentCVE
	if err := json.Unmarshal(report.RescanSentCves, &sent); err != nil {
		w.log.Error("decode digest rescan_sent_cves", "report_id", report.ID, "err", err)
		sent = nil
	}

	// Expand severity threshold.
	var severities []string
	if report.SeverityThreshold.Valid {
		severities = expandSeverityThreshold(report.SeverityThreshold.String)
	}

	// The next run's cursor is read before the query, so a CVE stamped while this
	// run is in progress falls after it.
	cursor := time.Now().UTC()

	// Query matching CVEs.
	cves, err := w.store.DigestCVEs(ctx, since.Add(-digestRescanWindow), severities, sent)
	if err != nil {
		return fmt.Errorf("query digest CVEs: %w", err)
	}
	sentInWindow := sentInRescanWindow(sent, cves, cursor)

	// Skip if no CVEs and send_on_empty is false.
	if len(cves) == 0 && !report.SendOnEmpty {
		// Still advance so we don't re-query the same window.
		return w.advanceReport(ctx, report, cursor, sentInWindow)
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

	// List active channels for this report (bypass-RLS — worker context).
	channels, err := w.store.ListActiveChannelsForDigest(ctx, report.OrgID, report.ID)
	if err != nil {
		return fmt.Errorf("list channels for digest: %w", err)
	}

	// Insert a delivery row per channel.
	for _, ch := range channels {
		if err := w.store.InsertDigestDelivery(ctx, report.OrgID, report.ID, ch.ID, payload); err != nil {
			w.log.Error("insert digest delivery", "report_id", report.ID, "channel_id", ch.ID, "err", err)
		}
	}

	return w.advanceReport(ctx, report, cursor, sentInWindow)
}

// sentInRescanWindow returns the sent CVE versions that the next run's scan, which
// starts digestRescanWindow before cursor, will reach again: those in previous
// (sent by earlier runs) and in cves (sent by this run).
func sentInRescanWindow(previous []store.DigestSentCVE, cves []store.DigestCVEsRow, cursor time.Time) []store.DigestSentCVE {
	floor := cursor.Add(-digestRescanWindow)
	var kept []store.DigestSentCVE
	for _, s := range previous {
		if s.DateModifiedCanonical.After(floor) {
			kept = append(kept, s)
		}
	}
	for _, row := range cves {
		if row.DateModifiedCanonical.After(floor) {
			kept = append(kept, store.DigestSentCVE{CVEID: row.CveID, DateModifiedCanonical: row.DateModifiedCanonical})
		}
	}
	return kept
}

// advanceReport sets last_run_at to cursor, records the sent CVE versions the next
// run must leave out, and advances next_run_at by one day.
func (w *Worker) advanceReport(ctx context.Context, report store.ScheduledReportRow, cursor time.Time, sent []store.DigestSentCVE) error {
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
	return w.store.AdvanceReport(ctx, report.ID, cursor, nextRun, sent)
}
