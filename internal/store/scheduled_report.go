// ABOUTME: Store methods for scheduled_reports digest configuration CRUD.
// ABOUTME: The digest runner (RunDueDigest, DigestRun) uses withBypassTx; API ops use withOrgTx.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// ScheduledReportRow is the scheduled report record returned by store methods.
type ScheduledReportRow = generated.ScheduledReport

// CreateScheduledReportParams holds the fields for creating a new scheduled report.
type CreateScheduledReportParams struct {
	Name              string
	ScheduledTime     string // "HH:MM:SS" format — Postgres TIME column
	Timezone          string
	NextRunAt         time.Time
	SeverityThreshold sql.NullString
	WatchlistIds      []uuid.UUID
	SendOnEmpty       bool
	AiSummary         bool
	Status            string
}

// CreateScheduledReport creates a new scheduled report within orgID.
func (s *Store) CreateScheduledReport(ctx context.Context, orgID uuid.UUID, p CreateScheduledReportParams) (*ScheduledReportRow, error) {
	var result *ScheduledReportRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.CreateScheduledReport(ctx, generated.CreateScheduledReportParams{
			OrgID:             orgID,
			Name:              p.Name,
			ScheduledTime:     p.ScheduledTime,
			Timezone:          p.Timezone,
			NextRunAt:         p.NextRunAt,
			SeverityThreshold: p.SeverityThreshold,
			WatchlistIds:      p.WatchlistIds,
			SendOnEmpty:       p.SendOnEmpty,
			AiSummary:         p.AiSummary,
			Status:            p.Status,
		})
		if err != nil {
			return fmt.Errorf("create scheduled report: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// GetScheduledReport returns the scheduled report with the given id within orgID,
// or nil if not found.
func (s *Store) GetScheduledReport(ctx context.Context, orgID, id uuid.UUID) (*ScheduledReportRow, error) {
	var result *ScheduledReportRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetScheduledReport(ctx, generated.GetScheduledReportParams{
			ID:    id,
			OrgID: orgID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get scheduled report: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// ListScheduledReports returns all non-deleted scheduled reports for orgID.
func (s *Store) ListScheduledReports(ctx context.Context, orgID uuid.UUID) ([]ScheduledReportRow, error) {
	var result []ScheduledReportRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		rows, err := q.ListScheduledReports(ctx, orgID)
		if err != nil {
			return fmt.Errorf("list scheduled reports: %w", err)
		}
		result = rows
		return nil
	})
	return result, err
}

// UpdateScheduledReportParams holds the mutable fields for updating a scheduled report.
// The handler reads the existing record and applies PATCH fields before calling this.
type UpdateScheduledReportParams = generated.UpdateScheduledReportParams

// UpdateScheduledReport performs a full replacement of mutable fields on a scheduled report.
func (s *Store) UpdateScheduledReport(ctx context.Context, orgID, id uuid.UUID, p UpdateScheduledReportParams) (*ScheduledReportRow, error) {
	var result *ScheduledReportRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		p.ID = id
		p.OrgID = orgID
		row, err := q.UpdateScheduledReport(ctx, p)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("update scheduled report: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// SoftDeleteScheduledReport marks a scheduled report as deleted.
func (s *Store) SoftDeleteScheduledReport(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.SoftDeleteScheduledReport(ctx, generated.SoftDeleteScheduledReportParams{
			ID:    id,
			OrgID: orgID,
		})
	})
}

// DigestRun is one claimed report's digest run. Its methods run in the
// transaction that holds the report's row lock, so the delivery rows and the
// report's advance commit together or not at all, and no other run can claim
// the report until then.
type DigestRun struct {
	Report ScheduledReportRow
	q      *generated.Queries
}

// RunDueDigest claims the earliest due scheduled report that is not in skip and
// not held by another run, and calls fn with it in one bypass-RLS (worker
// context) transaction. The transaction commits if fn returns nil and rolls back
// otherwise, leaving the report due. Returns the claimed report, or nil when no
// report is due, together with fn's error.
func (s *Store) RunDueDigest(ctx context.Context, skip []uuid.UUID, fn func(*DigestRun) error) (*ScheduledReportRow, error) {
	// A nil array binds as NULL, and id <> ALL(NULL) matches no rows.
	if skip == nil {
		skip = []uuid.UUID{}
	}
	var claimed *ScheduledReportRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		report, err := q.ClaimDueReport(ctx, skip)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim due report: %w", err)
		}
		claimed = &report
		return fn(&DigestRun{Report: report, q: q})
	})
	return claimed, err
}

// CVEs returns the CVEs for this digest; see Store.DigestCVEs.
func (r *DigestRun) CVEs(ctx context.Context, since time.Time, severities []string, sent []DigestSentCVE) ([]DigestCVEsRow, error) {
	return digestCVEs(ctx, r.q, since, severities, sent)
}

// Channels returns the non-deleted channels bound to the report; see
// Store.ListActiveChannelsForDigest.
func (r *DigestRun) Channels(ctx context.Context) ([]generated.ListActiveChannelsForDigestRow, error) {
	return listActiveChannelsForDigest(ctx, r.q, r.Report.OrgID, r.Report.ID)
}

// InsertDelivery inserts the report's digest delivery for one channel.
func (r *DigestRun) InsertDelivery(ctx context.Context, channelID uuid.UUID, payload json.RawMessage) error {
	return insertDigestDelivery(ctx, r.q, r.Report.OrgID, r.Report.ID, channelID, payload)
}

// Advance updates last_run_at, next_run_at, and the sent CVE versions the next
// run's re-scan window must leave out.
func (r *DigestRun) Advance(ctx context.Context, lastRunAt, nextRunAt time.Time, sent []DigestSentCVE) error {
	sentJSON, err := marshalDigestSentCVEs(sent)
	if err != nil {
		return fmt.Errorf("advance report: %w", err)
	}
	return r.q.AdvanceReport(ctx, generated.AdvanceReportParams{
		ID:             r.Report.ID,
		LastRunAt:      sql.NullTime{Time: lastRunAt, Valid: true},
		NextRunAt:      nextRunAt,
		RescanSentCves: sentJSON,
	})
}

// GetAlertRuleName returns the name of an alert rule by ID.
// Returns "" if the rule does not exist. Uses bypass-RLS (worker context).
func (s *Store) GetAlertRuleName(ctx context.Context, ruleID uuid.UUID) (string, error) {
	var result string
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		name, err := q.GetAlertRuleName(ctx, ruleID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get alert rule name: %w", err)
		}
		result = name
		return nil
	})
	return result, err
}

// GetScheduledReportName returns the name of a scheduled report by ID.
// Returns "" if the report does not exist. Uses bypass-RLS (worker context).
func (s *Store) GetScheduledReportName(ctx context.Context, reportID uuid.UUID) (string, error) {
	var result string
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		name, err := q.GetScheduledReportName(ctx, reportID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get scheduled report name: %w", err)
		}
		result = name
		return nil
	})
	return result, err
}
