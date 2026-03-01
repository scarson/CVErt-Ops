// ABOUTME: Store methods for scheduled_reports digest configuration CRUD.
// ABOUTME: Runner ops (ClaimDueReports, AdvanceReport) use withBypassTx; API ops use withOrgTx.
package store

import (
	"context"
	"database/sql"
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

// ClaimDueReports claims up to limit scheduled reports that are due for execution.
// Uses bypass-RLS (worker context).
func (s *Store) ClaimDueReports(ctx context.Context, limit int) ([]ScheduledReportRow, error) {
	var result []ScheduledReportRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		rows, err := q.ClaimDueReports(ctx, int32(limit)) //nolint:gosec // G115: limit is always small
		if err != nil {
			return fmt.Errorf("claim due reports: %w", err)
		}
		result = rows
		return nil
	})
	return result, err
}

// AdvanceReport updates last_run_at and next_run_at after a digest run.
// Uses bypass-RLS (worker context).
func (s *Store) AdvanceReport(ctx context.Context, id uuid.UUID, lastRunAt, nextRunAt time.Time) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.AdvanceReport(ctx, generated.AdvanceReportParams{
			ID:        id,
			LastRunAt: sql.NullTime{Time: lastRunAt, Valid: true},
			NextRunAt: nextRunAt,
		})
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

