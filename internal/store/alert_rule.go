// ABOUTME: Store methods for alert rule, run, and event management.
// ABOUTME: Org-scoped methods use withOrgTx; cross-org worker methods use withBypassTx.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// AlertRuleRow is the alert rule record returned by store methods.
type AlertRuleRow = generated.AlertRule

// CreateAlertRuleParams holds the fields for creating an alert rule.
type CreateAlertRuleParams struct {
	Name                     string
	Logic                    string
	Conditions               json.RawMessage
	WatchlistIds             []uuid.UUID
	HasEpssCondition         bool
	IsEpssOnly               bool
	Status                   string
	FireOnNonMaterialChanges bool
}

// UpdateAlertRuleParams holds the mutable fields for updating an alert rule.
// Status is included so the content update and status transition are atomic.
type UpdateAlertRuleParams struct {
	Name                     string
	Logic                    string
	Conditions               json.RawMessage
	WatchlistIds             []uuid.UUID
	HasEpssCondition         bool
	IsEpssOnly               bool
	FireOnNonMaterialChanges bool
	Status                   string
}

// ListAlertEventsParams holds optional filters for listing alert events.
type ListAlertEventsParams struct {
	RuleID *uuid.UUID
	CveID  *string
	Limit  int
}

// AlertRuleStore defines the DB operations for alert rule, run, and event management.
type AlertRuleStore interface {
	CreateAlertRule(ctx context.Context, orgID uuid.UUID, p CreateAlertRuleParams) (*AlertRuleRow, error)
	GetAlertRule(ctx context.Context, orgID, id uuid.UUID) (*AlertRuleRow, error)
	UpdateAlertRule(ctx context.Context, orgID, id uuid.UUID, p UpdateAlertRuleParams) (*AlertRuleRow, error)
	SoftDeleteAlertRule(ctx context.Context, orgID, id uuid.UUID) error
	SetAlertRuleStatus(ctx context.Context, orgID, id uuid.UUID, status string) error
	ListAlertRules(ctx context.Context, orgID uuid.UUID, status *string, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]AlertRuleRow, error)
	InsertAlertRuleRun(ctx context.Context, ruleID, orgID uuid.UUID, path string) (*generated.AlertRuleRun, error)
	UpdateAlertRuleRun(ctx context.Context, id uuid.UUID, status string, candidatesEvaluated, matchesFound int32, errorMsg *string) error
	InsertAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error)
	GetUnresolvedAlertEventCVEs(ctx context.Context, ruleID, orgID uuid.UUID) ([]string, error)
	ResolveAlertEvent(ctx context.Context, ruleID, orgID uuid.UUID, cveID string) error
	ListAlertEvents(ctx context.Context, orgID uuid.UUID, p ListAlertEventsParams) ([]generated.AlertEvent, error)
	ListActiveRulesForEvaluation(ctx context.Context) ([]AlertRuleRow, error)
	ListActiveRulesForEPSS(ctx context.Context) ([]AlertRuleRow, error)
}

// CreateAlertRule inserts a new alert rule for the given org.
func (s *Store) CreateAlertRule(ctx context.Context, orgID uuid.UUID, p CreateAlertRuleParams) (*AlertRuleRow, error) {
	ids := p.WatchlistIds
	if ids == nil {
		ids = []uuid.UUID{}
	}
	var row generated.AlertRule
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateAlertRule(ctx, generated.CreateAlertRuleParams{
			OrgID:                    orgID,
			Name:                     p.Name,
			Logic:                    p.Logic,
			Conditions:               p.Conditions,
			WatchlistIds:             ids,
			DslVersion:               1,
			HasEpssCondition:         p.HasEpssCondition,
			IsEpssOnly:               p.IsEpssOnly,
			Status:                   p.Status,
			FireOnNonMaterialChanges: p.FireOnNonMaterialChanges,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create alert rule: %w", err)
	}
	return &row, nil
}

// GetAlertRule returns the alert rule with the given id within orgID, or (nil, nil) if not
// found or soft-deleted.
func (s *Store) GetAlertRule(ctx context.Context, orgID, id uuid.UUID) (*AlertRuleRow, error) {
	var result *AlertRuleRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetAlertRule(ctx, generated.GetAlertRuleParams{ID: id, OrgID: orgID})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get alert rule: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// UpdateAlertRule updates the mutable fields of an alert rule. Returns (nil, nil) if the
// rule is not found or has been soft-deleted.
func (s *Store) UpdateAlertRule(ctx context.Context, orgID, id uuid.UUID, p UpdateAlertRuleParams) (*AlertRuleRow, error) {
	ids := p.WatchlistIds
	if ids == nil {
		ids = []uuid.UUID{}
	}
	var result *AlertRuleRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.UpdateAlertRule(ctx, generated.UpdateAlertRuleParams{
			ID:                       id,
			OrgID:                    orgID,
			Name:                     p.Name,
			Logic:                    p.Logic,
			Conditions:               p.Conditions,
			WatchlistIds:             ids,
			HasEpssCondition:         p.HasEpssCondition,
			IsEpssOnly:               p.IsEpssOnly,
			FireOnNonMaterialChanges: p.FireOnNonMaterialChanges,
			Status:                   p.Status,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("update alert rule: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// SoftDeleteAlertRule soft-deletes an alert rule by setting deleted_at.
func (s *Store) SoftDeleteAlertRule(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.SoftDeleteAlertRule(ctx, generated.SoftDeleteAlertRuleParams{ID: id, OrgID: orgID})
	})
}

// SetAlertRuleStatus updates the status field of an alert rule.
func (s *Store) SetAlertRuleStatus(ctx context.Context, orgID, id uuid.UUID, status string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.SetAlertRuleStatus(ctx, generated.SetAlertRuleStatusParams{ID: id, OrgID: orgID, Status: status})
	})
}

// ListAlertRules returns a page of non-deleted alert rules for an org, ordered by
// created_at DESC, id DESC. An optional status filter limits results to matching rules.
// Caller passes Limit+1 to detect whether a next page exists.
func (s *Store) ListAlertRules(ctx context.Context, orgID uuid.UUID, status *string, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]AlertRuleRow, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.
		Select("id, org_id, name, logic, conditions, watchlist_ids, dsl_version, has_epss_condition, is_epss_only, status, fire_on_non_material_changes, created_at, updated_at, deleted_at").
		From("alert_rules").
		Where(sq.Eq{"org_id": orgID}).
		Where("deleted_at IS NULL").
		OrderBy("created_at DESC, id DESC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if status != nil {
		sb = sb.Where(sq.Eq{"status": *status})
	}
	if afterTime != nil && afterID != nil {
		sb = sb.Where("(created_at, id) < (?, ?)", *afterTime, *afterID)
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("list alert rules: build query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alert rules: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var result []generated.AlertRule
	for rows.Next() {
		var r generated.AlertRule
		if err := rows.Scan(
			&r.ID, &r.OrgID, &r.Name, &r.Logic, &r.Conditions,
			pq.Array(&r.WatchlistIds),
			&r.DslVersion, &r.HasEpssCondition, &r.IsEpssOnly,
			&r.Status, &r.FireOnNonMaterialChanges,
			&r.CreatedAt, &r.UpdatedAt, &r.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("list alert rules: scan: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// InsertAlertRuleRun records the start of an evaluation run. Worker path: uses bypass_rls.
func (s *Store) InsertAlertRuleRun(ctx context.Context, ruleID, orgID uuid.UUID, path string) (*generated.AlertRuleRun, error) {
	var run generated.AlertRuleRun
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		run, err = q.InsertAlertRuleRun(ctx, generated.InsertAlertRuleRunParams{
			RuleID: ruleID,
			OrgID:  orgID,
			Path:   path,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("insert alert rule run: %w", err)
	}
	return &run, nil
}

// UpdateAlertRuleRun records the completion of an evaluation run. Worker path: uses bypass_rls.
func (s *Store) UpdateAlertRuleRun(ctx context.Context, id uuid.UUID, status string, candidatesEvaluated, matchesFound int32, errorMsg *string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpdateAlertRuleRun(ctx, generated.UpdateAlertRuleRunParams{
			ID:                  id,
			Status:              status,
			CandidatesEvaluated: candidatesEvaluated,
			MatchesFound:        matchesFound,
			ErrorMessage:        nullString(errorMsg),
		})
	})
}

// InsertAlertEvent inserts a new alert event using exactly-once ON CONFLICT DO NOTHING semantics.
// Returns the new event ID, or uuid.Nil if the event already existed (duplicate suppressed).
func (s *Store) InsertAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		id, err = q.InsertAlertEvent(ctx, generated.InsertAlertEventParams{
			OrgID:            orgID,
			RuleID:           ruleID,
			CveID:            cveID,
			MaterialHash:     materialHash,
			SuppressDelivery: suppressDelivery,
		})
		if errors.Is(err, sql.ErrNoRows) {
			// ON CONFLICT DO NOTHING: event already exists for this (org, rule, cve, hash).
			id = uuid.Nil
			return nil
		}
		return err
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert alert event: %w", err)
	}
	return id, nil
}

// GetUnresolvedAlertEventCVEs returns the CVE IDs of alert events for ruleID that are
// currently in a matched state (last_match_state = true).
func (s *Store) GetUnresolvedAlertEventCVEs(ctx context.Context, ruleID, orgID uuid.UUID) ([]string, error) {
	var cveIDs []string
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		cveIDs, err = q.GetUnresolvedAlertEventCVEs(ctx, generated.GetUnresolvedAlertEventCVEsParams{
			RuleID: ruleID,
			OrgID:  orgID,
		})
		return err
	})
	return cveIDs, err
}

// ResolveAlertEvent marks a previously-matched alert event as no longer matching.
func (s *Store) ResolveAlertEvent(ctx context.Context, ruleID, orgID uuid.UUID, cveID string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.ResolveAlertEvent(ctx, generated.ResolveAlertEventParams{
			RuleID: ruleID,
			OrgID:  orgID,
			CveID:  cveID,
		})
	})
}

// ListAlertEvents returns a page of alert events for an org, with optional filters.
// Ordered by first_fired_at DESC, id DESC. Caller passes Limit+1 to detect next page.
func (s *Store) ListAlertEvents(ctx context.Context, orgID uuid.UUID, p ListAlertEventsParams) ([]generated.AlertEvent, error) {
	limit := p.Limit
	if limit <= 0 {
		limit = 100
	}
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.
		Select("id, rule_id, org_id, cve_id, material_hash, last_match_state, suppress_delivery, first_fired_at, last_fired_at, times_fired").
		From("alert_events").
		Where(sq.Eq{"org_id": orgID}).
		OrderBy("first_fired_at DESC, id DESC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if p.RuleID != nil {
		sb = sb.Where(sq.Eq{"rule_id": *p.RuleID})
	}
	if p.CveID != nil {
		sb = sb.Where(sq.Eq{"cve_id": *p.CveID})
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("list alert events: build query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alert events: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var result []generated.AlertEvent
	for rows.Next() {
		var e generated.AlertEvent
		if err := rows.Scan(
			&e.ID, &e.RuleID, &e.OrgID, &e.CveID, &e.MaterialHash,
			&e.LastMatchState, &e.SuppressDelivery,
			&e.FirstFiredAt, &e.LastFiredAt, &e.TimesFired,
		); err != nil {
			return nil, fmt.Errorf("list alert events: scan: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// ListActiveRulesForEvaluation returns all active non-EPSS-only rules across all orgs.
// Worker path only: uses bypass_rls; do not call from HTTP handlers.
func (s *Store) ListActiveRulesForEvaluation(ctx context.Context) ([]AlertRuleRow, error) {
	var rules []generated.AlertRule
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rules, err = q.ListActiveRulesForEvaluation(ctx)
		return err
	})
	return rules, err
}

// ListActiveRulesForEPSS returns all active rules with EPSS conditions across all orgs.
// Worker path only: uses bypass_rls; do not call from HTTP handlers.
func (s *Store) ListActiveRulesForEPSS(ctx context.Context) ([]AlertRuleRow, error) {
	var rules []generated.AlertRule
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rules, err = q.ListActiveRulesForEPSS(ctx)
		return err
	})
	return rules, err
}
