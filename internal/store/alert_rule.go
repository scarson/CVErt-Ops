// ABOUTME: Store methods for alert rule, run, and event management.
// ABOUTME: Org-scoped methods use withOrgTx; cross-org worker methods use withBypassTx.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/dbutil"
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
	RuleID         *uuid.UUID
	CveID          *string
	LastMatchState *bool
	Since          *time.Time
	AfterTime      *time.Time
	AfterID        *uuid.UUID
	Limit          int
	// ExpandCVE adds each event's CVE fields (AlertEventListRow.CVE) in the same query.
	ExpandCVE bool
	// ExpandRule adds each event's rule name and matching watchlist items (AlertEventListRow.Rule).
	ExpandRule bool
	// Ascending lists in feed order, feed_seq ascending, starting after AfterSeq when it
	// is set. Positions become visible in position order (see LockAlertEventFeed), so a
	// poller that resumes from the last row's FeedSeq sees each fire exactly once.
	// AfterTime and AfterID are ignored.
	Ascending bool
	AfterSeq  *int64
}

// AlertEventListRow is an alert event with the context ListAlertEvents was asked to expand.
type AlertEventListRow struct {
	generated.AlertEvent
	// CVE is set when ExpandCVE was asked for and the CVE is in the corpus.
	CVE *AlertEventCVE
	// Rule is set when ExpandRule was asked for.
	Rule *AlertEventRule
}

// AlertEventCVE is the CVE context of an alert event, read when the list is.
type AlertEventCVE struct {
	Status      *string
	Severity    *string // as the feed sent it
	CVSSv3Score *float64
	CVSSv4Score *float64
	InCISAKEV   bool
	EPSSScore   *float64
}

// AlertEventRule is the rule context of an alert event.
type AlertEventRule struct {
	Name    string
	Deleted bool
	// WatchlistMatches are the live items of the rule's watchlists that match the
	// event's CVE now, by the same conditions rule evaluation uses. Empty for a rule
	// with no watchlists.
	WatchlistMatches []AlertEventWatchlistMatch
}

// AlertEventWatchlistMatch is one watchlist item that matches an alert event's CVE.
// The fields set depend on ItemType: CveID for cve, Ecosystem and PackageName
// (and Namespace when given) for package, CPE for cpe.
type AlertEventWatchlistMatch struct {
	WatchlistID uuid.UUID `json:"watchlist_id"`
	ItemID      uuid.UUID `json:"item_id"`
	ItemType    string    `json:"item_type"`
	CveID       *string   `json:"cve_id"`
	Ecosystem   *string   `json:"ecosystem"`
	PackageName *string   `json:"package_name"`
	Namespace   *string   `json:"namespace"`
	CPE         *string   `json:"cpe"`
}

// AlertRuleStore defines the DB operations for alert rule, run, and event management.
type AlertRuleStore interface {
	CreateAlertRule(ctx context.Context, orgID uuid.UUID, p CreateAlertRuleParams) (*AlertRuleRow, error)
	GetAlertRule(ctx context.Context, orgID, id uuid.UUID) (*AlertRuleRow, error)
	UpdateAlertRule(ctx context.Context, orgID, id uuid.UUID, p UpdateAlertRuleParams) (*AlertRuleRow, error)
	SoftDeleteAlertRule(ctx context.Context, orgID, id uuid.UUID) error
	SetAlertRuleStatus(ctx context.Context, orgID, id uuid.UUID, status string) error
	SetAlertRuleStatusIf(ctx context.Context, orgID, id uuid.UUID, newStatus, requiredCurrentStatus string) (bool, error)
	ListAlertRules(ctx context.Context, orgID uuid.UUID, status *string, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]AlertRuleRow, error)
	InsertAlertRuleRun(ctx context.Context, ruleID, orgID uuid.UUID, path string) (*generated.AlertRuleRun, error)
	UpdateAlertRuleRun(ctx context.Context, id uuid.UUID, status string, candidatesEvaluated, matchesFound int32, errorMsg *string) error
	InsertAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error)
	ReopenAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error)
	GetUnresolvedAlertEventCVEs(ctx context.Context, ruleID, orgID uuid.UUID) ([]string, error)
	ResolveAlertEvent(ctx context.Context, ruleID, orgID uuid.UUID, cveID string) (bool, error)
	ListAlertEvents(ctx context.Context, orgID uuid.UUID, p ListAlertEventsParams) ([]AlertEventListRow, error)
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

// SetAlertRuleStatusIf updates the status field only if the current status matches
// requiredCurrentStatus. Returns true if the row was updated, false if the precondition
// did not match (e.g. user disabled the rule during activation).
func (s *Store) SetAlertRuleStatusIf(ctx context.Context, orgID, id uuid.UUID, newStatus, requiredCurrentStatus string) (bool, error) {
	var updated bool
	err := s.withOrgRawTx(ctx, orgID, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx,
			`UPDATE alert_rules SET status = $1, updated_at = now()
			 WHERE id = $2 AND org_id = $3 AND status = $4 AND deleted_at IS NULL`,
			newStatus, id, orgID, requiredCurrentStatus)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		updated = n > 0
		return nil
	})
	return updated, err
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

	var result []generated.AlertRule
	err = s.withOrgRawTx(ctx, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list alert rules: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var r generated.AlertRule
			if err := rows.Scan(
				&r.ID, &r.OrgID, &r.Name, &r.Logic, &r.Conditions,
				pq.Array(&r.WatchlistIds),
				&r.DslVersion, &r.HasEpssCondition, &r.IsEpssOnly,
				&r.Status, &r.FireOnNonMaterialChanges,
				&r.CreatedAt, &r.UpdatedAt, &r.DeletedAt,
			); err != nil {
				return fmt.Errorf("list alert rules: scan: %w", err)
			}
			result = append(result, r)
		}
		return rows.Err()
	})
	return result, err
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
			ErrorMessage:        dbutil.NullStringPtr(errorMsg),
		})
	})
}

// InsertAlertEvent inserts a new alert event using exactly-once ON CONFLICT DO NOTHING semantics.
// Returns the new event ID, or uuid.Nil if the event already existed (duplicate suppressed).
// Worker path: uses bypass_rls since this is called from the alert evaluator.
func (s *Store) InsertAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		if err := q.LockAlertEventFeed(ctx, orgID); err != nil {
			return fmt.Errorf("lock alert event feed: %w", err)
		}
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

// ReopenAlertEvent marks a resolved alert event open again when its CVE matches the rule
// at a material_hash the rule already fired on. It returns the event's ID only to the
// caller whose update changed the state, and uuid.Nil if the event is already open or does
// not exist. Postgres re-checks the state after waiting on the row lock, so concurrent
// evaluators cannot both receive an ID. suppressDelivery replaces the stored value: delivery
// recovery reads it, and the reopen, not the original fire, decides whether to notify.
// Worker path: uses bypass_rls since this is called from the alert evaluator.
func (s *Store) ReopenAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		// The feed lock comes before the row lock: an insert of the same event holds
		// the feed lock and can wait on this row, so the reverse order could deadlock.
		if err := q.LockAlertEventFeed(ctx, orgID); err != nil {
			return fmt.Errorf("lock alert event feed: %w", err)
		}
		var err error
		id, err = q.ReopenAlertEvent(ctx, generated.ReopenAlertEventParams{
			OrgID:            orgID,
			RuleID:           ruleID,
			CveID:            cveID,
			MaterialHash:     materialHash,
			SuppressDelivery: suppressDelivery,
		})
		if errors.Is(err, sql.ErrNoRows) {
			id = uuid.Nil
			return nil
		}
		return err
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("reopen alert event: %w", err)
	}
	return id, nil
}

// GetUnresolvedAlertEventCVEs returns the CVE IDs of alert events for ruleID that are
// currently in a matched state (last_match_state = true).
// Worker path: uses bypass_rls since this is called from the alert evaluator.
func (s *Store) GetUnresolvedAlertEventCVEs(ctx context.Context, ruleID, orgID uuid.UUID) ([]string, error) {
	var cveIDs []string
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		cveIDs, err = q.GetUnresolvedAlertEventCVEs(ctx, generated.GetUnresolvedAlertEventCVEsParams{
			RuleID: ruleID,
			OrgID:  orgID,
		})
		return err
	})
	return cveIDs, err
}

// ResolveAlertEvent marks every still-matching alert event for the CVE as no longer
// matching. It reports whether the rule's channels should be told: true only when this
// call changed a row and at least one changed row was delivered. Of any number of
// concurrent callers, only the first changes rows, so a CVE resolves with one notification.
// Activation-scan events are not delivered, so resolving only those reports false.
// Worker path: uses bypass_rls since this is called from the alert evaluator.
func (s *Store) ResolveAlertEvent(ctx context.Context, ruleID, orgID uuid.UUID, cveID string) (bool, error) {
	var suppressed []bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		// The feed lock comes before the row locks, as in ReopenAlertEvent.
		if err := q.LockAlertEventFeed(ctx, orgID); err != nil {
			return fmt.Errorf("lock alert event feed: %w", err)
		}
		var err error
		suppressed, err = q.ResolveAlertEvent(ctx, generated.ResolveAlertEventParams{
			RuleID: ruleID,
			OrgID:  orgID,
			CveID:  cveID,
		})
		return err
	})
	if err != nil {
		return false, err
	}
	return slices.Contains(suppressed, false), nil
}

// alertEventWatchlistMatchesSQL aggregates the live items of rule r's watchlists that
// match event ae's CVE, using the conditions rule evaluation uses. The explicit org_id
// predicate keeps another org's watchlist out even if a rule names it; RLS does too.
var alertEventWatchlistMatchesSQL = `LEFT JOIN LATERAL (
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'watchlist_id', wi.watchlist_id, 'item_id', wi.id, 'item_type', wi.item_type::text,
               'cve_id', wi.cve_id, 'ecosystem', wi.ecosystem, 'package_name', wi.package_name,
               'namespace', wi.namespace, 'cpe', wi.cpe_normalized)
             ORDER BY wi.created_at, wi.id), '[]'::jsonb) AS matches
    FROM watchlist_items wi
    WHERE wi.watchlist_id = ANY(r.watchlist_ids)
      AND wi.org_id = ae.org_id
      AND wi.deleted_at IS NULL
      AND (
        (wi.item_type = 'cve' AND wi.cve_id = ae.cve_id)
        OR (wi.item_type = 'package' AND EXISTS (
            SELECT 1 FROM cve_affected_packages cap
            WHERE cap.cve_id = ae.cve_id AND ` + dsl.WatchlistPackageMatchSQL("cap", "wi") + `))
        OR (wi.item_type = 'cpe' AND EXISTS (
            SELECT 1 FROM cve_affected_cpes cac
            WHERE cac.cve_id = ae.cve_id AND ` + dsl.WatchlistCPEMatchSQL("cac", "wi") + `))
      )
) m ON true`

// ListAlertEvents returns a page of alert events for an org, with optional filters.
// Ordered by first_fired_at DESC, id DESC, or in feed order when p.Ascending is set.
// A descending caller passes Limit+1 to detect a next page. ExpandCVE and ExpandRule add context from
// cves, alert_rules and watchlist_items in the same query.
func (s *Store) ListAlertEvents(ctx context.Context, orgID uuid.UUID, p ListAlertEventsParams) ([]AlertEventListRow, error) {
	limit := p.Limit
	if limit <= 0 {
		limit = 100
	}
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.
		Select("ae.id, ae.rule_id, ae.org_id, ae.cve_id, ae.material_hash, ae.last_match_state, ae.suppress_delivery, ae.first_fired_at, ae.last_fired_at, ae.times_fired, ae.feed_seq").
		From("alert_events ae").
		Where(sq.Eq{"ae.org_id": orgID}).
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if p.Ascending {
		sb = sb.OrderBy("ae.feed_seq")
		if p.AfterSeq != nil {
			sb = sb.Where(sq.Gt{"ae.feed_seq": *p.AfterSeq})
		}
	} else {
		sb = sb.OrderBy("ae.first_fired_at DESC, ae.id DESC")
		if p.AfterTime != nil && p.AfterID != nil {
			sb = sb.Where("(ae.first_fired_at, ae.id) < (?, ?)", *p.AfterTime, *p.AfterID)
		}
	}

	if p.ExpandCVE {
		sb = sb.Columns("c.cve_id IS NOT NULL", "c.status", "c.severity", "c.cvss_v3_score", "c.cvss_v4_score", "COALESCE(c.in_cisa_kev, false)", "c.epss_score").
			LeftJoin("cves c ON c.cve_id = ae.cve_id")
	}
	if p.ExpandRule {
		sb = sb.Columns("r.id IS NOT NULL", "COALESCE(r.name, '')", "r.deleted_at IS NOT NULL", "m.matches").
			LeftJoin("alert_rules r ON r.id = ae.rule_id AND r.org_id = ae.org_id").
			JoinClause(alertEventWatchlistMatchesSQL)
	}
	if p.RuleID != nil {
		sb = sb.Where(sq.Eq{"ae.rule_id": *p.RuleID})
	}
	if p.CveID != nil {
		sb = sb.Where(sq.Eq{"ae.cve_id": *p.CveID})
	}
	if p.LastMatchState != nil {
		sb = sb.Where(sq.Eq{"ae.last_match_state": *p.LastMatchState})
	}
	if p.Since != nil {
		sb = sb.Where(sq.GtOrEq{"ae.last_fired_at": *p.Since})
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("list alert events: build query: %w", err)
	}

	var result []AlertEventListRow
	err = s.withOrgRawTx(ctx, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list alert events: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var e AlertEventListRow
			dest := []any{
				&e.ID, &e.RuleID, &e.OrgID, &e.CveID, &e.MaterialHash,
				&e.LastMatchState, &e.SuppressDelivery,
				&e.FirstFiredAt, &e.LastFiredAt, &e.TimesFired, &e.FeedSeq,
			}
			var (
				cveFound, ruleFound bool
				cve                 AlertEventCVE
				rule                AlertEventRule
				matches             []byte
			)
			if p.ExpandCVE {
				dest = append(dest, &cveFound, &cve.Status, &cve.Severity, &cve.CVSSv3Score, &cve.CVSSv4Score, &cve.InCISAKEV, &cve.EPSSScore)
			}
			if p.ExpandRule {
				dest = append(dest, &ruleFound, &rule.Name, &rule.Deleted, &matches)
			}
			if err := rows.Scan(dest...); err != nil {
				return fmt.Errorf("list alert events: scan: %w", err)
			}
			if cveFound {
				e.CVE = &cve
			}
			if ruleFound {
				if err := json.Unmarshal(matches, &rule.WatchlistMatches); err != nil {
					return fmt.Errorf("list alert events: decode watchlist matches: %w", err)
				}
				e.Rule = &rule
			}
			result = append(result, e)
		}
		return rows.Err()
	})
	return result, err
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
