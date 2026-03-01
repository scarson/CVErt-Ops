// ABOUTME: Store methods for scheduled report ↔ notification channel M:M bindings.
// ABOUTME: Hard-delete join table; mirrors alert_rule_channels pattern. Digest runner uses bypass RLS.
package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// BindChannelToReport adds a channel to a scheduled report. Idempotent: a duplicate bind is silently ignored.
func (s *Store) BindChannelToReport(ctx context.Context, orgID, reportID, channelID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.BindChannelToReport(ctx, generated.BindChannelToReportParams{
			ReportID:  reportID,
			ChannelID: channelID,
			OrgID:     orgID,
		}); err != nil {
			return fmt.Errorf("bind channel to report: %w", err)
		}
		return nil
	})
}

// UnbindChannelFromReport removes a channel from a scheduled report. No-op if the binding does not exist.
func (s *Store) UnbindChannelFromReport(ctx context.Context, orgID, reportID, channelID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.UnbindChannelFromReport(ctx, generated.UnbindChannelFromReportParams{
			ReportID:  reportID,
			ChannelID: channelID,
			OrgID:     orgID,
		}); err != nil {
			return fmt.Errorf("unbind channel from report: %w", err)
		}
		return nil
	})
}

// ListChannelsForReport returns all non-deleted notification channels bound to a report,
// ordered by binding creation time ascending.
func (s *Store) ListChannelsForReport(ctx context.Context, orgID, reportID uuid.UUID) ([]generated.ListChannelsForReportRow, error) {
	var result []generated.ListChannelsForReportRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ListChannelsForReport(ctx, generated.ListChannelsForReportParams{
			ReportID: reportID,
			OrgID:    orgID,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list channels for report: %w", err)
	}
	return result, nil
}

// ListActiveChannelsForDigest returns channel config and signing secrets for all non-deleted
// channels bound to a report. Uses bypass RLS — must only be called from the digest runner,
// never from API handlers.
func (s *Store) ListActiveChannelsForDigest(ctx context.Context, orgID, reportID uuid.UUID) ([]generated.ListActiveChannelsForDigestRow, error) {
	var result []generated.ListActiveChannelsForDigestRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		result, err = q.ListActiveChannelsForDigest(ctx, generated.ListActiveChannelsForDigestParams{
			ReportID: reportID,
			OrgID:    orgID,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list active channels for digest: %w", err)
	}
	return result, nil
}

// ReportChannelBindingExists returns true if the given channel is bound to the given report
// within the org.
func (s *Store) ReportChannelBindingExists(ctx context.Context, orgID, reportID, channelID uuid.UUID) (bool, error) {
	var result bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ReportChannelBindingExists(ctx, generated.ReportChannelBindingExistsParams{
			ReportID:  reportID,
			ChannelID: channelID,
			OrgID:     orgID,
		})
		return err
	})
	if err != nil {
		return false, fmt.Errorf("report channel binding exists: %w", err)
	}
	return result, nil
}

// ChannelHasActiveBoundReports returns true if the channel is bound to any active scheduled report.
// Used as a pre-flight check before soft-deleting a channel.
func (s *Store) ChannelHasActiveBoundReports(ctx context.Context, orgID, channelID uuid.UUID) (bool, error) {
	var result bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ChannelHasActiveBoundReports(ctx, generated.ChannelHasActiveBoundReportsParams{
			ChannelID: channelID,
			OrgID:     orgID,
		})
		return err
	})
	if err != nil {
		return false, fmt.Errorf("channel has active bound reports: %w", err)
	}
	return result, nil
}

// ChannelHasActiveBindings returns true if the channel is bound to any active
// alert rule OR active digest report. Used as pre-flight check before soft-delete.
func (s *Store) ChannelHasActiveBindings(ctx context.Context, orgID, channelID uuid.UUID) (bool, error) {
	hasRules, err := s.ChannelHasActiveBoundRules(ctx, orgID, channelID)
	if err != nil {
		return false, err
	}
	if hasRules {
		return true, nil
	}
	return s.ChannelHasActiveBoundReports(ctx, orgID, channelID)
}
