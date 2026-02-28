// ABOUTME: Store methods for alert rule ↔ notification channel M:M bindings.
// ABOUTME: Hard-delete join table; no soft-delete. Fanout uses bypass RLS (worker path).
package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// AlertRuleChannelStore defines the DB operations for the alert rule ↔ channel join table.
type AlertRuleChannelStore interface {
	BindChannelToRule(ctx context.Context, ruleID, channelID, orgID uuid.UUID) error
	UnbindChannelFromRule(ctx context.Context, ruleID, channelID, orgID uuid.UUID) error
	ListChannelsForRule(ctx context.Context, ruleID, orgID uuid.UUID) ([]generated.ListChannelsForRuleRow, error)
	ListActiveChannelsForFanout(ctx context.Context, ruleID, orgID uuid.UUID) ([]generated.ListActiveChannelsForFanoutRow, error)
	ChannelRuleBindingExists(ctx context.Context, ruleID, channelID, orgID uuid.UUID) (bool, error)
}

// BindChannelToRule adds a channel to an alert rule. Idempotent: a duplicate bind is silently ignored.
func (s *Store) BindChannelToRule(ctx context.Context, ruleID, channelID, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.BindChannelToRule(ctx, generated.BindChannelToRuleParams{
			RuleID:    ruleID,
			ChannelID: channelID,
			OrgID:     orgID,
		}); err != nil {
			return fmt.Errorf("bind channel to rule: %w", err)
		}
		return nil
	})
}

// UnbindChannelFromRule removes a channel from an alert rule. No-op if the binding does not exist.
func (s *Store) UnbindChannelFromRule(ctx context.Context, ruleID, channelID, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.UnbindChannelFromRule(ctx, generated.UnbindChannelFromRuleParams{
			RuleID:    ruleID,
			ChannelID: channelID,
			OrgID:     orgID,
		}); err != nil {
			return fmt.Errorf("unbind channel from rule: %w", err)
		}
		return nil
	})
}

// ListChannelsForRule returns all non-deleted notification channels bound to a rule,
// ordered by binding creation time ascending.
func (s *Store) ListChannelsForRule(ctx context.Context, ruleID, orgID uuid.UUID) ([]generated.ListChannelsForRuleRow, error) {
	var result []generated.ListChannelsForRuleRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ListChannelsForRule(ctx, generated.ListChannelsForRuleParams{
			RuleID: ruleID,
			OrgID:  orgID,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list channels for rule: %w", err)
	}
	return result, nil
}

// ListActiveChannelsForFanout returns channel config and signing secrets for all non-deleted
// channels bound to a rule. Uses bypass RLS — must only be called from the evaluator worker,
// never from API handlers.
func (s *Store) ListActiveChannelsForFanout(ctx context.Context, ruleID, orgID uuid.UUID) ([]generated.ListActiveChannelsForFanoutRow, error) {
	var result []generated.ListActiveChannelsForFanoutRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		result, err = q.ListActiveChannelsForFanout(ctx, generated.ListActiveChannelsForFanoutParams{
			RuleID: ruleID,
			OrgID:  orgID,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list active channels for fanout: %w", err)
	}
	return result, nil
}

// ChannelRuleBindingExists returns true if the given channel is bound to the given rule
// within the org.
func (s *Store) ChannelRuleBindingExists(ctx context.Context, ruleID, channelID, orgID uuid.UUID) (bool, error) {
	var result bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ChannelRuleBindingExists(ctx, generated.ChannelRuleBindingExistsParams{
			RuleID:    ruleID,
			ChannelID: channelID,
			OrgID:     orgID,
		})
		return err
	})
	if err != nil {
		return false, fmt.Errorf("channel rule binding exists: %w", err)
	}
	return result, nil
}
