// ABOUTME: Store methods for notification channel CRUD and secret rotation.
// ABOUTME: Signing secrets are excluded from API-facing methods; only GetNotificationChannelForDelivery includes them.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// NotificationChannelRow is the notification channel record returned by store methods
// that do not include secrets.
type NotificationChannelRow = generated.GetNotificationChannelRow

// NotificationChannelForDeliveryRow is the notification channel record returned by
// GetNotificationChannelForDelivery — includes signing secrets for the delivery worker.
type NotificationChannelForDeliveryRow = generated.GetNotificationChannelForDeliveryRow

// UpdateNotificationChannelParams holds the mutable fields for updating a notification channel.
type UpdateNotificationChannelParams struct {
	Name   string
	Config json.RawMessage
}

// NotificationChannelStore defines the DB operations for notification channel management.
type NotificationChannelStore interface {
	CreateNotificationChannel(ctx context.Context, orgID uuid.UUID, name, chanType string, config json.RawMessage) (*generated.CreateNotificationChannelRow, string, error)
	GetNotificationChannel(ctx context.Context, orgID, id uuid.UUID) (*NotificationChannelRow, error)
	GetNotificationChannelForDelivery(ctx context.Context, id uuid.UUID) (*NotificationChannelForDeliveryRow, error)
	ListNotificationChannels(ctx context.Context, orgID uuid.UUID) ([]generated.ListNotificationChannelsRow, error)
	UpdateNotificationChannel(ctx context.Context, orgID, id uuid.UUID, p UpdateNotificationChannelParams) (*generated.UpdateNotificationChannelRow, error)
	SoftDeleteNotificationChannel(ctx context.Context, orgID, id uuid.UUID) error
	RotateSigningSecret(ctx context.Context, orgID, id uuid.UUID) (string, error)
	ClearSecondarySecret(ctx context.Context, orgID, id uuid.UUID) error
	ChannelHasActiveBoundRules(ctx context.Context, orgID, id uuid.UUID) (bool, error)
}

// generateSigningSecret returns a 32-byte crypto-random value encoded as a hex string.
func generateSigningSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate signing secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateNotificationChannel inserts a new notification channel with a server-generated
// signing secret. Returns the created row and the raw secret (shown to the caller once).
func (s *Store) CreateNotificationChannel(ctx context.Context, orgID uuid.UUID, name, chanType string, config json.RawMessage) (*generated.CreateNotificationChannelRow, string, error) {
	secret, err := generateSigningSecret()
	if err != nil {
		return nil, "", err
	}
	var row generated.CreateNotificationChannelRow
	err = s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateNotificationChannel(ctx, generated.CreateNotificationChannelParams{
			OrgID:         orgID,
			Name:          name,
			Type:          chanType,
			Config:        config,
			SigningSecret: secret,
		})
		return err
	})
	if err != nil {
		return nil, "", fmt.Errorf("create notification channel: %w", err)
	}
	return &row, secret, nil
}

// GetNotificationChannel returns the channel with the given id within orgID,
// or (nil, nil) if not found or soft-deleted. Signing secrets are not included.
func (s *Store) GetNotificationChannel(ctx context.Context, orgID, id uuid.UUID) (*NotificationChannelRow, error) {
	var result *NotificationChannelRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetNotificationChannel(ctx, generated.GetNotificationChannelParams{
			ID:    id,
			OrgID: orgID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get notification channel: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// GetNotificationChannelForDelivery returns the channel with secrets for the delivery worker.
// Uses bypass RLS — caller must be the delivery worker, not an HTTP handler.
// Returns (nil, nil) if not found or soft-deleted.
func (s *Store) GetNotificationChannelForDelivery(ctx context.Context, id uuid.UUID) (*NotificationChannelForDeliveryRow, error) {
	var result *NotificationChannelForDeliveryRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetNotificationChannelForDelivery(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get notification channel for delivery: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// ListNotificationChannels returns all non-deleted channels for an org, ordered by
// created_at DESC, id DESC.
func (s *Store) ListNotificationChannels(ctx context.Context, orgID uuid.UUID) ([]generated.ListNotificationChannelsRow, error) {
	var result []generated.ListNotificationChannelsRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ListNotificationChannels(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list notification channels: %w", err)
	}
	return result, nil
}

// UpdateNotificationChannel updates the mutable fields of a notification channel.
// Returns (nil, nil) if the channel is not found or has been soft-deleted.
func (s *Store) UpdateNotificationChannel(ctx context.Context, orgID, id uuid.UUID, p UpdateNotificationChannelParams) (*generated.UpdateNotificationChannelRow, error) {
	var result *generated.UpdateNotificationChannelRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.UpdateNotificationChannel(ctx, generated.UpdateNotificationChannelParams{
			ID:     id,
			OrgID:  orgID,
			Name:   p.Name,
			Config: p.Config,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("update notification channel: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// SoftDeleteNotificationChannel soft-deletes a channel by setting deleted_at.
func (s *Store) SoftDeleteNotificationChannel(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.SoftDeleteNotificationChannel(ctx, generated.SoftDeleteNotificationChannelParams{
			ID:    id,
			OrgID: orgID,
		}); err != nil {
			return fmt.Errorf("soft delete notification channel: %w", err)
		}
		return nil
	})
}

// RotateSigningSecret atomically promotes the current primary secret to secondary
// and sets a new primary. Returns the new primary secret.
// Returns ("", nil) if the channel is not found or soft-deleted.
func (s *Store) RotateSigningSecret(ctx context.Context, orgID, id uuid.UUID) (string, error) {
	newSecret, err := generateSigningSecret()
	if err != nil {
		return "", err
	}
	var result string
	err = s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		returned, err := q.RotateSigningSecret(ctx, generated.RotateSigningSecretParams{
			ID:            id,
			OrgID:         orgID,
			SigningSecret: newSecret,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("rotate signing secret: %w", err)
		}
		result = returned
		return nil
	})
	return result, err
}

// ClearSecondarySecret removes the secondary signing secret after the grace period.
func (s *Store) ClearSecondarySecret(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.ClearSecondarySecret(ctx, generated.ClearSecondarySecretParams{
			ID:    id,
			OrgID: orgID,
		}); err != nil {
			return fmt.Errorf("clear secondary secret: %w", err)
		}
		return nil
	})
}

// ChannelHasActiveBoundRules returns true if any active alert rules reference this channel.
// Used as a pre-flight check before soft-deleting a channel.
func (s *Store) ChannelHasActiveBoundRules(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	var result bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ChannelHasActiveBoundRules(ctx, generated.ChannelHasActiveBoundRulesParams{
			ChannelID: id,
			OrgID:     orgID,
		})
		return err
	})
	if err != nil {
		return false, fmt.Errorf("channel has active bound rules: %w", err)
	}
	return result, nil
}
