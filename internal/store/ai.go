// ABOUTME: Store methods for AI quota tracking, response caching, and request logging.
// ABOUTME: Wraps sqlc-generated queries with org-scoped and bypass-RLS transaction helpers.
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

// AIRequestLogEntry holds the fields for an AI request log insert.
type AIRequestLogEntry struct {
	OrgID         uuid.UUID
	UserID        uuid.UUID
	Feature       string
	InputHash     string
	PromptVersion string
	Model         string
	CacheHit      bool
	InputTokens   int
	OutputTokens  int
	LatencyMS     int
	Status        string
	ErrorType     string
}

// QuotaOverrideRow holds a single quota override row.
type QuotaOverrideRow struct {
	OrgID      uuid.UUID
	Feature    string
	DailyLimit int
}

// IncrementAIUsage increments the daily usage counter for an AI feature
// and returns the new count.
func (s *Store) IncrementAIUsage(ctx context.Context, orgID uuid.UUID, feature string) (int, error) {
	var count int32
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		count, err = q.IncrementAIUsage(ctx, generated.IncrementAIUsageParams{
			OrgID:   orgID,
			Feature: feature,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("increment ai usage: %w", err)
	}
	return int(count), nil
}

// DecrementAIUsage decrements the daily counter (floor 0) on LLM failure.
func (s *Store) DecrementAIUsage(ctx context.Context, orgID uuid.UUID, feature string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.DecrementAIUsage(ctx, generated.DecrementAIUsageParams{
			OrgID:   orgID,
			Feature: feature,
		})
	})
}

// UpdateAIUsageTokens adds token counts to the current day's usage entry.
func (s *Store) UpdateAIUsageTokens(ctx context.Context, orgID uuid.UUID, feature string, inputTokens, outputTokens int) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UpdateAIUsageTokens(ctx, generated.UpdateAIUsageTokensParams{
			OrgID:        orgID,
			Feature:      feature,
			InputTokens:  int32(inputTokens),  //nolint:gosec // G115: token counts are always small
			OutputTokens: int32(outputTokens), //nolint:gosec // G115: token counts are always small
		})
	})
}

// GetAIQuotaOverride returns the daily limit override. Returns (0, false, nil) if not set.
func (s *Store) GetAIQuotaOverride(ctx context.Context, orgID uuid.UUID, feature string) (int, bool, error) {
	var limit int32
	var found bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		limit, err = q.GetAIQuotaOverride(ctx, generated.GetAIQuotaOverrideParams{
			OrgID:   orgID,
			Feature: feature,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return int(limit), found, err
}

// SetAIQuotaOverride upserts a per-org quota override. Uses bypass TX (CLI path).
func (s *Store) SetAIQuotaOverride(ctx context.Context, orgID uuid.UUID, feature string, limit int) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.SetAIQuotaOverride(ctx, generated.SetAIQuotaOverrideParams{
			OrgID:      orgID,
			Feature:    feature,
			DailyLimit: int32(limit), //nolint:gosec // G115: daily limits are always small
		})
	})
}

// DeleteAIQuotaOverride removes a per-org override. Uses bypass TX.
func (s *Store) DeleteAIQuotaOverride(ctx context.Context, orgID uuid.UUID, feature string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.DeleteAIQuotaOverride(ctx, generated.DeleteAIQuotaOverrideParams{
			OrgID:   orgID,
			Feature: feature,
		})
	})
}

// ListAIQuotaOverrides returns all quota overrides across all orgs. Uses bypass TX (CLI/admin).
func (s *Store) ListAIQuotaOverrides(ctx context.Context) ([]QuotaOverrideRow, error) {
	var result []QuotaOverrideRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		rows, err := q.ListAIQuotaOverrides(ctx)
		if err != nil {
			return err
		}
		result = make([]QuotaOverrideRow, len(rows))
		for i, r := range rows {
			result[i] = QuotaOverrideRow{
				OrgID:      r.OrgID,
				Feature:    r.Feature,
				DailyLimit: int(r.DailyLimit),
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list ai quota overrides: %w", err)
	}
	return result, nil
}

// ListAIQuotaOverridesForOrg returns all quota overrides for a specific org.
// Uses bypass TX (CLI/admin path — org may not be the caller's org).
func (s *Store) ListAIQuotaOverridesForOrg(ctx context.Context, orgID uuid.UUID) ([]QuotaOverrideRow, error) {
	var result []QuotaOverrideRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		rows, err := q.ListAIQuotaOverridesForOrg(ctx, orgID)
		if err != nil {
			return err
		}
		result = make([]QuotaOverrideRow, len(rows))
		for i, r := range rows {
			result[i] = QuotaOverrideRow{
				OrgID:      orgID,
				Feature:    r.Feature,
				DailyLimit: int(r.DailyLimit),
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list ai quota overrides for org: %w", err)
	}
	return result, nil
}

// GetAICache returns a cached response if one exists and has not expired.
// Returns (nil, false, nil) on cache miss.
func (s *Store) GetAICache(ctx context.Context, orgID uuid.UUID, feature, promptVersion, inputHash string) (json.RawMessage, bool, error) {
	var resp json.RawMessage
	var found bool
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		resp, err = q.GetAICache(ctx, generated.GetAICacheParams{
			OrgID:         orgID,
			Feature:       feature,
			PromptVersion: promptVersion,
			InputHash:     inputHash,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return resp, found, err
}

// PutAICache upserts a cached AI response with the given TTL.
func (s *Store) PutAICache(ctx context.Context, orgID uuid.UUID, feature, promptVersion, inputHash string, response json.RawMessage, ttl time.Duration) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.PutAICache(ctx, generated.PutAICacheParams{
			OrgID:         orgID,
			Feature:       feature,
			PromptVersion: promptVersion,
			InputHash:     inputHash,
			Response:      response,
			Secs:          ttl.Seconds(),
		})
	})
}

// InsertAIRequestLog records an AI request for observability. Uses org TX.
func (s *Store) InsertAIRequestLog(ctx context.Context, entry AIRequestLogEntry) error {
	return s.withOrgTx(ctx, entry.OrgID, func(q *generated.Queries) error {
		return q.InsertAIRequestLog(ctx, generated.InsertAIRequestLogParams{
			OrgID:         entry.OrgID,
			UserID:        entry.UserID,
			Feature:       entry.Feature,
			InputHash:     entry.InputHash,
			PromptVersion: entry.PromptVersion,
			Model:         entry.Model,
			CacheHit:      entry.CacheHit,
			InputTokens:   toNullInt32(entry.InputTokens),
			OutputTokens:  toNullInt32(entry.OutputTokens),
			LatencyMs:     int32(entry.LatencyMS), //nolint:gosec // G115: latency in ms fits int32
			Status:        entry.Status,
			ErrorType:     toNullString(entry.ErrorType),
		})
	})
}


// toNullInt32 converts an int to sql.NullInt32; zero maps to NULL.
func toNullInt32(v int) sql.NullInt32 {
	if v == 0 {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: int32(v), Valid: true} //nolint:gosec // G115: token counts fit int32
}

// toNullString converts a string to sql.NullString; empty maps to NULL.
func toNullString(v string) sql.NullString {
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}
