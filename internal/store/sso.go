// ABOUTME: Store methods for SSO connection and email domain CRUD.
// ABOUTME: SSO connections are org-scoped (one per org); email domains are globally unique.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// SSOConnectionRow is the SSO connection record returned by store methods.
type SSOConnectionRow = generated.SsoConnection

// LookupSSOByDomainRow is the SSO connection info returned by domain lookup.
type LookupSSOByDomainRow = generated.LookupSSOByDomainRow

// CreateSSOConnection inserts a new SSO connection for an org.
// Returns error if org already has a connection (UNIQUE constraint on org_id).
func (s *Store) CreateSSOConnection(ctx context.Context, orgID uuid.UUID, displayName, issuerURL, clientID string, clientSecretEnc []byte, scopes []string, enabled bool) (*SSOConnectionRow, error) {
	if scopes == nil {
		scopes = []string{"openid", "profile", "email"}
	}
	var row SSOConnectionRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateSSOConnection(ctx, generated.CreateSSOConnectionParams{
			OrgID:           orgID,
			DisplayName:     displayName,
			IssuerUrl:       issuerURL,
			ClientID:        clientID,
			ClientSecretEnc: clientSecretEnc,
			Scopes:          scopes,
			Enabled:         enabled,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create sso connection: %w", err)
	}
	return &row, nil
}

// GetSSOConnection returns the SSO connection for the given org, or (nil, nil) if none exists.
func (s *Store) GetSSOConnection(ctx context.Context, orgID uuid.UUID) (*SSOConnectionRow, error) {
	var result *SSOConnectionRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetSSOConnection(ctx, orgID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get sso connection: %w", err)
	}
	return result, nil
}

// UpdateSSOConnection updates all mutable fields of the org's SSO connection.
func (s *Store) UpdateSSOConnection(ctx context.Context, orgID uuid.UUID, displayName, issuerURL, clientID string, clientSecretEnc []byte, scopes []string, enabled bool) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UpdateSSOConnection(ctx, generated.UpdateSSOConnectionParams{
			OrgID:           orgID,
			DisplayName:     displayName,
			IssuerUrl:       issuerURL,
			ClientID:        clientID,
			ClientSecretEnc: clientSecretEnc,
			Scopes:          scopes,
			Enabled:         enabled,
		})
	})
}

// DeleteSSOConnection removes the org's SSO connection (cascades to email domains).
func (s *Store) DeleteSSOConnection(ctx context.Context, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.DeleteSSOConnection(ctx, orgID)
	})
}

// SetSSOEmailDomains replaces all email domains for a connection (delete all, insert new).
func (s *Store) SetSSOEmailDomains(ctx context.Context, connectionID, orgID uuid.UUID, domains []string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.DeleteSSOEmailDomains(ctx, connectionID); err != nil {
			return fmt.Errorf("delete old domains: %w", err)
		}
		for _, domain := range domains {
			if err := q.UpsertSSOEmailDomain(ctx, generated.UpsertSSOEmailDomainParams{
				Domain:          domain,
				SsoConnectionID: connectionID,
				OrgID:           orgID,
			}); err != nil {
				return fmt.Errorf("insert domain %q: %w", domain, err)
			}
		}
		return nil
	})
}

// ListSSOEmailDomains returns all domains for a connection, sorted alphabetically.
func (s *Store) ListSSOEmailDomains(ctx context.Context, orgID, connectionID uuid.UUID) ([]string, error) {
	var result []string
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ListSSOEmailDomains(ctx, connectionID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list sso email domains: %w", err)
	}
	return result, nil
}

// LookupSSOByDomain finds the enabled SSO connection for an email domain.
// Returns (nil, nil) if no match or connection is disabled.
func (s *Store) LookupSSOByDomain(ctx context.Context, domain string) (*LookupSSOByDomainRow, error) {
	var result *LookupSSOByDomainRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.LookupSSOByDomain(ctx, domain)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("lookup sso by domain: %w", err)
	}
	return result, nil
}

// GetSSOConnectionByID returns the SSO connection with the given ID.
// Returns (nil, nil) if not found. Uses bypass RLS — for auth-path lookups.
func (s *Store) GetSSOConnectionByID(ctx context.Context, id uuid.UUID) (*SSOConnectionRow, error) {
	var result *SSOConnectionRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetSSOConnectionByID(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get sso connection by id: %w", err)
	}
	return result, nil
}
