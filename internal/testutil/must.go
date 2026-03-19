// ABOUTME: Must-style test helpers that call t.Fatalf on error instead of returning errors.
// ABOUTME: Eliminates the widespread `x, _ := s.Create*(...)` anti-pattern in test setup code.
package testutil

import (
	"context"
	"testing"

	"github.com/google/uuid"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// MustCreateOrg creates an org or fatals the test.
func (tdb *TestDB) MustCreateOrg(t *testing.T, ctx context.Context, name string) *generated.Organization {
	t.Helper()
	org, err := tdb.CreateOrg(ctx, name)
	if err != nil {
		t.Fatalf("setup: CreateOrg(%q): %v", name, err)
	}
	return org
}

// MustCreateUser creates a user or fatals the test.
func (tdb *TestDB) MustCreateUser(t *testing.T, ctx context.Context, email, displayName, passwordHash string, hashVersion int) *generated.User {
	t.Helper()
	user, err := tdb.CreateUser(ctx, email, displayName, passwordHash, hashVersion)
	if err != nil {
		t.Fatalf("setup: CreateUser(%q): %v", email, err)
	}
	return user
}

// MustCreateGroup creates a group or fatals the test.
func (tdb *TestDB) MustCreateGroup(t *testing.T, ctx context.Context, orgID uuid.UUID, name, description string) *generated.Group {
	t.Helper()
	group, err := tdb.CreateGroup(ctx, orgID, name, description)
	if err != nil {
		t.Fatalf("setup: CreateGroup(%q): %v", name, err)
	}
	return group
}

// MustGetCVE gets a CVE by ID or fatals the test.
func (tdb *TestDB) MustGetCVE(t *testing.T, ctx context.Context, cveID string) *generated.CVE {
	t.Helper()
	cve, err := tdb.GetCVE(ctx, cveID)
	if err != nil {
		t.Fatalf("setup: GetCVE(%q): %v", cveID, err)
	}
	return cve
}
