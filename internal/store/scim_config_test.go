// ABOUTME: Integration tests for SCIM config store methods.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
	"github.com/stretchr/testify/require"
)

// scimSetup creates an org and SSO connection for SCIM config tests.
func scimSetup(t *testing.T, db *testutil.TestDB, ctx context.Context, orgName string) (orgID, ssoConnID uuid.UUID) {
	t.Helper()
	org := db.MustCreateOrg(t, ctx, orgName)
	conn, err := db.CreateSSOConnection(ctx, org.ID, orgName+" IdP", "https://idp.example.com/"+orgName, "client-"+orgName, []byte("enc"), nil, true)
	require.NoError(t, err)
	return org.ID, conn.ID
}

func TestCreateSCIMConfig(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMCreate")

	cfg, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "hash123", "cvrt_", "viewer")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, orgID, cfg.OrgID)
	require.Equal(t, ssoConnID, cfg.SsoConnectionID)
	require.True(t, cfg.Enabled)
	require.Equal(t, "hash123", cfg.TokenHash)
	require.Equal(t, "cvrt_", cfg.TokenPrefix)
	require.Equal(t, "viewer", cfg.DefaultRole)
	require.False(t, cfg.CreatedAt.IsZero())
}

func TestCreateSCIMConfig_Duplicate(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMDup")

	_, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "hash1", "cvrt_", "viewer")
	require.NoError(t, err)

	_, err = db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "hash2", "cvrt_", "viewer")
	require.Error(t, err)
}

func TestGetSCIMConfigByTokenHash(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMTokenHash")

	_, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "known_hash", "cvrt_", "member")
	require.NoError(t, err)

	cfg, err := db.LookupSCIMConfigByTokenHash(ctx, "known_hash")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, orgID, cfg.OrgID)
	require.True(t, cfg.Enabled)

	// Non-existent hash returns nil, nil.
	cfg, err = db.LookupSCIMConfigByTokenHash(ctx, "nonexistent_hash")
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestGetSCIMConfigByOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMGetOrg")

	_, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, false, "hash_org", "cvrt_", "viewer")
	require.NoError(t, err)

	cfg, err := db.GetSCIMConfig(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, orgID, cfg.OrgID)
	require.Equal(t, "hash_org", cfg.TokenHash)

	// Random UUID returns nil, nil.
	cfg, err = db.GetSCIMConfig(ctx, uuid.New())
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestGetSCIMConfigBySSOConnectionID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMGetSSO")

	_, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "hash_sso", "cvrt_", "viewer")
	require.NoError(t, err)

	cfg, err := db.LookupSCIMConfigBySSOConnectionID(ctx, ssoConnID)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, orgID, cfg.OrgID)
	require.Equal(t, ssoConnID, cfg.SsoConnectionID)

	// Non-existent returns nil, nil.
	cfg, err = db.LookupSCIMConfigBySSOConnectionID(ctx, uuid.New())
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestUpdateSCIMConfig(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMUpdate")

	created, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, false, "hash_upd", "cvrt_", "viewer")
	require.NoError(t, err)

	// Small delay to ensure updated_at advances.
	time.Sleep(10 * time.Millisecond)

	err = db.UpdateSCIMConfig(ctx, orgID, true, "member")
	require.NoError(t, err)

	cfg, err := db.GetSCIMConfig(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.True(t, cfg.Enabled)
	require.Equal(t, "member", cfg.DefaultRole)
	require.True(t, cfg.UpdatedAt.After(created.CreatedAt))
}

func TestUpdateSCIMConfigToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMRotate")

	created, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "old_hash", "old_", "viewer")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	err = db.RotateSCIMToken(ctx, orgID, "new_hash", "new_")
	require.NoError(t, err)

	cfg, err := db.GetSCIMConfig(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, "new_hash", cfg.TokenHash)
	require.Equal(t, "new_", cfg.TokenPrefix)
	require.True(t, cfg.UpdatedAt.After(created.CreatedAt))
}

func TestDeleteSCIMConfig(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ssoConnID := scimSetup(t, db, ctx, "SCIMDelete")

	_, err := db.CreateSCIMConfig(ctx, orgID, ssoConnID, true, "hash_del", "cvrt_", "viewer")
	require.NoError(t, err)

	err = db.DeleteSCIMConfig(ctx, orgID)
	require.NoError(t, err)

	cfg, err := db.GetSCIMConfig(ctx, orgID)
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestSCIMConfig_RLSIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgA, ssoConnA := scimSetup(t, db, ctx, "SCIMRLSA")
	orgB, ssoConnB := scimSetup(t, db, ctx, "SCIMRLSB")

	// Create configs via superuser store.
	_, err := db.CreateSCIMConfig(ctx, orgA, ssoConnA, true, "hash_a", "a_", "viewer")
	require.NoError(t, err)
	_, err = db.CreateSCIMConfig(ctx, orgB, ssoConnB, true, "hash_b", "b_", "member")
	require.NoError(t, err)

	// Query via AppStore (subject to RLS) — org A should only see its own.
	cfgA, err := db.AppStore.GetSCIMConfig(ctx, orgA)
	require.NoError(t, err)
	require.NotNil(t, cfgA)
	require.Equal(t, orgA, cfgA.OrgID)

	// Query via AppStore — org B should only see its own.
	cfgB, err := db.AppStore.GetSCIMConfig(ctx, orgB)
	require.NoError(t, err)
	require.NotNil(t, cfgB)
	require.Equal(t, orgB, cfgB.OrgID)
}
