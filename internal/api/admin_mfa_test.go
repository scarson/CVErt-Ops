// ABOUTME: Integration tests for org-level admin MFA actions (reset MFA, force password reset).
// ABOUTME: Tests cover RBAC hierarchy enforcement across owner, admin, member, and site admin roles.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// adminMFATestSetup creates an org with owner, admin, and member users.
// Returns orgID, ownerID, adminID, memberID, and cookies for each user.
type adminMFAActors struct {
	orgID                                uuid.UUID
	ownerID, adminID, memberID           uuid.UUID
	ownerCookies, adminCookies, memberCookies []*http.Cookie
}

func setupAdminMFATest(t *testing.T, ctx context.Context, srv *Server, ts *httptest.Server) adminMFAActors {
	t.Helper()

	// Register owner — this creates the org.
	ownerResult := doRegister(t, ctx, ts, "mfa-owner@example.com", "owner-password-12345")
	orgID := uuid.MustParse(ownerResult.OrgID)
	ownerID := uuid.MustParse(ownerResult.UserID)

	// Register admin and member — creates their own orgs, then add to owner's org.
	adminResult := doRegister(t, ctx, ts, "mfa-admin@example.com", "admin-password-12345")
	adminID := uuid.MustParse(adminResult.UserID)
	if err := srv.store.CreateOrgMember(ctx, orgID, adminID, "admin"); err != nil {
		t.Fatalf("add admin to org: %v", err)
	}

	memberResult := doRegister(t, ctx, ts, "mfa-member@example.com", "member-password-12345")
	memberID := uuid.MustParse(memberResult.UserID)
	if err := srv.store.CreateOrgMember(ctx, orgID, memberID, "member"); err != nil {
		t.Fatalf("add member to org: %v", err)
	}

	// Login each user and collect cookies.
	ownerResp := doLogin(t, ctx, ts, "mfa-owner@example.com", "owner-password-12345")
	ownerResp.Body.Close() //nolint:errcheck,gosec // G104
	ownerCookies := ownerResp.Cookies()

	adminResp := doLogin(t, ctx, ts, "mfa-admin@example.com", "admin-password-12345")
	adminResp.Body.Close() //nolint:errcheck,gosec // G104
	adminCookies := adminResp.Cookies()

	memberResp := doLogin(t, ctx, ts, "mfa-member@example.com", "member-password-12345")
	memberResp.Body.Close() //nolint:errcheck,gosec // G104
	memberCookies := memberResp.Cookies()

	return adminMFAActors{
		orgID:         orgID,
		ownerID:       ownerID,
		adminID:       adminID,
		memberID:      memberID,
		ownerCookies:  ownerCookies,
		adminCookies:  adminCookies,
		memberCookies: memberCookies,
	}
}

func TestAdminMFAReset(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Enroll TOTP for the member.
	enrollTOTP(t, ctx, srv, actors.memberID)
	hasMFA, err := srv.store.UserHasMFACredentials(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("check MFA: %v", err)
	}
	if !hasMFA {
		t.Fatal("member should have MFA before reset")
	}

	// Owner resets member's MFA.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-mfa: got %d, want 200", resp.StatusCode)
	}

	// Verify MFA is cleared.
	hasMFA, err = srv.store.UserHasMFACredentials(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("check MFA after reset: %v", err)
	}
	if hasMFA {
		t.Error("member should have no MFA after reset")
	}
}

func TestAdminMFAResetByAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Enroll TOTP for the member.
	enrollTOTP(t, ctx, srv, actors.memberID)

	// Admin resets member's MFA — expect success.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.adminCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin reset member MFA: got %d, want 200", resp.StatusCode)
	}
}

func TestAdminMFAResetOwnerByAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Admin tries to reset owner's MFA — expect 403.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.ownerID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.adminCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin reset owner MFA: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminMFAResetByMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Member tries to reset anyone's MFA — expect 403 (middleware blocks).
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.adminID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.memberCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member reset admin MFA: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminForcePasswordReset(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Owner forces member password reset.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("force-password-reset: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("force-password-reset: got %d, want 200", resp.StatusCode)
	}

	// Verify the flag is set.
	status, err := srv.store.GetUserAuthStatus(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("get auth status: %v", err)
	}
	if !status.ForcePasswordReset {
		t.Error("force_password_reset should be true")
	}
}

func TestAdminForcePasswordResetByMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Member tries to force reset — expect 403.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.adminID.String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.memberCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("force-password-reset: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member force-password-reset: got %d, want 403", resp.StatusCode)
	}
}
