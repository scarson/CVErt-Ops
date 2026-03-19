// ABOUTME: Integration tests for org-level admin MFA actions (reset MFA, force password reset).
// ABOUTME: Tests cover RBAC hierarchy enforcement across owner, admin, member, and site admin roles.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// adminMFATestSetup creates an org with owner, admin, and member users.
// Returns orgID, ownerID, adminID, memberID, and cookies for each user.
type adminMFAActors struct {
	orgID                                     uuid.UUID
	ownerID, adminID, memberID                uuid.UUID
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

// ── Task 19: Per-member MFA requirements + org MFA settings ──────────────────

func TestAdminRequireMFA(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Owner adds per-member MFA requirement.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("require-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("require-mfa: got %d, want 201", resp.StatusCode)
	}

	// Verify the requirement exists.
	has, err := srv.store.UserHasMFARequirement(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("check requirement: %v", err)
	}
	if !has {
		t.Error("member should have MFA requirement after require-mfa")
	}
}

func TestAdminUnrequireMFA(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// First add the requirement.
	if err := srv.store.CreateMFARequirement(ctx, actors.orgID, actors.memberID, actors.ownerID); err != nil {
		t.Fatalf("create requirement: %v", err)
	}

	// Owner removes per-member MFA requirement.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodDelete, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("unrequire-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unrequire-mfa: got %d, want 204", resp.StatusCode)
	}

	// Verify the requirement is gone.
	has, err := srv.store.UserHasMFARequirement(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("check requirement: %v", err)
	}
	if has {
		t.Error("member should not have MFA requirement after unrequire-mfa")
	}
}

func TestAdminRequireMFASelfTarget(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Owner tries to require MFA on themselves — expect 400.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.ownerID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("require-mfa self: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self require-mfa: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminRequireMFAAdminTargetsAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Add a second admin.
	admin2Result := doRegister(t, ctx, ts, "mfa-admin2@example.com", "admin2-password-12345") //nolint:gosec // G101: test credentials
	admin2ID := uuid.MustParse(admin2Result.UserID)
	if err := srv.store.CreateOrgMember(ctx, actors.orgID, admin2ID, "admin"); err != nil {
		t.Fatalf("add admin2 to org: %v", err)
	}

	// Admin tries to require MFA for another admin — expect 403 (same level).
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + admin2ID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.adminCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("require-mfa admin→admin: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin require-mfa for admin: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminUnrequireMFASelfTarget(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Owner tries to unrequire MFA on themselves — expect 400.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.ownerID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodDelete, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("unrequire-mfa self: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self unrequire-mfa: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminRequireMFAByMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Member tries to require MFA → 403 (middleware blocks at admin+ level).
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.adminID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.memberCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("require-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member require-mfa: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminUpdateOrgMFASettings(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Owner updates MFA settings.
	body := `{"mfa_required_all":true,"mfa_remember_device_allowed":false,"mfa_remember_device_days":14}`
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/mfa-settings"
	req := authedRequest(t, ctx, http.MethodPatch, url, body, actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("mfa-settings: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa-settings: got %d, want 200", resp.StatusCode)
	}

	// Verify the settings were applied.
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result["mfa_required_all"] != true {
		t.Error("mfa_required_all should be true")
	}
	if result["mfa_remember_device_allowed"] != false {
		t.Error("mfa_remember_device_allowed should be false")
	}
	if result["mfa_remember_device_days"] != float64(14) {
		t.Errorf("mfa_remember_device_days: got %v, want 14", result["mfa_remember_device_days"])
	}

	// Verify persistence via store.
	org, err := srv.store.GetOrgByID(ctx, actors.orgID)
	if err != nil {
		t.Fatalf("get org: %v", err)
	}
	if !org.MfaRequiredAll {
		t.Error("org.MfaRequiredAll should be true in DB")
	}
}

func TestAdminUpdateOrgMFASettingsRememberDeviceDaysRange(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/mfa-settings"

	// Below minimum (7).
	req := authedRequest(t, ctx, http.MethodPatch, url, `{"mfa_remember_device_days":3}`, actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("mfa-settings low: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("mfa-settings days=3: got %d, want 400", resp.StatusCode)
	}

	// Above maximum (90).
	req = authedRequest(t, ctx, http.MethodPatch, url, `{"mfa_remember_device_days":100}`, actors.ownerCookies)
	resp, err = ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("mfa-settings high: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("mfa-settings days=100: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminUpdateOrgMFASettingsByMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Member tries to update MFA settings → 403.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/mfa-settings"
	req := authedRequest(t, ctx, http.MethodPatch, url, `{"mfa_required_all":true}`, actors.memberCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("mfa-settings: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member mfa-settings: got %d, want 403", resp.StatusCode)
	}
}

// ── P11 Task 4: Admin MFA Test Gaps ─────────────────────────────────────────

// SC2: Cross-org isolation for all 5 admin endpoints.
func TestAdminMFA_CrossOrg_Rejected(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)

	// Create Org A with owner A.
	ownerAResult := doRegister(t, ctx, ts, "crossorg-ownerA@example.com", "ownerA-password-12345")
	ownerACookies := func() []*http.Cookie {
		resp := doLogin(t, ctx, ts, "crossorg-ownerA@example.com", "ownerA-password-12345")
		defer resp.Body.Close() //nolint:errcheck,gosec
		return resp.Cookies()
	}()

	// Create Org B with owner B + member B.
	// ownerB is not the first user, so doRegister won't bootstrap an org.
	// Create one explicitly.
	ownerBResult := doRegister(t, ctx, ts, "crossorg-ownerB@example.com", "ownerB-password-12345")
	ownerBID := uuid.MustParse(ownerBResult.UserID)
	orgB, err := srv.store.CreateOrg(ctx, "Cross-Org B")
	if err != nil {
		t.Fatalf("create org B: %v", err)
	}
	orgBID := orgB.ID
	if err := srv.store.CreateOrgMember(ctx, orgBID, ownerBID, "owner"); err != nil {
		t.Fatalf("add ownerB to orgB: %v", err)
	}
	memberBResult := doRegister(t, ctx, ts, "crossorg-memberB@example.com", "memberB-password-12345")
	memberBID := uuid.MustParse(memberBResult.UserID)
	if err := srv.store.CreateOrgMember(ctx, orgBID, memberBID, "member"); err != nil {
		t.Fatalf("add memberB to orgB: %v", err)
	}

	_ = ownerAResult // used for ownerACookies

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"reset-mfa", http.MethodPost, "/api/v1/orgs/" + orgBID.String() + "/members/" + memberBID.String() + "/reset-mfa", ""},
		{"force-password-reset", http.MethodPost, "/api/v1/orgs/" + orgBID.String() + "/members/" + memberBID.String() + "/force-password-reset", ""},
		{"require-mfa", http.MethodPost, "/api/v1/orgs/" + orgBID.String() + "/members/" + memberBID.String() + "/require-mfa", ""},
		{"unrequire-mfa", http.MethodDelete, "/api/v1/orgs/" + orgBID.String() + "/members/" + memberBID.String() + "/require-mfa", ""},
		{"mfa-settings", http.MethodPatch, "/api/v1/orgs/" + orgBID.String() + "/mfa-settings", `{"mfa_required_all":true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := authedRequest(t, ctx, tt.method, ts.URL+tt.path, tt.body, ownerACookies)
			resp, err := ts.Client().Do(req) //nolint:gosec
			if err != nil {
				t.Fatalf("%s request: %v", tt.name, err)
			}
			defer resp.Body.Close() //nolint:errcheck,gosec
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s: got %d, want 403", tt.name, resp.StatusCode)
			}
		})
	}

	// Verify no admin reset event was emitted for cross-org attempts.
	events := flushAndQueryEvents(t, ew, db, secure.EventMFAAdminReset)
	if len(events) != 0 {
		t.Errorf("expected 0 cross-org EventMFAAdminReset events, got %d", len(events))
	}
}

// SC3: adminForcePasswordReset negative cases.
func TestAdminForcePasswordReset_SelfTarget(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.ownerID.String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("force-password-reset self: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self target: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminForcePasswordReset_NonExistentUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + uuid.New().String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("force-password-reset non-existent: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-existent user: got %d, want 404", resp.StatusCode)
	}
}

func TestAdminForcePasswordReset_AdminTargetsAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Register second admin.
	admin2Result := doRegister(t, ctx, ts, "fpr-admin2@example.com", "admin2-password-12345") //nolint:gosec
	admin2ID := uuid.MustParse(admin2Result.UserID)
	if err := srv.store.CreateOrgMember(ctx, actors.orgID, admin2ID, "admin"); err != nil {
		t.Fatalf("add admin2 to org: %v", err)
	}

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + admin2ID.String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.adminCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("force-password-reset admin→admin: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin targets admin: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminForcePasswordReset_OAuthOnlyAccount(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Clear member's password hash to simulate OAuth-only account.
	_, err := db.Pool().Exec(ctx, "UPDATE users SET password_hash = NULL WHERE id = $1", actors.memberID)
	if err != nil {
		t.Fatalf("clear password hash: %v", err)
	}

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("force-password-reset oauth: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("OAuth-only account: got %d, want 400", resp.StatusCode)
	}
}

// SC6: Site admin can reset an admin's MFA (member role in org, but site admin bypass).
func TestAdminMFAReset_SiteAdmin_CanTargetAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)

	// Register a regular owner + admin in the org.
	ownerResult := doRegister(t, ctx, ts, "sa-owner@example.com", "owner-password-12345")
	orgID := uuid.MustParse(ownerResult.OrgID)

	adminResult := doRegister(t, ctx, ts, "sa-admin@example.com", "admin-password-12345")
	adminID := uuid.MustParse(adminResult.UserID)
	if err := srv.store.CreateOrgMember(ctx, orgID, adminID, "admin"); err != nil {
		t.Fatalf("add admin to org: %v", err)
	}
	enrollTOTP(t, ctx, srv, adminID)

	// Register site admin and add to org as member.
	saResult := doRegister(t, ctx, ts, "sa-siteadmin@example.com", "siteadmin-password-12345")
	saID := uuid.MustParse(saResult.UserID)
	_, err := db.Pool().Exec(ctx, "UPDATE users SET is_site_admin = true WHERE id = $1", saID)
	if err != nil {
		t.Fatalf("set site admin: %v", err)
	}
	if err := srv.store.CreateOrgMember(ctx, orgID, saID, "member"); err != nil {
		t.Fatalf("add site admin to org as member: %v", err)
	}

	// Login as site admin.
	saResp := doLogin(t, ctx, ts, "sa-siteadmin@example.com", "siteadmin-password-12345")
	saCookies := saResp.Cookies()
	saResp.Body.Close() //nolint:errcheck,gosec

	// Site admin (member role) resets admin's MFA — should succeed via site admin bypass.
	url := ts.URL + "/api/v1/orgs/" + orgID.String() + "/members/" + adminID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", saCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("site admin reset admin MFA: got %d, want 200", resp.StatusCode)
	}

	events := flushAndQueryEvents(t, ew, db, secure.EventMFAAdminReset)
	if len(events) == 0 {
		t.Error("expected EventMFAAdminReset event to be emitted")
	}
}

// SC6: Viewer role rejected.
func TestAdminMFAReset_ViewerRole_Rejected(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	ownerResult := doRegister(t, ctx, ts, "viewer-owner@example.com", "owner-password-12345")
	orgID := uuid.MustParse(ownerResult.OrgID)

	memberResult := doRegister(t, ctx, ts, "viewer-member@example.com", "member-password-12345")
	memberID := uuid.MustParse(memberResult.UserID)
	if err := srv.store.CreateOrgMember(ctx, orgID, memberID, "member"); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Register viewer and add to org.
	viewerResult := doRegister(t, ctx, ts, "viewer-viewer@example.com", "viewer-password-12345")
	viewerID := uuid.MustParse(viewerResult.UserID)
	if err := srv.store.CreateOrgMember(ctx, orgID, viewerID, "viewer"); err != nil {
		t.Fatalf("add viewer to org: %v", err)
	}

	viewerResp := doLogin(t, ctx, ts, "viewer-viewer@example.com", "viewer-password-12345")
	viewerCookies := viewerResp.Cookies()
	viewerResp.Body.Close() //nolint:errcheck,gosec

	url := ts.URL + "/api/v1/orgs/" + orgID.String() + "/members/" + memberID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", viewerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer reset MFA: got %d, want 403", resp.StatusCode)
	}
}

// SC7: Admin reset with all side-effect assertions.
func TestAdminMFAReset_AllSideEffects(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Enroll TOTP and generate recovery codes for member.
	enrollTOTP(t, ctx, srv, actors.memberID)
	_, err := srv.store.GenerateRecoveryCodes(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	// Record token_version before reset.
	userBefore, err := srv.store.GetUserByID(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("GetUserByID before: %v", err)
	}

	// Owner resets member's MFA.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/reset-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-mfa: got %d, want 200", resp.StatusCode)
	}

	// Assert: no credentials.
	hasMFA, err := srv.store.UserHasMFACredentials(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("UserHasMFACredentials: %v", err)
	}
	if hasMFA {
		t.Error("expected no MFA credentials after reset")
	}

	// Assert: no recovery codes.
	unusedCodes, err := srv.store.CountUnusedRecoveryCodes(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if unusedCodes != 0 {
		t.Errorf("expected 0 recovery codes after reset, got %d", unusedCodes)
	}

	// Assert: token_version incremented.
	userAfter, err := srv.store.GetUserByID(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("GetUserByID after: %v", err)
	}
	if userAfter.TokenVersion <= userBefore.TokenVersion {
		t.Errorf("token_version did not increment: before=%d, after=%d", userBefore.TokenVersion, userAfter.TokenVersion)
	}

	// Assert: EventMFAAdminReset event.
	events := flushAndQueryEvents(t, ew, db, secure.EventMFAAdminReset)
	if len(events) == 0 {
		t.Fatal("expected EventMFAAdminReset event, got 0")
	}
	ev := events[0]
	if ev["severity"] != "critical" {
		t.Errorf("event severity = %q, want critical", ev["severity"])
	}
}

// SC7: Force password reset with all side-effect assertions.
func TestAdminForcePasswordReset_AllSideEffects(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Create a remember-device token for member.
	tokenBytes := sha256.Sum256([]byte("test-device-token"))
	tokenHash := hex.EncodeToString(tokenBytes[:])
	if err := srv.store.CreateRememberDeviceToken(ctx, actors.memberID, tokenHash, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("CreateRememberDeviceToken: %v", err)
	}

	// Record token_version.
	userBefore, err := srv.store.GetUserByID(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("GetUserByID before: %v", err)
	}

	// Owner forces password reset.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/force-password-reset"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("force-password-reset: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("force-password-reset: got %d, want 200", resp.StatusCode)
	}

	// Assert: force_password_reset flag is set.
	status, err := srv.store.GetUserAuthStatus(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("GetUserAuthStatus: %v", err)
	}
	if !status.ForcePasswordReset {
		t.Error("force_password_reset should be true")
	}

	// Assert: token_version incremented.
	userAfter, err := srv.store.GetUserByID(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("GetUserByID after: %v", err)
	}
	if userAfter.TokenVersion <= userBefore.TokenVersion {
		t.Errorf("token_version did not increment: before=%d, after=%d", userBefore.TokenVersion, userAfter.TokenVersion)
	}

	// Assert: remember-device token deleted.
	valid, err := srv.store.ValidateRememberDeviceToken(ctx, actors.memberID, tokenHash)
	if err != nil {
		t.Fatalf("ValidateRememberDeviceToken: %v", err)
	}
	if valid {
		t.Error("expected remember-device token to be deleted after force password reset")
	}

	// Assert: EventAuthPasswordResetForced event.
	events := flushAndQueryEvents(t, ew, db, secure.EventAuthPasswordResetForced)
	if len(events) == 0 {
		t.Fatal("expected EventAuthPasswordResetForced event, got 0")
	}
	if events[0]["severity"] != "critical" {
		t.Errorf("event severity = %q, want critical", events[0]["severity"])
	}
}

// C2: adminUnrequireMFA RBAC gaps.
func TestAdminUnrequireMFA_AdminTargetsMember_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Create requirement for member.
	if err := srv.store.CreateMFARequirement(ctx, actors.orgID, actors.memberID, actors.ownerID); err != nil {
		t.Fatalf("create requirement: %v", err)
	}

	// Admin removes member's MFA requirement — should succeed.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodDelete, url, "", actors.adminCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("unrequire-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin unrequire member: got %d, want 204", resp.StatusCode)
	}

	// Verify requirement removed.
	has, err := srv.store.UserHasMFARequirement(ctx, actors.memberID)
	if err != nil {
		t.Fatalf("check requirement: %v", err)
	}
	if has {
		t.Error("requirement should be removed")
	}
}

func TestAdminUnrequireMFA_AdminTargetsAdmin_Rejected(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Register second admin.
	admin2Result := doRegister(t, ctx, ts, "unreq-admin2@example.com", "admin2-password-12345") //nolint:gosec
	admin2ID := uuid.MustParse(admin2Result.UserID)
	if err := srv.store.CreateOrgMember(ctx, actors.orgID, admin2ID, "admin"); err != nil {
		t.Fatalf("add admin2 to org: %v", err)
	}

	// Create requirement for admin2.
	if err := srv.store.CreateMFARequirement(ctx, actors.orgID, admin2ID, actors.ownerID); err != nil {
		t.Fatalf("create requirement: %v", err)
	}

	// First admin tries to unrequire second admin — should fail.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + admin2ID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodDelete, url, "", actors.adminCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("unrequire-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin unrequire admin: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminUnrequireMFA_MemberRejected(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Create requirement for admin.
	if err := srv.store.CreateMFARequirement(ctx, actors.orgID, actors.adminID, actors.ownerID); err != nil {
		t.Fatalf("create requirement: %v", err)
	}

	// Member tries to unrequire admin's MFA — expect 403.
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.adminID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodDelete, url, "", actors.memberCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("unrequire-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member unrequire admin: got %d, want 403", resp.StatusCode)
	}
}

// SC1: Event assertions for admin handlers.
func TestAdminRequireMFA_EmitsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodPost, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("require-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("require-mfa: got %d, want 201", resp.StatusCode)
	}

	events := flushAndQueryEvents(t, ew, db, secure.EventMFAAdminRequireMember)
	if len(events) == 0 {
		t.Error("expected EventMFAAdminRequireMember event")
	}
}

func TestAdminUnrequireMFA_EmitsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	// Create requirement first.
	if err := srv.store.CreateMFARequirement(ctx, actors.orgID, actors.memberID, actors.ownerID); err != nil {
		t.Fatalf("create requirement: %v", err)
	}

	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/members/" + actors.memberID.String() + "/require-mfa"
	req := authedRequest(t, ctx, http.MethodDelete, url, "", actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("unrequire-mfa: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unrequire-mfa: got %d, want 204", resp.StatusCode)
	}

	events := flushAndQueryEvents(t, ew, db, secure.EventMFAAdminUnrequireMember)
	if len(events) == 0 {
		t.Error("expected EventMFAAdminUnrequireMember event")
	}
}

func TestAdminUpdateOrgMFASettings_EmitsEvent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, ew := newMFAServerWithEvents(t, db)
	actors := setupAdminMFATest(t, ctx, srv, ts)

	body := `{"mfa_required_all":true}`
	url := ts.URL + "/api/v1/orgs/" + actors.orgID.String() + "/mfa-settings"
	req := authedRequest(t, ctx, http.MethodPatch, url, body, actors.ownerCookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("mfa-settings: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa-settings: got %d, want 200", resp.StatusCode)
	}

	events := flushAndQueryEvents(t, ew, db, secure.EventMFAOrgRequireAllEnabled)
	if len(events) == 0 {
		t.Error("expected EventMFAOrgRequireAllEnabled event")
	}
	if len(events) > 0 && events[0]["severity"] != "info" {
		t.Errorf("event severity = %q, want info", events[0]["severity"])
	}
}
