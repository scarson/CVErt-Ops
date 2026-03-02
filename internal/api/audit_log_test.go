// ABOUTME: Integration tests for the GET /api/v1/orgs/{org_id}/audit-log endpoint.
// ABOUTME: Covers RBAC, enterprise tier gating, keyset pagination, filters, and cross-org isolation.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// auditLogResponse mirrors the JSON response from the audit-log endpoint.
type auditLogResponse struct {
	Items      []auditLogEntry `json:"items"`
	NextCursor *string         `json:"next_cursor,omitempty"`
}

type auditLogEntry struct {
	ID         string          `json:"id"`
	ActorID    *string         `json:"actor_id,omitempty"`
	ActorEmail string          `json:"actor_email"`
	Action     string          `json:"action"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	EntityName string          `json:"entity_name,omitempty"`
	Success    bool            `json:"success"`
	OldState   json.RawMessage `json:"old_state,omitempty"`
	NewState   json.RawMessage `json:"new_state,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  string          `json:"created_at"`
}

// setupAuditAPIOrg creates a server with audit enabled, registers a user,
// upgrades the org to enterprise tier, and returns the pieces tests need.
func setupAuditAPIOrg(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server, *audit.Writer, string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	srv, ts, aw := newAuditServer(t, db)
	reg := doRegister(t, ctx, ts, "audit-api@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-api@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(reg.OrgID)

	// Upgrade to enterprise so audit-log endpoint is accessible.
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("set enterprise tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	return srv, ts, aw, token, orgID
}

// seedAuditEntries inserts n audit entries directly via the store.
func seedAuditEntries(t *testing.T, db *testutil.TestDB, orgID uuid.UUID, n int, entityType, action string) {
	t.Helper()
	actorID := uuid.New()
	for i := 0; i < n; i++ {
		if err := db.InsertAuditEntry(context.Background(), store.AuditEntry{
			OrgID:      orgID,
			ActorID:    &actorID,
			Action:     action,
			EntityType: entityType,
			EntityID:   uuid.New().String(),
			Success:    true,
		}); err != nil {
			t.Fatalf("seed audit entry %d: %v", i, err)
		}
	}
}

func doGetAuditLog(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, queryString string) *http.Response {
	t.Helper()
	url := ts.URL + "/api/v1/orgs/" + orgID + "/audit-log"
	if queryString != "" {
		url += "?" + queryString
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Cookie", "access_token="+token)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestAuditAPI_RBAC(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, _, ownerToken, orgID := setupAuditAPIOrg(t, db)

	// Owner should get 200.
	resp := doGetAuditLog(t, ctx, ts, ownerToken, orgID.String(), "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Errorf("owner: got %d, want 200", resp.StatusCode)
	}

	// Create a second user as viewer (lowest role).
	viewerReg := doRegister(t, ctx, ts, "audit-viewer@example.com", "test-password-1234")
	viewerUserID, _ := uuid.Parse(viewerReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, viewerUserID, "viewer"); err != nil {
		t.Fatalf("create viewer member: %v", err)
	}
	viewerLogin := doLogin(t, ctx, ts, "audit-viewer@example.com", "test-password-1234")
	viewerToken := cookieValue(viewerLogin, "access_token")
	viewerLogin.Body.Close() //nolint:errcheck,gosec

	// Viewer should get 403 (admin+ required).
	resp = doGetAuditLog(t, ctx, ts, viewerToken, orgID.String(), "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer: got %d, want 403", resp.StatusCode)
	}

	// Create a member user.
	memberReg := doRegister(t, ctx, ts, "audit-member@example.com", "test-password-1234")
	memberUserID, _ := uuid.Parse(memberReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, memberUserID, "member"); err != nil {
		t.Fatalf("create member: %v", err)
	}
	memberLogin := doLogin(t, ctx, ts, "audit-member@example.com", "test-password-1234")
	memberToken := cookieValue(memberLogin, "access_token")
	memberLogin.Body.Close() //nolint:errcheck,gosec

	// Member should get 403.
	resp = doGetAuditLog(t, ctx, ts, memberToken, orgID.String(), "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member: got %d, want 403", resp.StatusCode)
	}

	// Create an admin user.
	adminReg := doRegister(t, ctx, ts, "audit-admin@example.com", "test-password-1234")
	adminUserID, _ := uuid.Parse(adminReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, adminUserID, "admin"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	adminLogin := doLogin(t, ctx, ts, "audit-admin@example.com", "test-password-1234")
	adminToken := cookieValue(adminLogin, "access_token")
	adminLogin.Body.Close() //nolint:errcheck,gosec

	// Admin should get 200.
	resp = doGetAuditLog(t, ctx, ts, adminToken, orgID.String(), "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin: got %d, want 200", resp.StatusCode)
	}
}

func TestAuditAPI_TierGating(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create server — org starts on free tier.
	srv, ts, _ := newAuditServer(t, db)
	reg := doRegister(t, ctx, ts, "audit-tier@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-tier@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(reg.OrgID)

	// Free tier — should get 403.
	resp := doGetAuditLog(t, ctx, ts, token, reg.OrgID, "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("free tier: got %d, want 403", resp.StatusCode)
	}

	// Upgrade to pro — should still get 403.
	if err := db.UpdateOrgTier(ctx, orgID, "pro"); err != nil {
		t.Fatalf("set pro tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)
	resp = doGetAuditLog(t, ctx, ts, token, reg.OrgID, "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("pro tier: got %d, want 403", resp.StatusCode)
	}

	// Upgrade to enterprise — should get 200.
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("set enterprise tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)
	resp = doGetAuditLog(t, ctx, ts, token, reg.OrgID, "")
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Errorf("enterprise tier: got %d, want 200", resp.StatusCode)
	}
}

func TestAuditAPI_Pagination(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, _, token, orgID := setupAuditAPIOrg(t, db)

	// Seed 5 audit entries.
	seedAuditEntries(t, db, orgID, 5, "alert_rule", "create")

	// Fetch with limit=2.
	resp := doGetAuditLog(t, ctx, ts, token, orgID.String(), "limit=2")
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page 1: got %d, want 200", resp.StatusCode)
	}
	var page1 auditLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&page1); err != nil {
		t.Fatalf("decode page 1: %v", err)
	}
	if len(page1.Items) != 2 {
		t.Fatalf("page 1: got %d items, want 2", len(page1.Items))
	}
	if page1.NextCursor == nil {
		t.Fatal("page 1: expected next_cursor")
	}

	// Fetch page 2 using cursor.
	resp2 := doGetAuditLog(t, ctx, ts, token, orgID.String(), "limit=2&cursor="+*page1.NextCursor)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("page 2: got %d, want 200", resp2.StatusCode)
	}
	var page2 auditLogResponse
	if err := json.NewDecoder(resp2.Body).Decode(&page2); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(page2.Items) != 2 {
		t.Fatalf("page 2: got %d items, want 2", len(page2.Items))
	}
	if page2.NextCursor == nil {
		t.Fatal("page 2: expected next_cursor")
	}

	// Verify no overlap.
	seen := map[string]bool{}
	for _, item := range page1.Items {
		seen[item.ID] = true
	}
	for _, item := range page2.Items {
		if seen[item.ID] {
			t.Errorf("overlap: item %s in both page 1 and page 2", item.ID)
		}
	}

	// Page 3: should have 1 remaining.
	resp3 := doGetAuditLog(t, ctx, ts, token, orgID.String(), "limit=2&cursor="+*page2.NextCursor)
	defer resp3.Body.Close() //nolint:errcheck,gosec
	var page3 auditLogResponse
	json.NewDecoder(resp3.Body).Decode(&page3) //nolint:errcheck,gosec
	if len(page3.Items) != 1 {
		t.Fatalf("page 3: got %d items, want 1", len(page3.Items))
	}
	if page3.NextCursor != nil {
		t.Error("page 3: expected no next_cursor")
	}
}

func TestAuditAPI_Filters(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, _, token, orgID := setupAuditAPIOrg(t, db)

	// Seed varied entries.
	actorAlice := uuid.New()
	actorBob := uuid.New()
	entries := []store.AuditEntry{
		{OrgID: orgID, ActorID: &actorAlice, Action: "create", EntityType: "alert_rule", EntityID: uuid.New().String(), Success: true},
		{OrgID: orgID, ActorID: &actorAlice, Action: "update", EntityType: "alert_rule", EntityID: uuid.New().String(), Success: true},
		{OrgID: orgID, ActorID: &actorBob, Action: "delete", EntityType: "channel", EntityID: uuid.New().String(), Success: true},
		{OrgID: orgID, ActorID: &actorBob, Action: "create", EntityType: "channel", EntityID: uuid.New().String(), Success: true},
	}
	for _, e := range entries {
		if err := db.InsertAuditEntry(ctx, e); err != nil {
			t.Fatalf("seed entry: %v", err)
		}
	}

	t.Run("EntityType", func(t *testing.T) {
		resp := doGetAuditLog(t, ctx, ts, token, orgID.String(), "entity_type=alert_rule")
		defer resp.Body.Close() //nolint:errcheck,gosec
		var body auditLogResponse
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck,gosec
		if len(body.Items) != 2 {
			t.Errorf("entity_type=alert_rule: got %d, want 2", len(body.Items))
		}
	})

	t.Run("Action", func(t *testing.T) {
		resp := doGetAuditLog(t, ctx, ts, token, orgID.String(), "action=create")
		defer resp.Body.Close() //nolint:errcheck,gosec
		var body auditLogResponse
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck,gosec
		if len(body.Items) != 2 {
			t.Errorf("action=create: got %d, want 2", len(body.Items))
		}
	})

	t.Run("ActorID", func(t *testing.T) {
		resp := doGetAuditLog(t, ctx, ts, token, orgID.String(), "actor_id="+actorAlice.String())
		defer resp.Body.Close() //nolint:errcheck,gosec
		var body auditLogResponse
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck,gosec
		if len(body.Items) != 2 {
			t.Errorf("actor_id=alice: got %d, want 2", len(body.Items))
		}
	})

	t.Run("DateRange", func(t *testing.T) {
		// All entries are recent — filter with after=1 hour ago, before=1 hour from now.
		after := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		before := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		resp := doGetAuditLog(t, ctx, ts, token, orgID.String(), "after="+after+"&before="+before)
		defer resp.Body.Close() //nolint:errcheck,gosec
		var body auditLogResponse
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck,gosec
		if len(body.Items) != 4 {
			t.Errorf("date range (all recent): got %d, want 4", len(body.Items))
		}

		// Filter with before=1 hour ago — should get 0.
		pastBefore := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		resp2 := doGetAuditLog(t, ctx, ts, token, orgID.String(), "before="+pastBefore)
		defer resp2.Body.Close() //nolint:errcheck,gosec
		var body2 auditLogResponse
		json.NewDecoder(resp2.Body).Decode(&body2) //nolint:errcheck,gosec
		if len(body2.Items) != 0 {
			t.Errorf("date range (past): got %d, want 0", len(body2.Items))
		}
	})

	t.Run("Combined", func(t *testing.T) {
		// entity_type=channel + action=create → 1 entry (bob's create channel).
		resp := doGetAuditLog(t, ctx, ts, token, orgID.String(), "entity_type=channel&action=create")
		defer resp.Body.Close() //nolint:errcheck,gosec
		var body auditLogResponse
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck,gosec
		if len(body.Items) != 1 {
			t.Errorf("entity_type=channel&action=create: got %d, want 1", len(body.Items))
		}
	})
}

func TestAuditAPI_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Set up org A (enterprise).
	srv, ts, _, tokenA, orgIDA := setupAuditAPIOrg(t, db)

	// Create org B (enterprise) with a separate user.
	// BootstrapFirstUserOrg only creates an org for the first user, so we
	// must create org B explicitly and add user B as owner.
	regB := doRegister(t, ctx, ts, "audit-orgb@example.com", "test-password-1234")
	userBID, _ := uuid.Parse(regB.UserID)
	orgB, err := db.CreateOrg(ctx, "Org B")
	if err != nil {
		t.Fatalf("create org B: %v", err)
	}
	orgIDB := orgB.ID
	if err := db.CreateOrgMember(ctx, orgIDB, userBID, "owner"); err != nil {
		t.Fatalf("add user B to org B: %v", err)
	}
	if err := db.UpdateOrgTier(ctx, orgIDB, "enterprise"); err != nil {
		t.Fatalf("set enterprise tier for org B: %v", err)
	}
	srv.tierCache.Invalidate(orgIDB)

	loginB := doLogin(t, ctx, ts, "audit-orgb@example.com", "test-password-1234")
	tokenB := cookieValue(loginB, "access_token")
	loginB.Body.Close() //nolint:errcheck,gosec

	// Seed entries in org A.
	seedAuditEntries(t, db, orgIDA, 3, "alert_rule", "create")

	// Seed entries in org B.
	seedAuditEntries(t, db, orgIDB, 2, "channel", "delete")

	// Org A should see only its 3 entries.
	respA := doGetAuditLog(t, ctx, ts, tokenA, orgIDA.String(), "")
	defer respA.Body.Close() //nolint:errcheck,gosec
	var bodyA auditLogResponse
	json.NewDecoder(respA.Body).Decode(&bodyA) //nolint:errcheck,gosec
	if len(bodyA.Items) != 3 {
		t.Errorf("org A: got %d items, want 3", len(bodyA.Items))
	}

	// Org B should see only its 2 entries.
	respB := doGetAuditLog(t, ctx, ts, tokenB, orgIDB.String(), "")
	defer respB.Body.Close() //nolint:errcheck,gosec
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("org B: got status %d, want 200", respB.StatusCode)
	}
	var bodyB auditLogResponse
	json.NewDecoder(respB.Body).Decode(&bodyB) //nolint:errcheck,gosec
	if len(bodyB.Items) != 2 {
		t.Errorf("org B: got %d items, want 2", len(bodyB.Items))
	}

	// User A trying to access org B's audit log should get 403 (not a member).
	respCross := doGetAuditLog(t, ctx, ts, tokenA, orgIDB.String(), "")
	respCross.Body.Close() //nolint:errcheck,gosec
	if respCross.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org: got %d, want 403", respCross.StatusCode)
	}
}
