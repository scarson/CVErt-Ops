// ABOUTME: Tests verifying SCIM operations produce correct audit log entries and security events.
// ABOUTME: Covers user provision/deprovision audit, auth failure events, and token create events.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// scimAuditTestEnv bundles a test server with both audit writer and event writer for assertions.
type scimAuditTestEnv struct {
	ts           *httptest.Server
	srv          *Server
	db           *testutil.TestDB
	ew           *secure.EventWriter
	aw           *audit.Writer
	orgID        uuid.UUID
	scimConfigID uuid.UUID
	rawToken     string
}

func newSCIMAuditTestEnv(t *testing.T) *scimAuditTestEnv {
	t.Helper()

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "scim-audit-test-org")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	ssoConn, err := db.CreateSSOConnection(ctx, org.ID, "Audit Test IdP",
		"https://idp.example.com", "client-id", []byte("encrypted"), nil, true)
	if err != nil {
		t.Fatalf("CreateSSOConnection: %v", err)
	}

	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}

	scimCfg, err := db.CreateSCIMConfig(ctx, org.ID, ssoConn.ID, true, tokenHash, tokenPrefix, "viewer")
	if err != nil {
		t.Fatalf("CreateSCIMConfig: %v", err)
	}

	ew := secure.NewEventWriter(db.Store)
	aw := audit.NewWriter(db.Store, slog.Default())

	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret: "scim-audit-test-secret-32bytes-m",
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{EventWriter: ew, AuditWriter: aw})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)

	r := chi.NewRouter()
	r.Route("/api/v1/orgs/{org_id}/scim/v2", func(sub chi.Router) {
		sub.Use(srv.requireSCIMAuth)
		sub.Post("/Users", srv.scimCreateUser)
		sub.Get("/Users", srv.scimListUsers)
		sub.Get("/Users/{id}", srv.scimGetUser)
		sub.Put("/Users/{id}", srv.scimReplaceUser)
		sub.Patch("/Users/{id}", srv.scimPatchUser)
		sub.Delete("/Users/{id}", srv.scimDeleteUser)
	})

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return &scimAuditTestEnv{
		ts:           ts,
		srv:          srv,
		db:           db,
		ew:           ew,
		aw:           aw,
		orgID:        org.ID,
		scimConfigID: scimCfg.ID,
		rawToken:     rawToken,
	}
}

// scimAuditRequest makes an HTTP request to the SCIM endpoint.
func (env *scimAuditTestEnv) scimAuditRequest(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2%s", env.ts.URL, env.orgID, path)
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.rawToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

// queryAuditEntries returns audit log entries matching the given entity type for the test org.
func (env *scimAuditTestEnv) queryAuditEntries(t *testing.T, entityType string) []auditRow {
	t.Helper()
	env.aw.Flush()
	rows, err := env.db.Pool().Query(context.Background(),
		"SELECT entity_type, action, entity_id, success, new_state, metadata FROM audit_log WHERE org_id = $1 AND entity_type = $2 ORDER BY created_at",
		env.orgID, entityType)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	var result []auditRow
	for rows.Next() {
		var r auditRow
		var newState, metadata *[]byte
		if err := rows.Scan(&r.EntityType, &r.Action, &r.EntityID, &r.Success, &newState, &metadata); err != nil {
			t.Fatalf("scan audit_log: %v", err)
		}
		if newState != nil {
			r.NewState = *newState
		}
		if metadata != nil {
			r.Metadata = *metadata
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("audit_log rows: %v", err)
	}
	return result
}

// auditRow is a simplified audit log row for test assertions.
type auditRow struct {
	EntityType string
	Action     string
	EntityID   string
	Success    bool
	NewState   []byte
	Metadata   []byte
}

func TestSCIMAudit_UserProvisionAuditEntry(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)

	// POST /Users — create a brand new user.
	body := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "provision-audit@example.com",
		"externalId": "ext-provision-audit-001",
	}
	resp := env.scimAuditRequest(t, http.MethodPost, "/Users", body)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /Users: got %d, want 201/200. Body: %s", resp.StatusCode, b)
	}

	// Query audit log.
	entries := env.queryAuditEntries(t, "member")
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry for entity_type=member, got 0")
	}

	// Find the create entry.
	var found bool
	for _, e := range entries {
		if e.Action == "create" {
			found = true
			if !e.Success {
				t.Error("audit entry Success should be true")
			}
			// Check metadata contains source=scim.
			if e.Metadata != nil {
				var meta map[string]any
				if err := json.Unmarshal(e.Metadata, &meta); err == nil {
					if meta["source"] != "scim" {
						t.Errorf("metadata.source = %v, want scim", meta["source"])
					}
					if meta["scim_config_id"] != env.scimConfigID.String() {
						t.Errorf("metadata.scim_config_id = %v, want %s", meta["scim_config_id"], env.scimConfigID)
					}
				}
			} else {
				t.Error("audit entry metadata should not be nil")
			}
		}
	}
	if !found {
		t.Error("expected audit entry with action=create for user provision")
	}
}

func TestSCIMAudit_UserDeprovisionAuditEntry(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)
	ctx := context.Background()

	// Create a user and make them an org member (not the owner).
	user := env.db.MustCreateUser(t, ctx, "deprovision-audit@example.com", "Deprovisioner", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// DELETE /Users/{id} — deactivate.
	resp := env.scimAuditRequest(t, http.MethodDelete, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE /Users: got %d, want 204. Body: %s", resp.StatusCode, b)
	}

	// Query audit log.
	entries := env.queryAuditEntries(t, "member")
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry for entity_type=member, got 0")
	}

	// Find the update entry for deactivation.
	var found bool
	for _, e := range entries {
		if e.Action == "update" && e.EntityID == user.ID.String() {
			found = true
			if !e.Success {
				t.Error("audit entry Success should be true")
			}
			// Check new_state has active=false.
			if e.NewState != nil {
				var ns map[string]any
				if err := json.Unmarshal(e.NewState, &ns); err == nil {
					if ns["active"] != false {
						t.Errorf("new_state.active = %v, want false", ns["active"])
					}
				}
			}
			// Check metadata has source=scim.
			if e.Metadata != nil {
				var meta map[string]any
				if err := json.Unmarshal(e.Metadata, &meta); err == nil {
					if meta["source"] != "scim" {
						t.Errorf("metadata.source = %v, want scim", meta["source"])
					}
				}
			}
		}
	}
	if !found {
		t.Error("expected audit entry with action=update for user deactivation")
	}
}

func TestSCIMAudit_AuthFailureSecurityEvent(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)

	// Make a request with a wrong token.
	wrongToken, _, _, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("GenerateSCIMToken: %v", err)
	}

	rawURL := fmt.Sprintf("%s/api/v1/orgs/%s/scim/v2/Users", env.ts.URL, env.orgID)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	req.Header.Set("Authorization", "Bearer "+wrongToken)

	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// Verify security event was emitted.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMAuthFailed)
	if len(events) == 0 {
		t.Error("expected at least one scim.auth_failed security event, got 0")
	}
	// Verify the event has the correct org_id.
	for _, ev := range events {
		if orgID, ok := ev["org_id"].(*uuid.UUID); ok && orgID != nil {
			if *orgID != env.orgID {
				t.Errorf("security event org_id = %v, want %v", *orgID, env.orgID)
			}
		}
	}
}

func TestSCIMAudit_TokenCreateSecurityEvent(t *testing.T) {
	t.Parallel()
	// This test uses the scimAdminEnv because token creation goes through the admin endpoint.
	env := newSCIMAdminEnv(t)
	env.createSSOForSCIM(t)

	resp := doSCIMConfigCreate(t, env.ts, env.token, env.orgID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create config: got %d, want 201. Body: %s", resp.StatusCode, b)
	}

	// Verify security event was emitted.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMTokenCreated)
	if len(events) == 0 {
		t.Error("expected at least one scim.token_created security event, got 0")
	}
	// Verify event type value.
	for _, ev := range events {
		if ev["event_type"] != secure.EventSCIMTokenCreated {
			t.Errorf("event_type = %v, want %v", ev["event_type"], secure.EventSCIMTokenCreated)
		}
	}
}

func TestSCIMAudit_UserProvisionedSecurityEvent(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)

	// POST /Users — create a brand new user.
	body := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "provisioned-event@example.com",
		"externalId": "ext-provisioned-event-001",
	}
	resp := env.scimAuditRequest(t, http.MethodPost, "/Users", body)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /Users: got %d, want 201/200. Body: %s", resp.StatusCode, b)
	}

	// Verify security event.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMUserProvisioned)
	if len(events) == 0 {
		t.Error("expected at least one scim.user_provisioned security event, got 0")
	}
}

func TestSCIMAudit_UserDeprovisionedSecurityEvent(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)
	ctx := context.Background()

	// Create a user and org membership.
	user := env.db.MustCreateUser(t, ctx, "deprovisioned-event@example.com", "Deprovisioner", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// DELETE /Users/{id} — deactivate.
	resp := env.scimAuditRequest(t, http.MethodDelete, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE /Users: got %d, want 204. Body: %s", resp.StatusCode, b)
	}

	// Verify security event.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMUserDeprovisioned)
	if len(events) == 0 {
		t.Error("expected at least one scim.user_deprovisioned security event, got 0")
	}
}

func TestSCIMAudit_ExemptSuppressedSecurityEvent(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)
	ctx := context.Background()

	// Create a user, make them an org member, then mark scim_exempt.
	user := env.db.MustCreateUser(t, ctx, "exempt-event@example.com", "Exempt User", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "viewer"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}
	if err := env.db.UpdateOrgMemberSCIMExempt(ctx, env.orgID, user.ID, true); err != nil {
		t.Fatalf("UpdateOrgMemberSCIMExempt: %v", err)
	}

	// PATCH /Users/{id} — try to modify exempt user.
	patchBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": "Should Not Change"},
		},
	}
	resp := env.scimAuditRequest(t, http.MethodPatch, "/Users/"+user.ID.String(), patchBody)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH exempt user: got %d, want 200. Body: %s", resp.StatusCode, b)
	}

	// Verify security event.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMExemptSuppressed)
	if len(events) == 0 {
		t.Error("expected at least one scim.exempt_suppressed security event, got 0")
	}

	// Verify audit entry has suppressed metadata.
	entries := env.queryAuditEntries(t, "member")
	var foundSuppressed bool
	for _, e := range entries {
		if e.Metadata != nil {
			var meta map[string]any
			if err := json.Unmarshal(e.Metadata, &meta); err == nil {
				if meta["suppressed"] == true && meta["reason"] == "scim_exempt" {
					foundSuppressed = true
				}
			}
		}
	}
	if !foundSuppressed {
		t.Error("expected audit entry with metadata.suppressed=true and metadata.reason=scim_exempt")
	}
}

func TestSCIMAudit_SoleOwnerProtectedSecurityEvent(t *testing.T) {
	t.Parallel()
	env := newSCIMAuditTestEnv(t)
	ctx := context.Background()

	// Create a user, make them the sole owner of the org.
	user := env.db.MustCreateUser(t, ctx, "sole-owner-event@example.com", "Sole Owner", "", 0)
	if err := env.db.CreateOrgMember(ctx, env.orgID, user.ID, "owner"); err != nil {
		t.Fatalf("CreateOrgMember: %v", err)
	}

	// DELETE /Users/{id} — try to deactivate sole owner.
	resp := env.scimAuditRequest(t, http.MethodDelete, "/Users/"+user.ID.String(), nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE sole owner: got %d, want 400. Body: %s", resp.StatusCode, b)
	}

	// Verify security event.
	events := flushAndQueryEvents(t, env.ew, env.db, secure.EventSCIMSoleOwnerProtected)
	if len(events) == 0 {
		t.Error("expected at least one scim.sole_owner_protected security event, got 0")
	}
}
