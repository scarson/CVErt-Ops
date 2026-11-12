// ABOUTME: Tests for the API server the serve command builds (newAPIServer).
// ABOUTME: Integration tests against a real Postgres via testcontainers (Docker).
package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/api"
	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestNewAPIServer_AuditsMutations verifies that the production server writes
// handler mutations to audit_log.
func TestNewAPIServer_AuditsMutations(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	secret := "serve-test-jwt-secret-at-least-32-bytes"                                                  //nolint:gosec // G101: test credentials
	srv, auditWriter, err := newAPIServer(db.Store, &config.Config{JWTSecret: secret}, api.ServerDeps{}) //nolint:exhaustruct // test: only JWT secret needed
	if err != nil {
		t.Fatalf("newAPIServer: %v", err)
	}
	t.Cleanup(auditWriter.Flush)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	user, err := db.CreateUser(ctx, "auditor@example.com", "Auditor", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	org, err := db.CreateOrg(ctx, "AuditOrg")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "owner"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	body := `{"name":"audit-hook","type":"webhook","config":{"url":"https://example.com/hook"}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+org.ID.String()+"/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token}) //nolint:gosec // G124: request cookie; Secure/HttpOnly/SameSite are response-only attributes
	resp, err := ts.Client().Do(req)                                //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create channel: got %d, body: %s", resp.StatusCode, b)
	}

	// The audit writer is asynchronous; poll until the entry lands.
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		rows, err := db.ListAuditEntries(ctx, store.AuditListParams{ //nolint:exhaustruct // unset filters match all
			OrgID:      org.ID,
			EntityType: "channel",
			After:      time.Now().Add(-time.Hour),
			Before:     time.Now().Add(time.Hour),
			PageSize:   10,
		})
		if err != nil {
			t.Fatalf("list audit entries: %v", err)
		}
		if len(rows) > 0 {
			if rows[0].Action != "create" {
				t.Errorf("audit action = %q, want %q", rows[0].Action, "create")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("channel creation was not written to audit_log within 5s")
		}
		<-ticker.C
	}
}
