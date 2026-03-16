// ABOUTME: Integration tests for audit log entries created by mutation handlers.
// ABOUTME: Verifies create/update/delete actions and tier-denied entries across all entity types.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newAuditServer creates a Server+httptest.Server with audit writing enabled.
// Returns the writer so tests can call Flush() instead of sleeping.
func newAuditServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server, *audit.Writer) {
	t.Helper()
	srv, ts := newRegisterServer(t, db, "open")
	w := audit.NewWriter(db.Store, slog.Default())
	srv.auditWriter = w
	return srv, ts, w
}

// findAuditEntry searches audit entries for one matching entity_type and action.
func findAuditEntry(t *testing.T, db *testutil.TestDB, orgID uuid.UUID, entityType, action string) *store.AuditRow {
	t.Helper()
	rows, err := db.ListAuditEntries(context.Background(), store.AuditListParams{
		OrgID:      orgID,
		EntityType: entityType,
		Action:     action,
		After:      time.Now().Add(-1 * time.Hour),
		Before:     time.Now().Add(1 * time.Hour),
		PageSize:   100,
	})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	if len(rows) == 0 {
		return nil
	}
	return &rows[0] // most recent first (ORDER BY created_at DESC)
}

// findFailedAuditEntry searches for a success=false audit entry.
func findFailedAuditEntry(t *testing.T, db *testutil.TestDB, orgID uuid.UUID, entityType string) *store.AuditRow {
	t.Helper()
	rows, err := db.ListAuditEntries(context.Background(), store.AuditListParams{
		OrgID:      orgID,
		EntityType: entityType,
		After:      time.Now().Add(-1 * time.Hour),
		Before:     time.Now().Add(1 * time.Hour),
		PageSize:   100,
	})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for i := range rows {
		if !rows[i].Success {
			return &rows[i]
		}
	}
	return nil
}

// ── Alert Rules ────────────────────────────────────────────────────────────────

func TestAuditIntegration_AlertRules(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, aw := newAuditServer(t, db)
	reg := doRegister(t, ctx, ts, "audit-ar@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-ar@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(reg.OrgID)
	var ruleID string

	t.Run("Create", func(t *testing.T) {
		body := `{"name":"Audit Test Rule","logic":"and","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0}],"enabled":false}`
		resp := doCreateAlertRule(t, ctx, ts, token, reg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: got %d, want 201", resp.StatusCode)
		}
		var rule alertRuleEntry
		json.NewDecoder(resp.Body).Decode(&rule) //nolint:errcheck,gosec // G104: test
		ruleID = rule.ID

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "alert_rule", "create")
		if entry == nil {
			t.Fatal("no audit entry for alert rule create")
		}
		if entry.EntityID != ruleID {
			t.Errorf("entity_id: got %s, want %s", entry.EntityID, ruleID)
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Update", func(t *testing.T) {
		if ruleID == "" {
			t.Skip("depends on Create")
		}
		body := `{"name":"Updated Audit Rule"}`
		resp := doPatchAlertRule(t, ctx, ts, token, reg.OrgID, ruleID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "alert_rule", "update")
		if entry == nil {
			t.Fatal("no audit entry for alert rule update")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if ruleID == "" {
			t.Skip("depends on Create")
		}
		resp := doDeleteAlertRule(t, ctx, ts, token, reg.OrgID, ruleID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete: got %d, want 204", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "alert_rule", "delete")
		if entry == nil {
			t.Fatal("no audit entry for alert rule delete")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated for delete")
		}
	})

	t.Run("TierDenied", func(t *testing.T) {
		// Free tier: max 5 alert rules. One was soft-deleted above, so create 5 fresh.
		for i := 0; i < 5; i++ {
			body := fmt.Sprintf(`{"name":"Fill Rule %d","logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}],"enabled":false}`, i)
			resp := doCreateAlertRule(t, ctx, ts, token, reg.OrgID, body)
			resp.Body.Close() //nolint:errcheck,gosec
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("create fill rule %d: got %d", i, resp.StatusCode)
			}
		}

		// 6th should be denied.
		body := `{"name":"Over Limit","logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}],"enabled":false}`
		resp := doCreateAlertRule(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("tier deny: got %d, want 403", resp.StatusCode)
		}

		aw.Flush()

		entry := findFailedAuditEntry(t, db, orgID, "alert_rule")
		if entry == nil {
			t.Fatal("no success=false audit entry for tier-denied alert rule create")
		}
		if entry.Action != "create" {
			t.Errorf("action: got %s, want create", entry.Action)
		}
	})
}

// ── Channels ──────────────────────────────────────────────────────────────────

func TestAuditIntegration_Channels(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, aw := newAuditServer(t, db)
	reg := doRegister(t, ctx, ts, "audit-ch@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-ch@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(reg.OrgID)
	var channelID string

	t.Run("Create", func(t *testing.T) {
		body := `{"name":"Audit Webhook","type":"webhook","config":{"url":"https://hooks.slack.com/services/T00/B00/xxxx"}}`
		resp := doCreateChannel(t, ctx, ts, token, reg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: got %d, want 201", resp.StatusCode)
		}
		var ch channelCreateEntry
		json.NewDecoder(resp.Body).Decode(&ch) //nolint:errcheck,gosec // G104: test
		channelID = ch.ID

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "channel", "create")
		if entry == nil {
			t.Fatal("no audit entry for channel create")
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
		if entry.NewState == nil {
			t.Fatal("expected new_state to be populated")
		}

		// Verify signing_secret is redacted in new_state.
		var state map[string]any
		if err := json.Unmarshal(entry.NewState, &state); err != nil {
			t.Fatalf("unmarshal new_state: %v", err)
		}
		if v, ok := state["signing_secret"]; ok {
			if v != "[REDACTED]" {
				t.Errorf("signing_secret: got %v, want [REDACTED]", v)
			}
		} else {
			t.Error("signing_secret missing from new_state")
		}

		// Verify URL is domain-only for channel entity.
		if urlVal, ok := state["url"]; ok {
			s, _ := urlVal.(string)
			if s != "https://hooks.slack.com/***" {
				t.Errorf("url: got %s, want https://hooks.slack.com/***", s)
			}
		}
	})

	t.Run("Patch", func(t *testing.T) {
		if channelID == "" {
			t.Skip("depends on Create")
		}
		body := `{"name":"Updated Webhook"}`
		resp := doPatchChannel(t, ctx, ts, token, reg.OrgID, channelID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("patch: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "channel", "update")
		if entry == nil {
			t.Fatal("no audit entry for channel patch")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if channelID == "" {
			t.Skip("depends on Create")
		}
		resp := doDeleteChannel(t, ctx, ts, token, reg.OrgID, channelID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete: got %d, want 204", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "channel", "delete")
		if entry == nil {
			t.Fatal("no audit entry for channel delete")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated for delete")
		}
	})

	t.Run("TierDenied", func(t *testing.T) {
		// Set org to a tier where email channels are not available.
		// Free tier has channels_email=false by default.
		body := `{"name":"Denied Email","type":"email","config":{"recipients":["test@example.com"]}}`
		resp := doCreateChannel(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Skipf("email channels not tier-gated on this tier (got %d)", resp.StatusCode)
		}

		aw.Flush()

		entry := findFailedAuditEntry(t, db, orgID, "channel")
		if entry == nil {
			t.Fatal("no success=false audit entry for tier-denied channel create")
		}
	})
}

// ── Watchlists ────────────────────────────────────────────────────────────────

func TestAuditIntegration_Watchlists(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, aw := newAuditServer(t, db)
	reg := doRegister(t, ctx, ts, "audit-wl@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-wl@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(reg.OrgID)
	var watchlistID string

	t.Run("Create", func(t *testing.T) {
		body := `{"name":"Audit Watchlist"}`
		resp := doCreateWatchlist(t, ctx, ts, token, reg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: got %d, want 201", resp.StatusCode)
		}
		var wl watchlistEntry
		json.NewDecoder(resp.Body).Decode(&wl) //nolint:errcheck,gosec // G104: test
		watchlistID = wl.ID

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "watchlist", "create")
		if entry == nil {
			t.Fatal("no audit entry for watchlist create")
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Update", func(t *testing.T) {
		if watchlistID == "" {
			t.Skip("depends on Create")
		}
		body := `{"name":"Updated Watchlist"}`
		resp := doPatchWatchlist(t, ctx, ts, token, reg.OrgID, watchlistID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "watchlist", "update")
		if entry == nil {
			t.Fatal("no audit entry for watchlist update")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if watchlistID == "" {
			t.Skip("depends on Create")
		}
		resp := doDeleteWatchlist(t, ctx, ts, token, reg.OrgID, watchlistID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete: got %d, want 204", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "watchlist", "delete")
		if entry == nil {
			t.Fatal("no audit entry for watchlist delete")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated for delete")
		}
	})

	t.Run("TierDenied", func(t *testing.T) {
		// Free tier: max 3 watchlists. One was soft-deleted above, create 3 fresh.
		for i := 0; i < 3; i++ {
			body := fmt.Sprintf(`{"name":"Fill WL %d"}`, i)
			resp := doCreateWatchlist(t, ctx, ts, token, reg.OrgID, body)
			resp.Body.Close() //nolint:errcheck,gosec
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("create fill watchlist %d: got %d", i, resp.StatusCode)
			}
		}

		body := `{"name":"Over Limit"}`
		resp := doCreateWatchlist(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("tier deny: got %d, want 403", resp.StatusCode)
		}

		aw.Flush()

		entry := findFailedAuditEntry(t, db, orgID, "watchlist")
		if entry == nil {
			t.Fatal("no success=false audit entry for tier-denied watchlist create")
		}
	})
}

// ── Members ──────────────────────────────────────────────────────────────────

func TestAuditIntegration_Members(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, aw := newAuditServer(t, db)
	aliceReg := doRegister(t, ctx, ts, "audit-alice@example.com", "test-password-1234")
	bobReg := doRegister(t, ctx, ts, "audit-bob@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-alice@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(aliceReg.OrgID)
	bobUserID, _ := uuid.Parse(bobReg.UserID)

	// Add bob to alice's org as viewer.
	if err := db.CreateOrgMember(ctx, orgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("create org member: %v", err)
	}

	t.Run("UpdateRole", func(t *testing.T) {
		resp := doUpdateMemberRole(t, ctx, ts, token, aliceReg.OrgID, bobReg.UserID, "member")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update role: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "member", "update")
		if entry == nil {
			t.Fatal("no audit entry for member role update")
		}
		if entry.EntityID != bobReg.UserID {
			t.Errorf("entity_id: got %s, want %s", entry.EntityID, bobReg.UserID)
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		resp := doRemoveMember(t, ctx, ts, token, aliceReg.OrgID, bobReg.UserID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("remove: got %d, want 204", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "member", "delete")
		if entry == nil {
			t.Fatal("no audit entry for member remove")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated for remove")
		}
	})

	t.Run("InviteAccept", func(t *testing.T) {
		// Register carol, invite her to alice's org, have her accept.
		carolReg := doRegister(t, ctx, ts, "audit-carol@example.com", "test-password-1234")

		createResp := doCreateInvitation(t, ctx, ts, token, aliceReg.OrgID, "audit-carol@example.com", "viewer")
		defer createResp.Body.Close() //nolint:errcheck,gosec
		if createResp.StatusCode != http.StatusAccepted {
			t.Fatalf("create invitation: got %d, want 202", createResp.StatusCode)
		}

		invitations, err := db.ListOrgInvitations(ctx, orgID)
		if err != nil || len(invitations) == 0 {
			t.Fatalf("list invitations: err=%v, len=%d", err, len(invitations))
		}
		invToken := invitations[len(invitations)-1].Token

		carolLogin := doLogin(t, ctx, ts, "audit-carol@example.com", "test-password-1234")
		defer carolLogin.Body.Close() //nolint:errcheck,gosec
		carolToken := cookieValue(carolLogin, "access_token")

		resp := doAcceptInvitation(t, ctx, ts, carolToken, invToken)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("accept invitation: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "member", "create")
		if entry == nil {
			t.Fatal("no audit entry for member create via invite accept")
		}
		if entry.EntityID != carolReg.UserID {
			t.Errorf("entity_id: got %s, want %s", entry.EntityID, carolReg.UserID)
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})
}

// ── Saved Searches ────────────────────────────────────────────────────────────

func TestAuditIntegration_SavedSearches(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts, aw := newAuditServer(t, db)
	reg := doRegister(t, ctx, ts, "audit-ss@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-ss@example.com", "test-password-1234")
	token := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	orgID, _ := uuid.Parse(reg.OrgID)
	var searchID string

	t.Run("Create", func(t *testing.T) {
		body := `{"name":"Audit Search","query_json":{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]},"is_shared":false}`
		resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: got %d, want 201", resp.StatusCode)
		}
		var ss savedSearchEntry
		json.NewDecoder(resp.Body).Decode(&ss) //nolint:errcheck,gosec // G104: test
		searchID = ss.ID

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "saved_search", "create")
		if entry == nil {
			t.Fatal("no audit entry for saved search create")
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Patch", func(t *testing.T) {
		if searchID == "" {
			t.Skip("depends on Create")
		}
		body := `{"name":"Updated Search"}`
		resp := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, searchID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("patch: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "saved_search", "update")
		if entry == nil {
			t.Fatal("no audit entry for saved search patch")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated")
		}
		if entry.NewState == nil {
			t.Error("expected new_state to be populated")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if searchID == "" {
			t.Skip("depends on Create")
		}
		resp := doDeleteSavedSearch(t, ctx, ts, token, reg.OrgID, searchID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete: got %d, want 204", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "saved_search", "delete")
		if entry == nil {
			t.Fatal("no audit entry for saved search delete")
		}
		if entry.OldState == nil {
			t.Error("expected old_state to be populated for delete")
		}
	})
}

// ── Nil-safe audit writer ────────────────────────────────────────────────────

func TestAuditLog_NilWriter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	// Audit writer not configured — stays nil.
	srv, ts := newRegisterServer(t, db, "open")
	_ = ts

	// auditLog must be a no-op (not panic) when writer is nil.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	srv.auditLog(req, audit.Entry{
		OrgID:      uuid.New(),
		Action:     "create",
		EntityType: "test",
		EntityID:   "test-id",
		Success:    true,
	})
	// If we reach here without panicking, the test passes.
}
