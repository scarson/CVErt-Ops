// ABOUTME: Tests that audit entries record which API key performed a mutation.
// ABOUTME: Drives real requests with a key and with a session cookie, then reads the audit-log API.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAuditLog_RecordsActingAPIKey(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, aw, token, orgID := setupAuditAPIOrg(t, db)

	user, err := db.GetUserByEmail(ctx, "audit-api@example.com")
	if err != nil || user == nil {
		t.Fatalf("get user: %v", err)
	}
	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	key, err := db.CreateAPIKey(ctx, orgID, user.ID, keyHash, "audit-key", "admin", sql.NullTime{})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	// One channel created with the API key, one with the session cookie.
	keyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID.String()+"/channels",
		bytes.NewBufferString(`{"name":"by-key","type":"webhook","config":{"url":"https://example.com/key"}}`))
	keyReq.Header.Set("Content-Type", "application/json")
	keyReq.Header.Set("Authorization", "Bearer "+rawKey)
	keyResp, err := ts.Client().Do(keyReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create channel with key: %v", err)
	}
	if keyResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(keyResp.Body)
		t.Fatalf("create channel with key: got %d, body: %s", keyResp.StatusCode, b)
	}
	keyResp.Body.Close() //nolint:errcheck,gosec

	cookieResp := doCreateChannel(t, ctx, ts, token, orgID.String(),
		`{"name":"by-session","type":"webhook","config":{"url":"https://example.com/session"}}`)
	if cookieResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(cookieResp.Body)
		t.Fatalf("create channel with session: got %d, body: %s", cookieResp.StatusCode, b)
	}
	cookieResp.Body.Close() //nolint:errcheck,gosec

	aw.Flush()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgID.String()+"/audit-log?entity_type=channel", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("list audit log: got %d, body: %s", resp.StatusCode, b)
	}
	var list struct {
		Items []struct {
			EntityName string  `json:"entity_name"`
			ActorID    *string `json:"actor_id"`
			APIKeyID   *string `json:"api_key_id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode audit log: %v", err)
	}

	seen := map[string]bool{}
	for _, item := range list.Items {
		seen[item.EntityName] = true
		if item.ActorID == nil || *item.ActorID != user.ID.String() {
			t.Errorf("%s: actor_id = %v, want %s", item.EntityName, item.ActorID, user.ID)
		}
		switch item.EntityName {
		case "by-key":
			if item.APIKeyID == nil || *item.APIKeyID != key.ID.String() {
				t.Errorf("by-key: api_key_id = %v, want %s", item.APIKeyID, key.ID)
			}
		case "by-session":
			if item.APIKeyID != nil {
				t.Errorf("by-session: api_key_id = %q, want absent", *item.APIKeyID)
			}
		}
	}
	if !seen["by-key"] || !seen["by-session"] {
		t.Fatalf("audit log entries = %+v, want both by-key and by-session", list.Items)
	}
}
