// ABOUTME: Integration tests for GET .../alert-events?expand=cve,rule, called with an API key as a script would.
// ABOUTME: Checks the embedded CVE fields, rule name and matching watchlist items, and the expand parameter's validation.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// expandAPIFixture is an org with one rule bound to a watchlist holding a package
// item, one event for a held CVE that the item matches, and a viewer key.
type expandAPIFixture struct {
	server *httptest.Server
	db     *testutil.TestDB
	orgID  uuid.UUID
	ruleID uuid.UUID
	itemID uuid.UUID
	key    string
}

const expandCVEID = "CVE-2024-72001"

func newExpandAPIFixture(t *testing.T) *expandAPIFixture {
	t.Helper()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	org, err := db.CreateOrg(ctx, "Expand API Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	owner, err := db.CreateUser(ctx, "expand-owner@example.test", "Owner", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, owner.ID, "owner"); err != nil {
		t.Fatalf("add member: %v", err)
	}
	raw, hash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := db.CreateAPIKey(ctx, org.ID, owner.ID, hash, "poller", "viewer", sql.NullTime{}); err != nil {
		t.Fatalf("create key: %v", err)
	}

	severity, score, kev := "HIGH", 7.5, true
	if err := merge.Ingest(ctx, db.Store, feed.CanonicalPatch{
		CVEID: expandCVEID, Status: "published", Severity: &severity, CVSSv3Score: &score, InCISAKEV: &kev,
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "Requests", Introduced: "0", Fixed: "2.32.0"}},
	}, "osv"); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx, `UPDATE cves SET epss_score = 0.25 WHERE cve_id = $1`, expandCVEID); err != nil {
		t.Fatalf("set epss: %v", err)
	}

	wl, err := db.CreateWatchlist(ctx, org.ID, uuid.NullUUID{}, "python", sql.NullString{})
	if err != nil {
		t.Fatalf("create watchlist: %v", err)
	}
	eco, name := "PyPI", "requests"
	item, err := db.CreateWatchlistItem(ctx, org.ID, wl.ID, store.CreateWatchlistItemParams{
		ItemType: generated.WatchlistItemTypePackage, Ecosystem: &eco, PackageName: &name,
	})
	if err != nil {
		t.Fatalf("create item: %v", err)
	}
	rule, err := db.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:         "Python deps",
		Logic:        "and",
		Conditions:   json.RawMessage(`[{"field":"cvss_v3_score","operator":"gte","value":0}]`),
		WatchlistIds: []uuid.UUID{wl.ID},
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := db.InsertAlertEvent(ctx, org.ID, rule.ID, expandCVEID, "hash-1", false); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	// Polling tests send more requests than the free tier's burst allows.
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE organizations SET tier_overrides = '{"api_rate_limit": 100000}' WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("raise rate limit: %v", err)
	}

	srv := newAuthTestServer(t, "test-jwt-secret-alert-expand", db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &expandAPIFixture{server: ts, db: db, orgID: org.ID, ruleID: rule.ID, itemID: item.ID, key: raw}
}

func (f *expandAPIFixture) list(t *testing.T, query string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		f.server.URL+"/api/v1/orgs/"+f.orgID.String()+"/alert-events"+query, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.key)
	resp, err := f.server.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, body
}

func TestAlertEvents_ExpandCVEAndRule(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t)

	status, body := f.list(t, "?expand=cve,rule")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, body)
	}
	var list struct {
		Items []struct {
			CveID string `json:"cve_id"`
			CVE   *struct {
				Status      *string  `json:"status"`
				Severity    *string  `json:"severity"`
				CVSSv3Score *float64 `json:"cvss_v3_score"`
				InCISAKEV   bool     `json:"in_cisa_kev"`
				EPSSScore   *float64 `json:"epss_score"`
			} `json:"cve"`
			Rule *struct {
				Name                  string `json:"name"`
				Deleted               bool   `json:"deleted"`
				MatchedWatchlistItems []struct {
					WatchlistID string `json:"watchlist_id"`
					ItemID      string `json:"item_id"`
					ItemType    string `json:"item_type"`
					Ecosystem   string `json:"ecosystem"`
					PackageName string `json:"package_name"`
				} `json:"matched_watchlist_items"`
			} `json:"rule"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	if len(list.Items) != 1 {
		t.Fatalf("items = %d, want 1 (body %s)", len(list.Items), body)
	}
	e := list.Items[0]
	if e.CVE == nil || e.CVE.Severity == nil || *e.CVE.Severity != "HIGH" || !e.CVE.InCISAKEV ||
		e.CVE.EPSSScore == nil || *e.CVE.EPSSScore != 0.25 || e.CVE.CVSSv3Score == nil || *e.CVE.CVSSv3Score != 7.5 {
		t.Errorf("cve = %+v, want HIGH, KEV, EPSS 0.25, CVSS 7.5 (body %s)", e.CVE, body)
	}
	if e.Rule == nil || e.Rule.Name != "Python deps" || e.Rule.Deleted {
		t.Fatalf("rule = %+v, want Python deps (body %s)", e.Rule, body)
	}
	if len(e.Rule.MatchedWatchlistItems) != 1 {
		t.Fatalf("matched_watchlist_items = %+v, want the requests item", e.Rule.MatchedWatchlistItems)
	}
	m := e.Rule.MatchedWatchlistItems[0]
	if m.ItemID != f.itemID.String() || m.ItemType != "package" || m.Ecosystem != "PyPI" || m.PackageName != "requests" {
		t.Errorf("match = %+v, want the PyPI requests item %s", m, f.itemID)
	}
}

// TestAlertEvents_NoExpandOmitsContext keeps the list unchanged without expand.
func TestAlertEvents_NoExpandOmitsContext(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t)
	status, body := f.list(t, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, body)
	}
	var list struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(list.Items))
	}
	for _, k := range []string{"cve", "rule"} {
		if _, ok := list.Items[0][k]; ok {
			t.Errorf("%q present without expand (body %s)", k, body)
		}
	}
}

func TestAlertEvents_ExpandRejectsUnknownValue(t *testing.T) {
	t.Parallel()
	f := newExpandAPIFixture(t)
	for _, q := range []string{"?expand=cve,watchlist", "?expand=", "?expand=cve,,rule"} {
		if status, body := f.list(t, q); status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", q, status, body)
		}
	}
	if status, body := f.list(t, "?expand=rule"); status != http.StatusOK {
		t.Errorf("expand=rule: status = %d, want 200 (body %s)", status, body)
	}
}
