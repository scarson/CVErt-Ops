// ABOUTME: Integration tests for watchlist and watchlist item HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── HTTP helper functions ─────────────────────────────────────────────────────

func doCreateWatchlist(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/watchlists", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create watchlist: %v", err)
	}
	return resp
}

func doGetWatchlist(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get watchlist: %v", err)
	}
	return resp
}

func doListWatchlists(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/watchlists", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list watchlists: %v", err)
	}
	return resp
}

func doPatchWatchlist(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+id, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("patch watchlist: %v", err)
	}
	return resp
}

func doDeleteWatchlist(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("delete watchlist: %v", err)
	}
	return resp
}

func doCreateWatchlistItem(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, watchlistID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+watchlistID+"/items",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create watchlist item: %v", err)
	}
	return resp
}

func doListWatchlistItems(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, watchlistID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+watchlistID+"/items", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list watchlist items: %v", err)
	}
	return resp
}

func doDeleteWatchlistItem(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, watchlistID, itemID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+watchlistID+"/items/"+itemID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("delete watchlist item: %v", err)
	}
	return resp
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestWatchlistCRUD verifies create, get, list, update, delete for watchlists.
func TestWatchlistCRUD(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create
	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"My List","description":"test list"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create watchlist: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created watchlist has empty ID")
	}
	if created.Name != "My List" {
		t.Errorf("name = %q, want %q", created.Name, "My List")
	}

	// Get
	getResp := doGetWatchlist(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get watchlist: got %d, want 200", getResp.StatusCode)
	}
	var got struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		ItemCount int64  `json:"item_count"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("get id = %q, want %q", got.ID, created.ID)
	}

	// List
	listResp := doListWatchlists(t, ctx, ts, token, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list watchlists: got %d, want 200", listResp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Items) != 1 {
		t.Errorf("got %d watchlists, want 1", len(listed.Items))
	}

	// Patch name
	patchResp := doPatchWatchlist(t, ctx, ts, token, aliceReg.OrgID, created.ID, `{"name":"Renamed"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch watchlist: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched.Name != "Renamed" {
		t.Errorf("patched name = %q, want %q", patched.Name, "Renamed")
	}

	// Delete
	deleteResp := doDeleteWatchlist(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer deleteResp.Body.Close() //nolint:errcheck,gosec // G104
	if deleteResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete watchlist: got %d, want 204", deleteResp.StatusCode)
	}

	// Get after delete → 404
	getAfterResp := doGetWatchlist(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer getAfterResp.Body.Close() //nolint:errcheck,gosec // G104
	if getAfterResp.StatusCode != http.StatusNotFound {
		t.Errorf("get deleted: got %d, want 404", getAfterResp.StatusCode)
	}
}

// TestWatchlistItems_PackageAndCPE verifies add, list, delete for package and CPE items.
func TestWatchlistItems_PackageAndCPE(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Items Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode watchlist: %v", err)
	}

	// Add package item
	pkgBody := `{"item_type":"package","ecosystem":"npm","package_name":"express"}`
	pkgResp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, pkgBody)
	defer pkgResp.Body.Close() //nolint:errcheck,gosec // G104
	if pkgResp.StatusCode != http.StatusCreated {
		t.Fatalf("add package item: got %d, want 201", pkgResp.StatusCode)
	}
	var pkgItem struct {
		ID       string `json:"id"`
		ItemType string `json:"item_type"`
	}
	if err := json.NewDecoder(pkgResp.Body).Decode(&pkgItem); err != nil {
		t.Fatalf("decode pkg item: %v", err)
	}
	if pkgItem.ItemType != "package" {
		t.Errorf("item_type = %q, want %q", pkgItem.ItemType, "package")
	}

	// Add CPE item
	cpeBody := `{"item_type":"cpe","cpe_normalized":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}`
	cpeResp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, cpeBody)
	defer cpeResp.Body.Close() //nolint:errcheck,gosec // G104
	if cpeResp.StatusCode != http.StatusCreated {
		t.Fatalf("add cpe item: got %d, want 201", cpeResp.StatusCode)
	}

	// List items
	listResp := doListWatchlistItems(t, ctx, ts, token, aliceReg.OrgID, wl.ID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list items: got %d, want 200", listResp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode items list: %v", err)
	}
	if len(listed.Items) != 2 {
		t.Errorf("got %d items, want 2", len(listed.Items))
	}

	// Delete package item
	deleteResp := doDeleteWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, pkgItem.ID)
	defer deleteResp.Body.Close() //nolint:errcheck,gosec // G104
	if deleteResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete item: got %d, want 204", deleteResp.StatusCode)
	}

	// List after delete → 1 item
	listResp2 := doListWatchlistItems(t, ctx, ts, token, aliceReg.OrgID, wl.ID)
	defer listResp2.Body.Close() //nolint:errcheck,gosec // G104
	var listed2 struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp2.Body).Decode(&listed2); err != nil {
		t.Fatalf("decode items list2: %v", err)
	}
	if len(listed2.Items) != 1 {
		t.Errorf("after delete, got %d items, want 1", len(listed2.Items))
	}
}

// TestWatchlistItem_UnknownEcosystem verifies 422 for unknown ecosystem.
func TestWatchlistItem_UnknownEcosystem(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Eco Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode watchlist: %v", err)
	}

	body := `{"item_type":"package","ecosystem":"notanecosystem","package_name":"lodash"}`
	resp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("unknown ecosystem: got %d, want 422", resp.StatusCode)
	}
}

// TestWatchlistItem_MalformedCPE verifies 422 for a CPE that doesn't start with cpe:2.3:.
func TestWatchlistItem_MalformedCPE(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"CPE Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode watchlist: %v", err)
	}

	body := `{"item_type":"cpe","cpe_normalized":"cpe:2.2:a:apache:log4j"}`
	resp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("malformed cpe: got %d, want 422", resp.StatusCode)
	}
}

// TestWatchlistItem_Duplicate verifies 409 on duplicate item insertion.
func TestWatchlistItem_Duplicate(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Dup Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode watchlist: %v", err)
	}

	body := `{"item_type":"package","ecosystem":"npm","package_name":"lodash"}`
	r1 := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, body)
	defer r1.Body.Close() //nolint:errcheck,gosec // G104
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("first insert: got %d, want 201", r1.StatusCode)
	}

	r2 := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID, body)
	defer r2.Body.Close() //nolint:errcheck,gosec // G104
	if r2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate insert: got %d, want 409", r2.StatusCode)
	}
}

// TestWatchlist_ViewerCannotWrite verifies 403 for viewer on write endpoints.
func TestWatchlist_ViewerCannotWrite(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add Bob as viewer: %v", err)
	}

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	resp := doCreateWatchlist(t, ctx, ts, bobToken, aliceReg.OrgID, `{"name":"Sneaky"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer create: got %d, want 403", resp.StatusCode)
	}
}

// TestWatchlist_WrongOrg verifies 403/404 for cross-org access.
func TestWatchlist_WrongOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	_ = doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	// Bob tries to create in Alice's org → 403
	resp := doCreateWatchlist(t, ctx, ts, bobToken, aliceReg.OrgID, `{"name":"Hack"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org create: got %d, want 403", resp.StatusCode)
	}
}

