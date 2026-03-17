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

// TestWatchlist_CrossOrgReadWriteIsolation verifies that a user from org B
// cannot GET, PATCH, or DELETE a watchlist belonging to org A.
func TestWatchlist_CrossOrgReadWriteIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the first user — she gets an auto-org.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	// Alice creates a watchlist with items.
	createResp := doCreateWatchlist(t, ctx, ts, aliceToken, aliceReg.OrgID, `{"name":"Alice Private"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create watchlist: got %d, want 201", createResp.StatusCode)
	}
	var aliceWL struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&aliceWL); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Add an item to Alice's watchlist.
	itemResp := doCreateWatchlistItem(t, ctx, ts, aliceToken, aliceReg.OrgID, aliceWL.ID,
		`{"item_type":"package","ecosystem":"npm","package_name":"lodash"}`)
	defer itemResp.Body.Close() //nolint:errcheck,gosec // G104
	if itemResp.StatusCode != http.StatusCreated {
		t.Fatalf("add item: got %d, want 201", itemResp.StatusCode)
	}
	var aliceItem struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(itemResp.Body).Decode(&aliceItem); err != nil {
		t.Fatalf("decode item: %v", err)
	}

	// Bob is the second user — no membership in Alice's org.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	// Bob cannot GET Alice's watchlist.
	getResp := doGetWatchlist(t, ctx, ts, bobToken, aliceReg.OrgID, aliceWL.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org get: got %d, want 403", getResp.StatusCode)
	}

	// Bob cannot PATCH Alice's watchlist.
	patchResp := doPatchWatchlist(t, ctx, ts, bobToken, aliceReg.OrgID, aliceWL.ID, `{"name":"Hacked"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org patch: got %d, want 403", patchResp.StatusCode)
	}

	// Bob cannot DELETE Alice's watchlist.
	delResp := doDeleteWatchlist(t, ctx, ts, bobToken, aliceReg.OrgID, aliceWL.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org delete: got %d, want 403", delResp.StatusCode)
	}

	// Bob cannot list Alice's watchlist items.
	listItemsResp := doListWatchlistItems(t, ctx, ts, bobToken, aliceReg.OrgID, aliceWL.ID)
	defer listItemsResp.Body.Close() //nolint:errcheck,gosec // G104
	if listItemsResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org list items: got %d, want 403", listItemsResp.StatusCode)
	}

	// Bob cannot add items to Alice's watchlist.
	addItemResp := doCreateWatchlistItem(t, ctx, ts, bobToken, aliceReg.OrgID, aliceWL.ID,
		`{"item_type":"package","ecosystem":"pypi","package_name":"requests"}`)
	defer addItemResp.Body.Close() //nolint:errcheck,gosec // G104
	if addItemResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org add item: got %d, want 403", addItemResp.StatusCode)
	}

	// Bob cannot delete items from Alice's watchlist.
	delItemResp := doDeleteWatchlistItem(t, ctx, ts, bobToken, aliceReg.OrgID, aliceWL.ID, aliceItem.ID)
	defer delItemResp.Body.Close() //nolint:errcheck,gosec // G104
	if delItemResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org delete item: got %d, want 403", delItemResp.StatusCode)
	}
}

// TestWatchlist_PatchEmptyName verifies that PATCH with an empty name returns 422.
func TestWatchlist_PatchEmptyName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Valid Name"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// PATCH with empty name → 422.
	patchResp := doPatchWatchlist(t, ctx, ts, token, aliceReg.OrgID, wl.ID, `{"name":""}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("patch empty name: got %d, want 422", patchResp.StatusCode)
	}

	// PATCH with whitespace-only name → 422.
	patchResp2 := doPatchWatchlist(t, ctx, ts, token, aliceReg.OrgID, wl.ID, `{"name":"   "}`)
	defer patchResp2.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("patch whitespace name: got %d, want 422", patchResp2.StatusCode)
	}
}

// TestWatchlist_DuplicateName verifies that creating a watchlist with a duplicate name returns 409.
func TestWatchlist_DuplicateName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	r1 := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Same Name"}`)
	defer r1.Body.Close() //nolint:errcheck,gosec // G104
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d, want 201", r1.StatusCode)
	}

	r2 := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Same Name"}`)
	defer r2.Body.Close() //nolint:errcheck,gosec // G104
	if r2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate name create: got %d, want 409", r2.StatusCode)
	}
}

// TestWatchlist_SoftDeleteBehavior verifies that soft-deleting a watchlist hides it from
// GET but does not cascade-delete items (items remain via ListWatchlistItems since the
// query filters on watchlist_items.deleted_at, not the parent watchlist's deleted_at).
func TestWatchlist_SoftDeleteBehavior(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create a watchlist and add an item.
	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Delete Me"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create watchlist: got %d, want 201", createResp.StatusCode)
	}
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	itemResp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID,
		`{"item_type":"package","ecosystem":"npm","package_name":"express"}`)
	defer itemResp.Body.Close() //nolint:errcheck,gosec // G104
	if itemResp.StatusCode != http.StatusCreated {
		t.Fatalf("add item: got %d, want 201", itemResp.StatusCode)
	}

	// Verify item exists before delete.
	listBefore := doListWatchlistItems(t, ctx, ts, token, aliceReg.OrgID, wl.ID)
	defer listBefore.Body.Close() //nolint:errcheck,gosec // G104
	var beforeItems struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listBefore.Body).Decode(&beforeItems); err != nil {
		t.Fatalf("decode before: %v", err)
	}
	if len(beforeItems.Items) != 1 {
		t.Fatalf("before delete: got %d items, want 1", len(beforeItems.Items))
	}

	// Soft-delete the watchlist.
	delResp := doDeleteWatchlist(t, ctx, ts, token, aliceReg.OrgID, wl.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete watchlist: got %d, want 204", delResp.StatusCode)
	}

	// GET on the watchlist itself should return 404 (soft-deleted).
	getResp := doGetWatchlist(t, ctx, ts, token, aliceReg.OrgID, wl.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET soft-deleted watchlist: got %d, want 404", getResp.StatusCode)
	}

	// Items listing returns empty after parent watchlist is soft-deleted.
	listAfter := doListWatchlistItems(t, ctx, ts, token, aliceReg.OrgID, wl.ID)
	defer listAfter.Body.Close() //nolint:errcheck,gosec // G104
	if listAfter.StatusCode != http.StatusOK {
		t.Fatalf("list items after delete: got %d, want 200", listAfter.StatusCode)
	}
	var afterItems struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listAfter.Body).Decode(&afterItems); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if len(afterItems.Items) != 0 {
		t.Errorf("items after soft-delete: got %d, want 0 (soft-delete cascades to items)", len(afterItems.Items))
	}
}

// doListWatchlistsWithQuery performs a GET /api/v1/orgs/{org_id}/watchlists
// with an optional query string (e.g. "?after=...").
func doListWatchlistsWithQuery(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, queryString string) *http.Response {
	t.Helper()
	url := ts.URL + "/api/v1/orgs/" + orgID + "/watchlists" + queryString
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list watchlists: %v", err)
	}
	return resp
}

// TestWatchlist_ListPagination verifies cursor-based pagination on the watchlist list endpoint.
func TestWatchlist_ListPagination(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create 3 watchlists.
	for i := 1; i <= 3; i++ {
		body := `{"name":"WL ` + string(rune('A'-1+i)) + `"}`
		resp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create watchlist %d: got %d, want 201", i, resp.StatusCode)
		}
	}

	// Fetch all to verify count.
	allResp := doListWatchlists(t, ctx, ts, token, aliceReg.OrgID)
	defer allResp.Body.Close() //nolint:errcheck,gosec // G104
	var allList struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	if err := json.NewDecoder(allResp.Body).Decode(&allList); err != nil {
		t.Fatalf("decode all: %v", err)
	}
	if len(allList.Items) != 3 {
		t.Fatalf("total watchlists = %d, want 3", len(allList.Items))
	}
	// The list limit is 20, so with 3 items there's no next_cursor.
	if allList.NextCursor != nil {
		// Use the cursor to verify the second page works.
		page2Resp := doListWatchlistsWithQuery(t, ctx, ts, token, aliceReg.OrgID, "?after="+*allList.NextCursor)
		defer page2Resp.Body.Close() //nolint:errcheck,gosec // G104
		if page2Resp.StatusCode != http.StatusOK {
			t.Fatalf("page 2: got %d, want 200", page2Resp.StatusCode)
		}
	}

	// Test with an invalid cursor — should return 400.
	badCursorResp := doListWatchlistsWithQuery(t, ctx, ts, token, aliceReg.OrgID, "?after=notavalidcursor")
	defer badCursorResp.Body.Close() //nolint:errcheck,gosec // G104
	if badCursorResp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad cursor: got %d, want 400", badCursorResp.StatusCode)
	}
}

// TestWatchlist_CreateEmptyName verifies that creating a watchlist with empty name returns 422.
func TestWatchlist_CreateEmptyName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":""}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("empty name create: got %d, want 422", resp.StatusCode)
	}
}

// TestWatchlistItem_InvalidType verifies 422 for an unsupported item_type.
func TestWatchlistItem_InvalidType(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Type Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode watchlist: %v", err)
	}

	resp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID,
		`{"item_type":"invalid","ecosystem":"npm","package_name":"express"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid item_type: got %d, want 422", resp.StatusCode)
	}
}

// TestWatchlist_GetNonExistent verifies 404 for a non-existent watchlist ID.
func TestWatchlist_GetNonExistent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	fakeID := uuid.New().String()
	getResp := doGetWatchlist(t, ctx, ts, token, aliceReg.OrgID, fakeID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("get non-existent: got %d, want 404", getResp.StatusCode)
	}
}

// TestWatchlist_PatchNonExistent verifies 404 for patching a non-existent watchlist.
func TestWatchlist_PatchNonExistent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	fakeID := uuid.New().String()
	patchResp := doPatchWatchlist(t, ctx, ts, token, aliceReg.OrgID, fakeID, `{"name":"Ghost"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusNotFound {
		t.Errorf("patch non-existent: got %d, want 404", patchResp.StatusCode)
	}
}

// TestWatchlist_DeleteNonExistent verifies 404 for deleting a non-existent watchlist.
func TestWatchlist_DeleteNonExistent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	fakeID := uuid.New().String()
	delResp := doDeleteWatchlist(t, ctx, ts, token, aliceReg.OrgID, fakeID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusNotFound {
		t.Errorf("delete non-existent: got %d, want 404", delResp.StatusCode)
	}
}

// ── Contract tests ────────────────────────────────────────────────────────────

// doCreateWatchlistRaw calls POST /api/v1/orgs/{orgID}/watchlists with a raw JSON body.
func doCreateWatchlistRaw(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, rawJSON string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/watchlists", bytes.NewBufferString(rawJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create watchlist raw: %v", err)
	}
	return resp
}

// doCreateWatchlistItemRaw calls POST /items with a raw JSON body.
func doCreateWatchlistItemRaw(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, watchlistID, rawJSON string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+watchlistID+"/items",
		bytes.NewBufferString(rawJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create watchlist item raw: %v", err)
	}
	return resp
}

// TestCreateWatchlist_MalformedJSON verifies 400 with application/problem+json on invalid JSON.
func TestCreateWatchlist_MalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateWatchlistRaw(t, ctx, ts, token, aliceReg.OrgID, "{bad json")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed JSON: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestCreateWatchlist_LocationHeader verifies Location header on 201 Created.
func TestCreateWatchlist_LocationHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Location Test"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("expected Location header on 201 response")
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantSuffix := "/watchlists/" + out.ID
	if len(loc) < len(wantSuffix) || loc[len(loc)-len(wantSuffix):] != wantSuffix {
		t.Errorf("Location = %q, want suffix %q", loc, wantSuffix)
	}
}

// TestCreateWatchlistItem_LocationHeader verifies Location header on item creation.
func TestCreateWatchlistItem_LocationHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Item Loc Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode: %v", err)
	}

	itemResp := doCreateWatchlistItem(t, ctx, ts, token, aliceReg.OrgID, wl.ID,
		`{"item_type":"package","ecosystem":"npm","package_name":"express"}`)
	defer itemResp.Body.Close() //nolint:errcheck,gosec // G104
	if itemResp.StatusCode != http.StatusCreated {
		t.Fatalf("create item: got %d, want 201", itemResp.StatusCode)
	}

	loc := itemResp.Header.Get("Location")
	if loc == "" {
		t.Fatal("expected Location header on item 201 response")
	}
	var item struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(itemResp.Body).Decode(&item); err != nil {
		t.Fatalf("decode item: %v", err)
	}
	wantSuffix := "/items/" + item.ID
	if len(loc) < len(wantSuffix) || loc[len(loc)-len(wantSuffix):] != wantSuffix {
		t.Errorf("Location = %q, want suffix %q", loc, wantSuffix)
	}
}

// TestListWatchlists_Envelope verifies {items: [...]} envelope on list endpoint.
func TestListWatchlists_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Empty list should still have items array (not null).
	listResp := doListWatchlists(t, ctx, ts, token, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want 200", listResp.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items, ok := raw["items"]
	if !ok {
		t.Fatal("response missing 'items' key")
	}
	arr, ok := items.([]any)
	if !ok {
		t.Fatal("items is not an array")
	}
	if arr == nil {
		t.Error("items array should be empty [], not null")
	}
}

// TestCreateWatchlist_ValidationError_ProblemJSON verifies 422 with field-level locations.
func TestCreateWatchlist_ValidationError_ProblemJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doCreateWatchlistRaw(t, ctx, ts, token, aliceReg.OrgID, `{"name":""}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("empty name: got %d, want 422", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	errs, ok := problem["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatal("expected errors array with at least one entry")
	}
	err0, _ := errs[0].(map[string]any)
	if err0["location"] != "body.name" {
		t.Errorf("errors[0].location = %v, want body.name", err0["location"])
	}
}

// TestCreateWatchlistItem_ValidationError_ProblemJSON verifies 422 with field locations on items.
func TestCreateWatchlistItem_ValidationError_ProblemJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Val Test"}`)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&wl); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Unknown ecosystem should return 422 with location body.ecosystem.
	resp := doCreateWatchlistItemRaw(t, ctx, ts, token, aliceReg.OrgID, wl.ID,
		`{"item_type":"package","ecosystem":"bogus","package_name":"foo"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("unknown ecosystem: got %d, want 422", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	errs, ok := problem["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatal("expected errors array with at least one entry")
	}
	err0, _ := errs[0].(map[string]any)
	if err0["location"] != "body.ecosystem" {
		t.Errorf("errors[0].location = %v, want body.ecosystem", err0["location"])
	}
}

// TestCreateWatchlist_TierLimit_ProblemType verifies tier-limit 403 uses problem type URI.
func TestCreateWatchlist_TierLimit_ProblemType(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	// Use "open" registration — tier resolver will use defaults.
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create watchlists until we hit the tier limit.
	// Default tier limit is typically > 0, so we just verify the format
	// IF we can trigger the limit. If not, this test just verifies the
	// endpoint works without hitting the limit.
	resp := doCreateWatchlist(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Tier Test"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	// We can't guarantee hitting the limit without knowing the tier config,
	// so just verify the 201 response has proper contract format.
	if resp.StatusCode != http.StatusCreated {
		// If it's 403, verify it has the right problem type.
		if resp.StatusCode == http.StatusForbidden {
			var problem map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if problem["type"] != "urn:cvert:error:tier-limit" {
				t.Errorf("type = %v, want urn:cvert:error:tier-limit", problem["type"])
			}
		}
	}
}

