// ABOUTME: Integration tests for CVE watchlist items and PUT /orgs/{org_id}/watchlists/{id}/items.
// ABOUTME: Runs the full srv.Handler() stack, including the role check and the 1 MiB request limit.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func doReplaceWatchlistItems(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, watchlistID, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+watchlistID+"/items",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("replace watchlist items: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read replace response: %v", err)
	}
	return resp.StatusCode, respBody
}

func cveItemsBody(ids ...string) string {
	items := make([]string, 0, len(ids))
	for _, id := range ids {
		items = append(items, fmt.Sprintf(`{"item_type":"cve","cve_id":%q}`, id))
	}
	return `{"items":[` + strings.Join(items, ",") + `]}`
}

type replaceCounts struct {
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

func mustReplaceItems(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, watchlistID, body string) replaceCounts {
	t.Helper()
	status, respBody := doReplaceWatchlistItems(t, ctx, ts, token, orgID, watchlistID, body)
	if status != http.StatusOK {
		t.Fatalf("replace: got %d, want 200", status)
	}
	var counts replaceCounts
	if err := json.Unmarshal(respBody, &counts); err != nil {
		t.Fatalf("decode replace response: %v", err)
	}
	return counts
}

// listedCVEIDs returns the sorted cve_id of every item on the first page of the watchlist.
func listedCVEIDs(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, watchlistID string) []string {
	t.Helper()
	resp := doListWatchlistItems(t, ctx, ts, token, orgID, watchlistID)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list items: got %d, want 200", resp.StatusCode)
	}
	var listed struct {
		Items []struct {
			ItemType string `json:"item_type"`
			CveID    string `json:"cve_id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	ids := make([]string, 0, len(listed.Items))
	for _, item := range listed.Items {
		if item.ItemType != "cve" {
			t.Errorf("item_type = %q, want cve", item.ItemType)
		}
		ids = append(ids, item.CveID)
	}
	slices.Sort(ids)
	return ids
}

// watchlistFixture registers a user with their own org and logs them in, then creates a watchlist.
func watchlistFixture(t *testing.T, ctx context.Context, ts *httptest.Server, email string) (token, orgID, watchlistID string) {
	t.Helper()
	reg := doRegister(t, ctx, ts, email, "test-password-1234")
	login := doLogin(t, ctx, ts, email, "test-password-1234")
	defer login.Body.Close() //nolint:errcheck,gosec // G104
	token = cookieValue(login, "access_token")

	create := doCreateWatchlist(t, ctx, ts, token, reg.OrgID, `{"name":"Scanner findings"}`)
	defer create.Body.Close() //nolint:errcheck,gosec // G104
	var wl struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&wl); err != nil {
		t.Fatalf("decode watchlist: %v", err)
	}
	return token, reg.OrgID, wl.ID
}

func TestWatchlistItem_CreateCVE(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")

	resp := doCreateWatchlistItem(t, ctx, ts, token, orgID, wlID, `{"item_type":"cve","cve_id":"cve-2024-3094"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create cve item: got %d, want 201", resp.StatusCode)
	}
	var item struct {
		ItemType string `json:"item_type"`
		CveID    string `json:"cve_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode item: %v", err)
	}
	if item.ItemType != "cve" || item.CveID != "CVE-2024-3094" {
		t.Errorf("item = %+v, want cve item with upper-case ID", item)
	}

	dup := doCreateWatchlistItem(t, ctx, ts, token, orgID, wlID, `{"item_type":"cve","cve_id":"CVE-2024-3094"}`)
	defer dup.Body.Close() //nolint:errcheck,gosec // G104
	if dup.StatusCode != http.StatusConflict {
		t.Errorf("duplicate cve item: got %d, want 409", dup.StatusCode)
	}
}

func TestParseWatchlistItem_RejectsMalformedFields(t *testing.T) {
	t.Parallel()
	str := func(s string) *string { return &s }
	long := strings.Repeat("a", 256)

	cases := map[string]createWatchlistItemBody{
		"cve without id":     {ItemType: "cve"},
		"GHSA id":            {ItemType: "cve", CveID: str("GHSA-xxxx-xxxx-xxxx")},
		"short sequence":     {ItemType: "cve", CveID: str("CVE-2024-123")},
		"trailing newline":   {ItemType: "cve", CveID: str("CVE-2024-1234\n")},
		"sql in id":          {ItemType: "cve", CveID: str("CVE-2024-1234' OR '1'='1")},
		"overlong id":        {ItemType: "cve", CveID: str("CVE-2024-" + strings.Repeat("1", 40))},
		"package no name":    {ItemType: "package", Ecosystem: str("npm")},
		"unknown ecosystem":  {ItemType: "package", Ecosystem: str("apt"), PackageName: str("a")},
		"blank package":      {ItemType: "package", Ecosystem: str("npm"), PackageName: str(" ")},
		"overlong package":   {ItemType: "package", Ecosystem: str("npm"), PackageName: str(long)},
		"overlong namespace": {ItemType: "package", Ecosystem: str("npm"), PackageName: str("a"), Namespace: str(long)},
		"NUL in package":     {ItemType: "package", Ecosystem: str("npm"), PackageName: str("a\x00b")},
		"cpe without value":  {ItemType: "cpe"},
		"cpe wrong prefix":   {ItemType: "cpe", CpeNormalized: str("cpe:/a:vendor")},
		"overlong cpe":       {ItemType: "cpe", CpeNormalized: str("cpe:2.3:" + strings.Repeat("a", 512))},
		"unknown item type":  {ItemType: "vendor"},
		"empty item type":    {},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, detail := parseWatchlistItem(body, "body"); detail == nil {
				t.Error("parseWatchlistItem accepted the item")
			}
		})
	}
}

func TestParseWatchlistItem_NormalizesFields(t *testing.T) {
	t.Parallel()
	str := func(s string) *string { return &s }

	cve, detail := parseWatchlistItem(createWatchlistItemBody{ItemType: "cve", CveID: str("cve-2024-3094")}, "body")
	if detail != nil {
		t.Fatalf("cve: %v", detail)
	}
	if *cve.CveID != "CVE-2024-3094" {
		t.Errorf("CveID = %q, want upper case", *cve.CveID)
	}

	pkg, detail := parseWatchlistItem(createWatchlistItemBody{
		ItemType: "package", Ecosystem: str("NPM"), PackageName: str("a"), Namespace: str(""),
	}, "body")
	if detail != nil {
		t.Fatalf("package: %v", detail)
	}
	if *pkg.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want lower case", *pkg.Ecosystem)
	}
	if pkg.Namespace != nil {
		t.Errorf("Namespace = %q, want nil for an empty namespace", *pkg.Namespace)
	}
}

// TestWatchlistItemHandlers_RejectMalformedItem checks both write handlers apply the shared
// validation and change nothing.
func TestWatchlistItemHandlers_RejectMalformedItem(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")
	const item = `{"item_type":"cve","cve_id":"GHSA-xxxx-xxxx-xxxx"}`

	post := doCreateWatchlistItem(t, ctx, ts, token, orgID, wlID, item)
	defer post.Body.Close() //nolint:errcheck,gosec // G104
	if post.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("POST: got %d, want 422", post.StatusCode)
	}
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, `{"items":[`+item+`]}`); status != http.StatusUnprocessableEntity {
		t.Errorf("PUT: got %d, want 422", status)
	}
	if ids := listedCVEIDs(t, ctx, ts, token, orgID, wlID); len(ids) != 0 {
		t.Errorf("rejected requests left items: %v", ids)
	}
}

func TestReplaceWatchlistItemsAPI_ReportsCountsAndConverges(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")

	got := mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"))
	if want := (replaceCounts{Added: 3}); got != want {
		t.Errorf("first push = %+v, want %+v", got, want)
	}

	got = mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"))
	if want := (replaceCounts{Unchanged: 3}); got != want {
		t.Errorf("same push = %+v, want %+v", got, want)
	}

	// Lower case and repeats describe the same list.
	got = mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("cve-2024-0001", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"))
	if want := (replaceCounts{Unchanged: 3}); got != want {
		t.Errorf("push with lower case and repeats = %+v, want %+v", got, want)
	}

	got = mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0002", "CVE-2024-0004"))
	if want := (replaceCounts{Added: 1, Removed: 2, Unchanged: 1}); got != want {
		t.Errorf("smaller push = %+v, want %+v", got, want)
	}
	if ids := listedCVEIDs(t, ctx, ts, token, orgID, wlID); !slices.Equal(ids, []string{"CVE-2024-0002", "CVE-2024-0004"}) {
		t.Errorf("listed = %v", ids)
	}

	got = mustReplaceItems(t, ctx, ts, token, orgID, wlID, `{"items":[]}`)
	if want := (replaceCounts{Removed: 2}); got != want {
		t.Errorf("empty push = %+v, want %+v", got, want)
	}
}

// TestReplaceWatchlistItemsAPI_MissingItemsLeavesListAlone: a client bug that drops the key
// must not read as "clear the list". Only an explicit empty array does that.
func TestReplaceWatchlistItemsAPI_MissingItemsLeavesListAlone(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")
	mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001"))

	for _, body := range []string{`{}`, `{"items":null}`, `{"item":[]}`} {
		status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, body)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("body %s: got %d, want 422", body, status)
		}
	}
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, `{"items":[`); status != http.StatusBadRequest {
		t.Errorf("truncated JSON: got %d, want 400", status)
	}
	if ids := listedCVEIDs(t, ctx, ts, token, orgID, wlID); !slices.Equal(ids, []string{"CVE-2024-0001"}) {
		t.Errorf("listed = %v, want the list untouched", ids)
	}
}

// TestReplaceWatchlistItemsAPI_OneBadItemRejectsAll checks the whole request fails without
// changing anything, and that the error names the offending item.
func TestReplaceWatchlistItemsAPI_OneBadItemRejectsAll(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")
	mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001"))

	status, respBody := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0002", "GHSA-xxxx-xxxx-xxxx"))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", status)
	}
	var problem struct {
		Errors []struct {
			Location string `json:"location"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if len(problem.Errors) != 1 || problem.Errors[0].Location != "body.items[1].cve_id" {
		t.Errorf("errors = %+v, want one at body.items[1].cve_id", problem.Errors)
	}
	if ids := listedCVEIDs(t, ctx, ts, token, orgID, wlID); !slices.Equal(ids, []string{"CVE-2024-0001"}) {
		t.Errorf("listed = %v, want the list untouched", ids)
	}
}

func TestReplaceWatchlistItemsAPI_CapFitsRequestLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")

	ids := make([]string, 0, maxReplaceWatchlistItems+1)
	for i := range maxReplaceWatchlistItems + 1 {
		ids = append(ids, fmt.Sprintf("CVE-2024-%07d", i))
	}

	atCap := cveItemsBody(ids[:maxReplaceWatchlistItems]...)
	if len(atCap) >= 1<<20 {
		t.Fatalf("a request at the cap is %d bytes, over the 1 MiB request limit", len(atCap))
	}
	got := mustReplaceItems(t, ctx, ts, token, orgID, wlID, atCap)
	if want := (replaceCounts{Added: maxReplaceWatchlistItems}); got != want {
		t.Errorf("push at cap = %+v, want %+v", got, want)
	}

	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, cveItemsBody(ids...)); status != http.StatusUnprocessableEntity {
		t.Errorf("push over cap: got %d, want 422", status)
	}

	// A body cut off by the request limit fails to parse, so it can never read as a short list.
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, `{"items":[`+strings.Repeat(" ", 1<<20)+`]}`); status == http.StatusOK {
		t.Error("body over 1 MiB: got 200")
	}
	count, err := db.CountWatchlistItems(ctx, uuid.MustParse(orgID), uuid.MustParse(wlID))
	if err != nil {
		t.Fatalf("CountWatchlistItems: %v", err)
	}
	if count != maxReplaceWatchlistItems {
		t.Errorf("count = %d, want %d: rejected requests changed the list", count, maxReplaceWatchlistItems)
	}
}

func TestReplaceWatchlistItemsAPI_RoleRequirement(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")
	mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001"))

	bob := doRegister(t, ctx, ts, "bob@example.com", "test-password-1234")
	if err := db.CreateOrgMember(ctx, uuid.MustParse(orgID), uuid.MustParse(bob.UserID), "viewer"); err != nil {
		t.Fatalf("add Bob as viewer: %v", err)
	}
	login := doLogin(t, ctx, ts, "bob@example.com", "test-password-1234")
	defer login.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(login, "access_token")

	if status, _ := doReplaceWatchlistItems(t, ctx, ts, bobToken, orgID, wlID, `{"items":[]}`); status != http.StatusForbidden {
		t.Errorf("viewer: got %d, want 403", status)
	}
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, "", orgID, wlID, `{"items":[]}`); status != http.StatusUnauthorized {
		t.Errorf("no credentials: got %d, want 401", status)
	}

	// A cookie session needs the CSRF header on this route like any other write.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		ts.URL+"/api/v1/orgs/"+orgID+"/watchlists/"+wlID+"/items", bytes.NewBufferString(`{"items":[]}`))
	req.Header.Set("Cookie", "access_token="+token)
	csrf, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request without CSRF header: %v", err)
	}
	defer csrf.Body.Close() //nolint:errcheck,gosec // G104
	if csrf.StatusCode != http.StatusForbidden {
		t.Errorf("no CSRF header: got %d, want 403", csrf.StatusCode)
	}

	if ids := listedCVEIDs(t, ctx, ts, token, orgID, wlID); !slices.Equal(ids, []string{"CVE-2024-0001"}) {
		t.Errorf("listed = %v, want the list untouched", ids)
	}
}

// TestReplaceWatchlistItemsAPI_OtherOrgCannotReadOrWrite uses a member of another org who
// knows the watchlist ID. The app-role version of this check is in the store tests.
func TestReplaceWatchlistItemsAPI_OtherOrgCannotReadOrWrite(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	aliceToken, aliceOrg, aliceList := watchlistFixture(t, ctx, ts, "alice@example.com")
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobOrg := db.MustCreateOrg(t, ctx, "Bob's org").ID.String()
	if err := db.CreateOrgMember(ctx, uuid.MustParse(bobOrg), uuid.MustParse(bobReg.UserID), "owner"); err != nil {
		t.Fatalf("add Bob to the second org: %v", err)
	}
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")
	mustReplaceItems(t, ctx, ts, aliceToken, aliceOrg, aliceList, cveItemsBody("CVE-2024-0001"))

	// Alice's org in the path: Bob is not a member.
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, bobToken, aliceOrg, aliceList, `{"items":[]}`); status != http.StatusForbidden {
		t.Errorf("foreign org in path: got %d, want 403", status)
	}
	// Bob's org in the path with Alice's watchlist ID.
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, bobToken, bobOrg, aliceList, `{"items":[]}`); status != http.StatusNotFound {
		t.Errorf("foreign watchlist replace: got %d, want 404", status)
	}
	if ids := listedCVEIDs(t, ctx, ts, bobToken, bobOrg, aliceList); len(ids) != 0 {
		t.Errorf("foreign watchlist read returned %v", ids)
	}

	// A row Bob's org could attach to Alice's watchlist would collide with her unique index.
	post := doCreateWatchlistItem(t, ctx, ts, bobToken, bobOrg, aliceList, `{"item_type":"cve","cve_id":"CVE-2024-0002"}`)
	defer post.Body.Close() //nolint:errcheck,gosec // G104
	if post.StatusCode != http.StatusNotFound {
		t.Errorf("foreign watchlist POST: got %d, want 404", post.StatusCode)
	}
	got := mustReplaceItems(t, ctx, ts, aliceToken, aliceOrg, aliceList, cveItemsBody("CVE-2024-0001", "CVE-2024-0002"))
	if want := (replaceCounts{Added: 1, Unchanged: 1}); got != want {
		t.Errorf("Alice's next push = %+v, want %+v", got, want)
	}
}

func TestReplaceWatchlistItemsAPI_UnknownWatchlist(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")

	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, uuid.NewString(), `{"items":[]}`); status != http.StatusNotFound {
		t.Errorf("unknown id: got %d, want 404", status)
	}
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, "not-a-uuid", `{"items":[]}`); status != http.StatusBadRequest {
		t.Errorf("malformed id: got %d, want 400", status)
	}

	del := doDeleteWatchlist(t, ctx, ts, token, orgID, wlID)
	defer del.Body.Close() //nolint:errcheck,gosec // G104
	if status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, `{"items":[]}`); status != http.StatusNotFound {
		t.Errorf("soft-deleted watchlist: got %d, want 404", status)
	}
}

// TestReplaceWatchlistItemsAPI_SamePackageTwiceConflicts: two namespaces for one
// (ecosystem, package) would break the unique index, so the request fails as a whole.
func TestReplaceWatchlistItemsAPI_SamePackageTwiceConflicts(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "alice@example.com")
	mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001"))

	status, _ := doReplaceWatchlistItems(t, ctx, ts, token, orgID, wlID, `{"items":[
		{"item_type":"package","ecosystem":"npm","package_name":"a","namespace":"@one"},
		{"item_type":"package","ecosystem":"npm","package_name":"a","namespace":"@two"}]}`)
	if status != http.StatusConflict {
		t.Errorf("got %d, want 409", status)
	}
	if ids := listedCVEIDs(t, ctx, ts, token, orgID, wlID); !slices.Equal(ids, []string{"CVE-2024-0001"}) {
		t.Errorf("listed = %v, want the list untouched", ids)
	}
}

// TestOpenAPISpec_ReplaceItemsCapMatchesHandler ties the maxItems tag, which a struct tag
// cannot read from a constant, to the limit the handler enforces.
func TestOpenAPISpec_ReplaceItemsCapMatchesHandler(t *testing.T) {
	t.Parallel()
	spec := fetchSpec(t, newOpenAPITestHandler(t), "/api/v1/openapi.json")
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	items := schemas["ReplaceWatchlistItemsBody"].(map[string]any)["properties"].(map[string]any)["items"].(map[string]any)
	if got := items["maxItems"]; got != float64(maxReplaceWatchlistItems) {
		t.Errorf("spec maxItems = %v, handler cap = %d", got, maxReplaceWatchlistItems)
	}
}

// TestReplaceWatchlistItemsAPI_AuditsChangesOnly: a scheduled push that changes nothing must
// not fill the audit log.
func TestReplaceWatchlistItemsAPI_AuditsChangesOnly(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, aw := newAuditServer(t, db)
	token, orgID, wlID := watchlistFixture(t, ctx, ts, "audit-replace@example.com")

	auditedUpdates := func() (count int, added, removed string) {
		t.Helper()
		aw.Flush()
		err := db.DB().QueryRowContext(ctx, `
			SELECT count(*), COALESCE(max(metadata->>'items_added'), ''), COALESCE(max(metadata->>'items_removed'), '')
			FROM audit_log
			WHERE org_id = $1 AND entity_type = 'watchlist' AND action = 'update' AND entity_id = $2`,
			orgID, wlID).Scan(&count, &added, &removed)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		return count, added, removed
	}

	mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001", "CVE-2024-0002"))
	if count, added, removed := auditedUpdates(); count != 1 || added != "2" || removed != "0" {
		t.Errorf("after a change: count=%d added=%s removed=%s, want 1, 2, 0", count, added, removed)
	}

	mustReplaceItems(t, ctx, ts, token, orgID, wlID, cveItemsBody("CVE-2024-0001", "CVE-2024-0002"))
	if count, _, _ := auditedUpdates(); count != 1 {
		t.Errorf("after a push that changed nothing: count=%d, want 1", count)
	}
}
