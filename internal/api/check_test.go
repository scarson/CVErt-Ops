// ABOUTME: Tests POST /orgs/{org_id}/check through the full srv.Handler() stack: roles, the error table and limits.
// ABOUTME: Also checks the spec's response types against check.Results and that item contents are never logged.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
)

// doCheck posts body to the check endpoint of orgID with an API key, or with no
// credentials when key is empty.
func doCheck(t *testing.T, f *securityFixture, key string, orgID uuid.UUID, body string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		f.server.URL+"/api/v1/orgs/"+orgID.String()+"/check", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := f.server.Client().Do(req) //nolint:gosec // G704: httptest server URL
	if err != nil {
		t.Fatalf("check request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read check response: %v", err)
	}
	return resp.StatusCode, resp.Header, respBody
}

// mustCheck posts body as a viewer and decodes the 200 response into the
// documented CheckResults type, refusing any field the type does not declare.
func mustCheck(t *testing.T, f *securityFixture, body string) CheckResults {
	t.Helper()
	status, _, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, body)
	if status != http.StatusOK {
		t.Fatalf("check: got %d, want 200: %s", status, respBody)
	}
	dec := json.NewDecoder(bytes.NewReader(respBody))
	dec.DisallowUnknownFields()
	var results CheckResults
	if err := dec.Decode(&results); err != nil {
		t.Fatalf("decode check response as CheckResults: %v\n%s", err, respBody)
	}
	return results
}

// packageItems returns a request body of n npm items with distinct names.
func packageItems(n int) string {
	items := make([]string, 0, n)
	for i := range n {
		items = append(items, fmt.Sprintf(`{"ecosystem":"npm","name":"pkg-%d","version":"1.0.0"}`, i))
	}
	return `{"items":[` + strings.Join(items, ",") + `]}`
}

func TestCheckAPI_Roles(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	body := packageItems(1)

	if status, _, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, body); status != http.StatusOK {
		t.Errorf("viewer: got %d, want 200: %s", status, respBody)
	}
	if status, _, _ := doCheck(t, f, "", f.orgID, body); status != http.StatusUnauthorized {
		t.Errorf("no credentials: got %d, want 401", status)
	}
	if status, _, _ := doCheck(t, f, f.keys["owner"], uuid.New(), body); status != http.StatusForbidden {
		t.Errorf("another org's path: got %d, want 403", status)
	}
}

func TestCheckAPI_RequestErrors(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)

	tests := []struct {
		name string
		body string
		want int
	}{
		{"no body", "", http.StatusBadRequest},
		{"malformed JSON", `{"items":[`, http.StatusBadRequest},
		{"items not an array", `{"items":"npm"}`, http.StatusBadRequest},
		{"items missing", `{}`, http.StatusUnprocessableEntity},
		{"items null", `{"items":null}`, http.StatusUnprocessableEntity},
		{"items empty", `{"items":[]}`, http.StatusUnprocessableEntity},
		{"items over the cap", packageItems(maxCheckItems + 1), http.StatusUnprocessableEntity},
		// The 1 MiB limit only wraps the body; reading past it must answer 413, not 400.
		{"body over 1 MiB", `{"items":[{"ecosystem":"npm","name":"` + strings.Repeat("a", 1<<20) + `","version":"1"}]}`,
			http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, header, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, tc.body)
			if status != tc.want {
				t.Fatalf("got %d, want %d: %s", status, tc.want, respBody)
			}
			if ct := header.Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", ct)
			}
		})
	}

	if status, _, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, packageItems(maxCheckItems)); status != http.StatusOK {
		t.Errorf("items at the cap: got %d, want 200: %s", status, respBody)
	}
}

func TestCheckAPI_InvalidItemAmongValid(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)

	results := mustCheck(t, f, `{"items":[
		{"id":"first","ecosystem":"npm","name":"left-pad","version":"1.0.0"},
		{"id":"second","version":"1.0.0"},
		{"cpe":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","version":"2.0"}]}`)

	if len(results.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(results.Results))
	}
	for i, res := range results.Results {
		if res.Index != i {
			t.Errorf("results[%d].index = %d", i, res.Index)
		}
	}
	bad := results.Results[1]
	if bad.Status != check.StatusInvalid || bad.Error == nil || bad.Error.Code != "invalid_form" {
		t.Errorf("invalid item = status %q, error %+v; want invalid with invalid_form", bad.Status, bad.Error)
	}
	if bad.ID == nil || *bad.ID != "second" {
		t.Errorf("invalid item id = %v, want second", bad.ID)
	}
	for _, i := range []int{0, 2} {
		if res := results.Results[i]; res.Status == check.StatusInvalid || res.Error != nil {
			t.Errorf("results[%d] = status %q, error %+v; want it answered", i, res.Status, res.Error)
		}
	}
}

func TestCheckAPI_AllSlotsInUse(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	for range cap(f.api.checkSem) {
		f.api.checkSem <- struct{}{}
	}

	status, header, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, packageItems(1))
	if status != http.StatusServiceUnavailable {
		t.Fatalf("all slots held: got %d, want 503: %s", status, respBody)
	}
	if got := header.Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}
	// The body is read and checked before a slot is taken.
	if status, _, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, `{"items":[`); status != http.StatusBadRequest {
		t.Errorf("malformed body with all slots held: got %d, want 400: %s", status, respBody)
	}

	for range cap(f.api.checkSem) {
		<-f.api.checkSem
	}
	if status, _, respBody := doCheck(t, f, f.keys["viewer"], f.orgID, packageItems(1)); status != http.StatusOK {
		t.Errorf("slots free again: got %d, want 200: %s", status, respBody)
	}
	if n := len(f.api.checkSem); n != 0 {
		t.Errorf("%d slots still held after the request", n)
	}
}

// blockingBody signals reading on its first Read and waits for release before
// returning any data, so a test can look at the server while the body uploads.
type blockingBody struct {
	r       io.Reader
	once    sync.Once
	reading chan struct{}
	release chan struct{}
}

func (b *blockingBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.reading)
		<-b.release
	})
	return b.r.Read(p)
}

// blockingWriter signals writing on its first Write and waits for release before
// accepting it, so a test can look at the server while the response is sent. It
// records each write deadline set through http.ResponseController, and whether
// a Write came before any deadline was set.
type blockingWriter struct {
	header          http.Header
	code            int
	body            bytes.Buffer
	once            sync.Once
	writing         chan struct{}
	release         chan struct{}
	deadlines       []time.Time
	wroteNoDeadline bool // a Write came before any deadline was set
}

func (w *blockingWriter) Header() http.Header  { return w.header }
func (w *blockingWriter) WriteHeader(code int) { w.code = code }
func (w *blockingWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}
func (w *blockingWriter) Write(p []byte) (int, error) {
	if len(w.deadlines) == 0 {
		w.wroteNoDeadline = true
	}
	w.once.Do(func() {
		close(w.writing)
		<-w.release
	})
	return w.body.Write(p)
}

// TestCheckAPI_SlotHeldOnlyWhileChecking calls the handler directly with a body
// that blocks while it is read and a writer that blocks while the response is
// written. Neither a slow upload nor a slow reader of the response may hold one
// of the few version check slots.
func TestCheckAPI_SlotHeldOnlyWhileChecking(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	ctx := context.WithValue(t.Context(), ctxOrgID, f.orgID)

	body := &blockingBody{r: strings.NewReader(packageItems(1)), reading: make(chan struct{}), release: make(chan struct{})}
	w := &blockingWriter{header: http.Header{}, writing: make(chan struct{}), release: make(chan struct{})}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/orgs/"+f.orgID.String()+"/check", body)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.api.checkComponentsHandler(w, req)
	}()

	select {
	case <-body.reading:
	case <-time.After(30 * time.Second):
		t.Fatal("the handler did not read the body")
	}
	if n := len(f.api.checkSem); n != 0 {
		t.Errorf("%d slots held while the body was read, want 0", n)
	}
	close(body.release)

	select {
	case <-w.writing:
	case <-time.After(30 * time.Second):
		t.Fatal("the handler did not write a response")
	}
	if n := len(f.api.checkSem); n != 0 {
		t.Errorf("%d slots held while the response was written, want 0", n)
	}
	close(w.release)
	<-done
	end := time.Now()

	if w.code != http.StatusOK {
		t.Errorf("got %d, want 200: %s", w.code, w.body.String())
	}
	// The server sets no write timeout, so the handler bounds the write itself.
	if len(w.deadlines) != 1 || w.wroteNoDeadline {
		t.Fatalf("write deadlines = %v, written before one was set = %v; want one deadline, set before the first Write",
			w.deadlines, w.wroteNoDeadline)
	}
	if d := w.deadlines[0]; d.Before(start.Add(checkWriteTimeout)) || d.After(end.Add(checkWriteTimeout)) {
		t.Errorf("write deadline %v is not %v after the handler ran (%v to %v)", d, checkWriteTimeout, start, end)
	}
}

// TestCheckAPI_CancelledContext calls the handler directly, because a client that
// cancels its request never sees the response.
func TestCheckAPI_CancelledContext(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), ctxOrgID, f.orgID))
	cancel()

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/orgs/"+f.orgID.String()+"/check",
		strings.NewReader(packageItems(1)))
	rec := httptest.NewRecorder()
	f.api.checkComponentsHandler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancelled context: got %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"results"`) {
		t.Errorf("cancelled context answered items: %s", rec.Body.String())
	}
	if n := len(f.api.checkSem); n != 0 {
		t.Errorf("%d slots still held after the request", n)
	}
}

// TestWriteCheckFailure covers how a failed read or evaluation is answered. The
// store tests show ReadCheckCandidates returns ErrCandidateLimit; reaching it
// through the handler would take 200,000 stored rows.
func TestWriteCheckFailure(t *testing.T) {
	var logs bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(orig) })

	live := t.Context()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelExpired()

	tests := []struct {
		name     string
		ctx      context.Context
		err      error
		want     int
		wantType string
		wantLog  bool
	}{
		{"request limit", live, fmt.Errorf("read check candidates: %w", store.ErrCandidateLimit),
			http.StatusUnprocessableEntity, problemTypeCandidateLimit, false},
		{"request limit after the context ended", cancelled, fmt.Errorf("read: %w", store.ErrCandidateLimit),
			http.StatusUnprocessableEntity, problemTypeCandidateLimit, false},
		{"cancelled", cancelled, context.Canceled, http.StatusServiceUnavailable, "", false},
		{"driver error after cancellation", cancelled, errors.New("pq: canceling statement due to user request"),
			http.StatusServiceUnavailable, "", false},
		{"30-second limit", expired, fmt.Errorf("read: %w", context.DeadlineExceeded), http.StatusServiceUnavailable, "", false},
		// DB_STATEMENT_TIMEOUT_MS (14 s by default) is shorter than the check's own
		// limit, so PostgreSQL can cancel a lookup while the context is still live.
		{"statement timeout", live, fmt.Errorf("read check candidates: cpe: %w",
			&pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"}),
			http.StatusServiceUnavailable, "", false},
		{"other error", live, errors.New("connection refused"), http.StatusInternalServerError, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/check", nil)
			writeCheckFailure(rec, req, tc.ctx, tc.err)

			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
			var problem struct {
				Type   string `json:"type"`
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if problem.Type != tc.wantType {
				t.Errorf("type = %q, want %q", problem.Type, tc.wantType)
			}
			if problem.Detail == "" {
				t.Error("problem has no detail")
			}
			// The check's own limit and DB_STATEMENT_TIMEOUT_MS differ, so the
			// detail names neither.
			if tc.want == http.StatusServiceUnavailable && strings.ContainsAny(problem.Detail, "0123456789") {
				t.Errorf("detail %q states a time limit", problem.Detail)
			}
			if logged := strings.Contains(logs.String(), tc.err.Error()); logged != tc.wantLog {
				t.Errorf("error logged = %v, want %v: %s", logged, tc.wantLog, logs.String())
			}
		})
	}
}

func TestCheckAPI_ReturnsResults(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	ctx := t.Context()

	severity := "HIGH"
	if err := merge.Ingest(ctx, f.db.Store, feed.CanonicalPatch{
		CVEID:    "CVE-2026-90001",
		Status:   "published",
		Severity: &severity,
		AffectedPackages: []feed.AffectedPackage{{
			Ecosystem: "npm", PackageName: "check-demo", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.2.3",
		}},
	}, "osv"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	now := time.Now()
	for name, cursor := range map[string]string{
		"ghsa": `{"since":"2026-11-01T00:00:00Z"}`,
		"osv":  `{"last_modified":"2026-11-01T00:00:00Z"}`,
		"nvd":  `{"caught_up":true}`,
	} {
		if err := f.db.UpsertFeedSyncState(ctx, store.FeedSyncState{
			FeedName: name, CursorJSON: json.RawMessage(cursor), LastSuccessAt: &now,
		}); err != nil {
			t.Fatalf("UpsertFeedSyncState %s: %v", name, err)
		}
	}

	results := mustCheck(t, f, `{"items":[
		{"id":"old","ecosystem":"npm","name":"check-demo","version":"1.0.0"},
		{"purl":"pkg:npm/check-demo@1.5.0"}]}`)

	if !results.DataComplete {
		t.Errorf("data_complete = false, want true; feeds %+v", results.Feeds)
	}
	if len(results.Feeds) != 3 {
		t.Errorf("feeds = %+v, want ghsa, nvd and osv", results.Feeds)
	}
	if len(results.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(results.Results))
	}

	old := results.Results[0]
	if old.Status != check.StatusAffected || old.Counts.Affected != 1 || len(old.Advisories) != 1 {
		t.Fatalf("1.0.0 = status %q, counts %+v, %d advisories; want affected by one", old.Status, old.Counts, len(old.Advisories))
	}
	adv := old.Advisories[0]
	if adv.AdvisoryID != "CVE-2026-90001" || adv.Verdict != check.VerdictAffected {
		t.Errorf("advisory = %s %s, want CVE-2026-90001 affected", adv.AdvisoryID, adv.Verdict)
	}
	if adv.FixedVersion == nil || *adv.FixedVersion != "1.2.3" {
		t.Errorf("fixed_version = %v, want 1.2.3", adv.FixedVersion)
	}
	if adv.Severity == nil || *adv.Severity != "HIGH" {
		t.Errorf("severity = %v, want HIGH", adv.Severity)
	}
	if len(adv.MatchedRanges) != 1 || adv.MatchedRanges[0].Evidence != "package_range" || adv.MatchedRanges[0].Fixed != "1.2.3" {
		t.Errorf("matched_ranges = %+v, want the package range fixed in 1.2.3", adv.MatchedRanges)
	}
	if old.Component == nil || old.Component.Kind != "package" || old.Component.Name != "check-demo" {
		t.Errorf("component = %+v, want the npm package", old.Component)
	}

	fixed := results.Results[1]
	if fixed.Status != check.StatusNotAffected || fixed.Counts.NotAffected != 1 || len(fixed.Advisories) != 0 {
		t.Errorf("1.5.0 = status %q, counts %+v, %d advisories; want not affected", fixed.Status, fixed.Counts, len(fixed.Advisories))
	}
}

// TestCheckAPI_DoesNotLogItems: the items describe what an org runs, so no log
// line may hold them, whatever the request's outcome. It replaces the default
// logger, so it does not run in parallel.
func TestCheckAPI_DoesNotLogItems(t *testing.T) {
	var logs bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(orig) })
	f := newSecurityFixture(t)

	const marker = "zzprivate"
	bodies := []string{
		`{"items":[{"purl":"pkg:npm/` + marker + `-purl@1.0.0"},
			{"ecosystem":"npm","name":"` + marker + `-name","version":"1.0.0"},
			{"cpe":"cpe:2.3:a:` + marker + `vendor:` + marker + `product:*:*:*:*:*:*:*:*","version":"1.0"},
			{"id":"` + marker + `-id","ecosystem":"NoSuchEcosystem","name":"` + marker + `-bad","version":"1"}]}`,
		`{"items":[{"ecosystem":"npm","name":"` + marker + `-malformed"`,
		`{"items":[` + strings.Repeat(`{"ecosystem":"npm","name":"`+marker+`-many","version":"1"},`, maxCheckItems) +
			`{"ecosystem":"npm","name":"` + marker + `-many","version":"1"}]}`,
	}
	for _, body := range bodies {
		doCheck(t, f, f.keys["viewer"], f.orgID, body)
	}
	if strings.Contains(strings.ToLower(logs.String()), marker) {
		t.Errorf("an item value was logged:\n%s", logs.String())
	}
}

// TestOpenAPISpec_CheckItemsCapMatchesHandler ties the maxItems tag, which a struct tag
// cannot read from a constant, to the limit the handler enforces.
func TestOpenAPISpec_CheckItemsCapMatchesHandler(t *testing.T) {
	t.Parallel()
	spec := fetchSpec(t, newOpenAPITestHandler(t), "/api/v1/openapi.json")
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	items := schemas["CheckRequest"].(map[string]any)["properties"].(map[string]any)["items"].(map[string]any)
	if got := items["maxItems"]; got != float64(maxCheckItems) {
		t.Errorf("spec maxItems = %v, handler cap = %d", got, maxCheckItems)
	}
	if got := items["minItems"]; got != float64(1) {
		t.Errorf("spec minItems = %v, want 1", got)
	}
}

// TestCheckResponseTypesMatchResults: the handler writes check.Results, and the
// spec documents CheckResults. A value written through either must read back
// through the other as the same JSON, so neither can gain, lose or change the
// nullability of a field without the other.
func TestCheckResponseTypesMatchResults(t *testing.T) {
	t.Parallel()
	filledResults, filledAPI := check.Results{}, CheckResults{}
	fillValue(t, reflect.ValueOf(&filledResults).Elem())
	fillValue(t, reflect.ValueOf(&filledAPI).Elem())

	sparseResults := check.Results{
		Feeds: []check.FeedStatus{{}},
		Results: []check.ItemResult{{
			Component:  &check.Component{},
			Advisories: []check.Advisory{{MatchedRanges: []check.MatchedRange{{}}}},
			Error:      &check.ItemError{},
		}},
	}
	sparseAPI := CheckResults{
		Feeds: []CheckFeedStatus{{}},
		Results: []CheckItemResult{{
			Component:  &CheckComponent{},
			Advisories: []CheckAdvisory{{MatchedRanges: []CheckMatchedRange{{}}}},
			Error:      &CheckItemError{},
		}},
	}

	for name, value := range map[string]any{"filled check.Results": filledResults, "sparse check.Results": sparseResults} {
		assertSameJSON(t, name, value, &CheckResults{})
	}
	for name, value := range map[string]any{"filled CheckResults": filledAPI, "sparse CheckResults": sparseAPI} {
		assertSameJSON(t, name, value, &check.Results{})
	}
}

// assertSameJSON marshals value, decodes it into into, and requires that
// marshalling into gives the same JSON document.
func assertSameJSON(t *testing.T, name string, value, into any) {
	t.Helper()
	first, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	if err := json.Unmarshal(first, into); err != nil {
		t.Fatalf("%s: unmarshal: %v", name, err)
	}
	second, err := json.Marshal(into)
	if err != nil {
		t.Fatalf("%s: marshal again: %v", name, err)
	}
	var a, b any
	if err := json.Unmarshal(first, &a); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if err := json.Unmarshal(second, &b); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("%s: JSON differs through %T\n got: %s\nwant: %s", name, into, second, first)
	}
}

// fillValue sets every exported field reachable from v: an allocated pointer, one
// element in each slice and map, and a non-zero scalar.
func fillValue(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillValue(t, v.Elem())
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fillValue(t, v.Field(i))
			}
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillValue(t, v.Index(0))
	case reflect.Map:
		key, elem := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fillValue(t, key)
		fillValue(t, elem)
		v.Set(reflect.MakeMapWithSize(v.Type(), 1))
		v.SetMapIndex(key, elem)
	case reflect.String:
		v.SetString("x")
	case reflect.Int:
		v.SetInt(1)
	case reflect.Float64:
		v.SetFloat(0.5)
	case reflect.Bool:
		v.SetBool(true)
	default:
		t.Fatalf("fillValue: no rule for %s", v.Type())
	}
}
