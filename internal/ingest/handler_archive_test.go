// ABOUTME: Tests an OSV backfill larger than one worker job, then the incremental run that follows it.
// ABOUTME: Drives the real OSV adapter through the handler against a fake osv-vulnerabilities bucket.
package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/osv"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// redirectTransport sends every request to the test server, standing in for the
// adapter's fixed upstream URL.
type redirectTransport struct {
	target *url.URL
}

func (rt redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func osvTestAdvisory(i int) []byte {
	return fmt.Appendf(nil, `{"id":"GHSA-test-%05d","aliases":["CVE-2024-%05d"]}`, i, i)
}

func buildOSVArchive(t *testing.T, count int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 1; i <= count; i++ {
		w, err := zw.Create(fmt.Sprintf("GHSA-test-%05d.json", i))
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(osvTestAdvisory(i)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// osvTestBucket serves all.zip, modified_id.csv and npm/<id>.json records, and
// counts requests per path.
type osvTestBucket struct {
	mu       sync.Mutex
	archive  []byte
	csv      string
	requests map[string]int
}

func (b *osvTestBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	b.mu.Lock()
	b.requests[path]++
	csv := b.csv
	b.mu.Unlock()

	var i int
	switch path {
	case "all.zip":
		_, _ = w.Write(b.archive)
	case "modified_id.csv":
		_, _ = w.Write([]byte(csv))
	default:
		if _, err := fmt.Sscanf(path, "npm/GHSA-test-%05d.json", &i); err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(osvTestAdvisory(i))
	}
}

func (b *osvTestBucket) count(path string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests[path]
}

func readOSVCursor(t *testing.T, db *testutil.TestDB) (osv.Cursor, *time.Time) {
	t.Helper()
	state, err := db.GetFeedSyncState(context.Background(), "osv")
	if err != nil || state == nil {
		t.Fatalf("GetFeedSyncState: %v, %v", state, err)
	}
	var c osv.Cursor
	if err := json.Unmarshal(state.CursorJSON, &c); err != nil {
		t.Fatalf("unmarshal cursor %s: %v", state.CursorJSON, err)
	}
	return c, state.LastSuccessAt
}

// A first OSV backfill with more entries than one page stops at the job time
// limit after a page, and the next job resumes it and completes it, merging
// every advisory once. The run after that is incremental: it fetches only the
// advisory modified_id.csv lists as changed, and does not download all.zip.
func TestFeedHandler_OSVBackfillContinuesAcrossJobsThenRunsIncrementally(t *testing.T) {
	db := testutil.NewTestDB(t)
	captureLogs(t)

	total := feed.ArchivePageSize + 1
	newest := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	bucket := &osvTestBucket{
		archive:  buildOSVArchive(t, total),
		csv:      newest.Format(time.RFC3339Nano) + ",npm/GHSA-test-00001\n",
		requests: map[string]int{},
	}
	srv := httptest.NewServer(bucket)
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: redirectTransport{target: target}}

	mergeMock := &mockMerge{}
	handler := handlerWithStore(db.Store, db.Store, client, mergeMock.fn, NewAdapter, nil, nil)
	payload, _ := json.Marshal(Payload{FeedName: "osv"})

	// First job: one page, then the time limit ends the run.
	if err := handler(nearDeadlineContext(t), payload); err != nil {
		t.Fatalf("first job: %v", err)
	}
	mid, lastSuccess := readOSVCursor(t, db)
	if mid.After == "" || !mid.Snapshot.Equal(newest) || !mid.LastModified.IsZero() {
		t.Fatalf("cursor after first job = %+v, want a mid-backfill cursor with snapshot %v", mid, newest)
	}
	if lastSuccess != nil {
		t.Errorf("LastSuccessAt = %v, want nil: the backfill has not finished", lastSuccess)
	}
	if got := len(mergeMock.calls); got != feed.ArchivePageSize {
		t.Fatalf("merged %d advisories in the first job, want one page of %d", got, feed.ArchivePageSize)
	}

	// Second job: resumes after the first page and finishes the backfill.
	if err := handler(context.Background(), payload); err != nil {
		t.Fatalf("second job: %v", err)
	}
	final, lastSuccess := readOSVCursor(t, db)
	if lastSuccess == nil {
		t.Error("LastSuccessAt is nil after the backfill finished")
	}
	if final.LastModified.IsZero() || !final.LastModified.Before(newest) || !final.Snapshot.IsZero() || final.After != "" {
		t.Errorf("cursor after the backfill = %+v, want only last_modified shortly before %v", final, newest)
	}
	seen := make(map[string]int, total)
	for _, c := range mergeMock.calls {
		seen[c.CVEID]++
	}
	if len(seen) != total || len(mergeMock.calls) != total {
		t.Errorf("merged %d calls over %d distinct CVEs, want each of %d CVEs once", len(mergeMock.calls), len(seen), total)
	}
	if got := bucket.count("all.zip"); got != 2 {
		t.Errorf("all.zip downloads = %d, want 2: one per job", got)
	}

	// Third job: one advisory changed after the backfill.
	bucket.mu.Lock()
	bucket.csv = newest.Add(2*time.Hour).Format(time.RFC3339Nano) + ",npm/GHSA-test-00007\n" + bucket.csv
	bucket.mu.Unlock()
	mergeMock.calls = nil
	if err := handler(context.Background(), payload); err != nil {
		t.Fatalf("incremental job: %v", err)
	}
	if got := len(mergeMock.calls); got != 2 {
		t.Errorf("incremental run merged %d advisories, want 2: the change and the one re-read inside the rescan window", got)
	}
	if got := bucket.count("all.zip"); got != 2 {
		t.Errorf("all.zip downloads = %d after the incremental run, want still 2", got)
	}
	if got := bucket.count("npm/GHSA-test-00007.json"); got != 1 {
		t.Errorf("fetches of the changed advisory = %d, want 1", got)
	}
}
