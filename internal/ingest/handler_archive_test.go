// ABOUTME: Tests a single-archive feed backfill that is larger than one worker job.
// ABOUTME: Drives the real MITRE adapter through the handler across two jobs against a test archive server.
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
	"sync"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
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

func buildCVEListArchive(t *testing.T, count int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 1; i <= count; i++ {
		id := fmt.Sprintf("CVE-2024-%05d", i)
		w, err := zw.Create(fmt.Sprintf("cvelistV5-main/cves/2024/%s.json", id))
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		fmt.Fprintf(w, `{"cveMetadata":{"cveId":%q,"state":"PUBLISHED"}}`, id)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// A first MITRE backfill with more entries than one page stops at the job time
// limit after a page, and the next job resumes the pass where it stopped and
// completes it. Every CVE is merged once, and the final cursor is the
// incremental cursor at the time the pass began.
func TestFeedHandler_ArchiveBackfillContinuesAcrossJobs(t *testing.T) {
	db := testutil.NewTestDB(t)
	captureLogs(t)
	bg := context.Background()

	total := feed.ArchivePageSize + 1
	archive := buildCVEListArchive(t, total)
	var mu sync.Mutex
	downloads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		downloads++
		mu.Unlock()
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: redirectTransport{target: target}}

	mergeMock := &mockMerge{}
	handler := handlerWithStore(db.Store, db.Store, client, mergeMock.fn, NewAdapter, nil, nil)
	payload, _ := json.Marshal(Payload{FeedName: "mitre"})

	// First job: one page, then the time limit ends the run.
	jobStart := time.Now().UTC()
	if err := handler(nearDeadlineContext(t), payload); err != nil {
		t.Fatalf("first job: %v", err)
	}
	state, err := db.GetFeedSyncState(bg, "mitre")
	if err != nil || state == nil {
		t.Fatalf("GetFeedSyncState after first job: %v, %v", state, err)
	}
	var mid feed.ArchiveCursor
	if err := json.Unmarshal(state.CursorJSON, &mid); err != nil {
		t.Fatalf("unmarshal cursor %s: %v", state.CursorJSON, err)
	}
	if mid.ResumeAfter == "" || mid.PassStartedAt.Before(jobStart) {
		t.Fatalf("cursor after first job = %s, want a mid-pass cursor from this pass", state.CursorJSON)
	}
	if state.LastSuccessAt != nil {
		t.Errorf("LastSuccessAt = %v, want nil: the backfill has not finished", state.LastSuccessAt)
	}
	if got := len(mergeMock.calls); got != feed.ArchivePageSize {
		t.Fatalf("merged %d CVEs in the first job, want one page of %d", got, feed.ArchivePageSize)
	}

	// Second job: resumes after the first page and finishes the pass.
	if err := handler(bg, payload); err != nil {
		t.Fatalf("second job: %v", err)
	}
	state, err = db.GetFeedSyncState(bg, "mitre")
	if err != nil || state == nil {
		t.Fatalf("GetFeedSyncState after second job: %v, %v", state, err)
	}
	if state.LastSuccessAt == nil {
		t.Error("LastSuccessAt is nil after the backfill finished")
	}
	var final feed.ArchiveCursor
	if err := json.Unmarshal(state.CursorJSON, &final); err != nil {
		t.Fatalf("unmarshal cursor %s: %v", state.CursorJSON, err)
	}
	if !final.LastModified.Equal(mid.PassStartedAt) || !final.PassStartedAt.IsZero() || final.ResumeAfter != "" {
		t.Errorf("final cursor = %s, want only last_modified at the pass start %v", state.CursorJSON, mid.PassStartedAt)
	}

	seen := make(map[string]int, total)
	for _, c := range mergeMock.calls {
		seen[c.CVEID]++
	}
	if len(seen) != total || len(mergeMock.calls) != total {
		t.Errorf("merged %d calls over %d distinct CVEs, want each of %d CVEs once", len(mergeMock.calls), len(seen), total)
	}
	if downloads != 2 {
		t.Errorf("downloads = %d, want 2: one per job", downloads)
	}
}
