// ABOUTME: Tests for ArchivePager, which pages a single-archive feed across Fetch calls and worker jobs.
// ABOUTME: Covers page slicing, resume in a new job, upstream archive changes, the baseline filter, and cleanup.
package feed

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type testArchiveEntry struct {
	name     string
	content  string
	modified time.Time
}

func entry(name string, modified time.Time) testArchiveEntry {
	return testArchiveEntry{name: name, content: fmt.Sprintf(`{"id":%q}`, name), modified: modified}
}

func buildTestArchive(t *testing.T, entries []testArchiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: e.modified})
		if err != nil {
			t.Fatalf("zip create %s: %v", e.name, err)
		}
		if _, err := io.WriteString(w, e.content); err != nil {
			t.Fatalf("zip write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// archiveServer serves whichever archive is current and counts downloads.
type archiveServer struct {
	*httptest.Server
	mu        sync.Mutex
	archive   []byte
	downloads int
}

func newArchiveServer(t *testing.T, archive []byte) *archiveServer {
	t.Helper()
	s := &archiveServer{archive: archive}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		body := s.archive
		s.downloads++
		s.mu.Unlock()
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *archiveServer) replace(archive []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archive = archive
}

func (s *archiveServer) downloadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloads
}

// parseTestEntry reads {"id": ...} and fails on anything that is not JSON.
func parseTestEntry(f *zip.File) (*CanonicalPatch, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	var doc struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(rc).Decode(&doc)
	_ = rc.Close()
	if err != nil {
		return nil, err
	}
	return &CanonicalPatch{CVEID: doc.ID, SourceID: doc.ID}, nil
}

// newTestPager returns a pager for one job: each worker job builds a new adapter,
// so a new pager stands for a new job.
func newTestPager(s *archiveServer, pageSize int) *ArchivePager {
	return &ArchivePager{
		Client:      s.Client(),
		RateLimiter: rate.NewLimiter(rate.Inf, 1),
		URL:         s.URL,
		TempPattern: "cvert-archive-test-*.zip",
		SourceName:  "test-archive",
		PageSize:    pageSize,
		IsEntry:     func(name string) bool { return len(name) > 5 && name[len(name)-5:] == ".json" },
		Parse:       parseTestEntry,
	}
}

func decodeArchiveCursor(t *testing.T, raw json.RawMessage) ArchiveCursor {
	t.Helper()
	var c ArchiveCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal cursor %s: %v", raw, err)
	}
	return c
}

func patchIDs(r *FetchResult) []string {
	ids := make([]string, 0, len(r.Patches))
	for _, p := range r.Patches {
		ids = append(ids, p.CVEID)
	}
	return ids
}

func fetchPage(t *testing.T, p *ArchivePager, cursor json.RawMessage) *FetchResult {
	t.Helper()
	r, err := p.Fetch(context.Background(), cursor)
	if err != nil {
		t.Fatalf("Fetch(%s): %v", cursor, err)
	}
	return r
}

var archiveEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// A full pass is split into pages in entry-name order, with one download per
// job. Each page's cursor records where to resume and the latest entry time in
// the archive the pass started on; the last page's cursor is the plain
// incremental cursor at that time.
func TestArchivePager_SplitsPassIntoPages(t *testing.T) {
	t.Parallel()
	latest := archiveEpoch.Add(3 * time.Hour)
	// Stored out of name order; pages follow name order. The README is not a
	// record, so its later time is not the archive's latest entry time.
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/5.json", archiveEpoch),
		entry("a/1.json", archiveEpoch),
		entry("a/4.json", latest),
		{name: "README.md", content: "not an entry", modified: latest.Add(time.Hour)},
		entry("a/2.json", archiveEpoch),
		{name: "a/3.json", content: "{not json", modified: archiveEpoch},
	}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	page1 := fetchPage(t, pager, nil)
	if got, want := patchIDs(page1), []string{"a/1.json", "a/2.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 1 = %v, want %v", got, want)
	}
	if page1.LastPage {
		t.Fatal("page 1 is marked as the last page")
	}
	c1 := decodeArchiveCursor(t, page1.NextCursor)
	if c1.ResumeAfter != "a/2.json" {
		t.Errorf("page 1 ResumeAfter = %q, want a/2.json", c1.ResumeAfter)
	}
	if !c1.Snapshot.Equal(latest) {
		t.Errorf("page 1 Snapshot = %v, want the latest record time %v", c1.Snapshot, latest)
	}
	if !c1.LastModified.IsZero() {
		t.Errorf("page 1 LastModified = %v, want zero: a first pass has no baseline", c1.LastModified)
	}

	// The malformed entry is skipped and does not count towards the page.
	page2 := fetchPage(t, pager, page1.NextCursor)
	if got, want := patchIDs(page2), []string{"a/4.json", "a/5.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 2 = %v, want %v", got, want)
	}
	if !page2.LastPage {
		t.Fatal("page 2 reached the end of the archive and is not marked as the last page")
	}
	final := decodeArchiveCursor(t, page2.NextCursor)
	want := latest.Add(-archiveTimeResolution)
	if !final.LastModified.Equal(want) || !final.Snapshot.IsZero() || final.ResumeAfter != "" {
		t.Errorf("final cursor = %s, want only last_modified at %v", page2.NextCursor, want)
	}
	if srv.downloadCount() != 1 {
		t.Errorf("downloads = %d, want 1: pages of one job share the archive", srv.downloadCount())
	}
}

// A later job resumes after the saved entry name, from a new download, and keeps
// the snapshot of the archive the pass started on, so the final cursor covers
// every change made upstream since that archive.
func TestArchivePager_ResumesInNewJob(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", archiveEpoch),
		entry("a/2.json", archiveEpoch),
		entry("a/3.json", archiveEpoch),
	}))

	job1 := newTestPager(srv, 2)
	page1 := fetchPage(t, job1, nil)
	if err := job1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	snapshot := decodeArchiveCursor(t, page1.NextCursor).Snapshot

	// The archive the second job downloads has a later entry.
	srv.replace(buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", archiveEpoch),
		entry("a/2.json", archiveEpoch),
		entry("a/3.json", archiveEpoch.Add(2*time.Hour)),
	}))
	job2 := newTestPager(srv, 2)
	t.Cleanup(func() { _ = job2.Close() })
	page2 := fetchPage(t, job2, page1.NextCursor)
	if got, want := patchIDs(page2), []string{"a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("resumed page = %v, want %v", got, want)
	}
	if !page2.LastPage {
		t.Fatal("resumed page is not marked as the last page")
	}
	if srv.downloadCount() != 2 {
		t.Errorf("downloads = %d, want 2: a new job downloads the archive again", srv.downloadCount())
	}
	final := decodeArchiveCursor(t, page2.NextCursor)
	if !snapshot.Equal(archiveEpoch) {
		t.Errorf("Snapshot = %v, want the first archive's latest record time %v", snapshot, archiveEpoch)
	}
	if want := snapshot.Add(-archiveTimeResolution); !final.LastModified.Equal(want) {
		t.Errorf("final LastModified = %v, want %v from the first archive's snapshot, not the second archive's", final.LastModified, want)
	}
}

// When the upstream archive changes between jobs, the resumed pass reads the new
// archive after the resume key. A change behind the key is not read in this
// pass, and the next incremental run picks it up because its modified time is
// later than the snapshot of the archive the pass started on.
func TestArchivePager_UpstreamChangeBetweenJobs_NothingMissed(t *testing.T) {
	t.Parallel()
	older := archiveEpoch.Add(-24 * time.Hour)
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", older),
		entry("a/3.json", older),
		entry("a/5.json", archiveEpoch),
	}))

	job1 := newTestPager(srv, 2)
	page1 := fetchPage(t, job1, nil)
	_ = job1.Close()
	if got, want := patchIDs(page1), []string{"a/1.json", "a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 1 = %v, want %v", got, want)
	}

	// Upstream adds a/2.json (behind the key) and a/4.json (ahead of it) and
	// updates a/1.json, all after the archive the pass started on.
	changed := archiveEpoch.Add(time.Hour)
	srv.replace(buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", changed),
		entry("a/2.json", changed),
		entry("a/3.json", older),
		entry("a/4.json", changed),
		entry("a/5.json", archiveEpoch),
	}))

	job2 := newTestPager(srv, 2)
	page2 := fetchPage(t, job2, page1.NextCursor)
	_ = job2.Close()
	if got, want := patchIDs(page2), []string{"a/4.json", "a/5.json"}; !slices.Equal(got, want) {
		t.Fatalf("resumed page = %v, want %v", got, want)
	}
	if !page2.LastPage {
		t.Fatal("resumed page is not marked as the last page")
	}

	job3 := newTestPager(srv, 2)
	t.Cleanup(func() { _ = job3.Close() })
	next := fetchPage(t, job3, page2.NextCursor)
	if got, want := patchIDs(next), []string{"a/1.json", "a/2.json"}; !slices.Equal(got, want) {
		t.Fatalf("first page of the next pass = %v, want the entries changed behind the key %v", got, want)
	}
}

// An archive is generated before it is downloaded. A record changed in that gap
// is missing from the archive and stamped before the download, so the next pass
// must start from the archive's own latest record time, not the download time.
func TestArchivePager_ChangeBetweenGenerationAndDownload_ReadNextPass(t *testing.T) {
	t.Parallel()
	older := archiveEpoch.Add(-24 * time.Hour)
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", older),
		entry("a/2.json", archiveEpoch),
	}))
	job1 := newTestPager(srv, 5)
	pass1 := fetchPage(t, job1, nil)
	_ = job1.Close()
	if !pass1.LastPage {
		t.Fatal("first pass did not end on its only page")
	}

	// Stamped after the first archive was generated, long before it was downloaded.
	srv.replace(buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", older),
		entry("a/2.json", archiveEpoch),
		entry("a/3.json", archiveEpoch.Add(30*time.Minute)),
	}))
	job2 := newTestPager(srv, 5)
	t.Cleanup(func() { _ = job2.Close() })
	pass2 := fetchPage(t, job2, pass1.NextCursor)
	// a/2.json is the first archive's newest record, read again because the
	// cursor sits one time step before it.
	if got, want := patchIDs(pass2), []string{"a/2.json", "a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("next pass = %v, want %v", got, want)
	}
}

// An archive with no records ends the pass without moving the baseline.
func TestArchivePager_NoRecords_KeepsBaseline(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		{name: "README.md", content: "not an entry", modified: archiveEpoch.Add(time.Hour)},
	}))
	cursor, _ := json.Marshal(ArchiveCursor{LastModified: archiveEpoch})
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	r := fetchPage(t, pager, cursor)
	if len(r.Patches) != 0 || !r.LastPage {
		t.Fatalf("got %d patches, LastPage=%v; want 0 patches on the last page", len(r.Patches), r.LastPage)
	}
	if c := decodeArchiveCursor(t, r.NextCursor); !c.LastModified.Equal(archiveEpoch) {
		t.Errorf("final LastModified = %v, want the baseline %v", c.LastModified, archiveEpoch)
	}
}

// OSV's export stamps every entry with the same zero DOS time. A cursor saved as
// a download time is later than every entry time and selects nothing; the next
// cursor follows the archive's own times instead, so the following pass reads
// the archive again rather than never reading it.
func TestArchivePager_BaselineAfterEveryEntryTime_NextPassReadsArchive(t *testing.T) {
	t.Parallel()
	dosZero := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", dosZero),
		entry("a/2.json", dosZero),
	}))
	cursor, _ := json.Marshal(ArchiveCursor{LastModified: archiveEpoch})

	job1 := newTestPager(srv, 5)
	pass1 := fetchPage(t, job1, cursor)
	_ = job1.Close()
	if len(pass1.Patches) != 0 {
		t.Fatalf("pass with a later baseline read %v, want nothing", patchIDs(pass1))
	}

	job2 := newTestPager(srv, 5)
	t.Cleanup(func() { _ = job2.Close() })
	pass2 := fetchPage(t, job2, pass1.NextCursor)
	if got, want := patchIDs(pass2), []string{"a/1.json", "a/2.json"}; !slices.Equal(got, want) {
		t.Fatalf("next pass = %v, want %v", got, want)
	}
}

// An incremental pass skips entries at or before its baseline on every page,
// including pages resumed in a later job.
func TestArchivePager_IncrementalPassKeepsBaseline(t *testing.T) {
	t.Parallel()
	baseline := archiveEpoch.Add(24 * time.Hour)
	newer := baseline.Add(time.Hour)
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", newer),
		entry("a/2.json", archiveEpoch),
		entry("a/3.json", newer),
		entry("a/4.json", baseline),
		entry("a/5.json", newer),
	}))
	cursor, _ := json.Marshal(ArchiveCursor{LastModified: baseline})

	job1 := newTestPager(srv, 2)
	page1 := fetchPage(t, job1, cursor)
	_ = job1.Close()
	if got, want := patchIDs(page1), []string{"a/1.json", "a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 1 = %v, want %v", got, want)
	}
	c1 := decodeArchiveCursor(t, page1.NextCursor)
	if !c1.LastModified.Equal(baseline) {
		t.Errorf("mid-pass LastModified = %v, want the baseline %v", c1.LastModified, baseline)
	}

	job2 := newTestPager(srv, 2)
	t.Cleanup(func() { _ = job2.Close() })
	page2 := fetchPage(t, job2, page1.NextCursor)
	if got, want := patchIDs(page2), []string{"a/5.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 2 = %v, want %v", got, want)
	}
}

// An incremental run with nothing new returns one empty last page, as before.
func TestArchivePager_NothingNew_EmptyLastPage(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{entry("a/1.json", archiveEpoch)}))
	cursor, _ := json.Marshal(ArchiveCursor{LastModified: archiveEpoch})

	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })
	r := fetchPage(t, pager, cursor)
	if len(r.Patches) != 0 || !r.LastPage {
		t.Fatalf("got %d patches, LastPage=%v; want 0 patches on the last page", len(r.Patches), r.LastPage)
	}
	want := archiveEpoch.Add(-archiveTimeResolution)
	if c := decodeArchiveCursor(t, r.NextCursor); !c.LastModified.Equal(want) {
		t.Errorf("final LastModified = %v, want one time step before the latest record time, %v", c.LastModified, want)
	}
}

// Entries with the same name are not split across pages, so resuming after a
// name cannot skip a duplicate of it.
func TestArchivePager_DuplicateNamesStayOnOnePage(t *testing.T) {
	t.Parallel()
	dup := testArchiveEntry{name: "a/2.json", content: `{"id":"a/2.json-second"}`, modified: archiveEpoch}
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", archiveEpoch),
		entry("a/2.json", archiveEpoch),
		dup,
		entry("a/3.json", archiveEpoch),
	}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	page1 := fetchPage(t, pager, nil)
	if got := len(page1.Patches); got != 3 {
		t.Fatalf("page 1 has %d patches %v, want 3: both a/2.json entries", got, patchIDs(page1))
	}
	page2 := fetchPage(t, pager, page1.NextCursor)
	if got, want := patchIDs(page2), []string{"a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 2 = %v, want %v", got, want)
	}
}

// The downloaded archive is removed when the pass ends and when the job closes
// the pager part-way through.
func TestArchivePager_RemovesDownloadedArchive(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", archiveEpoch),
		entry("a/2.json", archiveEpoch),
		entry("a/3.json", archiveEpoch),
	}))

	t.Run("closed part-way", func(t *testing.T) {
		pager := newTestPager(srv, 2)
		fetchPage(t, pager, nil)
		path := pager.archivePath()
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("archive missing while the pass is in progress: %v", err)
		}
		if err := pager.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("archive still present after Close: %v", err)
		}
		if err := pager.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})

	t.Run("pass ends", func(t *testing.T) {
		pager := newTestPager(srv, 2)
		page1 := fetchPage(t, pager, nil)
		path := pager.archivePath()
		fetchPage(t, pager, page1.NextCursor)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("archive still present after the last page: %v", err)
		}
	})
}

// A new pass always downloads the current archive, even if this pager still
// holds one from an earlier pass.
func TestArchivePager_NewPassDownloadsAgain(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json", archiveEpoch),
		entry("a/2.json", archiveEpoch),
		entry("a/3.json", archiveEpoch),
	}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	fetchPage(t, pager, nil)
	fetchPage(t, pager, nil)
	if srv.downloadCount() != 2 {
		t.Errorf("downloads = %d, want 2", srv.downloadCount())
	}
}

func TestArchivePager_RejectsResumeWithoutSnapshot(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{entry("a/1.json", archiveEpoch)}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	_, err := pager.Fetch(context.Background(), json.RawMessage(`{"last_modified":"0001-01-01T00:00:00Z","resume_after":"a/1.json"}`))
	if err == nil {
		t.Fatal("Fetch accepted a resume cursor without snapshot")
	}
	if srv.downloadCount() != 0 {
		t.Errorf("downloads = %d, want 0: the cursor is checked first", srv.downloadCount())
	}
}

// Cursors saved before paging existed hold only last_modified and start a new pass.
func TestArchivePager_AcceptsIncrementalCursorShape(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{entry("a/1.json", archiveEpoch.Add(time.Hour))}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	r := fetchPage(t, pager, json.RawMessage(`{"last_modified":"2024-01-01T00:00:00Z"}`))
	if got, want := patchIDs(r), []string{"a/1.json"}; !slices.Equal(got, want) {
		t.Fatalf("patches = %v, want %v", got, want)
	}
}

func TestArchivePager_DownloadError(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)
	pager := &ArchivePager{
		Client: ts.Client(), RateLimiter: rate.NewLimiter(rate.Inf, 1), URL: ts.URL,
		TempPattern: "cvert-archive-test-*.zip", SourceName: "test-archive", PageSize: 2,
		IsEntry: func(string) bool { return true }, Parse: parseTestEntry,
	}
	_, err := pager.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("Fetch returned no error for HTTP 500")
	}
	if want := "test-archive: download zip"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
}
