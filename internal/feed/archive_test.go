// ABOUTME: Tests for ArchivePager, which pages a downloaded ZIP archive in entry-name order across Fetch calls and jobs.
// ABOUTME: Covers page slicing, resume in a new job, upstream archive changes, duplicate names, and cleanup.
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
	name    string
	content string
}

func entry(name string) testArchiveEntry {
	return testArchiveEntry{name: name, content: fmt.Sprintf(`{"id":%q}`, name)}
}

func buildTestArchive(t *testing.T, entries []testArchiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})
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

func pageIDs(p *ArchivePage) []string {
	ids := make([]string, 0, len(p.Patches))
	for _, patch := range p.Patches {
		ids = append(ids, patch.CVEID)
	}
	return ids
}

func readPage(t *testing.T, p *ArchivePager, resumeAfter string) *ArchivePage {
	t.Helper()
	page, err := p.Page(context.Background(), resumeAfter)
	if err != nil {
		t.Fatalf("Page(%q): %v", resumeAfter, err)
	}
	return page
}

// A pass is split into pages in entry-name order, with one download per job.
// Each page reports the last entry name it read, where the next page resumes.
func TestArchivePager_SplitsPassIntoPages(t *testing.T) {
	t.Parallel()
	// Stored out of name order; pages follow name order.
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/5.json"),
		entry("a/1.json"),
		entry("a/4.json"),
		{name: "README.md", content: "not an entry"},
		entry("a/2.json"),
		{name: "a/3.json", content: "{not json"},
	}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	page1 := readPage(t, pager, "")
	if got, want := pageIDs(page1), []string{"a/1.json", "a/2.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 1 = %v, want %v", got, want)
	}
	if page1.Done {
		t.Fatal("page 1 is marked as the end of the archive")
	}
	if page1.Last != "a/2.json" {
		t.Errorf("page 1 Last = %q, want a/2.json", page1.Last)
	}

	// The malformed entry is skipped and does not count towards the page.
	page2 := readPage(t, pager, page1.Last)
	if got, want := pageIDs(page2), []string{"a/4.json", "a/5.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 2 = %v, want %v", got, want)
	}
	if !page2.Done {
		t.Fatal("page 2 reached the end of the archive and is not marked done")
	}
	if srv.downloadCount() != 1 {
		t.Errorf("downloads = %d, want 1: pages of one job share the archive", srv.downloadCount())
	}
}

// A later job downloads the archive again and resumes after the saved entry name.
func TestArchivePager_ResumesInNewJob(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json"), entry("a/2.json"), entry("a/3.json"),
	}))

	job1 := newTestPager(srv, 2)
	page1 := readPage(t, job1, "")
	if err := job1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	job2 := newTestPager(srv, 2)
	t.Cleanup(func() { _ = job2.Close() })
	page2 := readPage(t, job2, page1.Last)
	if got, want := pageIDs(page2), []string{"a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("resumed page = %v, want %v", got, want)
	}
	if !page2.Done {
		t.Fatal("resumed page is not marked done")
	}
	if srv.downloadCount() != 2 {
		t.Errorf("downloads = %d, want 2: a new job downloads the archive again", srv.downloadCount())
	}
}

// When the upstream archive changes between jobs, the resumed pass reads the new
// archive after the resume name: entries added ahead of it are read, and
// entries added behind it are left to whatever the caller reads next.
func TestArchivePager_UpstreamChangeBetweenJobs_ResumesByName(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json"), entry("a/3.json"), entry("a/5.json"),
	}))

	job1 := newTestPager(srv, 2)
	page1 := readPage(t, job1, "")
	_ = job1.Close()

	srv.replace(buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json"), entry("a/2.json"), entry("a/3.json"), entry("a/4.json"), entry("a/5.json"),
	}))
	job2 := newTestPager(srv, 5)
	t.Cleanup(func() { _ = job2.Close() })
	page2 := readPage(t, job2, page1.Last)
	if got, want := pageIDs(page2), []string{"a/4.json", "a/5.json"}; !slices.Equal(got, want) {
		t.Fatalf("resumed page = %v, want %v", got, want)
	}
}

// Entries with the same name are not split across pages, so resuming after a
// name cannot skip a duplicate of it.
func TestArchivePager_DuplicateNamesStayOnOnePage(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json"),
		entry("a/2.json"),
		{name: "a/2.json", content: `{"id":"a/2.json-second"}`},
		entry("a/3.json"),
	}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	page1 := readPage(t, pager, "")
	if got := len(page1.Patches); got != 3 {
		t.Fatalf("page 1 has %d patches %v, want 3: both a/2.json entries", got, pageIDs(page1))
	}
	page2 := readPage(t, pager, page1.Last)
	if got, want := pageIDs(page2), []string{"a/3.json"}; !slices.Equal(got, want) {
		t.Fatalf("page 2 = %v, want %v", got, want)
	}
}

// The downloaded archive is removed when the pass ends and when the job closes
// the pager part-way through.
func TestArchivePager_RemovesDownloadedArchive(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{
		entry("a/1.json"), entry("a/2.json"), entry("a/3.json"),
	}))

	t.Run("closed part-way", func(t *testing.T) {
		pager := newTestPager(srv, 2)
		readPage(t, pager, "")
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
		page1 := readPage(t, pager, "")
		path := pager.archivePath()
		readPage(t, pager, page1.Last)
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
		entry("a/1.json"), entry("a/2.json"), entry("a/3.json"),
	}))
	pager := newTestPager(srv, 2)
	t.Cleanup(func() { _ = pager.Close() })

	readPage(t, pager, "")
	readPage(t, pager, "")
	if srv.downloadCount() != 2 {
		t.Errorf("downloads = %d, want 2", srv.downloadCount())
	}
}

func TestArchivePager_RejectsPageSizeBelowOne(t *testing.T) {
	t.Parallel()
	srv := newArchiveServer(t, buildTestArchive(t, []testArchiveEntry{entry("a/1.json")}))
	pager := newTestPager(srv, 0)
	if _, err := pager.Page(context.Background(), ""); err == nil {
		t.Fatal("Page accepted a page size of 0")
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
	_, err := pager.Page(context.Background(), "")
	if err == nil {
		t.Fatal("Page returned no error for HTTP 500")
	}
	if want := "test-archive: download zip"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
}
