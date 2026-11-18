// ABOUTME: Tests for the MITRE adapter's incremental, paged walk of the cvelistV5 archive.
// ABOUTME: Every test archive gives all entries one modified time, as the real archive does.
package mitre

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

// archiveTime is the one modified time every entry carries, like the commit
// time that GitHub stamps on every entry of the real archive.
var archiveTime = time.Date(2026, 11, 7, 21, 10, 52, 0, time.UTC)

// record is one CVE in a test archive. A nil content means a minimal valid
// record with the given dateUpdated.
type record struct {
	id      string
	updated string
	content []byte
}

func recordJSON(id, updated string) []byte {
	root := cve5Root{
		CVEMetadata: cve5Metadata{
			CVEID:         id,
			State:         "PUBLISHED",
			DatePublished: "2024-01-01T00:00:00Z",
			DateUpdated:   updated,
		},
		Containers: cve5Containers{
			CNA: cve5CNA{Descriptions: []cve5Description{{Lang: "en", Value: "Test vulnerability in " + id}}},
		},
	}
	b, _ := json.Marshal(root)
	return b
}

// uniformArchive builds a cvelistV5-style ZIP whose entries all share archiveTime.
func uniformArchive(t *testing.T, records ...record) []byte {
	t.Helper()
	entries := make([]zipEntry, 0, len(records))
	for _, r := range records {
		content := r.content
		if content == nil {
			content = recordJSON(r.id, r.updated)
		}
		year := strings.Split(r.id, "-")[1]
		entries = append(entries, zipEntry{
			name:    "cvelistV5-main/cves/" + year + "/0xxx/" + r.id + ".json",
			content: content,
			header:  &zip.FileHeader{Modified: archiveTime, Method: zip.Deflate},
		})
	}
	return buildMITREZip(t, entries)
}

// archiveServer serves a replaceable archive and counts downloads.
type archiveServer struct {
	t         *testing.T
	srv       *httptest.Server
	mu        sync.Mutex
	zipData   []byte
	downloads int
}

func newArchiveServer(t *testing.T, zipData []byte) *archiveServer {
	t.Helper()
	s := &archiveServer{t: t, zipData: zipData}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		data := s.zipData
		s.downloads++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(data)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *archiveServer) replace(zipData []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zipData = zipData
}

func (s *archiveServer) downloadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloads
}

// adapter returns an adapter for one job, with the given page size.
func (s *archiveServer) adapter(pageSize int) *Adapter {
	a := newTestAdapter(s.srv)
	a.pageSize = pageSize
	s.t.Cleanup(func() { _ = a.Close() })
	return a
}

func cveIDs(patches []feed.CanonicalPatch) []string {
	ids := make([]string, 0, len(patches))
	for _, p := range patches {
		ids = append(ids, p.CVEID)
	}
	return ids
}

func decodeCursor(t *testing.T, raw json.RawMessage) Cursor {
	t.Helper()
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode cursor %s: %v", raw, err)
	}
	return c
}

func mustCursor(t *testing.T, c Cursor) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	return b
}

// walkToEnd calls Fetch until LastPage and returns every patch and the final cursor.
func walkToEnd(t *testing.T, a *Adapter, cursor json.RawMessage) ([]feed.CanonicalPatch, json.RawMessage) {
	t.Helper()
	var all []feed.CanonicalPatch
	for range 100 {
		result, err := a.Fetch(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		all = append(all, result.Patches...)
		cursor = result.NextCursor
		if result.LastPage {
			return all, cursor
		}
		if len(result.Patches) == 0 {
			t.Fatal("Fetch returned an empty page that is not the last page")
		}
	}
	t.Fatal("walk did not reach its last page")
	return nil, nil
}

func TestFetch_SelectsRecordsUpdatedAfterCursor(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-06-01T00:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-09-01T00:00:00.123Z"},
	))

	result, err := s.adapter(1000).Fetch(context.Background(), json.RawMessage(`{"last_modified":"2024-03-01T00:00:00Z"}`))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, want := cveIDs(result.Patches), []string{"CVE-2024-0002", "CVE-2024-0003"}; !slices.Equal(got, want) {
		t.Errorf("patches = %v, want %v", got, want)
	}
	if !result.LastPage {
		t.Error("LastPage = false, want true")
	}
}

// A record that has no dateUpdated cannot be shown to be unchanged.
func TestFetch_SelectsRecordsWithoutDateUpdated(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: ""},
	))

	result, err := s.adapter(1000).Fetch(context.Background(), json.RawMessage(`{"last_modified":"2024-03-01T00:00:00Z"}`))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, want := cveIDs(result.Patches), []string{"CVE-2024-0002"}; !slices.Equal(got, want) {
		t.Errorf("patches = %v, want %v", got, want)
	}
}

func TestFetch_FirstRunReturnsEveryRecordInPagesByCVEID(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0004", updated: "2024-01-04T00:00:00Z"},
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0005", updated: "2024-01-05T00:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-01-03T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-01-02T00:00:00Z"},
	))
	a := s.adapter(2)

	var pages [][]string
	var cursor json.RawMessage
	for {
		result, err := a.Fetch(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		pages = append(pages, cveIDs(result.Patches))
		cursor = result.NextCursor
		if result.LastPage {
			break
		}
		if len(pages) > 5 {
			t.Fatalf("too many pages: %v", pages)
		}
	}

	want := [][]string{
		{"CVE-2024-0001", "CVE-2024-0002"},
		{"CVE-2024-0003", "CVE-2024-0004"},
		{"CVE-2024-0005"},
	}
	if !slices.EqualFunc(pages, want, slices.Equal) {
		t.Errorf("pages = %v, want %v", pages, want)
	}
	if n := s.downloadCount(); n != 1 {
		t.Errorf("downloads = %d, want 1 for one job", n)
	}
}

func TestFetch_IntermediateCursorRecordsPosition(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-05-01T12:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-01-03T00:00:00Z"},
	))

	result, err := s.adapter(1).Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.LastPage {
		t.Fatal("LastPage = true on the first of three pages")
	}
	c := decodeCursor(t, result.NextCursor)
	if c.After != "CVE-2024-0001" {
		t.Errorf("After = %q, want CVE-2024-0001", c.After)
	}
	if want := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC); !c.Snapshot.Equal(want) {
		t.Errorf("Snapshot = %s, want the archive's latest dateUpdated %s", c.Snapshot, want)
	}
	if !c.LastModified.IsZero() {
		t.Errorf("LastModified = %s, want zero during a first walk", c.LastModified)
	}
}

func TestFetch_WalkEndsAtLatestDateUpdatedLessRescanWindow(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-05-01T12:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-01-03T00:00:00Z"},
	))

	_, final := walkToEnd(t, s.adapter(1), nil)

	c := decodeCursor(t, final)
	want := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Add(-rescanWindow)
	if !c.LastModified.Equal(want) {
		t.Errorf("LastModified = %s, want %s", c.LastModified, want)
	}
	if c.After != "" || !c.Snapshot.IsZero() {
		t.Errorf("finished walk left After=%q Snapshot=%s, want both empty", c.After, c.Snapshot)
	}
}

// A job cut off by its time limit leaves the last saved cursor; the next job
// downloads the archive again and continues after the last returned record.
func TestFetch_NewJobResumesAfterLastReturnedRecord(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-01-02T00:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-01-03T00:00:00Z"},
		record{id: "CVE-2024-0004", updated: "2024-01-04T00:00:00Z"},
	))

	first, err := s.adapter(2).Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("job 1 Fetch: %v", err)
	}

	rest, _ := walkToEnd(t, s.adapter(2), first.NextCursor)

	if got, want := cveIDs(rest), []string{"CVE-2024-0003", "CVE-2024-0004"}; !slices.Equal(got, want) {
		t.Errorf("job 2 patches = %v, want %v", got, want)
	}
	if n := s.downloadCount(); n != 2 {
		t.Errorf("downloads = %d, want one per job", n)
	}
}

// Records passed early in a walk can change, or appear, before the walk ends.
// The next walk must fetch them.
func TestFetch_RecordChangedDuringWalkIsFetchedByNextWalk(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0009", updated: "2024-06-01T00:00:00Z"},
	))

	// Job 1 returns CVE-2024-0001, then the archive moves on upstream.
	first, err := s.adapter(1).Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("job 1 Fetch: %v", err)
	}
	if got := cveIDs(first.Patches); !slices.Equal(got, []string{"CVE-2024-0001"}) {
		t.Fatalf("job 1 patches = %v", got)
	}
	s.replace(uniformArchive(t,
		record{id: "CVE-2024-0000", updated: "2024-07-01T00:00:00Z"},
		record{id: "CVE-2024-0001", updated: "2024-07-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0003", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0009", updated: "2024-06-01T00:00:00Z"},
	))

	// Job 2 finishes the walk on the newer archive.
	rest, walkEnd := walkToEnd(t, s.adapter(1), first.NextCursor)
	if got, want := cveIDs(rest), []string{"CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0009"}; !slices.Equal(got, want) {
		t.Errorf("job 2 patches = %v, want %v", got, want)
	}

	// The next walk fetches the changed and the inserted record, not the unchanged ones.
	next, _ := walkToEnd(t, s.adapter(1000), walkEnd)
	got := cveIDs(next)
	for _, id := range []string{"CVE-2024-0000", "CVE-2024-0001"} {
		if !slices.Contains(got, id) {
			t.Errorf("next walk = %v, missing %s", got, id)
		}
	}
	for _, id := range []string{"CVE-2024-0002", "CVE-2024-0003"} {
		if slices.Contains(got, id) {
			t.Errorf("next walk = %v, includes unchanged %s", got, id)
		}
	}
}

// A malformed record is skipped without leaving a short page, which the
// ingest handler would take as the end of the feed.
func TestFetch_MalformedRecordDoesNotShortenPage(t *testing.T) {
	t.Parallel()
	s := newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", content: []byte(`{not valid json`)},
		record{id: "CVE-2024-0003", updated: "2024-01-03T00:00:00Z"},
		record{id: "CVE-2024-0004", updated: "2024-01-04T00:00:00Z"},
	))
	a := s.adapter(2)
	logs := captureWarnings(a)

	result, err := a.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, want := cveIDs(result.Patches), []string{"CVE-2024-0001", "CVE-2024-0003"}; !slices.Equal(got, want) {
		t.Errorf("page 1 = %v, want %v", got, want)
	}
	if result.LastPage {
		t.Error("LastPage = true with CVE-2024-0004 still to return")
	}
	if got := logs.String(); !strings.Contains(got, "skipping unreadable CVE record") || !strings.Contains(got, "CVE-2024-0002.json") {
		t.Errorf("log = %q, want a warning naming CVE-2024-0002.json", got)
	}
}

// captureWarnings sends the adapter's warnings to a buffer the test reads.
func captureWarnings(a *Adapter) *bytes.Buffer {
	var buf bytes.Buffer
	a.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return &buf
}

// The feed handler closes an adapter that implements io.Closer when its run
// ends, and both archive feeds return pages of the same size.
func TestNew_IsCloserWithArchivePageSize(t *testing.T) {
	t.Parallel()
	a := New(nil)
	if _, ok := any(a).(io.Closer); !ok {
		t.Error("Adapter does not implement io.Closer, so the feed handler will not close it")
	}
	if a.pageSize != feed.ArchivePageSize {
		t.Errorf("pageSize = %d, want feed.ArchivePageSize (%d)", a.pageSize, feed.ArchivePageSize)
	}
}

func archiveFileGone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// heldArchivePath returns the temp file the adapter holds between pages.
func heldArchivePath(t *testing.T, a *Adapter) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.archive == nil {
		t.Fatal("adapter holds no archive between pages")
	}
	return a.archive.file.Name()
}

func twoPageArchive(t *testing.T) *archiveServer {
	return newArchiveServer(t, uniformArchive(t,
		record{id: "CVE-2024-0001", updated: "2024-01-01T00:00:00Z"},
		record{id: "CVE-2024-0002", updated: "2024-01-02T00:00:00Z"},
	))
}

func TestFetch_RemovesArchiveAfterLastPage(t *testing.T) {
	t.Parallel()
	a := twoPageArchive(t).adapter(1)

	first, err := a.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	path := heldArchivePath(t, a)

	last, err := a.Fetch(context.Background(), first.NextCursor)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !last.LastPage {
		t.Fatal("second page is not the last page")
	}
	if !archiveFileGone(path) {
		t.Errorf("archive %s still exists after the last page", path)
	}
}

func TestClose_RemovesArchiveMidWalk(t *testing.T) {
	t.Parallel()
	a := twoPageArchive(t).adapter(1)

	if _, err := a.Fetch(context.Background(), nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	path := heldArchivePath(t, a)

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !archiveFileGone(path) {
		t.Errorf("archive %s still exists after Close", path)
	}
}

// The ingest handler does not close adapters; the job context ending must
// remove the archive of a walk the job did not finish.
func TestFetch_RemovesArchiveWhenJobContextEnds(t *testing.T) {
	t.Parallel()
	a := twoPageArchive(t).adapter(1)
	ctx, cancel := context.WithCancel(context.Background())

	if _, err := a.Fetch(ctx, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	path := heldArchivePath(t, a)

	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for !archiveFileGone(path) {
		if time.Now().After(deadline) {
			t.Fatalf("archive %s still exists after the job context ended", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
