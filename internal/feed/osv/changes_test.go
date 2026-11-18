// ABOUTME: Tests for OSV runs: a first backfill paged over all.zip, and incremental runs driven by modified_id.csv.
// ABOUTME: A fake bucket counts requests per path, so tests pin which downloads each kind of run makes.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// testBucket stands in for the osv-vulnerabilities bucket: all.zip,
// modified_id.csv, and one JSON object per record under <ecosystem>/<id>.json.
type testBucket struct {
	mu       sync.Mutex
	zip      []byte
	csv      string
	records  map[string][]byte // "<ecosystem>/<id>" → advisory JSON
	status   map[string]int    // "<ecosystem>/<id>" → forced HTTP status
	requests map[string]int    // request path without the leading "/" → count
}

func newTestBucket(zip []byte, csv string) *testBucket {
	return &testBucket{zip: zip, csv: csv, records: map[string][]byte{}, status: map[string]int{}, requests: map[string]int{}}
}

func (b *testBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	b.mu.Lock()
	b.requests[path]++
	zip, csv := b.zip, b.csv
	key := strings.TrimSuffix(path, ".json")
	rec, ok := b.records[key]
	status := b.status[key]
	b.mu.Unlock()

	switch {
	case path == "all.zip":
		_, _ = w.Write(zip)
	case path == "modified_id.csv":
		_, _ = w.Write([]byte(csv))
	case status != 0:
		w.WriteHeader(status)
	case ok:
		_, _ = w.Write(rec)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (b *testBucket) setCSV(csv string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.csv = csv
}

// addRecord serves a minimal advisory whose ID is the key's last segment.
func (b *testBucket) addRecord(key string) {
	id := key[strings.LastIndex(key, "/")+1:]
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records[key] = minimalOSVAdvisoryJSON(id, nil)
}

func (b *testBucket) count(path string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests[path]
}

// recordFetches counts requests for single records.
func (b *testBucket) recordFetches() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for p, c := range b.requests {
		if p != "all.zip" && p != "modified_id.csv" {
			n += c
		}
	}
	return n
}

// newBucketAdapter returns an adapter for one job against the bucket, with
// rate limits lifted so tests do not wait.
func newBucketAdapter(t *testing.T, b *testBucket, pageSize int) *Adapter {
	t.Helper()
	ts := httptest.NewServer(b)
	t.Cleanup(ts.Close)
	a := newTestAdapter(ts)
	a.pager.RateLimiter = rate.NewLimiter(rate.Inf, 1)
	a.listLimiter = rate.NewLimiter(rate.Inf, 1)
	a.recordLimiter = rate.NewLimiter(rate.Inf, 1)
	a.pager.PageSize = pageSize
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// csvLines builds modified_id.csv content, newest first as OSV publishes it.
func csvLines(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func csvLine(t time.Time, key string) string {
	return t.Format(time.RFC3339Nano) + "," + key
}

func decodeCursor(t *testing.T, raw json.RawMessage) Cursor {
	t.Helper()
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal cursor %s: %v", raw, err)
	}
	return c
}

func fetchIDs(t *testing.T, a *Adapter, cursor json.RawMessage) ([]string, json.RawMessage, bool) {
	t.Helper()
	r, err := a.Fetch(context.Background(), cursor)
	if err != nil {
		t.Fatalf("Fetch(%s): %v", cursor, err)
	}
	ids := make([]string, 0, len(r.Patches))
	for _, p := range r.Patches {
		ids = append(ids, p.SourceID)
	}
	return ids, r.NextCursor, r.LastPage
}

var changeBase = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// backfillCSV is a modified_id.csv for tests that only exercise a backfill,
// which reads its first line.
var backfillCSV = csvLines(csvLine(changeBase, "Go/GHSA-xxxx-xxxx-xxxx"))

// A first backfill reads the newest time in modified_id.csv, then pages
// all.zip. When the archive is read, the cursor becomes that time less
// rescanWindow, so the next run fetches only what changed since.
func TestFetch_Backfill_EndsAtNewestChangeLessRescanWindow(t *testing.T) {
	t.Parallel()
	b := newTestBucket(buildOSVZip(t, []zipEntry{
		{name: "GHSA-aaaa-0001.json", content: minimalOSVAdvisoryJSON("GHSA-aaaa-0001", nil)},
		{name: "GHSA-aaaa-0002.json", content: minimalOSVAdvisoryJSON("GHSA-aaaa-0002", nil)},
		{name: "GHSA-aaaa-0003.json", content: minimalOSVAdvisoryJSON("GHSA-aaaa-0003", nil)},
	}), csvLines(csvLine(changeBase, "npm/GHSA-aaaa-0003"), csvLine(changeBase.Add(-time.Hour), "npm/GHSA-aaaa-0001")))

	job1 := newBucketAdapter(t, b, 2)
	ids, cursor, last := fetchIDs(t, job1, nil)
	if want := []string{"GHSA-aaaa-0001", "GHSA-aaaa-0002"}; !slices.Equal(ids, want) || last {
		t.Fatalf("page 1 = %v (last %v), want %v and more to come", ids, last, want)
	}
	mid := decodeCursor(t, cursor)
	if !mid.LastModified.IsZero() || !mid.Snapshot.Equal(changeBase) || mid.After != "GHSA-aaaa-0002.json" {
		t.Errorf("mid-backfill cursor = %s, want zero last_modified, snapshot %v, after GHSA-aaaa-0002.json", cursor, changeBase)
	}
	_ = job1.Close()

	// A later job resumes the backfill without reading modified_id.csv again.
	job2 := newBucketAdapter(t, b, 2)
	ids, cursor, last = fetchIDs(t, job2, cursor)
	if want := []string{"GHSA-aaaa-0003"}; !slices.Equal(ids, want) || !last {
		t.Fatalf("page 2 = %v (last %v), want %v on the last page", ids, last, want)
	}
	final := decodeCursor(t, cursor)
	if want := changeBase.Add(-rescanWindow); !final.LastModified.Equal(want) || !final.Snapshot.IsZero() || final.After != "" {
		t.Errorf("final cursor = %s, want only last_modified %v", cursor, want)
	}
	if got := b.count("modified_id.csv"); got != 1 {
		t.Errorf("modified_id.csv requests = %d, want 1", got)
	}
	if got := b.count("all.zip"); got != 2 {
		t.Errorf("all.zip requests = %d, want 2: once per job", got)
	}
	if got := b.recordFetches(); got != 0 {
		t.Errorf("record fetches = %d, want 0 during a backfill", got)
	}
}

// An incremental run with N changed records fetches those N records one by one
// and never downloads all.zip.
func TestFetch_Incremental_FetchesOnlyChangedRecords(t *testing.T) {
	t.Parallel()
	cursorTime := changeBase.Add(-3 * time.Hour)
	b := newTestBucket(nil, csvLines(
		csvLine(changeBase, "PyPI/PYSEC-2026-3"),
		csvLine(changeBase.Add(-time.Hour), "[EMPTY]/OSV-2026-2"),
		csvLine(changeBase.Add(-2*time.Hour), "Go/GO-2026-1"),
		csvLine(cursorTime, "Go/GO-2026-0"),
		csvLine(changeBase.Add(-4*time.Hour), "npm/GHSA-old0-old0-old0"),
	))
	for _, k := range []string{"PyPI/PYSEC-2026-3", "[EMPTY]/OSV-2026-2", "Go/GO-2026-1", "Go/GO-2026-0", "npm/GHSA-old0-old0-old0"} {
		b.addRecord(k)
	}
	cursor, _ := json.Marshal(Cursor{LastModified: cursorTime})

	a := newBucketAdapter(t, b, 10)
	ids, next, last := fetchIDs(t, a, cursor)
	if want := []string{"GO-2026-1", "PYSEC-2026-3", "OSV-2026-2"}; !slices.Equal(ids, want) {
		t.Fatalf("patches = %v, want %v in key order", ids, want)
	}
	if !last {
		t.Error("a run that fetched every changed record is not marked as the last page")
	}
	if got := b.recordFetches(); got != 3 {
		t.Errorf("record fetches = %d, want 3, one per changed record", got)
	}
	if got := b.count("all.zip"); got != 0 {
		t.Errorf("all.zip requests = %d, want 0 on an incremental run", got)
	}
	if got := b.count("[EMPTY]/OSV-2026-2.json"); got != 1 {
		t.Errorf("requests for [EMPTY]/OSV-2026-2.json = %d, want 1: the ecosystem directory must survive escaping", got)
	}
	if final := decodeCursor(t, next); !final.LastModified.Equal(changeBase.Add(-rescanWindow)) || !final.Snapshot.IsZero() {
		t.Errorf("final cursor = %s, want only last_modified %v", next, changeBase.Add(-rescanWindow))
	}
}

// modified_id.csv is newest first, so an incremental run stops reading at the
// first line at or before its cursor and never reads the rest of the file.
func TestFetch_Incremental_StopsReadingAtCursor(t *testing.T) {
	t.Parallel()
	cursorTime := changeBase.Add(-time.Hour)
	b := newTestBucket(nil, csvLines(
		csvLine(changeBase, "Go/GO-2026-1"),
		csvLine(cursorTime, "Go/GO-2026-0"),
		"not a csv line at all",
	))
	b.addRecord("Go/GO-2026-1")
	cursor, _ := json.Marshal(Cursor{LastModified: cursorTime})

	a := newBucketAdapter(t, b, 10)
	ids, _, _ := fetchIDs(t, a, cursor)
	if want := []string{"GO-2026-1"}; !slices.Equal(ids, want) {
		t.Fatalf("patches = %v, want %v", ids, want)
	}
}

// A malformed line among the changes is an error, not a silent skip: the file's
// order is what lets a run stop early, and a line without a time breaks it.
func TestFetch_Incremental_MalformedLine(t *testing.T) {
	t.Parallel()
	b := newTestBucket(nil, csvLines(csvLine(changeBase, "Go/GO-2026-1"), "yesterday,Go/GO-2026-0"))
	cursor, _ := json.Marshal(Cursor{LastModified: changeBase.Add(-24 * time.Hour)})

	a := newBucketAdapter(t, b, 10)
	if _, err := a.Fetch(context.Background(), cursor); err == nil {
		t.Fatal("Fetch accepted a modified_id.csv line without a valid time")
	}
}

// Nothing changed since the cursor: no record fetches, and the cursor stays.
func TestFetch_Incremental_NothingNew(t *testing.T) {
	t.Parallel()
	b := newTestBucket(nil, csvLines(csvLine(changeBase, "Go/GO-2026-1")))
	cursor, _ := json.Marshal(Cursor{LastModified: changeBase})

	a := newBucketAdapter(t, b, 10)
	ids, next, last := fetchIDs(t, a, cursor)
	if len(ids) != 0 || !last {
		t.Fatalf("patches = %v (last %v), want none on the last page", ids, last)
	}
	if got := decodeCursor(t, next); !got.LastModified.Equal(changeBase) {
		t.Errorf("cursor = %s, want last_modified unchanged at %v", next, changeBase)
	}
	if got := b.recordFetches(); got != 0 {
		t.Errorf("record fetches = %d, want 0", got)
	}
}

// An incremental pass larger than one job resumes in key order. Records that
// change again, or appear, after the pass began are left to the next pass,
// which starts from the pass's snapshot less rescanWindow.
func TestFetch_Incremental_PagesResumeAcrossJobs(t *testing.T) {
	t.Parallel()
	cursorTime := changeBase.Add(-5 * time.Hour)
	b := newTestBucket(nil, csvLines(
		csvLine(changeBase, "Go/GO-2026-A"),
		csvLine(changeBase.Add(-2*time.Hour), "Go/GO-2026-B"),
		csvLine(changeBase.Add(-3*time.Hour), "Go/GO-2026-C"),
		csvLine(cursorTime, "Go/GO-2026-Z"),
	))
	for _, k := range []string{"Go/GO-2026-A", "Go/GO-2026-B", "Go/GO-2026-C", "Go/GO-2026-E"} {
		b.addRecord(k)
	}
	cursor, _ := json.Marshal(Cursor{LastModified: cursorTime})

	job1 := newBucketAdapter(t, b, 2)
	ids, next, last := fetchIDs(t, job1, cursor)
	if want := []string{"GO-2026-A", "GO-2026-B"}; !slices.Equal(ids, want) || last {
		t.Fatalf("page 1 = %v (last %v), want %v and more to come", ids, last, want)
	}
	mid := decodeCursor(t, next)
	if !mid.LastModified.Equal(cursorTime) || !mid.Snapshot.Equal(changeBase) || mid.After != "Go/GO-2026-B" {
		t.Errorf("mid-pass cursor = %s, want the pass baseline, snapshot %v and after Go/GO-2026-B", next, changeBase)
	}

	// Between jobs, A changes again and E is added, both after the snapshot.
	later := changeBase.Add(time.Hour)
	b.setCSV(csvLines(
		csvLine(later, "Go/GO-2026-E"),
		csvLine(later, "Go/GO-2026-A"),
		csvLine(changeBase.Add(-2*time.Hour), "Go/GO-2026-B"),
		csvLine(changeBase.Add(-3*time.Hour), "Go/GO-2026-C"),
		csvLine(cursorTime, "Go/GO-2026-Z"),
	))
	job2 := newBucketAdapter(t, b, 2)
	ids, next, last = fetchIDs(t, job2, next)
	if want := []string{"GO-2026-C"}; !slices.Equal(ids, want) || !last {
		t.Fatalf("resumed page = %v (last %v), want %v on the last page", ids, last, want)
	}
	if final := decodeCursor(t, next); !final.LastModified.Equal(changeBase.Add(-rescanWindow)) {
		t.Errorf("final cursor = %s, want last_modified %v", next, changeBase.Add(-rescanWindow))
	}

	job3 := newBucketAdapter(t, b, 10)
	ids, _, _ = fetchIDs(t, job3, next)
	if want := []string{"GO-2026-A", "GO-2026-E"}; !slices.Equal(ids, want) {
		t.Fatalf("next pass = %v, want the records changed after the snapshot %v", ids, want)
	}
}

// A record listed in modified_id.csv but gone from the bucket is skipped; any
// other failed fetch fails the run so the page is retried.
func TestFetch_Incremental_RecordFetchFailures(t *testing.T) {
	t.Parallel()
	cursor, _ := json.Marshal(Cursor{LastModified: changeBase.Add(-time.Hour)})
	csv := csvLines(csvLine(changeBase, "Go/GO-2026-1"), csvLine(changeBase, "Go/GO-2026-2"))

	t.Run("not found is skipped", func(t *testing.T) {
		b := newTestBucket(nil, csv)
		b.addRecord("Go/GO-2026-2")
		ids, _, _ := fetchIDs(t, newBucketAdapter(t, b, 10), cursor)
		if want := []string{"GO-2026-2"}; !slices.Equal(ids, want) {
			t.Fatalf("patches = %v, want %v", ids, want)
		}
	})

	t.Run("server error fails the run", func(t *testing.T) {
		b := newTestBucket(nil, csv)
		b.addRecord("Go/GO-2026-2")
		b.status["Go/GO-2026-1"] = http.StatusServiceUnavailable
		_, err := newBucketAdapter(t, b, 10).Fetch(context.Background(), cursor)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(http.StatusServiceUnavailable)) {
			t.Fatalf("Fetch error = %v, want one naming status 503", err)
		}
	})
}
