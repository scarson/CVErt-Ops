// ABOUTME: Tests feed completeness: a finished walk read from each adapter's cursor, and a success within 7 days.
// ABOUTME: Cursors are marshalled from the adapters' own Cursor types, so a renamed JSON key fails here.
package check

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed/ghsa"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/feed/osv"
)

var feedNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func marshalCursor(t *testing.T, cursor any) []byte {
	t.Helper()
	b, err := json.Marshal(cursor)
	if err != nil {
		t.Fatalf("marshal %+v: %v", cursor, err)
	}
	return b
}

func ago(d time.Duration) *time.Time {
	at := feedNow.Add(-d)
	return &at
}

// finishedCursors returns, for each feed, a cursor whose walk has finished.
func finishedCursors(t *testing.T) map[string][]byte {
	return map[string][]byte{
		ghsa.SourceName: marshalCursor(t, ghsa.Cursor{Since: "2026-11-09T00:00:00Z"}),
		osv.SourceName:  marshalCursor(t, osv.Cursor{LastModified: feedNow.Add(-time.Hour)}),
		nvd.SourceName:  marshalCursor(t, nvd.Cursor{CaughtUp: true}),
	}
}

func TestFeedStatusesWalkFinished(t *testing.T) {
	t.Parallel()
	finished := finishedCursors(t)
	tests := []struct {
		name   string
		feed   string
		cursor []byte
		want   bool
	}{
		{"GHSA with since", ghsa.SourceName, finished[ghsa.SourceName], true},
		{"GHSA without since", ghsa.SourceName, marshalCursor(t, ghsa.Cursor{After: "page2"}), false},
		{"OSV with last_modified", osv.SourceName, finished[osv.SourceName], true},
		{"OSV during its first backfill", osv.SourceName, marshalCursor(t, osv.Cursor{After: "a.json", Snapshot: feedNow}), false},
		{"NVD caught up", nvd.SourceName, finished[nvd.SourceName], true},
		{"NVD walking", nvd.SourceName, marshalCursor(t, nvd.Cursor{WindowStart: feedNow, StartIndex: 2000}), false},
		{"unparseable cursor", nvd.SourceName, []byte(`{"caught_up":`), false},
		{"empty cursor", ghsa.SourceName, nil, false},
		{"JSON null cursor", osv.SourceName, []byte(`null`), false},
		{"OSV last_modified that is not a time", osv.SourceName, []byte(`{"last_modified":"soon"}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FeedStatuses([]FeedRow{{Name: tt.feed, CursorJSON: tt.cursor, LastSuccessAt: ago(time.Hour)}}, feedNow)
			if got[tt.feed].Complete != tt.want {
				t.Errorf("complete = %v, want %v (cursor %s)", got[tt.feed].Complete, tt.want, tt.cursor)
			}
		})
	}
}

func TestFeedStatusesStaleness(t *testing.T) {
	t.Parallel()
	cursor := finishedCursors(t)[nvd.SourceName]
	tests := []struct {
		name        string
		lastSuccess *time.Time
		want        bool
	}{
		{"an hour ago", ago(time.Hour), true},
		{"exactly 7 days ago", ago(7 * 24 * time.Hour), true},
		{"just over 7 days ago", ago(7*24*time.Hour + time.Second), false},
		{"never succeeded", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FeedStatuses([]FeedRow{{Name: nvd.SourceName, CursorJSON: cursor, LastSuccessAt: tt.lastSuccess}}, feedNow)
			want := FeedStatus{Name: nvd.SourceName, Complete: tt.want, LastSuccessAt: tt.lastSuccess}
			if !reflect.DeepEqual(got[nvd.SourceName], want) {
				t.Errorf("status = %+v, want %+v", got[nvd.SourceName], want)
			}
		})
	}
}

// TestFeedStatusesListsEveryCheckFeed checks that ghsa, osv and nvd always
// appear, incomplete when they have no row, and that other feeds do not.
func TestFeedStatusesListsEveryCheckFeed(t *testing.T) {
	t.Parallel()
	got := FeedStatuses([]FeedRow{
		{Name: "kev", CursorJSON: []byte(`{}`), LastSuccessAt: ago(time.Hour)},
		{Name: osv.SourceName, CursorJSON: finishedCursors(t)[osv.SourceName], LastSuccessAt: ago(time.Hour)},
	}, feedNow)
	want := map[string]FeedStatus{
		"ghsa": {Name: "ghsa"},
		"osv":  {Name: "osv", Complete: true, LastSuccessAt: ago(time.Hour)},
		"nvd":  {Name: "nvd"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FeedStatuses = %+v, want %+v", got, want)
	}
}

func TestFeedStatusJSON(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal([]FeedStatus{
		{Name: "osv", Complete: true, LastSuccessAt: ago(0)},
		{Name: "nvd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"name":"osv","complete":true,"last_success_at":"2026-11-10T12:00:00Z"},` +
		`{"name":"nvd","complete":false,"last_success_at":null}]`
	if string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}

// TestFeedsFor checks design section 5's dependency table.
func TestFeedsFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		item Item
		want []string
	}{
		{"distro package", Item{Package: &PackageRef{Ecosystem: "Ubuntu:26.04:LTS", Name: "php8.5"}}, []string{"osv"}},
		{"distro package without a release", Item{Package: &PackageRef{Ecosystem: "Wolfi", Name: "php"}}, []string{"osv"}},
		{"other package", Item{Package: &PackageRef{Ecosystem: "npm", Name: "fastify"}}, []string{"ghsa", "nvd", "osv"}},
		{"CPE", Item{Product: &ProductRef{Part: "a", Vendor: "nodejs", Product: "node.js"}}, []string{"nvd"}},
		{"invalid", Item{Error: &ItemError{Code: "invalid_form"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := feedsFor(tt.item); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("feedsFor = %v, want %v", got, tt.want)
			}
		})
	}
}
