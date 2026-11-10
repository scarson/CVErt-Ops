// ABOUTME: Decides whether each feed a version check depends on is complete: its walk finished and it ran within 7 days.
// ABOUTME: Also names the feeds each item depends on (design section 5).
package check

import (
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// The feeds a version check answer can depend on, by feed_sync_state.feed_name.
const (
	feedGHSA = "ghsa"
	feedNVD  = "nvd"
	feedOSV  = "osv"
)

// feedStaleAfter is how long after its last success a feed counts as incomplete,
// because "not affected" would then mean "not affected as of that run".
const feedStaleAfter = 7 * 24 * time.Hour

// FeedRow is one feed_sync_state row.
type FeedRow struct {
	Name          string
	CursorJSON    []byte
	LastSuccessAt *time.Time
}

// FeedStatus is one feed's completeness, as the response reports it.
type FeedStatus struct {
	Name          string     `json:"name"`
	Complete      bool       `json:"complete"`
	LastSuccessAt *time.Time `json:"last_success_at"`
}

// walkFinished reads, from each feed's cursor, whether a full walk has finished.
// Each mirrors the JSON key its adapter writes: the GHSA cursor's since, set
// once a sync completes; the OSV cursor's last_modified, zero until the first
// backfill completes; and the NVD cursor's caught_up.
var walkFinished = map[string]func(cursor []byte) bool{
	feedGHSA: func(cursor []byte) bool {
		var c struct {
			Since string `json:"since"`
		}
		return json.Unmarshal(cursor, &c) == nil && c.Since != ""
	},
	feedOSV: func(cursor []byte) bool {
		var c struct {
			LastModified time.Time `json:"last_modified"`
		}
		return json.Unmarshal(cursor, &c) == nil && !c.LastModified.IsZero()
	},
	feedNVD: func(cursor []byte) bool {
		var c struct {
			CaughtUp bool `json:"caught_up"`
		}
		return json.Unmarshal(cursor, &c) == nil && c.CaughtUp
	},
}

// FeedNames returns the feeds FeedStatuses reports on, sorted: the feed_sync_state
// rows a version check reads.
func FeedNames() []string {
	return slices.Sorted(maps.Keys(walkFinished))
}

// FeedStatuses returns the status of ghsa, osv and nvd, each present. A feed is
// complete when its walk has finished and its last success is no more than 7
// days before now. A feed with no row, a cursor that cannot be read, or no
// success is incomplete. Rows for other feeds are ignored.
func FeedStatuses(rows []FeedRow, now time.Time) map[string]FeedStatus {
	statuses := make(map[string]FeedStatus, len(walkFinished))
	for name := range walkFinished {
		statuses[name] = FeedStatus{Name: name}
	}
	for _, row := range rows {
		finished, ok := walkFinished[row.Name]
		if !ok {
			continue
		}
		statuses[row.Name] = FeedStatus{
			Name:          row.Name,
			Complete:      row.LastSuccessAt != nil && now.Sub(*row.LastSuccessAt) <= feedStaleAfter && finished(row.CursorJSON),
			LastSuccessAt: row.LastSuccessAt,
		}
	}
	return statuses
}

// feedsFor returns the feeds an item's answer depends on, sorted by name: OSV
// alone for a distro package, which only OSV holds and which reads no CNA rows;
// GHSA, OSV and NVD (for CNA package rows) for any other package; NVD for a CPE.
// An invalid item depends on none.
func feedsFor(item Item) []string {
	switch {
	case item.Package != nil && ecosystem.IsDistro(item.Package.Ecosystem):
		return []string{feedOSV}
	case item.Package != nil:
		return []string{feedGHSA, feedNVD, feedOSV}
	case item.Product != nil:
		return []string{feedNVD}
	}
	return nil
}
