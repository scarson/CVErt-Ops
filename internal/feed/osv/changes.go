// ABOUTME: OSV cursor and paging: a backfill over all.zip, and incremental runs that read modified_id.csv
// ABOUTME: and fetch only the advisories changed since the cursor, one by one and rate-limited.
package osv

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

// rescanWindow is how far before a pass's Snapshot the next pass starts.
// modified_id.csv is exported separately from the advisories it lists and from
// all.zip, so an advisory can appear in it after one with a later time. The
// window re-reads the last hour of changes instead of risking a miss, as the
// MITRE adapter does for the same reason.
const rescanWindow = time.Hour

// maxRecordSize bounds one advisory's JSON. The largest real advisories are a
// few hundred kilobytes.
const maxRecordSize = 16 << 20

// Cursor is the JSON-serializable sync state for the OSV adapter.
//
// Between passes it holds only LastModified. A zero LastModified means no
// backfill has completed, and the next run reads all.zip. During a pass the
// cursor also holds Snapshot and After, so a later job continues the pass.
type Cursor struct {
	// LastModified selects the advisories an incremental pass reads: those
	// listed in modified_id.csv with a later time.
	LastModified time.Time `json:"last_modified"`
	// Snapshot is the newest time in modified_id.csv when the current pass
	// began. A pass reads changes up to it, and the next pass starts from it
	// less rescanWindow. Zero between passes.
	Snapshot time.Time `json:"snapshot,omitzero"`
	// After is where the current pass resumes: the last all.zip entry name read
	// during a backfill, or the last "<ecosystem>/<id>" read during an
	// incremental pass.
	After string `json:"after,omitempty"`
}

// backfillPage returns the next page of all.zip. The first page reads the
// newest time in modified_id.csv before downloading the archive; when the
// archive is read, the next pass starts from that time less rescanWindow.
func (a *Adapter) backfillPage(ctx context.Context, cur Cursor) ([]feed.CanonicalPatch, Cursor, bool, error) {
	snapshot := cur.Snapshot
	if cur.After == "" {
		newest, err := a.newestChange(ctx)
		if err != nil {
			return nil, Cursor{}, false, err
		}
		snapshot = newest
	} else if snapshot.IsZero() {
		return nil, Cursor{}, false, fmt.Errorf("osv: backfill cursor resumes after %q but has no snapshot", cur.After)
	}

	page, err := a.pager.Page(ctx, cur.After)
	if err != nil {
		return nil, Cursor{}, false, err
	}
	if page.Done {
		return page.Patches, Cursor{LastModified: snapshot.Add(-rescanWindow)}, true, nil
	}
	return page.Patches, Cursor{Snapshot: snapshot, After: page.Last}, false, nil
}

// changesPage returns the next page of advisories listed in modified_id.csv
// with a time after cur.LastModified and no later than the pass's Snapshot, in
// "<ecosystem>/<id>" order. An advisory that changes again after the pass
// began moves past the Snapshot and is left to the next pass.
func (a *Adapter) changesPage(ctx context.Context, cur Cursor) ([]feed.CanonicalPatch, Cursor, bool, error) {
	changes, err := a.readChanges(ctx, cur.LastModified)
	if err != nil {
		return nil, Cursor{}, false, err
	}
	snapshot := cur.Snapshot
	if snapshot.IsZero() {
		if len(changes) == 0 {
			return nil, Cursor{LastModified: cur.LastModified}, true, nil
		}
		snapshot = changes[0].modified
	}

	keys := make([]string, 0, len(changes))
	for _, c := range changes {
		if !c.modified.After(snapshot) {
			keys = append(keys, c.key)
		}
	}
	sort.Strings(keys)
	keys = slicesCompact(keys)

	i := sort.SearchStrings(keys, cur.After)
	if i < len(keys) && keys[i] == cur.After {
		i++
	}
	var patches []feed.CanonicalPatch
	for ; i < len(keys) && len(patches) < a.pager.PageSize; i++ {
		patch, err := a.fetchRecord(ctx, keys[i])
		if err != nil {
			return nil, Cursor{}, false, err
		}
		if patch != nil {
			patches = append(patches, *patch)
		}
	}

	if i >= len(keys) {
		return patches, Cursor{LastModified: snapshot.Add(-rescanWindow)}, true, nil
	}
	return patches, Cursor{LastModified: cur.LastModified, Snapshot: snapshot, After: keys[i-1]}, false, nil
}

// slicesCompact removes adjacent duplicates from a sorted slice.
func slicesCompact(keys []string) []string {
	out := keys[:0]
	for i, k := range keys {
		if i == 0 || k != keys[i-1] {
			out = append(out, k)
		}
	}
	return out
}

// change is one modified_id.csv line.
type change struct {
	modified time.Time
	key      string // "<ecosystem>/<id>"
}

// errStopReading ends a read of modified_id.csv early.
var errStopReading = errors.New("stop reading modified_id.csv")

// readChanges returns the modified_id.csv lines with a time after since,
// newest first. The file is newest first, so reading stops at the first line at
// or before since and the rest of the file is never downloaded.
func (a *Adapter) readChanges(ctx context.Context, since time.Time) ([]change, error) {
	var changes []change
	err := a.readModifiedIDs(ctx, func(c change) error {
		if !c.modified.After(since) {
			return errStopReading
		}
		changes = append(changes, c)
		return nil
	})
	return changes, err
}

// newestChange returns the time on the first line of modified_id.csv.
func (a *Adapter) newestChange(ctx context.Context) (time.Time, error) {
	var newest time.Time
	err := a.readModifiedIDs(ctx, func(c change) error {
		newest = c.modified
		return errStopReading
	})
	if err != nil {
		return time.Time{}, err
	}
	if newest.IsZero() {
		return time.Time{}, errors.New("osv: modified_id.csv lists no advisories")
	}
	return newest, nil
}

// readModifiedIDs streams modified_id.csv to visit, line by line, until visit
// returns errStopReading or the file ends.
func (a *Adapter) readModifiedIDs(ctx context.Context, visit func(change) error) error {
	if err := a.listLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("osv: rate limit: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modifiedIDsURL, nil)
	if err != nil {
		return fmt.Errorf("osv: read modified_id.csv: %w", err)
	}
	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is a fixed bucket constant
	if err != nil {
		return fmt.Errorf("osv: read modified_id.csv: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: read modified_id.csv: HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		c, err := parseChange(line)
		if err != nil {
			return err
		}
		if err := visit(c); err != nil {
			if errors.Is(err, errStopReading) {
				return nil
			}
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("osv: read modified_id.csv: %w", err)
	}
	return nil
}

// parseChange parses "<RFC 3339 time>,<ecosystem>/<id>". A line that does not
// parse is an error: the file's newest-first order is what lets a run stop
// reading early, and a line without a time breaks it.
func parseChange(line string) (change, error) {
	ts, key, ok := strings.Cut(line, ",")
	if !ok || key == "" {
		return change{}, fmt.Errorf("osv: malformed modified_id.csv line %.80q", line)
	}
	modified, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return change{}, fmt.Errorf("osv: malformed modified_id.csv time in %.80q", line)
	}
	return change{modified: modified, key: key}, nil
}

// fetchRecord downloads one advisory, <ecosystem>/<id>.json. An advisory listed
// in modified_id.csv but no longer in the bucket returns nil and is skipped;
// any other failure is an error, so the page is retried.
func (a *Adapter) fetchRecord(ctx context.Context, key string) (*feed.CanonicalPatch, error) {
	if err := a.recordLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("osv: rate limit: %w", err)
	}
	segments := strings.Split(key, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	recordURL := bucketURL + strings.Join(segments, "/") + ".json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, recordURL, nil)
	if err != nil {
		return nil, fmt.Errorf("osv: fetch %s: %w", key, err)
	}
	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the fixed bucket plus an escaped object name
	if err != nil {
		return nil, fmt.Errorf("osv: fetch %s: %w", key, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	switch {
	case resp.StatusCode == http.StatusNotFound:
		slog.WarnContext(ctx, "skipping OSV advisory missing from the bucket", "feed", SourceName, "advisory", key)
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("osv: fetch %s: HTTP %d", key, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRecordSize+1))
	if err != nil {
		return nil, fmt.Errorf("osv: fetch %s: %w", key, err)
	}
	if len(raw) > maxRecordSize {
		return nil, fmt.Errorf("osv: fetch %s: advisory exceeds %d bytes", key, maxRecordSize)
	}
	patch, err := parseRecord(raw)
	if err != nil {
		slog.WarnContext(ctx, "skipping unreadable OSV advisory", "feed", SourceName, "advisory", key, "error", err)
		return nil, nil
	}
	return patch, nil
}
