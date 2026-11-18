// ABOUTME: Holds one downloaded cvelistV5 ZIP for the length of a job and selects the records a walk returns.
// ABOUTME: Selection reads each record's cveMetadata.dateUpdated, because every ZIP entry carries the same modified time.
package mitre

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

// archive is a downloaded cvelistV5 ZIP and the records selected from it.
type archive struct {
	file *os.File
	zr   *zip.Reader
	// stopRelease cancels the removal registered on the context of the job
	// that downloaded the archive.
	stopRelease func() bool

	// selected holds the records whose CVE ID sorts after selectedAfter and
	// whose dateUpdated is after selectedSince, ordered by CVE ID.
	selected      []cveEntry
	selectedSince time.Time
	selectedAfter string
	hasSelection  bool
	// latest is the latest dateUpdated among the records the selection read.
	latest time.Time
}

// cveEntry is one CVE record in the archive.
type cveEntry struct {
	cveID string
	file  *zip.File
}

// openArchive reads the central directory of a downloaded archive.
func openArchive(f *os.File) (*archive, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat temp file: %w", err)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	return &archive{file: f, zr: zr}, nil
}

// remove closes and deletes the archive's temp file.
func (ar *archive) remove() {
	if ar.stopRelease != nil {
		ar.stopRelease()
	}
	_ = ar.file.Close()
	_ = os.Remove(ar.file.Name()) //nolint:gosec // G703: path from os.CreateTemp
}

// covers reports whether the current selection holds every record a page
// starting at cur needs.
func (ar *archive) covers(cur Cursor) bool {
	return ar.hasSelection && ar.selectedSince.Equal(cur.LastModified) && cur.After >= ar.selectedAfter
}

// selectRecords reads the dateUpdated of every record whose CVE ID sorts after
// after, and keeps those updated after since. A record without a readable
// dateUpdated is kept, since nothing shows it unchanged. Only cveMetadata is
// decoded, so a record that lists it before its containers is not read in full.
func (ar *archive) selectRecords(ctx context.Context, log *slog.Logger, since time.Time, after string) error {
	var selected []cveEntry
	var latest time.Time
	for _, f := range ar.zr.File {
		if !isCVEEntry(f.Name) {
			continue
		}
		id := strings.TrimSuffix(path.Base(f.Name), ".json")
		if id <= after {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		updated, err := readDateUpdated(f)
		if err != nil {
			log.WarnContext(ctx, "skipping unreadable CVE record", "feed", SourceName, "entry", f.Name, "error", err)
			continue
		}
		if updated.After(latest) {
			latest = updated
		}
		if updated.IsZero() || updated.After(since) {
			selected = append(selected, cveEntry{cveID: id, file: f})
		}
	}
	slices.SortFunc(selected, func(x, y cveEntry) int { return strings.Compare(x.cveID, y.cveID) })

	ar.selected = selected
	ar.selectedSince = since
	ar.selectedAfter = after
	ar.hasSelection = true
	ar.latest = latest
	return nil
}

// firstAfter returns the index of the first selected record whose CVE ID sorts after id.
func (ar *archive) firstAfter(id string) int {
	i, found := slices.BinarySearchFunc(ar.selected, id, func(r cveEntry, target string) int {
		return strings.Compare(r.cveID, target)
	})
	if found {
		i++
	}
	return i
}

// readDateUpdated returns a record's cveMetadata.dateUpdated, or the zero time
// when the record has none or it does not parse. It stops reading the entry
// once cveMetadata is decoded.
func readDateUpdated(f *zip.File) (time.Time, error) {
	rc, err := f.Open()
	if err != nil {
		return time.Time{}, err
	}
	defer rc.Close() //nolint:errcheck // read-only entry

	dec := json.NewDecoder(bufio.NewReaderSize(rc, 4096))
	if tok, err := dec.Token(); err != nil {
		return time.Time{}, err
	} else if tok != json.Delim('{') {
		return time.Time{}, errors.New("record is not a JSON object")
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return time.Time{}, err
		}
		if key == "cveMetadata" {
			var meta struct {
				DateUpdated string `json:"dateUpdated"`
			}
			if err := dec.Decode(&meta); err != nil {
				return time.Time{}, err
			}
			return feed.ParseTime(meta.DateUpdated), nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return time.Time{}, err
		}
	}
	return time.Time{}, nil
}
