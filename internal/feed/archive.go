// ABOUTME: Pages a feed published as one ZIP archive, so a pass larger than one worker job resumes in the next job.
// ABOUTME: Used by the OSV adapter; the cursor records the pass start time and the last entry name read.
package feed

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"golang.org/x/time/rate"
)

// ArchivePageSize is the number of patches in one archive page. A page is the
// unit the feed handler checkpoints, and at the roughly 13 CVEs per second seen
// on a real backfill it merges in about 80 seconds, well inside the handler's
// page reserve.
const ArchivePageSize = 1000

// ArchiveCursor is the sync state of a feed published as one ZIP archive.
//
// Between passes it holds only LastModified, the download time of the archive
// that began the last completed pass. During a pass it also holds PassStartedAt
// and ResumeAfter, so a later job can continue the pass from a new download.
type ArchiveCursor struct {
	// LastModified is the baseline of the current pass: entries modified at or
	// before it are skipped. Zero on a first pass, which reads every entry.
	LastModified time.Time `json:"last_modified"`
	// PassStartedAt is the download time of the archive that began the current
	// pass. It becomes LastModified when the pass ends, so every upstream change
	// made after the pass began is read by the next pass.
	PassStartedAt time.Time `json:"pass_started_at,omitzero"`
	// ResumeAfter is the name of the last entry read by the last completed page.
	// The pass continues with entries whose names sort after it.
	ResumeAfter string `json:"resume_after,omitempty"`
}

// ArchivePager fetches a ZIP archive and returns its entries in pages, in
// entry-name order. Within one job the downloaded archive is kept between Fetch
// calls; a later job downloads the current archive and continues after the
// cursor's entry name. Names, not positions, identify where to continue, because
// the upstream archive may have changed between jobs.
//
// The pager removes the downloaded archive when a pass ends; Close removes it
// when a job ends part-way through a pass. An ArchivePager is not safe for
// concurrent use.
type ArchivePager struct {
	Client      *http.Client
	RateLimiter *rate.Limiter
	URL         string
	// TempPattern is the os.CreateTemp pattern for the downloaded archive.
	TempPattern string
	// SourceName prefixes errors and is reported in SourceMeta.
	SourceName string
	PageSize   int
	// IsEntry reports whether an archive entry holds a record.
	IsEntry func(name string) bool
	// Parse reads one entry. An error or nil patch skips the entry.
	Parse func(entry *zip.File) (*CanonicalPatch, error)

	archive *downloadedArchive
}

// downloadedArchive is an archive held between the Fetch calls of one job.
type downloadedArchive struct {
	file      *os.File
	entries   []*zip.File // record entries, sorted by name
	fetchedAt time.Time
}

// Fetch returns the next page of the pass that cursorJSON describes, or the
// first page of a new pass when the cursor is not mid-pass.
func (p *ArchivePager) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*FetchResult, error) {
	if p.PageSize < 1 {
		return nil, fmt.Errorf("%s: archive page size %d is below 1", p.SourceName, p.PageSize)
	}
	var cur ArchiveCursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("%s: parse cursor: %w", p.SourceName, err)
		}
	}
	resuming := cur.ResumeAfter != ""
	if resuming && cur.PassStartedAt.IsZero() {
		return nil, fmt.Errorf("%s: cursor resumes after %q but has no pass_started_at", p.SourceName, cur.ResumeAfter)
	}

	// A new pass reads the current archive, never one held from an earlier pass.
	if !resuming {
		if err := p.Close(); err != nil {
			return nil, err
		}
	}
	if p.archive == nil {
		if err := p.download(ctx); err != nil {
			return nil, err
		}
	}

	passStartedAt := p.archive.fetchedAt
	if resuming {
		passStartedAt = cur.PassStartedAt
	}

	entries := p.archive.entries
	i := 0
	if resuming {
		i = sort.Search(len(entries), func(k int) bool { return entries[k].Name > cur.ResumeAfter })
	}

	var patches []CanonicalPatch
	for ; i < len(entries) && len(patches) < p.PageSize; i++ {
		entry := entries[i]
		// The modified time is in the central directory, so skipping costs no I/O.
		if !cur.LastModified.IsZero() && !entry.Modified.After(cur.LastModified) {
			continue
		}
		patch, err := p.Parse(entry)
		if err != nil || patch == nil {
			// Skip malformed or empty entries; do not abort the pass.
			continue
		}
		patches = append(patches, *patch)
	}
	// Keep entries with the same name on one page: the next page starts after the
	// name, so a duplicate left behind would be skipped.
	for ; i > 0 && i < len(entries) && entries[i].Name == entries[i-1].Name; i++ {
		if !cur.LastModified.IsZero() && !entries[i].Modified.After(cur.LastModified) {
			continue
		}
		if patch, err := p.Parse(entries[i]); err == nil && patch != nil {
			patches = append(patches, *patch)
		}
	}

	result := &FetchResult{
		Patches:    patches,
		SourceMeta: SourceMeta{SourceName: p.SourceName, FetchedAt: p.archive.fetchedAt},
	}
	next := ArchiveCursor{LastModified: passStartedAt}
	if i < len(entries) {
		next = ArchiveCursor{
			LastModified:  cur.LastModified,
			PassStartedAt: passStartedAt,
			ResumeAfter:   entries[i-1].Name,
		}
	} else {
		result.LastPage = true
		if err := p.Close(); err != nil {
			return nil, err
		}
	}

	nextJSON, err := json.Marshal(next)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal cursor: %w", p.SourceName, err)
	}
	result.NextCursor = nextJSON
	return result, nil
}

// download fetches the archive to a temp file and indexes its record entries.
func (p *ArchivePager) download(ctx context.Context) error {
	if err := p.RateLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("%s: rate limit: %w", p.SourceName, err)
	}

	// archive/zip needs an io.ReaderAt, so the archive goes to a temp file.
	f, err := DownloadToTemp(ctx, p.Client, p.URL, p.TempPattern, MaxDownloadSize)
	if err != nil {
		return fmt.Errorf("%s: download zip: %w", p.SourceName, err)
	}
	fetchedAt := time.Now().UTC()

	entries, err := p.recordEntries(f)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp
		return err
	}
	p.archive = &downloadedArchive{file: f, entries: entries, fetchedAt: fetchedAt}
	return nil
}

func (p *ArchivePager) recordEntries(f *os.File) ([]*zip.File, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: stat temp file: %w", p.SourceName, err)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: open zip: %w", p.SourceName, err)
	}
	entries := make([]*zip.File, 0, len(zr.File))
	for _, e := range zr.File {
		if p.IsEntry(e.Name) {
			entries = append(entries, e)
		}
	}
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].Name < entries[b].Name })
	return entries, nil
}

// Close removes the downloaded archive, if one is held. It is safe to call more
// than once.
func (p *ArchivePager) Close() error {
	if p.archive == nil {
		return nil
	}
	f := p.archive.file
	p.archive = nil
	closeErr := f.Close()
	removeErr := os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp
	if err := errors.Join(closeErr, removeErr); err != nil {
		return fmt.Errorf("%s: remove downloaded archive: %w", p.SourceName, err)
	}
	return nil
}

// archivePath returns the path of the held archive, or "" when none is held.
func (p *ArchivePager) archivePath() string {
	if p.archive == nil {
		return ""
	}
	return p.archive.file.Name()
}
