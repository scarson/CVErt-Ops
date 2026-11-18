// ABOUTME: Pages a downloaded ZIP archive in entry-name order, so reading it can span several worker jobs.
// ABOUTME: Used by the OSV adapter for a first backfill; a later job resumes after the last entry name read.
package feed

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"

	"golang.org/x/time/rate"
)

// ArchivePageSize is the number of patches in one archive page. A page is the
// unit the feed handler checkpoints, and at the roughly 13 CVEs per second seen
// on a real backfill it merges in about 80 seconds, well inside the handler's
// page reserve.
const ArchivePageSize = 1000

// ArchivePager downloads a ZIP archive and returns its record entries in pages,
// in entry-name order. Within one job the downloaded archive is kept between
// pages; a later job downloads the current archive and continues after the last
// entry name read. Names, not positions, identify where to continue, because the
// upstream archive may have changed between jobs.
//
// The pager removes the downloaded archive when the last page is read; Close
// removes it when a job ends part-way through. An ArchivePager is not safe for
// concurrent use.
type ArchivePager struct {
	Client      *http.Client
	RateLimiter *rate.Limiter
	URL         string
	// TempPattern is the os.CreateTemp pattern for the downloaded archive.
	TempPattern string
	// SourceName prefixes errors.
	SourceName string
	PageSize   int
	// IsEntry reports whether an archive entry holds a record.
	IsEntry func(name string) bool
	// Parse reads one entry. An error or nil patch skips the entry.
	Parse func(entry *zip.File) (*CanonicalPatch, error)

	archive *downloadedArchive
}

// ArchivePage is one page of an archive.
type ArchivePage struct {
	Patches []CanonicalPatch
	// Last is the name of the last entry this page read; the next page resumes
	// after it.
	Last string
	// Done reports that no entries remain after this page.
	Done bool
}

// downloadedArchive is an archive held between the pages of one job.
type downloadedArchive struct {
	file    *os.File
	entries []*zip.File // record entries, sorted by name
}

// Page returns the next page of record entries whose names sort after
// resumeAfter. An empty resumeAfter starts a new read on a fresh download.
func (p *ArchivePager) Page(ctx context.Context, resumeAfter string) (*ArchivePage, error) {
	if p.PageSize < 1 {
		return nil, fmt.Errorf("%s: archive page size %d is below 1", p.SourceName, p.PageSize)
	}
	// A new read uses the current archive, never one held from an earlier read.
	if resumeAfter == "" {
		if err := p.Close(); err != nil {
			return nil, err
		}
	}
	if p.archive == nil {
		if err := p.download(ctx); err != nil {
			return nil, err
		}
	}

	entries := p.archive.entries
	i := sort.Search(len(entries), func(k int) bool { return entries[k].Name > resumeAfter })

	page := &ArchivePage{Last: resumeAfter}
	for ; i < len(entries) && len(page.Patches) < p.PageSize; i++ {
		page.add(p.Parse(entries[i]))
	}
	// Keep entries with the same name on one page: the next page starts after the
	// name, so a duplicate left behind would be skipped.
	for ; i > 0 && i < len(entries) && entries[i].Name == entries[i-1].Name; i++ {
		page.add(p.Parse(entries[i]))
	}
	if i > 0 {
		page.Last = entries[i-1].Name
	}

	if i >= len(entries) {
		page.Done = true
		if err := p.Close(); err != nil {
			return nil, err
		}
	}
	return page, nil
}

// add appends a parsed entry, skipping malformed or empty ones so one bad entry
// does not abort the read.
func (page *ArchivePage) add(patch *CanonicalPatch, err error) {
	if err != nil || patch == nil {
		return
	}
	page.Patches = append(page.Patches, *patch)
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
	entries, err := p.recordEntries(f)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name()) //nolint:gosec // G703: path from os.CreateTemp
		return err
	}
	p.archive = &downloadedArchive{file: f, entries: entries}
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
