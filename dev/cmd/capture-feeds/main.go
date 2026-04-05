// ABOUTME: Dev CLI to capture raw HTTP responses from all feed sources.
// ABOUTME: Saves responses to a configurable directory for offline test fixture generation.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/ghsa"
	"github.com/scarson/cvert-ops/internal/feed/msrc"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/feed/redhat"
)

// defaultDataDir is the default location for captured feed snapshots.
// Override with --output flag.
const defaultDataDir = ".data/feed-snapshots"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: capture-feeds <feed|all> [--output DIR]\n")
		fmt.Fprintf(os.Stderr, "Feeds: nvd, mitre, ghsa, osv, kev, epss, msrc, redhat, all\n")
		fmt.Fprintf(os.Stderr, "Default output: %s\n", defaultDataDir)
		os.Exit(1)
	}

	feedName := os.Args[1]
	outDir := defaultDataDir
	for i, arg := range os.Args {
		if arg == "--output" && i+1 < len(os.Args) {
			outDir = os.Args[i+1]
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	feeds := []string{feedName}
	if feedName == "all" {
		// Order: single-file feeds first (fast), then paginated feeds (slow).
		feeds = []string{"kev", "epss", "mitre", "osv", "ghsa", "msrc", "redhat", "nvd"}
	}

	for _, f := range feeds {
		if err := captureFeed(ctx, f, outDir); err != nil {
			slog.Error("capture failed", "feed", f, "error", err) //nolint:gosec // G706: dev tool logging, not user-facing
			// Continue to next feed — don't abort entire run.
		}
	}
}

func captureFeed(ctx context.Context, feedName, baseDir string) error {
	feedDir := filepath.Join(baseDir, feedName)
	if err := os.MkdirAll(feedDir, 0755); err != nil { //nolint:gosec // G301: dev tool data directory
		return fmt.Errorf("mkdir %s: %w", feedDir, err)
	}

	switch feedName {
	case "kev":
		return captureDirectDownload(ctx, feedDir,
			"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			"catalog.json")
	case "epss":
		return captureDirectDownload(ctx, feedDir,
			"https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
			"scores.csv.gz")
	case "mitre":
		return captureDirectDownload(ctx, feedDir,
			"https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip",
			"cvelistV5.zip")
	case "osv":
		return captureDirectDownload(ctx, feedDir,
			"https://osv-vulnerabilities.storage.googleapis.com/all.zip",
			"all.zip")
	case "nvd":
		return captureWithAdapter(ctx, feedDir, nvd.New(recordingClient(feedDir)))
	case "ghsa":
		return captureWithAdapter(ctx, feedDir, ghsa.New(recordingClient(feedDir)))
	case "msrc":
		return captureWithAdapter(ctx, feedDir, msrc.New(recordingClient(feedDir)))
	case "redhat":
		return captureWithAdapter(ctx, feedDir, redhat.New(recordingClient(feedDir)))
	default:
		return fmt.Errorf("unknown feed: %s", feedName)
	}
}

// recordingClient returns an HTTP client with a recording transport that saves
// all request/response pairs to the given directory.
func recordingClient(outDir string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &RecordingTransport{
			Inner:  http.DefaultTransport,
			OutDir: outDir,
		},
	}
}

// captureDirectDownload fetches a single URL and saves it to disk.
func captureDirectDownload(ctx context.Context, dir, url, filename string) error {
	slog.Info("downloading", "url", url, "dest", filepath.Join(dir, filename)) //nolint:gosec // G706: dev tool logging, not user-facing
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", feed.DefaultUserAgent)

	client := &http.Client{Timeout: 30 * time.Minute} // ZIP files can be large
	resp, err := client.Do(req)                       //nolint:gosec // G704: capture tool intentionally fetches external URLs
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response body

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	outPath := filepath.Join(dir, filename)
	f, err := os.Create(outPath) //nolint:gosec // G703: dev tool writes to user-specified output dir
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // best-effort close after io.Copy

	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	slog.Info("downloaded", "file", outPath, "bytes", n, "elapsed", time.Since(start).Round(time.Second)) //nolint:gosec // G706: dev tool logging, not user-facing
	return nil
}

// captureWithAdapter runs a feed.Adapter with a recording transport, paginating
// until LastPage. All HTTP responses are saved to disk by the transport.
func captureWithAdapter(ctx context.Context, dir string, adapter feed.Adapter) error {
	slog.Info("capturing with adapter", "dir", dir) //nolint:gosec // G706: dev tool logging, not user-facing
	start := time.Now()
	var totalPatches, totalPages int

	var cursor json.RawMessage // nil = first page
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		result, err := adapter.Fetch(ctx, cursor)
		if err != nil {
			return fmt.Errorf("fetch page %d: %w", totalPages+1, err)
		}

		totalPages++
		totalPatches += len(result.Patches)
		slog.Info("fetched page", //nolint:gosec // G706: dev tool logging, not user-facing
			"page", totalPages,
			"patches", len(result.Patches),
			"total_patches", totalPatches,
			"last_page", result.LastPage,
		)

		cursor = result.NextCursor
		if result.LastPage {
			break
		}
	}

	slog.Info("capture complete", //nolint:gosec // G706: dev tool logging, not user-facing
		"dir", dir,
		"pages", totalPages,
		"patches", totalPatches,
		"elapsed", time.Since(start).Round(time.Second),
	)
	return nil
}
