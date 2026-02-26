// Package epss implements the EPSS (Exploit Prediction Scoring System) enrichment
// adapter. Unlike CVE feed adapters, this package does NOT implement feed.Adapter —
// it writes directly to the database via the two-statement IS DISTINCT FROM pattern
// described in PLAN.md §5.3.
//
// EPSS is published daily by FIRST.org at https://epss.empiricalsecurity.com/ as a
// gzip-compressed CSV file containing ~250,000 scored CVEs. The adapter downloads
// the file, parses the score_date from the comment on line 1, and applies each score
// inside an advisory-locked per-row transaction that coordinates with the CVE merge
// pipeline to prevent TOCTOU races (PLAN.md §5.3).
//
// CSV format (live-verified 2026-02-25):
//
//	Line 1: "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z"  (comment)
//	Line 2: "cve,epss,percentile"                                           (header)
//	Line 3+: "CVE-1999-0001,0.01025,0.76951"                               (data)
//
// score_date is a full RFC3339 timestamp, NOT a plain date string.
//
// Cursor format: {"score_date":"2026-02-25T12:55:00Z","model_version":"v2025.03.14"}
// The adapter skips the download when the cursor's score_date (date component, UTC)
// matches today's date — the file is published once daily.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

const (
	// SourceName is the canonical feed name stored in feed_sync_state.
	SourceName = "epss"

	// feedURL is the canonical EPSS endpoint. The server follows HTTP 302 to
	// the dated file (epss_scores-YYYY-MM-DD.csv.gz); Go's HTTP client resolves
	// the redirect automatically. The old domain epss.cyentia.com redirects
	// HTTP 301 to this domain; use the canonical URL directly (verified 2026-02-25).
	feedURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// Cursor is the JSON-serializable sync state for the EPSS adapter.
type Cursor struct {
	// ScoreDate is the full RFC3339 timestamp from the CSV line-1 comment,
	// e.g. "2026-02-25T12:55:00Z". The date component is compared against today
	// to decide whether to skip the download.
	ScoreDate string `json:"score_date,omitempty"`

	// ModelVersion is the EPSS model version string from line 1,
	// e.g. "v2025.03.14". A change triggers a slog.Warn because all scores
	// shift non-incrementally when the model is updated.
	ModelVersion string `json:"model_version,omitempty"`
}

// Adapter downloads and applies EPSS scores to the canonical CVE corpus.
// It does NOT implement feed.Adapter — call Apply for each sync cycle.
type Adapter struct {
	client      *http.Client
	rateLimiter *rate.Limiter
}

// New creates an EPSS adapter. Pass nil to use http.DefaultClient.
// The adapter is rate-limited to one download per 24 hours.
func New(client *http.Client) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	// One file per day; 24h limiter enforces that at the adapter level even if the
	// scheduler fires early.
	return &Adapter{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(24*time.Hour), 1),
	}
}

// Apply downloads the EPSS CSV and applies each score to the database.
//
// Download is skipped when the cursor's score_date (UTC date component) matches
// today — the file is published once daily, roughly 12:00–14:00 UTC. When a
// download does occur, each of the ~250,000 rows is applied inside its own
// advisory-locked transaction coordinating with the merge pipeline (PLAN.md §5.3).
//
// IMPORTANT: Do not inspect RowsAffected from either DB statement. Both the
// IS DISTINCT FROM guard (Statement 1) and the WHERE NOT EXISTS guard (Statement 2)
// are evaluated DB-side. Branching on RowsAffected causes scoring thrash — see
// PLAN.md §5.3 for the full explanation.
//
// Returns the updated cursor JSON for the caller to persist in feed_sync_state.
func (a *Adapter) Apply(ctx context.Context, s *store.Store, cursorJSON json.RawMessage) (json.RawMessage, error) {
	var cur Cursor
	if len(cursorJSON) > 0 {
		if err := json.Unmarshal(cursorJSON, &cur); err != nil {
			return nil, fmt.Errorf("epss: parse cursor: %w", err)
		}
	}

	// Short-circuit: skip download if today's file has already been processed.
	if cur.ScoreDate != "" {
		curDate := feed.ParseTime(cur.ScoreDate)
		if !curDate.IsZero() {
			today := time.Now().UTC().Truncate(24 * time.Hour)
			if curDate.UTC().Truncate(24 * time.Hour).Equal(today) {
				return cursorJSON, nil
			}
		}
	}

	if err := a.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("epss: rate limit: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("epss: build request: %w", err)
	}
	req.Header.Set("User-Agent", "CVErt-Ops/1.0 vulnerability intelligence platform")

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is a hardcoded constant
	if err != nil {
		return nil, fmt.Errorf("epss: fetch: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: HTTP %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("epss: gzip reader: %w", err)
	}
	defer gz.Close() //nolint:errcheck

	// bufio.Reader maintains its position within the gzip reader. We read line 1
	// (the comment) manually, then hand the same reader to csv.NewReader for the
	// remaining lines — the csv package will see line 2 onward.
	br := bufio.NewReader(gz)

	// Line 1: "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z"
	line1, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("epss: read line 1: %w", err)
	}

	newCursor, err := parseLine1(line1)
	if err != nil {
		return nil, fmt.Errorf("epss: parse line 1: %w", err)
	}

	// Warn when the model version changes — all ~250k scores shift together, not
	// incrementally. Analysts may want to know why alert thresholds behave differently.
	if cur.ModelVersion != "" && cur.ModelVersion != newCursor.ModelVersion {
		slog.WarnContext(ctx, "epss: model version changed; all scores have shifted non-incrementally",
			"prev_version", cur.ModelVersion,
			"new_version", newCursor.ModelVersion,
		)
	}

	asOfDate := feed.ParseTime(newCursor.ScoreDate)
	if asOfDate.IsZero() {
		return nil, fmt.Errorf("epss: unparseable score_date %q", newCursor.ScoreDate)
	}

	// The csv.NewReader wraps the same bufio.Reader, now positioned at line 2.
	// Discard line 2 ("cve,epss,percentile") — it is the CSV header, not data.
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = 3 // cve, epss, percentile
	cr.ReuseRecord = true  // reuses backing slice; clone fields before next Read

	if _, err := cr.Read(); err != nil {
		return nil, fmt.Errorf("epss: read csv header: %w", err)
	}

	db := s.DB()
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("epss: read csv row: %w", err)
		}

		// Clone fields before the next cr.Read() overwrites the ReuseRecord buffer.
		cveID := strings.Clone(feed.StripNullBytes(record[0]))
		if cveID == "" {
			continue
		}

		score, parseErr := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		if parseErr != nil {
			slog.WarnContext(ctx, "epss: skip row with unparseable score",
				"cve_id", cveID,
				"score_raw", record[1],
				"err", parseErr,
			)
			continue
		}

		if err := applyRow(ctx, db, cveID, score, asOfDate); err != nil {
			return nil, fmt.Errorf("epss: apply row %q: %w", cveID, err)
		}
	}

	nextCursorJSON, err := json.Marshal(newCursor)
	if err != nil {
		return nil, fmt.Errorf("epss: marshal cursor: %w", err)
	}

	return nextCursorJSON, nil
}

// applyRow executes the two-statement EPSS pattern for a single CVE inside an
// advisory-locked transaction. Both statements run unconditionally — do NOT
// inspect RowsAffected (PLAN.md §5.3).
//
// Advisory lock key matches the merge pipeline exactly (merge.CVEAdvisoryKey),
// preventing the TOCTOU race where a concurrent CVE ingest inserts a row after
// Statement 1 runs but before Statement 2 can write to epss_staging.
func applyRow(ctx context.Context, db *sql.DB, cveID string, score float64, asOfDate time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is a no-op after Commit; always safe to defer.
	defer func() { _ = tx.Rollback() }()

	// Advisory lock: same key as the merge pipeline (PLAN.md §5.3). Prevents the
	// TOCTOU race between concurrent EPSS and CVE ingest workers.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", merge.CVEAdvisoryKey(cveID)); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}

	q := generated.New(tx)

	// Statement 1: update cves.epss_score if the CVE exists AND score changed.
	// IS DISTINCT FROM handles NULL-safe comparison; no-op when score is unchanged.
	if err := q.UpdateCVEEPSS(ctx, generated.UpdateCVEEPSSParams{
		CveID:     cveID,
		EpssScore: sql.NullFloat64{Float64: score, Valid: true},
	}); err != nil {
		return fmt.Errorf("update cve epss: %w", err)
	}

	// Statement 2: insert into epss_staging if CVE does not yet exist in cves.
	// WHERE NOT EXISTS is evaluated atomically DB-side within this transaction.
	// The ON CONFLICT guard prevents duplicate staging rows from accumulating.
	if err := q.UpsertEPSSStaging(ctx, generated.UpsertEPSSStagingParams{
		Column1: cveID,
		Column2: score,
		Column3: asOfDate,
	}); err != nil {
		return fmt.Errorf("upsert epss staging: %w", err)
	}

	return tx.Commit()
}

// parseLine1 extracts model_version and score_date from the EPSS CSV comment line.
//
// Input format: "#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z\n"
// score_date is a full RFC3339 timestamp with time component — NOT a plain date.
// SplitN(part, ":", 2) splits on the first colon only, so the colons inside the
// RFC3339 timestamp ("T12:55:00Z") are preserved in kv[1].
func parseLine1(line string) (Cursor, error) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	var cur Cursor
	for _, part := range strings.Split(line, ",") {
		// SplitN with n=2: splits on the first ':' only — safe for RFC3339 values.
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "model_version":
			cur.ModelVersion = strings.Clone(kv[1])
		case "score_date":
			cur.ScoreDate = strings.Clone(kv[1])
		}
	}
	if cur.ScoreDate == "" {
		return cur, fmt.Errorf("score_date not found in line 1 %q", line)
	}
	return cur, nil
}
