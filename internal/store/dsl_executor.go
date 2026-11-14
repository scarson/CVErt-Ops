// ABOUTME: Executes compiled DSL rules against the CVE corpus with keyset pagination.
// ABOUTME: Shared by NL search and saved search execution.
package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// cveColumns is the canonical column list for the cves table, matching the
// physical column order in migration 000002. All dynamic CVE queries
// (SearchCVEs, ExecuteDSLQuery) MUST use this slice to stay synchronized
// with scanCVERow.
var cveColumns = []string{
	"cves.cve_id",
	"cves.status",
	"cves.date_published",
	"cves.date_modified_source_max",
	"cves.date_modified_canonical",
	"cves.date_first_seen",
	"cves.description_primary",
	"cves.severity",
	"cves.cvss_v3_score",
	"cves.cvss_v3_vector",
	"cves.cvss_v3_source",
	"cves.cvss_v4_score",
	"cves.cvss_v4_vector",
	"cves.cvss_v4_source",
	"cves.cvss_score_diverges",
	"cves.cwe_ids",
	"cves.exploit_available",
	"cves.in_cisa_kev",
	"cves.epss_score",
	"cves.date_epss_updated",
	"cves.material_hash",
}

// scanCVERow scans a single row into a generated.CVE. The column order must
// match cveColumns exactly.
func scanCVERow(rows *sql.Rows) (generated.CVE, error) {
	var c generated.CVE
	if err := rows.Scan(
		&c.CveID,
		&c.Status,
		&c.DatePublished,
		&c.DateModifiedSourceMax,
		&c.DateModifiedCanonical,
		&c.DateFirstSeen,
		&c.DescriptionPrimary,
		&c.Severity,
		&c.CvssV3Score,
		&c.CvssV3Vector,
		&c.CvssV3Source,
		&c.CvssV4Score,
		&c.CvssV4Vector,
		&c.CvssV4Source,
		&c.CvssScoreDiverges,
		pq.Array(&c.CweIds),
		&c.ExploitAvailable,
		&c.InCisaKev,
		&c.EpssScore,
		&c.DateEpssUpdated,
		&c.MaterialHash,
	); err != nil {
		return c, err
	}
	return c, nil
}

// dslCursor is the keyset pagination cursor for DSL query results.
type dslCursor struct {
	SortDate time.Time `json:"d"`
	CVEID    string    `json:"c"`
}

// encodeDSLCursor encodes a cursor as URL-safe base64 JSON.
func encodeDSLCursor(c dslCursor) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode cursor: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// decodeDSLCursor decodes a base64 JSON cursor. Returns zero-value cursor and
// nil error for empty input.
func decodeDSLCursor(s string) (dslCursor, error) {
	if s == "" {
		return dslCursor{}, nil
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return dslCursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	var c dslCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return dslCursor{}, fmt.Errorf("unmarshal cursor: %w", err)
	}
	return c, nil
}

// ExecuteDSLQuery runs a compiled DSL rule against the CVE corpus with keyset
// pagination. Returns matching CVEs, a cursor for the next page (empty string
// if no more results), and any error.
//
// The query runs in a read-only transaction under dsl.RuleQuerySettings, as
// the alert evaluator runs a rule's candidate query. The cves table is global
// (no org_id, no RLS). However, compiled rules with watchlist conditions
// reference the org-scoped watchlist_items table via EXISTS subqueries, so
// those transactions also bypass RLS.
// PostFilters (regex conditions) are applied in-process after the SQL query.
func (s *Store) ExecuteDSLQuery(ctx context.Context, compiled *dsl.CompiledRule, cursor string, limit int) ([]generated.CVE, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}

	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	sb := psql.Select(cveColumns...).From("cves")

	// Apply optional JOINs from the compiled rule (e.g., FTS cve_search_index).
	for _, j := range compiled.Joins {
		sb = sb.Join(j)
	}

	// Apply the compiled WHERE clause. Saved and AI searches have no candidate IDs.
	if where := compiled.Where(nil); where != nil {
		sb = sb.Where(where)
	}

	// Filter out rejected and withdrawn CVEs (§10 alert evaluation). COALESCE keeps
	// CVEs with no status: NULL NOT IN (...) is NULL, which drops the row.
	sb = sb.Where("COALESCE(lower(cves.status), '') NOT IN ('rejected', 'withdrawn')")

	// Keyset cursor: WHERE (date_modified_canonical, cve_id) < (last_date, last_id).
	cur, err := decodeDSLCursor(cursor)
	if err != nil {
		return nil, "", fmt.Errorf("store: dsl query cursor: %w", err)
	}
	if !cur.SortDate.IsZero() && cur.CVEID != "" {
		sb = sb.Where(
			"(cves.date_modified_canonical, cves.cve_id) < (?, ?)",
			cur.SortDate, cur.CVEID,
		)
	}

	sb = sb.
		OrderBy("cves.date_modified_canonical DESC, cves.cve_id DESC").
		Limit(uint64(limit + 1)) //nolint:gosec // G115: limit is clamped to 1-100 above

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, "", fmt.Errorf("store: build dsl query: %w", err)
	}

	results, err := s.queryDSLRows(ctx, compiled.HasWatchlist, query, args)
	if err != nil {
		return nil, "", err
	}

	// Save pre-filter state for pagination. The pagination decision must use the
	// pre-filter row count because PostFilters can remove rows after SQL fetch.
	preFetchCount := len(results)

	// Save the last pre-filter row's cursor position BEFORE filtering overwrites results.
	// Needed when PostFilters remove all visible rows but more pages exist.
	var preFetchCursorRow generated.CVE
	if preFetchCount > limit {
		preFetchCursorRow = results[limit-1]
	}

	// Apply in-process PostFilters (regex conditions) to SQL results.
	if len(compiled.PostFilters) > 0 {
		wrapped := make([]cvePostFilterTarget, len(results))
		for i := range results {
			wrapped[i] = cvePostFilterTarget{&results[i]}
		}
		filtered := dsl.ApplyPostFilters(wrapped, compiled.PostFilters, compiled.Logic)
		results = make([]generated.CVE, len(filtered))
		for i := range filtered {
			results[i] = *filtered[i].cve
		}
	}

	// If the pre-filter fetch returned limit+1 rows, there is a next page.
	var nextCursor string
	if preFetchCount > limit {
		// Trim post-filtered results to at most limit entries.
		if len(results) > limit {
			results = results[:limit]
		}
		// Use the last visible row for cursor when we have post-filter results,
		// otherwise fall back to the pre-filter cursor position so the client
		// can advance past this empty page.
		cursorSource := preFetchCursorRow
		if len(results) > 0 {
			cursorSource = results[len(results)-1]
		}
		nextCursor, err = encodeDSLCursor(dslCursor{
			SortDate: cursorSource.DateModifiedCanonical,
			CVEID:    cursorSource.CveID,
		})
		if err != nil {
			return nil, "", err
		}
	}

	return results, nextCursor, nil
}

// queryDSLRows runs a compiled rule's query in a read-only transaction under
// dsl.RuleQuerySettings and scans every row. bypassRLS is for rules with
// watchlist subqueries: they read the org-scoped watchlist_items table (has
// RLS), whose org_id the compiled SQL already embeds, without app.org_id set.
func (s *Store) queryDSLRows(ctx context.Context, bypassRLS bool, query string, args []interface{}) ([]generated.CVE, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store: begin dsl query tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is safe after commit
	if bypassRLS {
		if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
			return nil, fmt.Errorf("store: set bypass_rls: %w", err)
		}
	}
	if err := dsl.PrepareRuleQueryTx(ctx, tx); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	results, err := scanDSLRows(ctx, tx, query, args)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit dsl query tx: %w", err)
	}
	return results, nil
}

// scanDSLRows executes a query in tx and scans all rows.
func scanDSLRows(ctx context.Context, tx *sql.Tx, query string, args []interface{}) ([]generated.CVE, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: execute dsl query: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var results []generated.CVE
	for rows.Next() {
		c, scanErr := scanCVERow(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("store: scan dsl query row: %w", scanErr)
		}
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: dsl query rows error: %w", err)
	}
	return results, nil
}

// cvePostFilterTarget wraps generated.CVE to implement dsl.PostFilterTarget.
type cvePostFilterTarget struct {
	cve *generated.CVE
}

// PostFilterField implements dsl.PostFilterTarget for generated.CVE. Values are
// matched as stored: regex PostFilters ignore case unless their pattern turns
// that off, as in the alert evaluator.
func (c cvePostFilterTarget) PostFilterField(field string) string {
	if field == "cve_id" {
		return c.cve.CveID
	}
	return c.cve.DescriptionPrimary.String
}
