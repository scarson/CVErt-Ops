// ABOUTME: Reads what a version check needs in one read-only snapshot: candidate rows, CVE enrichment and feed state.
// ABOUTME: One statement per data source, bounded per key; the request's row and byte limits are counted as rows arrive.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// ErrCandidateLimit is returned when one version check request reads more rows,
// or more bytes of row data, than its limit. A partial read cannot say which
// items lost rows, so nothing is answered from it.
var ErrCandidateLimit = errors.New("version check candidate rows exceed the request limit")

// checkLimits bounds what one version check reads (design section 9).
type checkLimits struct {
	KeyRows      int // rows kept for one key; a key with more has Overflow set
	RequestRows  int // rows read over every statement
	RequestBytes int // bytes of string fields and versions JSON read over every statement
}

// defaultCheckLimits is the limits ReadCheckCandidates applies.
var defaultCheckLimits = checkLimits{KeyRows: 50_000, RequestRows: 200_000, RequestBytes: 128 << 20}

// checkFeeds are the feeds check.FeedStatuses reports on.
var checkFeeds = []string{"ghsa", "nvd", "osv"}

// cpeIndexExpr is the expression cve_cpe_matches_check_idx indexes, on column.
// The C collation lets a range on a CPE prefix use the index whatever the
// database collation.
func cpeIndexExpr(column string) string {
	return column + ` COLLATE "C"`
}

// cnaNameIndexExpr is one of the expressions cve_cna_affected_check_idx indexes,
// on column (vendor or product): its first 256 characters, lower-cased, which
// check.Keys cuts its CNA names to match.
func cnaNameIndexExpr(column string) string {
	return "left(lower(" + column + `), 256) COLLATE "C"`
}

// The version check lookups. Each joins unnest of its keys to its table through
// CROSS JOIN LATERAL, so each key is read by one index scan under a LIMIT, and
// returns the key's 1-based position first. Its last parameter is that LIMIT.
// Rows of rejected and withdrawn CVEs are read, with their status, so the
// response can count them. The join to cves is a LEFT JOIN because the LIMIT
// runs before it: a row with no cves row (cve_affected_packages has no foreign
// key to cves) must still be returned and counted, or a key over its limit
// could look complete.
var (
	checkPackagesSQL = `
SELECT k.ord, p.cve_id, p.ecosystem, p.package_name, COALESCE(p.range_type, ''), COALESCE(p.introduced, ''),
       COALESCE(p.fixed, ''), COALESCE(p.last_affected, ''), COALESCE(c.status, '')
FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS k(eco, name, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_affected_packages q
  WHERE q.ecosystem = k.eco AND ` + ecosystem.FoldedNameSQL("q.ecosystem", "q.package_name") + ` = k.name
  LIMIT $3
) p
LEFT JOIN cves c ON c.cve_id = p.cve_id`

	checkCPESQL = `
SELECT k.ord, m.cve_id, m.cpe_normalized, COALESCE(m.version_start_including, ''), COALESCE(m.version_start_excluding, ''),
       COALESCE(m.version_end_including, ''), COALESCE(m.version_end_excluding, ''), COALESCE(c.status, '')
FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS k(lo, hi, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cpe_matches q
  WHERE ` + cpeIndexExpr("q.cpe_normalized") + ` >= k.lo COLLATE "C"
    AND ` + cpeIndexExpr("q.cpe_normalized") + ` <  k.hi COLLATE "C"
    AND q.vulnerable
  LIMIT $3
) m
LEFT JOIN cves c ON c.cve_id = m.cve_id`

	// The index holds 256 characters of each name, so the whole vendor and
	// product are rechecked; full_product is empty for a prefix key.
	checkCNANamesSQL = `
SELECT k.ord, a.cve_id, COALESCE(a.vendor, ''), COALESCE(a.product, ''), a.versions, COALESCE(c.status, '')
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) WITH ORDINALITY
     AS k(v, lo, hi, full_vendor, full_product, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cna_affected q
  WHERE ` + cnaNameIndexExpr("q.vendor") + ` = k.v COLLATE "C"
    AND ` + cnaNameIndexExpr("q.product") + ` >= k.lo COLLATE "C"
    AND ` + cnaNameIndexExpr("q.product") + ` <  k.hi COLLATE "C"
    AND lower(q.vendor) = k.full_vendor
    AND (k.full_product = '' OR lower(q.product) = k.full_product)
  LIMIT $6
) a
LEFT JOIN cves c ON c.cve_id = a.cve_id`

	checkCNAPackageKeysSQL = `
SELECT k.ord, a.cve_id, a.versions, COALESCE(c.status, '')
FROM unnest($1::text[]) WITH ORDINALITY AS k(key, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cna_affected q WHERE q.package_key = k.key LIMIT $2
) a
LEFT JOIN cves c ON c.cve_id = a.cve_id`

	// CNA rows under the vendor whose product contains the fragment, on CVEs
	// with no cve_cpe_matches row for the item's own CPE vendor.
	checkCNANearSQL = `
SELECT k.ord, a.cve_id, COALESCE(a.vendor, ''), COALESCE(a.product, ''), COALESCE(c.status, '')
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) WITH ORDINALITY
     AS k(v, full_vendor, frag, vendor_lo, vendor_hi, ord)
CROSS JOIN LATERAL (
  SELECT q.cve_id, q.vendor, q.product FROM cve_cna_affected q
  WHERE ` + cnaNameIndexExpr("q.vendor") + ` = k.v COLLATE "C"
    AND lower(q.vendor) = k.full_vendor
    AND strpos(lower(q.product), k.frag) > 0
    AND NOT EXISTS (
      SELECT 1 FROM cve_cpe_matches m
      WHERE m.cve_id = q.cve_id
        AND ` + cpeIndexExpr("m.cpe_normalized") + ` >= k.vendor_lo COLLATE "C"
        AND ` + cpeIndexExpr("m.cpe_normalized") + ` <  k.vendor_hi COLLATE "C"
    )
  LIMIT $6
) a
LEFT JOIN cves c ON c.cve_id = a.cve_id`

	checkEnrichmentSQL = `
SELECT cve_id, severity, cvss_v3_score, in_cisa_kev, epss_score FROM cves WHERE cve_id = ANY($1::text[])`

	checkFeedsSQL = `
SELECT feed_name, cursor_json, last_success_at FROM feed_sync_state WHERE feed_name = ANY($1::text[])`
)

// ReadCheckCandidates reads, in one read-only REPEATABLE READ snapshot, the rows
// for every key, the severity and exploit data of every advisory read and of
// the CVEs each names (check.CVEIDsFor), and the feed rows of ghsa, nvd and osv.
// Candidates holds one KeyRows per key, in the order of keys. It returns
// ErrCandidateLimit when the request reads more than its limits allow.
func (s *Store) ReadCheckCandidates(ctx context.Context, orgID uuid.UUID, keys check.Keys) (
	check.Candidates, map[string]check.CVEEnrichment, []check.FeedRow, error) {
	return s.readCheckCandidates(ctx, orgID, keys, defaultCheckLimits, nil)
}

// readCheckCandidates is ReadCheckCandidates with the given limits. When
// afterStatement is non-nil it is called with each statement's name after that
// statement has run; a lookup with no keys is not run.
func (s *Store) readCheckCandidates(ctx context.Context, orgID uuid.UUID, keys check.Keys, limits checkLimits,
	afterStatement func(name string)) (check.Candidates, map[string]check.CVEEnrichment, []check.FeedRow, error) {
	cands := check.Candidates{
		Packages:       make([]check.KeyRows[check.PackageRow], len(keys.Packages)),
		CPEs:           make([]check.KeyRows[check.CPERow], len(keys.CPEPrefixes)),
		CNANames:       make([]check.KeyRows[check.CNARow], len(keys.CNANames)),
		CNAPackageKeys: make([]check.KeyRows[check.CNARow], len(keys.CNAPackageKeys)),
		CNANear:        make([]check.KeyRows[check.CNANearRow], len(keys.CNANear)),
	}
	var (
		enrichment map[string]check.CVEEnrichment
		feeds      []check.FeedRow
	)
	err := s.withOrgSnapshotTx(ctx, orgID, func(tx *sql.Tx) error {
		r := &checkRead{tx: tx, limits: limits, after: afterStatement, advisories: map[string]bool{}}
		if err := r.lookups(ctx, keys, cands); err != nil {
			return err
		}
		var err error
		if enrichment, err = r.enrichment(ctx); err != nil {
			return err
		}
		feeds, err = r.feeds(ctx)
		return err
	})
	if err != nil {
		return check.Candidates{}, nil, nil, fmt.Errorf("read check candidates: %w", err)
	}
	return cands, enrichment, feeds, nil
}

// checkRead is one version check read in progress: its transaction, its
// limits, the totals counted so far and the advisory IDs kept.
type checkRead struct {
	tx         *sql.Tx
	limits     checkLimits
	after      func(name string)
	rows       int
	bytes      int
	advisories map[string]bool
}

// lookups runs the five lookups, filling each key's slot in cands.
func (r *checkRead) lookups(ctx context.Context, keys check.Keys, cands check.Candidates) error {
	limit := r.limits.KeyRows + 1

	ecos, names := make([]string, len(keys.Packages)), make([]string, len(keys.Packages))
	for i, k := range keys.Packages {
		ecos[i], names[i] = k.Ecosystem, k.Name
	}
	err := readKeyRows(ctx, r, "packages", checkPackagesSQL, []any{pq.Array(ecos), pq.Array(names), limit}, cands.Packages,
		func(rows *sql.Rows) (s scanned[check.PackageRow], err error) {
			p := &s.row
			err = rows.Scan(&s.ord, &p.CVEID, &p.Ecosystem, &p.PackageName, &p.RangeType, &p.Introduced, &p.Fixed,
				&p.LastAffected, &p.Status)
			s.cveID, s.size = p.CVEID, byteLen(p.CVEID, p.Ecosystem, p.PackageName, p.RangeType, p.Introduced, p.Fixed,
				p.LastAffected, p.Status)
			return s, err
		})
	if err != nil {
		return err
	}

	los, his := make([]string, len(keys.CPEPrefixes)), make([]string, len(keys.CPEPrefixes))
	for i, k := range keys.CPEPrefixes {
		los[i], his[i] = k.Lo, k.Hi
	}
	err = readKeyRows(ctx, r, "cpe", checkCPESQL, []any{pq.Array(los), pq.Array(his), limit}, cands.CPEs,
		func(rows *sql.Rows) (s scanned[check.CPERow], err error) {
			m := &s.row
			err = rows.Scan(&s.ord, &m.CVEID, &m.CPE, &m.VersionStartIncluding, &m.VersionStartExcluding,
				&m.VersionEndIncluding, &m.VersionEndExcluding, &m.Status)
			s.cveID, s.size = m.CVEID, byteLen(m.CVEID, m.CPE, m.VersionStartIncluding, m.VersionStartExcluding,
				m.VersionEndIncluding, m.VersionEndExcluding, m.Status)
			return s, err
		})
	if err != nil {
		return err
	}

	n := len(keys.CNANames)
	vs, nameLos, nameHis := make([]string, n), make([]string, n), make([]string, n)
	fullVendors, fullProducts := make([]string, n), make([]string, n)
	for i, k := range keys.CNANames {
		vs[i], nameLos[i], nameHis[i], fullVendors[i], fullProducts[i] = k.V, k.Lo, k.Hi, k.FullVendor, k.FullProduct
	}
	err = readKeyRows(ctx, r, "cna_names", checkCNANamesSQL,
		[]any{pq.Array(vs), pq.Array(nameLos), pq.Array(nameHis), pq.Array(fullVendors), pq.Array(fullProducts), limit},
		cands.CNANames,
		func(rows *sql.Rows) (s scanned[check.CNARow], err error) {
			a := &s.row
			var versions []byte
			if err = rows.Scan(&s.ord, &a.CVEID, &a.Vendor, &a.Product, &versions, &a.Status); err != nil {
				return s, err
			}
			s.cveID, s.size = a.CVEID, byteLen(a.CVEID, a.Vendor, a.Product, a.Status)+len(versions)
			a.Versions, err = decodeCNAVersions(a.CVEID, versions)
			return s, err
		})
	if err != nil {
		return err
	}

	err = readKeyRows(ctx, r, "cna_package_keys", checkCNAPackageKeysSQL, []any{pq.Array(keys.CNAPackageKeys), limit},
		cands.CNAPackageKeys,
		func(rows *sql.Rows) (s scanned[check.CNARow], err error) {
			a := &s.row
			var versions []byte
			if err = rows.Scan(&s.ord, &a.CVEID, &versions, &a.Status); err != nil {
				return s, err
			}
			s.cveID, s.size = a.CVEID, byteLen(a.CVEID, a.Status)+len(versions)
			a.Versions, err = decodeCNAVersions(a.CVEID, versions)
			return s, err
		})
	if err != nil {
		return err
	}

	n = len(keys.CNANear)
	nearVs, nearVendors, frags := make([]string, n), make([]string, n), make([]string, n)
	vendorLos, vendorHis := make([]string, n), make([]string, n)
	for i, k := range keys.CNANear {
		nearVs[i], nearVendors[i], frags[i], vendorLos[i], vendorHis[i] = k.V, k.FullVendor, k.Fragment, k.VendorLo, k.VendorHi
	}
	return readKeyRows(ctx, r, "cna_near", checkCNANearSQL,
		[]any{pq.Array(nearVs), pq.Array(nearVendors), pq.Array(frags), pq.Array(vendorLos), pq.Array(vendorHis), limit},
		cands.CNANear,
		func(rows *sql.Rows) (s scanned[check.CNANearRow], err error) {
			a := &s.row
			err = rows.Scan(&s.ord, &a.CVEID, &a.Vendor, &a.Product, &a.Status)
			s.cveID, s.size = a.CVEID, byteLen(a.CVEID, a.Vendor, a.Product, a.Status)
			return s, err
		})
}

// scanned is one lookup row with the 1-based position of its key, its advisory
// ID, and its size: the bytes of its string fields and of any versions JSON.
type scanned[T any] struct {
	ord   int64
	row   T
	cveID string
	size  int
}

// readKeyRows runs one lookup and adds each row to its key's slot in out. A slot
// keeps at most limits.KeyRows rows; a further row sets its Overflow. Every row
// read counts towards the request's limits. A lookup with no keys is not run.
//
// The statement runs under its own context, cancelled before its rows are closed
// on any early return (the request's limits passed, or a row that cannot be
// read), so the driver stops the statement rather than reading its remaining
// rows.
func readKeyRows[T any](ctx context.Context, r *checkRead, name, query string, args []any, out []check.KeyRows[T],
	scan func(*sql.Rows) (scanned[T], error)) error {
	if len(out) == 0 {
		return nil
	}
	stmtCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	rows, err := r.tx.QueryContext(stmtCtx, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer rows.Close() //nolint:errcheck // closed explicitly below; this covers early returns
	defer cancel()     // runs before the deferred Close
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := r.count(s.size); err != nil {
			return err
		}
		if s.ord < 1 || s.ord > int64(len(out)) {
			return fmt.Errorf("%s: key position %d outside %d keys", name, s.ord, len(out))
		}
		slot := &out[s.ord-1]
		if len(slot.Rows) >= r.limits.KeyRows {
			slot.Overflow = true
			continue
		}
		slot.Rows = append(slot.Rows, s.row)
		r.advisories[s.cveID] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	r.ran(name)
	return nil
}

// count adds one row of size bytes to the request's totals, and returns
// ErrCandidateLimit once either total passes its limit.
func (r *checkRead) count(size int) error {
	r.rows++
	r.bytes += size
	if r.rows > r.limits.RequestRows {
		return fmt.Errorf("%w: more than %d rows", ErrCandidateLimit, r.limits.RequestRows)
	}
	if r.bytes > r.limits.RequestBytes {
		return fmt.Errorf("%w: more than %d bytes", ErrCandidateLimit, r.limits.RequestBytes)
	}
	return nil
}

// ran reports that statement name has run.
func (r *checkRead) ran(name string) {
	if r.after != nil {
		r.after(name)
	}
}

// enrichment reads the cves row of every advisory kept and of every CVE each
// names, keyed by cve_id. It reads nothing when no advisory was kept.
func (r *checkRead) enrichment(ctx context.Context) (map[string]check.CVEEnrichment, error) {
	ids := map[string]bool{}
	for id := range r.advisories {
		ids[id] = true
		for _, cve := range check.CVEIDsFor(id) {
			ids[cve] = true
		}
	}
	enrichment := make(map[string]check.CVEEnrichment, len(ids))
	if len(ids) == 0 {
		return enrichment, nil
	}
	rows, err := r.tx.QueryContext(ctx, checkEnrichmentSQL, pq.Array(slices.Sorted(maps.Keys(ids))))
	if err != nil {
		return nil, fmt.Errorf("enrichment: %w", err)
	}
	defer rows.Close() //nolint:errcheck // closed explicitly below; this covers early returns
	for rows.Next() {
		var (
			id       string
			severity sql.NullString
			cvss     sql.NullFloat64
			e        check.CVEEnrichment
			epss     sql.NullFloat64
		)
		if err := rows.Scan(&id, &severity, &cvss, &e.InCISAKEV, &epss); err != nil {
			return nil, fmt.Errorf("enrichment: %w", err)
		}
		if severity.Valid {
			e.Severity = &severity.String
		}
		if cvss.Valid {
			e.CVSSv3Score = &cvss.Float64
		}
		if epss.Valid {
			e.EPSSScore = &epss.Float64
		}
		enrichment[id] = e
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("enrichment: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("enrichment: %w", err)
	}
	r.ran("enrichment")
	return enrichment, nil
}

// feeds reads the feed_sync_state rows of the feeds a version check depends on.
// A feed with no row is absent.
func (r *checkRead) feeds(ctx context.Context) ([]check.FeedRow, error) {
	rows, err := r.tx.QueryContext(ctx, checkFeedsSQL, pq.Array(checkFeeds))
	if err != nil {
		return nil, fmt.Errorf("feeds: %w", err)
	}
	defer rows.Close() //nolint:errcheck // closed explicitly below; this covers early returns
	var feeds []check.FeedRow
	for rows.Next() {
		var (
			f           check.FeedRow
			lastSuccess sql.NullTime
		)
		if err := rows.Scan(&f.Name, &f.CursorJSON, &lastSuccess); err != nil {
			return nil, fmt.Errorf("feeds: %w", err)
		}
		if lastSuccess.Valid {
			f.LastSuccessAt = &lastSuccess.Time
		}
		feeds = append(feeds, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feeds: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("feeds: %w", err)
	}
	r.ran("feeds")
	return feeds, nil
}

// decodeCNAVersions decodes one cve_cna_affected versions array.
func decodeCNAVersions(cveID string, raw []byte) ([]check.CNAVersion, error) {
	var versions []check.CNAVersion
	if err := json.Unmarshal(raw, &versions); err != nil {
		return nil, fmt.Errorf("decode CNA versions of %s: %w", cveID, err)
	}
	return versions, nil
}

// byteLen returns the total length in bytes of fields.
func byteLen(fields ...string) int {
	n := 0
	for _, f := range fields {
		n += len(f)
	}
	return n
}
