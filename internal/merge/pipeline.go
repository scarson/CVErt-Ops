package merge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sqlc-dev/pqtype"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// Ingest merges a single source patch into the canonical CVE corpus.
// It executes all steps within a single database/sql transaction protected by
// a per-CVE advisory lock (PLAN.md §D4).
//
// Steps (within the advisory-locked transaction):
//  1. pg_advisory_xact_lock — serializes concurrent writes for the same CVE
//  2. Upsert cve_sources — store normalized source data (IS DISTINCT FROM guard)
//  3. Insert cve_raw_payloads — store original payload for audit/debugging
//  4. Read all cve_sources → resolve() — compute canonical field values
//  5. Compute material_hash — detect material changes
//  6. Upsert cves — update canonical row (IS DISTINCT FROM guard on hash)
//  7. Tombstone — NULL out CVSS/EPSS/KEV if status is rejected/withdrawn
//  8. Delete + re-insert child tables — references, packages, CPEs
//  9. Apply staged EPSS — drain epss_staging for this CVE (always delete)
//  10. Upsert FTS index — update cve_search_index (IS DISTINCT FROM guard)
func Ingest(
	ctx context.Context,
	s *store.Store,
	patch feed.CanonicalPatch,
	sourceName string,
	rawPayload json.RawMessage,
) error {
	// Serialize and sanitize normalized patch for cve_sources.normalized_json.
	normalizedJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("merge: marshal patch: %w", err)
	}
	// Strip null bytes — Postgres TEXT/JSONB rejects \x00 (pitfall §2.10).
	normalizedJSON = bytes.ReplaceAll(normalizedJSON, []byte{0}, []byte{})
	if rawPayload != nil {
		rawPayload = bytes.ReplaceAll(rawPayload, []byte{0}, []byte{})
	}

	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("merge: begin tx: %w", err)
	}
	// Rollback is a no-op after Commit; always safe to defer.
	defer func() { _ = tx.Rollback() }()

	// Step 1: per-CVE advisory lock — serializes all writers for this CVE.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", CVEAdvisoryKey(patch.CVEID)); err != nil {
		return fmt.Errorf("merge: advisory lock: %w", err)
	}

	// Bind sqlc queries to this transaction.
	q := generated.New(tx)

	// Step 2: upsert cve_sources. IS DISTINCT FROM guard in SQL prevents TOAST
	// bloat for unchanged normalized_json.
	if err := q.UpsertCVESource(ctx, generated.UpsertCVESourceParams{
		CveID:              patch.CVEID,
		SourceName:         sourceName,
		SourceID:           toNullString(patch.SourceID),
		NormalizedJson:     normalizedJSON,
		SourceDateModified: toNullTimePtr(patch.DateModified),
		SourceUrl:          sql.NullString{}, // not available in CanonicalPatch
	}); err != nil {
		return fmt.Errorf("merge: upsert cve_sources: %w", err)
	}

	// Step 3: insert raw payload for audit / debugging (best-effort; skip if nil).
	if rawPayload != nil {
		if err := q.InsertCVERawPayload(ctx, generated.InsertCVERawPayloadParams{
			CveID:      patch.CVEID,
			SourceName: sourceName,
			Payload:    rawPayload,
		}); err != nil {
			return fmt.Errorf("merge: insert raw payload: %w", err)
		}
	}

	// Step 4: read all sources and resolve canonical field values.
	sources, err := q.GetAllCVESources(ctx, patch.CVEID)
	if err != nil {
		return fmt.Errorf("merge: get cve sources: %w", err)
	}
	resolved, err := resolve(sources)
	if err != nil {
		return fmt.Errorf("merge: resolve sources: %w", err)
	}

	// Step 5: compute material_hash.
	materialHash := ComputeMaterialHash(MaterialFields{
		Status:       resolved.Status,
		Severity:     resolved.Severity,
		CVSSv3Score:  resolved.CVSSv3Score,
		CVSSv3Vector: resolved.CVSSv3Vector,
		CVSSv4Score:  resolved.CVSSv4Score,
		CVSSv4Vector: resolved.CVSSv4Vector,
		CWEIDs:       resolved.CWEIDs,
		ExploitAvail: resolved.ExploitAvailable,
		InCISAKEV:    resolved.InCISAKEV,
		AffectedPkgs: buildAffectedPkgKeys(resolved.AffectedPackages),
		AffectedCPEs: buildCPEStrings(resolved.AffectedCPEs),
	})

	// Ensure slices are non-nil so pq.Array sends "[]" not "null".
	cweIDs := resolved.CWEIDs
	if cweIDs == nil {
		cweIDs = []string{}
	}

	// Step 6: upsert cves. IS DISTINCT FROM guard on material_hash means
	// date_modified_canonical is only bumped on actual material changes.
	if err := q.UpsertCVE(ctx, generated.UpsertCVEParams{
		CveID:                 patch.CVEID,
		Status:                toNullString(resolved.Status),
		DatePublished:         toNullTimePtr(resolved.DatePublished),
		DateModifiedSourceMax: toNullTimePtr(resolved.DateModifiedSourceMax),
		DateModifiedCanonical: time.Now().UTC(),
		DescriptionPrimary:    toNullStringPtr(resolved.DescriptionPrimary),
		Severity:              toNullString(resolved.Severity),
		CvssV3Score:           toNullFloat64(resolved.CVSSv3Score),
		CvssV3Vector:          toNullString(resolved.CVSSv3Vector),
		CvssV3Source:          toNullString(resolved.CVSSv3Source),
		CvssV4Score:           toNullFloat64(resolved.CVSSv4Score),
		CvssV4Vector:          toNullString(resolved.CVSSv4Vector),
		CvssV4Source:          toNullString(resolved.CVSSv4Source),
		CvssScoreDiverges:     resolved.CVSSScoreDiverges,
		CweIds:                cweIDs,
		ExploitAvailable:      resolved.ExploitAvailable,
		InCisaKev:             resolved.InCISAKEV,
		MaterialHash:          sql.NullString{String: materialHash, Valid: true},
	}); err != nil {
		return fmt.Errorf("merge: upsert cves: %w", err)
	}

	// Step 7: tombstone — NULL out sensitive fields for rejected/withdrawn CVEs.
	if resolved.IsWithdrawn {
		if err := q.TombstoneCVE(ctx, patch.CVEID); err != nil {
			return fmt.Errorf("merge: tombstone: %w", err)
		}
	}

	// Step 8: delete + re-insert child tables.
	// References — deduplicated by url_canonical via ON CONFLICT DO NOTHING.
	if err := q.DeleteCVEReferences(ctx, patch.CVEID); err != nil {
		return fmt.Errorf("merge: delete references: %w", err)
	}
	for _, ref := range resolved.References {
		tags := ref.Tags
		if tags == nil {
			tags = []string{}
		}
		if err := q.InsertCVEReference(ctx, generated.InsertCVEReferenceParams{
			CveID:        patch.CVEID,
			Url:          ref.URL,
			UrlCanonical: ref.URLCanonical,
			Tags:         tags,
		}); err != nil {
			return fmt.Errorf("merge: insert reference: %w", err)
		}
	}

	// Affected packages.
	if err := q.DeleteCVEAffectedPackages(ctx, patch.CVEID); err != nil {
		return fmt.Errorf("merge: delete affected packages: %w", err)
	}
	for _, pkg := range resolved.AffectedPackages {
		if err := q.InsertAffectedPackage(ctx, generated.InsertAffectedPackageParams{
			CveID:        patch.CVEID,
			Ecosystem:    pkg.Ecosystem,
			PackageName:  pkg.PackageName,
			Namespace:    toNullString(pkg.Namespace),
			RangeType:    toNullString(pkg.RangeType),
			Introduced:   toNullString(pkg.Introduced),
			Fixed:        toNullString(pkg.Fixed),
			LastAffected: toNullString(pkg.LastAffected),
			Events:       toNullRawMessage(pkg.Events),
		}); err != nil {
			return fmt.Errorf("merge: insert affected package: %w", err)
		}
	}

	// Affected CPEs — deduplicated by cpe_normalized via ON CONFLICT DO NOTHING.
	if err := q.DeleteCVEAffectedCPEs(ctx, patch.CVEID); err != nil {
		return fmt.Errorf("merge: delete affected CPEs: %w", err)
	}
	for _, cpe := range resolved.AffectedCPEs {
		if err := q.InsertAffectedCPE(ctx, generated.InsertAffectedCPEParams{
			CveID:         patch.CVEID,
			Cpe:           cpe.CPE,
			CpeNormalized: cpe.CPENormalized,
		}); err != nil {
			return fmt.Errorf("merge: insert affected CPE: %w", err)
		}
	}

	// Step 9: apply staged EPSS. The staging row is always deleted regardless
	// of whether a score was found — prevents stale accumulation (pitfall §2.7).
	staging, err := q.GetEPSSStaging(ctx, patch.CVEID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("merge: get EPSS staging: %w", err)
	}
	if err == nil {
		// Score in staging: apply to cves. IS DISTINCT FROM guard prevents
		// dead tuples if score happens to match the current value.
		if err := q.UpdateCVEEPSS(ctx, generated.UpdateCVEEPSSParams{
			CveID:     patch.CVEID,
			EpssScore: sql.NullFloat64{Float64: staging.EpssScore, Valid: true},
		}); err != nil {
			return fmt.Errorf("merge: apply staged EPSS: %w", err)
		}
	}
	// Always drain staging entry — even on sql.ErrNoRows (no-op DELETE is fine).
	if err := q.DeleteEPSSStaging(ctx, patch.CVEID); err != nil {
		return fmt.Errorf("merge: delete EPSS staging: %w", err)
	}

	// Step 10: update FTS index. IS DISTINCT FROM guard in SQL prevents writing
	// when tsvector content hasn't changed (e.g., only timestamps/scores changed).
	pkgNames := collectPackageNames(resolved.AffectedPackages)
	if err := q.UpsertCVESearchIndex(ctx, generated.UpsertCVESearchIndexParams{
		CveID:        patch.CVEID,
		Description:  derefString(resolved.DescriptionPrimary),
		CweNames:     strings.Join(resolved.CWEIDs, " "),
		PackageNames: strings.Join(pkgNames, " "),
	}); err != nil {
		return fmt.Errorf("merge: upsert search index: %w", err)
	}

	return tx.Commit()
}

// --- sql.Null* conversion helpers ---

func toNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func toNullStringPtr(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func toNullFloat64(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}

func toNullTimePtr(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func toNullRawMessage(msg json.RawMessage) pqtype.NullRawMessage {
	if msg == nil {
		return pqtype.NullRawMessage{}
	}
	return pqtype.NullRawMessage{RawMessage: msg, Valid: true}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- material_hash helper types ---

// buildAffectedPkgKeys converts resolved packages to the minimal key form
// used in material_hash computation.
func buildAffectedPkgKeys(pkgs []feed.AffectedPackage) []affectedPkgKey {
	keys := make([]affectedPkgKey, 0, len(pkgs))
	for _, p := range pkgs {
		keys = append(keys, affectedPkgKey{
			Ecosystem:   p.Ecosystem,
			PackageName: p.PackageName,
			Introduced:  p.Introduced,
			Fixed:       p.Fixed,
		})
	}
	return keys
}

// buildCPEStrings extracts the normalized CPE strings for material_hash.
func buildCPEStrings(cpes []feed.AffectedCPE) []string {
	out := make([]string, 0, len(cpes))
	for _, c := range cpes {
		out = append(out, c.CPENormalized)
	}
	return out
}

// collectPackageNames extracts unique package names for FTS indexing.
func collectPackageNames(pkgs []feed.AffectedPackage) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, p := range pkgs {
		if _, ok := seen[p.PackageName]; !ok {
			seen[p.PackageName] = struct{}{}
			names = append(names, p.PackageName)
		}
	}
	return names
}
