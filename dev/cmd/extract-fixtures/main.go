// ABOUTME: Extracts curated test fixtures from captured feed snapshots based on a CVE manifest.
// ABOUTME: Produces per-adapter golden files in internal/feed/<adapter>/testdata/golden/.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Manifest represents the curated CVE selection produced by the selection agent.
type Manifest struct {
	Generated   string           `json:"generated"`
	CaptureDate string           `json:"capture_date"`
	Records     []ManifestRecord `json:"records"`
}

// ManifestRecord identifies a single CVE or advisory to include in the corpus.
type ManifestRecord struct {
	CVEID      string   `json:"cve_id,omitempty"`
	GHSAID     string   `json:"ghsa_id,omitempty"`
	Categories []string `json:"categories"`
	Feeds      []string `json:"feeds"`
	Why        string   `json:"why"`
}

func main() {
	manifestPath := flag.String("manifest", "", "path to test-fixture-manifest.json")
	snapshotsDir := flag.String("snapshots", "", "path to feed-snapshots directory")
	outputDir := flag.String("output", ".", "project root for writing fixtures")
	flag.Parse()

	if *manifestPath == "" || *snapshotsDir == "" {
		fmt.Fprintf(os.Stderr, "Usage: extract-fixtures --manifest PATH --snapshots DIR [--output DIR]\n")
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	manifest, err := loadManifest(*manifestPath)
	if err != nil {
		slog.Error("load manifest", "error", err)
		os.Exit(1)
	}

	// Build lookup sets from manifest.
	cveIDs := make(map[string]bool)
	ghsaIDs := make(map[string]bool)
	for _, r := range manifest.Records {
		if r.CVEID != "" {
			cveIDs[r.CVEID] = true
		}
		if r.GHSAID != "" {
			ghsaIDs[r.GHSAID] = true
		}
	}

	slog.Info("manifest loaded", "cve_count", len(cveIDs), "ghsa_count", len(ghsaIDs))

	extractors := []struct {
		name string
		fn   func(snapshotsDir, outputDir string, cveIDs, ghsaIDs map[string]bool) error
	}{
		{"NVD", extractNVD},
		{"GHSA", extractGHSA},
		{"KEV", extractKEV},
		{"EPSS", extractEPSS},
		{"MITRE", extractMITRE},
		{"OSV", extractOSV},
		{"MSRC", extractMSRC},
		{"RedHat", extractRedHat},
	}

	for _, e := range extractors {
		if err := e.fn(*snapshotsDir, *outputDir, cveIDs, ghsaIDs); err != nil {
			slog.Error("extraction failed", "feed", e.name, "error", err)
			// Continue to next feed.
		}
	}
}

func loadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0755) //nolint:gosec // G301: dev tool data directory
}

// --- NVD Extraction ---

// nvdEnvelope is the NVD API response envelope structure.
type nvdEnvelope struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Format          string            `json:"format"`
	Version         string            `json:"version"`
	Timestamp       string            `json:"timestamp"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

func extractNVD(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	nvdDir := filepath.Join(snapshotsDir, "nvd")
	outDir := filepath.Join(outputDir, "internal", "feed", "nvd", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	bodyFiles, err := filepath.Glob(filepath.Join(nvdDir, "*.body"))
	if err != nil {
		return err
	}
	sort.Strings(bodyFiles)

	var matched []json.RawMessage
	for _, bodyFile := range bodyFiles {
		data, err := os.ReadFile(bodyFile)
		if err != nil {
			slog.Warn("skip NVD body", "file", bodyFile, "error", err)
			continue
		}

		// Parse the NVD response to extract individual vulnerabilities.
		var env nvdEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			slog.Warn("skip NVD body (parse)", "file", bodyFile, "error", err)
			continue
		}

		for _, vuln := range env.Vulnerabilities {
			// Extract the CVE ID from the vulnerability JSON.
			var wrapper struct {
				CVE struct {
					ID string `json:"id"`
				} `json:"cve"`
			}
			if err := json.Unmarshal(vuln, &wrapper); err != nil {
				continue
			}
			if cveIDs[wrapper.CVE.ID] {
				matched = append(matched, vuln)
			}
		}
	}

	if len(matched) == 0 {
		slog.Warn("NVD: no matching CVEs found")
		return nil
	}

	// Create a single synthetic page with all matched CVEs.
	page := nvdEnvelope{
		ResultsPerPage:  len(matched),
		StartIndex:      0,
		TotalResults:    len(matched),
		Format:          "NVD_CVE",
		Version:         "2.0",
		Timestamp:       "2026-03-11T10:00:00.000",
		Vulnerabilities: matched,
	}

	pageJSON, err := json.MarshalIndent(page, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal NVD page: %w", err)
	}

	outPath := filepath.Join(outDir, "page-001.json")
	if err := os.WriteFile(outPath, pageJSON, 0644); err != nil { //nolint:gosec // G306: dev tool output files
		return err
	}

	slog.Info("NVD: extracted", "cves", len(matched), "pages", 1, "output", outPath)
	return nil
}

// --- GHSA Extraction ---

func extractGHSA(snapshotsDir, outputDir string, cveIDs, ghsaIDs map[string]bool) error {
	ghsaDir := filepath.Join(snapshotsDir, "ghsa")
	outDir := filepath.Join(outputDir, "internal", "feed", "ghsa", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	bodyFiles, err := filepath.Glob(filepath.Join(ghsaDir, "*.body"))
	if err != nil {
		return err
	}
	sort.Strings(bodyFiles)

	var matched []json.RawMessage
	for _, bodyFile := range bodyFiles {
		data, err := os.ReadFile(bodyFile)
		if err != nil {
			continue
		}

		// GHSA responses are JSON arrays of advisories.
		var advisories []json.RawMessage
		if err := json.Unmarshal(data, &advisories); err != nil {
			continue
		}

		for _, adv := range advisories {
			var meta struct {
				GHSAID string  `json:"ghsa_id"`
				CVEID  *string `json:"cve_id"`
			}
			if err := json.Unmarshal(adv, &meta); err != nil {
				continue
			}

			// Match on CVE ID or GHSA ID selector.
			if (meta.CVEID != nil && cveIDs[*meta.CVEID]) || ghsaIDs[meta.GHSAID] {
				matched = append(matched, adv)
			}
		}
	}

	if len(matched) == 0 {
		slog.Warn("GHSA: no matching advisories found")
		return nil
	}

	// GHSA adapter expects a JSON array at the top level.
	pageJSON, err := json.MarshalIndent(matched, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal GHSA page: %w", err)
	}

	outPath := filepath.Join(outDir, "page-001.json")
	if err := os.WriteFile(outPath, pageJSON, 0644); err != nil { //nolint:gosec // G306: dev tool output files
		return err
	}

	slog.Info("GHSA: extracted", "advisories", len(matched), "output", outPath)
	return nil
}

// --- KEV Extraction ---

func extractKEV(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	inPath := filepath.Join(snapshotsDir, "kev", "catalog.json")
	outDir := filepath.Join(outputDir, "internal", "feed", "kev", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}

	// Parse the KEV catalog.
	var catalog struct {
		CatalogVersion  string            `json:"catalogVersion"`
		DateReleased    string            `json:"dateReleased"`
		Count           int               `json:"count"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return fmt.Errorf("parse KEV catalog: %w", err)
	}

	var matched []json.RawMessage
	for _, vuln := range catalog.Vulnerabilities {
		var entry struct {
			CveID string `json:"cveID"`
		}
		if err := json.Unmarshal(vuln, &entry); err != nil {
			continue
		}
		if cveIDs[entry.CveID] {
			matched = append(matched, vuln)
		}
	}

	if len(matched) == 0 {
		slog.Warn("KEV: no matching CVEs found")
		return nil
	}

	// Reconstruct the catalog with filtered entries.
	filtered := struct {
		CatalogVersion  string            `json:"catalogVersion"`
		DateReleased    string            `json:"dateReleased"`
		Count           int               `json:"count"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}{
		CatalogVersion:  catalog.CatalogVersion,
		DateReleased:    catalog.DateReleased,
		Count:           len(matched),
		Vulnerabilities: matched,
	}

	outJSON, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal KEV catalog: %w", err)
	}

	outPath := filepath.Join(outDir, "catalog.json")
	if err := os.WriteFile(outPath, outJSON, 0644); err != nil { //nolint:gosec // G306: dev tool output files
		return err
	}

	slog.Info("KEV: extracted", "cves", len(matched), "output", outPath)
	return nil
}

// --- EPSS Extraction ---

func extractEPSS(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	inPath := filepath.Join(snapshotsDir, "epss", "scores.csv")
	outDir := filepath.Join(outputDir, "internal", "feed", "epss", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	f, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only file

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	scanner := bufio.NewScanner(f)
	lineNum := 0
	var extracted int
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Line 1: comment, Line 2: header — always include.
		if lineNum <= 2 {
			_, _ = fmt.Fprintln(gz, line) //nolint:gosec // G705: dev tool writes to local gzip buffer, not HTTP response
			continue
		}

		// Data rows: "CVE-YYYY-NNNN,score,percentile"
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 1 {
			continue
		}
		if cveIDs[parts[0]] {
			_, _ = fmt.Fprintln(gz, line) //nolint:gosec // G705: dev tool writes to local gzip buffer, not HTTP response
			extracted++
		}
	}
	if err := scanner.Err(); err != nil {
		_ = gz.Close()
		return fmt.Errorf("scan EPSS CSV: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	outPath := filepath.Join(outDir, "scores.csv.gz")
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil { //nolint:gosec // G306: dev tool output files
		return err
	}

	slog.Info("EPSS: extracted", "cves", extracted, "output", outPath)
	return nil
}

// --- MITRE Extraction ---

func extractMITRE(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	inPath := filepath.Join(snapshotsDir, "mitre", "cvelistV5.zip")
	outDir := filepath.Join(outputDir, "internal", "feed", "mitre", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return fmt.Errorf("open MITRE ZIP: %w", err)
	}
	defer zr.Close() //nolint:errcheck // read-only zip reader

	// Create output ZIP.
	outPath := filepath.Join(outDir, "cvelistV5.zip")
	outFile, err := os.Create(outPath) //nolint:gosec // G703: dev tool writes to user-specified output dir
	if err != nil {
		return err
	}
	zw := zip.NewWriter(outFile)

	var extracted int
	for _, entry := range zr.File {
		// Match entries by CVE ID in filename.
		name := entry.Name
		matched := false
		for cveID := range cveIDs {
			if strings.Contains(name, cveID) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Copy the matching entry to the output ZIP.
		// Explicit close per iteration (FEED-5: no defer in loops).
		rc, err := entry.Open()
		if err != nil {
			slog.Warn("skip MITRE entry", "name", name, "error", err)
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close() //nolint:errcheck,gosec // explicit close per FEED-5
		if err != nil {
			slog.Warn("skip MITRE entry (read)", "name", name, "error", err)
			continue
		}

		w, err := zw.Create(name)
		if err != nil {
			slog.Warn("skip MITRE entry (write)", "name", name, "error", err)
			continue
		}
		if _, err := w.Write(data); err != nil {
			slog.Warn("skip MITRE entry (write data)", "name", name, "error", err)
			continue
		}
		extracted++
	}

	if err := zw.Close(); err != nil {
		outFile.Close() //nolint:errcheck,gosec // best-effort cleanup on zip write error
		return fmt.Errorf("close MITRE ZIP writer: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close MITRE output file: %w", err)
	}

	slog.Info("MITRE: extracted", "cves", extracted, "output", outPath)
	return nil
}

// --- OSV Extraction ---

func extractOSV(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	inPath := filepath.Join(snapshotsDir, "osv", "all.zip")
	outDir := filepath.Join(outputDir, "internal", "feed", "osv", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return fmt.Errorf("open OSV ZIP: %w", err)
	}
	defer zr.Close() //nolint:errcheck // read-only zip reader

	outPath := filepath.Join(outDir, "all.zip")
	outFile, err := os.Create(outPath) //nolint:gosec // G703: dev tool writes to user-specified output dir
	if err != nil {
		return err
	}
	zw := zip.NewWriter(outFile)

	var extracted int
	for _, entry := range zr.File {
		name := entry.Name

		// Check if filename contains a CVE ID.
		matchedByName := false
		for cveID := range cveIDs {
			if strings.Contains(name, cveID) {
				matchedByName = true
				break
			}
		}

		if matchedByName {
			// Copy directly.
			rc, err := entry.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close() //nolint:errcheck,gosec // explicit close per FEED-5
			if err != nil {
				continue
			}

			w, err := zw.Create(name)
			if err != nil {
				continue
			}
			_, _ = w.Write(data)
			extracted++
			continue
		}

		// Check if the entry's JSON content has a CVE in aliases.
		// Only read small-ish entries to avoid memory issues.
		if entry.UncompressedSize64 > 10<<20 { // skip entries > 10 MB
			continue
		}

		rc, err := entry.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close() //nolint:errcheck,gosec // explicit close per FEED-5
		if err != nil {
			continue
		}

		var osvEntry struct {
			Aliases []string `json:"aliases"`
		}
		if err := json.Unmarshal(data, &osvEntry); err != nil {
			continue
		}

		for _, alias := range osvEntry.Aliases {
			if cveIDs[alias] {
				w, err := zw.Create(name)
				if err != nil {
					break
				}
				_, _ = w.Write(data)
				extracted++
				break
			}
		}
	}

	if err := zw.Close(); err != nil {
		outFile.Close() //nolint:errcheck,gosec // best-effort cleanup on zip write error
		return fmt.Errorf("close OSV ZIP writer: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close OSV output file: %w", err)
	}

	slog.Info("OSV: extracted", "entries", extracted, "output", outPath)
	return nil
}

// --- MSRC Extraction ---

func extractMSRC(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	msrcDir := filepath.Join(snapshotsDir, "msrc")
	outDir := filepath.Join(outputDir, "internal", "feed", "msrc", "testdata", "golden")
	if err := ensureDir(outDir); err != nil {
		return err
	}

	// Read the updates list (first body file — URL contains /updates).
	metaFiles, err := filepath.Glob(filepath.Join(msrcDir, "*.meta.json"))
	if err != nil {
		return err
	}

	var updatesBody string
	for _, metaFile := range metaFiles {
		metaData, err := os.ReadFile(metaFile)
		if err != nil {
			continue
		}
		var meta struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(metaData, &meta); err != nil {
			continue
		}
		if strings.Contains(meta.URL, "/updates") {
			bodyFile := strings.TrimSuffix(metaFile, ".meta.json") + ".body"
			updatesBody = bodyFile
			break
		}
	}

	if updatesBody == "" {
		slog.Warn("MSRC: no updates list found")
		return nil
	}

	// Copy the updates list as-is.
	data, err := os.ReadFile(updatesBody)
	if err != nil {
		return fmt.Errorf("read MSRC updates: %w", err)
	}
	outPath := filepath.Join(outDir, "updates.json")
	if err := os.WriteFile(outPath, data, 0644); err != nil { //nolint:gosec // G306: dev tool output files
		return err
	}

	// Also copy any manually captured CVRF documents that contain manifest CVE IDs.
	csafDir := filepath.Join(outDir, "csaf")
	if err := ensureDir(csafDir); err != nil {
		return err
	}

	cvrfFiles, err := filepath.Glob(filepath.Join(msrcDir, "cvrf-*.json"))
	if err != nil {
		return err
	}

	var csafCount int
	for _, cvrfFile := range cvrfFiles {
		cvrfData, err := os.ReadFile(cvrfFile)
		if err != nil {
			continue
		}

		// Check if this CVRF doc contains any manifest CVE IDs.
		content := string(cvrfData)
		hasMatch := false
		for cveID := range cveIDs {
			if strings.Contains(content, cveID) {
				hasMatch = true
				break
			}
		}
		if !hasMatch {
			continue
		}

		// Extract release ID from filename (e.g., "cvrf-2026-Mar.json" → "2026-Mar").
		base := filepath.Base(cvrfFile)
		releaseID := strings.TrimSuffix(strings.TrimPrefix(base, "cvrf-"), ".json")
		outCSAF := filepath.Join(csafDir, releaseID+".json")
		if err := os.WriteFile(outCSAF, cvrfData, 0644); err != nil { //nolint:gosec // G306: dev tool output files
			slog.Warn("write MSRC CSAF", "error", err)
			continue
		}
		csafCount++
	}

	slog.Info("MSRC: extracted", "updates", 1, "csaf_docs", csafCount, "output", outDir)
	return nil
}

// --- Red Hat Extraction ---

func extractRedHat(snapshotsDir, outputDir string, cveIDs, _ map[string]bool) error {
	rhDir := filepath.Join(snapshotsDir, "redhat")
	outDir := filepath.Join(outputDir, "internal", "feed", "redhat", "testdata", "golden")
	detailDir := filepath.Join(outDir, "detail")
	if err := ensureDir(detailDir); err != nil {
		return err
	}

	metaFiles, err := filepath.Glob(filepath.Join(rhDir, "*.meta.json"))
	if err != nil {
		return err
	}

	// Identify detail pages whose URL contains a manifest CVE ID.
	var detailCount int
	var matchedCVEs []string
	for _, metaFile := range metaFiles {
		metaData, err := os.ReadFile(metaFile)
		if err != nil {
			continue
		}
		var meta struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(metaData, &meta); err != nil {
			continue
		}

		// Detail pages have URLs like /hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json
		if !strings.Contains(meta.URL, "/cve/CVE-") {
			continue
		}

		// Extract CVE ID from URL.
		for cveID := range cveIDs {
			if strings.Contains(meta.URL, cveID) {
				bodyFile := strings.TrimSuffix(metaFile, ".meta.json") + ".body"
				bodyData, err := os.ReadFile(bodyFile)
				if err != nil {
					slog.Warn("skip Red Hat detail", "cve", cveID, "error", err)
					continue
				}

				outPath := filepath.Join(detailDir, cveID+".json")
				if err := os.WriteFile(outPath, bodyData, 0644); err != nil { //nolint:gosec // G306: dev tool output files
					slog.Warn("write Red Hat detail", "cve", cveID, "error", err)
					continue
				}
				matchedCVEs = append(matchedCVEs, cveID)
				detailCount++
				break
			}
		}
	}

	if detailCount == 0 {
		slog.Warn("Red Hat: no matching detail pages found")
		return nil
	}

	// Create a minimal synthetic list page referencing matched CVEs.
	type listEntry struct {
		CVE string `json:"CVE"`
	}
	var listEntries []listEntry
	for _, cveID := range matchedCVEs {
		listEntries = append(listEntries, listEntry{CVE: cveID})
	}

	listJSON, err := json.MarshalIndent(listEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Red Hat list: %w", err)
	}

	outPath := filepath.Join(outDir, "list.json")
	if err := os.WriteFile(outPath, listJSON, 0644); err != nil { //nolint:gosec // G306: dev tool output files
		return err
	}

	slog.Info("Red Hat: extracted", "cves", detailCount, "output", outDir)
	return nil
}
