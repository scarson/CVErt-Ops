// ABOUTME: Integration tests for match_inputs_hash and date_match_inputs_changed written by the merge pipeline.
// ABOUTME: A CNA-only change stamps the re-check date without moving material_hash; unchanged and case-only re-ingests do not.
package merge_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// recheckState is the part of a cves row the re-check signal reads and writes.
type recheckState struct {
	materialHash      string
	matchInputsHash   sql.NullString
	dateModified      time.Time
	dateInputsChanged sql.NullTime
}

func readRecheckState(t *testing.T, s *testutil.TestDB, cveID string) recheckState {
	t.Helper()
	var st recheckState
	if err := s.DB().QueryRowContext(context.Background(), `
		SELECT material_hash, match_inputs_hash, date_modified_canonical, date_match_inputs_changed
		FROM cves WHERE cve_id = $1`, cveID).Scan(
		&st.materialHash, &st.matchInputsHash, &st.dateModified, &st.dateInputsChanged); err != nil {
		t.Fatalf("read cves row %s: %v", cveID, err)
	}
	return st
}

// recheckStamp is a fixed date_match_inputs_changed set before a re-ingest. The
// merge stamps with Go's clock and the test reads with the database's, and two
// clock readings from different transactions are not ordered, so a test can only
// observe whether the merge replaced this value.
var recheckStamp = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func setRecheckStamp(t *testing.T, s *testutil.TestDB, cveID string) {
	t.Helper()
	if _, err := s.DB().ExecContext(context.Background(),
		`UPDATE cves SET date_match_inputs_changed = $2 WHERE cve_id = $1`, cveID, recheckStamp); err != nil {
		t.Fatalf("set re-check stamp: %v", err)
	}
}

func stampKept(st recheckState) bool {
	return st.dateInputsChanged.Valid && st.dateInputsChanged.Time.Equal(recheckStamp)
}

func ingestOrFatal(t *testing.T, s *testutil.TestDB, patch feed.CanonicalPatch, source string) {
	t.Helper()
	if err := merge.Ingest(context.Background(), s.Store, patch, source); err != nil {
		t.Fatalf("Ingest %s: %v", source, err)
	}
}

func TestIngest_MatchInputsRecheckSignal(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveID = "CVE-2024-99960"
	sev := "HIGH"
	mitre := feed.CanonicalPatch{
		CVEID:       cveID,
		Status:      "published",
		Severity:    &sev,
		CNAAffected: []feed.CNAAffected{{Vendor: "nodejs", Product: "n/a"}},
	}

	// A new CVE: both dates come from the one clock value the insert binds.
	ingestOrFatal(t, s, mitre, "mitre")
	first := readRecheckState(t, s, cveID)
	if !first.matchInputsHash.Valid || first.matchInputsHash.String == "" {
		t.Fatal("match_inputs_hash not set after the first ingest")
	}
	if !first.dateInputsChanged.Valid || !first.dateInputsChanged.Time.Equal(first.dateModified) {
		t.Fatalf("date_match_inputs_changed = %v, want date_modified_canonical %v", first.dateInputsChanged, first.dateModified)
	}

	t.Run("CNA product change alone", func(t *testing.T) {
		setRecheckStamp(t, s, cveID)
		before := readRecheckState(t, s, cveID)
		mitre.CNAAffected = []feed.CNAAffected{{Vendor: "nodejs", Product: "Node.js"}}
		ingestOrFatal(t, s, mitre, "mitre")
		after := readRecheckState(t, s, cveID)

		if after.materialHash != before.materialHash {
			t.Errorf("material_hash moved: %s -> %s", before.materialHash, after.materialHash)
		}
		if !after.dateModified.Equal(before.dateModified) {
			t.Errorf("date_modified_canonical moved: %v -> %v", before.dateModified, after.dateModified)
		}
		if after.matchInputsHash == before.matchInputsHash {
			t.Errorf("match_inputs_hash unchanged (%s), want a new hash", after.matchInputsHash.String)
		}
		if !after.dateInputsChanged.Valid || stampKept(after) {
			t.Errorf("date_match_inputs_changed = %v, want a new merge stamp", after.dateInputsChanged)
		}
	})

	t.Run("unchanged re-ingest", func(t *testing.T) {
		setRecheckStamp(t, s, cveID)
		before := readRecheckState(t, s, cveID)
		ingestOrFatal(t, s, mitre, "mitre")
		after := readRecheckState(t, s, cveID)

		if after.matchInputsHash != before.matchInputsHash {
			t.Errorf("match_inputs_hash moved on an unchanged re-ingest: %s -> %s", before.matchInputsHash.String, after.matchInputsHash.String)
		}
		if !stampKept(after) {
			t.Errorf("date_match_inputs_changed = %v, want exactly %v", after.dateInputsChanged, recheckStamp)
		}
	})

	t.Run("NVD relay differing only in ASCII case", func(t *testing.T) {
		setRecheckStamp(t, s, cveID)
		before := readRecheckState(t, s, cveID)
		nvd := feed.CanonicalPatch{
			CVEID:       cveID,
			Status:      "published",
			CNAAffected: []feed.CNAAffected{{Vendor: "NodeJS", Product: "node.js"}},
		}
		ingestOrFatal(t, s, nvd, "nvd")
		after := readRecheckState(t, s, cveID)

		if n := countRows(t, s, "cve_cna_affected", cveID); n != 2 {
			t.Fatalf("cve_cna_affected has %d rows, want both copies (2)", n)
		}
		if after.matchInputsHash != before.matchInputsHash {
			t.Errorf("a case-only copy moved match_inputs_hash: %s -> %s", before.matchInputsHash.String, after.matchInputsHash.String)
		}
		if !stampKept(after) {
			t.Errorf("date_match_inputs_changed = %v, want exactly %v", after.dateInputsChanged, recheckStamp)
		}
	})

	t.Run("stored NULL hash is stamped once", func(t *testing.T) {
		setRecheckStamp(t, s, cveID)
		before := readRecheckState(t, s, cveID)
		// A column on an existing row, as a CVE merged before the column existed has.
		if _, err := s.DB().ExecContext(ctx, `UPDATE cves SET match_inputs_hash = NULL WHERE cve_id = $1`, cveID); err != nil {
			t.Fatalf("clear match_inputs_hash: %v", err)
		}
		ingestOrFatal(t, s, mitre, "mitre")
		after := readRecheckState(t, s, cveID)

		if after.matchInputsHash != before.matchInputsHash {
			t.Errorf("match_inputs_hash after the NULL merge = %v, want the inputs' hash %s", after.matchInputsHash, before.matchInputsHash.String)
		}
		if !after.dateInputsChanged.Valid || stampKept(after) {
			t.Errorf("date_match_inputs_changed = %v, want a new merge stamp", after.dateInputsChanged)
		}
		if !after.dateModified.Equal(before.dateModified) || after.materialHash != before.materialHash {
			t.Errorf("material state moved: %s at %v -> %s at %v", before.materialHash, before.dateModified, after.materialHash, after.dateModified)
		}

		// Once: the next merge of the same inputs leaves the stamp alone.
		setRecheckStamp(t, s, cveID)
		ingestOrFatal(t, s, mitre, "mitre")
		if again := readRecheckState(t, s, cveID); !stampKept(again) {
			t.Errorf("second merge after NULL: date_match_inputs_changed = %v, want exactly %v", again.dateInputsChanged, recheckStamp)
		}
	})
}
