// ABOUTME: Integration test for the ingest handler that verifies data reaches the database.
// ABOUTME: Uses a real Postgres testcontainer and real merge.Ingest to test the full handler→merge→DB path.
package ingest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/ingest"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// singlePatchAdapter returns one known patch on the first call, signaling last page.
type singlePatchAdapter struct {
	patch feed.CanonicalPatch
}

func (a *singlePatchAdapter) Fetch(_ context.Context, _ json.RawMessage) (*feed.FetchResult, error) {
	return &feed.FetchResult{
		Patches: []feed.CanonicalPatch{a.patch},
		SourceMeta: feed.SourceMeta{
			SourceName: "nvd",
			FetchedAt:  time.Now().UTC(),
		},
		NextCursor: json.RawMessage(`{"done":true}`),
		LastPage:   true,
	}, nil
}

func TestHandler_Integration_DataReachesDB(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	desc := "A test vulnerability for integration testing"
	sev := "HIGH"
	patch := feed.CanonicalPatch{
		CVEID:              "CVE-2024-88801",
		Status:             "published",
		DescriptionPrimary: &desc,
		Severity:           &sev,
	}

	adapter := &singlePatchAdapter{patch: patch}
	factory := func(_ string, _ *http.Client) (feed.Adapter, error) {
		return adapter, nil
	}

	handler := ingest.HandlerWithFactory(tdb.Store, nil, merge.Ingest, factory)

	payload, err := json.Marshal(ingest.Payload{FeedName: "nvd"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	err = handler(ctx, payload)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	// Verify the CVE was persisted to the database.
	cve, err := tdb.GetCVE(ctx, "CVE-2024-88801")
	if err != nil {
		t.Fatalf("GetCVE: %v", err)
	}
	if cve == nil {
		t.Fatal("CVE not found in database after handler execution")
	}
	if !cve.DescriptionPrimary.Valid || cve.DescriptionPrimary.String != desc {
		t.Errorf("description = %q, want %q", cve.DescriptionPrimary.String, desc)
	}
	if !cve.Severity.Valid || cve.Severity.String != sev {
		t.Errorf("severity = %q, want %q", cve.Severity.String, sev)
	}
	if !cve.MaterialHash.Valid || cve.MaterialHash.String == "" {
		t.Error("material_hash should be non-empty after merge")
	}

	// Verify the sync cursor advanced (non-nil after successful run).
	state, err := tdb.GetFeedSyncState(ctx, "nvd")
	if err != nil {
		t.Fatalf("GetFeedSyncState: %v", err)
	}
	if state == nil {
		t.Fatal("feed sync state not found after handler execution")
	}
	if state.CursorJSON == nil {
		t.Error("cursor should be non-nil after successful handler run")
	}
	if state.LastSuccessAt == nil {
		t.Error("last_success_at should be set after successful handler run")
	}
	if state.ConsecutiveFailures != 0 {
		t.Errorf("consecutive_failures = %d, want 0", state.ConsecutiveFailures)
	}
}
