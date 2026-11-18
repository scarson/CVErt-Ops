// ABOUTME: Tests that the activation scan writes each page's matched events with one store call.
// ABOUTME: Covers the page write's skip of a CVE that late-binding renames after the candidate read.
package alert_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// pageCountingStore counts the activation scan's writes and can run a hook before the
// first page write, after the page's candidates were read.
type pageCountingStore struct {
	store.AlertRuleStore
	beforeFirstPage func()
	once            sync.Once
	pageWrites      atomic.Int32
	eventInserts    atomic.Int32
	eventReopens    atomic.Int32
}

func (s *pageCountingStore) RecordActivationAlertEvents(ctx context.Context, orgID, ruleID uuid.UUID, matches []store.AlertEventMatch) (int64, error) {
	if s.beforeFirstPage != nil {
		s.once.Do(s.beforeFirstPage)
	}
	s.pageWrites.Add(1)
	return s.AlertRuleStore.RecordActivationAlertEvents(ctx, orgID, ruleID, matches)
}

func (s *pageCountingStore) InsertAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error) {
	s.eventInserts.Add(1)
	return s.AlertRuleStore.InsertAlertEvent(ctx, orgID, ruleID, cveID, materialHash, suppressDelivery)
}

func (s *pageCountingStore) ReopenAlertEvent(ctx context.Context, orgID, ruleID uuid.UUID, cveID, materialHash string, suppressDelivery bool) (uuid.UUID, error) {
	s.eventReopens.Add(1)
	return s.AlertRuleStore.ReopenAlertEvent(ctx, orgID, ruleID, cveID, materialHash, suppressDelivery)
}

// newActivatingRule creates a rule in the 'activating' state, as the API does before it
// enqueues the activation job.
func newActivatingRule(t *testing.T, ctx context.Context, st store.AlertRuleStore, orgID uuid.UUID, conditions string) uuid.UUID {
	t.Helper()
	rule := mustRule(t, ctx, st, orgID, "and", conditions, nil)
	if err := st.SetAlertRuleStatus(ctx, orgID, rule.ID, "activating"); err != nil {
		t.Fatalf("set rule activating: %v", err)
	}
	return rule.ID
}

// TestEvaluateActivation_WritesEachPageOnce runs an activation over more than one page
// of CVEs and checks that each page with matches is written by one call, with no
// per-event inserts or reopens.
func TestEvaluateActivation_WritesEachPageOnce(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Two full pages and part of a third, all matching.
	const total = 2*1000 + 5
	if _, err := tdb.DB().ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, cvss_v3_score, material_hash)
		SELECT format('CVE-2099-%s', lpad(i::text, 6, '0')), 'Analyzed', 9.0, 'page-hash-' || i
		FROM generate_series(1, $1) AS i`, total); err != nil {
		t.Fatalf("insert CVEs: %v", err)
	}
	const cvssCond = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	ruleID := newActivatingRule(t, ctx, tdb.Store, orgID, cvssCond)

	st := &pageCountingStore{AlertRuleStore: tdb.Store}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := alert.New(tdb.DB(), st, alert.NewRuleCache(), log, 0)
	if err := ev.EvaluateActivation(ctx, ruleID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	if n := st.pageWrites.Load(); n != 3 {
		t.Errorf("page writes = %d, want 3", n)
	}
	if n, m := st.eventInserts.Load(), st.eventReopens.Load(); n != 0 || m != 0 {
		t.Errorf("per-event inserts = %d, reopens = %d, want 0 of each", n, m)
	}
	var events, suppressed int
	if err := tdb.DB().QueryRowContext(ctx,
		`SELECT count(*), count(*) FILTER (WHERE suppress_delivery AND last_match_state) FROM alert_events WHERE rule_id = $1`,
		ruleID).Scan(&events, &suppressed); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != total || suppressed != total {
		t.Errorf("events = %d (%d open and suppressed), want %d", events, suppressed, total)
	}
	if s := getRuleStatus(t, tdb.DB(), ruleID); s != "active" {
		t.Errorf("rule status = %q, want active", s)
	}
}

// TestEvaluateActivation_SkipsCVERenamedAfterCandidateRead renames a matched CVE between
// the page's candidate read and its write. No event may be recorded under the old ID,
// which no longer exists and so could never resolve.
func TestEvaluateActivation_SkipsCVERenamedAfterCandidateRead(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const native, cve, other = "GHSA-late-activation", "CVE-2026-40101", "CVE-2026-40102"
	for _, id := range []string{native, other} {
		if err := merge.Ingest(ctx, tdb.Store, kevPatch(id, id), "osv"); err != nil {
			t.Fatalf("merge.Ingest %s: %v", id, err)
		}
	}
	orgID := createTestOrg(t, tdb.DB())
	ruleID := newActivatingRule(t, ctx, tdb.AppStore, orgID, kevCondition)

	renamed := false
	st := &pageCountingStore{AlertRuleStore: tdb.AppStore, beforeFirstPage: func() {
		if err := merge.Ingest(ctx, tdb.Store, kevPatch(cve, native), "osv"); err != nil {
			t.Errorf("merge.Ingest (promotion): %v", err)
			return
		}
		renamed = true
	}}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := alert.New(tdb.AppStore.DB(), st, alert.NewRuleCache(), log, 0)
	if err := ev.EvaluateActivation(ctx, ruleID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	if !renamed {
		t.Fatal("the activation scan never wrote a page, so the rename did not run")
	}
	if n := countAlertEvents(t, tdb.DB(), ruleID, native); n != 0 {
		t.Errorf("%d events recorded under a renamed CVE", n)
	}
	if n := countAlertEvents(t, tdb.DB(), ruleID, other); n != 1 {
		t.Errorf("%d events for %s, which was not renamed, want 1", n, other)
	}
}

// TestEvaluateActivation_PageWriteFailureFailsActivation checks that a failed page
// write puts the rule in 'error' rather than activating it with a partial baseline.
func TestEvaluateActivation_PageWriteFailureFailsActivation(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	score := 9.0
	insertCVE(t, tdb.DB(), "CVE-2099-7001", "Analyzed", "page failure", &score, "page-fail-hash")
	const cvssCond = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	ruleID := newActivatingRule(t, ctx, tdb.Store, orgID, cvssCond)

	st := &failingPageStore{AlertRuleStore: tdb.Store}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := alert.New(tdb.DB(), st, alert.NewRuleCache(), log, 0)
	err := ev.EvaluateActivation(ctx, ruleID, orgID)
	if err == nil {
		t.Fatal("EvaluateActivation succeeded although the page write failed")
	}
	if want := "simulated page failure"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err, want)
	}
	if s := getRuleStatus(t, tdb.DB(), ruleID); s != "error" {
		t.Errorf("rule status = %q, want error", s)
	}
}

// failingPageStore fails every activation page write.
type failingPageStore struct {
	store.AlertRuleStore
}

func (s *failingPageStore) RecordActivationAlertEvents(context.Context, uuid.UUID, uuid.UUID, []store.AlertEventMatch) (int64, error) {
	return 0, errors.New("simulated page failure")
}
