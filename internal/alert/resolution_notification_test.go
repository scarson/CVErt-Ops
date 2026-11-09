// ABOUTME: Integration tests that a CVE falling out of a rule sends one resolution notification.
// ABOUTME: Runs the real merge pipeline, evaluator and dispatcher, and asserts on delivery rows.
package alert_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	highScoreCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	noMatchReason      = "CVE no longer matches this rule's conditions"
)

// wantRetractionReason gives the reason expected for each spelling in retractedStatuses.
var wantRetractionReason = map[string]string{
	"Rejected":  "CVE was rejected by its source",
	"REJECTED":  "CVE was rejected by its source",
	"withdrawn": "CVE was withdrawn by its source",
}

// resolutionFixture is an evaluator wired to the real dispatcher, with one webhook channel.
type resolutionFixture struct {
	tdb       *testutil.TestDB
	ev        *alert.Evaluator
	orgID     uuid.UUID
	channelID uuid.UUID
}

func newResolutionFixture(t *testing.T) *resolutionFixture {
	t.Helper()
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ev.SetDispatcher(notify.NewDispatcher(tdb.Store, 300))
	orgID := createTestOrg(t, tdb.DB())
	channel, _, err := tdb.CreateNotificationChannel(context.Background(), orgID, "resolution-channel", "webhook",
		json.RawMessage(`{"url":"https://example.com/hook"}`))
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	return &resolutionFixture{tdb: tdb, ev: ev, orgID: orgID, channelID: channel.ID}
}

func (f *resolutionFixture) bindChannel(t *testing.T, ctx context.Context, ruleID uuid.UUID) {
	t.Helper()
	if err := f.tdb.BindChannelToRule(ctx, ruleID, f.channelID, f.orgID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}
}

// activeBoundRule creates an active rule that delivers to the fixture's channel.
func (f *resolutionFixture) activeBoundRule(t *testing.T, ctx context.Context, conditions string) *store.AlertRuleRow {
	t.Helper()
	rule := mustRule(t, ctx, f.tdb.Store, f.orgID, "and", conditions, nil)
	f.bindChannel(t, ctx, rule.ID)
	activateRule(t, ctx, f.tdb.Store, f.orgID, rule.ID)
	return rule
}

func (f *resolutionFixture) ingestScore(t *testing.T, ctx context.Context, cveID string, score float64) {
	t.Helper()
	if err := merge.Ingest(ctx, f.tdb.Store, feed.CanonicalPatch{
		CVEID:       cveID,
		Status:      "Analyzed",
		CVSSv3Score: &score,
	}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(%s): %v", cveID, err)
	}
}

func (f *resolutionFixture) runBatch(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := f.ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
}

func (f *resolutionFixture) runRealtime(t *testing.T, ctx context.Context, cveID string) {
	t.Helper()
	if err := f.ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime: %v", err)
	}
}

// resolutionNotification is one CVE in a rule's resolution deliveries.
type resolutionNotification struct {
	CVEID       string   `json:"cve_id"`
	Reason      string   `json:"reason"`
	CVSSV3Score *float64 `json:"cvss_v3_score"`
}

// resolutionsForRule returns every CVE in the rule's resolution deliveries.
func (f *resolutionFixture) resolutionsForRule(t *testing.T, ctx context.Context, ruleID uuid.UUID) []resolutionNotification {
	t.Helper()
	rows, err := f.tdb.DB().QueryContext(ctx,
		`SELECT payload FROM notification_deliveries WHERE rule_id = $1 AND kind = 'resolution'`, ruleID)
	if err != nil {
		t.Fatalf("query resolution deliveries: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	var all []resolutionNotification
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan resolution delivery: %v", err)
		}
		var items []resolutionNotification
		if err := json.Unmarshal(raw, &items); err != nil {
			t.Fatalf("unmarshal resolution payload %s: %v", raw, err)
		}
		all = append(all, items...)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate resolution deliveries: %v", err)
	}
	return all
}

// assertOneResolution checks the rule sent exactly one resolution, for cveID, with reason.
func (f *resolutionFixture) assertOneResolution(t *testing.T, ctx context.Context, ruleID uuid.UUID, cveID, reason string) resolutionNotification {
	t.Helper()
	got := f.resolutionsForRule(t, ctx, ruleID)
	if len(got) != 1 {
		t.Fatalf("resolutions = %+v, want exactly 1 for %s", got, cveID)
	}
	if got[0].CVEID != cveID {
		t.Errorf("resolution cve_id = %q, want %q", got[0].CVEID, cveID)
	}
	if got[0].Reason != reason {
		t.Errorf("resolution reason = %q, want %q", got[0].Reason, reason)
	}
	return got[0]
}

func assertCurrentScore(t *testing.T, got resolutionNotification, want float64) {
	t.Helper()
	if got.CVSSV3Score == nil || *got.CVSSV3Score != want {
		t.Errorf("resolution cvss_v3_score = %v, want %v", got.CVSSV3Score, want)
	}
}

func TestResolutionNotification_ScoreDowngrade(t *testing.T) {
	f := newResolutionFixture(t)
	ctx := context.Background()

	t.Run("Batch", func(t *testing.T) {
		const cveID = "CVE-2098-1001"
		f.ingestScore(t, ctx, cveID, 9.8)
		rule := f.activeBoundRule(t, ctx, highScoreCondition)
		f.runBatch(t, ctx)
		assertEventOpen(t, f.tdb.DB(), rule.ID, cveID)
		if got := f.resolutionsForRule(t, ctx, rule.ID); len(got) != 0 {
			t.Fatalf("resolutions while the CVE matches = %+v, want none", got)
		}

		ageCorpus(t, ctx, f.tdb.DB())
		f.ingestScore(t, ctx, cveID, 4.3)
		f.runBatch(t, ctx)
		assertCurrentScore(t, f.assertOneResolution(t, ctx, rule.ID, cveID, noMatchReason), 4.3)

		// The CVE is still inside the batch path's re-scan window on this run.
		f.runBatch(t, ctx)
		f.assertOneResolution(t, ctx, rule.ID, cveID, noMatchReason)
	})

	t.Run("Realtime", func(t *testing.T) {
		const cveID = "CVE-2098-1002"
		f.ingestScore(t, ctx, cveID, 9.8)
		rule := f.activeBoundRule(t, ctx, highScoreCondition)
		f.runRealtime(t, ctx, cveID)

		f.ingestScore(t, ctx, cveID, 4.3)
		f.runRealtime(t, ctx, cveID)
		assertCurrentScore(t, f.assertOneResolution(t, ctx, rule.ID, cveID, noMatchReason), 4.3)
	})
}

func TestResolutionNotification_RetractedCVE(t *testing.T) {
	f := newResolutionFixture(t)
	ctx := context.Background()

	for i, status := range retractedStatuses {
		t.Run("Batch/"+status, func(t *testing.T) {
			cveID := fmt.Sprintf("CVE-2098-%04d", 2000+i)
			ingestCritical(t, ctx, f.tdb, cveID)
			rule := f.activeBoundRule(t, ctx, criticalSeverityCondition)
			f.runBatch(t, ctx)
			assertEventOpen(t, f.tdb.DB(), rule.ID, cveID)

			ageCorpus(t, ctx, f.tdb.DB())
			ingestRetraction(t, ctx, f.tdb, cveID, status)
			f.runBatch(t, ctx)
			f.assertOneResolution(t, ctx, rule.ID, cveID, wantRetractionReason[status])
		})

		t.Run("Realtime/"+status, func(t *testing.T) {
			cveID := fmt.Sprintf("CVE-2098-%04d", 3000+i)
			ingestCritical(t, ctx, f.tdb, cveID)
			rule := f.activeBoundRule(t, ctx, criticalSeverityCondition)
			f.runRealtime(t, ctx, cveID)

			ingestRetraction(t, ctx, f.tdb, cveID, status)
			f.runRealtime(t, ctx, cveID)
			f.assertOneResolution(t, ctx, rule.ID, cveID, wantRetractionReason[status])
		})

		t.Run("EPSSOnly/"+status, func(t *testing.T) {
			cveID := fmt.Sprintf("CVE-2098-%04d", 4000+i)
			ruleID := openEPSSOnlyEvent(t, ctx, f.tdb, f.ev, f.orgID, cveID)
			f.bindChannel(t, ctx, ruleID)

			ageCorpus(t, ctx, f.tdb.DB())
			ingestRetraction(t, ctx, f.tdb, cveID, status)
			if err := f.ev.EvaluateEPSS(ctx); err != nil {
				t.Fatalf("EvaluateEPSS: %v", err)
			}
			f.assertOneResolution(t, ctx, ruleID, cveID, wantRetractionReason[status])
		})
	}
}

// TestResolutionNotification_OncePerCVE covers a CVE with one alert_events row per
// material_hash, and a CVE that the realtime and batch paths both evaluate.
func TestResolutionNotification_OncePerCVE(t *testing.T) {
	f := newResolutionFixture(t)
	ctx := context.Background()

	t.Run("SeveralEvents", func(t *testing.T) {
		const cveID = "CVE-2098-5001"
		f.ingestScore(t, ctx, cveID, 9.8)
		rule := f.activeBoundRule(t, ctx, highScoreCondition)
		f.runBatch(t, ctx)
		f.ingestScore(t, ctx, cveID, 9.9)
		f.runBatch(t, ctx)
		if n := countAlertEvents(t, f.tdb.DB(), rule.ID, cveID); n != 2 {
			t.Fatalf("alert events before downgrade = %d, want 2", n)
		}

		ageCorpus(t, ctx, f.tdb.DB())
		f.ingestScore(t, ctx, cveID, 4.3)
		f.runBatch(t, ctx)
		f.assertOneResolution(t, ctx, rule.ID, cveID, noMatchReason)
	})

	t.Run("RealtimeThenBatch", func(t *testing.T) {
		const cveID = "CVE-2098-5002"
		f.ingestScore(t, ctx, cveID, 9.8)
		rule := f.activeBoundRule(t, ctx, highScoreCondition)
		f.runRealtime(t, ctx, cveID)

		f.ingestScore(t, ctx, cveID, 4.3)
		f.runRealtime(t, ctx, cveID)
		f.runBatch(t, ctx)
		f.assertOneResolution(t, ctx, rule.ID, cveID, noMatchReason)
	})
}

// TestResolutionNotification_ReopenedEventResolvesAgain covers a score that drops, returns
// and drops again: each drop is its own transition, so each one notifies.
func TestResolutionNotification_ReopenedEventResolvesAgain(t *testing.T) {
	f := newResolutionFixture(t)
	ctx := context.Background()

	const cveID = "CVE-2098-5101"
	f.ingestScore(t, ctx, cveID, 9.8)
	rule := f.activeBoundRule(t, ctx, highScoreCondition)
	f.runRealtime(t, ctx, cveID)

	f.ingestScore(t, ctx, cveID, 4.3)
	f.runRealtime(t, ctx, cveID)
	f.ingestScore(t, ctx, cveID, 9.8)
	f.runRealtime(t, ctx, cveID)
	if !getMatchState(t, f.tdb.DB(), rule.ID, cveID) {
		t.Fatal("last_match_state after the score returned = false, want true")
	}

	f.ingestScore(t, ctx, cveID, 4.3)
	f.runRealtime(t, ctx, cveID)
	if got := f.resolutionsForRule(t, ctx, rule.ID); len(got) != 2 {
		t.Errorf("resolutions = %+v, want one per drop (2)", got)
	}
}

// TestResolutionNotification_ActivationBaselineStaysQuiet covers a CVE recorded by the
// activation scan: channels never heard about it, so they hear nothing when it resolves.
func TestResolutionNotification_ActivationBaselineStaysQuiet(t *testing.T) {
	f := newResolutionFixture(t)
	ctx := context.Background()

	const cveID = "CVE-2098-6001"
	f.ingestScore(t, ctx, cveID, 9.8)
	rule := mustRule(t, ctx, f.tdb.Store, f.orgID, "and", highScoreCondition, nil)
	f.bindChannel(t, ctx, rule.ID)
	if err := f.tdb.SetAlertRuleStatus(ctx, f.orgID, rule.ID, "activating"); err != nil {
		t.Fatalf("SetAlertRuleStatus: %v", err)
	}
	if err := f.ev.EvaluateActivation(ctx, rule.ID, f.orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}
	assertEventOpen(t, f.tdb.DB(), rule.ID, cveID)

	ageCorpus(t, ctx, f.tdb.DB())
	f.ingestScore(t, ctx, cveID, 4.3)
	f.runBatch(t, ctx)

	if getMatchState(t, f.tdb.DB(), rule.ID, cveID) {
		t.Error("last_match_state after downgrade = true, want false")
	}
	if got := f.resolutionsForRule(t, ctx, rule.ID); len(got) != 0 {
		t.Errorf("resolutions for an activation baseline = %+v, want none", got)
	}
}

// failingResolutionDispatcher delivers alerts and fails every resolution fan-out.
type failingResolutionDispatcher struct {
	calls atomic.Int32
}

func (d *failingResolutionDispatcher) Fanout(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (d *failingResolutionDispatcher) FanoutResolution(context.Context, uuid.UUID, uuid.UUID, string) error {
	d.calls.Add(1)
	return fmt.Errorf("simulated resolution fan-out failure")
}

func TestResolutionNotification_FanoutErrorLeavesEventResolved(t *testing.T) {
	f := newResolutionFixture(t)
	ctx := context.Background()
	disp := &failingResolutionDispatcher{}
	f.ev.SetDispatcher(disp)

	const cveID = "CVE-2098-7001"
	f.ingestScore(t, ctx, cveID, 9.8)
	rule := f.activeBoundRule(t, ctx, highScoreCondition)
	f.runRealtime(t, ctx, cveID)

	f.ingestScore(t, ctx, cveID, 4.3)
	f.runRealtime(t, ctx, cveID)

	if n := disp.calls.Load(); n != 1 {
		t.Errorf("FanoutResolution calls = %d, want 1", n)
	}
	if getMatchState(t, f.tdb.DB(), rule.ID, cveID) {
		t.Error("last_match_state after a failed fan-out = true, want false")
	}
}
