// ABOUTME: Integration tests for the alert evaluator using a testcontainer Postgres database.
// ABOUTME: Tests cover realtime, batch, activation scan, and zombie sweeper paths.
package alert_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests (no DB)
// ──────────────────────────────────────────────────────────────────────────────

func TestRuleCache_GetSetEvict(t *testing.T) {
	cache := alert.NewRuleCache()
	ruleID := uuid.New()

	// Get from empty cache → miss
	if _, ok := cache.Get(ruleID, 1); ok {
		t.Fatal("expected miss on empty cache")
	}

	// Set then Get → hit
	cache.Set(ruleID, 1, nil) // nil compiled rule is fine for cache tests
	if _, ok := cache.Get(ruleID, 1); !ok {
		t.Fatal("expected hit after Set")
	}

	// Get wrong version → miss
	if _, ok := cache.Get(ruleID, 2); ok {
		t.Fatal("expected miss on wrong dsl_version")
	}

	// Evict then Get → miss
	cache.Evict(ruleID)
	if _, ok := cache.Get(ruleID, 1); ok {
		t.Fatal("expected miss after Evict")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration test helpers
// ──────────────────────────────────────────────────────────────────────────────

func newTestEvaluator(t *testing.T, tdb *testutil.TestDB) *alert.Evaluator {
	t.Helper()
	cache := alert.NewRuleCache()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return alert.New(tdb.DB(), tdb.Store, cache, log)
}

// createTestOrg inserts an organization row and returns its ID.
// Required because alert_rules.org_id has a FK to organizations(id).
func createTestOrg(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO organizations (id, name) VALUES ($1, $2)`,
		id, "Test Org "+id.String()[:8],
	)
	if err != nil {
		t.Fatalf("createTestOrg: %v", err)
	}
	return id
}

// insertCVE inserts a minimal CVE row. status="" means NULL.
func insertCVE(t *testing.T, db *sql.DB, cveID, status, description string, cvssV3 *float64, materialHash string) {
	t.Helper()
	ctx := context.Background()
	var statusVal, descVal, hashVal interface{}
	if status != "" {
		statusVal = status
	}
	if description != "" {
		descVal = description
	}
	if materialHash != "" {
		hashVal = materialHash
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, description_primary, cvss_v3_score, material_hash)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (cve_id) DO UPDATE SET
			status               = EXCLUDED.status,
			description_primary  = EXCLUDED.description_primary,
			cvss_v3_score        = EXCLUDED.cvss_v3_score,
			material_hash        = EXCLUDED.material_hash,
			date_modified_canonical = now()
	`, cveID, statusVal, descVal, cvssV3, hashVal)
	if err != nil {
		t.Fatalf("insertCVE %s: %v", cveID, err)
	}
}

// mustRule creates an active alert rule and registers a cleanup to soft-delete it.
func mustRule(t *testing.T, ctx context.Context, st store.AlertRuleStore, orgID uuid.UUID, logic, conditions string, watchlistIDs []uuid.UUID) *store.AlertRuleRow {
	t.Helper()
	conds := json.RawMessage(conditions)
	row, err := st.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:         fmt.Sprintf("test-rule-%s", uuid.New().String()[:8]),
		Logic:        logic,
		Conditions:   conds,
		WatchlistIds: watchlistIDs,
		Status:       "draft",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	t.Cleanup(func() {
		_ = st.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})
	return row
}

// activateRule sets a rule's status to 'active'.
func activateRule(t *testing.T, ctx context.Context, st store.AlertRuleStore, orgID, ruleID uuid.UUID) {
	t.Helper()
	if err := st.SetAlertRuleStatus(ctx, orgID, ruleID, "active"); err != nil {
		t.Fatalf("activate rule: %v", err)
	}
}

// countAlertEvents returns the number of alert_events for (rule, cve).
func countAlertEvents(t *testing.T, db *sql.DB, ruleID uuid.UUID, cveID string) int {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM alert_events WHERE rule_id = $1 AND cve_id = $2`,
		ruleID, cveID,
	).Scan(&n)
	if err != nil {
		t.Fatalf("countAlertEvents: %v", err)
	}
	return n
}

// getMatchState returns last_match_state for the most recent alert_event for (rule, cve).
func getMatchState(t *testing.T, db *sql.DB, ruleID uuid.UUID, cveID string) bool {
	t.Helper()
	var state bool
	err := db.QueryRowContext(context.Background(),
		`SELECT last_match_state FROM alert_events WHERE rule_id = $1 AND cve_id = $2 LIMIT 1`,
		ruleID, cveID,
	).Scan(&state)
	if err != nil {
		t.Fatalf("getMatchState: %v", err)
	}
	return state
}

// getSuppressDelivery returns suppress_delivery for the first alert_event for (rule, cve).
func getSuppressDelivery(t *testing.T, db *sql.DB, ruleID uuid.UUID, cveID string) bool {
	t.Helper()
	var s bool
	err := db.QueryRowContext(context.Background(),
		`SELECT suppress_delivery FROM alert_events WHERE rule_id = $1 AND cve_id = $2 LIMIT 1`,
		ruleID, cveID,
	).Scan(&s)
	if err != nil {
		t.Fatalf("getSuppressDelivery: %v", err)
	}
	return s
}

// getRuleStatus returns the current status of an alert rule.
func getRuleStatus(t *testing.T, db *sql.DB, ruleID uuid.UUID) string {
	t.Helper()
	var s string
	err := db.QueryRowContext(context.Background(),
		`SELECT status FROM alert_rules WHERE id = $1`,
		ruleID,
	).Scan(&s)
	if err != nil {
		t.Fatalf("getRuleStatus: %v", err)
	}
	return s
}

// countRuns returns the number of alert_rule_runs for a rule.
func countRuns(t *testing.T, db *sql.DB, ruleID uuid.UUID) int {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM alert_rule_runs WHERE rule_id = $1`,
		ruleID,
	).Scan(&n)
	if err != nil {
		t.Fatalf("countRuns: %v", err)
	}
	return n
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration tests — shared single container per test function
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorRealtime(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`

	t.Run("Match", func(t *testing.T) {
		cveID := "CVE-RT-MATCH-001"
		score := 8.5
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "critical vuln", &score, "hash001")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("EvaluateRealtime: %v", err)
		}

		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
			t.Fatalf("want 1 alert_event, got %d", n)
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		cveID := "CVE-RT-NOMATCH-001"
		score := 5.0 // below 7.0 threshold
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "low severity vuln", &score, "hash002")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("EvaluateRealtime: %v", err)
		}

		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 0 {
			t.Fatalf("want 0 alert_events, got %d", n)
		}
	})

	t.Run("Dedup", func(t *testing.T) {
		cveID := "CVE-RT-DEDUP-001"
		score := 9.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "dedup test", &score, "hashdedup")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		for i := 0; i < 2; i++ {
			if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
				t.Fatalf("EvaluateRealtime iteration %d: %v", i, err)
			}
		}

		// ON CONFLICT DO NOTHING ensures only one row
		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
			t.Fatalf("want 1 alert_event after dedup, got %d", n)
		}
	})

	t.Run("RegexMatch", func(t *testing.T) {
		cveID := "CVE-RT-REGEX-001"
		score := 8.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "Apache HTTP server vulnerability", &score, "hashregex1")

		// Rule requires cvss>=7.0 AND description matches "apache"
		const regexConds = `[
			{"field":"cvss_v3_score","operator":"gte","value":7.0},
			{"field":"description_primary","operator":"regex","value":"apache"}
		]`
		rule := mustRule(t, ctx, tdb.Store, orgID, "and", regexConds, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("EvaluateRealtime: %v", err)
		}

		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
			t.Fatalf("want 1 alert_event for regex match, got %d", n)
		}
	})

	t.Run("RegexNoMatch", func(t *testing.T) {
		cveID := "CVE-RT-REGEX-002"
		score := 8.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "Windows kernel vulnerability", &score, "hashregex2")

		const regexConds = `[
			{"field":"cvss_v3_score","operator":"gte","value":7.0},
			{"field":"description_primary","operator":"regex","value":"apache"}
		]`
		rule := mustRule(t, ctx, tdb.Store, orgID, "and", regexConds, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("EvaluateRealtime: %v", err)
		}

		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 0 {
			t.Fatalf("want 0 alert_events for regex no-match, got %d", n)
		}
	})

	t.Run("RejectedCVE", func(t *testing.T) {
		cveID := "CVE-RT-REJECTED-001"
		score := 9.5
		insertCVE(t, tdb.DB(), cveID, "Rejected", "rejected vuln", &score, "hashrejected")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("EvaluateRealtime: %v", err)
		}

		// Rejected CVEs are excluded by the evaluator
		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 0 {
			t.Fatalf("want 0 alert_events for rejected CVE, got %d", n)
		}
	})

	t.Run("ResolutionDetection", func(t *testing.T) {
		cveID := "CVE-RT-RESOLVE-001"
		// First evaluation: score 9.0 → matches
		score := 9.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "critical", &score, "hashresolve1")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("first evaluation: %v", err)
		}
		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
			t.Fatalf("want 1 event after first eval, got %d", n)
		}

		// Second evaluation: score drops below threshold → should resolve
		lowScore := 4.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "patched", &lowScore, "hashresolve2")

		// NOTE: With the same material_hash approach, the ON CONFLICT DO NOTHING means
		// a new event is not inserted (different hash). Resolution detection looks at
		// previously matched events that no longer match the DSL for this CVE.
		// We need to simulate this properly: the first event has hash "hashresolve1",
		// the CVE now has hash "hashresolve2". The evaluator evaluates cveID against the
		// rule, finds no match (score too low), and marks existing event as resolved.
		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("second evaluation: %v", err)
		}

		// The first alert_event should now have last_match_state = false
		if state := getMatchState(t, tdb.DB(), rule.ID, cveID); state {
			t.Fatal("want last_match_state=false after resolution, got true")
		}
	})
}

func TestEvaluatorActivation(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Insert some CVEs that match the rule (cvss >= 7.0)
	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	for i := 1; i <= 5; i++ {
		cveID := fmt.Sprintf("CVE-ACT-%04d", i)
		score := 8.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "activation test", &score, fmt.Sprintf("acthash%d", i))
	}
	// Insert one that does NOT match
	lowScore := 3.0
	insertCVE(t, tdb.DB(), "CVE-ACT-NOMATCH", "Analyzed", "low severity", &lowScore, "acthash-low")

	// Create rule with status='activating'
	conds := json.RawMessage(cvssCondition)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "activation-test-rule",
		Logic:      "and",
		Conditions: conds,
		Status:     "activating",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	t.Cleanup(func() {
		_ = tdb.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})

	if err := ev.EvaluateActivation(ctx, row.ID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	// Rule should be 'active'
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "active" {
		t.Fatalf("want rule status 'active', got %q", s)
	}

	// 5 matching CVEs → 5 events with suppress_delivery=true
	for i := 1; i <= 5; i++ {
		cveID := fmt.Sprintf("CVE-ACT-%04d", i)
		if n := countAlertEvents(t, tdb.DB(), row.ID, cveID); n != 1 {
			t.Fatalf("CVE %s: want 1 alert_event, got %d", cveID, n)
		}
		if !getSuppressDelivery(t, tdb.DB(), row.ID, cveID) {
			t.Fatalf("CVE %s: want suppress_delivery=true", cveID)
		}
	}

	// Non-matching CVE → no event
	if n := countAlertEvents(t, tdb.DB(), row.ID, "CVE-ACT-NOMATCH"); n != 0 {
		t.Fatalf("non-matching CVE: want 0 events, got %d", n)
	}

	// A run row should have been written
	if n := countRuns(t, tdb.DB(), row.ID); n == 0 {
		t.Fatal("want at least 1 alert_rule_run, got 0")
	}
}

func TestEvaluatorSweepZombieActivations(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Create a rule in 'activating' status
	conds := json.RawMessage(`[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "zombie-test-rule",
		Logic:      "and",
		Conditions: conds,
		Status:     "activating",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	t.Cleanup(func() {
		_ = tdb.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})

	// Directly insert a 'running' activation job with old locked_at to simulate zombie
	payload, _ := json.Marshal(map[string]string{
		"rule_id": row.ID.String(),
		"org_id":  orgID.String(),
	})
	var jobID uuid.UUID
	err = tdb.DB().QueryRowContext(ctx, `
		INSERT INTO job_queue (queue, lock_key, payload, status, locked_by, locked_at)
		VALUES ('alert_activation', $1, $2, 'running', 'worker-1', now() - interval '20 minutes')
		RETURNING id
	`, "alert:activation:"+row.ID.String(), payload).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert zombie job: %v", err)
	}

	if err := ev.SweepZombieActivations(ctx); err != nil {
		t.Fatalf("SweepZombieActivations: %v", err)
	}

	// Rule should now be 'error'
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "error" {
		t.Fatalf("want rule status 'error', got %q", s)
	}

	// Job should be 'failed'
	var jobStatus string
	if err := tdb.DB().QueryRowContext(ctx, `SELECT status FROM job_queue WHERE id = $1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatalf("get job status: %v", err)
	}
	if jobStatus != "failed" {
		t.Fatalf("want job status 'failed', got %q", jobStatus)
	}
}

func TestEvaluatorBatch(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`

	// Insert a CVE that matches
	cveID := "CVE-BATCH-001"
	score := 9.0
	insertCVE(t, tdb.DB(), cveID, "Analyzed", "batch test", &score, "batchhash1")

	rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	// First batch: cursor is zero, so all CVEs are candidates
	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("first EvaluateBatch: %v", err)
	}

	// Matching CVE should have an event
	if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
		t.Fatalf("want 1 alert_event after batch, got %d", n)
	}

	// Cursor should be written to feed_sync_state
	var feedName string
	err := tdb.DB().QueryRowContext(ctx,
		`SELECT feed_name FROM feed_sync_state WHERE feed_name = 'alert:batch'`,
	).Scan(&feedName)
	if err != nil {
		t.Fatalf("cursor not written to feed_sync_state: %v", err)
	}

	// Second batch: cursor advanced, no new CVEs modified → no new events
	cursorBefore := time.Now()
	_ = cursorBefore // cursor check: second batch evaluates only CVEs modified after cursor
	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("second EvaluateBatch: %v", err)
	}
	// Still just 1 event (dedup from ON CONFLICT DO NOTHING, and cursor filters most CVEs)
	if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
		t.Fatalf("want 1 alert_event after second batch, got %d", n)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// mockDispatcher records Fanout calls for assertion in evaluator tests.
// The evaluator tests use a real DB but mock the dispatcher because Fanout's
// delivery behavior is covered by the notify package tests.
// ──────────────────────────────────────────────────────────────────────────────

type mockDispatcher struct {
	calls []struct {
		orgID  uuid.UUID
		ruleID uuid.UUID
		cveID  string
	}
	mu sync.Mutex
}

func (m *mockDispatcher) Fanout(_ context.Context, orgID, ruleID uuid.UUID, cveID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, struct {
		orgID  uuid.UUID
		ruleID uuid.UUID
		cveID  string
	}{orgID, ruleID, cveID})
	return nil
}

func TestEvaluateRealtime_FanoutCalledForNewEvent(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	disp := &mockDispatcher{}
	ev.SetDispatcher(disp)

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	cveID := "CVE-FANOUT-NEW-001"
	score := 8.5
	insertCVE(t, tdb.DB(), cveID, "Analyzed", "fanout test", &score, "hashfanout1")

	rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime: %v", err)
	}

	disp.mu.Lock()
	defer disp.mu.Unlock()
	if len(disp.calls) != 1 {
		t.Fatalf("want 1 Fanout call, got %d", len(disp.calls))
	}
	if disp.calls[0].cveID != cveID {
		t.Fatalf("want Fanout cveID=%q, got %q", cveID, disp.calls[0].cveID)
	}
}

func TestEvaluateRealtime_FanoutNotCalledForSuppressedEvent(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`

	// Create 2 CVEs that match so activation scan has something to write
	for i := 1; i <= 2; i++ {
		cveID := fmt.Sprintf("CVE-FANOUT-SUPP-%04d", i)
		score := 9.0
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "suppressed fanout test", &score, fmt.Sprintf("hashsupp%d", i))
	}

	// Create rule in 'activating' state (activation scan uses suppressDelivery=true)
	conds := json.RawMessage(cvssCondition)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "fanout-suppress-test-rule",
		Logic:      "and",
		Conditions: conds,
		Status:     "activating",
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	t.Cleanup(func() {
		_ = tdb.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})

	// Build a fresh evaluator with the mock dispatcher attached
	cache := alert.NewRuleCache()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := alert.New(tdb.DB(), tdb.Store, cache, log)
	disp := &mockDispatcher{}
	ev.SetDispatcher(disp)

	if err := ev.EvaluateActivation(ctx, row.ID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	disp.mu.Lock()
	defer disp.mu.Unlock()
	if len(disp.calls) != 0 {
		t.Fatalf("want 0 Fanout calls for suppressed events, got %d", len(disp.calls))
	}
}

func TestEvaluateRealtime_FanoutNotCalledForDuplicateEvent(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	disp := &mockDispatcher{}
	ev.SetDispatcher(disp)

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	cveID := "CVE-FANOUT-DEDUP-001"
	score := 8.5
	insertCVE(t, tdb.DB(), cveID, "Analyzed", "fanout dedup test", &score, "hashfanoutdedup")

	rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	// First call: new alert_event inserted → Fanout fires.
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime (first): %v", err)
	}
	// Second call: same material_hash → ON CONFLICT DO NOTHING → uuid.Nil → Fanout must not fire.
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime (second): %v", err)
	}

	disp.mu.Lock()
	defer disp.mu.Unlock()
	if len(disp.calls) != 1 {
		t.Fatalf("want exactly 1 Fanout call (dedup suppresses second), got %d", len(disp.calls))
	}
}
