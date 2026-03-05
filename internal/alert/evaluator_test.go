// ABOUTME: Integration tests for the alert evaluator using a testcontainer Postgres database.
// ABOUTME: Tests cover realtime, batch, EPSS, activation, dry-run, zombie sweeper, and cache paths.
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

// insertCVEWithEPSS inserts a CVE row with EPSS score and date_epss_updated columns set.
func insertCVEWithEPSS(t *testing.T, db *sql.DB, cveID, status, description string, cvssV3, epssScore *float64, materialHash string) {
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
		INSERT INTO cves (cve_id, status, description_primary, cvss_v3_score, epss_score, date_epss_updated, material_hash)
		VALUES ($1, $2, $3, $4, $5, now(), $6)
		ON CONFLICT (cve_id) DO UPDATE SET
			status               = EXCLUDED.status,
			description_primary  = EXCLUDED.description_primary,
			cvss_v3_score        = EXCLUDED.cvss_v3_score,
			epss_score           = EXCLUDED.epss_score,
			date_epss_updated    = now(),
			material_hash        = EXCLUDED.material_hash,
			date_modified_canonical = now()
	`, cveID, statusVal, descVal, cvssV3, epssScore, hashVal)
	if err != nil {
		t.Fatalf("insertCVEWithEPSS %s: %v", cveID, err)
	}
}

// mustEPSSRule creates an active alert rule with has_epss_condition/is_epss_only flags set.
func mustEPSSRule(t *testing.T, ctx context.Context, st store.AlertRuleStore, orgID uuid.UUID, logic, conditions string, isEPSSOnly bool) *store.AlertRuleRow {
	t.Helper()
	conds := json.RawMessage(conditions)
	row, err := st.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:             fmt.Sprintf("test-epss-rule-%s", uuid.New().String()[:8]),
		Logic:            logic,
		Conditions:       conds,
		HasEpssCondition: true,
		IsEpssOnly:       isEPSSOnly,
		Status:           "draft",
	})
	if err != nil {
		t.Fatalf("create EPSS alert rule: %v", err)
	}
	t.Cleanup(func() {
		_ = st.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})
	return row
}

// countAllAlertEventsForRule returns the total number of alert_events for a rule.
func countAllAlertEventsForRule(t *testing.T, db *sql.DB, ruleID uuid.UUID) int {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM alert_events WHERE rule_id = $1`,
		ruleID,
	).Scan(&n)
	if err != nil {
		t.Fatalf("countAllAlertEventsForRule: %v", err)
	}
	return n
}

// getRunPath returns the path column for the most recent alert_rule_run for a rule.
func getRunPath(t *testing.T, db *sql.DB, ruleID uuid.UUID) string {
	t.Helper()
	var p string
	err := db.QueryRowContext(context.Background(),
		`SELECT path FROM alert_rule_runs WHERE rule_id = $1 ORDER BY started_at DESC LIMIT 1`,
		ruleID,
	).Scan(&p)
	if err != nil {
		t.Fatalf("getRunPath: %v", err)
	}
	return p
}

// getCursorSince reads the "since" value from the feed_sync_state cursor JSON for the named feed.
func getCursorSince(t *testing.T, db *sql.DB, feedName string) time.Time {
	t.Helper()
	var raw []byte
	err := db.QueryRowContext(context.Background(),
		`SELECT cursor_json FROM feed_sync_state WHERE feed_name = $1`, feedName,
	).Scan(&raw)
	if err != nil {
		t.Fatalf("getCursorSince for %s: %v", feedName, err)
	}
	var cur struct {
		Since time.Time `json:"since"`
	}
	if err := json.Unmarshal(raw, &cur); err != nil {
		t.Fatalf("parse cursor for %s: %v", feedName, err)
	}
	return cur.Since
}

// bulkInsertCVEs inserts count CVEs with sequential IDs using a batch INSERT for speed.
// All CVEs get status="Analyzed", the given cvssV3 score, and unique material hashes.
func bulkInsertCVEs(t *testing.T, db *sql.DB, prefix string, count int, cvssV3 float64) {
	t.Helper()
	ctx := context.Background()
	const batchSize = 500
	for start := 0; start < count; start += batchSize {
		end := start + batchSize
		if end > count {
			end = count
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("bulkInsertCVEs begin tx: %v", err)
		}
		for i := start; i < end; i++ {
			cveID := fmt.Sprintf("%s-%06d", prefix, i)
			_, err := tx.ExecContext(ctx, `
				INSERT INTO cves (cve_id, status, description_primary, cvss_v3_score, material_hash)
				VALUES ($1, 'Analyzed', 'bulk test', $2, $3)
				ON CONFLICT (cve_id) DO NOTHING
			`, cveID, cvssV3, fmt.Sprintf("bulkhash-%s-%d", prefix, i))
			if err != nil {
				_ = tx.Rollback()
				t.Fatalf("bulkInsertCVEs insert %s: %v", cveID, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("bulkInsertCVEs commit: %v", err)
		}
	}
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

// ──────────────────────────────────────────────────────────────────────────────
// EvaluateEPSS tests
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorEPSS(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	t.Run("HappyPath", func(t *testing.T) {
		// Insert a CVE with high EPSS score
		cveID := "CVE-EPSS-001"
		score := 6.0
		epss := 0.95
		insertCVEWithEPSS(t, tdb.DB(), cveID, "Analyzed", "epss test vuln", &score, &epss, "epss-hash-001")

		// Create an EPSS-only rule: epss_score >= 0.9
		const epssCond = `[{"field":"epss_score","operator":"gte","value":0.9}]`
		rule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and", epssCond, true)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("EvaluateEPSS: %v", err)
		}

		// The CVE with EPSS 0.95 should match the rule
		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
			t.Fatalf("want 1 alert_event for EPSS match, got %d", n)
		}

		// A run row should be written with path=epss
		if n := countRuns(t, tdb.DB(), rule.ID); n == 0 {
			t.Fatal("want at least 1 alert_rule_run for EPSS, got 0")
		}
		if p := getRunPath(t, tdb.DB(), rule.ID); p != "epss" {
			t.Fatalf("want run path 'epss', got %q", p)
		}
	})

	t.Run("NoMatchBelowThreshold", func(t *testing.T) {
		cveID := "CVE-EPSS-002"
		score := 6.0
		epss := 0.1 // below 0.9 threshold
		insertCVEWithEPSS(t, tdb.DB(), cveID, "Analyzed", "low epss", &score, &epss, "epss-hash-002")

		const epssCond = `[{"field":"epss_score","operator":"gte","value":0.9}]`
		rule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and", epssCond, true)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("EvaluateEPSS: %v", err)
		}

		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 0 {
			t.Fatalf("want 0 alert_events for low EPSS, got %d", n)
		}
	})

	t.Run("OnlyEPSSRulesEvaluated", func(t *testing.T) {
		// Insert a CVE with high EPSS and high CVSS
		cveID := "CVE-EPSS-003"
		score := 9.0
		epss := 0.99
		insertCVEWithEPSS(t, tdb.DB(), cveID, "Analyzed", "epss-only check", &score, &epss, "epss-hash-003")

		// Create a non-EPSS rule (cvss only) — should NOT be picked up by EvaluateEPSS
		const cvssOnlyCond = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
		nonEPSSRule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssOnlyCond, nil)
		activateRule(t, ctx, tdb.Store, orgID, nonEPSSRule.ID)

		// Create an EPSS rule — should be picked up
		const epssCond = `[{"field":"epss_score","operator":"gte","value":0.9}]`
		epssRule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and", epssCond, true)
		activateRule(t, ctx, tdb.Store, orgID, epssRule.ID)

		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("EvaluateEPSS: %v", err)
		}

		// EPSS rule should have a match
		if n := countAlertEvents(t, tdb.DB(), epssRule.ID, cveID); n != 1 {
			t.Fatalf("want 1 alert_event for EPSS rule, got %d", n)
		}
		// Non-EPSS rule should NOT be evaluated by EvaluateEPSS path
		// (it may have events from other evaluator calls, but no "epss" path run)
		var epssRunCount int
		err := tdb.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM alert_rule_runs WHERE rule_id = $1 AND path = 'epss'`,
			nonEPSSRule.ID,
		).Scan(&epssRunCount)
		if err != nil {
			t.Fatalf("query epss runs: %v", err)
		}
		if epssRunCount != 0 {
			t.Fatalf("non-EPSS rule should have 0 epss-path runs, got %d", epssRunCount)
		}
	})

	t.Run("CursorAdvancement", func(t *testing.T) {
		// Insert a matching CVE
		cveID := "CVE-EPSS-CURSOR-001"
		score := 6.0
		epss := 0.95
		insertCVEWithEPSS(t, tdb.DB(), cveID, "Analyzed", "cursor test", &score, &epss, "epss-hash-cursor1")

		const epssCond = `[{"field":"epss_score","operator":"gte","value":0.9}]`
		rule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and", epssCond, true)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		// First EPSS run
		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("first EvaluateEPSS: %v", err)
		}

		// Cursor should be written
		cursor1 := getCursorSince(t, tdb.DB(), "alert:epss")
		if cursor1.IsZero() {
			t.Fatal("EPSS cursor should be non-zero after first run")
		}

		// Second EPSS run with no new EPSS updates — cursor should advance
		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("second EvaluateEPSS: %v", err)
		}

		cursor2 := getCursorSince(t, tdb.DB(), "alert:epss")
		if !cursor2.After(cursor1) {
			t.Fatalf("EPSS cursor should advance: cursor1=%v, cursor2=%v", cursor1, cursor2)
		}
	})

	t.Run("MixedEPSSAndCVSSRule", func(t *testing.T) {
		// A rule with both EPSS and CVSS conditions (has_epss_condition=true, is_epss_only=false)
		// should still be picked up by EvaluateEPSS
		cveID := "CVE-EPSS-MIXED-001"
		score := 8.0
		epss := 0.95
		insertCVEWithEPSS(t, tdb.DB(), cveID, "Analyzed", "mixed condition", &score, &epss, "epss-hash-mixed1")

		const mixedConds = `[
			{"field":"epss_score","operator":"gte","value":0.9},
			{"field":"cvss_v3_score","operator":"gte","value":7.0}
		]`
		rule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and", mixedConds, false)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("EvaluateEPSS: %v", err)
		}

		if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
			t.Fatalf("want 1 alert_event for mixed EPSS+CVSS rule, got %d", n)
		}
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// DryRun tests
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorDryRun(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`

	t.Run("MatchingCVEs", func(t *testing.T) {
		// Insert CVEs: 3 match, 1 does not
		for i := 1; i <= 3; i++ {
			cveID := fmt.Sprintf("CVE-DRY-MATCH-%04d", i)
			score := 8.0
			insertCVE(t, tdb.DB(), cveID, "Analyzed", "dry run test", &score, fmt.Sprintf("dryhash-match%d", i))
		}
		lowScore := 4.0
		insertCVE(t, tdb.DB(), "CVE-DRY-NOMATCH-001", "Analyzed", "low score", &lowScore, "dryhash-nomatch1")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		result, err := ev.DryRun(ctx, rule.ID, orgID)
		if err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		if result == nil {
			t.Fatal("DryRun returned nil result")
		}
		if result.MatchCount < 3 {
			t.Fatalf("want at least 3 matches, got %d", result.MatchCount)
		}
		if result.Partial {
			t.Fatal("DryRun should not be partial for small corpus")
		}
		if result.CandidatesEvaluated < 3 {
			t.Fatalf("want at least 3 candidates evaluated, got %d", result.CandidatesEvaluated)
		}

		// DryRun must NOT write any alert_events
		if n := countAllAlertEventsForRule(t, tdb.DB(), rule.ID); n != 0 {
			t.Fatalf("DryRun should not write alert_events, got %d", n)
		}
	})

	t.Run("RuleNotFound", func(t *testing.T) {
		result, err := ev.DryRun(ctx, uuid.New(), orgID)
		if err != nil {
			t.Fatalf("DryRun with missing rule: %v", err)
		}
		if result != nil {
			t.Fatalf("want nil result for missing rule, got %+v", result)
		}
	})

	t.Run("SampleCVEsCapped", func(t *testing.T) {
		// Insert 15 matching CVEs so we exceed the 10-sample cap
		for i := 1; i <= 15; i++ {
			cveID := fmt.Sprintf("CVE-DRY-SAMPLE-%04d", i)
			score := 9.0
			insertCVE(t, tdb.DB(), cveID, "Analyzed", "sample test", &score, fmt.Sprintf("dryhash-sample%d", i))
		}

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		result, err := ev.DryRun(ctx, rule.ID, orgID)
		if err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		if len(result.SampleCVEs) > 10 {
			t.Fatalf("SampleCVEs should be capped at 10, got %d", len(result.SampleCVEs))
		}
	})

	t.Run("WithRegexPostFilter", func(t *testing.T) {
		// Insert CVEs: one with "apache" in description, one without
		score := 8.0
		insertCVE(t, tdb.DB(), "CVE-DRY-REGEX-001", "Analyzed", "Apache HTTP server flaw", &score, "dryhash-regex1")
		insertCVE(t, tdb.DB(), "CVE-DRY-REGEX-002", "Analyzed", "Windows kernel flaw", &score, "dryhash-regex2")

		const regexConds = `[
			{"field":"cvss_v3_score","operator":"gte","value":7.0},
			{"field":"description_primary","operator":"regex","value":"apache"}
		]`
		rule := mustRule(t, ctx, tdb.Store, orgID, "and", regexConds, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		result, err := ev.DryRun(ctx, rule.ID, orgID)
		if err != nil {
			t.Fatalf("DryRun: %v", err)
		}

		// Only the Apache CVE should match the regex post-filter; Windows CVE must not.
		for _, id := range result.SampleCVEs {
			if id == "CVE-DRY-REGEX-002" {
				t.Fatal("CVE-DRY-REGEX-002 should not match apache regex")
			}
		}

		// Confirm no events were written
		if n := countAllAlertEventsForRule(t, tdb.DB(), rule.ID); n != 0 {
			t.Fatalf("DryRun should not write alert_events, got %d", n)
		}
	})

	t.Run("ExcludesRejectedCVEs", func(t *testing.T) {
		score := 9.5
		insertCVE(t, tdb.DB(), "CVE-DRY-REJECTED-001", "Rejected", "rejected vuln", &score, "dryhash-rejected1")

		rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		result, err := ev.DryRun(ctx, rule.ID, orgID)
		if err != nil {
			t.Fatalf("DryRun: %v", err)
		}

		for _, id := range result.SampleCVEs {
			if id == "CVE-DRY-REJECTED-001" {
				t.Fatal("rejected CVE should not appear in DryRun results")
			}
		}
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// CandidateCap fail-closed (security-critical)
// ──────────────────────────────────────────────────────────────────────────────

// TestDryRun_CandidateCapFailClosed verifies that when the candidate count exceeds
// the 5000 candidateCap, the evaluator returns partial=true and zero matches.
// This is the fail-closed security behavior: regex rules must not match-all on overflow.
func TestDryRun_CandidateCapFailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping candidateCap test in short mode (inserts 5100 rows)")
	}
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Insert 5100 CVEs that all match cvss >= 1.0 (intentionally broad rule)
	bulkInsertCVEs(t, tdb.DB(), "CVE-CAP", 5100, 8.0)

	// A broad rule that matches everything with cvss >= 1.0
	const broadCondition = `[{"field":"cvss_v3_score","operator":"gte","value":1.0}]`
	rule := mustRule(t, ctx, tdb.Store, orgID, "and", broadCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	result, err := ev.DryRun(ctx, rule.ID, orgID)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if result == nil {
		t.Fatal("DryRun returned nil result")
	}
	if !result.Partial {
		t.Fatalf("want Partial=true when candidates exceed 5000, got false (MatchCount=%d, CandidatesEvaluated=%d)",
			result.MatchCount, result.CandidatesEvaluated)
	}
	// When partial=true, MatchCount should be 0 (fail-closed: no matches reported)
	if result.MatchCount != 0 {
		t.Fatalf("want MatchCount=0 on partial (fail-closed), got %d", result.MatchCount)
	}
	// CandidatesEvaluated should be candidateCap+1 (5001) to signal overflow
	if result.CandidatesEvaluated != 5001 {
		t.Fatalf("want CandidatesEvaluated=5001 on partial, got %d", result.CandidatesEvaluated)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// EvaluateBatch — additional tests for cursor and EPSS-only rule skipping
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorBatch_CursorAdvancement(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	score := 9.0
	insertCVE(t, tdb.DB(), "CVE-BATCHCUR-001", "Analyzed", "cursor test", &score, "batchcur1")

	rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	// First batch
	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("first EvaluateBatch: %v", err)
	}

	cursor1 := getCursorSince(t, tdb.DB(), "alert:batch")
	if cursor1.IsZero() {
		t.Fatal("batch cursor should be non-zero after first run")
	}

	// Insert a new CVE after the cursor
	time.Sleep(10 * time.Millisecond) // ensure date_modified_canonical > cursor
	insertCVE(t, tdb.DB(), "CVE-BATCHCUR-002", "Analyzed", "after cursor", &score, "batchcur2")

	// Second batch
	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("second EvaluateBatch: %v", err)
	}

	// New CVE should be matched
	if n := countAlertEvents(t, tdb.DB(), rule.ID, "CVE-BATCHCUR-002"); n != 1 {
		t.Fatalf("want 1 alert_event for new CVE after cursor, got %d", n)
	}

	// Cursor should have advanced
	cursor2 := getCursorSince(t, tdb.DB(), "alert:batch")
	if !cursor2.After(cursor1) {
		t.Fatalf("batch cursor should advance: cursor1=%v, cursor2=%v", cursor1, cursor2)
	}
}

func TestEvaluatorBatch_SkipsEPSSOnlyRules(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Insert a CVE with high EPSS that matches EPSS condition
	epss := 0.95
	score := 9.0
	insertCVEWithEPSS(t, tdb.DB(), "CVE-BATCHEPSS-001", "Analyzed", "epss only test", &score, &epss, "batchepss1")

	// Create an EPSS-only rule (is_epss_only=true)
	const epssCond = `[{"field":"epss_score","operator":"gte","value":0.9}]`
	epssRule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and", epssCond, true)
	activateRule(t, ctx, tdb.Store, orgID, epssRule.ID)

	// Create a non-EPSS rule
	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	cvssRule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, cvssRule.ID)

	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}

	// CVSS rule should have a batch run
	var cvssRunCount int
	err := tdb.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alert_rule_runs WHERE rule_id = $1 AND path = 'batch'`,
		cvssRule.ID,
	).Scan(&cvssRunCount)
	if err != nil {
		t.Fatalf("query cvss batch runs: %v", err)
	}
	if cvssRunCount == 0 {
		t.Fatal("CVSS rule should have batch-path runs")
	}

	// EPSS-only rule should NOT have a batch run (ListActiveRulesForEvaluation filters is_epss_only=true out)
	var epssRunCount int
	err = tdb.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alert_rule_runs WHERE rule_id = $1 AND path = 'batch'`,
		epssRule.ID,
	).Scan(&epssRunCount)
	if err != nil {
		t.Fatalf("query epss batch runs: %v", err)
	}
	if epssRunCount != 0 {
		t.Fatalf("EPSS-only rule should have 0 batch-path runs, got %d", epssRunCount)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// EvaluateActivation — additional tests for keyset pagination and status transition
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorActivation_KeysetPagination(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Insert more CVEs than activationBatch (1000) to exercise keyset pagination.
	// We use a smaller number that still proves pagination works: we just need > 1 page.
	// The evaluator pages in batches of 1000 (activationBatch), so we insert 1005 CVEs.
	const total = 1005
	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	score := 8.0
	for i := 1; i <= total; i++ {
		cveID := fmt.Sprintf("CVE-ACTPAGE-%05d", i)
		insertCVE(t, tdb.DB(), cveID, "Analyzed", "pagination test", &score, fmt.Sprintf("actpagehash%d", i))
	}

	conds := json.RawMessage(cvssCondition)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "activation-pagination-rule",
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

	// All 1005 matching CVEs should have events
	n := countAllAlertEventsForRule(t, tdb.DB(), row.ID)
	if n < total {
		t.Fatalf("want at least %d alert_events, got %d", total, n)
	}
}

func TestEvaluatorActivation_RuleNotFound(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	err := ev.EvaluateActivation(ctx, uuid.New(), orgID)
	if err == nil {
		t.Fatal("want error for missing rule")
	}
}

func TestEvaluatorActivation_StatusTransitionToActive(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	conds := json.RawMessage(cvssCondition)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "status-transition-rule",
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

	// Verify starts as 'activating'
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "activating" {
		t.Fatalf("want initial status 'activating', got %q", s)
	}

	if err := ev.EvaluateActivation(ctx, row.ID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	// Verify transitions to 'active'
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "active" {
		t.Fatalf("want final status 'active', got %q", s)
	}

	// Verify run row written with activation path
	if p := getRunPath(t, tdb.DB(), row.ID); p != "activation" {
		t.Fatalf("want run path 'activation', got %q", p)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Fanout error propagation
// ──────────────────────────────────────────────────────────────────────────────

// failingDispatcher returns an error from Fanout() to test that the evaluator
// logs the error and continues processing subsequent events.
type failingDispatcher struct {
	calls int
	mu    sync.Mutex
}

func (f *failingDispatcher) Fanout(_ context.Context, _, _ uuid.UUID, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return fmt.Errorf("simulated fanout failure")
}

func TestEvaluateRealtime_FanoutErrorContinuesProcessing(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	disp := &failingDispatcher{}
	ev.SetDispatcher(disp)

	const cvssCondition = `[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`
	cveID := "CVE-FANOUT-ERR-001"
	score := 9.0
	insertCVE(t, tdb.DB(), cveID, "Analyzed", "fanout error test", &score, "hashfanouterr1")

	rule := mustRule(t, ctx, tdb.Store, orgID, "and", cvssCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	// EvaluateRealtime must not return an error even when Fanout fails.
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime should not fail when Fanout errors: %v", err)
	}

	// Alert event should still be committed (the event is written before Fanout).
	if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 1 {
		t.Fatalf("alert_event should be committed despite Fanout error, got %d", n)
	}

	// Fanout should have been called.
	disp.mu.Lock()
	defer disp.mu.Unlock()
	if disp.calls != 1 {
		t.Errorf("Fanout should have been called once, got %d", disp.calls)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// SweepZombieActivations — additional tests
// ──────────────────────────────────────────────────────────────────────────────

func TestSweepZombieActivations_NoZombies(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()

	// No zombie jobs in the queue — sweep should succeed silently
	if err := ev.SweepZombieActivations(ctx); err != nil {
		t.Fatalf("SweepZombieActivations with no zombies: %v", err)
	}
}

func TestSweepZombieActivations_RecentJobNotSwept(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Create a rule in 'activating' status
	conds := json.RawMessage(`[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "recent-job-rule",
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

	// Insert a 'running' job with RECENT locked_at (5 minutes ago, within 15-minute threshold)
	payload, _ := json.Marshal(map[string]string{
		"rule_id": row.ID.String(),
		"org_id":  orgID.String(),
	})
	var jobID uuid.UUID
	err = tdb.DB().QueryRowContext(ctx, `
		INSERT INTO job_queue (queue, lock_key, payload, status, locked_by, locked_at)
		VALUES ('alert_activation', $1, $2, 'running', 'worker-1', now() - interval '5 minutes')
		RETURNING id
	`, "alert:activation:"+row.ID.String(), payload).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert recent job: %v", err)
	}

	if err := ev.SweepZombieActivations(ctx); err != nil {
		t.Fatalf("SweepZombieActivations: %v", err)
	}

	// Rule should still be 'activating' (not swept)
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "activating" {
		t.Fatalf("want rule status 'activating' (not swept), got %q", s)
	}

	// Job should still be 'running'
	var jobStatus string
	if err := tdb.DB().QueryRowContext(ctx, `SELECT status FROM job_queue WHERE id = $1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatalf("get job status: %v", err)
	}
	if jobStatus != "running" {
		t.Fatalf("want job status 'running', got %q", jobStatus)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RuleCache — concurrent access tests
// ──────────────────────────────────────────────────────────────────────────────

func TestRuleCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	cache := alert.NewRuleCache()
	ruleID := uuid.New()

	// Run concurrent Set and Get operations to verify thread-safety
	var wg sync.WaitGroup
	const goroutines = 50

	// Half the goroutines write, half read
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func(version int) {
				defer wg.Done()
				cache.Set(ruleID, version, nil)
			}(i)
		} else {
			go func(version int) {
				defer wg.Done()
				cache.Get(ruleID, version)
			}(i)
		}
	}
	wg.Wait()
	// No race condition or panic = pass
}

func TestRuleCache_ConcurrentEvict(t *testing.T) {
	cache := alert.NewRuleCache()
	ruleID := uuid.New()

	// Pre-populate multiple versions
	for v := 1; v <= 10; v++ {
		cache.Set(ruleID, v, nil)
	}

	// Evict while reading concurrently
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cache.Evict(ruleID)
	}()
	go func() {
		defer wg.Done()
		for v := 1; v <= 10; v++ {
			cache.Get(ruleID, v)
		}
	}()
	wg.Wait()

	// After eviction, all versions should miss
	for v := 1; v <= 10; v++ {
		if _, ok := cache.Get(ruleID, v); ok {
			t.Fatalf("expected miss for version %d after Evict", v)
		}
	}
}

func TestRuleCache_EvictOnlyTargetRule(t *testing.T) {
	cache := alert.NewRuleCache()
	ruleA := uuid.New()
	ruleB := uuid.New()

	cache.Set(ruleA, 1, nil)
	cache.Set(ruleB, 1, nil)

	cache.Evict(ruleA)

	// ruleA should be evicted
	if _, ok := cache.Get(ruleA, 1); ok {
		t.Fatal("ruleA should be evicted")
	}
	// ruleB should still be cached
	if _, ok := cache.Get(ruleB, 1); !ok {
		t.Fatal("ruleB should still be cached")
	}
}

func TestRuleCache_EvictMultipleVersions(t *testing.T) {
	cache := alert.NewRuleCache()
	ruleID := uuid.New()

	// Set multiple versions
	cache.Set(ruleID, 1, nil)
	cache.Set(ruleID, 2, nil)
	cache.Set(ruleID, 3, nil)

	// Verify all cached
	for v := 1; v <= 3; v++ {
		if _, ok := cache.Get(ruleID, v); !ok {
			t.Fatalf("expected hit for version %d before evict", v)
		}
	}

	// Evict removes ALL versions
	cache.Evict(ruleID)
	for v := 1; v <= 3; v++ {
		if _, ok := cache.Get(ruleID, v); ok {
			t.Fatalf("expected miss for version %d after evict", v)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Bug fix tests — Task 6
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluateActivation_DoesNotOverrideDisabledStatus(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Insert a CVE that will match the rule
	score := 8.0
	insertCVE(t, tdb.DB(), "CVE-DISABLE-001", "Analyzed", "disable test", &score, "disablehash1")

	// Create rule in 'activating' status
	conds := json.RawMessage(`[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "disable-race-rule",
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

	// Simulate user disabling the rule during activation (before EvaluateActivation completes)
	if err := tdb.SetAlertRuleStatus(ctx, orgID, row.ID, "disabled"); err != nil {
		t.Fatalf("disable rule: %v", err)
	}

	// Run activation — should complete without error
	if err := ev.EvaluateActivation(ctx, row.ID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	// Rule should remain 'disabled' — NOT overwritten to 'active'
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "disabled" {
		t.Fatalf("want rule status 'disabled' (user-set), got %q", s)
	}
}

func TestSweepZombieActivations_SkipsCompletedJobs(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Create a rule that successfully completed activation (status = 'active')
	conds := json.RawMessage(`[{"field":"cvss_v3_score","operator":"gte","value":7.0}]`)
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "completed-activation-rule",
		Logic:      "and",
		Conditions: conds,
		Status:     "active", // already completed activation
	})
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	t.Cleanup(func() {
		_ = tdb.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})

	// Insert a zombie job for this rule (old locked_at) — simulates a TOCTOU race where
	// the activation completed just before the sweep query ran
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

	// Rule should STILL be 'active' — sweep must NOT overwrite to 'error'
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "active" {
		t.Fatalf("want rule status 'active' (completed), got %q", s)
	}

	// Job should be marked 'failed' (zombie cleanup is fine for the job row)
	var jobStatus string
	if err := tdb.DB().QueryRowContext(ctx, `SELECT status FROM job_queue WHERE id = $1`, jobID).Scan(&jobStatus); err != nil {
		t.Fatalf("get job status: %v", err)
	}
	if jobStatus != "failed" {
		t.Fatalf("want job status 'failed', got %q", jobStatus)
	}
}

func TestApplyPostFilters_UsesORLogicForORRules(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	// Insert CVEs: one matches "apache", other matches "windows", neither matches both
	score := 8.0
	insertCVE(t, tdb.DB(), "CVE-ORPF-001", "Analyzed", "Apache HTTP server exploit", &score, "orpf-hash1")
	insertCVE(t, tdb.DB(), "CVE-ORPF-002", "Analyzed", "Windows kernel overflow", &score, "orpf-hash2")
	insertCVE(t, tdb.DB(), "CVE-ORPF-003", "Analyzed", "Linux privilege escalation", &score, "orpf-hash3")

	// Create an OR rule with two regex PostFilters:
	// "apache" OR "windows" — both CVE-ORPF-001 and CVE-ORPF-002 should match
	const orRegexConds = `[
		{"field":"description_primary","operator":"regex","value":"apache"},
		{"field":"description_primary","operator":"regex","value":"windows"}
	]`
	// Need a SQL condition too since all-regex with no watchlist fails compilation
	const orCondWithCVSS = `[
		{"field":"cvss_v3_score","operator":"gte","value":7.0},
		{"field":"description_primary","operator":"regex","value":"apache"},
		{"field":"description_primary","operator":"regex","value":"windows"}
	]`
	rule := mustRule(t, ctx, tdb.Store, orgID, "or", orCondWithCVSS, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	// DryRun to check results
	result, err := ev.DryRun(ctx, rule.ID, orgID)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if result == nil {
		t.Fatal("DryRun returned nil")
	}

	// With OR logic, any CVE matching "apache" OR "windows" should be included.
	// CVE-ORPF-001 (apache) and CVE-ORPF-002 (windows) should match.
	// CVE-ORPF-003 (linux) should NOT match.
	matched := make(map[string]bool)
	for _, id := range result.SampleCVEs {
		matched[id] = true
	}

	if !matched["CVE-ORPF-001"] {
		t.Error("CVE-ORPF-001 (apache) should match OR rule")
	}
	if !matched["CVE-ORPF-002"] {
		t.Error("CVE-ORPF-002 (windows) should match OR rule")
	}
	if matched["CVE-ORPF-003"] {
		t.Error("CVE-ORPF-003 (linux) should NOT match OR rule")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Batch evaluator — empty candidates
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorBatch_NoCandidates(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()

	// Run batch with no CVEs and no rules — should succeed and write cursor
	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("EvaluateBatch with no CVEs: %v", err)
	}

	// Cursor should be written even when no candidates
	cursor := getCursorSince(t, tdb.DB(), "alert:batch")
	if cursor.IsZero() {
		t.Fatal("batch cursor should be set even with no candidates")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// EPSS evaluator — empty candidates
// ──────────────────────────────────────────────────────────────────────────────

func TestEvaluatorEPSS_NoCandidates(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()

	// Run EPSS with no CVEs having EPSS scores — should succeed and write cursor
	if err := ev.EvaluateEPSS(ctx); err != nil {
		t.Fatalf("EvaluateEPSS with no EPSS candidates: %v", err)
	}

	cursor := getCursorSince(t, tdb.DB(), "alert:epss")
	if cursor.IsZero() {
		t.Fatal("EPSS cursor should be set even with no candidates")
	}
}
