// ABOUTME: Integration tests for store/alert_rule.go -- alert rule, run, and event CRUD.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// helpers

func mustCreateAlertRule(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) *store.AlertRuleRow {
	t.Helper()
	r, err := s.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       name,
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		Status:     "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule(%q): %v", name, err)
	}
	return r
}

// tests

func TestCreateAndGetAlertRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg1")

	r, err := s.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:             "Critical CVEs",
		Logic:            "and",
		Conditions:       json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
		HasEpssCondition: false,
		IsEpssOnly:       false,
		Status:           "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if r.Name != "Critical CVEs" {
		t.Errorf("Name = %q, want Critical CVEs", r.Name)
	}
	if r.Status != "draft" {
		t.Errorf("Status = %q, want draft", r.Status)
	}

	got, err := s.GetAlertRule(ctx, org.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule: %v", err)
	}
	if got == nil {
		t.Fatal("GetAlertRule returned nil for existing rule")
	}
	if got.ID != r.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, r.ID)
	}
}

func TestGetAlertRule_WrongOrgReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AROrg2a")
	org2 := s.MustCreateOrg(t, ctx, "AROrg2b")
	r := mustCreateAlertRule(t, s, ctx, org1.ID, "Rule A")

	got, err := s.GetAlertRule(ctx, org2.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule(wrong org): %v", err)
	}
	if got != nil {
		t.Error("GetAlertRule with wrong org should return nil")
	}
}

func TestUpdateAlertRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg3")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "Original")

	updated, err := s.UpdateAlertRule(ctx, org.ID, r.ID, store.UpdateAlertRuleParams{
		Name:             "Updated",
		Logic:            "or",
		Conditions:       json.RawMessage(`[{"field":"in_cisa_kev","operator":"eq","value":true}]`),
		HasEpssCondition: false,
		IsEpssOnly:       false,
		Status:           "activating",
	})
	if err != nil {
		t.Fatalf("UpdateAlertRule: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateAlertRule returned nil")
	}
	if updated.Name != "Updated" {
		t.Errorf("Name = %q, want Updated", updated.Name)
	}
	if updated.Logic != "or" {
		t.Errorf("Logic = %q, want or", updated.Logic)
	}
}

func TestSoftDeleteAlertRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg4")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "DeleteMe")

	if err := s.SoftDeleteAlertRule(ctx, org.ID, r.ID); err != nil {
		t.Fatalf("SoftDeleteAlertRule: %v", err)
	}

	got, err := s.GetAlertRule(ctx, org.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule(deleted): %v", err)
	}
	if got != nil {
		t.Error("GetAlertRule should return nil for soft-deleted rule")
	}
}

func TestSetAlertRuleStatus(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg5")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "StatusRule")

	if err := s.SetAlertRuleStatus(ctx, org.ID, r.ID, "active"); err != nil {
		t.Fatalf("SetAlertRuleStatus: %v", err)
	}

	got, err := s.GetAlertRule(ctx, org.ID, r.ID)
	if err != nil {
		t.Fatalf("GetAlertRule(after status change): %v", err)
	}
	if got == nil {
		t.Fatal("GetAlertRule returned nil after status change")
	}
	if got.Status != "active" {
		t.Errorf("Status = %q, want active", got.Status)
	}
}

func TestInsertAlertEvent_DeduplicatesOnConflict(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg6")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "DedupeRule")

	// First insert returns a new ID.
	id1, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0001", "hash1", false)
	if err != nil {
		t.Fatalf("InsertAlertEvent (first): %v", err)
	}
	if id1 == uuid.Nil {
		t.Error("first insert should return a non-nil UUID")
	}

	// Second insert with same (org, rule, cve, hash) returns zero UUID (DO NOTHING).
	id2, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0001", "hash1", false)
	if err != nil {
		t.Fatalf("InsertAlertEvent (duplicate): %v", err)
	}
	if id2 != uuid.Nil {
		t.Errorf("duplicate insert should return uuid.Nil, got %v", id2)
	}
}

func TestResolveAlertEvent(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg7")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "ResolveRule")

	if _, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0002", "hash2", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}

	// Before resolving: should appear in unresolved list.
	unresolvedBefore, err := s.GetUnresolvedAlertEventCVEs(ctx, r.ID, org.ID)
	if err != nil {
		t.Fatalf("GetUnresolvedAlertEventCVEs: %v", err)
	}
	if len(unresolvedBefore) != 1 || unresolvedBefore[0] != "CVE-2024-0002" {
		t.Errorf("unresolved before = %v, want [CVE-2024-0002]", unresolvedBefore)
	}

	if err := s.ResolveAlertEvent(ctx, r.ID, org.ID, "CVE-2024-0002"); err != nil {
		t.Fatalf("ResolveAlertEvent: %v", err)
	}

	unresolvedAfter, err := s.GetUnresolvedAlertEventCVEs(ctx, r.ID, org.ID)
	if err != nil {
		t.Fatalf("GetUnresolvedAlertEventCVEs after resolve: %v", err)
	}
	if len(unresolvedAfter) != 0 {
		t.Errorf("unresolved after = %v, want []", unresolvedAfter)
	}
}

func TestInsertAndUpdateAlertRuleRun(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg8")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "RunRule")

	run, err := s.InsertAlertRuleRun(ctx, r.ID, org.ID, "batch")
	if err != nil {
		t.Fatalf("InsertAlertRuleRun: %v", err)
	}
	if run.Status != "running" {
		t.Errorf("initial status = %q, want running", run.Status)
	}

	if err := s.UpdateAlertRuleRun(ctx, run.ID, "complete", 100, 5, nil); err != nil {
		t.Fatalf("UpdateAlertRuleRun: %v", err)
	}
}

func TestListActiveRulesForEvaluation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg9")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "ActiveRule")
	_ = s.SetAlertRuleStatus(ctx, org.ID, r.ID, "active")

	// Also create a draft rule — should not appear.
	_ = mustCreateAlertRule(t, s, ctx, org.ID, "DraftRule")

	rules, err := s.ListActiveRulesForEvaluation(ctx)
	if err != nil {
		t.Fatalf("ListActiveRulesForEvaluation: %v", err)
	}

	found := false
	for _, rule := range rules {
		if rule.ID == r.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("active rule %v not found in ListActiveRulesForEvaluation", r.ID)
	}

	for _, rule := range rules {
		if rule.Status != "active" {
			t.Errorf("non-active rule %v (status=%q) found in active list", rule.ID, rule.Status)
		}
		if rule.IsEpssOnly {
			t.Errorf("EPSS-only rule %v should not be in evaluation list", rule.ID)
		}
	}
}

func TestListAlertRules_StatusFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg10")
	r1 := mustCreateAlertRule(t, s, ctx, org.ID, "Draft1")
	r2 := mustCreateAlertRule(t, s, ctx, org.ID, "Active1")
	_ = s.SetAlertRuleStatus(ctx, org.ID, r2.ID, "active")

	// No filter: both rules returned.
	all, err := s.ListAlertRules(ctx, org.ID, nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListAlertRules(all): %v", err)
	}
	if len(all) < 2 {
		t.Errorf("all rules: got %d, want >= 2", len(all))
	}

	// Filter by status=active.
	activeStr := "active"
	active, err := s.ListAlertRules(ctx, org.ID, &activeStr, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListAlertRules(active): %v", err)
	}
	for _, rule := range active {
		if rule.Status != "active" {
			t.Errorf("rule %v has status %q, want active", rule.ID, rule.Status)
		}
	}
	_ = r1
}

func TestListAlertRules_RLSIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "ARRLSOrg1")
	org2 := s.MustCreateOrg(t, ctx, "ARRLSOrg2")
	mustCreateAlertRule(t, s, ctx, org1.ID, "Org1-Rule")
	mustCreateAlertRule(t, s, ctx, org2.ID, "Org2-Rule")

	got, err := s.AppStore.ListAlertRules(ctx, org1.ID, nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("AppStore.ListAlertRules(org1): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 rule for org1, got %d", len(got))
	}
	if got[0].Name != "Org1-Rule" {
		t.Errorf("Name = %q, want Org1-Rule", got[0].Name)
	}

	got2, err := s.AppStore.ListAlertRules(ctx, org2.ID, nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("AppStore.ListAlertRules(org2): %v", err)
	}
	if len(got2) != 1 {
		t.Fatalf("expected 1 rule for org2, got %d", len(got2))
	}
}

func TestListAlertEvents_RLSIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "AERLSOrg1")
	org2 := s.MustCreateOrg(t, ctx, "AERLSOrg2")
	r1 := mustCreateAlertRule(t, s, ctx, org1.ID, "RLSEventRule1")
	r2 := mustCreateAlertRule(t, s, ctx, org2.ID, "RLSEventRule2")

	if _, err := s.InsertAlertEvent(ctx, org1.ID, r1.ID, "CVE-2024-0100", "rls1", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}
	if _, err := s.InsertAlertEvent(ctx, org2.ID, r2.ID, "CVE-2024-0101", "rls2", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}

	events, err := s.AppStore.ListAlertEvents(ctx, org1.ID, store.ListAlertEventsParams{Limit: 10})
	if err != nil {
		t.Fatalf("AppStore.ListAlertEvents(org1): %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event for org1, got %d", len(events))
	}
	if events[0].CveID != "CVE-2024-0100" {
		t.Errorf("CveID = %q, want CVE-2024-0100", events[0].CveID)
	}
}

func TestListAlertEvents_Filters(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg11")
	r1 := mustCreateAlertRule(t, s, ctx, org.ID, "EventRule1")
	r2 := mustCreateAlertRule(t, s, ctx, org.ID, "EventRule2")

	if _, err := s.InsertAlertEvent(ctx, org.ID, r1.ID, "CVE-2024-0010", "h10", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}
	if _, err := s.InsertAlertEvent(ctx, org.ID, r1.ID, "CVE-2024-0011", "h11", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}
	if _, err := s.InsertAlertEvent(ctx, org.ID, r2.ID, "CVE-2024-0012", "h12", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}

	// Filter by rule_id.
	events, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		RuleID: &r1.ID,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(by rule): %v", err)
	}
	if len(events) != 2 {
		t.Errorf("by rule_id: got %d, want 2", len(events))
	}

	// Filter by cve_id.
	cveID := "CVE-2024-0010"
	events2, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		CveID: &cveID,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(by cve_id): %v", err)
	}
	if len(events2) != 1 {
		t.Errorf("by cve_id: got %d, want 1", len(events2))
	}

	// No filter: all 3 events.
	all, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListAlertEvents(all): %v", err)
	}
	if len(all) != 3 {
		t.Errorf("all: got %d, want 3", len(all))
	}
}

func TestListAlertRules_Pagination(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg12")
	for i := range 5 {
		mustCreateAlertRule(t, s, ctx, org.ID, "PageRule-"+string(rune('a'+i)))
	}

	// Page 1: first 3 rules.
	page1, err := s.ListAlertRules(ctx, org.ID, nil, nil, nil, 3)
	if err != nil {
		t.Fatalf("ListAlertRules(page1): %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1: got %d rules, want 3", len(page1))
	}

	// Page 2: remaining rules using cursor from last item.
	last := page1[len(page1)-1]
	page2, err := s.ListAlertRules(ctx, org.ID, nil, &last.CreatedAt, &last.ID, 3)
	if err != nil {
		t.Fatalf("ListAlertRules(page2): %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2: got %d rules, want 2", len(page2))
	}

	// No overlap.
	seen := map[uuid.UUID]bool{}
	for _, r := range page1 {
		seen[r.ID] = true
	}
	for _, r := range page2 {
		if seen[r.ID] {
			t.Errorf("overlap: rule %v appeared in both pages", r.ID)
		}
	}
}

func TestUpdateAlertRule_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg13")

	updated, err := s.UpdateAlertRule(ctx, org.ID, uuid.New(), store.UpdateAlertRuleParams{
		Name:       "Ghost",
		Logic:      "and",
		Conditions: json.RawMessage(`[]`),
		Status:     "draft",
	})
	if err != nil {
		t.Fatalf("UpdateAlertRule(not found): %v", err)
	}
	if updated != nil {
		t.Error("UpdateAlertRule should return nil for non-existent rule")
	}
}

func TestListActiveRulesForEPSS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg14")

	// Create an EPSS-conditioned active rule.
	epssRule, err := s.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:             "EPSS Rule",
		Logic:            "and",
		Conditions:       json.RawMessage(`[{"field":"epss_score","operator":"gte","value":0.5}]`),
		HasEpssCondition: true,
		IsEpssOnly:       true,
		Status:           "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule (EPSS): %v", err)
	}
	_ = s.SetAlertRuleStatus(ctx, org.ID, epssRule.ID, "active")

	// Create a non-EPSS active rule — should not appear in EPSS list.
	nonEpss := mustCreateAlertRule(t, s, ctx, org.ID, "NonEPSSRule")
	_ = s.SetAlertRuleStatus(ctx, org.ID, nonEpss.ID, "active")

	rules, err := s.ListActiveRulesForEPSS(ctx)
	if err != nil {
		t.Fatalf("ListActiveRulesForEPSS: %v", err)
	}

	found := false
	for _, rule := range rules {
		if rule.ID == epssRule.ID {
			found = true
		}
		if !rule.HasEpssCondition {
			t.Errorf("non-EPSS rule %v found in EPSS list", rule.ID)
		}
	}
	if !found {
		t.Errorf("EPSS rule %v not found in ListActiveRulesForEPSS", epssRule.ID)
	}
}

func TestInsertAlertEvent_DifferentMaterialHash(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg15")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "DiffHashRule")

	// Same (org, rule, cve) but different material_hash should create separate events.
	id1, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0020", "hashA", false)
	if err != nil {
		t.Fatalf("InsertAlertEvent (hashA): %v", err)
	}
	if id1 == uuid.Nil {
		t.Error("first insert should return non-nil UUID")
	}

	id2, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0020", "hashB", false)
	if err != nil {
		t.Fatalf("InsertAlertEvent (hashB): %v", err)
	}
	if id2 == uuid.Nil {
		t.Error("second insert with different hash should return non-nil UUID")
	}
	if id1 == id2 {
		t.Error("different hashes should produce different event IDs")
	}
}

func TestListAlertEvents_LastMatchStateFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg16")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "MatchStateRule")

	if _, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0030", "h30", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}
	if _, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0031", "h31", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}

	// Resolve one event.
	_ = s.ResolveAlertEvent(ctx, r.ID, org.ID, "CVE-2024-0030")

	// Filter for unresolved (last_match_state = true).
	matchTrue := true
	unresolved, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		LastMatchState: &matchTrue,
		Limit:          10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(unresolved): %v", err)
	}
	if len(unresolved) != 1 {
		t.Errorf("unresolved: got %d, want 1", len(unresolved))
	}
	if len(unresolved) > 0 && unresolved[0].CveID != "CVE-2024-0031" {
		t.Errorf("unresolved cve = %q, want CVE-2024-0031", unresolved[0].CveID)
	}

	// Filter for resolved (last_match_state = false).
	matchFalse := false
	resolved, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		LastMatchState: &matchFalse,
		Limit:          10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(resolved): %v", err)
	}
	if len(resolved) != 1 {
		t.Errorf("resolved: got %d, want 1", len(resolved))
	}
	if len(resolved) > 0 && resolved[0].CveID != "CVE-2024-0030" {
		t.Errorf("resolved cve = %q, want CVE-2024-0030", resolved[0].CveID)
	}
}

func TestListAlertEvents_SinceFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg17")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "SinceRule")

	if _, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0040", "h40", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}

	// Since = now() means only events from now onward — the just-inserted event should be excluded.
	since := time.Now().Add(1 * time.Second)
	events, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		Since: &since,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(since): %v", err)
	}
	if len(events) != 0 {
		t.Errorf("since filter: got %d events, want 0", len(events))
	}
}

func TestListAlertEvents_Pagination(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg18")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "PageEventRule")

	for i := range 5 {
		cveID := "CVE-2024-005" + string(rune('0'+i))
		hash := "ph" + string(rune('0'+i))
		if _, err := s.InsertAlertEvent(ctx, org.ID, r.ID, cveID, hash, false); err != nil {
			t.Fatalf("setup: InsertAlertEvent: %v", err)
		}
	}

	page1, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{Limit: 3})
	if err != nil {
		t.Fatalf("ListAlertEvents(page1): %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1: got %d events, want 3", len(page1))
	}

	last := page1[len(page1)-1]
	page2, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{
		AfterTime: &last.FirstFiredAt,
		AfterID:   &last.ID,
		Limit:     3,
	})
	if err != nil {
		t.Fatalf("ListAlertEvents(page2): %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2: got %d events, want 2", len(page2))
	}

	seen := map[uuid.UUID]bool{}
	for _, e := range page1 {
		seen[e.ID] = true
	}
	for _, e := range page2 {
		if seen[e.ID] {
			t.Errorf("overlap: event %v appeared in both pages", e.ID)
		}
	}
}

func TestSoftDeleteAlertRule_NotVisibleInList(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg19")
	r1 := mustCreateAlertRule(t, s, ctx, org.ID, "ActiveRule19")
	r2 := mustCreateAlertRule(t, s, ctx, org.ID, "DeletedRule19")

	_ = s.SoftDeleteAlertRule(ctx, org.ID, r2.ID)

	rules, err := s.ListAlertRules(ctx, org.ID, nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListAlertRules: %v", err)
	}
	for _, rule := range rules {
		if rule.ID == r2.ID {
			t.Error("soft-deleted rule should not appear in ListAlertRules")
		}
	}
	found := false
	for _, rule := range rules {
		if rule.ID == r1.ID {
			found = true
		}
	}
	if !found {
		t.Error("active rule should appear in ListAlertRules")
	}
}

func TestInsertAlertEvent_SuppressDelivery(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg20")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "SuppressRule")

	id, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0060", "h60", true)
	if err != nil {
		t.Fatalf("InsertAlertEvent (suppress): %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected non-nil event ID")
	}

	events, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListAlertEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.ID == id {
			found = true
			if !e.SuppressDelivery {
				t.Error("SuppressDelivery should be true")
			}
		}
	}
	if !found {
		t.Error("suppressed event not found in list")
	}
}

func TestUpdateAlertRuleRun_WithError(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg21")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "ErrorRunRule")

	run, err := s.InsertAlertRuleRun(ctx, r.ID, org.ID, "batch")
	if err != nil {
		t.Fatalf("InsertAlertRuleRun: %v", err)
	}

	errMsg := "evaluation timeout exceeded"
	if err := s.UpdateAlertRuleRun(ctx, run.ID, "error", 50, 0, &errMsg); err != nil {
		t.Fatalf("UpdateAlertRuleRun (error): %v", err)
	}
}

func TestCreateAlertRule_WithWatchlistIds(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg22")

	r, err := s.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:         "Watchlist Rule",
		Logic:        "and",
		Conditions:   json.RawMessage(`[{"field":"severity","operator":"eq","value":"high"}]`),
		WatchlistIds: []uuid.UUID{uuid.New(), uuid.New()},
		Status:       "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if len(r.WatchlistIds) != 2 {
		t.Errorf("WatchlistIds = %d, want 2", len(r.WatchlistIds))
	}
}

func TestListAlertEvents_DefaultLimit(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "AROrg23")
	r := mustCreateAlertRule(t, s, ctx, org.ID, "DefaultLimitRule")
	if _, err := s.InsertAlertEvent(ctx, org.ID, r.ID, "CVE-2024-0070", "h70", false); err != nil {
		t.Fatalf("setup: InsertAlertEvent: %v", err)
	}

	// Limit = 0 should default to 100 (per ListAlertEvents implementation).
	events, err := s.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{Limit: 0})
	if err != nil {
		t.Fatalf("ListAlertEvents(default limit): %v", err)
	}
	if len(events) != 1 {
		t.Errorf("default limit: got %d events, want 1", len(events))
	}
}
